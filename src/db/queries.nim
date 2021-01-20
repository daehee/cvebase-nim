import std/[asyncdispatch, json, tables, times, strutils, options, strformat]

import ./pg
import ../models/[cve, pagination]

#proc parseNvdDateTime*(s: string): DateTime =
#  # Example: "2006-01-02T15:04Z"
#  let layout = "yyyy-MM-dd'T'HH:mm'Z'"
#  s.parse(layout, utc())

proc parsePgDateTime*(s: string): DateTime =
  # Example: "2006-01-02 15:15:00"
  let layout = "yyyy-MM-dd HH:mm:ss"
  s.parse(layout, utc())

## Cve

proc parseCveRow(row: Row): Cve {.inline.} =
  var
    refUrls: seq[string] = @[]
    description: string

  let
    cveId = row[1]
    cveData = row[5]
    pubDate = parsePgDateTime(row[4])
  if cveData != "":
    let cveDataJson = parseJson(cveData)
    description = cveDataJson["cve"]["description"]["description_data"][0]["value"].getStr()
    for item in cveDataJson["cve"]["references"]["reference_data"]:
      refUrls.add(item["url"].getStr())
  else:
    let fmtDate = pubDate.format("MMM d, yyyy")
    description = &"""{cveId} is reserved and pending public disclosure since {fmtDate}.
When the official advisory for {cveId} is released, details such as weakness type and vulnerability scoring
will be provided here."""

  Cve(
    cveId: cveId,
    year: parseInt(row[2]),
    sequence: parseInt(row[3]),
    description: description,
    refUrls: refUrls,
    pubDate: pubDate,
  )

proc parsePocs(rows: seq[Row]): seq[Poc] {.inline.} =
  for row in rows:
    result.add Poc(url: row[0])

proc parseCwe(rows: seq[Row]): Cwe =
  Cwe(name: rows[0][0], description: rows[0][1])

const
  resultsPerPage = 10

  cveBySequenceQuery = sql("select id, cve_id, year, sequence, published_date, data, cwe_id from cves where year = ? and sequence = ?")
  cvesByYearQuery = sql("""select id, cve_id, year, sequence, published_date, data from cves
    where extract(year from published_date) = ?
    order by cve_pocs_count
    desc nulls last
    limit 10 offset ?""".unindent)
  cvesByYearCountQuery = sql("select count(*) from cves where extract(year from published_date) = ?")
  cvePocsQuery = sql("select url from cve_references where cve_references.type = 'CvePoc' and cve_references.cve_id = ?")
  cveCweQuery = sql("select name, description from cwes where id = ?")

proc getCveBySequence*(db: AsyncPool; year, seq: int): Future[Cve] {.async.} =
  let
    rows = await db.rows(cveBySequenceQuery, @[$year, $seq])
    id = rows[0][0] # actual row id; field idx 0
    cweId = rows[0][6] # field idx 6
  # Build basic Cve object
  result = parseCveRow(rows[0])
  # Relational queries for rest of fields
  if cweId.len() > 0:
    result.cwe = parseCwe(await db.rows(cveCweQuery, @[cweId])).some()
  result.pocs = parsePocs(await db.rows(cvePocsQuery, @[id]))

#proc getCveByCveId*(cveId: string): Future[Cve] {.async.} =
#  var param = cveId
#  let rows = await db.rows(cveByCveIdQuery, @[param])
#  result = parseCveRow(rows[0])

template paginateQuery(countQuery: SqlQuery, countParams: seq[string], page: int): untyped =
  ## Injects offset and count variables for paginated queries
  let offset {.inject} = (if page == 1: 0 else: page * resultsPerPage)
  let countResult = await db.rows(countQuery, countParams)
  let count {.inject.} = parseInt(countResult[0][0])
  # TODO: Error if invalid page number i.e. page > pages available

proc getCvesByYear*(db: AsyncPool; year: int; page: int = 1): Future[Pagination[Cve]] {.async.} =
  paginateQuery(cvesByYearCountQuery, @[$year], page)
  let rows = await db.rows(cvesByYearQuery, @[$year, $offset])
  # TODO: Change to "seek" technique to reduce to single query without offset
  result = newPagination[Cve](cvesByYearQuery, page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)
