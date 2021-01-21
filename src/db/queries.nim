import std/[asyncdispatch, json, tables, times, strutils, options, strformat, strutils]

import ./pg
import ../models/[cve, pagination]

#proc parseNvdDateTime*(s: string): DateTime =
#  # Example: "2006-01-02T15:04Z"
#  let layout = "yyyy-MM-dd'T'HH:mm'Z'"
#  s.parse(layout, utc())

const pgDateLayout = "yyyy-MM-dd HH:mm:ss"

proc parsePgDateTime*(s: string): DateTime =
  # Example: "2006-01-02 15:15:00"
  let layout = pgDateLayout
  s.parse(layout, utc())

## Cve

proc parseCveRow(row: Row): Cve {.inline.} =
  result.cveId = row[1]
  result.year = parseInt(row[2])
  result.sequence = parseInt(row[3])
  result.pubDate = parsePgDateTime(row[4])

  # initialize with 0 if cve_pocs_count column is NULL
  let pocsCount = row[6]
  result.pocsCount = if pocsCount == "": 0 else: parseInt(pocsCount)

  let cveData = row[5]
  if cveData != "":
    let cveDataJson = parseJson(cveData)
    result.description = cveDataJson["cve"]["description"]["description_data"][0]["value"].getStr()

    if len(cveDataJson["cve"]["references"]["reference_data"]) > 0:
      for item in cveDataJson["cve"]["references"]["reference_data"]:
        result.refUrls.add(item["url"].getStr())

    # CVSS data if exists
    let score = cveDataJson["impact"]["baseMetricV3"]["cvssV3"]["baseScore"].getFloat()
    if score > 0:
      result.cvss3 = Cvss3(
        score: if score == 10: "10" else: $score.formatFloat(ffDecimal, 1),
        severity: cveDataJson["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"].getStr()
      ).some()
  else:
    let fmtDate = result.pubDate.format("MMM d, yyyy")
    result.description = (&"""{result.cveId} is reserved and pending public disclosure since {fmtDate}.
      When the official advisory for {result.cveId} is released, details such as weakness type and vulnerability scoring
      will be provided here.""").unindent.replace("\n", " ")


proc parsePocs(rows: seq[Row]): seq[Poc] {.inline.} =
  for row in rows:
    result.add Poc(url: row[0])

proc parseCwe(rows: seq[Row]): Cwe =
  Cwe(name: rows[0][0], description: rows[0][1])

const
  resultsPerPage = 10

  selectCvesIndexFields = "select id, cve_id, year, sequence, published_date, data, cve_pocs_count"
  cveBySequenceQuery = sql(selectCvesIndexFields & ", wiki_data, cwe_id from cves where year = ? and sequence = ?")

  cvesByYearQuery = sql((selectCvesIndexFields & """ from cves
    where extract(year from published_date) = ?
    order by cve_pocs_count
    desc nulls last
    limit 10 offset ?""").unindent.replace("\n", " "))
  cvesByYearCountQuery = sql("select count(*) from cves where extract(year from published_date) = ?")

  # Cve.where(published_date: d.beginning_of_month.beginning_of_day..d.end_of_month.end_of_day).order('published_date DESC')
  cvesByMonthQuery = sql((selectCvesIndexFields & """ from cves
    where published_date between ? and ?
    order by published_date desc
    limit 10 offset ?""").unindent.replace("\n", " "))
  cvesByMonthCountQuery = sql("select count(*) from cves where published_date between ? and ?")

  ## selects all distinct years from cves
  cveYearsQuery = sql("select distinct(extract(year from published_date))::INTEGER as year FROM cves order by year desc")

  ## selects all months available in a year from cves
  # SELECT date_part('month', DATE_TRUNC('month', published_date)) as month FROM "cves" WHERE (extract(year from published_date) = 2020) GROUP BY month order by month asc
  cveYearMonthsQuery = sql("""select date_part('month', date_trunc('month', published_date)) as month from cves
  where (extract(year from published_date) = ?)
  group by month order by month desc""".unindent)

  cvePocsQuery = sql("select url from cve_references where cve_references.type = 'CvePoc' and cve_references.cve_id = ?")
  cveCweQuery = sql("select name, description from cwes where id = ?")


proc getCveBySequence*(db: AsyncPool; year, seq: int): Future[Cve] {.async.} =
  let
    rows = await db.rows(cveBySequenceQuery, @[$year, $seq])
    data = rows[0]
    id = data[0]         # pk id; field idx 0
    wikiData = data[7]
    cweId = data[8]

  # Build basic Cve object
  result = parseCveRow(data)

  # Relational queries for rest of fields
  if cweId.len() > 0:
    result.cwe = parseCwe(await db.rows(cveCweQuery, @[cweId])).some()

  result.pocs = parsePocs(await db.rows(cvePocsQuery, @[id]))

  result.wiki = newJObject() # initialize wiki JsonNode field to prevent SIGSEGV on null
  if wikiData != "":
    result.wiki = parseJson(wikiData)


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

proc getCvesByMonth*(db: AsyncPool; year: int, month: int; page: int = 1): Future[Pagination[Cve]] {.async.} =
  let monthDate = initDateTime(01, Month(month), year, 00, 00, 00, utc())
  let lastDayOfMonth = monthDate.month.getDaysInMonth(year)
  let monthEndDate = initDateTime(MonthdayRange(lastDayOfMonth), Month(month), year, 23, 59, 59, utc())

  let beginTime = monthDate.format(pgDateLayout) # 2020-12-01 00:00:00
  let endTime = monthEndDate.format(pgDateLayout) # 2020-12-31 23:59:59.999999

  paginateQuery(cvesByMonthCountQuery, @[beginTime, endTime], page)
  let rows = await db.rows(cvesByMonthQuery, @[beginTime, endTime, $offset])
  # TODO: Change to "seek" technique to reduce to single query without offset
  result = newPagination[Cve](cvesByMonthQuery, page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)

proc getCveYears*(db: AsyncPool): Future[seq[int]] {.async.} =
  let rows = await db.rows(cveYearsQuery, @[])
  for row in rows:
    result.add parseInt(row[0])

proc getCveYearMonths*(db: AsyncPool, year: int): Future[seq[int]] {.async.} =
  let rows = await db.rows(cveYearMonthsQuery, @[$year])
  for row in rows:
    result.add parseInt(row[0])
