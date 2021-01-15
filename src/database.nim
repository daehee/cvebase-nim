import std/[asyncdispatch, strformat, json, tables, times, strutils, uri]
import pg

import models/[cve]

var db* {.threadvar.}: AsyncPool

proc dbConnect*(connStr: string) =
  let uri = parseUri(connStr)
  # TODO make pool connections a config variable
  db = newAsyncPool(uri.hostname, uri.username, uri.password, strip(uri.path, chars={'/'}), 20)


proc parsePgDateTime*(s: string): DateTime =
  # Example: "2006-01-02T15:04Z"
  let layout = "yyyy-MM-dd'T'HH:mm'Z'"
  s.parse(layout, utc())

## Cve

proc parseCveRow(row: Row): Cve {.inline.} =
  let cveData = parseJson(row[4])
  var refUrls: seq[string] = @[]
  for item in cveData["cve"]["references"]["reference_data"]:
    refUrls.add(item["url"].getStr())
  Cve(
    cveId: row[1],
    year: parseInt(row[2]),
    sequence: parseInt(row[3]),
    description: cveData["cve"]["description"]["description_data"][0]["value"].getStr(),
    refUrls: refUrls,
    pubDate: parsePgDateTime(cveData["publishedDate"].getStr()),
  )

proc parsePocs(rows: seq[Row]): seq[Poc] {.inline.} =
  for row in rows:
    result.add Poc(url: row[0])

proc parseCwe(rows: seq[Row]): Cwe =
  Cwe(name: rows[0][0], description: rows[0][1])

const
  resultsPerPage = 10

  cveBySequenceQuery = sql("select id, cve_id, year, sequence, data, cwe_id from cves where year = ? and sequence = ?")
  cvesByYearQuery = sql("select id, cve_id, year, sequence, data from cves where extract(year from published_date) = ? order by cve_pocs_count desc nulls last limit 10 offset ?")
  cvePocsQuery = sql("select url from cve_references where cve_references.type = 'CvePoc' and cve_references.cve_id = ?")
  cveCweQuery = sql("select name, description from cwes where id = ?")

proc getCveBySequence*(year, seq: int): Future[Cve] {.async.} =
  let
    rows = await db.rows(cveBySequenceQuery, @[$year, $seq])
    id = rows[0][0]
    cweId = rows[0][5]
  result = parseCveRow(rows[0])
  if cweId.len() > 0:
    result.cwe = parseCwe(await db.rows(cveCweQuery, @[cweId]))
  result.pocs = parsePocs(await db.rows(cvePocsQuery, @[id]))
  echo result.cwe

#proc getCveByCveId*(cveId: string): Future[Cve] {.async.} =
#  var param = cveId
#  let rows = await db.rows(cveByCveIdQuery, @[param])
#  result = parseCveRow(rows[0])

proc getCvesByYear*(year, page: int = 0): Future[seq[Cve]] {.async.} =
  let offset = page * resultsPerPage
  let rows = await db.rows(cvesByYearQuery, @[$year, $offset])
  for item in rows:
    result.add parseCveRow(item)
