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

const
  resultsPerPage = 10

  selectCveFields = "select id, cve_id, year, sequence, data from cves"
  cveBySequenceQuery = sql(&"{selectCveFields} where year = ? and sequence = ?")
  cveByCveIdQuery = sql(&"{selectCveFields} where cve_id = ?")
  cvesByYearQuery = sql(&"{selectCveFields} where extract(year from published_date) = ? order by cve_pocs_count desc nulls last limit 10 offset ?")
  cvePocsQuery = sql("select url from cve_references where cve_references.type = 'CvePoc' and cve_references.cve_id = ?")

proc getCveBySequence*(year, seq: int): Future[Cve] {.async.} =
  let rows = await db.rows(cveBySequenceQuery, @[$year, $seq])
  let id = rows[0][0]
  result = parseCveRow(rows[0])
  result.pocs = parsePocs(await db.rows(cvePocsQuery, @[id]))

proc getCveByCveId*(cveId: string): Future[Cve] {.async.} =
  var param = cveId
  let rows = await db.rows(cveByCveIdQuery, @[param])
  result = parseCveRow(rows[0])

proc getCvesByYear*(year, page: int = 0): Future[seq[Cve]] {.async.} =
  let offset = page * resultsPerPage
  let rows = await db.rows(cvesByYearQuery, @[$year, $offset])
  for item in rows:
    result.add parseCveRow(item)
