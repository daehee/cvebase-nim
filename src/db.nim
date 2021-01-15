import std/[asyncdispatch, strformat, json, tables, times, strutils, uri]
import pg

import models/[cve]

type
  DbClient* = ref object
    conn: AsyncPool
    connStr: string

var
  dbClient* {.threadvar.}: DbClient

proc initDbClient*(connStr: string): DBClient =
  let uri = parseUri(connStr)
  let pg = newAsyncPool(uri.hostname, uri.username, uri.password, strip(uri.path, chars={'/'}), 20)
  return DBClient(conn: pg, connStr: connStr)

#proc close*(cl: DbClient) =
#  cl.conn.close()

proc parsePgDateTime*(s: string): DateTime =
  # Example: "2006-01-02T15:04Z"
  let layout = "yyyy-MM-dd'T'HH:mm'Z'"
  s.parse(layout, utc())

## Cve

proc parseCveRow*(row: Row): Cve {.inline.} =
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

const
  resultsPerPage = 10

  selectCveFields = "select id, cve_id, year, sequence, data from cves"

proc getCveBySequence*(cl: DbClient; year, seq: int): Future[Cve] {.async.} =
  let rows = await cl.conn.rows(sql(&"{selectCveFields} where year = ? and sequence = ?"), @[$year, $seq])
  result = parseCveRow(rows[0])

proc getCveByCveId*(cl: DbClient, cveId: string): Future[Cve] {.async.} =
  var param = cveId
  let rows = await cl.conn.rows(sql(&"{selectCveFields} where cve_id = ?"), @[param])
  result = parseCveRow(rows[0])

proc getCvesByYear*(cl: DbClient; year, page: int = 0): Future[seq[Cve]] {.async.} =
  let offset = page * resultsPerPage
  let rows = await cl.conn.rows(sql(&"{selectCveFields} where extract(year from published_date) = ? order by cve_pocs_count desc nulls last limit 10 offset ?"), @[$year, $offset])
  for item in rows:
    result.add parseCveRow(item)
