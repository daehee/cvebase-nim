import std/[asyncdispatch, strformat, json, tables, times, strutils]
import asyncpg

import models/[cve]

type
  DbClient* = ref object
    conn: apgPool
    connStr: string

var
  dbClient* {.threadvar.}: DbClient

proc initDbClient*(connStr: string): Future[DBClient] {.async.} =
  let pool = newPool()
  await pool.connect(connStr)
  return DBClient(conn: pool, connStr: connStr)

#proc setDbClient*(connStr: string) =
#  dbClient = waitFor initDbClient(connStr)

proc close*(cl: DbClient) =
  cl.conn.close()

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
  let res = await cl.conn.exec(&"{selectCveFields} where year = $1 and sequence = $2", year, seq)
  let row = res[0].getRow()
  result = parseCveRow(row)

proc getCveByCveId*(cl: DbClient, cveId: string): Future[Cve] {.async.} =
  var param = cveId
  let res = await cl.conn.exec(&"{selectCveFields} where cve_id = $1", param)
  let row = res[0].getRow()
  result = parseCveRow(row)

proc getCvesByYear*(cl: DbClient; year, page: int = 0): Future[seq[Cve]] {.async.} =
  let offset = page * resultsPerPage
  let res = await cl.conn.exec(&"{selectCveFields} where extract(year from published_date) = $1 order by cve_pocs_count desc nulls last limit 10 offset $2", year, offset)
  for item in res[0].getAllRows():
    result.add parseCveRow(item)
