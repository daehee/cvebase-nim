import asyncdispatch, strformat, json, tables
import asyncpg

import models/[cve]
export cve

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

template parseCveRow*(row: Row): Cve =
  let
    cveId = row[1]
    cveData = parseJson(row[2])
    description = cveData["cve"]["description"]["description_data"][0]["value"].getStr()
    pubDate = parsePgDateTime(cveData["publishedDate"].getStr())
  Cve(cveId: cveId, description: description, pubDate: pubDate)

proc getCveBySequence*(cl: DbClient; year, seq: int): Future[Cve] {.async.} =
  var params = {"year": year, "seq": seq}.toTable
  let res = await cl.conn.exec("select id, cve_id, data from cves where year = $1 and sequence = $2", params["year"], params["seq"])
  let row = res[0].getRow()
  result = parseCveRow(row)

proc getCveByCveId*(cl: DbClient, cveId: string): Future[Cve] {.async.} =
  var param = cveId
  let res = await cl.conn.exec("select id, cve_id, data from cves where cve_id = $1", param)
  let row = res[0].getRow()
  result = parseCveRow(row)

proc close*(cl: DbClient) =
  cl.conn.close()

