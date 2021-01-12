import asyncdispatch, strformat, json, tables
import asyncpg

import models/[cve]

type
  DbClient* = ref object
    conn: apgPool
    connStr: string

proc initDbClient*(connStr: string): Future[DBClient] {.async.} =
  let pool = newPool()
  await pool.connect(connStr)
  return DBClient(conn: pool, connStr: connStr)

proc checkHealth*(cl: DbClient): Future[string] {.async.} =
  let tmpConn = await connect(cl.connStr)
  let ver = tmpConn.getServerVersion()
  result = $ver
  tmpConn.close()

template parseCveRow*(row: Row): Cve =
  let
    cveId = row[1]
    cveData = parseJson(row[2])
    description = cveData["cve"]["description"]["description_data"][0]["value"].getStr()
  Cve(cveId: cveId, description: description)

proc getCveBySequence*(cl: DbClient; year, seq: int): Future[Cve] {.async.} =
  # TODO move this to models?
  var params = {"year": year, "seq": seq}.toTable
  let res = await cl.conn.exec("select id, cve_id, data from cves where year = $1 and sequence = $2", params["year"], params["seq"])
  let row = res[0].getRow()
  result = parseCveRow(row)

proc getCveByCveId*(cl: DbClient, cveId: string): Future[Cve] {.async.} =
  # TODO move this to models?
  var param = cveId
  let res = await cl.conn.exec("select id, cve_id, data from cves where cve_id = $1", param)
  let row = res[0].getRow()
  result = parseCveRow(row)

proc close*(cl: DbClient) =
  cl.conn.close()

#proc connect
# Establish connection to PostgreSQL server

#proc get
