import os, strformat, strutils, uri, db_postgres

proc parseDbUrl*(dbUrl: string): string =
  ## Converts Postgres database URL to keyword/value connection string
  let
    uri = parseUri(dbUrl)
    database = strip(uri.path, chars={'/'})

  result.add &"user = {uri.username} password = {uri.password} host = {uri.hostname} port = {uri.port} dbname = {database}"

  if uri.query == "sslmode=require":
    result.add " sslmode = require"

let
  connStr = parseDbUrl(getEnv("DATABASE_URL", ""))
  db = db_postgres.open("", "", "", connStr)


# check each researcher github profile against pocs database
let rows1 = db.getAllRows(sql"select id, github from researchers where github <> ''")
for row in rows1:
  # find researcher username matching pocs
  let
    username = row[1]
    researcherId = row[0]

  let rows2 = db.getAllRows(sql(&"select id, url from pocs where url ~ 'github.com/{username}'"))
  for row in rows2:
    let
      pocId = row[0]
      pocUrl = row[1]
    # add researcher_id to poc
    try:
      db.exec(sql("update pocs set researcher_id = ? where id = ?"), @[researcherId, pocId])
    except:
      let
        e = getCurrentException()
        msg = getCurrentExceptionMsg()
      echo "Got exception ", repr(e), " with message ", msg

    echo &"match: {username} -> {pocUrl}"

db.close()
