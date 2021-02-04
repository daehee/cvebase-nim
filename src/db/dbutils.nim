import times, uri, strutils, strformat

const pgDateLayout* = "yyyy-MM-dd HH:mm:ss"

proc parsePgDateTime*(s: string): DateTime =
  # Example: "2006-01-02 15:15:00"
  let layout = pgDateLayout
  s.parse(layout, utc())


proc parseDbUrl*(dbUrl: string): string =
  ## Converts Postgres database URL to keyword/value connection string
  let
    uri = parseUri(dbUrl)
    database = strip(uri.path, chars={'/'})
  result.add &"user = {uri.username} password = {uri.password} host = {uri.hostname} port = {uri.port} dbname = {database}"
  if uri.query == "sslmode=require":
    result.add " sslmode = require"
