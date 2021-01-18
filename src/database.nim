import std/[asyncdispatch, strformat, json, tables, times, strutils, uri, options]
import db/pg

import models/[cve]

var db* {.threadvar.}: AsyncPool

proc dbConnect*(connStr: string) =
  let uri = parseUri(connStr)
  # TODO make pool connections a config variable
  db = newAsyncPool(uri.hostname, uri.username, uri.password, strip(uri.path, chars={'/'}), 20)


