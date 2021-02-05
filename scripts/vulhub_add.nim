
import json, streams, uri, strutils, os, re
import os, strformat, strutils, uri, db_postgres

import lib/github/[client, repository]
import db/dbutils

proc toReadmePath(url: string): string =
  ## Converts repo url to README path
  let split = parseUri(url).path.split('/')
  result = split[^2..^1].join("/")
  result.add "/README.md"

proc fetchReadme(cl: GithubApiClient, url: string): string =
  # https://github.com/vulhub/vulhub/blob/master/activemq/CVE-2015-5254/README.md
  var res = cl.getContents("vulhub", "vulhub", url.toReadmePath())
  return res.bodyStream.readAll()

proc rewriteReadme(content: string, subDir: string): string =
  # TODO: translate from chinese to english
  # replace link destination from relative to absolute
  # ^\[([\w\s\d]+)\]\(((?:\/|https?:\/\/)[\w\d./?=#]+)\)$
  # replace image src from relative to absolute
  # !\[[^\]]*\]\((?<filename>.*?)(?=\"|\))\)
  result = content

  let rawBaseUrl = &"https://raw.githubusercontent.com/vulhub/vulhub/master/{subDir}"
  let imgRx = re"""!\[[^\]]*\]\((?<filename>.*?)(?=\"|\))\)"""
#  let linkRx = re"""[^!]?\[(.+)\]\((.+)\)"""
  result = result.replacef(imgRx, &"![]({rawBaseUrl}/$1)")
#  result = content.replace(linkRx, "")
  result = result.replace("[中文版本(Chinese version)](README.zh-cn.md)", "")
  result = strip(result)

proc toRepoSubdir(url: string): string =
  let split = parseUri(url).path.split('/')
  result = split[^2..^1].join("/")

when isMainModule:
  if paramCount() == 0:
    echo "no cmd parameters"
    quit(1)
  let cveId = paramStr(1)
  let vulhubUrl = paramStr(2)
  if cveId == "":
    echo "cve id required as cmd parameter 1"
    quit(1)
  if vulhubUrl == "":
    echo "vulhub url required as cmd parameter 2"
    quit(1)

  let
    connStr = parseDbUrl(getEnv("DATABASE_URL", ""))
    token = getEnv("GITHUB_TOKEN", "")
    db = db_postgres.open("", "", "", connStr)

  # find cve in db
  let rows = db.getAllRows(sql"select id from cves where cve_id = ? limit 1", @[cveId])
  if len(rows) == 0:
    echo "could not find cve"
    quit(1)
  let cveRowId = rows[0][0]
  echo &"found {cveId} at row {cveRowId}"

  # fetch README content
  var cl = newGithubApiClient(token)
  let content = cl.fetchReadme(vulhubUrl)
  if content == "":
    echo "empty README"
    quit(1)

  # rewrite README
  let rewrite = content.rewriteReadme(vulhubUrl.toRepoSubdir())

  # insert
  try:
    db.exec(sql("insert into vulhubs (url, readme_raw, readme, cve_id, created_at) values (?, ?, ?, ?, now())"), @[vulhubUrl, content, rewrite, cveRowId])
  except:
    let
      e = getCurrentException()
      msg = getCurrentExceptionMsg()
    echo "Got exception ", repr(e), " with message ", msg

  echo "done"
