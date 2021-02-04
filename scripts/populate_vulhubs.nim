import json, streams, uri, strutils, os, re
import os, strformat, strutils, uri, db_postgres

import lib/github/[client, repository]
import db/dbutils


proc toReadmePath(url: string): string =
  ## Converts repo url to README path
  let split = parseUri(url).path.split('/')
  result = split[^2..^1].join("/")
  result.add "/README.md"


proc toRepoSubdir(url: string): string =
  let split = parseUri(url).path.split('/')
  result = split[^2..^1].join("/")


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

  let rawBaseUrl = &"https://raw.githubusercontent.com/vulhub/vulhub/master/{subDir}"
  let imgRx = re"""!\[[^\]]*\]\((?<filename>.*?)(?=\"|\))\)"""
  let linkRx = re"""\[(.+)\]\((.+)\)(\n\n)?"""
  result = content.replace(linkRx, &"")
  result = result.replacef(imgRx, &"![]({rawBaseUrl}/$1)")


type
  Vulhub = object
    rowId: string
    url: string
    readmeRaw: string


when isMainModule:
  let
    connStr = parseDbUrl(getEnv("DATABASE_URL", ""))
    token = getEnv("GITHUB_TOKEN", "")
    db = db_postgres.open("", "", "", connStr)

  echo "github access token: " & token

  var vulhubs: seq[Vulhub]
#  let rows1 = db.getAllRows(sql"select id, url from vulhubs where content is NULL")
  let rows1 = db.getAllRows(sql"select id, url, readme_raw from vulhubs")
  for row in rows1:
    vulhubs.add Vulhub(rowId: row[0], url: row[1], readmeRaw: row[2])

  when defined(populate):
    echo &"populating {len(vulhubs)} vulhubs"

    var cl = newGithubApiClient(token)
    for vulhub in vulhubs:
      let content = cl.fetchReadme(vulhub.url)
      try:
        db.exec(sql("update vulhubs set readme_raw = ? where id = ?"), @[content, vulhub.rowId])
      except:
        let
          e = getCurrentException()
          msg = getCurrentExceptionMsg()
        echo "Got exception ", repr(e), " with message ", msg

      echo &"{vulhub.rowId}: {vulhub.url}"

  when defined(rewrite):
    for vulhub in vulhubs:
      let readme = rewriteReadme(vulhub.readmeRaw, vulhub.url.toRepoSubdir())
      try:
        db.exec(sql("update vulhubs set readme = ? where id = ?"), @[readme, vulhub.rowId])
      except:
        let
          e = getCurrentException()
          msg = getCurrentExceptionMsg()
        echo "Got exception ", repr(e), " with message ", msg

  echo "done"
  db.close()
