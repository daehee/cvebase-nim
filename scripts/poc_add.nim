## Adds Pocs from nomi-sec GitHub repo

import
  json, streams, uri, os, re, sequtils, os, strformat,
  strutils, uri, db_postgres, osproc, times

import lib/github/[client, repository]
import models/cve

template withDir(dir, body) =
   let old = getCurrentDir()
   try:
     setCurrentDir(dir)
     body
   finally:
     setCurrentDir(old)

const pocDateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"

proc parsePocFile(fileStr: string): seq[Poc] =
  let data = parseJson(fileStr)
  for item in data:
    result.add Poc(
      url: item["html_url"].getStr(),
      description: item["description"].getStr(),
      stars: item["stargazers_count"].getInt(),
      createdAt: item["created_at"].getStr().parse(pocDateFormat, utc())
    )

when isMainModule:
  ## check latest push in PoC-In-Github repo
  ## check if already processed commit hash (in a stored meta file)
  ## get files changed in the push
  ## process contents of json files

  let token = getEnv("GITHUB_TOKEN", "")

  echo "github access token: " & token
  var cl = newGithubApiClient(token)

  var headSha, lastSha: string

  # TODO: Set lastSha based on meta file
  lastSha = "e7c4705e00c1e77d79b7ca2fa84e7fdb95f50365"

  block:
    ## Fetch latest commit hash
    let resp = cl.listCommits("nomi-sec", "PoC-in-GitHub")
    let data = parseJson(resp.bodyStream.readAll())
    headSha = data[0]["sha"].getStr()

  if headSha == lastSha:
    echo "already up to date"
    echo headSha
    quit(1)

  var filesChanged = newSeq[string]()
  block:
    ## Compare files changed between last and head commits
    let resp = cl.compareCommits("nomi-sec", "PoC-in-GitHub", lastSha, headSha)
    let data = parseJson(resp.bodyStream.readAll())
    filesChanged = data["files"].mapIt(it["filename"].getStr())

  block:
    ## Prepare local repo
    let url = "https://github.com/nomi-sec/PoC-in-GitHub"
    withDir "./tmp":
      if not dirExists("PoC-in-GitHub"):
        let code = execCmd(&"git clone -q {url}")
        if code > 0:
          raise newOSError(code.OSErrorCode, "error git clone")

  block:
    ## Open actual poc json files in repo and parse the JSON
    withDir "./tmp/PoC-in-GitHub":
      let f = readFile(filesChanged[0])
      let parsed = parsePocFile(f)
      for poc in parsed:
        echo poc.url
        echo poc.description
        echo poc.stars
        echo poc.createdAt.format("yyyy-MM-dd")
