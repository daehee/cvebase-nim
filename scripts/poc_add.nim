## Adds Pocs from nomi-sec GitHub repo

import
  db_postgres,
  json,
  os,
  strformat,
  strutils,
  times,
  uri

import lib/github/[client, repository]
import lib/gitrepo/repo
import models/cve

const pocDateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"

proc parsePocFiles(repoDir: string, filepaths: seq[string]): seq[Poc] =
  withDir(getCurrentDir() / repoDir):
    for fp in filepaths:
      if not fp.endsWith(".json"): continue
      let data = readFile(getCurrentDir() / fp).parseJson()
      for item in data:
        let poc = Poc(
          url: item["html_url"].getStr(),
          description: item["description"].getStr(),
          stars: item["stargazers_count"].getInt(),
          createdAt: item["created_at"].getStr().parse(pocDateFormat, utc())
        )
        result.add poc

when isMainModule:
  let
    token = getEnv("GITHUB_TOKEN", "")
    workDir = getCurrentDir() / "tmp"
    metaFile = "PoC-in-GitHub.meta"

  echo "github access token: " & token
  var cl = newGithubApiClient(token)

  ## Check if already processed commit hash (in a stored meta file)
  var lastSha: string
  withDir workDir:
    lastSha = readFile(metaFile)

  let headSha = cl.getHeadCommit("nomi-sec", "PoC-in-GitHub")
  if headSha == lastSha:
    echo "already up to date @ commit " & headSha
    quit(0)

  let filesChanged = cl.getFilesChanged("nomi-sec", "PoC-in-GitHub", lastSha, headSha)

  let url = "https://github.com/nomi-sec/PoC-in-GitHub"
  url.loadGitRepo("master", workDir)

  ## Open actual poc json files in repo and parse the JSON
  let pocs = parsePocFiles("tmp/PoC-in-GitHub", filesChanged)
  for poc in pocs:
    echo poc.url
    echo poc.description
    echo poc.stars
    echo poc.createdAt.format("yyyy-MM-dd")

  ## Compare fetched Pocs with what's in the db pocs table

  ## Save headSha to meta file
  withDir workDir:
    writeFile(metaFile, headSha)
