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
import db/dbutils

const pocDateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"

type
  GithubPoc = object
    cveId: string
    poc: Poc


proc parsePocFiles(repoDir: string, filepaths: seq[string]): seq[GithubPoc] =
  withDir(getCurrentDir() / repoDir):
    for fp in filepaths:
      if not fp.endsWith(".json"): continue
      # cveID
      let cveId = fp.split('/')[^1].split('.')[0]
      # poc
      let data = readFile(getCurrentDir() / fp).parseJson()
      for item in data:
        let poc = Poc(
          url: item["html_url"].getStr(),
          description: item["description"].getStr(),
          stars: item["stargazers_count"].getInt(),
          # createdAt: item["created_at"].getStr().parse(pocDateFormat, utc())
        )
        result.add GithubPoc(cveId: cveId, poc: poc)

when isMainModule:
  # TODO: nim-schedules to run process every X hours (instead of cron)
  let
    token = getEnv("GITHUB_TOKEN", "")
    dbUrl = getEnv("DATABASE_URL", "")
    metaFile = "PoC-in-GitHub.meta"

  if dbUrl == "":
    echo "DATABASE_URL env variable required"
    quit(1)

  if token == "":
    echo "github access token not provided"
    quit(1)

  # Set working dir
  # let workDir = getCurrentDir() / "tmp"
  if paramCount() == 0:
    echo "cmd parameter missing"
    quit(1)
  let workDir = paramStr(1)
  if not dirExists(workDir):
    echo "working dir does not exist: " & workDir
    quit(1)

  # Initialize db and github API clients
  let
    connStr = parseDbUrl(dbUrl)
    db = db_postgres.open("", "", "", connStr)
    cl = newGithubApiClient(token)

  let commitShas = cl.listCommitShas("nomi-sec", "PoC-in-GitHub")
  let headSha = commitShas[0]
  var lastSha: string
  # Check if meta file exists; if not, default to arbitrary previous commmit
  withDir workDir:
    try:
      # Check if already processed commit hash (in a stored meta file)
      lastSha = readFile(metaFile)
    except:
      # nomi-sec updates repo every 6 hours i.e. 4 times a day. So fetch last 24 hours to begin with...
      lastSha = commitShas[^4]

  if headSha == lastSha:
    echo "already up to date @ commit " & headSha
    quit(0)

  echo "last sha: " & lastSha
  echo "head sha: " & headSha

  let filesChanged = cl.getFilesChanged("nomi-sec", "PoC-in-GitHub", lastSha, headSha)

  echo "files changed: " & $len(filesChanged)

  let url = "https://github.com/nomi-sec/PoC-in-GitHub"
  let repoPath = url.loadGitRepo("master", workDir)

  ## Open actual poc json files in repo and parse the JSON
  let data = parsePocFiles(repoPath, filesChanged)

  echo "pocs to process: " & $len(data)

  for item in data:
    let
      poc = item.poc
      cveId = item.cveId

    let rows = db.getAllRows(sql("select id from cves where cve_id = ? limit 1"), @[cveId])
    if len(rows) == 0:
      echo poc.url
      echo "not found in db: " & cveId
      continue

    let cveRowId = rows[0][0]
    db.exec(sql("""INSERT INTO pocs (url, cve_id, description, stars, created_at)
VALUES (?, ?, ?, ?, now())
ON CONFLICT (cve_id, url) DO UPDATE SET description = ?, stars = ?, updated_at = now()"""), @[poc.url, cveRowId, poc.description, $poc.stars, poc.description, $poc.stars])

  ## Save headSha to meta file
  withDir workDir:
    writeFile(metaFile, headSha)
