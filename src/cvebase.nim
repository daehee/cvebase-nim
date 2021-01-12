# This is just an example to get you started. A typical hybrid package
# uses this file as the main entry point of the application.

import htmlgen
import jester
import strutils

import config
import routes/[cve]
import db

const configPath {.strdefine.} = "./cvebase.conf"
let (cfg, fullCfg) = getConfig(configPath)

dbClient = waitFor initDbClient("postgres://postgres:yeetya123@localhost:5432/cvebase_development")

settings:
  port = Port(cfg.port)
  staticDir = cfg.staticDir
  bindAddr = cfg.address

# Initialize routes
# /
# /cve
# /poc
# /researcher
# /bugbounty
# /lab

router cve: # namespace: /cve
  get "/@year/@sequence":
    var year, sequence: int
    try:
      year = parseInt(@"year")
      sequence = parseInt(@"sequence")
    except ValueError:
      raise
    let cve = await dbClient.getCveBySequence(year, sequence)
    resp showCve(request, cve)

routes:
  get "/":
    resp h1("Hello world")

  error Http404:
    # FIXME replace with debug logging
    echo "error 404: " & request.ip & " -> " & request.path
    resp Http404, "Looks like you took a wrong turn somewhere."

  error Exception:
    # FIXME replace with debug logging
    echo "error 500: " & request.ip & " -> " & request.path & " : " & exception.msg
    resp Http500, "Something bad happened."

  # Extend routes with custom routers
  extend cve, "/cve"

