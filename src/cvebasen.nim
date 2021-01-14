# This is just an example to get you started. A typical hybrid package
# uses this file as the main entry point of the application.

import htmlgen
import jester

import config
import controllers/[cve]
import db

const configPath {.strdefine.} = "./cvebase.conf"
let (cfg, fullCfg) = getConfig(configPath)

# Initialize postgres DB
dbClient = waitFor initDbClient(cfg.dbConn)

# Set jester settings
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
    resp await showCve(request, @"year", @"sequence")

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

  # Extend routes with custom routers declared above
  extend cve, "/cve"

