# This is just an example to get you started. A typical hybrid package
# uses this file as the main entry point of the application.

import config
import htmlgen
import jester
import routes/[cve]

const configPath {.strdefine.} = "./cvebase.conf"
let (cfg, fullCfg) = getConfig(configPath)

# Initialize controllers
# createWelcomeRouter() # /
createCveRouter() # /cve
# /poc
# /researcher
# /bugbounty
# /lab


settings:
  port = Port(cfg.port)
  staticDir = cfg.staticDir
  bindAddr = cfg.address

routes:
  get "/":
    resp h1("Hello world")

  error Http404:
    resp Http404, "Looks you took a wrong turn somewhere."

  error Exception:
    resp Http500, "Something bad happened: " & exception.msg

#  error Http404:
#    resp Http404, or("Page not found", cfg)

  # Extend routes with custom routers
  extend cve, "/cve"

