import std/[logging]

import prologue
import prologue/middlewares/staticfile

import config
import routes
#import controllers/[cve]
import db

const configPath {.strdefine.} = "./cvebase.conf"

proc setLoggingLevel() =
  addHandler(newConsoleLogger())
  logging.setLogFilter(lvlAll)

let
  event = initEvent(setLoggingLevel)
  (cfg, fullCfg) = getConfig(configPath)

# Initialize postgres DB
dbClient = waitFor initDbClient(cfg.dbConn)

let settings = newSettings(
  appName = "cvebase",
  debug = true,         # TODO get this from config
  port = Port(cfg.port),
  secretKey = "test",   # TODO get this from config
)
var app = newApp(settings = settings, startup = @[event])

app.use(staticFileMiddleware(cfg.staticDir))
app.addRoute(routes.cvePatterns, "/cve")
app.run()

# Set jester settings
#settings:
#  port = Port(cfg.port)
#  staticDir = cfg.staticDir
#  bindAddr = cfg.address

# Initialize routes
# /
# /cve
# /poc
# /researcher
# /bugbounty
# /lab

#router cve: # namespace: /cve
#  get "/@year/@sequence":
#    resp await showCve(request, @"year", @"sequence")
#  get "/@year?page=@page":
#    resp await showCveYear(request, @"year", @"page")
#  get "/@year":
#    resp await showCveYear(request, @"year")
#
#routes:
#  get "/":
#    resp h1("Hello world")
#
#  error Http404:
#    echo "error 404: " & request.ip & " -> " & request.path
#    resp Http404, "Looks like you took a wrong turn somewhere."
#
#  error Exception:
#    echo "error 500: " & request.ip & " -> " & request.path & " : " & exception.msg
#    resp Http500, "Something bad happened."
#
#  # Extend routes with custom routers declared above
#  extend cve, "/cve"

