import std/[logging]

import prologue
import prologue/middlewares/staticfile

import config
import routes
#import controllers/[cve]
import db

var cfg {.threadvar.}: config.Config
cfg = configureApp()

proc setLoggingLevel() =
  addHandler(newConsoleLogger())
  when defined(release):
    logging.setLogFilter(lvlError)
  else:
    logging.setLogFilter(lvlAll)

proc setDbClient() {.gcsafe.} =
  dbClient = initDbClient(cfg.dbUrl)

let
  logEvent = initEvent(setLoggingLevel)
  dbEvent = initEvent(setDbClient)

#dbClient = initDbClient(cfg.dbUrl)

let settings = newSettings(
  appName = cfg.appName,
  debug = cfg.debug,         # TODO get this from config
  port = Port(cfg.port),
  secretKey = cfg.secretKey,   # TODO get this from config
)
var app = newApp(settings = settings, startup = @[logEvent, dbEvent])

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

