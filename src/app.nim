import std/[logging]

import prologue
import prologue/middlewares/staticfile
import pg

import config
import routes
#import controllers/[cve]
import database

var cfg {.threadvar.}: config.Config

proc setLoggingLevel() =
  addHandler(newConsoleLogger())
  # when defined(release):
  #   logging.setLogFilter(lvlError)
  # else:
  logging.setLogFilter(lvlAll)

cfg = configureApp()
dbConnect(cfg.dbUrl)

let
  logEvent = initEvent(setLoggingLevel)
  settings = newSettings(
    appName = cfg.appName,
    debug = cfg.debug,
    port = Port(cfg.port),
    secretKey = cfg.secretKey,
  )
var app = newApp(settings = settings, startup = @[logEvent])

# Serve static files from CDN in production
# when not defined(release):
app.use(staticFileMiddleware(cfg.staticDir))
app.addRoute(routes.cvePatterns, "/cve")
app.run()

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

