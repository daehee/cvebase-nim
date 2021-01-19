import std/[logging, uri, strutils]

# prologue framework imports
import
  prologue,
  prologue/middlewares/staticfile
# app-level imports
import
  globals,
  config,
  controllers/cve
from db/pg import newAsyncPool


var cfg {.threadvar.}: config.Config

proc dbConnect*(connStr: string) =
  let uri = parseUri(connStr)
  # TODO: Make num of pool connections a config var
  db = newAsyncPool(uri.hostname, uri.username, uri.password, strip(uri.path, chars={'/'}), 20)

proc setLoggingLevel() =
  addHandler(newConsoleLogger())
  # when defined(release):
  #   logging.setLogFilter(lvlError)
  # else:
  logging.setLogFilter(lvlAll)

cfg = configureApp()
dbConnect(cfg.dbUrl)

# TODO: Set shutdown event to close db connections

let
  loggerEvent = initEvent(setLoggingLevel)
  settings = newSettings(
    appName = cfg.appName,
    debug = cfg.debug,
    port = Port(cfg.port),
    secretKey = cfg.secretKey,
  )
var app = newApp(settings = settings, startup = @[loggerEvent])

# Initialize routes
# /
# /cve
# /poc
# /researcher
# /bugbounty
# /lab

let
  cveRoutes* = @[
    pattern("/{year}/{sequence}", showCve, @[HttpGet], "cve"),
    pattern("/{year}", showCveYear, @[HttpGet], "cveYear"),
  ]

proc go404*(ctx: Context) {.async.} =
  ## Custom 404 error handler
  resp "Looks like you took a wrong turn somewhere.", Http404

app.use(staticFileMiddleware(cfg.staticDir))
app.addRoute(cveRoutes, "/cve")
app.registerErrorHandler(Http404, go404)
app.run()

