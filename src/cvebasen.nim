import std/[logging, uri, strutils]

# prologue framework imports
import
  prologue,
  prologue/middlewares/staticfile
# app-level imports
import
  globals,
  config,
  controllers/[cve_ctrl, researcher_ctrl, error_ctrl]
from db/pg import newAsyncPool


var cfg {.threadvar.}: config.Config

proc dbConnect*(connStr: string) =
  let uri = parseUri(connStr)
  # TODO: Make num of pool connections a config var
  db = newAsyncPool(uri.hostname, uri.username, uri.password, strip(uri.path, chars={'/'}), 20)

proc setLoggingLevel() =
  addHandler(newConsoleLogger())
  # when defined(release):
  logging.setLogFilter(lvlAll)
  #logging.setLogFilter(lvlError)

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

proc redirectCNVD(ctx: Context) {.async.} =
  resp redirect("/cve")

let
  cveRoutes* = @[
    pattern("/{year}/m/{month}", showCveMonth, @[HttpGet], "cveMonth"),
    pattern("/{year}/{sequence}", showCve, @[HttpGet], "cve"),
    pattern("/{year}", showCveYear, @[HttpGet], "cveYear"),
    pattern("/", showCveIndex, @[HttpGet], "cveIndex"),
  ]
  researcherRoutes* = @[
    pattern("/{alias}", showResearcher, @[HttpGet], "researcher"),
    pattern("/", showResearcherIndex, @[HttpGet], "researcherIndex"),
  ]
  pocRoutes* = @[
    pattern("/", showPocIndex, @[HttpGet], "pocIndex"),
  ]
  cnvdRoutes* = @[
    pattern("/{year}/{sequence}", redirectCNVD, @[HttpGet]),
    pattern("/", redirectCNVD, @[HttpGet]),
  ]


app.use(staticFileMiddleware(cfg.staticDir))
app.addRoute(cveRoutes, "/cve")
app.addRoute(researcherRoutes, "/researcher")
app.addRoute(pocRoutes, "/poc")
app.addRoute(cnvdRoutes, "/cnvd") # Redirect all CNVD to CVE index
app.registerErrorHandler(Http404, go404)
app.run()
