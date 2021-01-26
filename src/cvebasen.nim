import std/[logging, uri, strutils, strformat]

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
  let
    uri = parseUri(connStr)
    database = strip(uri.path, chars={'/'})

  var connKV = &"user = {uri.username} password = {uri.password} host = {uri.hostname} port = {uri.port} dbname = {database}"

  if uri.query == "sslmode=require":
    connKV.add " sslmode = require"

  # set db global variable
  # TODO: Make num of pool connections a config var
  db = newAsyncPool("", "", "", connKV, 20)

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

proc redirectToCve(ctx: Context) {.async.} =
  resp redirect("/cve")

let
  cveRoutes* = @[
    pattern("/tag/{tag}", redirectToCve, @[HttpGet], "cveTag"),
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
  productRoutes* = @[
    pattern("/{slug}", showProduct, @[HttpGet], "product"),
  ]
  cnvdRoutes* = @[
    pattern("/{year}/{sequence}", redirectToCve, @[HttpGet]),
    pattern("/", redirectToCve, @[HttpGet]),
  ]


app.use(staticFileMiddleware(cfg.staticDir))
app.addRoute(cveRoutes, "/cve")
app.addRoute(researcherRoutes, "/researcher")
app.addRoute(productRoutes, "/product")
app.addRoute(pocRoutes, "/poc")
app.addRoute("/bugbounty", showHacktivities, HttpGet, "hacktivityIndex")
#app.addRoute("/labs", showLabs, HttpGet)
app.addRoute(cnvdRoutes, "/cnvd") # Redirect all CNVD to CVE index
#app.addRoute("/", showWelcome, HttpGet)
app.registerErrorHandler(Http404, go404)
app.run()
