import std/[strutils, strformat, times]

import prologue

import
  ../globals,
  ../db/queries,
  ../models/[cve, pagination],
  ../views/[layout_view, cve_view],
  ../helpers/app_helper

let currentYear = now().year

proc isValidYear(year: int): bool =
  if year in 1996..currentYear: return true

proc isValidMonth(month: int): bool =
  if month in 1..12: return true


proc showCve*(ctx: Context) {.async.} =
  var year, seq: int
  try:
    year = parseInt(ctx.getPathParams("year"))
    seq = parseInt(ctx.getPathParams("sequence"))
  except:
    respDefault Http404
    return

  if not year.isValidYear():
    respDefault Http404
    return

  try:
    let cve = await db.getCveBySequence(year, seq)
    let researchers = await db.getResearchersByCveId(cve.id)
    ctx.ctxData["title"] = cve.titleTag
    ctx.ctxData["description"] = cve.description.truncate(160)

    resp ctx.renderMain(ctx.renderCve(cve, researchers), renderHero(cve.cveId))
  except NotFoundException:
    respDefault Http404
    return
  except PGError:
    respDefault Http404
    return


proc showCveYear*(ctx: Context) {.async.} =
  var year: int
  year = parseInt(ctx.getPathParams("year"))
  if not year.isValidYear():
    respDefault Http404
    return

  let pageParam = ctx.getQueryParams("page")
  var pgn: Pagination[Cve]
  try:
    if pageParam != "":
      let pageNum = parseInt(pageParam)
      pgn = await db.getCvesByYear(year, pageNum)
    else:
      pgn = await db.getCvesByYear(year)
  except PGError:
    respDefault Http404
    return

  if len(pgn.items) == 0:
    respDefault Http404
    return

  # Sidebar date items
  let
    allYears = await db.getCveYears()
    yearMonths = await db.getCveYearMonths(year)

  # Set year in ctx using first cve item (prevent injection of variable in template)
  let
    aCve = pgn.items[0]
    yearStr = $aCve.pubDate.year
  ctx.ctxData["year"] = yearStr
  ctx.ctxData["title"] = &"CVEs Published in {yearStr}"
  ctx.ctxData["description"] = &"Browse the top 100 CVE vulnerabilities of {yearStr} by PoC exploits available."

  resp ctx.renderMain(ctx.renderCveYear(pgn, allYears, yearMonths), renderHero(&"Most Exploitable CVEs of {yearStr}"))

proc showCveMonth*(ctx: Context) {.async.} =
  var year, month: int
  year = parseInt(ctx.getPathParams("year"))
  if not year.isValidYear():
    respDefault Http404
    return
  month = parseInt(ctx.getPathParams("month"))
  if not month.isValidMonth():
    respDefault Http404
    return

  let pageParam = ctx.getQueryParams("page")
  var pgn: Pagination[Cve]
  if pageParam != "":
    let pageNum = parseInt(pageParam)
    pgn = await db.getCvesByMonth(year, month, pageNum)
  else:
    pgn = await db.getCvesByMonth(year, month)
  if len(pgn.items) == 0:
    respDefault Http404
    return

  # Sidebar date items
  let
    allYears = await db.getCveYears()
    yearMonths = await db.getCveYearMonths(year)

  # Set year in ctx using first cve item (prevent injection of variable in template)
  let
    aCve = pgn.items[0]
    yearStr = $aCve.pubDate.year
    monthNum = $aCve.pubDate.month.ord
    monthStr = $parseInt(monthNum).Month
  ctx.ctxData["year"] = yearStr
  ctx.ctxData["month"] = monthNum
  ctx.ctxData["title"] = &"CVEs Published in {monthStr} {yearStr}"
  ctx.ctxData["description"] = &"Browse CVE vulnerabilities published in {monthStr} {yearStr}."

  resp ctx.renderMain(ctx.renderCveMonth(pgn, allYears, yearMonths), renderHero(&"CVEs Published in {monthStr} {yearStr}"))

proc showCveIndex*(ctx: Context) {.async.} =
  let pageParam = ctx.getQueryParams("page")
  var pgn: Pagination[Cve]
  if pageParam != "":
    let pageNum = parseInt(pageParam)
    pgn = await db.getCvesIndex(pageNum)
  else:
    pgn = await db.getCvesIndex()
  if len(pgn.items) == 0:
    respDefault Http404
    return

  let allYears = await db.getCveYears()

  let
    today = now()
    month = today.month
    day = today.monthday

  ctx.ctxData["title"] = &"Today's Trending CVE Vulnerabilities"
  ctx.ctxData["description"] = &"Check out the latest CVE vulnerabilities the infosec community is talking about."

  resp ctx.renderMain(ctx.renderCveIndex(pgn, allYears), renderHero(&"Trending CVEs for {month} {day}"))

proc showPocIndex*(ctx: Context) {.async.} =
  let leaders = await db.getPocLeaderboard()
  let activity = await db.getCvesPocActivity()

  ctx.ctxData["title"] = &"Top CVEs with Proof-of-Concept Exploits"
  ctx.ctxData["description"] = &"Top-Ranked CVE Vulnerabilities with Open-Source Proof-of-Concept Exploits"

  resp ctx.renderMain(ctx.renderPocIndex(leaders, activity))

proc showProduct*(ctx: Context) {.async.} =
  let slug = ctx.getPathParams("slug")

  var product: Product
  try:
    product = await db.getProduct(slug)
  except NotFoundException:
    # if param converts to int, try fallback to id instead of slug
    var tmpId: int
    try:
      tmpId = parseInt(slug)
    except ValueError:
      respDefault Http404
      return

    try:
      # if found, redirect to slug
      product = await db.getProductById(tmpId)
      resp redirect(&"/product/{product.slug}")
      return
    except NotFoundException:
      respDefault Http404
      return
  except PGError:
    respDefault Http404
    return

  let pageParam = ctx.getQueryParams("page")
  var pgn: Pagination[Cve]
  # get related Cves
  if pageParam != "":
    let pageNum = parseInt(pageParam)
    pgn = await db.getProductCves(product.id, pageNum)
  else:
    pgn = await db.getProductCves(product.id)

  # <Product> Vulnerabilities (<Num> CVEs)
  ctx.ctxData["title"] = &"{product.name} Vulnerabilities (CVEs)"
  # <Num> CVEs are published for <Product> by <Vendor>. Browse vulnerability data and PoC exploits for <Product>.
#    ctx.ctxData["description"] =
  let heroTitle = &"{product.name} Vulnerabilities"

  resp ctx.renderMain(ctx.renderProduct(product, pgn), renderHero(heroTitle))
