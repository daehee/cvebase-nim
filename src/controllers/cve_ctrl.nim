import std/[strutils]

import prologue

import
  ../globals,
  ../db/queries,
  ../models/[cve, pagination],
  ../views/[layout_view, cve_view]

proc showCve*(ctx: Context) {.async.} =
  var year, seq: int
  year = parseInt(ctx.getPathParams("year"))
  seq = parseInt(ctx.getPathParams("sequence"))

  let cve = await db.getCveBySequence(year, seq)

  ctx.ctxData["title"] = cve.titleTag
#  ctx.ctxData["description"] = ""

  resp ctx.renderMain(ctx.renderCve(cve), renderHero(cve))

proc showCveYear*(ctx: Context) {.async.} =
  var year: int
  year = parseInt(ctx.getPathParams("year"))
  let pageParam = ctx.getQueryParams("page")
  var pgn: Pagination[Cve]
  if pageParam != "":
    let pageNum = parseInt(pageParam)
    pgn = await db.getCvesByYear(year, pageNum)
  else:
    pgn = await db.getCvesByYear(year)
  if len(pgn.items) == 0:
    respDefault Http404
    return
  # TODO: Replace title
  # Set year in ctx using first cve item (prevent injection of variable in template)
  ctx.ctxData["year"] = $pgn.items[0].year
  resp ctx.renderMain(ctx.renderCveYear(pgn))
