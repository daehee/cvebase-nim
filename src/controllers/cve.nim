import std/[strutils]

import prologue

import ../db/queries
import ../models/[cve, pagination]
import ../views/[layout_view, cve_view]

import ../globals

proc showCve*(ctx: Context) {.async.} =
  var year, seq: int
  year = parseInt(ctx.getPathParams("year"))
  seq = parseInt(ctx.getPathParams("sequence"))

  let cve = await db.getCveBySequence(year, seq)

  # TODO: Replace title
  resp renderMain(ctx.renderCve(cve), renderHero(cve), "CVE")

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
  resp renderMain(ctx.renderCveYear(pgn), "CVE Year")
