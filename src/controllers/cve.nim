import std/[strutils]

import prologue

import ../db/queries
import ../models/cve
import ../views/[layout_view, cve_view]

import ../globals

proc showCve*(ctx: Context) {.async.} =
  var year, seq: int
  year = parseInt(ctx.getPathParams("year"))
  seq = parseInt(ctx.getPathParams("sequence"))

  let cve = await db.getCveBySequence(year, seq)

  # TODO: Replace title
  resp renderMain(renderCve(cve), renderHero(cve), "CVE")

proc showCveYear*(ctx: Context) {.async.} =
  var year: int
  year = parseInt(ctx.getPathParams("year"))
  let pageParam = ctx.getQueryParams("page")
  var cves: seq[Cve]
  if pageParam != "":
    let pageNum = parseInt(pageParam)
    cves = await db.getCvesByYear(year, pageNum)
  else:
    cves = await db.getCvesByYear(year)
  if len(cves) == 0:
    respDefault Http404
    return
  # TODO: Replace title
  # https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-ix-pagination
  # If cves.hasNext
#  nextUrl = linkTo()
#  prevUrl =
  resp renderMain(ctx.renderCveYear(cves), "CVE Year")
