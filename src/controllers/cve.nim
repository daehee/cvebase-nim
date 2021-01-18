import std/[strutils]

import prologue

import ../db/queries
import ../views/[layout_view, cve_view]

import ../globals

proc showCve*(ctx: Context) {.async.} =
  var year, seq: int
  year = parseInt(ctx.getPathParams("year"))
  seq = parseInt(ctx.getPathParams("sequence"))

  let cve = await db.getCveBySequence(year, seq)

  resp renderMain(renderCve(cve), renderHero(cve), "CVE")

#proc showCveYear*(request: Request, paramYear: string): Future[string] {.async.} =
#  var year: int
#  year = parseInt(paramYear)
#
#  let cves = await dbClient.getCvesByYear(year)
#  return renderMain(renderCveYear(cves), request, "CVE Year")
#
#proc showCveYear*(request: Request; paramYear, paramPage: string): Future[string] {.async.} =
#  var year: int
#  year = parseInt(paramYear)
#
#  let cves = await dbClient.getCvesByYear(year)
#  return renderMain(renderCveYear(cves), request, "CVE Year")
