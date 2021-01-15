import std/[strutils]
import jester

import ../db
import ../views/[layout_view, cve_view]

proc showCve*(request: Request; paramYear, paramSeq: string): Future[string] {.async.} =
  var year, seq: int
  year = parseInt(paramYear)
  seq = parseInt(paramSeq)

  let cve = await dbClient.getCveBySequence(year, seq)

  return renderMain(renderCve(cve), renderHero(cve), request, "CVE")

proc showCveYear*(request: Request, paramYear: string): Future[string] {.async.} =
  var year: int
  year = parseInt(paramYear)

  let cves = await dbClient.getCvesByYear(year)
  return renderMain(renderCveYear(cves), request, "CVE Year")

proc showCveYear*(request: Request; paramYear, paramPage: string): Future[string] {.async.} =
  var year: int
  year = parseInt(paramYear)

  let cves = await dbClient.getCvesByYear(year)
  return renderMain(renderCveYear(cves), request, "CVE Year")
