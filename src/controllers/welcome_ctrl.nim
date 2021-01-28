import std/[strutils]

import prologue

import
  ../globals,
  ../db/queries,
  ../views/[layout_view, welcome_view]

proc showWelcome*(ctx: Context) {.async.} =
  #[
    @cves = Cve.get_welcome_cves
    @hacktivities = Hacktivity.get_hacktivities_with_cves.limit(5)
    @researchers = Researcher.limit(3).order("RANDOM()")
   ]#
  let researchers = await db.getWelcomeResearchers()
  let cves = await db.getWelcomeCves()
  let hacktivities = await db.getWelcomeHacktivities()

  ctx.ctxData["title"] = "cvebase: Discover CVE vulnerabilities & PoC exploits"
  ctx.ctxData["description"] = "Share, discuss, and reverse the latest security vulnerabilities and PoC exploits. Join the thousands of security researchers, pentesters, and bug bounty hunters who use cvebase as their vulnerability knowledge base."

  resp ctx.renderMain(ctx.renderWelcome(researchers, cves, hacktivities))
