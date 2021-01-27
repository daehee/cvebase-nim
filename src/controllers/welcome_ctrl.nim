import std/[strutils]

import prologue

import
  ../globals,
  ../db/queries,
  ../models/[researcher, cve],
  ../views/[layout_view, welcome_view]

proc showWelcome*(ctx: Context) {.async.} =
  #[
    @cves = Cve.get_welcome_cves
    @hacktivities = Hacktivity.get_hacktivities_with_cves.limit(5)
    @researchers = Researcher.limit(3).order("RANDOM()")
   ]#
  let researchers = await db.getWelcomeResearchers()

  resp ctx.renderMain(ctx.renderWelcome(researchers))
