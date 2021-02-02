import std/[strutils]

import prologue

import
  ../globals,
  ../views/[layout_view, researcher_view]

proc showResearcher*(ctx: Context) {.async.} =
  let alias = ctx.getPathParams("alias")

  let pageParam = ctx.getQueryParams("page")
  var pgn: Pagination[Cve]
  try:
    let researcher = await db.getResearcher(alias)
    if pageParam != "":
      let pageNum = parseInt(pageParam)
      pgn = await db.getResearcherCves(researcher.id, pageNum)
    else:
      pgn = await db.getResearcherCves(researcher.id)

    ctx.ctxData["title"] = researcher.name
    ctx.ctxData["description"] = researcher.bio.truncate(160)

    resp ctx.renderMain(ctx.renderResearcher(researcher, pgn), renderHero(researcher.name))
  except NotFoundException:
    respDefault Http404
    return
  except PGError:
    respDefault Http404
    return

proc showResearcherIndex*(ctx: Context) {.async.} =
  let leaders = await db.getResearcherLeaderboard()
  let activity = await db.getResearchersCveActivity()

  ctx.ctxData["title"] = "Top CVE Security Researchers"
  ctx.ctxData["description"] = "The latest exploits from the world's top security researchers"

  resp ctx.renderMain(ctx.renderResearcherIndex(leaders, activity))
