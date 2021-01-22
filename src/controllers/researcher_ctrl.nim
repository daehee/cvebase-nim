import std/[strutils]

import prologue

import
  ../globals,
  ../db/queries,
  ../models/[researcher, cve, pagination],
  ../views/[layout_view, researcher_view],
  ../helpers/app_helper

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
