import
  strutils

import prologue

import
  ../globals,
  ../views/[layout_view, search_view]


proc searchCve*(ctx: Context) {.async.} =
  ## Search Cves shows search results matching the GET parameter `query`
  ctx.ctxData["title"] = "Search Results"
  # check if blank query
  let queryParam = ctx.getQueryParams("query")
  if queryParam == "":
    resp ctx.renderMain(ctx.renderSearchEmpty, renderHero("Search Results"))
    return


  # do query
  let pageParam = ctx.getQueryParams("page")
  var pgn: Pagination[Cve]
  # get related Cves
  if pageParam != "":
    let pageNum = parseInt(pageParam)
    pgn = await db.searchByCveId(queryParam, pageNum)
  else:
    pgn = await db.searchByCveId(queryParam)

  # check if no results
  if len(pgn.items) == 0:
    resp ctx.renderMain(ctx.renderSearchEmpty, renderHero("Search Results"))
    return

  # render results
  # FIXME: queryParam could be an injection point
  resp ctx.renderMain(ctx.renderSearch(pgn, queryParam), renderHero("Search Results"))
