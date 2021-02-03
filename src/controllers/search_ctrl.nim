import prologue

import
  ../globals,
  ../views/[layout_view, search_view]


proc searchCve*(ctx: Context) {.async.} =
  ## Search Cves shows search results matching the GET parameter `query`
  let queryParam = ctx.getQueryParams("query")
  if queryParam == "":
    resp ctx.renderMain(ctx.renderSearchEmpty, renderHero("Search Results"))
    return

  let cves = await db.searchByCveId(queryParam)

  if len(cves) == 0:
    resp ctx.renderMain(ctx.renderSearchEmpty, renderHero("Search Results"))
    return

  resp ctx.renderMain(ctx.renderSearch(cves), renderHero("Search Results"))
