import prologue

import
  ../views/[layout_view, error_view]

proc go404*(ctx: Context) {.async.} =
  ## Custom 404 error handler
  resp ctx.renderMain(ctx.render404), Http404
