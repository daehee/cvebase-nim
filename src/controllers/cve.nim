import std/[strutils]
import jester, karax/[karaxdsl, vdom]

import ../db
import ../models/[cve]
import ../views/[layout_v, cve_v]

proc showCve*(request: Request; paramYear, paramSeq: string): Future[string] {.async.} =
  var year, seq: int
  try:
    year = parseInt(paramYear)
    seq = parseInt(paramSeq)
  except ValueError:
    raise

  let cve = await dbClient.getCveBySequence(year, seq)

  let vnode = buildHtml(tdiv(class="yeet")):
    renderCve(cve)

  return renderMain(vnode, request, "CVE")
