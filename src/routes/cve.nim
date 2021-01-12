import jester, karax/[karaxdsl, vdom]
import strformat

import db
import ../views/[general, cve]

proc showCve*(request: Request; year, sequence: string): string =
  ## Pretty much `show*` is the controller, which passed on to `render*` view actions
  let vnode = buildHtml(tdiv(class="yeet")):
    h1: text &"CVE-{year}-{sequence}"

  renderMain(vnode, request, "CVE")

proc createCveRouter*() =
  router cve:
    get "/@year/@sequence":
      y = parseInt(@"year")
      seq = parseInt(@"sequence")
      dbClient.getCVE(y, seq)
      resp showCve(request, @"year", @"sequence")
