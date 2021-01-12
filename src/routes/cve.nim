import jester, karax/[karaxdsl, vdom]
import strformat, strutils

import ../db
import ../views/[general, cve]

proc showCve*(request: Request; cve: Cve): string =
  ## Pretty much `show*` is the controller, which passed on to `render*` view actions
  let vnode = buildHtml(tdiv(class="yeet")):
    h1: text cve.cveId
    p: text cve.description

  renderMain(vnode, request, "CVE")

proc createCveRouter*(dbClient: DbClient) =
  router cve:
    get "/@year/@sequence":
      var y, seq: int
#      try:
#        y = parseInt(@"year")
#        seq = parseInt(@"sequence")
      y = 2020
      seq = 14882
#      except ValueError:
#        echo "no no no"
      let cve = await dbClient.getCveBySequence(y, seq)
      resp showCve(request, cve)
