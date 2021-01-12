import jester, karax/[karaxdsl, vdom]

#import ../db
import ../models/cve
import ../views/[general]

proc showCve*(request: Request; cve: Cve): string =
  ## Pretty much `show*` is the controller, which passed on to `render*` view actions
  let vnode = buildHtml(tdiv(class="yeet")):
    h1: text cve.cveId
    p: text cve.description

  renderMain(vnode, request, "CVE")

#proc createCveRouter*(dbClient: DbClient) =
#  router cve:
#    get "/@year/@sequence":
#      var year, sequence: int
#      try:
#        year = parseInt(@"year")
#        sequence = parseInt(@"sequence")
#      except ValueError:
#        echo "no no no"
#      let cve = await dbClient.getCveBySequence(year, sequence)
#      resp showCve(request, cve)
