import uri, strutils, strformat
import jester, karax/[karaxdsl, vdom]

const
  doctype = "<!DOCTYPE html>\n"

proc renderMain*(body: VNode; req: Request; titleText=""; desc=""): string =
  let node = buildHtml(html(lang="en")):
#    renderHead()
    body:
      body

  result = doctype & $node


proc renderError*(error: string): VNode =
  buildHtml(tdiv(class="panel-container")):
    tdiv(class="error-panel"):
      span: verbatim error