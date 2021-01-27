import std/[json, strutils]
import karax/[karaxdsl, vdom]

import ../models/cve

proc renderCveLabButtons*(labs: seq[Lab]): VNode =
  buildHtml(tdiv(class = "buttons")):
    for lab in labs:
      a(target = "_blank", class = "button is-outlined is-primary", rel = "nofollow", href = lab.url):
        span(class = "icon"):
          italic(class = "fas fa-flask")
        span:
          # TODO: Stack as numbered collection when duplicate vendors e.g. Vulhub 1, Vulhub 2
          text lab.vendor
