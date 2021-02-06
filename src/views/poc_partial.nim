import strformat

import layout_view

proc renderPocList*(url: string, stars: int = 0): VNode =
  buildHtml():
    li:
      a(target = "_blank", class = "is-size-6 has-text-grey-light", rel = "nofollow", href = url):
        verbatim peekOutlink(url)
#        span(class = "icon has-text-grey-light is-size-6"):
#          italic(class = "fas fa-external-link-square-alt")
      if stars > 0:
        verbatim &"<small>(<i class=\"far fa-star\"></i> {$stars})</small>"
