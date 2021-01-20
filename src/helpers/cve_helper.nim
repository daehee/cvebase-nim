import std/[json, strutils]
import karax/[karaxdsl, vdom]

proc urlToLabVendor(url: string): string =
  if url.contains("pentesterlab"): "PentesterLab"
  elif url.contains("vulhub"): "Vulhub"
  elif url.contains("hackthebox"): "Hack The Box"
  elif url.contains("tryhackme"): "TryHackMe"
  else: ""

proc renderCveLabButtons*(labsJson: seq[JsonNode]): VNode =
  buildHtml(tdiv(class = "buttons")):
    for item in labsJson:
      let url = item.getStr()
      a(target = "_blank", class = "button is-outlined is-primary", rel = "nofollow", href = url):
        span(class = "icon"):
          italic(class = "fas fa-flask")
        span:
          text urlToLabVendor(url)
