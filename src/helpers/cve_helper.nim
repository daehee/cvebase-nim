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
          # TODO: Stack as numbered collection when duplicate vendors e.g. Vulhub 1, Vulhub 2
          text urlToLabVendor(url)

proc severityColorClass*(severity: string): string {.inline.} =
  result = case severity:
  of "LOW": "is-severity-low"
  of "MEDIUM": "is-severity-medium"
  of "HIGH": "is-severity-high"
  of "CRITICAL": "is-severity-critical"
  else: "is-dark"