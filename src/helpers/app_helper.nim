## Common and reusable code for views
import uri, strutils, strformat

import prologue/core/[context, request]


const baseUrl = "https://www.cvebase.com"

proc canonicalUrl*(ctx: Context): string =
  return baseUrl & ctx.request.path

proc peekOutlink*(url: string): string =
  let parsed = parseUri(url)
  var host = parsed.hostname

  # Strip subdomain if exists
  var splitHost = host.split('.')
  if len(splitHost) > 2: splitHost.delete(0)
  host = splitHost.join(".")

#  if host.startsWith("www"):
#    host.removePrefix("www.")

  case host:
  of "github.com":
    result.add """<span class="icon"><i class="fab fa-github"></i></span> """
    result.add parsed.path.strip(chars = {'/'})
  of "githubusercontent.com":
    result.add """<span class="icon"><i class="fab fa-github"></i></span> """
    var split = parsed.path.split('/')
    split.delete(3)
    result.add split.join("/").strip(chars = {'/'})
  of "gitlab.com":
    result.add """<span class="icon"><i class="fab fa-gitlab"></i></span> """
    result.add parsed.path.strip(chars = {'/'})
  of "exploit-db.com":
    result.add """<span class="icon"><i class="fas fa-spider"></i></span> """
    result.add parsed.path.split('/')[2]
  of "twitter.com":
    result.add """<span class="icon"><i class="fab fa-twitter"></i></span> """
    result.add "tweet by " & parsed.path.split('/')[1]
  of "youtube.com":
    result.add """<span class="icon"><i class="fab fa-youtube"></i></span> """
    result.add "watch video"
  of "medium.com":
    result.add """<span class="icon"><i class="fab fa-medium"></i></span> """
    result.add parsed.path.strip(chars = {'/'})
  else:
    result.add host & parsed.path


proc truncate*(s: string, truncAt: int): string =
  ## Truncates a given text after a given length if text is longer than length
  result = s
  if s.len > truncAt:
    var i = truncAt
    while i > 0 and s[i] notin Whitespace:
      dec i
    while i > 0 and s[i] in Whitespace: dec i
    setLen result, i+1
    result.add "..."

proc pluralize*(i: int64, s: string): string =
  result = &"{i} {s}"
  if i != 1: result.add "s"

proc severityColorClass*(severity: string): string {.inline.} =
  result = case severity:
  of "LOW": "is-severity-low"
  of "MEDIUM": "is-severity-medium"
  of "HIGH": "is-severity-high"
  of "CRITICAL": "is-severity-critical"
  else: "is-dark"
