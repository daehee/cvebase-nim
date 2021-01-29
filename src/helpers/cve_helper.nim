import std/[json, strformat]
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


proc cveSequenceToDir*(seq: int): string =
  ## Converts Cve sequence number to a "x"-padded sequence directory name
  var seqStr = $seq
  if len(seqStr) <= 3: return "0xxx"
  seqStr = seqStr[0..<(seqStr.len - 3)] # trim last 3 characters
  result = &"{seqStr}xxx"

const githubRepoCveDir = "https://github.com/cvebase/cvebase.com/blob/main/cve/"

proc repoPath*(cve: Cve, absolute: bool = false): string =
  ## Gets file path to cve file in github repo.
  # Append path to base cve directory of github.com repo
  if absolute:
    result.add githubRepoCveDir
  let seqDir = cveSequenceToDir(cve.sequence)
  result.add &"{$cve.year}/{seqDir}/{cve.cveId}.md"
