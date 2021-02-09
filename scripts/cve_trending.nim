import
  httpclient,
  random,
  sequtils,
  strutils

from xmltree import `$`, innerText
from htmlparser import parseHtml
from streams import newStringStream
import nimquery

import
  lib/httputils/faker

const
  cveStalkerTargetUrl = "https://cvestalker.com/daily.php"
  minHeatScore = 20

type
  TrendingCve = object
    cveId: string
    heatScore: int


when isMainModule:

  var client = newHttpClient(userAgent = fakeUserAgent())

  let content = client.getContent(cveStalkerTargetUrl)
  let xml = parseHtml(content)

  # TODO: Check health of page that all elements exist
  let elements = xml.querySelectorAll("tr:not(:first-child)")

  var cves = newSeq[TrendingCve]()
  for el in elements:
    let cveId = el.querySelector("td:nth-child(2) > a:first-child").innerText()
    var heatScore: int
    try:
      heatScore = parseInt(el.querySelector("td:nth-child(3)").innerText())
    except:
      raise
      echo "could not convert heat score: " & cveId
      continue
    if heatScore < minHeatScore: continue
    cves.add TrendingCve(cveId: cveId, heatScore: heatScore)

  # FIXME: Fetch Cve if not exists in db
  echo cves
