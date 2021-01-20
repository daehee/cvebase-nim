import std/[times, options, strformat]

import ../helpers/app_helper

type
  Cve* = object
    cveId*: string
    year*: int
    sequence*: int
    description*: string
    pubDate*: DateTime
    refUrls*: seq[string]
    cvss3*: Option[Cvss3]
    pocs*: seq[Poc]
    cwe*: Option[Cwe]

  Cvss3* = object
    score*: string
    severity*: string

  Cwe* = object
    name*: string
    description*: string

  Poc* = object
    url*: string
    updatedAt*: DateTime

  # TODO split into own model files
  Product* = object
    name*: string
    uriShort*: string

  Vendor* = object
    name*: string
    products*: seq[Product]


proc titleTag*(cve: Cve): string =
  result = cve.cveId
  let numPocs = len(cve.pocs)
  if numPocs > 0:
    let exploits = numPocs.pluralize("PoC Exploit")
    result.add &" ({exploits} Available)"
