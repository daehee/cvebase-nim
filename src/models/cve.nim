import std/[times, options, strformat, strtabs, json]

import ../helpers/app_helper

type
  Cve* = object
    id*: int # primary key from db
    cveId*: string
    year*: int
    sequence*: int
    description*: string
    pubDate*: DateTime
    refUrls*: seq[string]
    cvss3*: Option[Cvss3]
    pocs*: seq[Poc]
    cwe*: Option[Cwe]
    wiki*: JsonNode
    pocsCount*: int

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
    id*: string # primary key from db
    name*: string
    uriShort*: string
    slug*: string

  Vendor* = object
    name*: string
    products*: seq[Product]


proc titleTag*(cve: Cve): string =
  result = cve.cveId
  if cve.pocsCount > 0:
    let exploits = cve.pocsCount.pluralize("PoC Exploit")
    result.add &" ({exploits} Available)"
