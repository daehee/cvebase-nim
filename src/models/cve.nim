import std/[times, options]

import ../concerns

type
  Cve* = object
    cveId*: string
    year*: int
    sequence*: int
    description*: string
    pubDate*: DateTime
    refUrls*: seq[string]
    cvss3*: float
    pocs*: seq[Poc]
    cwe*: Option[Cwe]

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

proc linkTo*(cve: Cve): string =
  relPath("cve", cve.year, cve.sequence)

proc linkToYear*(cve: Cve): string =
  relPath("cve", cve.pubDate.year())

proc linkToMonth*(cve: Cve): string =
  relPath("cve", cve.pubDate.year(), "m", cve.pubDate.month().ord())