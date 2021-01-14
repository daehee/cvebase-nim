import os
import times

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

  CveYear* = object

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