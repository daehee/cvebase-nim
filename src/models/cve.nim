import std/times

type
  Cve* = object
    cveId*: string
    year*: int
    sequence*: int
    description*: string
    pubDate*: DateTime
    refUrls*: seq[string]
    cvss3*: float

  Product* = object
    name*: string
    uriShort*: string

  Vendor* = object
    name*: string
    products*: seq[Product]

proc parsePgDateTime*(s: string): DateTime =
  # Example: "2006-01-02T15:04Z"
  let layout = "yyyy-MM-dd'T'HH:mm'Z'"
  s.parse(layout, utc())
