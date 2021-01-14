import times

type
  Cve* = object
    cveId*: string
    year*: int
    sequence*: int
    description*: string
    pubDate*: DateTime
    refUrls*: seq[string]
    cvss3*: float

  # TODO split into own model files
  Product* = object
    name*: string
    uriShort*: string

  Vendor* = object
    name*: string
    products*: seq[Product]

