import std/[times, options, strformat, strtabs, json, strutils, asyncdispatch]

import
  ../db/[pg, dbutils],
  ../globals,
  ../helpers/app_helper


type
  # base fields available on index call
  # select cves.id, cves.cve_id, year, sequence, published_date, data, cve_pocs_count
  Cve* = object
    id*: int # primary key from db
    cveId*: string
    year*: int
    sequence*: int
    pubDate*: DateTime # published_date
    data*: JsonNode
    wiki*: JsonNode # wiki_data
    pocsCount*: int
    cweId*: int

  Cvss3* = object
    score*: string
    severity*: string

  Cwe* = object
    name*: string
    description*: string

  Poc* = object
    url*: string
    description*: string
    stars*: int
    createdAt*: DateTime

  Lab* = object
    url*: string
    vendor*: string
    cve*: Cve

  Product* = object
    id*: int # primary key from db
    name*: string
    uriShort*: string
    slug*: string

  Vendor* = object
    name*: string
    products*: seq[Product]

  Hacktivity* = object
    id*: string # primary key from db
    title*: string
    researcher*: string
    url*: string
    vendor*: string
    vendorHandle*: string
    submittedAt*: DateTime
    disclosedAt*: DateTime

  CveHacktivity* = object
    cve*: Cve
    hacktivity*: Hacktivity

  Researcher* = object
    id*: int # db primary key
    name*: string
    alias*: string
    nationality*: string
    bio*: string
    cvesCount*: int
    social*: ResearcherSocial

  ResearcherSocial* = object # FIXME: flatten into Researcher
    website*: Option[string]
    twitter*: Option[string]
    github*: Option[string]
    linkedin*: Option[string]
    hackerone*: Option[string]
    bugcrowd*: Option[string]

  Vulhub* = object
    url*: string
    readme*: string

##
## Cve
##

const
  cvePocsQuery = sql("select url, stars from pocs where pocs.cve_id = ? order by stars desc")
  cveLabsQuery = sql("select url from cve_references where cve_references.type = 'CveCourse' and cve_references.cve_id = ? order by created_at desc")

  cveResearchersQuery = sql("""select alias, name from researchers where researchers.id in (select researcher_id from cves_researchers where cve_id = ?)""")

  cveProductsQuery = sql("select name, slug from products inner join cves_products cp on products.id = cp.product_id where cp.cve_id = ?")

  hacktivitiesFields = "title, researcher, url, vendor, vendor_handle, DATE_TRUNC('second', submitted_at), DATE_TRUNC('second', disclosed_at) as disclosed"
  cveHacktivitiesQuery = sql(&"select {hacktivitiesFields} from hacktivities inner join cves_hacktivities cp on hacktivities.id = cp.hacktivity_id where cp.cve_id = ?")

  cveCweQuery = sql("select name, description from cwes where id = ?")


proc getPocs*(cve: Cve): Future[seq[Poc]] {.async.} =
  let rows = await db.rows(cvePocsQuery, @[$cve.id])
  for row in rows:
    result.add Poc(url: row[0], stars: parseInt(row[1]))

proc getResearchers*(cve: Cve): Future[seq[Researcher]] {.async.} =
  let rows = await db.rows(cveResearchersQuery, @[$cve.id])
  for item in rows:
    result.add Researcher(alias: item[0], name: item[1])

proc getCwe*(cve: Cve): Future[Option[Cwe]] {.async.} =
  if cve.cweId > 0:
    let rows = await db.rows(cveCweQuery, @[$cve.cweId])
    result = Cwe(name: rows[0][0], description: rows[0][1]).some()

proc toLabVendor*(url: string): string =
  if url.contains("pentesterlab"): "PentesterLab"
  elif url.contains("vulhub"): "Vulhub"
  elif url.contains("hackthebox"): "Hack The Box"
  elif url.contains("tryhackme"): "TryHackMe"
  else: ""

proc getLabs*(cve: Cve): Future[seq[Lab]] {.async.} =
  let rows = await db.rows(cveLabsQuery, @[$cve.id])
  for row in rows:
   let url = row[0]
   result.add Lab(url: url, vendor: url.toLabVendor())

proc getProducts*(cve: Cve): Future[seq[Product]] {.async.} =
  let rows = await db.rows(cveProductsQuery, @[$cve.id])
  for row in rows:
    result.add Product(name: row[0], slug: row[1])

proc getHacktivities*(cve: Cve): Future[seq[Hacktivity]] {.async.} =
  let rows = await db.rows(cveHacktivitiesQuery, @[$cve.id])
  for row in rows:
    result.add Hacktivity(
      title: row[0],
      researcher: row[1],
      url: row[2],
      vendor: row[3],
      vendorHandle: row[4],
      submittedAt: parsePgDateTime(row[5]),
      disclosedAt: parsePgDateTime(row[6])
    )

proc getVulhub*(cve: Cve): Future[Option[Vulhub]] {.async.} =
  let rows = await db.rows(sql"select url, readme from vulhubs where cve_id = ? limit 1", @[$cve.id])

  if len(rows) > 0:
    result = Vulhub(
      url: rows[0][0],
      readme: rows[0][1]
    ).some()

proc description*(cve: Cve): string =
  if cve.data.hasKey("cve") and len(cve.data["cve"]["description"]["description_data"]) > 0:
    result = cve.data["cve"]["description"]["description_data"][0]["value"].getStr()
  else:
    let fmtDate = cve.pubDate.format("MMM d, yyyy")
    result = (&"""{cve.cveId} is reserved and pending public disclosure since {fmtDate}.
      When the official advisory for {cve.cveId} is released, details such as weakness type and vulnerability scoring
      will be provided here.""").unindent.replace("\n", " ")

proc refUrls*(cve: Cve): seq[string] =
  if cve.data.hasKey("cve"):
    if len(cve.data["cve"]["references"]["reference_data"]) > 0:
      for item in cve.data["cve"]["references"]["reference_data"]:
        result.add(item["url"].getStr())

proc cvss3*(cve: Cve): Option[Cvss3] =
  if cve.data.hasKey("impact"):
    # CVSS3 data if exists
    let score = cve.data["impact"]["baseMetricV3"]["cvssV3"]["baseScore"].getFloat()
    if score > 0:
      let cvss3 = Cvss3(
        score: if score == 10: "10" else: $score.formatFloat(ffDecimal, 1),
        severity: cve.data["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"].getStr()
      )
      result = some(cvss3)

proc titleTag*(cve: Cve): string =
  result = cve.cveId
  if cve.pocsCount > 0:
    let exploits = cve.pocsCount.pluralize("PoC Exploit")
    result.add &" ({exploits} Available)"


##
## Researcher
##

const
  selectPocFields = "url, DATE_TRUNC('second', created_at)"

proc getPocs*(researcher: Researcher): Future[seq[Poc]] {.async.} =
  let rows = await db.rows(sql(&"select {selectPocFields} from pocs where researcher_id = ?"), @[$researcher.id])
  for row in rows:
    result.add Poc(url: row[0], createdAt: parsePgDateTime(row[1]))
