import std/[asyncdispatch, json, tables, times, strutils, options, strformat, strutils, sequtils]

import ./pg
import ../models/[cve, researcher, pagination]

export PGError

type
  NotFoundException* = object of Exception

#proc parseNvdDateTime*(s: string): DateTime =
#  # Example: "2006-01-02T15:04Z"
#  let layout = "yyyy-MM-dd'T'HH:mm'Z'"
#  s.parse(layout, utc())

const pgDateLayout = "yyyy-MM-dd HH:mm:ss"

proc parsePgDateTime*(s: string): DateTime =
  # Example: "2006-01-02 15:15:00"
  let layout = pgDateLayout
  s.parse(layout, utc())

## Cve

proc parseCveRow(row: Row): Cve {.inline.} =
  result.id = parseInt(row[0])  # primary key; field idx 0
  result.cveId = row[1]
  result.year = parseInt(row[2])
  result.sequence = parseInt(row[3])
  result.pubDate = parsePgDateTime(row[4])

  # initialize with 0 if cve_pocs_count column is NULL
  let pocsCount = row[6]
  result.pocsCount = if pocsCount == "": 0 else: parseInt(pocsCount)

  let cveData = row[5]
  if cveData != "":
    let cveDataJson = parseJson(cveData)
    result.description = cveDataJson["cve"]["description"]["description_data"][0]["value"].getStr()

    if len(cveDataJson["cve"]["references"]["reference_data"]) > 0:
      for item in cveDataJson["cve"]["references"]["reference_data"]:
        result.refUrls.add(item["url"].getStr())

    # CVSS data if exists
    let score = cveDataJson["impact"]["baseMetricV3"]["cvssV3"]["baseScore"].getFloat()
    if score > 0:
      result.cvss3 = Cvss3(
        score: if score == 10: "10" else: $score.formatFloat(ffDecimal, 1),
        severity: cveDataJson["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"].getStr()
      ).some()
  else:
    let fmtDate = result.pubDate.format("MMM d, yyyy")
    result.description = (&"""{result.cveId} is reserved and pending public disclosure since {fmtDate}.
      When the official advisory for {result.cveId} is released, details such as weakness type and vulnerability scoring
      will be provided here.""").unindent.replace("\n", " ")


proc parsePocs(rows: seq[Row]): seq[Poc] {.inline.} =
  for row in rows:
    result.add Poc(url: row[0])

proc parseLabs(rows: seq[Row]): seq[Lab] =
  for row in rows:
    let url = row[0]
    let vendor = if url.contains("pentesterlab"): "PentesterLab"
    elif url.contains("vulhub"): "Vulhub"
    elif url.contains("hackthebox"): "Hack The Box"
    elif url.contains("tryhackme"): "TryHackMe"
    else: ""
    result.add Lab(url: url, vendor: vendor)

proc parseCwe(rows: seq[Row]): Cwe =
  Cwe(name: rows[0][0], description: rows[0][1])

proc parseCveProducts(rows: seq[Row]): seq[Product] =
  for row in rows:
    result.add Product(name: row[0], slug: row[1])

proc parseCveHacktivities(rows: seq[Row]): seq[Hacktivity] =
  # title, researcher, url, vendor, vendor_handle, DATE_TRUNC('second', submitted_at), DATE_TRUNC('second', disclosed_at) as disclosed
  for row in rows:
    result.add Hacktivity(title: row[0], researcher: row[1], url: row[2], vendor: row[3], vendorHandle: row[4], submittedAt: parsePgDateTime(row[5]), disclosedAt: parsePgDateTime(row[6]))

const
  resultsPerPage = 10

  selectCvesIndexFields = "select id, cve_id, year, sequence, published_date, data, cve_pocs_count"
  selectCvesJoinsFields = "select cves.id, cves.cve_id, year, sequence, published_date, data, cve_pocs_count"

  cveBySequenceQuery = sql(selectCvesIndexFields & ", wiki_data, cwe_id from cves where year = ? and sequence = ?")

  cvesByYearQuery = sql((selectCvesIndexFields & """ from cves
    where extract(year from published_date) = ?
    order by cve_pocs_count
    desc nulls last
    limit 10 offset ?""").unindent.replace("\n", " "))
  cvesByYearCountQuery = sql("select count(*) from cves where extract(year from published_date) = ?")

  # Cve.where(published_date: d.beginning_of_month.beginning_of_day..d.end_of_month.end_of_day).order('published_date DESC')
  cvesByMonthQuery = sql((selectCvesIndexFields & """ from cves
    where published_date between ? and ?
    order by published_date desc
    limit 10 offset ?""").unindent.replace("\n", " "))
  cvesByMonthCountQuery = sql("select count(*) from cves where published_date between ? and ?")

  cvesIndexQuery = sql((selectCvesIndexFields & """ from cves
    where featured_at is not NULL
    order by featured_at desc
    limit 10 offset ?""").unindent.replace("\n", " "))
  cvesIndexCountQuery = sql("select count(*) from cves where featured_at is not NULL")

  ## selects all distinct years from cves
  cveYearsQuery = sql("select distinct(extract(year from published_date))::INTEGER as year FROM cves order by year desc")

  ## selects all months available in a year from cves
  # SELECT date_part('month', DATE_TRUNC('month', published_date)) as month FROM "cves" WHERE (extract(year from published_date) = 2020) GROUP BY month order by month asc
  cveYearMonthsQuery = sql("""select date_part('month', date_trunc('month', published_date)) as month from cves
  where (extract(year from published_date) = ?)
  group by month order by month desc""".unindent)

  cvePocsQuery = sql("select url from cve_references where cve_references.type = 'CvePoc' and cve_references.cve_id = ?")
  cveLabsQuery = sql("select url from cve_references where cve_references.type = 'CveCourse' and cve_references.cve_id = ?")

  cveCweQuery = sql("select name, description from cwes where id = ?")

  researcherQuery = sql("""select id, name, alias, nationality, bio, cves_count,
    website, twitter, github, linkedin, hackerone, bugcrowd
    from researchers where slug = ?""")

  researcherCvesQuery  = sql((selectCvesJoinsFields & """ from cves
  INNER JOIN cves_researchers ON cves.id = cves_researchers.cve_id
  where cves_researchers.researcher_id = ?
  order by published_date desc limit 10 offset ?""").unindent.replace("\n", " "))
  researcherCvesCountQuery = sql("""select count(*) FROM cves
  INNER JOIN cves_researchers ON cves.id = cves_researchers.cve_id
  WHERE cves_researchers.researcher_id = ?""".unindent.replace("\n", " "))

  cveResearchersQuery = sql("""select alias, name from researchers where researchers.id in
  (select researcher_id from cves_researchers where cve_id = ?)""")

  researcherLeaderboardQuery = sql("""select alias, name from researchers
  order by cves_count desc limit 25""")

  # Get the 10 most recent & unique cves that have researcher credit
  researchersCveActivityQuery = sql("""SELECT DISTINCT cves.id, cves.cve_id, cves.year, cves.sequence, cves.published_date, cves.data, cves.cve_pocs_count FROM cves
  INNER JOIN cves_researchers ON cves_researchers.cve_id = cves.id
  INNER JOIN researchers ON researchers.id = cves_researchers.researcher_id
  ORDER BY published_date DESC LIMIT 10""".unindent.replace("\n", " "))
#  researchersInQuery = sql("""select id, alias, name from researchers where id in ({})""")

  pocLeaderboardQuery = sql(selectCvesIndexFields & """ from cves
  order by cve_pocs_count desc nulls last limit 25""")

  pocActivityQuery = sql(selectCvesIndexFields & """ from cves
  where cves.id in
  (select cve_id from cve_references where type = 'CvePoc' order by created_at desc limit 200) limit 10""")

  productQuery = sql("select id, name, slug from products where slug = ?")
  productByIdQuery = sql("select slug from products where id = ?")

  cvesProductsJoin = """INNER JOIN cves_products ON cves.id = cves_products.cve_id
    where cves_products.product_id = ?"""

  productCvesQuery  = sql((selectCvesJoinsFields & " from cves " &
    cvesProductsJoin & " order by published_date desc limit 10 offset ?").unindent.replace("\n", " "))

  productCvesCountQuery = sql("select count(*) FROM cves " & cvesProductsJoin)

  cveProductsQuery = sql("select name, slug from products inner join cves_products cp on products.id = cp.product_id where cp.cve_id = ?")

  # hacktivities
  hacktivitiesFields = "title, researcher, url, vendor, vendor_handle, DATE_TRUNC('second', submitted_at), DATE_TRUNC('second', disclosed_at) as disclosed"
  joinHacktivitiesCves = """hacktivities inner join cves_hacktivities ch on hacktivities.id = ch.hacktivity_id
    inner join cves c on ch.cve_id = c.id"""
  hacktivitiesQuery = sql((&"select distinct hacktivities.id, {hacktivitiesFields} from " &
    joinHacktivitiesCves & " order by disclosed desc limit ? offset ?"))
  hacktivitiesCountQuery = sql(("select count(*) from (select distinct hacktivities.id from " & joinHacktivitiesCves & ") subquery_for_count"))

  cveHacktivitiesQuery = sql(&"select {hacktivitiesFields} from hacktivities inner join cves_hacktivities cp on hacktivities.id = cp.hacktivity_id where cp.cve_id = ?")


proc getCveBySequence*(db: AsyncPool; year, seq: int): Future[Cve] {.async.} =
  let rows = await db.rows(cveBySequenceQuery, @[$year, $seq])
  if len(rows) == 0:
    raise newException(NotFoundException, &"CVE-{$year}-{$seq} not found")

  let
    data = rows[0]
    wikiData = data[7]
    cweId = data[8]

  # Build basic Cve object
  result = parseCveRow(data)


  # Append rest of fields; join queries
  # cwe
  if cweId.len() > 0:
    result.cwe = parseCwe(await db.rows(cveCweQuery, @[cweId])).some()
  # pocs
  result.pocs = parsePocs(await db.rows(cvePocsQuery, @[$result.id]))
  # labs
  result.labs = parseLabs(await db.rows(cveLabsQuery, @[$result.id]))
  # wiki
  result.wiki = newJObject() # initialize wiki JsonNode field to prevent SIGSEGV on null
  if wikiData != "": # need to check for null column value
    result.wiki = parseJson(wikiData)
  # products
  result.products = parseCveProducts(await db.rows(cveProductsQuery, @[$result.id]))
  # hacktivities
  result.hacktivities = parseCveHacktivities(await db.rows(cveHacktivitiesQuery, @[$result.id]))

## Helper functions

template paginateQuery(countQuery: SqlQuery, countParams: seq[string], page: int): untyped =
  ## Calculates offset given current page, and queries total count
  ## Injects: offset, count
  # let offset {.inject} = (if page == 1: 0 else: page * resultsPerPage)
  let offset {.inject} = (page - 1) * resultsPerPage
  let countResult = await db.rows(countQuery, countParams)
  let count {.inject.} = parseInt(countResult[0][0])
  # TODO: Raise exception if invalid page number: page > pages available

proc questionify(n: int): string =
  ## Produces a string like '?,?,?' for n specified entries.
  repeat("?,", (n - 1)) & "?"

proc getInQuery(db: AsyncPool, queryStr: string, ids: seq[string]): Future[seq[Row]] {.async.} =
  ## Selects sequence of Rows by a sequence of ids.
  ## Deduplicates ids and then builds a "questionify"-parameterized query using WHERE IN.
  var queryStr = queryStr
  let ids = ids.deduplicate(true) # isSorted = true for faster algorithm
  let qNum = questionify(ids.len)
  queryStr.add(&" ({qNum})")
  return await db.rows(queryStr.sql, ids)

proc matchInQuery(inQueryRows: seq[Row], colIdx: int, cmp: string): Row =
  ## Finds Row in inQueryRows with colIdx value that matches cmp.
  result = inQueryRows.filterIt(it[colIdx] == cmp)[0] # take first match
  if result.len == 0: raise newException(ValueError, &"no match for {cmp} in inQuery Rows")

proc fieldOption(field: string): Option[string] =
  ## Converts string to Option.
  ## Returns none Option if string is empty.
  if field != "": return some(field)


## Query functions

proc getCvesIndex*(db: AsyncPool; page: int = 1): Future[Pagination[Cve]] {.async.} =
  paginateQuery(cvesIndexCountQuery, @[], page)
  let rows = await db.rows(cvesIndexQuery, @[$offset])
  result = newPagination[Cve](page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)

proc getCvesByYear*(db: AsyncPool; year: int; page: int = 1): Future[Pagination[Cve]] {.async.} =
  paginateQuery(cvesByYearCountQuery, @[$year], page)
  let rows = await db.rows(cvesByYearQuery, @[$year, $offset])
  # TODO: Change to "seek" technique to reduce to single query without offset
  result = newPagination[Cve](page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)

proc getCvesByMonth*(db: AsyncPool; year: int, month: int; page: int = 1): Future[Pagination[Cve]] {.async.} =
  let monthDate = initDateTime(01, Month(month), year, 00, 00, 00, utc())
  let lastDayOfMonth = monthDate.month.getDaysInMonth(year)
  let monthEndDate = initDateTime(MonthdayRange(lastDayOfMonth), Month(month), year, 23, 59, 59, utc())

  let beginTime = monthDate.format(pgDateLayout) # 2020-12-01 00:00:00
  let endTime = monthEndDate.format(pgDateLayout) # 2020-12-31 23:59:59.999999

  paginateQuery(cvesByMonthCountQuery, @[beginTime, endTime], page)
  let rows = await db.rows(cvesByMonthQuery, @[beginTime, endTime, $offset])
  # TODO: Change to "seek" technique to reduce to single query without offset
  result = newPagination[Cve](page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)

proc getCveYears*(db: AsyncPool): Future[seq[int]] {.async.} =
  let rows = await db.rows(cveYearsQuery, @[])
  for row in rows:
    result.add parseInt(row[0])

proc getCveYearMonths*(db: AsyncPool, year: int): Future[seq[int]] {.async.} =
  let rows = await db.rows(cveYearMonthsQuery, @[$year])
  for row in rows:
    result.add parseInt(row[0])

proc getResearcher*(db: AsyncPool; alias: string): Future[Researcher] {.async.} =
  let rows = await db.rows(researcherQuery, @[alias])
  if len(rows) == 0:
    raise newException(NotFoundException, &"Researcher {alias} not found")

  let data = rows[0]

  result.id = parseInt(data[0]) # pk id; field idx 0
  result.name = data[1]
  result.alias = data[2]
  result.nationality = data[3]
  result.bio = data[4]
  result.cvesCount = parseInt(data[5])
  result.social = ResearcherSocial(
    website: data[6].fieldOption,
    twitter: data[7].fieldOption,
    github: data[8].fieldOption,
    linkedin: data[9].fieldOption,
    hackerone: data[10].fieldOption,
    bugcrowd: data[11].fieldOption,
  )

proc getResearcherCves*(db: AsyncPool, rId: int; page: int = 1): Future[Pagination[Cve]] {.async.} =
  paginateQuery(researcherCvesCountQuery, @[$rId], page)
  let rows = await db.rows(researcherCvesQuery, @[$rId, $offset])
  result = newPagination[Cve](page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)

proc getResearchersByCveId*(db: AsyncPool, cveId: int): Future[seq[Researcher]] {.async.} =
  let rows = await db.rows(cveResearchersQuery, @[$cveId])
  for item in rows:
    result.add Researcher(alias: item[0], name: item[1])

proc getResearcherLeaderboard*(db: AsyncPool): Future[seq[Researcher]] {.async.} =
  let rows = await db.rows(researcherLeaderboardQuery, @[])
  for item in rows:
    result.add Researcher(alias: item[0], name: item[1])

proc getResearchersCveActivity*(db: AsyncPool): Future[seq[Cve]] {.async.} =
  ## Get latest published Cves having Researcher credits
  let rows = await db.rows(researchersCveActivityQuery, @[])
  for row in rows:
    result.add parseCveRow(row)

  let researcherRows = await db.getInQuery("select researchers.id, alias, name, ch.cve_id from researchers inner join cves_researchers ch on researchers.id = ch.researcher_id where ch.cve_id in", result.mapIt($it.id))
  for i, item in result.pairs:
    let match = researcherRows.matchInQuery(3, $item.id)
    result[i].researchers.add Researcher(alias: match[1], name: match[2])

proc getPocLeaderboard*(db: AsyncPool): Future[seq[Cve]] {.async.} =
  let rows = await db.rows(pocLeaderboardQuery, @[])
  for item in rows:
    result.add parseCveRow(item)

proc getCvesPocActivity*(db: AsyncPool): Future[seq[Cve]] {.async.} =
  let rows = await db.rows(pocActivityQuery, @[])
  for item in rows:
    result.add parseCveRow(item)

proc getProduct*(db: AsyncPool, slug: string): Future[Product] {.async.} =
  let rows = await db.rows(productQuery, @[slug])

  if len(rows) == 0:
    raise newException(NotFoundException, &"Product {slug} not found")

  let data = rows[0]
  result = Product(id: parseInt(data[0]), name: data[1], slug: data[2])

proc getProductById*(db: AsyncPool, id: int): Future[Product] {.async.} =
  let rows = await db.rows(productByIdQuery, @[$id])

  if len(rows) == 0:
    raise newException(NotFoundException, &"Product id {id} not found")

  let data = rows[0]
  result = Product(slug: data[0])

proc getProductCves*(db: AsyncPool, pId: int; page: int = 1): Future[Pagination[Cve]] {.async.} =
  paginateQuery(productCvesCountQuery, @[$pId], page)
  let rows = await db.rows(productCvesQuery, @[$pId, $offset])
  result = newPagination[Cve](page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)

proc getHacktivities*(db: AsyncPool, limit: int, offset: int = 0): Future[seq[Hacktivity]] {.async.} =
  let rows = await db.rows(hacktivitiesQuery, @[$limit, $offset])
  for row in rows:
    result.add Hacktivity(
      id: row[0],
      title: row[1],
      researcher: row[2],
      url: row[3],
      vendor: row[4],
      vendorHandle: row[5],
      submitted_at: parsePgDateTime(row[6]),
      disclosed_at: parsePgDateTime(row[7]),
    )

proc getHacktivitiesPages*(db: AsyncPool, page: int = 1): Future[Pagination[Hacktivity]] {.async.} =
  # populate count and offset variables
  paginateQuery(hacktivitiesCountQuery, @[], page)
  # get hacktivities, mutable to append further cve data
  var hacktivities = await db.getHacktivities(resultsPerPage, offset)
  # query basic cve data to append to Hacktivity objects
  let cvesInQuery = selectCvesJoinsFields & ", ch.hacktivity_id from cves inner join cves_hacktivities ch on cves.id = ch.cve_id where ch.hacktivity_id in"
  let cveRows = await db.getInQuery(cvesInQuery, hacktivities.mapIt(it.id))

  for i, item in hacktivities.pairs:
    # match cve query results by hacktivity id
    let match = cveRows.matchInQuery(7, item.id)
    # let match = cveRows.filterIt(it[7] == item.id)[0] # idx 7 is hacktivity_id; take first
    hacktivities[i].cve = Cve(cveId: match[1], year: parseInt(match[2]), sequence: parseInt(match[3]))

  result = newPagination[Hacktivity](page, resultsPerPage, count, hacktivities)
