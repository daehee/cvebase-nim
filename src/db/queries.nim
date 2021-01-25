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

proc parseCwe(rows: seq[Row]): Cwe =
  Cwe(name: rows[0][0], description: rows[0][1])

const
  resultsPerPage = 10

  selectCvesIndexFields = "select id, cve_id, year, sequence, published_date, data, cve_pocs_count"
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
  cveCweQuery = sql("select name, description from cwes where id = ?")

  researcherQuery = sql("""select id, name, alias, nationality, bio, cves_count,
    website, twitter, github, linkedin, hackerone, bugcrowd
    from researchers where slug = ?""")

  researcherCvesQuery  = sql("""select cves.id, cves.cve_id, year, sequence, published_date, data, cve_pocs_count from cves
  INNER JOIN cves_researchers ON cves.id = cves_researchers.cve_id
  where cves_researchers.researcher_id = ?
  order by published_date desc limit 10 offset ?""".unindent.replace("\n", " "))
  researcherCvesCountQuery = sql("""select count(*) FROM cves
  INNER JOIN cves_researchers ON cves.id = cves_researchers.cve_id
  WHERE cves_researchers.researcher_id = ?""".unindent.replace("\n", " "))

  cveResearchersQuery = sql("""select alias, name from researchers where researchers.id in
  (select researcher_id from cves_researchers where cve_id = ?)""")

  researcherLeaderboardQuery = sql("""select alias, name from researchers
  order by cves_count desc limit 25""")

  # Get the 10 most recent & unique cves that have researcher credit
  researchersCveActivityQuery = sql("""SELECT DISTINCT cves.id, cves.cve_id, cves.year, cves.sequence, cves.published_date, cves.data, cves.cve_pocs_count, researchers.id FROM cves
  INNER JOIN cves_researchers ON cves_researchers.cve_id = cves.id
  INNER JOIN researchers ON researchers.id = cves_researchers.researcher_id
  ORDER BY published_date DESC LIMIT 10""".unindent.replace("\n", " "))
#  researchersInQuery = sql("""select id, alias, name from researchers where id in ({})""")

  pocLeaderboardQuery = sql(selectCvesIndexFields & """ from cves
  order by cve_pocs_count desc nulls last limit 25""")

  pocActivityQuery = sql(selectCvesIndexFields & """ from cves
  where cves.id in
  (select cve_id from cve_references where type = 'CvePoc' order by created_at desc limit 200) limit 10""")

  productQuery = sql("select id, name from products where slug = ?")
  productByIdQuery = sql("select slug from products where id = ?")

  # SELECT "cves".* FROM "cves" INNER JOIN "cves_products" ON "cves"."id" = "cves_products"."cve_id" WHERE "cves_products"."product_id" = $1 ORDER BY published_date DESC LIMIT $2 OFFSET $3

proc questionify*(n: int): string =
  ## Produces a string like '?,?,?' for n specified entries.
  repeat("?,", (n - 1)) & "?"


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
  result.id = parseInt(data[0])  # primary key; field idx 0

  # Relational queries for rest of fields
  if cweId.len() > 0:
    result.cwe = parseCwe(await db.rows(cveCweQuery, @[cweId])).some()

  result.pocs = parsePocs(await db.rows(cvePocsQuery, @[$result.id]))

  result.wiki = newJObject() # initialize wiki JsonNode field to prevent SIGSEGV on null
  if wikiData != "":
    result.wiki = parseJson(wikiData)


template paginateQuery(countQuery: SqlQuery, countParams: seq[string], page: int): untyped =
  ## Injects offset and count variables for paginated queries
  let offset {.inject} = (if page == 1: 0 else: page * resultsPerPage)
  let countResult = await db.rows(countQuery, countParams)
  let count {.inject.} = parseInt(countResult[0][0])
  # TODO: Error if invalid page number i.e. page > pages available

proc getCvesIndex*(db: AsyncPool; page: int = 1): Future[Pagination[Cve]] {.async.} =
  paginateQuery(cvesIndexCountQuery, @[], page)
  let rows = await db.rows(cvesIndexQuery, @[$offset])
  result = newPagination[Cve](cvesIndexQuery, page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)

proc getCvesByYear*(db: AsyncPool; year: int; page: int = 1): Future[Pagination[Cve]] {.async.} =
  paginateQuery(cvesByYearCountQuery, @[$year], page)
  let rows = await db.rows(cvesByYearQuery, @[$year, $offset])
  # TODO: Change to "seek" technique to reduce to single query without offset
  result = newPagination[Cve](cvesByYearQuery, page, resultsPerPage, count, newSeq[Cve]())
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
  result = newPagination[Cve](cvesByMonthQuery, page, resultsPerPage, count, newSeq[Cve]())
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

proc fieldOption(field: string): Option[string] =
  if field != "": return some(field)

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
  result = newPagination[Cve](researcherCvesQuery, page, resultsPerPage, count, newSeq[Cve]())
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

proc getResearchersCveActivity*(db: AsyncPool): Future[seq[ResearcherCve]] {.async.} =
  let rows = await db.rows(researchersCveActivityQuery, @[])

  var cves = initTable[string, Cve]() # researcher ids mapped to Cve
  for item in rows:
    result.add ResearcherCve(
      cve: parseCveRow(item),
      researcherId: item[7],
    )

  let rIds = result.mapIt(it.researcherId).deduplicate

  let qNum = questionify(rIds.len)
  let researchersInQuery = sql(&"select id, alias, name from researchers where id in ({qNum})")

  let rows2 = await db.rows(researchersInQuery, rIds)
  for i, item in result.pairs:
    let match = rows2.filterIt(it[0] == item.researcherId)[0]
    result[i].alias = match[1]
    result[i].name = match[2]

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
  result = Product(id: data[0], name: data[1])

proc getProductById*(db: AsyncPool, id: int): Future[Product] {.async.} =
  let rows = await db.rows(productByIdQuery, @[$id])

  if len(rows) == 0:
    raise newException(NotFoundException, &"Product id {id} not found")

  let data = rows[0]
  result = Product(slug: data[0])
