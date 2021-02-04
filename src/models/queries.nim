import std/[asyncdispatch, json, tables, times, strutils, options, strformat, strutils, sequtils]

import
  ../db/[pg, dbutils],
  cve, pagination

export PGError

type
  NotFoundException* = object of Exception

#proc parseNvdDateTime*(s: string): DateTime =
#  # Example: "2006-01-02T15:04Z"
#  let layout = "yyyy-MM-dd'T'HH:mm'Z'"
#  s.parse(layout, utc())

## Cve

proc parseCveRow(row: Row): Cve {.inline.} =
  result.id = parseInt(row[0])  # primary key; field idx 0
  result.cveId = row[1]
  result.year = parseInt(row[2])
  result.sequence = parseInt(row[3])
  result.pubDate = parsePgDateTime(row[4])

  let cveData = row[5]
  result.data = if cveData == "": newJObject() else: parseJson(cveData)

  let wikiData = row[6]
  result.wiki = if wikiData == "": newJObject() else: parseJson(wikiData)

  let pocsCount = row[7]
  result.pocsCount = if pocsCount == "": 0 else: parseInt(pocsCount)

  let cweId = row[8]
  result.cweId = if cweId == "": 0 else: parseInt(cweId)


const
  resultsPerPage = 10

  # 9 items
  selectCveFields = "cves.id, cves.cve_id, year, sequence, published_date, data, wiki_data, cve_pocs_count, cwe_id"

  cveBySequenceQuery = sql(&"select {selectCveFields} from cves where year = ? and sequence = ?")

  cvesByYearQuery = sql((&"""select {selectCveFields} from cves
    where extract(year from published_date) = ?
    order by cve_pocs_count
    desc nulls last
    limit 10 offset ?""").unindent.replace("\n", " "))
  cvesByYearCountQuery = sql("select count(*) from cves where extract(year from published_date) = ?")

  # Cve.where(published_date: d.beginning_of_month.beginning_of_day..d.end_of_month.end_of_day).order('published_date DESC')
  cvesByMonthQuery = sql((&"""select {selectCveFields} from cves
    where published_date between ? and ?
    order by published_date desc
    limit 10 offset ?""").unindent.replace("\n", " "))
  cvesByMonthCountQuery = sql("select count(*) from cves where published_date between ? and ?")

  cvesIndexQuery = sql((&"""select {selectCveFields} from cves
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

  researcherQuery = sql("""select id, name, alias, nationality, bio, cves_count,
    website, twitter, github, linkedin, hackerone, bugcrowd
    from researchers where slug = ?""")

  researcherCvesQuery  = sql((&"""select {selectCveFields} from cves
  INNER JOIN cves_researchers ON cves.id = cves_researchers.cve_id
  where cves_researchers.researcher_id = ?
  order by published_date desc limit 10 offset ?""").unindent.replace("\n", " "))
  researcherCvesCountQuery = sql("""select count(*) FROM cves
  INNER JOIN cves_researchers ON cves.id = cves_researchers.cve_id
  WHERE cves_researchers.researcher_id = ?""".unindent.replace("\n", " "))

  researcherLeaderboardQuery = sql("""select alias, name, nationality from researchers
  order by cves_count desc limit 25""")

  # Get the 10 most recent & unique cves that have researcher credit
  researchersCveActivityQuery = sql((&"""SELECT DISTINCT {selectCveFields} FROM cves
  INNER JOIN cves_researchers ON cves_researchers.cve_id = cves.id
  INNER JOIN researchers ON researchers.id = cves_researchers.researcher_id
  ORDER BY published_date DESC LIMIT 10""").unindent.replace("\n", " "))

  pocLeaderboardQuery = sql((&"""select {selectCveFields} from cves
  order by cve_pocs_count desc nulls last limit 25"""))

  cvesPocActivityQuery = sql((&"""select {selectCveFields} from cves
  where cves.id in
  (select cve_id from cve_references where type = 'CvePoc' order by created_at desc limit 200) limit 10"""))

  pocActivityQuery = sql((&"""select url, DATE_TRUNC('second', cr.created_at), {selectCveFields} from cve_references cr
  inner join cves on cves.id = cr.cve_id
  where cr.type = 'CvePoc'
  order by cr.created_at desc limit 25""").unindent.replace("\n", " "))

  productQuery = sql("select id, name, slug from products where slug = ?")
  productByIdQuery = sql("select slug from products where id = ?")

  cvesProductsJoin = """INNER JOIN cves_products ON cves.id = cves_products.cve_id
    where cves_products.product_id = ?"""

  productCvesQuery  = sql((&"select {selectCveFields} from cves " &
    cvesProductsJoin & " order by published_date desc limit 10 offset ?").unindent.replace("\n", " "))

  productCvesCountQuery = sql("select count(*) FROM cves " & cvesProductsJoin)


  # hacktivities
  hacktivitiesFields = "title, researcher, url, vendor, vendor_handle, DATE_TRUNC('second', submitted_at), DATE_TRUNC('second', disclosed_at) as disclosed"
  joinHacktivitiesCves = """hacktivities inner join cves_hacktivities ch on hacktivities.id = ch.hacktivity_id
    inner join cves c on ch.cve_id = c.id"""
  hacktivitiesQuery = sql((&"select distinct hacktivities.id, {hacktivitiesFields} from " &
    joinHacktivitiesCves & " order by disclosed desc limit ? offset ?"))
  hacktivitiesCountQuery = sql(("select count(*) from (select distinct hacktivities.id from " & joinHacktivitiesCves & ") subquery_for_count"))


  labsActivityCountQuery = sql("select count(*) from cves inner join cve_references cr on cves.id = cr.cve_id where cr.type = 'CveCourse'")
  labsActivityQuery = sql((&"""select {selectCveFields}, cr.url from cves
    inner join cve_references cr on cves.id = cr.cve_id
    where cr.type = 'CveCourse'
    order by published_date desc limit ? offset ?"""))


proc getCveBySequence*(db: AsyncPool; year, seq: int): Future[Cve] {.async.} =
  let rows = await db.rows(cveBySequenceQuery, @[$year, $seq])
  if len(rows) == 0:
    raise newException(NotFoundException, &"CVE-{$year}-{$seq} not found")
  result = parseCveRow(rows[0])

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

proc getInQuery(db: AsyncPool, queryStr: string, ids: seq[string], order: string = ""): Future[seq[Row]] {.async.} =
  ## Selects sequence of Rows by a sequence of ids.
  ## Deduplicates ids and then builds a "questionify"-parameterized query using WHERE IN.
  var queryStr = queryStr
  let ids = ids.deduplicate(true) # isSorted = true for faster algorithm
  let qNum = questionify(ids.len)
  queryStr.add(&" ({qNum})")
  if order != "":
    queryStr.add(&" order by {order}")
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

# TODO: Cache this
proc getCvesByYear*(db: AsyncPool; year: int; page: int = 1): Future[Pagination[Cve]] {.async.} =
  paginateQuery(cvesByYearCountQuery, @[$year], page)
  let rows = await db.rows(cvesByYearQuery, @[$year, $offset])
  # TODO: Change to "seek" technique to reduce to single query without offset
  result = newPagination[Cve](page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)

# TODO: Cache this
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

# TODO: Cache this
proc getCveYears*(db: AsyncPool): Future[seq[int]] {.async.} =
  let rows = await db.rows(cveYearsQuery, @[])
  for row in rows:
    result.add parseInt(row[0])

# TODO: Cache this
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

# TODO: Move this into method on Researcher
proc getResearcherCves*(db: AsyncPool, rId: int; page: int = 1): Future[Pagination[Cve]] {.async.} =
  paginateQuery(researcherCvesCountQuery, @[$rId], page)
  let rows = await db.rows(researcherCvesQuery, @[$rId, $offset])
  result = newPagination[Cve](page, resultsPerPage, count, newSeq[Cve]())
  for item in rows:
    result.items.add parseCveRow(item)

proc getResearcherLeaderboard*(db: AsyncPool): Future[seq[Researcher]] {.async.} =
  let rows = await db.rows(researcherLeaderboardQuery, @[])
  for item in rows:
    result.add Researcher(alias: item[0], name: item[1], nationality: item[2])

proc getResearchersCveActivity*(db: AsyncPool): Future[seq[tuple[researcher: Researcher, cve: Cve]]] {.async.} =
  ## Get latest published Cves having Researcher credits
  let rows = await db.rows(researchersCveActivityQuery, @[])
  for row in rows:
    result.add (researcher: Researcher(), cve: parseCveRow(row))

  let researcherRows = await db.getInQuery("select researchers.id, alias, name, ch.cve_id from researchers inner join cves_researchers ch on researchers.id = ch.researcher_id where ch.cve_id in", result.mapIt($it.cve.id))
  for i, item in result.pairs:
    let match = researcherRows.matchInQuery(3, $item.cve.id)
    result[i].researcher = Researcher(alias: match[1], name: match[2])

proc getPocLeaderboard*(db: AsyncPool): Future[seq[Cve]] {.async.} =
  let rows = await db.rows(pocLeaderboardQuery, @[])
  for item in rows:
    result.add parseCveRow(item)

proc getPocActivity*(db: AsyncPool): Future[seq[tuple[poc: Poc, cve: Cve]]] {.async.} =
  ## Returns sequence of tuple containing
  let rows = await db.rows(pocActivityQuery, @[])
  for row in rows:
    let cve = parseCveRow(row[2..10])
    let poc = Poc(url: row[0], createdAt: parsePgDateTime(row[1]))
    result.add (poc: poc, cve: cve)

proc getCvesPocActivity*(db: AsyncPool): Future[seq[Cve]] {.async.} =
  ## Deprecated: Use getPocActivity instead
  let rows = await db.rows(cvesPocActivityQuery, @[])
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

proc getCveHacktivities*(db: AsyncPool, limit: int, offset: int = 0): Future[seq[CveHacktivity]] {.async.} =
  let hacktivities = await db.getHacktivities(limit, offset)
  # query basic cve data to append to Hacktivity objects
  let cvesInQuery = &"select {selectCveFields}, ch.hacktivity_id from cves inner join cves_hacktivities ch on cves.id = ch.cve_id where ch.hacktivity_id in"
  let cveRows = await db.getInQuery(cvesInQuery, hacktivities.mapIt(it.id))

  for i, item in hacktivities.pairs:
    # match cve query results by hacktivity id
    let match = cveRows.matchInQuery(9, item.id)
    result.add CveHacktivity(hacktivity: item, cve: parseCveRow(match))

proc getHacktivitiesPages*(db: AsyncPool, page: int = 1): Future[Pagination[CveHacktivity]] {.async.} =
  # populate count and offset variables
  paginateQuery(hacktivitiesCountQuery, @[], page)
  # get hacktivities, mutable to append further cve data
  let hacktivities = await db.getCveHacktivities(resultsPerPage, offset)
  result = newPagination[CveHacktivity](page, resultsPerPage, count, hacktivities)

proc getLabsPages*(db: AsyncPool, page: int = 1): Future[Pagination[Lab]] {.async.} =
  paginateQuery(labsActivityCountQuery, @[], page)
  let rows = await db.rows(labsActivityQuery, @[$resultsPerPage, $offset])

  var labs: seq[Lab]
  for i, row in rows.pairs:
    let labUrl = row[9]
    labs.add Lab(url: labUrl, vendor: labUrl.toLabVendor(), cve: parseCveRow(row))

  result = newPagination[Lab](page, resultsPerPage, count, labs)

proc getWelcomeResearchers*(db: AsyncPool): Future[seq[tuple[researcher: Researcher, cve: Cve]]] {.async.} =
  let researcherRows = await db.rows(sql("select id, alias, name from (select * from researchers order by cves_count desc limit 25) subquery_for_top order by random() limit 3"), @[])
  var researchers = newSeq[Researcher]()
  for row in researcherRows:
    researchers.add Researcher(id: parseInt(row[0]), alias: row[1], name: row[2])

  # Get 3 random researchers and their latest cve
  let cvesInQuery = &"select {selectCveFields}, cr.researcher_id from cves inner join cves_researchers cr on cves.id = cr.cve_id where cr.researcher_id in"
  let cveRows = await db.getInQuery(cvesInQuery, researchers.mapIt($it.id), "published_date desc")

  for i, item in researchers.pairs:
    let match = cveRows.matchInQuery(9, $item.id)
    result.add (researcher: researchers[i], cve: parseCveRow(match))

proc getWelcomeCves*(db: AsyncPool): Future[seq[Cve]] {.async.} =
  # get featured cves
  let rows = await db.rows(sql(&"select {selectCveFields} from cves where featured_at is not null order by featured_at desc limit 4"), @[])
  for row in rows:
    result.add parseCveRow(row)

proc getWelcomeHacktivities*(db: AsyncPool): Future[seq[CveHacktivity]] {.async.} =
  result = await db.getCveHacktivities(5)

proc searchByCveId*(db: AsyncPool, query: string): Future[seq[Cve]] {.async.} =
  let searchQuery = &"""SELECT {selectCveFields} FROM cves
    INNER JOIN (
    SELECT cves.id AS pg_search_id,
    (ts_rank((to_tsvector('simple', translate(cves.cve_id::text, '-', ' '))), (plainto_tsquery('simple', translate(?::text, '-', ' '))), 0)) AS rank
    FROM cves
    WHERE ((to_tsvector('simple', translate(cves.cve_id::text, '-', ' '))) @@
    (plainto_tsquery('simple', translate(?::text, '-', ' '))))) AS pg_search_f4bc98b8c7189982c7c49a
    ON cves.id = pg_search_f4bc98b8c7189982c7c49a.pg_search_id
    ORDER BY pg_search_f4bc98b8c7189982c7c49a.rank DESC, cves.id ASC LIMIT 10 OFFSET 0"""

  let rows = await db.rows(searchQuery.sql, @[query, query])
  for row in rows:
    result.add parseCveRow(row)
