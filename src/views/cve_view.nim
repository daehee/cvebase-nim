import std/[times, strformat, options, strtabs, strutils, json, sequtils]
import karax/[karaxdsl, vdom]
import markdown

import prologue/core/context

import ../models/[cve, pagination, researcher]
import ../helpers/[app_helper, cve_helper]
import layout_view

proc renderSidebar(ctx: Context, cve: Cve): VNode =
  let
    cvePubYear = $cve.pubDate.year
    cvePubMonth = $cve.pubDate.month
    cvePubMonthNum = $cve.pubDate.month.ord()
  buildHtml(tdiv(class="column is-3 is-offset-1")):
    aside(class="menu"):
      p(class="menu-label"):
        text &"{cve.cveId} Dorks"
      ul(class="menu-list"):
        li():
          let links = @[
            ("Twitter", &"https://twitter.com/search?q=%22{cve.cveId}%22"),
            ("Google", &"https://www.google.com/search?q={cve.cveId}"),
            ("YouTube", &"https://www.youtube.com/results?search_query={cve.cveId}"),
          ]
          for link in links:
            a(target="_blank",rel="nofollow",href = link[1]):
              span(class="icon"):
                italic(class="fas fa-search")
              text link[0]
      p(class="menu-label"):
        text "Related Vulnerabilities "
      ul(class="menu-list"):
        li():
          a(href="/cve"):
            text "Popular CVEs"
        li():
          a(href = ctx.urlFor("cveMonth", {"year": cvePubYear, "month": cvePubMonthNum})):
            text &"{cvePubMonth} {cvePubYear} CVEs"

proc renderCveDateBreadcrumbs(ctx: Context, cve: Cve): VNode =
  ## cve
  let
    cvePubYear = $cve.pubDate.year
    cvePubMonth = $cve.pubDate.month
    cvePubMonthNum = $cve.pubDate.month.ord()
  buildHtml():
    nav(class="breadcrumb"):
      ul():
        li():
          a(href = "/cve"):
            text "CVE"
        li():
          a(href = ctx.urlFor("cveYear", {"year": cvePubYear})):
            text cvePubYear
        li():
          a(href = ctx.urlFor("cveMonth", {"year": cvePubYear, "month": cvePubMonthNum})):
            text cvePubMonth
        li(class="is-active"):
          a(href = ctx.urlFor("cve", {"year": $cve.year, "sequence": $cve.sequence})):
            text cve.cveId

proc renderCveDateBreadcrumbs(ctx: Context; year: string): VNode =
  ## cveYear
  buildHtml():
    nav(class="breadcrumb"):
      ul():
        li():
          a(href = "/cve"):
            text "CVE"
        li():
          a(href = ctx.urlFor("cveYear", {"year": year})):
            text year

proc renderCveDateBreadcrumbs(ctx: Context; year, month: string): VNode =
  ## cveMonth
  let monthDate = parseInt(month).Month
  buildHtml():
    nav(class="breadcrumb"):
      ul():
        li():
          a(href = "/cve"):
            text "CVE"
        li():
          a(href = ctx.urlFor("cveYear", {"year": year})):
            text year
        li():
          a(href = ctx.urlFor("cveMonth", {"year": year, "month": month})):
            text $monthDate

proc renderCve*(ctx: Context, cve: Cve, researchers: seq[Researcher]): VNode =
  buildHtml(section(class="section")):
    tdiv(class="container is-desktop"):
      tdiv(class="columns"):
        tdiv(class="column"):
          ctx.renderCveDateBreadcrumbs(cve)
          tdiv(class="content",id="description"):
            if cve.cvss3.isSome():
              let cvss3 = cve.cvss3.get()
              let colorClass = severityColorClass(cvss3.severity)
              tdiv(class="columns is-vcentered is-mobile"):
                tdiv(class="column is-three-fifths-touch is-one-third-widescreen"):
                  progress(max="10",class = &"progress is-small {colorClass}", value = cvss3.score):
                    text cvss3.score
                tdiv(class="column"):
                  span(class="is-size-5 has-text-weight-bold"):
                    text &"{cvss3.score} / 10"
                  br()
                  span(class="is-size-7 has-text-weight-semibold"):
                    text cvss3.severity
            p():
              text cve.description
            if cve.cwe.isSome():
              h5():
                text &"Weakness: {cve.cwe.get().name}"
              p():
                text cve.cwe.get().description
            p():
              small(class="has-text-grey-light"):
                let fmtDate = cve.pubDate.format("yyyy-MM-dd")
                text &"Published: {fmtDate}"

            # Researcher Credit
            if researchers.len > 0:
              h3:
                text "Researcher Credit"
              ul:
                for researcher in researchers:
                  li:
                    a(href = ctx.urlFor("researcher", {"alias": researcher.alias})):
                      text researcher.name

            # Products
            if cve.products.isSome():
              h3:
                text "Vulnerable Products"
              ul:
                let products = cve.products.get()
                for product in products:
                  li:
                    a(href = ctx.urlFor("product", {"slug": product.slug})):
                      text product.name

            h3():
              text "Community Advisory"
            if cve.wiki.hasKey("advisory"):
              verbatim markdown(cve.wiki["advisory"].getStr())
            else:
              p:
                small(class="has-text-grey-light"):
                  text "This section is open source, for any additional information that enhances or clarifies the official advisory above. "
            p():
              a(class="button",rel="nofollow",href="https://github.com/cvebase/cvebase.com"):
                span(class="icon"):
                  italic(class="fab fa-github")
                span():
                  text "Improve Advisory"
            h3():
              text "Proof-of-Concept Exploits"
            if cve.pocsCount > 0:
              details():
                summary():
                  text &"View list ({cve.pocsCount})"
                ul(id="pocs"):
                  for url in cve.pocs.map(proc(x: Poc): string = x.url):
                    li:
                      a(target="_blank",class="is-size-6 has-text-grey-light",rel="nofollow",href=url):
                        verbatim peekOutlink(url)
                        span(class="icon has-text-grey-light is-size-6"):
                          italic(class="fas fa-external-link-square-alt")
            p():
              a(class="button",rel="nofollow",href="https://github.com/cvebase/cvebase.com/"):
                span(class="icon"):
                  italic(class="fab fa-github")
                span():
                  text "Add PoC"
            if cve.wiki.hasKey("courses"):
              h3():
                text "Research Labs"
              renderCveLabButtons(cve.wiki["courses"].getElems())

            h3():
              text "Official References"
            details():
              summary():
                text "View list"
              ul(id="references"):
                for url in cve.refUrls:
                  li:
                    a(target="_blank",class="is-size-6 has-text-grey-light",rel="nofollow",href=url):
                      verbatim peekOutlink(url)
                      span(class="icon has-text-grey-light is-size-6"):
                        italic(class="fas fa-external-link-square-alt")
        ctx.renderSidebar(cve)


proc renderCveCard(ctx: Context, cve:Cve): VNode =
  let linkToCve = ctx.urlFor("cve", {"year": $cve.year, "sequence": $cve.sequence})
  buildHtml():
    tdiv(class="column is-half"):
      tdiv(class="card"):
        header(class="card-header"):
          p(class="card-header-title"):
            a(class = "has-text-primary-light is-size-5", href = linkToCve):
              text cve.cveId
          tdiv(class="card-header-icon"):
            if cve.cvss3.isSome():
              renderCvssTag(cve.cvss3.get())
        tdiv(class="card-content has-background-black"):
          p():
            text truncate(cve.description, 180)
            br()
            small(class="has-text-grey-light is-size-7"):
              text cve.pubDate.ago
        footer(class="card-footer"):
          p(class="card-footer-item"):
            span(class="is-size-7"):
              a(class = "has-text-white", href = linkToCve):
                text "show details"
          p(class="card-footer-item"):
            span(class="is-size-7"):
              if cve.pocsCount > 0:
                a(class = "has-text-primary", href = linkToCve):
                  text &"{cve.pocsCount} PoC exploits available"

proc renderCveDateSidebar(ctx: Context; selected: tuple[year, monthNum: string]; allYears, yearMonths: seq[int]): VNode =
  buildHtml():
    aside(class="menu"):
      p(class="menu-label"):
        text "Browse By Date "
      ul(class="menu-list"):
        for y in allYears:
          let yStr = $y
          li:
            if yStr == selected.year:
              a(class = "is-active", href = ctx.urlFor("cveYear", {"year": yStr})):
                text yStr
              ul:
                for m in yearMonths:
                  let mStr = $m
                  li:
                    if mStr == selected.monthNum:
                      a(class = "is-active", href = ctx.urlFor("cveMonth", {"year": yStr, "month": mStr})):
                        text $Month(m)
                    else:
                      a(href = ctx.urlFor("cveMonth", {"year": $y, "month": mStr})):
                        text $Month(m)
            else:
              a(href = ctx.urlFor("cveYear", {"year": $y})):
                text $y

proc renderCveYear*(ctx: Context, pgn: Pagination; allYears, yearMonths: seq[int]): VNode =
  let year = ctx.ctxData.getOrDefault("year")
  buildHtml():
    section(class="section"):
      tdiv(class="container is-widescreen"):
        tdiv(class="columns"):
          tdiv(class="column"):
            ctx.renderCveDateBreadcrumbs(year)
            tdiv(class="columns is-multiline"):
              for cve in pgn.items:
                ctx.renderCveCard(cve)
            hr()
            ctx.renderPagination(pgn, "cveYear", {"year": year})
          tdiv(class="column is-2"):
            ctx.renderCveDateSidebar((year: year, monthNum: ""), allYears, yearMonths)

proc renderCveMonth*(ctx: Context, pgn: Pagination; allYears, yearMonths: seq[int]): VNode =
  let
    year = ctx.ctxData.getOrDefault("year")
    month = ctx.ctxData.getOrDefault("month")
    monthNum = Month(parseInt(month)).ord()
  buildHtml():
    section(class="section"):
      tdiv(class="container is-widescreen"):
        tdiv(class="columns"):
          tdiv(class="column"):
            ctx.renderCveDateBreadcrumbs(year, month)
            tdiv(class="columns is-multiline"):
              for cve in pgn.items:
                ctx.renderCveCard(cve)
            hr()
            ctx.renderPagination(pgn, "cveMonth", {"year": year, "month": month})
          tdiv(class="column is-2"):
            ctx.renderCveDateSidebar((year: year, monthNum: $monthNum), allYears, yearMonths)

proc renderCveIndex*(ctx: Context, pgn: Pagination, allyears: seq[int]): VNode =
  buildHtml():
    section(class="section"):
      tdiv(class="container is-widescreen"):
        tdiv(class="columns"):
          tdiv(class="column"):
            tdiv(class="columns is-multiline"):
              for cve in pgn.items:
                ctx.renderCveCard(cve)
            hr()
            ctx.renderPagination(pgn, "cveIndex", @[])
          tdiv(class="column is-2"):
            ctx.renderCveDateSidebar((year: "", monthNum: ""), allYears, newSeq[int]())

proc renderPocIndex*(ctx: Context; leaders, activity: seq[Cve]): VNode =
  buildHtml():
    section(class="section",id="pocs-index"):
      tdiv(class="container is-desktop"):
        tdiv(class="columns is-variable is-1-mobile is-2-tablet is-4-desktop is-8-widescreen is-8-fullhd"):
          tdiv(class="column is-4"):
            h2(class="title is-size-4"):
              text "Top CVEs by Exploits"
            table(class="table is-fullwidth"):
              tbody():
                for i, cve in leaders.pairs():
                  tr():
                    td():
                      span(class="has-text-grey-light"):
                        text $(i + 1)
                    td:
                      a(class = "has-text-white", href = ctx.urlFor("cve", {"year": $cve.year, "sequence": $cve.sequence})):
                        text cve.cveId
                    if cve.cvss3.isSome():
                      td():
                        renderCvssTag(cve.cvss3.get())
          br()
          tdiv(class="column"):
            h2(class="title is-size-4"):
              text "Latest CVE Exploit Activity"
            tdiv(class="columns is-multiline"):
              for cve in activity:
                ctx.renderCveCard(cve)

proc renderProduct*(ctx: Context, product: Product, pgn: Pagination[Cve]): VNode =
  buildHtml():
    section(class="section"):
      tdiv(class="container is-widescreen"):
        tdiv(class="columns"):
          tdiv(class="column"):
            tdiv(class="columns is-multiline"):
              for cve in pgn.items:
                ctx.renderCveCard(cve)
            hr()
            ctx.renderPagination(pgn, "product", {"slug": product.slug})
