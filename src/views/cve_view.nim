import std/[times, strformat, options, strtabs]
import karax/[karaxdsl, vdom]

import prologue/core/context

import ../models/[cve, pagination]
import ../helpers/app_helper
import layout_view

proc renderHero*(cve: Cve): HeroVNode =
  let hero = buildHtml(section(class="hero is-black is-medium",id="page-hero")):
    tdiv(class="hero-body"):
      tdiv(class="container has-text-centered"):
        h1(class="title is-2"):
          text cve.cveId
  hero.HeroVNode # Explicit type conversion to distinct type

proc renderSidebar(cve: Cve): VNode =
  buildHtml(tdiv(class="column is-3 is-offset-1")):
    aside(class="menu"):
      p(class="menu-label"):
        text &"{cve.cveId} Dorks"
      ul(class="menu-list"):
        li():
          a(target="_blank",rel="nofollow",href = &"https://twitter.com/search?q=%22{cve.cveId}%22"):
            span(class="icon"):
              italic(class="fas fa-search")
            text "Twitter "
          a(target="_blank",rel="nofollow",href = &"https://www.google.com/search?q={cve.cveId}"):
            span(class="icon"):
              italic(class="fas fa-search")
            text "Google "
          a(target="_blank",rel="nofollow",href = &"https://www.youtube.com/results?search_query={cve.cveId}"):
            span(class="icon"):
              italic(class="fas fa-search")
            text "YouTube "
      p(class="menu-label"):
        text "Related Vulnerabilities "
      ul(class="menu-list"):
        li():
          a(href="/cve"):
            text "Popular CVEs"
        li():
          a(href = "REPLACEME"):
            text &"{$cve.pubDate.month()} {$cve.pubDate.year()} CVEs"

proc renderBreadCrumbs(ctx: Context, cve: Cve): VNode =
  buildHtml(nav(class="breadcrumb")):
    ul():
      li():
        a(href = "/cve"):
          text "CVE"
      li():
        a(href = ctx.urlFor("cveYear", {"year": $cve.year})):
          text $cve.pubDate.year()
      li():
        a(href = "REPLACEME"):
          text $cve.pubDate.month()
      li(class="is-active"):
        a(href = ctx.urlFor("cve", {"year": $cve.year, "sequence": $cve.sequence})):
          text cve.cveId

proc renderCve*(ctx: Context, cve: Cve): VNode =
  buildHtml(section(class="section")):
    tdiv(class="container is-desktop"):
      tdiv(class="columns"):
        tdiv(class="column"):
          ctx.renderBreadcrumbs(cve)
          tdiv(class="content",id="description"):
            if cve.cvss3.isSome():
              tdiv(class="columns is-vcentered is-mobile"):
                tdiv(class="column is-three-fifths-touch is-one-third-widescreen"):
                  progress(max="10",class="progress is-small is-danger",value = $cve.cvss3.get().score):
                    text $cve.cvss3.get().score
                tdiv(class="column"):
                  span(class="is-size-5 has-text-weight-bold"):
                    text &"{cve.cvss3.get().score} / 10"
                  br()
                  span(class="is-size-7 has-text-weight-semibold"):
                    text cve.cvss3.get().severity
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
            h3():
              text "Community Advisory"
            p():
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
            details():
              summary():
                let numPocs = len(cve.pocs)
                text &"View list ({numPocs})"
              ul(id="pocs"):
                for item in cve.pocs:
                  li():
                    a(target="_blank",class="is-size-6 has-text-grey-light",rel="nofollow",href=item.url):
                      text peekCveLink(item.url)
                      span(class="icon has-text-grey-light is-size-6"):
                        italic(class="fas fa-external-link-square-alt")
            p():
              a(class="button",rel="nofollow",href="https://github.com/cvebase/cvebase.com/"):
                span(class="icon"):
                  italic(class="fab fa-github")
                span():
                  text "Add PoC"
            h3():
              text "Official References"
            details():
              summary():
                text "View list"
              ul(id="references"):
                for item in cve.refUrls:
                  li():
                    a(target="_blank",class="is-size-6 has-text-grey-light",rel="nofollow",href=item):
                      text peekCveLink(item)
                      span(class="icon has-text-grey-light is-size-6"):
                        italic(class="fas fa-external-link-square-alt")
        renderSidebar(cve)

proc renderCveYearBreadcrumbs(ctx: Context): VNode =
  buildHtml():
    nav(class="breadcrumb"):
      ul():
        li():
          a(href="/cve"):
            text "CVE"
        li(class="is-active"):
          a(href = ctx.urlFor("cveYear", {"year": ctx.ctxData.getOrDefault("year")})):
            text ctx.getPathParams("year")

proc renderCveCard(ctx: Context, cve:Cve): VNode =
  buildHtml():
    tdiv(class="column is-half"):
      tdiv(class="card"):
        header(class="card-header"):
          p(class="card-header-title"):
            a(class = "has-text-primary-light is-size-5", href = ctx.urlFor("cve", {"year": $cve.year, "sequence": $cve.sequence})):
              text cve.cveId
          tdiv(class="card-header-icon"):
            tdiv(class="tags"):
              span(class="tag is-dark"):
                text "N/A"
        tdiv(class="card-content has-background-black"):
          p():
            text truncate(cve.description, 180)
            br()
            small(class="has-text-grey-light is-size-7"):
              text cve.pubDate.ago
        footer(class="card-footer"):
          p(class="card-footer-item"):
            span(class="is-size-7"):
              a(class = "has-text-white", href = ctx.urlFor("cve", {"year": $cve.year, "sequence": $cve.sequence})):
                text "show details"
          p(class="card-footer-item")
          # TODO: PoC exploits available

proc renderCveYear*(ctx: Context, pgn: Pagination): VNode =
  buildHtml():
    section(class="section"):
      tdiv(class="container is-widescreen"):
        tdiv(class="columns"):
          tdiv(class="column"):
            ctx.renderCveYearBreadcrumbs()
            tdiv(class="columns is-multiline"):
              for cve in pgn.items:
                ctx.renderCveCard(cve)
            hr()
            nav(class = "pagination"):
              if pgn.hasPrev:
                a(class = "pagination-previous", href = ctx.urlFor("cveYear", {"year": ctx.ctxData.getOrDefault("year")}, {"page": $pgn.prevNum})):
                  text "Previous"
              if pgn.hasNext:
                a(class = "pagination-next", href = ctx.urlFor("cveYear", {"year": ctx.ctxData.getOrDefault("year")}, {"page": $pgn.nextNum})):
                  text "Next page"
          tdiv(class="column is-2"):
            aside(class="menu"):
              p(class="menu-label"):
                text "Browse By Date "
              ul(class="menu-list"):
                li():
                  a(class="",href="/cve/2021"):
                    text "2021"
                  ul():
                    li():
                      a(href="/cve/1996/m/4"):
                        text "April"
                    li():
                      a(href="/cve/1996/m/2"):
                        text "February"