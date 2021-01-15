import std/[times, strformat]
import karax/[karaxdsl, vdom]

import ../models/cve
import ../helpers
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
          a(href = cve.linkToMonth()):
            text &"{$cve.pubDate.month()} {$cve.pubDate.year()} CVEs"

proc renderBreadCrumbs(cve: Cve): VNode =
  buildHtml(nav(class="breadcrumb")):
    ul():
      li():
        a(href = "/cve"):
          text "CVE"
      li():
        a(href = cve.linkToYear()):
          text $cve.pubDate.year()
      li():
        a(href = cve.linkToMonth()):
          text $cve.pubDate.month()
      li(class="is-active"):
        a(href=cve.linkTo()):
          text cve.cveId

proc renderCve*(cve: Cve): VNode =
  buildHtml(section(class="section")):
    tdiv(class="container is-desktop"):
      tdiv(class="columns"):
        tdiv(class="column"):
          renderBreadcrumbs(cve)
          tdiv(class="content",id="description"):
            tdiv(class="columns is-vcentered is-mobile"):
              tdiv(class="column is-three-fifths-touch is-one-third-widescreen"):
                progress(max="10",class="progress is-small is-danger",value="8.1"):
                  # TODO Add
                  text "8.1%"
              tdiv(class="column"):
                span(class="is-size-5 has-text-weight-bold"):
                  text "8.1 / 10"
                br()
                span(class="is-size-7 has-text-weight-semibold"):
                  text "HIGH"
            p():
              text cve.description
            if cve.cwe.name != "":
              h5():
                text &"Weakness: {cve.cwe.name}"
              p():
                text cve.cwe.description
            p():
              small(class="has-text-grey-light"):
                text "Published: 2021-01-12 "
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
                text "View list"
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

proc renderCveYearBreadcrumbs(): VNode =
  buildHtml():
    nav(class="breadcrumb"):
      ul():
        li():
          a(href="/cve"):
            text "CVE"
        li(class="is-active"):
          a(href="/cve/1996"):
            text "1996"

proc renderCveCard(cve:Cve): VNode =
  buildHtml():
    tdiv(class="column is-half"):
      tdiv(class="card"):
        header(class="card-header"):
          p(class="card-header-title"):
            a(class="has-text-primary-light is-size-5",href=linkTo(cve)):
              text cve.cveId
          tdiv(class="card-header-icon"):
            tdiv(class="tags"):
              span(class="tag is-dark"):
                text "N/A"
        tdiv(class="card-content has-background-black"):
          p():
            text cve.description
            br()
            small(class="has-text-grey-light is-size-7"):
              text "almost 25 years ago "
        footer(class="card-footer"):
          p(class="card-footer-item"):
            span(class="is-size-7"):
              a(class="has-text-white",href="/cve/1999/70"):
                text "show details"
          p(class="card-footer-item"):
            span(class="is-size-7"):
              a(class="has-text-white",href="/cve/1999/70"):
                text "show details"

proc renderCveYear*(cves: seq[Cve]): VNode =
  buildHtml():
    section(class="section"):
      tdiv(class="container is-widescreen"):
        tdiv(class="columns"):
          tdiv(class="column"):
            renderCveYearBreadcrumbs()
            tdiv(class="columns is-multiline"):
              for cve in cves:
                renderCveCard(cve)
            hr()
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