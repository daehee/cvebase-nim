import std/times
import karax/[karaxdsl, vdom]

import ../models/[cve]

proc renderHero(cve: Cve): VNode =
  buildHtml(section(class="hero is-black is-medium",id="page-hero")):
    tdiv(class="hero-body"):
      tdiv(class="container has-text-centered"):
        h1(class="title is-2"):
          text cve.cveId

proc renderSidebar(cve: Cve): VNode =
  buildHtml(tdiv(class="column is-3 is-offset-1")):
    aside(class="menu"):
      p(class="menu-label"):
        text "CVE-2020-35655 Dorks "
      ul(class="menu-list"):
        li():
          a(target="_blank",rel="nofollow",href="https://twitter.com/search?q=%22CVE-2020-35655%22"):
            span(class="icon"):
              i(class="fas fa-search")
            text "Twitter "
          a(target="_blank",rel="nofollow",href="https://www.google.com/search?q=CVE-2020-35655"):
            span(class="icon"):
              i(class="fas fa-search")
            text "Google "
          a(target="_blank",rel="nofollow",href="https://www.youtube.com/results?search_query=CVE-2020-35655"):
            span(class="icon"):
              i(class="fas fa-search")
            text "YouTube "
      p(class="menu-label"):
        text "Related Vulnerabilities "
      ul(class="menu-list"):
        li():
          a(href="/cve"):
            text "Popular CVEs"
        li():
          a(href="/cve/2021/m/1"):
            text "January 2021 CVEs"

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
    renderHero(cve)
    tdiv(class="container is-desktop"):
      tdiv(class="columns"):
        tdiv(class="column"):
          renderBreadcrumbs(cve)
          tdiv(class="content",id="description"):
            tdiv(class="columns is-vcentered is-mobile"):
              tdiv(class="column is-three-fifths-touch is-one-third-widescreen"):
                progress(max="10",class="progress is-small is-danger",value="8.1"):
                  text "8.1%"
              tdiv(class="column"):
                span(class="is-size-5 has-text-weight-bold"):
                  text "8.1 / 10"
                br()
                span(class="is-size-7 has-text-weight-semibold"):
                  text "HIGH"
            p():
              text cve.description
            h5():
              text "Weakness: Out-of-bounds Read"
            p():
              text "The software reads data past the end, or before the beginning, of the intended buffer."
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
                  i(class="fab fa-github")
                span():
                  text "Improve Advisory"
            h3():
              text "Proof-of-Concept Exploits"
            p():
              a(class="button",rel="nofollow",href="https://github.com/cvebase/cvebase.com/"):
                span(class="icon"):
                  i(class="fab fa-github")
                span():
                  text "Add PoC"
            h3():
              text "Official References"
            details():
              summary():
                text "View list"
              ul(id="references"):
                li():
                  a(target="_blank",class="is-size-6 has-text-grey-light",rel="nofollow",href="https://pillow.readthedocs.io/en/stable/releasenotes/index.html"):
                    text "pillow.readthedocs.io/en/.../index.html"
                    span(class="icon has-text-grey-light is-size-6"):
                      i(class="fas fa-external-link-square-alt")
            h3():
              text "What Others Are Saying About This"
            article(class="media"):
              tdiv(class="media-content"):
                tdiv(class="content"):
                  p():
                    small():
                      text "@GrupoICA_Ciber"
                    br()
                    text "PYTHON Multiples vulnerabilidades de severidad alta en productos PYTHON: CVE-2020-35654,CVE-2020-35653,CVE-2020-35655 Mas info en: "
        renderSidebar(cve)
