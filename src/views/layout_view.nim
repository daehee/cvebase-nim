import jester, karax/[karaxdsl, vdom, vstyles]

type
  HeroVNode* = distinct VNode

const
  doctype = "<!DOCTYPE html>\n"

proc renderHead*(): VNode =
  buildHtml(head):
    title:
      text "replace me  title"
    meta(name="viewport", content="width=device-width, initial-scale=1.0")
    link(rel="stylesheet", type="text/css", href="/css/style.css?v=3")
    script(src="https://kit.fontawesome.com/007fa0d61e.js", data-mutate-approach="sync")
    # TODO add canonical
    # TODO add og and twitter meta tags
    # TODO add application javascript
    # TODO add google analytics

proc renderNavBar*(): VNode =
  buildHtml(nav(class = "main-nav navbar is-black is-spaced", style = "border: none".toCss)):
    tdiv(class="container"):
      tdiv(class="navbar-brand"):
        tdiv(aria-label="menu",role="button",aria-expanded="false",class="navbar-burger burger"):
          span(aria-hidden="true")
          span(aria-hidden="true")
          span(aria-hidden="true")
      tdiv(class="navbar-menu",id="navbarMenuIndex"):
        tdiv(class="navbar-start"):
          tdiv(class="navbar-item")
        tdiv(class="navbar-end"):
          a(class="navbar-item",href="/cve"):
            text "CVEs"
          a(class="navbar-item",href="/researcher"):
            text "Researchers"
          a(class="navbar-item",href="/poc"):
            text "PoC Exploits"
          a(class="navbar-item",href="/bugbounty"):
            text "Bug Bounties"
          a(class="navbar-item",href="/lab"):
            text "Learn"
          a(target="_blank",class="navbar-item",href="https://github.com/cvebase/cvebase.com"):
            span(class="icon"):
              i(class="fab fa-github")
          a(target="_blank",class="navbar-item",href="https://twitter.com/cvebase"):
            span(class="icon"):
              i(class="fab fa-twitter")

proc renderFooter*(): VNode =
  buildHtml(footer(class = "footer")):
    tdiv(class="container"):
      tdiv(class="columns"):
        tdiv(class="column"):
          aside(class="menu"):
            p(class="menu-label"):
              text "Discover"
            ul(class="menu-list"):
              li():
                a(href="/cve"):
                  text "Popular Vulnerabilities"
              li():
                a(href="/researcher"):
                  text "Top Security Researchers"
              li():
                a(href="/poc"):
                  text "Latest PoC Exploits"
              li():
                a(href="/lab"):
                  text "Learn To Reverse CVEs"
              li():
                a(href="/bugbounty"):
                  text "Bug Bounty Disclosures"
              li():
                a(href="/cve/tag/jaeles"):
                  text "CVE Detection Signatures"
              li():
                a(href="/cnvd/2020"):
                  text "China Vulnerabilities"
        tdiv(class="column")
        tdiv(class="column"):
          aside(class="menu"):
            p(class="menu-label"):
              text "Stay Connected"
            ul(class="menu-list"):
              a(target="_blank",href="https://twitter.com/cvebase"):
                span(class="icon"):
                  i(class="fab fa-twitter")
                text "Twitter "
              a(target="_blank",href="https://www.linkedin.com/company/cvebase"):
                span(class="icon"):
                  i(class="fab fa-linkedin")
                text "Linkedin "
              a(target="_blank",href="https://github.com/cvebase/cvebase.com"):
                span(class="icon"):
                  i(class="fab fa-github")
                text "GitHub "
    br()
    tdiv(class="container"):
      tdiv(class="columns"):
        tdiv(class="column is-4"):
          p():
            small(class="has-text-grey-light"):
              text "CVE data provided by the National Vulnerability Database at NIST. The authoritative source of CVE details is The MITRE Corporation. "
              br()
              text "Website content licensed "
              a(href="https://creativecommons.org/licenses/by-nc-sa/4.0/"):
                text "CC BY-NC-SA 4.0"

proc renderMain*(body: VNode; req: Request; titleText=""; desc=""): string =
  let node = buildHtml(html(lang="en")):
    renderHead()
    body:
      renderNavBar()
      body
      renderFooter()

  result = doctype & $node

proc renderMain*(body: VNode; hero: HeroVNode; req: Request; titleText=""; desc=""): string =
  ## Overloaded with hero
  let node = buildHtml(html(lang="en")):
    renderHead()
    body:
      renderNavBar()
      hero.VNode
      body
      renderFooter()

  result = doctype & $node

proc renderError*(error: string): VNode =
  buildHtml(tdiv(class="panel-container")):
    tdiv(class="error-panel"):
      span: verbatim error