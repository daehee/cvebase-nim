import std/[strformat]

import
  karax/[karaxdsl, vdom, vstyles],
  prologue,
  ago

import
  ../models/[cve, pagination, queries],
  ../helpers/app_helper

export karaxdsl, vdom, vstyles
export prologue
export ago
export cve, pagination, queries
export app_helper


type
  HeroVNode* = distinct VNode

const
  doctype = "<!DOCTYPE html>\n"

proc renderHead*(ctx: Context): VNode =
  buildHtml(head):
    title:
      text ctx.ctxData.getOrDefault("title")
    meta(name="viewport", content="width=device-width, initial-scale=1.0")
    meta(name = "description", content = ctx.ctxData.getOrDefault("description"))
    link(rel = "canonical", href = ctx.canonicalUrl)
    link(rel="stylesheet", type="text/css", href="/public/css/style.css?v=3")
    if ctx.request.path.isFlagPath():
      link(rel="stylesheet", type="text/css", href="/public/css/flag-icon.min.css")
    script(src="/public/js/jquery-3.5.1.min.js")
    script(src="/public/js/app.js")
    script(src="https://kit.fontawesome.com/007fa0d61e.js", data-mutate-approach="sync")
    when defined(release):
      let gaScript = """
      <!-- Global site tag (gtag.js) - Google Analytics -->
      <script async src="https://www.googletagmanager.com/gtag/js?id=UA-180163190-1"></script>
      <script>
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          gtag('js', new Date());

          gtag('config', 'UA-180163190-1');
      </script>
      """
      verbatim gaScript
    # TODO add og and twitter meta tags


proc renderNavBar*(): VNode =
  buildHtml():
    nav(class = "main-nav navbar is-black is-spaced", style = "border: none".toCss):
      tdiv(class="container"):
        tdiv(class="navbar-brand"):
          a(href="/", class="navbar-item"):
            img(src="/public/images/cvebase.png", style = "max-height: 2.5rem".toCss)
          tdiv(aria-label="menu",role="button",aria-expanded="false",class="navbar-burger burger"):
            span(aria-hidden="true")
            span(aria-hidden="true")
            span(aria-hidden="true")
        tdiv(id="navbarMenuIndex", class="navbar-menu"):
          tdiv(class="navbar-start"):
            tdiv(class="navbar-item"):
              form(accept-charset="UTF-8", action="/search", `method`="get"):
                tdiv(class="field has-addons"):
                  p(class="control is-expanded"):
                    input(class="input", placeholder="Search Vulnerabilities", value="", name="query", id="query")
                  p(class="control"):
                    button(class="button is-primary", `type`="submit"):
                      verbatim "<span class=\"icon\"><i class=\"fas fa-search\"></i></span>"
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
                italic(class="fab fa-github")
            a(target="_blank",class="navbar-item",href="https://twitter.com/cvebase"):
              span(class="icon"):
                italic(class="fab fa-twitter")

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
        tdiv(class="column")
        tdiv(class="column"):
          aside(class="menu"):
            p(class="menu-label"):
              text "Stay Connected"
            ul(class="menu-list"):
              a(target="_blank",href="https://twitter.com/cvebase"):
                span(class="icon"):
                  italic(class="fab fa-twitter")
                text "Twitter "
              a(target="_blank",href="https://www.linkedin.com/company/cvebase"):
                span(class="icon"):
                  italic(class="fab fa-linkedin")
                text "Linkedin "
              a(target="_blank",href="https://github.com/cvebase/cvebase.com"):
                span(class="icon"):
                  italic(class="fab fa-github")
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

proc renderMain*(ctx: Context; body: VNode; titleText=""; desc=""): string =
  let node = buildHtml(html(lang="en")):
    ctx.renderHead()
    body:
      renderNavBar()
      body
      renderFooter()

  result = doctype & $node

proc renderMain*(ctx: Context; body: VNode; hero: HeroVNode; titleText=""; desc=""): string =
  ## Overloaded with hero
  let node = buildHtml(html(lang="en")):
    ctx.renderHead()
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

proc renderPagination*(ctx: Context, pgn: Pagination, route: string, params: openArray[(string, string)]): VNode =
  buildHtml():
    nav(class = "pagination"):
      if pgn.hasPrev:
        a(class = "pagination-previous", href = ctx.urlFor(route, params, {"page": $pgn.prevNum})):
          text "Previous"
      if pgn.hasNext:
        a(class = "pagination-next", href = ctx.urlFor(route, params, {"page": $pgn.nextNum})):
          text "Next page"

proc renderHero*(title: string): HeroVNode =
  let hero = buildHtml(section(class="hero is-black",id="page-hero")):
    tdiv(class="hero-body"):
      tdiv(class="container has-text-centered"):
        h1(class="title is-2"):
          text title
  hero.HeroVNode # Explicit type conversion to distinct type

proc renderCvssTag*(cvss3: Cvss3): VNode =
  let colorClass = severityColorClass(cvss3.severity)
  buildHtml():
    span(class = &"tag {colorClass}"):
      text &"{cvss3.score} {cvss3.severity}"

proc renderCveCard*(ctx: Context, cve:Cve): VNode =
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
