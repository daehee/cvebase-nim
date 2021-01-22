import std/[times, strformat, options, strtabs, strutils, json, sequtils, uri]
import karax/[karaxdsl, vdom]

import prologue/core/context

import markdown

import ../models/[researcher, cve, pagination]
import ../helpers/[app_helper]
import layout_view

#      section(class="hero is-black is-medium",id="page-hero"):
#        tdiv(class="hero-body"):
#          tdiv(class="container has-text-centered"):
#            h1(class="title is-2"):
#              text "Orange Tsai "
#            h2(class="subtitle is-size-5"):
#              text "Security Researcher "
#              span(class="flag-icon flag-icon-tw")

proc renderResearcher*(ctx: Context, researcher: Researcher, pgn: Pagination): VNode =
  buildHtml():
    section(class="section",id="researcher"):
      tdiv(class="container"):
        tdiv(class="columns"):
          tdiv(class="column is-8 is-offset-2"):
            nav(class="breadcrumb"):
              ul():
                li():
                  a(href="/researcher"):
                    text "Researchers"
                li(class="is-active"):
                  a(href = ctx.urlFor("researcher", {"alias": researcher.alias})):
                    text researcher.alias
            tdiv(class="block"):
              tdiv(class="container"):
                tdiv(class="columns"):
                  tdiv(class="column is-three-fifths"):
                    tdiv(class="content"):
                      p():
                        verbatim markdown(researcher.bio)
                  tdiv(class="column"):
                    let social = researcher.social
                    if social.website.isSome():
                      let
                        website = social.website.get()
                        url = parseUri(website)
                      tdiv(class="profile-link"):
                        h5(class="has-text-grey-light is-size-6 has-text-weight-light"):
                          text "Website"
                        p(class="is-size-6"):
                          a(target = "_blank", class = "has-text-white", rel = "nofollow", href = website):
                            text url.hostname & url.path
                    if social.twitter.isSome():
                      let twitter = social.twitter.get()
                      tdiv(class="profile-link"):
                        h5(class="has-text-grey-light is-size-6 has-text-weight-light"):
                          text "Twitter"
                        p(class="is-size-6"):
                          a(target = "_blank", class = "has-text-white", rel = "nofollow", href = &"https://twitter.com/{twitter}"):
                            text &"@{twitter}"
                    if social.github.isSome():
                      let github = social.github.get()
                      tdiv(class="profile-link"):
                        h5(class="has-text-grey-light is-size-6 has-text-weight-light"):
                          text "GitHub"
                        p(class="is-size-6"):
                          a(target = "_blank", class = "has-text-white", rel = "nofollow", href = &"https://github.com/{github}"):
                            text "View on GitHub"
                            span(class="icon has-text-white is-size-7"):
                              italic(class="fas fa-external-link-square-alt")
                    if social.linkedin.isSome():
                      let linkedin = social.linkedin.get()
                      tdiv(class="profile-link"):
                        h5(class="has-text-grey-light is-size-6 has-text-weight-light"):
                          text "LinkedIn"
                        p(class="is-size-6"):
                          a(target = "_blank", class = "has-text-white", rel = "nofollow", href = &"https://www.linkedin.com/in/{linkedin}"):
                            text "View on LinkedIn"
                            span(class="icon has-text-white is-size-7"):
                              italic(class="fas fa-external-link-square-alt")
                    if social.hackerone.isSome():
                      let hackerone = social.hackerone.get()
                      tdiv(class="profile-link"):
                        h5(class="has-text-grey-light is-size-6 has-text-weight-light"):
                          text "HackerOne"
                        p(class="is-size-6"):
                          a(target = "_blank", class = "has-text-white", rel = "nofollow", href = &"https://hackerone.com/{hackerone}"):
                            text "View on Hackerone"
                            span(class="icon has-text-white is-size-7"):
                              italic(class="fas fa-external-link-square-alt")
                    if social.bugcrowd.isSome():
                      let bugcrowd = social.bugcrowd.get()
                      tdiv(class="profile-link"):
                        h5(class="has-text-grey-light is-size-6 has-text-weight-light"):
                          text "Bugcrowd"
                        p(class="is-size-6"):
                          a(target = "_blank", class = "has-text-white", rel = "nofollow", href = &"https://bugcrowd.com/{bugcrowd}"):
                            text "View on Bugcrowd"
                            span(class="icon has-text-white is-size-7"):
                              italic(class="fas fa-external-link-square-alt")
            hr()
            nav(class="level",id="researcher-stats"):
              tdiv(class="level-item has-text-centered"):
                tdiv():
                  p(class="heading"):
                    text "Total CVEs"
                  p(class="title"):
                    text $researcher.cvesCount
#              tdiv(class="level-item has-text-centered"):
#                tdiv():
#                  p(class="heading"):
#                    text "90 Days"
#                  p(class="title"):
#                    text "1"
            hr()
            tdiv(class="block"):
              h3(class="title is-size-6"):
                text &"{researcher.name} CVE Credits "
              table(class="table is-fullwidth"):
                tbody():
                  for cve in pgn.items:
                    let linkToCve = ctx.urlFor("cve", {"year": $cve.year, "sequence": $cve.sequence})
                    tr():
                      td():
                        small(class="has-text-grey-light"):
                          text $cve.pubDate
                      td():
                        a(class="is-size-5 has-text-weight-semibold has-text-primary",href= linkToCve):
                          text cve.cveId
                        br()
                        p():
                          small(class="has-text-white"):
                            text truncate(cve.description, 120)
                      td():
                        if cve.cvss3.isSome():
                          renderCvssTag(cve.cvss3.get())
            tdiv(class="content block"):
              p():
                small(class="has-text-grey-light"):
                  text "This page is open source. Noticed a typo? Or something missing? "
              p():
                a(class="button",rel="nofollow",href="https://github.com/cvebase/cvebase.com/blob/main/researcher/orange.md"):
                  span(class="icon"):
                    italic(class="fab fa-github")
                  span():
                    text "Improve this page"
