import std/[strformat, options, strtabs, json]

import layout_view


proc renderWelcome*(ctx: Context, researchers: seq[tuple[researcher: Researcher, cve: Cve]], cves: seq[Cve], hacktivities: seq[Hacktivity]): VNode =
  buildHtml():
    tdiv:
      section(class="hero is-black is-medium",id="welcome-hero"):
        tdiv(class="hero-body"):
          tdiv(class="container has-text-centered"):
            h1(class="title intro-title is-size-2"):
              verbatim "Find your <strong>inspiration</strong> in the state of <strong>insecurity</strong>."
            h2(class="subtitle is-size-4"):
              text "Follow security researchers, discover trending PoC exploits, learn by reversing CVEs. "
      # researchers
      section(class="section welcome-strip"):
        tdiv(class="container"):
          # header researchers
          header(class="strip-header"):
            h3(class="title is-3"):
              text "Share in the passion of the world\'s top Security Researchers. "
          # cards researchers
          tdiv(class="columns is-multiline"):
            for (researcher, cve) in researchers:
              tdiv(class="column is-one-third"):
                tdiv(class="card"):
                  header(class="card-header"):
                    p(class="card-header-title"):
                      a(class="is-size-5 has-text-primary-light",href = ctx.urlFor("researcher", {"alias": researcher.alias})):
                        text researcher.name
                    tdiv(class="card-header-icon"):
                      span(class="flag-icon flag-icon-us")
                  tdiv(class="card-content has-background-black"):
                    p:
                      text &"{cve.cveId}: "
                      text truncate(cve.description, 160)
                      br()
                      small(class="has-text-grey-light is-size-7"):
                        text cve.pubDate.ago
          # cta researchers
          tdiv(class="buttons is-centered section-cta"):
            a(class="button is-primary",href="/researcher"):
              text "View top researchers"

      # cves
      section(class="section welcome-strip"):
        tdiv(class="container"):
          # header cves
          header(class="strip-header"):
            h3(class="title is-3"):
              text "Discover vulnerabilities being exploited in the wild, right now. "
          tdiv(class="columns is-multiline"):
            for cve in cves:
              ctx.renderCveCard(cve)
          # cta cves
          tdiv(class="buttons is-centered section-cta"):
            a(class="button is-primary",href="/cve"):
              text "View popular CVEs"
            a(class="button",href="/poc"):
              text "Show me the exploits"

      # hacktivities
      section(class="section welcome-strip"):
        tdiv(class="container"):
          # header hacktivities
          header(class="strip-header"):
            h3(class="title is-3"):
              text "Follow these proven ways to make money with Bug Bounty. "
          # cards hacktivities
          tdiv(class="block"):
            for hacktivity in hacktivities:
              article(class="media article-hacktivity"):
                tdiv(class="media-content"):
                  tdiv(class="content"):
                    p:
                      a(class="has-text-white",href= ctx.urlFor("cve", {"year": $hacktivity.cve.year, "sequence": $hacktivity.cve.sequence})):
                        text hacktivity.title
                      small(style = "margin-bottom: .5rem".toCss, class = "has-text-grey-light"):
                        text &"disclosed {hacktivity.disclosedAt.ago} by {hacktivity.researcher}"
          tdiv(class="buttons is-centered section-cta"):
            a(class="button is-primary",href="/bugbounty"):
              text "View bug bounties"

      # labs
      section(class="section welcome-strip"):
        tdiv(class="container"):
          header(class="strip-header"):
            h3(class="title is-3"):
              text "Learn to pwn in a safe environment. "
          tdiv(class="buttons is-centered section-cta"):
            a(class="button is-primary",href="/lab"):
              text "View research labs"
