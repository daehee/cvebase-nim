import std/[times, strformat, options, strtabs, strutils, json, sequtils, uri]
import karax/[karaxdsl, vdom]

import prologue/core/context

import ../models/[researcher, cve, pagination]
import ../helpers/[app_helper]
import layout_view


proc renderWelcome*(ctx: Context, researchers: seq[Researcher], cves: seq[Cve]): VNode =
  buildHtml():
    tdiv:
      section(class="hero is-black is-medium",id="welcome-hero"):
        tdiv(class="hero-body"):
          tdiv(class="container has-text-centered"):
            h1(class="title intro-title is-size-2"):
              text "Find your "
              strong():
                text "inspiration"
              text "in the state of "
              strong():
                text "insecurity"
              text ". "
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
            for researcher in researchers:
              tdiv(class="column is-one-third"):
                tdiv(class="card"):
                  header(class="card-header"):
                    p(class="card-header-title"):
                      a(class="is-size-5 has-text-primary-light",href = ctx.urlFor("researcher", {"alias": researcher.alias})):
                        text researcher.name
                    tdiv(class="card-header-icon"):
                      span(class="flag-icon flag-icon-us")
                  tdiv(class="card-content has-background-black"):
                    let cve = researcher.cves[0]
                    p():
                      text truncate(cve.description, 180)
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
          header(class="strip-header"):
            h3(class="title is-3"):
              text "Follow these proven ways to make money with Bug Bounty. "
          tdiv(class="block"):
            article(class="media article-hacktivity"):
              tdiv(class="media-content"):
                tdiv(class="content"):
                  p():
                    a(class="has-text-white",href="/cve/2020/8295"):
                      text "Denial of Service by requesting to reset a password"
#                    small(style="margin-bottom: .5rem",class="has-text-grey-light"):
#                      text "disclosed about 15 hours ago by makerlab"
          tdiv(class="buttons is-centered section-cta"):
            a(class="button is-primary",href="/bugbounty"):
              text "View bug bounties"
      section(class="section welcome-strip"):
        tdiv(class="container"):
          header(class="strip-header"):
            h3(class="title is-3"):
              text "Learn to pwn in a safe environment. "
          tdiv(class="buttons is-centered section-cta"):
            a(class="button is-primary",href="/lab"):
              text "View research labs"
