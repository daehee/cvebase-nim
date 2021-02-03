import std/[times, strformat, options, strtabs, strutils, json, sequtils]

import
  layout_view

proc renderSearchEmpty*(ctx: Context): VNode =
  buildHtml():
    section(class="section is-medium"):
      tdiv(class="container"):
        tdiv(class="columns is-vcentered"):
          tdiv(class="column has-text-centered"):
            p(class="subtitle"):
              text "No results for your query."

proc renderSearch*(ctx: Context, cves: seq[Cve]): VNode =
  buildHtml():
    section(class="section"):
      tdiv(class="container is-widescreen"):
        tdiv(class="columns"):
          tdiv(class="column"):
            tdiv(class="columns is-multiline"):
              for cve in cves:
                ctx.renderCveCard(cve)
