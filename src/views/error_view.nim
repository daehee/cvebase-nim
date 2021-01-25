import karax/[karaxdsl, vdom]

import prologue/core/context

proc render404*(ctx: Context): VNode =
  buildHtml():
    section(class="section is-medium"):
      tdiv(class="container"):
        tdiv(class="columns is-vcentered"):
          tdiv(class="column has-text-centered"):
            h1(class="title"):
              text "404 Page Not Found"
            p(class="subtitle"):
              text "Looks like you took a wrong turn somewhere."
