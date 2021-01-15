import prologue

import controllers/cve

let
#  indexPatterns* = @[
#    pattern("/", views.read, @[HttpGet], name = "index")
#  ]
  cvePatterns* = @[
    pattern("/{year}/{sequence}", cve.showCve, @[HttpGet])
  ]