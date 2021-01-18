import prologue

import controllers/cve

let
#  indexPatterns* = @[
#    pattern("/", views.read, @[HttpGet], name = "index")
#  ]
  cvePatterns* = @[
    pattern("/{year}/{sequence}", showCve, @[HttpGet], "cve"),
    pattern("/{year}", showCveYear, @[HttpGet], "cveYear"),
  ]
