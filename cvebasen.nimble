# Package

version       = "0.1.0"
author        = "cvebase"
description   = "cvebase.com"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
bin           = @["cvebasen"]


# Dependencies

requires "nim >= 1.4.2"
requires "jester >= 0.5.0"
requires "karax >= 1.1.2"
requires "sass#e683aa1"

# Tasks

task scss, "Generate css":
  exec "nim c --hint[Processing]:off -r tools/gencss"