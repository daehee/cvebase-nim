# Package

version       = "0.1.0"
author        = "cvebase"
description   = "cvebase.com"
license       = "MIT"
srcDir        = "src"
skipExt       = @["nim"]
bin           = @["cvebasen"]


# Dependencies

requires "nim >= 1.4.2"
requires "jester >= 0.5.0"
requires "karax >= 1.1.2"
requires "sass#e683aa1"
requires "pg#5739d1a"
requires "print"
requires "prologue"

# Tasks

task release, "Build a production release":
  --verbose
  --forceBuild:on
  --opt:speed
  --define:release
  --define:ssl
  --hints:off
  --outdir:"."
  setCommand "c", "src/cvebasen.nim"

task scss, "Generate css":
  exec "nim c --hint[Processing]:off -r tools/gencss"
