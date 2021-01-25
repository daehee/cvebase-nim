# Package

version       = "0.1.0"
author        = "cvebase"
description   = "cvebase.com"
license       = "MIT"
srcDir        = "src"
bin           = @["cvebasen"]


# Dependencies

requires "nim >= 1.4.2"
requires "jester >= 0.5.0"
requires "karax >= 1.2.1"
requires "sass#e683aa1"
requires "prologue"
requires "markdown#head"

# Tasks

task release, "Build a production release":
  --verbose
  --forceBuild:on
  --opt:speed
  --define:release
  --define:ssl
  --define:usestd
  --hints:off
  --outdir:"."
  setCommand "c", "src/cvebasen.nim"

task scss, "Generate css":
  exec "nim c --hint[Processing]:off -r tools/gencss"

task dev, "Build a dev release":
  exec "nim c -d:usestd -d:ssl --outdir:./tmp src/cvebasen.nim"

task server, "Run server in dev mode":
  exec "nim c -d:usestd -d:ssl --outdir:./tmp -r src/cvebasen.nim"

task testdb, "Test db":
  exec "nim c -r tests/tdb.nim"
