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
requires "prologue >= 0.4.4"
requires "markdown#head"
requires "ago#head"
requires "schedules#head"

# Tasks

task release, "Build a production release":
  --verbose
  --forceBuild:on
  --opt:speed
  --define:release
  --define:ssl
  --define:usestd
  --define:logueRouteLoose
  --hints:off
  --outdir:"."
  setCommand "c", "src/cvebasen.nim"

task scss, "Generate css":
  exec "nim c --hint[Processing]:off -r tools/gencss"

task dev, "Build a dev release":
  exec "nim c -d:usestd -d:ssl -d:logueRouteLoose --outdir:./tmp src/cvebasen.nim"

task server, "Run server in dev mode":
  exec "nim c -d:usestd -d:ssl -d:logueRouteLoose --outdir:./tmp -r src/cvebasen.nim"

task testdb, "Test db":
  exec "nim c -r tests/tdb.nim"

task buildpoc, "Build release for cvebasepoc":
  exec "nim c -d:ssl -d:release --threads:on --outdir:./scripts scripts/poc_add.nim"
