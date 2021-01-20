import unittest
import std/[asyncdispatch, times, uri, strutils, options]

import models/[cve, pagination]
import db/[pg, queries]

suite "db tests":
  let connStr = "postgres://postgres:yeetya123@localhost:5432/cvebase_development"
  let uri = parseUri(connStr)
  let db = newAsyncPool(uri.hostname, uri.username, uri.password, strip(uri.path, chars={'/'}), 20)

  test "CVE having all data":
    block:
      let cve = waitFor db.getCveBySequence(2020, 14882)
      check cve.cveId == "CVE-2020-14882"
      check cve.year == 2020
      check cve.sequence == 14882
      check cve.description == """Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)."""
      check cve.pubDate.month().ord() == 10
      check cve.refUrls.len() == 3
      check cve.cvss3.get().score == "9.8"
      check cve.cvss3.get().severity == "CRITICAL"

  test "CVE with reserved status":
    block:
      let cve = waitFor db.getCveBySequence(2020, 8554)
      check cve.description == """CVE-2020-8554 is reserved and pending public disclosure since Feb 3, 2020. When the official advisory for CVE-2020-8554 is released, details such as weakness type and vulnerability scoring will be provided here."""

  test "getCvesByYear":
    block:
      let pgn = waitFor db.getCvesByYear(2020)
      check pgn.page == 1
      check pgn.perPage == 10
      check pgn.total > 0
      check pgn.pages > 0
      check pgn.nextNum == 2
      check pgn.prevNum == 0
      check pgn.hasNext == true
      check pgn.hasPrev == false

  test "getCvesByMonth":
    block:
      let pgn = waitFor db.getCvesByMonth(2020, 8)
      check pgn.page == 1
      check pgn.perPage == 10
      check pgn.total > 0
      check pgn.pages > 0
      check pgn.nextNum == 2
      check pgn.prevNum == 0
      check pgn.hasNext == true
      check pgn.hasPrev == false

  waitFor db.close()