import unittest
import std/[asyncdispatch, times, uri, strutils]

import models/cve
import database
import db/[pg, queries]

template checkCve(cve: Cve) =
  check cve.cveId == "CVE-2020-14882"
  check cve.year == 2020
  check cve.sequence == 14882
  check cve.description == """Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)."""
  check cve.pubDate.month().ord() == 10
  check cve.refUrls.len() == 3

suite "db tests":
  let connStr = "postgres://postgres:yeetya123@localhost:5432/cvebase_development"
  let uri = parseUri(connStr)
  db = newAsyncPool(uri.hostname, uri.username, uri.password, strip(uri.path, chars={'/'}), 20)

  test "getCve":
    block:
      let cve = waitFor db.getCveBySequence(2020, 14882)
      checkCve cve

  waitFor db.close()