import unittest
import std/[asyncdispatch, times, uri, strutils, options, json, sequtils, strformat]

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
      check len(cve.wiki["advisory"].getStr()) > 0

    block:
      let cve = waitFor db.getCveBySequence(2020, 29156)
      check cve.cveId == "CVE-2020-29156"
      check not cve.wiki.hasKey("advisory")


  test "CVE Weakness":
    block:
      let cve = waitFor db.getCveBySequence(2020, 14882)
      check cve.cwe.isNone()
    block:
      let cve = waitFor db.getCveBySequence(2020, 796)
      check cve.cwe.get().name == "Improper Input Validation"
      check cve.cwe.get().description.contains("The product receives input or data, but it does")

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
      let pgn = waitFor db.getCvesByMonth(2020, 12)
      check pgn.page == 1
      check pgn.perPage == 10
      check pgn.total > 0
      check pgn.pages > 0
      check pgn.nextNum == 2
      check pgn.prevNum == 0
      check pgn.hasNext == true
      check pgn.hasPrev == false

  test "getCveYears":
    block:
      let years = waitFor db.getCveYears()
      check years == @[2020, 2019, 2018, 2017, 2016, 2015, 2014, 2013, 2012, 2011, 2010, 2009, 2008, 2007, 2006, 2005, 2004, 2003, 2002, 2001, 2000, 1999, 1997, 1996]

  test "getCveYearMonths":
    block:
      let months = waitFor db.getCveYearMonths(2020)
      check months == @[12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    block:
      let months = waitFor db.getCveYearMonths(1996)
      check months == @[4, 2]

  test "cveResearchersQuery":
    block:
      let researchers = waitFor db.getResearchersByCveId(338)
      check researchers.anyIt(it.alias in @["bar-lahav", "honggang-ren", "hardik-shah", "galdeleon"])

  test "getResearchersCveActivity":
    block:
      let res = waitFor db.getResearchersCveActivity()
      check len(res) == 10
#      for item in res:
#        echo &"{item.alias} {item.cve.cveId}"

  waitFor db.close()
