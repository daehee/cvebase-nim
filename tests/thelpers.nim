import unittest

import sequtils, times

import helpers

suite "test helpers":
  test "peekCveLink":
    let tests = @[
      "http://packetstormsecurity.com/files/159769/Oracle-WebLogic-Server-Remote-Code-Execution.html",
      "https://www.oracle.com/security-alerts/cpuoct2020.html",
      "https://www.zerodayinitiative.com/advisories/ZDI-21-010/",
    ]
    let expected = @[
      "packetstormsecurity.com/files/159769/Oracle-WebLogic-Server-Remote-Code-Execution.html",
      "oracle.com/security-alerts/cpuoct2020.html",
      "zerodayinitiative.com/advisories/ZDI-21-010/",
    ]

    for (tt, exp) in zip(tests, expected):
      check(peekCveLink(tt) == exp)

  test "truncate":
    let test = "In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability ."
    let expected = "In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to..."
    check(truncate(test, 180) == expected)

  test "time fromTime in words":
    block:
      let fromTime = now() - 29.seconds
      check fromTime.ago == "less than a minute ago"

    block:
      let fromTime = now() - 45.minutes
      check fromTime.ago == "about 1 hour ago"

    block:
      let fromTime = now() - (2.days + 12.hours)
      check fromTime.ago == "3 days ago"

    block:
      let fromTime = now() - (3.months + 12.hours)
      check fromTime.ago == "3 months ago"

    block:
      let fromTime = now() - (2.years + 2.months)
      check fromTime.ago == "about 2 years ago"

    block:
      let fromTime = now() - (2.years + 3.months)
      check fromTime.ago == "over 2 years ago"

    block:
      let fromTime = now() - (2.years + 11.months)
      check fromTime.ago == "almost 3 years ago"
