import unittest

import sequtils

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

