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

  test "truncate":
    let test = "In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability ."
    let expected = "In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI..."
    check(truncate(test, 180) == expected)

