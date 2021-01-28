import unittest

import sequtils, times

import helpers/app_helper

suite "test helpers":
  test "peekOutlink":
    let tests = @[
      "http://packetstormsecurity.com/files/159769/Oracle-WebLogic-Server-Remote-Code-Execution.html",
      "https://www.oracle.com/security-alerts/cpuoct2020.html",
      "https://www.zerodayinitiative.com/advisories/ZDI-21-010/",
      "https://gitlab.com/kar0nt3/ssh-users-enumeration-by-cve-2016-6210",
      "https://www.exploit-db.com/raw/40113",
      "https://www.youtube.com/watch?v=0f3RrvC-zGI",
      "https://rapidsafeguard.medium.com/cve-2018-11776-apache-struts-vulnerability-ad0f87632f45",
      "https://twitter.com/jonasLyk/status/1316104870987010048",
      "https://raw.githubusercontent.com/jaeles-project/jaeles-signatures/master/cves/oracle-weblogic-rce-cve-2020-14882.yaml",
    ]
    let expected = @[
      "packetstormsecurity.com/files/159769/Oracle-WebLogic-Server-Remote-Code-Execution.html",
      "oracle.com/security-alerts/cpuoct2020.html",
      "zerodayinitiative.com/advisories/ZDI-21-010/",
      """<span class="icon"><i class="fab fa-gitlab"></i></span> kar0nt3/ssh-users-enumeration-by-cve-2016-6210""",
      """<span class="icon"><i class="fas fa-spider"></i></span> 40113""",
      """<span class="icon"><i class="fab fa-youtube"></i></span> watch video""",
      """<span class="icon"><i class="fab fa-medium"></i></span> cve-2018-11776-apache-struts-vulnerability-ad0f87632f45""",
      """<span class="icon"><i class="fab fa-twitter"></i></span> tweet by jonasLyk""",
      """<span class="icon"><i class="fab fa-github"></i></span> jaeles-project/jaeles-signatures/cves/oracle-weblogic-rce-cve-2020-14882.yaml""",
    ]

    for (tt, exp) in zip(tests, expected):
      check(peekOutlink(tt) == exp)

  test "truncate":
    let test = "In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability ."
    let expected = "In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to..."
    check(truncate(test, 180) == expected)
