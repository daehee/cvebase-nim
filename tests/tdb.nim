import unittest
import asyncdispatch

import db

suite "db tests":
  let dbClient = waitFor initDbClient("postgres://postgres:yeetya123@localhost:5432/cvebase_development")

#  test "health":
#    let health = waitFor dbClient.checkHealth()
#    check(health == "130000")

  test "get cve":
    block:
      let cve = waitFor dbClient.getCveBySequence(2020, 14882)
      check(cve.cveId == "CVE-2020-14882")
      check(cve.description == """Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).""")

    block:
      let cve = waitFor dbClient.getCveByCveId("CVE-2020-14882")
      check(cve.cveId == "CVE-2020-14882")
      check(cve.description == """Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).""")

  dbClient.close()