import unittest
import std/[times]

import models/cve

suite "cve tests":

  test "parsePgDateTime":
    let tStr = "2006-01-02T15:04Z"
    let got = tStr.parsePgDateTime()
    check $got.month() == "January"
    check got.year() == 2006
    check got.monthday() == 2
    check got.hour() == 15
    check got.minute() == 4
