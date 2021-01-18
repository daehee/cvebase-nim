import db/pg

var db* {.threadvar.}: AsyncPool

