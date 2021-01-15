import prologue
import logging

proc read*(ctx: Context) {.async.} =
  logging.debug "yeet"
  resp "Hello prologue!"