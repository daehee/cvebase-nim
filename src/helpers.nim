import os

proc relPath*(paths: varargs[string, `$`]): string =
  ## Generates relative url path with given arguments
  let joined = joinPath(paths)
  absolutePath(joined, "/")
