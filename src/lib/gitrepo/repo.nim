import osproc, strformat, os, strutils

template withDir*(dir, body) =
   let old = getCurrentDir()
   try:
     setCurrentDir(dir)
     body
   finally:
     setCurrentDir(old)

proc loadGitRepo*(url, branch: string; workDir: string = getCurrentDir()): string =
  ## Clones repo to local work directory.
  ## Returns path to repo directory.
  let repoDir = url.split('/')[^1]
  withDir(workDir):
    if not dirExists(repoDir):
      let code = execCmd(&"git clone -q {url}")
      if code > 0: raise newOSError(code.OSErrorCode, "error git clone")
  withDir(workDir / repoDir):
    let code = execCmd(&"git pull origin {branch}")
    if code > 0: raise newOSError(code.OSErrorCode, "error git pull")
  return workDir / repoDir
