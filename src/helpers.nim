## Common and reusable code for views
import uri, strutils

proc peekCveLink*(url: string): string =
  var parsed = parseUri(url)

  # Strip www if exists
  if parsed.hostname.startsWith("www"):
    parsed.hostname.removePrefix("www.")

  # TODO case switch: process domain specific
  #[
if host =~ /github\.com|githubusercontent\.com/
  return raw "<span class=\"icon\"><i class=\"fab fa-github\"></i></span> #{stitch_repo_file(uri.path)}"
elsif  host =~ /gitlab.com/
  return raw "<span class=\"icon\"><i class=\"fab fa-gitlab\"></i></span> #{stitch_repo_file(uri.path)}"
elsif host =~ /exploit-db.com/
  return raw "<span class=\"icon\"><i class=\"fas fa-spider\"></i></span> #{uri.path.split('/')[2]}"
elsif host =~ /twitter.com/
  return raw "<span class=\"icon\"><i class=\"fab fa-twitter\"></i></span> tweet by @#{uri.path.split('/')[1]}"
elsif host =~ /youtube.com/
  return raw "<span class=\"icon\"><i class=\"fab fa-youtube\"></i></span> watch video"
elsif host =~ /medium.com/
  return raw "<span class=\"icon\"><i class=\"fab fa-medium-m\"></i></span> #{uri.path[1..-1]}"
end
  ]#

  return parsed.hostname & parsed.path

proc truncate*(s: string, truncAt: int): string =
  ## Truncates a given text after a given length if text is longer than length
  result = s
  if s.len > truncAt:
    var i = truncAt
    while i > 0 and s[i] notin Whitespace:
      dec i
    while i > 0 and s[i] in Whitespace: dec i
    setLen result, i+1
    result.add "..."
