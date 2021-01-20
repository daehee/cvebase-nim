## Common and reusable code for views
import uri, strutils, times, strformat, math

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

const
  hourMinutes = 60
  dayMinutes = hourMinutes * 24
  monthMinutes = dayMinutes * 30
  yearMinutes = dayMinutes * 365
  quarterMinutes = yearMinutes / 4

proc pluralize*(i: int64, s: string): string =
  result = &"{i} {s}"
  if i != 1: result.add "s"

proc ago*(fromTime: DateTime): string =
  # https://github.com/justincampbell/timeago/blob/master/timeago.go
  let dur = now() - fromTime
  let sec = dur.inSeconds # in seconds
  if sec < 30: return "less than a minute ago"
  if sec < 90: return "1 minute ago"

  let min = dur.inMinutes
  if min < 45: return min.pluralize("minute") & " ago"

  var hr = ceil(min.int / 60).int
  if min < dayMinutes: return "about " & hr.pluralize("hour") & " ago"
  if min < (42 * hr): return "1 day ago"

  let dy = ceil(hr / 24).int
  if min < (30 * dayMinutes): return dy.pluralize("day") & " ago"

  let months = floor(dy / 30).int
  if min < (45 * dayMinutes): return "about 1 month ago"
  if min < (60 * dayMinutes): return "about 2 months ago"
  if min < yearMinutes: return months.int.pluralize("month") & " ago"

  let rem = floorMod(min, yearMinutes)
  var yr = floor(min.int / yearMinutes).int

  if rem < (3 * monthMinutes): return "about " & yr.pluralize("year") & " ago"
  if rem < (9 * monthMinutes): return "over " & yr.pluralize("year") & " ago"
  yr.inc
  "almost " & yr.pluralize("year") & " ago"
