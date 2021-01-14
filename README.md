# cvebasen

## Model
Defines object type and interacts with database

## View
Builds html with Karax DSL

## Controller
Sanitize and validate parameters sent by router (here)
Fetch object from database (in model)
Render views and send to router (in view)

## Notes:
* Jester tries to move external router into main router: https://github.com/dom96/jester/issues/178