import std/[options, math]

type
  # Pagination is a generic type with generic param `T`
  # representing paginated results from the db.
  # Modeled after Flask Pagination object:
  # https://github.com/pallets/flask-sqlalchemy/blob/330c9f66425c3e0388446acdf4571fd6813f8182/src/flask_sqlalchemy/__init__.py#L308
  Pagination*[T] = object
    page*: int  # current page (1 indexed)
    perPage*: int # results per page
    total*: int
    items*: seq[T]
    # pages: int  # total number of pages

proc newPagination*[T](page, perPage, total: int; items: seq[T]): Pagination[T] =
  Pagination[T](
    page: page,
    perPage: perPage,
    total: total,
    items: items,
  )

proc hasPrev*(pgn: Pagination): bool =
  pgn.page > 1

proc hasNext*(pgn: Pagination): bool =
  pgn.page < pgn.pages

proc nextNum*(pgn: Pagination): int =
  if pgn.hasNext: return pgn.page + 1

proc prevNum*(pgn: Pagination): int =
  if pgn.hasPrev: return pgn.page - 1

proc pages*(pgn: Pagination): int =
  ## Total number of pages
  if pgn.perPage == 0 or pgn.total == 0:
    result = 0
  else:
    result = ceil(pgn.total.float / pgn.perPage.float).int

#proc next*(pgn: Pagination): Future[Pagination] =
