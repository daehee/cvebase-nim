
type
  Config* = ref object
    address*: string
    port*: int
    useHttps*: bool
    title*: string
    hostname*: string
    staticDir*: string

    # redisHost*: string
    # redisPort*: int
    # redisConns*: int
    # redisMaxConns*: int
