import std/[os, strutils]

type
  Config* = ref object
    address*: string
    port*: int
    useHttps*: bool
    appName*: string
    debug*: bool
    hostname*: string
    staticDir*: string
    secretKey*: string
    dbUrl*: string
    # redisHost*: string
    # redisPort*: int
    # redisConns*: int
    # redisMaxConns*: int

proc configureApp*(): Config =
  Config(
    address: getEnv("PLG_ADDRESS", "0.0.0.0"),
    port: getEnv("PLG_PORT", "6969").parseInt(),
    useHttps: getEnv("PLG_HTTPS", "false").parseBool(),
    appName: getEnv("PLG_APPNAME", "cvebase"),
    debug: getEnv("PLG_DEBUG", "true").parseBool(),
    hostname: getEnv("PLG_HOSTNAME", "cvebase.com"),
    staticDir: getEnv("PLG_STATICDIR", "/public"),
    secretKey: getEnv("PLG_SECRET", "s3cret"), # TODO Update this
    dbUrl: getEnv("DATABASE_URL", ""),
  )