import parsecfg except Config
import strutils
import types

proc get*[T](config: parseCfg.Config; s, v: string; default: T): T =
  let val = config.getSectionValue(s, v)
  if val.len == 0: return default

  when T is int: parseInt(val)
  elif T is bool: parseBool(val)
  elif T is string: val



proc getConfig*(path: string): (Config, parseCfg.Config) =
  var cfg = loadConfig(path)

  let conf = Config(
    address: cfg.get("Server", "address", "0.0.0.0"),
    port: cfg.get("Server", "port", 8080),
    useHttps: cfg.get("Server", "https", true),
    title: cfg.get("Server", "title", "cvebase"),
    hostname: cfg.get("Server", "hostname", "cvebase.com"),
    staticDir: cfg.get("Server", "staticDir", "./public"),

    # redisHost: cfg.get("Cache", "redisHost", "localhost"),
    # redisPort: cfg.get("Cache", "redisPort", 6379),
    # redisConns: cfg.get("Cache", "redisConnections", 20),
    # redisMaxConns: cfg.get("Cache", "redisMaxConnections", 30)
  )

  return (conf, cfg)