import std/[options]

type
  Researcher* = object
    id*: int # db primary key
    name*: string
    alias*: string
    nationality*: string
    bio*: string
    cvesCount*: int
    social*: ResearcherSocial

  ResearcherSocial* = object
    website*: Option[string]
    twitter*: Option[string]
    github*: Option[string]
    linkedin*: Option[string]
    hackerone*: Option[string]
    bugcrowd*: Option[string]
