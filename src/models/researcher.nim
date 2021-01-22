import std/[options]

import cve

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

  # Represents a Researcher's Cve (single)
  ResearcherCve* = object
    alias*: string
    name*: string
    nationality*: string
    cve*: Cve
    researcherId*: string # for comparison with db query results only
