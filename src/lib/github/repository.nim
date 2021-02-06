## This module contains procs related to Repository management
## in GitHub. Information on the procs in this file can be
## found in the GitHub API documentation.
## https://developer.github.com/v3/repos/

import httpclient, os, strutils, json, marshal, strformat
import ./client

type
    User* = ref object
        login*: string
        id*: int
        avatar_url*: string
        gravatar_id*: string
        url*: string
        html_url*: string
        followers_url*: string
        following_url*: string
        gists_url*: string
        starred_url*: string
        subscriptions_url*: string
        organizations_url*: string
        repos_url*: string
        events_url*: string
        received_events_url*: string
        # type*: string
        site_admin*: bool
    Repository* = ref object
        id*: int
        name*: string
        full_name*: string
        owner*: User
        private*: bool
        html_url*: string
        description*: string
        fork*: bool
        url*: string
        forks_url*: string
        keys_url*: string
        collaborators_url*: string
        teams_url*: string
        hooks_url*: string
        issue_events_url*: string
        events_url*: string
        assignees_url*: string
        branches_url*: string
        tags_url*: string
        blobs_url*: string
        git_tags_url*: string
        git_refs_url*: string
        trees_url*: string
        statuses_url*: string
        languages_url*: string
        stargazers_url*: string
        contributors_url*: string
        subscribers_url*: string
        subscription_url*: string
        commits_url*: string
        git_commits_url*: string
        comments_url*: string
        issue_comment_url*: string
        contents_url*: string
        compare_url*: string
        merges_url*: string
        archive_url*: string
        downloads_url*: string
        issues_url*: string
        pulls_url*: string
        milestones_url*: string
        notifications_url*: string
        labels_url*: string
        releases_url*: string
        deployments_url*: string
        created_at*: string
        updated_at*: string
        pushed_at*: string
        git_url*: string
        ssh_url*: string
        clone_url*: string
        svn_url*: string
        homepage*: string
        size*: int
        stargazers_count*: int
        watchers_count*: int
        language*: string
        has_issues*: bool
        has_projects*: bool
        has_downloads*: bool
        has_wiki*: bool
        has_pages*: bool
        forks_count*: int
        mirror_url*: string
        archived*: bool
        open_issues_count*: int
        forks*: int
        open_issues*: int
        watchers*: int
        default_branch*: string

proc listRepos*(
    client: GithubApiClient,
    visibility: string = "",
    affiliation: string = "",
    repoType: string = "",
    sort: string = "",
    direction: string = "",
    limit: int = 100,
    page: int = 1): Response =
    ## https://developer.github.com/v3/repos/#list-your-repositories

    var data = %*{
        "visibility": visibility,
        "affiliation": affiliation,
        "type": repoType,
        "sort": sort,
        "direction": direction,
        "per_page": limit,
        "page": page
    }
    var path = "/user/repos"
    client.request(path, query = data)

proc listUserRepos*(
    client: GithubApiClient,
    username: string,
    repoType: string = "",
    sort: string = "",
    direction: string = "",
    limit: int = 100,
    page: int = 1): Response =
    ## https://developer.github.com/v3/repos/#list-user-repositories

    var data = %*{
        "type": repoType,
        "sort": sort,
        "direction": direction,
        "per_page": limit,
        "page": page
    }
    var path = "/users" / username / "repos"
    client.request(path, query = data)

proc listOrgRepos*(
    client: GithubApiClient,
    orgName: string,
    repoType: string = "",
    limit: int = 100,
    page: int = 1): Response =
    ## https://developer.github.com/v3/repos/#list-organization-repositories

    var data = %*{
        "type": repoType,
        "per_page": limit,
        "page": page
    }
    var path = "/orgs" / orgName / "repos"
    client.request(path, query = data)

proc listAllRepos*(
    client: GithubApiClient,
    since: int = 0): Response =
    ## https://developer.github.com/v3/repos/#list-all-public-repositories

    var data = %*{
        "since": since
    }
    var path = "/repositories"
    client.request(path, query = data)

proc getRepo*(
    client: GithubApiClient,
    owner: string,
    repo: string): Response =
    ## https://developer.github.com/v3/repos/#get

    var path = "/repos" / owner / repo
    client.request(path)

proc getContents*(client: GithubApiClient, owner: string, repo: string, contentPath: string): Response =
  ## https://docs.github.com/en/rest/reference/repos#get-repository-content
  ## Example: https://api.github.com/repos/octocat/hello-world/contents/PATH
  var path = "/repos" / owner / repo / "/contents" / contentPath
  client.request(path, mediaType = "raw")

proc listCommits*(client: GithubApiClient, owner: string, repo: string): Response =
  var path = "/repos" / owner / repo / "commits"
  client.request(path)

proc compareCommits*(client: GithubApiClient; owner, repo, base, head: string): Response =
  var path = "/repos" / owner / repo / "compare" / &"{base}...{head}"
  client.request(path)
