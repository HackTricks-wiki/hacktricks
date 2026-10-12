"""Decide whether this run still has to create a CloudFront invalidation.

A single push to master fans out into several workflows that each invalidate an
overlapping set of paths, and CloudFront bills every path past the first 1000
each month. When a later run is *guaranteed* to invalidate a superset of what
this run would, doing it here only costs money.

Every check is a reason to skip, so anything that cannot be answered - a failed
API call, an unexpected payload - leaves the invalidation in place. Serving a
stale wiki is far more expensive than the half cent a redundant path costs.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"


def log(message):
    print(message, file=sys.stderr)


def api(path, token, method="GET", payload=None):
    url = path if path.startswith("http") else f"{API}/{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def covering_run_is_handling_this_commit(repo, sha, token, workflows):
    """True when a workflow whose invalidation is a superset runs for this commit.

    GitHub creates every run a push triggers up front, so a workflow that is
    absent here genuinely was not triggered and cannot be relied on.
    """
    for workflow in workflows:
        query = urllib.parse.urlencode({"head_sha": sha, "per_page": 20})
        runs = api(f"repos/{repo}/actions/workflows/{workflow}/runs?{query}", token)
        for run in runs.get("workflow_runs", []):
            status = run.get("status")
            conclusion = run.get("conclusion")
            if status in ("queued", "in_progress", "waiting", "requested", "pending"):
                return f"{workflow} is invalidating a superset for this same commit (status {status})"
            if status == "completed" and conclusion == "success":
                return f"{workflow} already invalidated a superset for this same commit"
    return None


def newer_run_of_this_workflow(repo, run_id, workflow_file, token):
    """True when a newer run of this same workflow is already queued behind us."""
    this_run = api(f"repos/{repo}/actions/runs/{run_id}", token)
    created_at = this_run.get("created_at")
    if not created_at:
        return None

    runs = api(f"repos/{repo}/actions/workflows/{workflow_file}/runs?per_page=30", token)
    newer = [
        run
        for run in runs.get("workflow_runs", [])
        if str(run.get("id")) != str(run_id)
        and run.get("status") in ("queued", "in_progress", "waiting")
        and (run.get("created_at") or "") > created_at
    ]
    if newer:
        numbers = ", ".join(str(run.get("run_number")) for run in newer)
        return f"newer run(s) #{numbers} of this workflow are queued and will invalidate instead"
    return None


MERGE_QUERY = """
query($owner:String!, $name:String!, $cursor:String) {
  repository(owner:$owner, name:$name) {
    pullRequests(states:OPEN, first:50, after:$cursor,
                 orderBy:{field:UPDATED_AT, direction:DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        isDraft
        mergeable
        comments(last:50) { nodes { author { login } body } }
      }
    }
  }
}
"""


def pull_requests_awaiting_auto_merge(repo, token, author):
    """Open pull requests the auto-merge workflow is going to merge shortly.

    Merging one pushes to the default branch, which invalidates again. Only a
    pull request that can actually be merged counts: the auto-merge workflow
    skips a conflicted one, so counting it would suppress invalidations for as
    long as the conflict lasts.
    """
    owner, name = repo.split("/", 1)
    cursor = None
    waiting = []
    for _ in range(10):
        result = api(
            "graphql",
            token,
            method="POST",
            payload={"query": MERGE_QUERY, "variables": {"owner": owner, "name": name, "cursor": cursor}},
        )
        if "errors" in result:
            raise RuntimeError(result["errors"])
        page = result["data"]["repository"]["pullRequests"]
        for node in page["nodes"]:
            if node.get("isDraft") or node.get("mergeable") != "MERGEABLE":
                continue
            for comment in node["comments"]["nodes"]:
                if (comment.get("author") or {}).get("login") != author:
                    continue
                # The auto-merge workflow matches the first line of the comment
                # against exactly "merge", case insensitively.
                first_line = (comment.get("body") or "").replace("\r", "").split("\n")[0]
                if first_line.strip().lower() == "merge":
                    waiting.append(node["number"])
                    break
        if not page["pageInfo"]["hasNextPage"]:
            break
        cursor = page["pageInfo"]["endCursor"]
    return waiting


def decide(needed, reason):
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"needed={'true' if needed else 'false'}\n")
            handle.write(f"reason={reason}\n")
    print(f"::notice title=CloudFront invalidation::needed={needed} - {reason}")
    sys.exit(0)


def main():
    token = os.environ["INPUT_GITHUB_TOKEN"]
    repo = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["GITHUB_SHA"]
    run_id = os.environ["GITHUB_RUN_ID"]
    author = os.environ.get("INPUT_MERGE_COMMENT_AUTHOR", "carlospolop")
    covered_by = [w.strip() for w in os.environ.get("INPUT_COVERED_BY", "").split(",") if w.strip()]

    # "owner/repo/.github/workflows/build_master.yml@refs/heads/master" - the ref
    # after the @ contains slashes, so it has to be cut off before basename.
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    workflow_file = os.path.basename(workflow_ref.split("@", 1)[0]) if workflow_ref else ""

    try:
        if covered_by:
            reason = covering_run_is_handling_this_commit(repo, sha, token, covered_by)
            if reason:
                decide(False, reason)

        if workflow_file:
            reason = newer_run_of_this_workflow(repo, run_id, workflow_file, token)
            if reason:
                decide(False, reason)

        # An empty author disables this check, for a repository that has no
        # auto-merge workflow: nothing there turns a pending pull request into a
        # push, so waiting for one would suppress invalidations indefinitely.
        waiting = pull_requests_awaiting_auto_merge(repo, token, author) if author else []
        if waiting:
            numbers = ", ".join(f"#{n}" for n in waiting)
            decide(
                False,
                f"pull request(s) {numbers} are mergeable and carry a 'merge' comment "
                f"from {author}; auto-merge will push and invalidate again",
            )
    except Exception as exc:  # noqa: BLE001 - any doubt must keep the invalidation
        log(f"invalidation guard could not reach a conclusion: {exc!r}")
        decide(True, "the guard could not prove a later invalidation is coming")

    decide(True, "no later run is guaranteed to invalidate these paths")


if __name__ == "__main__":
    main()
