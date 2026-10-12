#!/usr/bin/env python3
"""Merge up to two approved PRs when other repository workflows are idle."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path


AUTHORIZED_USER = "carlospolop"
WORKFLOW_NAME = "Auto Merge Approved PRs"
ACTIVE_STATUSES = ("in_progress", "queued", "waiting", "pending", "requested")


def is_merge_comment(comment):
    return (
        comment.get("user", {}).get("login") == AUTHORIZED_USER
        and comment.get("body", "").strip().casefold() == "merge"
    )


def should_handle_event(name, event):
    if name == "issue_comment":
        return bool(event.get("issue", {}).get("pull_request")) and is_merge_comment(
            event.get("comment", {})
        )
    if name == "workflow_run":
        run = event.get("workflow_run", {})
        return run.get("status") == "completed" and run.get("name") != WORKFLOW_NAME
    return name in ("workflow_dispatch", "pull_request_target", "schedule")


def gh_json(arguments):
    for attempt in range(1, 6):
        result = subprocess.run(
            ["gh", *arguments], capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise RuntimeError("GitHub CLI returned invalid JSON") from error
        if attempt == 5:
            raise RuntimeError(result.stderr.strip() or "GitHub CLI request failed")
        print(f"GitHub request failed; retrying ({attempt}/5)", flush=True)
        time.sleep(2 * attempt)


def api_pages(endpoint):
    pages = gh_json(["api", "--paginate", "--slurp", endpoint])
    if not isinstance(pages, list):
        raise RuntimeError("Expected paginated GitHub API results")
    return pages


def api_items(endpoint):
    pages = api_pages(endpoint)
    if not all(isinstance(page, list) for page in pages):
        raise RuntimeError("Expected lists in paginated GitHub API results")
    return [item for page in pages for item in page]


def other_workflows_active(repo, merger_workflow_id):
    # Exclude every merger instance, including the pending concurrency run.
    for status in ACTIVE_STATUSES:
        pages = api_pages(f"repos/{repo}/actions/runs?status={status}&per_page=100")
        for page in pages:
            for run in page["workflow_runs"]:
                if run["workflow_id"] != merger_workflow_id and run["status"] != "completed":
                    label = run.get("name") or run.get("id")
                    print(f"Other workflow is {run['status']}: {label}", flush=True)
                    return True
    return False


def approved_by_title(pr):
    return (
        pr.get("user", {}).get("login") == AUTHORIZED_USER
        and pr.get("title", "").startswith("Research Update Enhanced")
    )


def merge_details(repo, number):
    for attempt in range(11):
        details = gh_json([
            "pr", "view", str(number), "--repo", repo,
            "--json", "state,isDraft,mergeable,headRefOid",
        ])
        if details["state"] != "OPEN" or details["isDraft"] or details["mergeable"] != "UNKNOWN":
            return details
        if attempt < 10:
            time.sleep(2)
    return details


def merge_pr(repo, number, head_sha):
    result = subprocess.run([
        "gh", "pr", "merge", str(number), "--repo", repo,
        "--merge", "--delete-branch", "--match-head-commit", head_sha,
    ], capture_output=True, text=True, check=False)
    if result.returncode:
        print(f"PR #{number} was not merged: {result.stderr.strip()}", flush=True)
        return False
    print(f"Merged PR #{number}", flush=True)
    return True


def merge_approved(repo, merger_workflow_id, max_merges=2):
    if other_workflows_active(repo, merger_workflow_id):
        print("Repository is busy; retrying on the next workflow completion.")
        return 0
    prs = api_items(f"repos/{repo}/pulls?state=open&sort=created&direction=asc&per_page=100")
    merged = 0
    for pr in prs:
        if merged >= max_merges:
            break
        if pr.get("draft"):
            continue
        number = pr["number"]
        try:
            if not approved_by_title(pr):
                comments = api_items(f"repos/{repo}/issues/{number}/comments?per_page=100")
                if not any(is_merge_comment(comment) for comment in comments):
                    continue
            details = merge_details(repo, number)
        except RuntimeError as error:
            print(f"Cannot verify PR #{number}; skipping: {error}", flush=True)
            continue
        if details["state"] != "OPEN" or details["isDraft"]:
            continue
        if details["mergeable"] != "MERGEABLE":
            print(f"Skipping PR #{number}: {details['mergeable']}", flush=True)
            continue
        # A preceding merge may have queued a build while approvals were read.
        if other_workflows_active(repo, merger_workflow_id):
            print("Another workflow started; stopping this merge batch.")
            break
        if merge_pr(repo, number, details["headRefOid"]):
            merged += 1
    print(f"Merged {merged} approved PR(s).", flush=True)
    return merged


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    if not should_handle_event(os.environ["GITHUB_EVENT_NAME"], event):
        print("Event does not request an approval check.")
        return 0
    repo = os.environ["GITHUB_REPOSITORY"]
    run_id = os.environ["GITHUB_RUN_ID"]
    current_run = gh_json(["api", f"repos/{repo}/actions/runs/{run_id}"])
    merge_approved(repo, current_run["workflow_id"])
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, KeyError, OSError, ValueError) as error:
        print(f"Merger stopped without bypassing verification: {error}", file=sys.stderr)
        sys.exit(1)
