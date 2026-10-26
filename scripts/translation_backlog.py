#!/usr/bin/env python3
"""Track which English source blobs have been translated on a language branch.

The language branches do not share ancestry with master, so comparing their
Markdown contents cannot tell whether translated prose is current. Each branch
instead records the Git blob ID of every English page it has translated.
"""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path


STATE_PATH = Path(".translation-source-blobs.json")


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])


def markdown_blobs(ref: str) -> dict[str, str]:
    result = {}
    for entry in git("ls-tree", "-rz", ref, "--", "src").split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        if path.endswith(".md") and path != "src/SUMMARY.md":
            result[path] = metadata.split()[2].decode("ascii")
    return result


def language_files(branch: str) -> set[str]:
    return set(markdown_blobs(branch))


def load_state(branch: str, existing_files: set[str]) -> dict[str, str]:
    try:
        state_json = subprocess.check_output(
            ["git", "show", f"{branch}:{STATE_PATH}"], stderr=subprocess.DEVNULL
        )
        state = json.loads(state_json.decode("utf-8"))
    except subprocess.CalledProcessError:
        # New language branches have no translations yet, even if they were
        # initially copied from master and contain English Markdown files.
        return {}
    if state.get("schema") != 1 or not isinstance(state.get("sources"), dict):
        raise ValueError(f"Invalid translation state on {branch}")
    return state["sources"]


def extra_paths(args: argparse.Namespace) -> set[str]:
    values = []
    if args.extras:
        values.append(Path(args.extras).read_text(encoding="utf-8"))
    if args.extra_env:
        values.append(os.environ.get(args.extra_env, ""))
    return {path.strip() for value in values for path in re.split(r"[,\n]", value) if path.strip()}


def pending(branch: str, source_ref: str, extras: set[str]) -> list[str]:
    source = markdown_blobs(source_ref)
    existing = language_files(branch)
    state = load_state(branch, existing)
    return sorted(
        path for path, blob in source.items()
        if path not in existing or state.get(path) != blob or path in extras
    )


def file_list(path: str) -> list[str]:
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "mark", "verify"))
    parser.add_argument("--language", required=True, help="Local language branch name")
    parser.add_argument("--source-ref", default="master")
    parser.add_argument("--output", help="Newline-delimited output for plan")
    parser.add_argument("--file-list", help="Completed batch for mark")
    parser.add_argument("--extras", help="Comma- or newline-delimited paths to retry")
    parser.add_argument("--extra-env", help="Environment variable with comma-delimited paths")
    args = parser.parse_args()

    if args.action == "plan":
        if not args.output:
            parser.error("plan requires --output")
        paths = pending(args.language, args.source_ref, extra_paths(args))
        Path(args.output).write_text("".join(f"{path}\n" for path in paths), encoding="utf-8")
        print(f"{args.language}: {len(paths)} English pages pending translation")
    elif args.action == "mark":
        if not args.file_list:
            parser.error("mark requires --file-list")
        if git("rev-parse", "--abbrev-ref", "HEAD").decode().strip() != args.language:
            raise RuntimeError(f"mark must run on {args.language}")
        source = markdown_blobs(args.source_ref)
        existing = language_files(args.language)
        state = load_state(args.language, existing)
        paths = file_list(args.file_list)
        for path in paths:
            if path not in source or not Path(path).is_file():
                raise RuntimeError(f"Translated page is missing: {path}")
            state[path] = source[path]
        STATE_PATH.write_text(
            json.dumps({"schema": 1, "sources": state}, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Recorded {len(paths)} translated pages for {args.language}")
    else:
        paths = pending(args.language, args.source_ref, set())
        if paths:
            raise SystemExit(f"{args.language}: {len(paths)} pages still pending; first: {paths[:10]}")
        print(f"{args.language}: all English source pages have translations")


if __name__ == "__main__":
    main()
