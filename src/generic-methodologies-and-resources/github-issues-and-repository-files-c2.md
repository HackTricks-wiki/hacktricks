# GitHub Issues and Repository Files as a C2 Channel

{{#include ../banners/hacktricks-training.md}}

A private repository can separate **session state** from **payload transfer**: issues record each host and its handshake state, while repository files carry encrypted data in both directions. This is more than simply polling an issue body for commands. The observed implementation uses a GitHub personal access token (PAT) to access both APIs.<sup>[[1]](#references)</sup> For a fine-grained PAT, creating or updating issues needs Issues write permission, and uploading files needs Contents write permission. A classic PAT instead needs the `repo` scope. Anyone who obtains a sufficiently privileged token can access the same channel.<sup>[[2]](#references)[[3]](#references)</sup>

## Issue and file handshake

One observed workflow uses a short hexadecimal host ID and the following state machine. The exact ID range, strings and prefixes are protocol markers, not GitHub API requirements.<sup>[[1]](#references)</sup>

1. On startup, query open and closed issues with `GET /repos/{owner}/{repo}/issues?state=open` (and `state=closed`) to find prior session state. Create an open issue titled `1[ID]` with body `hel` using `POST /repos/{owner}/{repo}/issues`.
2. Read a repository file whose name starts with `2[ID]`; it supplies the server's RSA public key. Generate a fresh 16-byte session key, RSA-encrypt it and upload the result in a file prefixed `1[ID]`.
3. Derive the subsequent IV by XORing the embedded IV with that session key. For each exchanged file, use its filename's random 16-byte key to AES-encrypt or decrypt the contents. Prefix `2` denotes server-to-host data; prefix `1` denotes host-to-server data. Thus the filename carries routing and per-file key material, while the issue carries state.
4. Read the next `2`-prefixed file and require its decrypted contents to equal `hel`. Upload encrypted host information, then change the issue body to `hey` with `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Only then start command polling.

GitHub's Contents API reads a file through `GET /repos/{owner}/{repo}/contents/{path}` and creates or replaces one through `PUT` at that path. For files of at most 1 MB, the default JSON response includes Base64-encoded content; files between 1 and 100 MB need the raw media type to retrieve their contents. The upload body needs a commit message and Base64-encoded file contents; replacing an existing file also needs its current blob SHA. Those API details are distinct from the encryption protocol above.<sup>[[2]](#references)[[3]](#references)</sup>

For an authorized test repository, the issue-control portion can be exercised with the REST API (substitute a test repository and test PAT). Do not place a live token in the URL, issue body or committed file.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

The mechanism does **not** require the issue title, `hel`/`hey` markers or the particular cipher choices shown here; those identify one implementation. The reusable idea is to split mutable host state from bidirectional encrypted objects, and to bind both to a host ID.<sup>[[1]](#references)</sup> For another GitHub-issue transport, see the [AdaptixC2 custom listener notes](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). For an issue-comment fallback that rotates repository credentials rather than carrying session state, see [Web services and dead-drop resolvers](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – REST API endpoints for issues](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – REST API endpoints for repository contents](https://docs.github.com/en/rest/repos/contents)
