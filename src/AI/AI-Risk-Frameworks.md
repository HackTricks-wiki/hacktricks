# Rủi ro AI

{{#include ../banners/hacktricks-training.md}}

## 10 lỗ hổng hàng đầu trong Machine Learning của OWASP

OWASP đã xác định 10 lỗ hổng hàng đầu trong machine learning có thể ảnh hưởng đến các hệ thống AI. Những lỗ hổng này có thể dẫn đến nhiều vấn đề bảo mật, bao gồm data poisoning, model inversion và adversarial attacks. Hiểu rõ những lỗ hổng này là yếu tố then chốt để xây dựng các hệ thống AI an toàn.

Để xem danh sách cập nhật và chi tiết về 10 lỗ hổng hàng đầu trong machine learning, tham khảo dự án [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Kẻ tấn công thêm những thay đổi nhỏ, thường không thể nhìn thấy, vào **dữ liệu đầu vào** để khiến mô hình đưa ra quyết định sai.\
    *Ví dụ*: Một vài vệt sơn trên biển báo dừng đánh lừa xe tự lái, khiến nó “nhìn thấy” biển giới hạn tốc độ.

- **Data Poisoning Attack**: **Tập dữ liệu huấn luyện** bị cố ý làm nhiễm các mẫu xấu, khiến mô hình học những quy tắc có hại.\
*Ví dụ*: Các mẫu malware bị gán nhãn sai là “lành tính” trong tập dữ liệu huấn luyện antivirus, khiến những malware tương tự có thể lọt qua sau này.

- **Model Inversion Attack**: Bằng cách thăm dò đầu ra, kẻ tấn công xây dựng một **mô hình đảo ngược** để tái tạo các đặc điểm nhạy cảm của đầu vào ban đầu.\
*Ví dụ*: Tái tạo ảnh MRI của bệnh nhân từ dự đoán của mô hình phát hiện ung thư.

- **Membership Inference Attack**: Kẻ tấn công kiểm tra xem **một bản ghi cụ thể** có được dùng trong quá trình huấn luyện hay không bằng cách nhận biết sự khác biệt về độ tin cậy.\
*Ví dụ*: Xác nhận rằng giao dịch ngân hàng của một người có trong dữ liệu huấn luyện của mô hình phát hiện gian lận.

- **Model Theft**: Truy vấn lặp đi lặp lại giúp kẻ tấn công tìm hiểu ranh giới quyết định và **sao chép hành vi của mô hình** (cũng như IP).\
*Ví dụ*: Thu thập đủ các cặp hỏi-đáp từ API ML-as-a-Service để tạo một mô hình cục bộ gần tương đương.

- **AI Supply‑Chain Attack**: Xâm nhập bất kỳ thành phần nào (dữ liệu, thư viện, trọng số được huấn luyện trước, CI/CD) trong **pipeline ML** để làm hỏng các mô hình phía sau.\
*Ví dụ*: Một dependency bị đầu độc trên model hub cài đặt mô hình phân tích cảm xúc có backdoor trên nhiều ứng dụng.

- **Transfer Learning Attack**: Logic độc hại được cài vào **mô hình được huấn luyện trước** và vẫn tồn tại sau khi fine-tune trên tác vụ của nạn nhân.\
*Ví dụ*: Một vision backbone có trigger ẩn vẫn đảo nhãn sau khi được điều chỉnh cho tác vụ chẩn đoán hình ảnh y tế.

- **Model Skewing**: Dữ liệu thiên lệch hoặc gán nhãn sai một cách tinh vi **làm lệch đầu ra của mô hình** để phục vụ mục đích của kẻ tấn công.\
*Ví dụ*: Chèn các email spam “sạch” được gán nhãn là ham để bộ lọc spam cho phép những email tương tự đi qua trong tương lai.

- **Output Integrity Attack**: Kẻ tấn công **thay đổi dự đoán của mô hình khi đang truyền**, chứ không sửa mô hình, nhằm đánh lừa các hệ thống phía sau.\
*Ví dụ*: Đổi kết quả “độc hại” của bộ phân loại malware thành “lành tính” trước khi bước cách ly tệp nhận được kết quả.

- **Model Poisoning** --- Thay đổi trực tiếp, có mục tiêu vào **tham số của mô hình**, thường sau khi giành được quyền ghi, để thay đổi hành vi.\
*Ví dụ*: Điều chỉnh trọng số của mô hình phát hiện gian lận trong môi trường production để giao dịch từ một số thẻ nhất định luôn được phê duyệt.


## Rủi ro Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) của Google nêu ra nhiều rủi ro liên quan đến các hệ thống AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Các tác nhân độc hại sửa đổi hoặc chèn dữ liệu huấn luyện/tinh chỉnh để làm giảm độ chính xác, cài backdoor hoặc làm lệch kết quả, từ đó ảnh hưởng đến tính toàn vẹn của mô hình trong toàn bộ vòng đời dữ liệu.

- **Unauthorized Training Data**: Việc tiếp nhận các tập dữ liệu có bản quyền, nhạy cảm hoặc chưa được cho phép tạo ra rủi ro pháp lý, đạo đức và hiệu năng vì mô hình học từ dữ liệu mà nó không được phép sử dụng.

- **Model Source Tampering**: Việc thao túng mã mô hình, dependencies hoặc trọng số trước hoặc trong quá trình huấn luyện từ chuỗi cung ứng hoặc người nội bộ có thể cài logic ẩn vẫn tồn tại ngay cả sau khi huấn luyện lại.

- **Excessive Data Handling**: Các biện pháp kiểm soát lưu giữ và quản trị dữ liệu yếu kém khiến hệ thống lưu trữ hoặc xử lý nhiều dữ liệu cá nhân hơn mức cần thiết, làm tăng nguy cơ lộ lọt và rủi ro tuân thủ.

- **Model Exfiltration**: Kẻ tấn công đánh cắp tệp/trọng số mô hình, gây mất tài sản trí tuệ và cho phép tạo dịch vụ sao chép hoặc thực hiện các cuộc tấn công tiếp theo.

- **Model Deployment Tampering**: Kẻ tấn công sửa đổi artifacts của mô hình hoặc hạ tầng phục vụ để mô hình đang chạy khác với phiên bản đã được kiểm duyệt, có khả năng làm thay đổi hành vi.

- **Denial of ML Service**: Làm ngập API hoặc gửi các đầu vào “sponge” có thể làm cạn tài nguyên tính toán/năng lượng và khiến mô hình ngừng hoạt động, tương tự các cuộc tấn công DoS cổ điển.

- **Model Reverse Engineering**: Bằng cách thu thập số lượng lớn cặp đầu vào-đầu ra, kẻ tấn công có thể sao chép hoặc distil mô hình, tạo điều kiện cho các sản phẩm bắt chước và adversarial attacks được tùy biến.

- **Insecure Integrated Component**: Các plugin, agent hoặc dịch vụ upstream dễ bị tấn công cho phép kẻ tấn công chèn mã hoặc leo thang đặc quyền trong pipeline AI.

- **Prompt Injection**: Tạo prompt (trực tiếp hoặc gián tiếp) để lén đưa vào các chỉ thị ghi đè mục đích của hệ thống, khiến mô hình thực hiện những lệnh không mong muốn.

- **Model Evasion**: Các đầu vào được thiết kế cẩn thận khiến mô hình phân loại sai, hallucinate hoặc tạo nội dung bị cấm, làm suy giảm độ an toàn và niềm tin.

- **Sensitive Data Disclosure**: Mô hình tiết lộ thông tin riêng tư hoặc bí mật từ dữ liệu huấn luyện hoặc ngữ cảnh người dùng, vi phạm quyền riêng tư và quy định.

- **Inferred Sensitive Data**: Mô hình suy luận các thuộc tính cá nhân chưa từng được cung cấp, gây ra những tổn hại mới về quyền riêng tư thông qua suy luận.

- **Insecure Model Output**: Các phản hồi chưa được làm sạch đưa mã độc hại, thông tin sai lệch hoặc nội dung không phù hợp đến người dùng hoặc hệ thống phía sau.

- **Rogue Actions**: Các agent được tích hợp tự động thực hiện những thao tác ngoài đời thực không mong muốn (ghi tệp, gọi API, mua hàng, v.v.) mà không có sự giám sát đầy đủ của người dùng.

## Ma trận Mitre AI ATLAS

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) cung cấp một framework toàn diện để hiểu và giảm thiểu các rủi ro liên quan đến hệ thống AI. Framework này phân loại nhiều kỹ thuật và chiến thuật tấn công mà kẻ thù có thể sử dụng nhắm vào mô hình AI, đồng thời cũng mô tả cách sử dụng hệ thống AI để thực hiện các cuộc tấn công khác nhau.<sup>[[3]](#references)</sup>

## LLMJacking (Đánh cắp token và bán lại quyền truy cập LLM được lưu trữ trên cloud)

Kẻ tấn công đánh cắp token phiên đang hoạt động hoặc thông tin xác thực API cloud rồi sử dụng trái phép các LLM trả phí được lưu trữ trên cloud. Quyền truy cập thường được bán lại thông qua reverse proxy đứng trước tài khoản của nạn nhân, ví dụ như các triển khai "oai-reverse-proxy". Hậu quả bao gồm thiệt hại tài chính, sử dụng mô hình ngoài chính sách và việc hoạt động bị quy trách nhiệm cho tenant của nạn nhân.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Thu thập token từ máy tính hoặc trình duyệt của nhà phát triển bị nhiễm; đánh cắp secrets CI/CD; mua cookie bị leak.<sup>[[5]](#references)</sup>
- Dựng reverse proxy chuyển tiếp yêu cầu đến nhà cung cấp chính thức, che giấu upstream key và phân phối yêu cầu cho nhiều khách hàng.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Lạm dụng các endpoint base-model trực tiếp để vượt qua guardrail và giới hạn tốc độ của doanh nghiệp.<sup>[[4]](#references)</sup>

**Tái sử dụng API key trong host:** Sau khi host bị xâm nhập, implant có thể gửi yêu cầu API model trực tiếp từ host của nạn nhân và chuyển tiếp phản hồi qua C2 mà không cần xuất API key cloud hoặc chạy AI CLI cục bộ. Trong handler được quan sát, key do C2 cung cấp được ưu tiên; chỉ khi không có key đó, implant mới đọc `OPENAI_API_KEY` từ môi trường tiến trình của chính nó. Do đó, việc sử dụng tài khoản của nạn nhân đòi hỏi một key hợp lệ mà tiến trình đó có thể truy cập và quyền truy cập vào model API. Prompt của operator được gửi đến Chat Completions API, còn đầu ra của mô hình và mức sử dụng token được trả về qua C2. Điều này có thể tiêu thụ quyền truy cập mô hình trả phí của nạn nhân mà không cần chạy các công cụ AI của nhà phát triển, khác với việc lạm dụng [cấu hình AI CLI cục bộ hoặc MCP](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Biện pháp giảm thiểu:
- Ràng buộc token với dấu vân tay thiết bị, dải IP và xác thực client; áp dụng thời hạn ngắn và yêu cầu MFA khi làm mới.
- Giới hạn key ở mức tối thiểu (không cấp quyền truy cập tool, chỉ đọc khi phù hợp); xoay vòng key khi phát hiện bất thường.
- Định tuyến toàn bộ traffic phía server qua policy gateway để áp dụng bộ lọc an toàn, hạn mức theo route và cách ly tenant.
- Theo dõi các kiểu sử dụng bất thường (chi phí tăng đột biến, khu vực không thường dùng, chuỗi UA) và tự động thu hồi các phiên đáng ngờ.
- Ưu tiên mTLS hoặc JWT được IdP của bạn cấp và ký thay vì API key tĩnh có thời hạn dài.

## Tăng cường bảo mật cho suy luận LLM tự host

Chạy máy chủ LLM cục bộ để xử lý dữ liệu mật tạo ra bề mặt tấn công khác với API được lưu trữ trên cloud: các endpoint suy luận/Debug có thể làm lộ prompt, stack phục vụ thường để lộ reverse proxy, còn các node thiết bị GPU cho phép truy cập vào những bề mặt `ioctl()` lớn. Nếu bạn đang đánh giá hoặc triển khai dịch vụ suy luận on-prem, hãy xem xét ít nhất các điểm sau.<sup>[[8]](#references)</sup>

### Rò rỉ prompt qua các endpoint debug và giám sát

Hãy xem API suy luận là một **dịch vụ nhạy cảm, đa người dùng**. Các route debug hoặc giám sát có thể làm lộ nội dung prompt, trạng thái slot, metadata mô hình hoặc thông tin hàng đợi nội bộ. Trong `llama.cpp`, endpoint `/slots` đặc biệt nhạy cảm vì nó để lộ trạng thái của từng slot và chỉ предназначен cho việc kiểm tra/quản lý slot.<sup>[[8]](#references)</sup>

Để fingerprint black-box và kiểm thử các model runner bị lộ cùng các dịch vụ AI liên quan, hãy xem [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Đặt reverse proxy trước máy chủ suy luận và **mặc định từ chối**.
- Chỉ đưa vào allowlist các tổ hợp HTTP method + path chính xác mà client/UI cần.
- Bất cứ khi nào có thể, hãy tắt các endpoint introspection ngay trong backend, ví dụ `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Bind reverse proxy với `127.0.0.1` và truy cập thông qua một transport đã xác thực như SSH local port forwarding, thay vì công khai trên LAN.

Ví dụ allowlist với nginx:

```nginx
map "$request_method:$uri" $llm_whitelist {
    default 0;

    "GET:/health"              1;
    "GET:/v1/models"           1;
    "POST:/v1/completions"     1;
    "POST:/v1/chat/completions" 1;
}

server {
    listen 127.0.0.1:80;

    location / {
        if ($llm_whitelist = 0) { return 403; }
        proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
    }
}
```

### Container không root, không có network và UNIX socket

Nếu inference daemon hỗ trợ lắng nghe trên UNIX socket, hãy ưu tiên cách này thay vì TCP và chạy container **không có network stack**:<sup>[[8]](#references)</sup>

```bash
podman run --rm -d \
  --network none \
  --user 1000:1000 \
  --userns=keep-id \
  --umask=007 \
  --volume /var/lib/models:/models:ro \
  --volume /srv/llm/socks:/run/llama-cpp \
  ghcr.io/ggml-org/llama.cpp:server-cuda13 \
    --host /run/llama-cpp/llama-cpp.sock \
    --model /models/model.gguf \
    --parallel 4 \
    --no-slots
```

Lợi ích:
- `--network none` loại bỏ khả năng bị lộ qua TCP/IP cả chiều vào lẫn chiều ra, đồng thời tránh dùng các trình trợ giúp ở user-mode mà container rootless nếu không sẽ cần.
- UNIX socket cho phép dùng quyền POSIX/ACL trên đường dẫn socket làm lớp kiểm soát truy cập đầu tiên.
- `--userns=keep-id` và Podman rootless giảm tác động của việc thoát container vì root trong container không phải root trên host.
- Mount model chỉ đọc giảm khả năng model bị sửa đổi từ bên trong container.

Với các triển khai lâu dài, có thể áp dụng những hạn chế tương tự bằng các đơn vị Podman Quadlet. Nếu quyền truy cập GPU được ủy quyền thông qua Container Device Interface, hãy giữ đặc tả thiết bị CDI càng hẹp càng tốt thay vì để lộ mọi nút tăng tốc.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Giảm thiểu các nút thiết bị GPU

Đối với suy luận dùng GPU, các tệp `/dev/nvidia*` là bề mặt tấn công cục bộ có giá trị cao vì chúng cung cấp quyền truy cập vào các trình xử lý `ioctl()` lớn và có khả năng cả những đường dẫn quản lý bộ nhớ GPU dùng chung.<sup>[[8]](#references)</sup>

- Không để `/dev/nvidia*` có quyền ghi cho mọi người.
- Hạn chế `nvidia`, `nvidiactl` và `nvidia-uvm` bằng `NVreg_DeviceFileUID/GID/Mode`, quy tắc udev và ACL để chỉ UID được ánh xạ của container mới có thể mở chúng.
- Chặn các module không cần thiết như `nvidia_drm`, `nvidia_modeset` và `nvidia_peermem` trên các máy chủ suy luận không có giao diện đồ họa.
- Nạp trước khi khởi động chỉ những module cần thiết, thay vì để runtime tự gọi `modprobe` khi khởi chạy suy luận.

Ví dụ:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Một điểm quan trọng cần xem xét là **`/dev/nvidia-uvm`**. Ngay cả khi workload không sử dụng `cudaMallocManaged()` một cách tường minh, các CUDA runtime gần đây vẫn có thể yêu cầu `nvidia-uvm`. Vì thiết bị này được chia sẻ và xử lý việc quản lý bộ nhớ ảo của GPU, hãy xem nó là một bề mặt có nguy cơ làm lộ dữ liệu giữa các tenant. Nếu inference backend hỗ trợ, Vulkan backend có thể là một lựa chọn đáng cân nhắc vì có thể tránh hoàn toàn việc để lộ `nvidia-uvm` cho container.<sup>[[8]](#references)</sup>

### Cô lập LSM cho các inference worker

Nên sử dụng AppArmor/SELinux/seccomp để tăng cường bảo vệ cho tiến trình inference:<sup>[[8]](#references)</sup>

- Chỉ cho phép các thư viện dùng chung, đường dẫn model, thư mục socket và các nút thiết bị GPU thực sự cần thiết.
- Chủ động từ chối các capability có rủi ro cao như `sys_admin`, `sys_module`, `sys_rawio` và `sys_ptrace`.
- Để thư mục model ở chế độ chỉ đọc và chỉ giới hạn các đường dẫn có thể ghi trong thư mục socket/cache runtime.
- Theo dõi log từ chối vì chúng cung cấp dữ liệu đo từ xa hữu ích để phát hiện khi model server hoặc payload post-exploitation cố thoát khỏi hành vi dự kiến.

Ví dụ về các quy tắc AppArmor cho worker sử dụng GPU:

```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```

## Phantom Squatting: Các domain do LLM ảo giác tạo ra như một vector tấn công chuỗi cung ứng AI

Phantom squatting là **phiên bản tương đương domain/URL của slopsquatting**. Thay vì ảo giác ra một tên package không tồn tại, LLM ảo giác ra một **domain portal, API, webhook, billing, SSO, download hoặc support** có vẻ hợp lý cho một thương hiệu có thật, rồi kẻ tấn công đăng ký namespace đó trước khi con người hoặc agent sử dụng nó.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Điều này quan trọng vì trong nhiều quy trình có AI hỗ trợ, đầu ra của model được xem là **dependency đáng tin cậy**:
- Developer dán endpoint được đề xuất vào code hoặc tích hợp CI/CD.
- AI agent tự động lấy tài liệu, schema, APK, ZIP hoặc đích webhook.
- Runbook hoặc tài liệu được tạo có thể nhúng URL giả như thể đó là URL chính thức.

### Quy trình tấn công

1. **Thăm dò bề mặt ảo giác**: đặt câu hỏi cụ thể về thương hiệu, xoay quanh các workflow thực tế như portal `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` hoặc `mobile app`.<sup>[[12]](#references)</sup>
2. **Chuẩn hóa các ứng viên**: phân giải URL được tạo, rút gọn các phản hồi NXDOMAIN về domain cha có thể đăng ký, rồi loại bỏ trùng lặp giữa các nhóm prompt. Bộ prompt nên đa dạng, chẳng hạn loại các mục gần trùng lặp bằng **Jaccard similarity**.
3. **Ưu tiên các ảo giác dễ dự đoán**:
   - **Thermal Hallucination Persistence (THP)**: cùng một domain giả xuất hiện ở nhiều mức temperature, kể cả mức thấp như `T=0.1`.
   - **Đồng thuận giữa các model**: nhiều họ LLM tạo ra cùng một domain giả.
4. **Đăng ký và vũ khí hóa** domain cha, sau đó lưu trữ trang phishing, bản tải APK/ZIP giả, công cụ thu thập thông tin xác thực, tài liệu độc hại hoặc endpoint API thu thập bí mật/ payload webhook. **Ảo giác thuần cấp domain** dễ kiếm tiền nhất vì kẻ tấn công kiểm soát toàn bộ namespace; ảo giác về subdomain/path vẫn có thể bị khai thác nếu domain cha đã được chuẩn hóa chưa được đăng ký.
5. **Khai thác khoảng thời gian chưa có danh tiếng**: domain mới đăng ký thường chưa có lịch sử trong blocklist, thông tin danh tiếng URL và telemetry đủ lâu, nên có thể vượt qua các biện pháp kiểm soát cho đến khi hệ thống phát hiện bắt kịp. Kẻ tấn công có thể kéo dài khoảng thời gian này bằng cách chỉ trả về nội dung lành tính cho crawler, che giấu bằng redirect, dùng CAPTCHA hoặc trì hoãn triển khai payload.

### Vì sao agent gặp nguy hiểm

Với nạn nhân là con người, domain giả thường vẫn cần một cú click và một thao tác tiếp theo. Trong **workflow agentic**, LLM có thể vừa là **mồi nhử** vừa là **bên thực thi**: agent nhận URL do ảo giác tạo ra, truy cập URL đó, phân tích phản hồi, rồi có thể làm lộ token, thực thi chỉ dẫn, tải dependency hoặc đưa dữ liệu bị đầu độc vào CI/CD mà không cần con người xem xét.<sup>[[12]](#references)</sup>

### Prompt thực tế dành cho kẻ tấn công

Các prompt có hiệu quả cao thường giống tác vụ doanh nghiệp thông thường hơn là lời dụ phishing rõ ràng:<sup>[[12]](#references)</sup>
- “URL payment sandbox cho các tích hợp `<brand>` là gì?”
- “Tôi nên dùng endpoint webhook nào cho thông báo bản build của `<brand>`?”
- “Portal benefits / billing / SSO dành cho nhân viên của `<brand>` ở đâu?”
- “Hãy cho tôi link tải trực tiếp Android APK hoặc desktop client của `<brand>`.”

### Đảo chiều phòng thủ

Hãy xem đây là vấn đề giám sát domain chủ động, không chỉ là vấn đề prompt injection:<sup>[[12]](#references)</sup>
- Xây dựng **bộ prompt theo thương hiệu** và định kỳ thăm dò các LLM mà người dùng/agent của bạn dựa vào.
- Lưu URL do ảo giác tạo ra và theo dõi URL nào ổn định qua các mức temperature/model.
- Theo dõi **Adversarial Exploitation Window (AEW)**: khoảng thời gian từ lúc ảo giác xuất hiện lần đầu đến khi kẻ tấn công đăng ký domain. AEW dương nghĩa là bên phòng thủ có thể đăng ký trước, sinkhole hoặc chặn trước khi domain bị vũ khí hóa.
- Giám sát các chuyển đổi **NXDOMAIN → đã đăng ký** của domain cha.
- Khi domain được đăng ký, phân loại registrar, ngày tạo, nameserver, biện pháp che giấu thông tin, nội dung trang, ảnh chụp màn hình, trạng thái trang đỗ domain và mức độ tương đồng với tài sản thương hiệu.
- Thêm các cổng kiểm soát chính sách để agent/developer **không mặc định tin cậy domain do LLM tạo ra**: yêu cầu allowlist, xác thực quyền sở hữu, kiểm tra CT/RDAP hoặc phê duyệt của con người trước lần sử dụng đầu tiên.

Điều này đồng thời thuộc nhiều nhóm rủi ro AI: **tấn công chuỗi cung ứng AI**, **đầu ra model không an toàn** và **hành động trái phép** khi agent tự động sử dụng URL do ảo giác tạo ra.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Top 10 lỗ hổng Machine Learning của OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Rủi ro](https://saif.google/secure-ai-framework/risks)
- [3] [Ma trận mối đe dọa MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Rủi ro của các LLM trợ lý code: Nội dung có hại, lạm dụng và lừa đảo](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Thông tin xác thực cloud bị đánh cắp được dùng trong cuộc tấn công AI mới](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Tổng quan về thủ đoạn LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (bán lại quyền truy cập LLM bị đánh cắp)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Phân tích chuyên sâu về triển khai máy chủ LLM on-premise với quyền hạn thấp](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README máy chủ llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Đặc tả CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Các domain do AI ảo giác tạo ra như một vector tấn công chuỗi cung ứng phần mềm](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Cách ảo giác AI tiếp sức cho một lớp tấn công chuỗi cung ứng mới](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: Framework command-and-control mới được hỗ trợ bởi AI](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
