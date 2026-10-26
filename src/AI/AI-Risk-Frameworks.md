# Rủi ro AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Lỗ hổng Machine Learning

OWASP đã xác định 10 lỗ hổng machine learning hàng đầu có thể ảnh hưởng đến các hệ thống AI. Những lỗ hổng này có thể dẫn đến nhiều vấn đề bảo mật, bao gồm đầu độc dữ liệu, đảo ngược mô hình và tấn công đối kháng. Hiểu rõ các lỗ hổng này là điều thiết yếu để xây dựng các hệ thống AI an toàn.

Để xem danh sách 10 lỗ hổng machine learning hàng đầu đã cập nhật và chi tiết, hãy tham khảo dự án [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Kẻ tấn công thêm những thay đổi rất nhỏ, thường không nhìn thấy được, vào **dữ liệu đầu vào** khiến mô hình đưa ra quyết định sai.\
    *Ví dụ*: Vài đốm sơn trên biển báo dừng đánh lừa xe tự lái, khiến xe "nhìn thấy" biển giới hạn tốc độ.

- **Data Poisoning Attack**: **Tập huấn luyện** bị cố ý làm nhiễm bẩn bằng các mẫu sai lệch, khiến mô hình học theo những quy tắc có hại.\
*Ví dụ*: Các tệp nhị phân malware bị gắn nhãn nhầm là "lành tính" trong tập dữ liệu huấn luyện antivirus, khiến những malware tương tự dễ dàng qua mặt hệ thống sau này.

- **Model Inversion Attack**: Bằng cách thăm dò đầu ra, kẻ tấn công tạo ra một **mô hình ngược** để tái dựng các đặc điểm nhạy cảm từ đầu vào ban đầu.\
*Ví dụ*: Tái tạo ảnh MRI của bệnh nhân từ các dự đoán của mô hình phát hiện ung thư.

- **Membership Inference Attack**: Kẻ tấn công kiểm tra xem một **bản ghi cụ thể** có được dùng trong quá trình huấn luyện hay không bằng cách nhận biết sự khác biệt về độ tin cậy.\
*Ví dụ*: Xác nhận rằng giao dịch ngân hàng của một người xuất hiện trong dữ liệu huấn luyện của mô hình phát hiện gian lận.

- **Model Theft**: Truy vấn lặp đi lặp lại giúp kẻ tấn công tìm hiểu ranh giới quyết định và **sao chép hành vi của mô hình** (cùng IP).\
*Ví dụ*: Thu thập đủ cặp hỏi đáp từ API ML-as-a-Service để xây dựng một mô hình cục bộ gần tương đương.

- **AI Supply‑Chain Attack**: Xâm phạm bất kỳ thành phần nào (dữ liệu, thư viện, trọng số tiền huấn luyện, CI/CD) trong **ML pipeline** để làm hỏng các mô hình phía sau.\
*Ví dụ*: Một dependency bị đầu độc trên model hub cài đặt mô hình phân tích cảm xúc có backdoor trên nhiều ứng dụng.

- **Transfer Learning Attack**: Logic độc hại được cài vào **mô hình tiền huấn luyện** và vẫn tồn tại sau khi fine-tune cho tác vụ của nạn nhân.\
*Ví dụ*: Một vision backbone có trigger ẩn vẫn làm đảo nhãn sau khi được điều chỉnh cho việc chụp ảnh y tế.

- **Model Skewing**: Dữ liệu bị thiên lệch hoặc gắn nhãn sai một cách tinh vi **làm lệch đầu ra của mô hình** theo hướng có lợi cho mục đích của kẻ tấn công.\
*Ví dụ*: Chèn email spam "sạch" được gắn nhãn là thư thường, khiến bộ lọc spam cho phép các email tương tự trong tương lai đi qua.

- **Output Integrity Attack**: Kẻ tấn công **thay đổi dự đoán của mô hình khi dữ liệu đang được truyền**, chứ không thay đổi bản thân mô hình, để đánh lừa các hệ thống phía sau.\
*Ví dụ*: Đổi kết quả "độc hại" của bộ phân loại malware thành "lành tính" trước khi tệp được chuyển đến giai đoạn cách ly.

- **Model Poisoning** --- Thay đổi trực tiếp, có chủ đích đối với **các tham số mô hình**, thường là sau khi giành được quyền ghi, nhằm thay đổi hành vi.\
*Ví dụ*: Điều chỉnh trọng số của mô hình phát hiện gian lận trong môi trường production để các giao dịch từ một số thẻ nhất định luôn được chấp thuận.


## Rủi ro Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) của Google nêu ra nhiều rủi ro liên quan đến các hệ thống AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Các tác nhân độc hại thay đổi hoặc chèn dữ liệu huấn luyện/tinh chỉnh để làm giảm độ chính xác, cài backdoor hoặc làm lệch kết quả, từ đó làm suy yếu tính toàn vẹn của mô hình trong toàn bộ vòng đời dữ liệu.

- **Unauthorized Training Data**: Việc tiếp nhận các tập dữ liệu có bản quyền, nhạy cảm hoặc chưa được cho phép tạo ra rủi ro pháp lý, đạo đức và hiệu năng vì mô hình học từ dữ liệu mà nó không được phép sử dụng.

- **Model Source Tampering**: Việc thao túng mã mô hình, dependency hoặc trọng số trước hay trong quá trình huấn luyện bởi kẻ tấn công chuỗi cung ứng hoặc người nội bộ có thể cài logic ẩn vẫn tồn tại ngay cả sau khi huấn luyện lại.

- **Excessive Data Handling**: Các biện pháp kiểm soát lưu giữ và quản trị dữ liệu yếu kém khiến hệ thống lưu trữ hoặc xử lý nhiều dữ liệu cá nhân hơn mức cần thiết, làm tăng nguy cơ lộ lọt và rủi ro tuân thủ.

- **Model Exfiltration**: Kẻ tấn công đánh cắp tệp/trọng số mô hình, gây mất tài sản trí tuệ và cho phép tạo dịch vụ sao chép hoặc thực hiện các cuộc tấn công tiếp theo.

- **Model Deployment Tampering**: Kẻ tấn công sửa đổi hiện vật mô hình hoặc hạ tầng phục vụ để mô hình đang chạy khác với phiên bản đã được kiểm duyệt, có thể làm thay đổi hành vi.

- **Denial of ML Service**: Làm ngập API hoặc gửi đầu vào “sponge” có thể làm cạn kiệt tài nguyên tính toán/năng lượng và khiến mô hình ngừng hoạt động, tương tự các cuộc tấn công DoS kinh điển.

- **Model Reverse Engineering**: Bằng cách thu thập số lượng lớn cặp đầu vào-đầu ra, kẻ tấn công có thể sao chép hoặc chưng cất mô hình, tạo điều kiện cho sản phẩm bắt chước và các cuộc tấn công đối kháng được tùy chỉnh.

- **Insecure Integrated Component**: Các plugin, agent hoặc dịch vụ thượng nguồn có lỗ hổng cho phép kẻ tấn công chèn mã hoặc leo thang đặc quyền bên trong AI pipeline.

- **Prompt Injection**: Tạo prompt (trực tiếp hoặc gián tiếp) để lén đưa vào các chỉ dẫn ghi đè mục đích của hệ thống, khiến mô hình thực hiện các lệnh ngoài dự kiến.

- **Model Evasion**: Các đầu vào được thiết kế cẩn thận khiến mô hình phân loại sai, hallucinate hoặc tạo ra nội dung bị cấm, làm suy giảm độ an toàn và niềm tin.

- **Sensitive Data Disclosure**: Mô hình tiết lộ thông tin riêng tư hoặc bí mật từ dữ liệu huấn luyện hay ngữ cảnh người dùng, vi phạm quyền riêng tư và quy định.

- **Inferred Sensitive Data**: Mô hình suy luận ra các thuộc tính cá nhân chưa từng được cung cấp, tạo ra những tác hại mới về quyền riêng tư thông qua suy luận.

- **Insecure Model Output**: Các phản hồi chưa được làm sạch truyền mã độc hại, thông tin sai lệch hoặc nội dung không phù hợp đến người dùng hay các hệ thống phía sau.

- **Rogue Actions**: Các agent được tích hợp khả năng tự hành thực hiện những thao tác ngoài dự kiến trong thế giới thực (ghi tệp, gọi API, mua hàng, v.v.) mà không có sự giám sát đầy đủ của người dùng.

## Ma trận MITRE AI ATLAS

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) cung cấp một khuôn khổ toàn diện để tìm hiểu và giảm thiểu các rủi ro liên quan đến hệ thống AI. Ma trận phân loại nhiều kỹ thuật và chiến thuật tấn công mà đối thủ có thể sử dụng nhắm vào các mô hình AI, cũng như cách sử dụng hệ thống AI để thực hiện nhiều cuộc tấn công khác nhau.<sup>[[3]](#references)</sup>

## LLMJacking (Đánh cắp token và bán lại quyền truy cập LLM được lưu trữ trên cloud)

Kẻ tấn công đánh cắp token phiên đang hoạt động hoặc thông tin xác thực API cloud để sử dụng trái phép các LLM trả phí được lưu trữ trên cloud. Quyền truy cập thường được bán lại thông qua các reverse proxy đứng ra làm trung gian cho tài khoản của nạn nhân, chẳng hạn như các bản triển khai "oai-reverse-proxy". Hậu quả bao gồm thiệt hại tài chính, sử dụng mô hình trái với chính sách và khiến tenant của nạn nhân bị quy trách nhiệm.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Thu thập token từ máy tính hoặc trình duyệt của nhà phát triển đã bị nhiễm; đánh cắp secrets trong CI/CD; mua cookies bị leak.<sup>[[5]](#references)</sup>
- Dựng reverse proxy chuyển tiếp yêu cầu đến nhà cung cấp chính thức, che giấu key upstream và phân phối yêu cầu cho nhiều khách hàng.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Lạm dụng các endpoint base model trực tiếp để vượt qua guardrail và giới hạn tốc độ của doanh nghiệp.<sup>[[4]](#references)</sup>

Biện pháp giảm thiểu:
- Gắn token với fingerprint thiết bị, dải IP và client attestation; đặt thời hạn ngắn và yêu cầu MFA khi làm mới.
- Giới hạn phạm vi key ở mức tối thiểu (không cấp quyền truy cập công cụ, chỉ đọc nếu phù hợp); xoay vòng khi phát hiện bất thường.
- Chuyển toàn bộ lưu lượng qua gateway chính sách phía máy chủ để áp dụng bộ lọc an toàn, hạn mức theo từng route và cách ly tenant.
- Theo dõi các kiểu sử dụng bất thường (chi phí tăng đột biến, khu vực lạ, chuỗi UA) và tự động thu hồi các phiên đáng ngờ.
- Ưu tiên mTLS hoặc JWT có chữ ký do IdP của bạn cấp thay vì API key tĩnh có thời hạn dài.

## Tăng cường bảo mật cho inference LLM tự lưu trữ

Chạy máy chủ LLM cục bộ để xử lý dữ liệu bảo mật tạo ra bề mặt tấn công khác với API lưu trữ trên cloud: các endpoint inference/debug có thể làm lộ prompt, stack phục vụ thường cung cấp một reverse proxy, còn các device node GPU cho phép truy cập vào nhiều giao diện `ioctl()`. Nếu bạn đang đánh giá hoặc triển khai dịch vụ inference on-prem, hãy xem xét ít nhất các điểm sau.<sup>[[8]](#references)</sup>

### Rò rỉ prompt qua endpoint debug và giám sát

Hãy xem API inference là một **dịch vụ nhạy cảm dành cho nhiều người dùng**. Các route debug hoặc giám sát có thể làm lộ nội dung prompt, trạng thái slot, metadata mô hình hoặc thông tin hàng đợi nội bộ. Trong `llama.cpp`, endpoint `/slots` đặc biệt nhạy cảm vì nó cung cấp trạng thái từng slot và chỉ dành cho việc kiểm tra/quản lý slot.<sup>[[8]](#references)</sup>

Để fingerprint và kiểm thử theo kiểu black-box các model runner bị lộ và những dịch vụ AI liên quan, hãy xem [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Đặt reverse proxy phía trước máy chủ inference và **mặc định từ chối**.
- Chỉ cho phép các tổ hợp phương thức HTTP + path chính xác mà client/UI cần.
- Tắt các endpoint introspection ngay trong backend bất cứ khi nào có thể, ví dụ `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Bind reverse proxy vào `127.0.0.1` và cung cấp quyền truy cập thông qua phương thức truyền tải có xác thực như SSH local port forwarding, thay vì công khai nó trên LAN.

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

### Rootless containers không có mạng và UNIX socket

Nếu inference daemon hỗ trợ lắng nghe trên UNIX socket, hãy ưu tiên cách đó thay vì TCP và chạy container **không có network stack**:<sup>[[8]](#references)</sup>

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
- `--network none` loại bỏ khả năng tiếp xúc TCP/IP inbound/outbound và tránh các user-mode helper mà container rootless nếu không sẽ cần.
- UNIX socket cho phép sử dụng quyền POSIX/ACL trên đường dẫn socket làm lớp kiểm soát truy cập đầu tiên.
- `--userns=keep-id` và Podman rootless giảm tác động của việc container breakout vì root trong container không phải root trên host.
- Các model mount chỉ đọc giảm nguy cơ model bị sửa đổi từ bên trong container.

Đối với các triển khai chạy lâu dài, có thể biểu diễn cùng những hạn chế này bằng các đơn vị Podman Quadlet. Nếu quyền truy cập GPU được ủy quyền thông qua Container Device Interface, hãy giữ thông số thiết bị CDI càng giới hạn càng tốt, thay vì để lộ mọi nút accelerator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Giảm thiểu các nút thiết bị GPU

Đối với inference dùng GPU, các tệp `/dev/nvidia*` là bề mặt tấn công cục bộ có giá trị cao vì chúng làm lộ các trình xử lý driver `ioctl()` lớn và có thể cả những đường dẫn quản lý bộ nhớ GPU dùng chung.<sup>[[8]](#references)</sup>

- Không để `/dev/nvidia*` có quyền ghi cho mọi người dùng.
- Hạn chế `nvidia`, `nvidiactl` và `nvidia-uvm` bằng `NVreg_DeviceFileUID/GID/Mode`, quy tắc udev và ACL để chỉ UID container được ánh xạ mới có thể mở chúng.
- Vô hiệu hóa các module không cần thiết như `nvidia_drm`, `nvidia_modeset` và `nvidia_peermem` trên các host inference không dùng màn hình.
- Nạp trước chỉ những module cần thiết khi khởi động thay vì để runtime tự ý chạy `modprobe` trong lúc khởi chạy inference.

Ví dụ:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Một điểm quan trọng cần xem xét là **`/dev/nvidia-uvm`**. Ngay cả khi workload không sử dụng rõ ràng `cudaMallocManaged()`, các CUDA runtime gần đây vẫn có thể cần `nvidia-uvm`. Vì thiết bị này được chia sẻ và quản lý bộ nhớ ảo GPU, hãy xem nó là một bề mặt có nguy cơ lộ dữ liệu giữa các tenant. Nếu inference backend hỗ trợ, Vulkan backend có thể là một lựa chọn đáng cân nhắc vì có thể tránh hoàn toàn việc để lộ `nvidia-uvm` cho container.<sup>[[8]](#references)</sup>

### Hạn chế inference worker bằng LSM

Nên dùng AppArmor/SELinux/seccomp để tăng cường phòng thủ cho tiến trình inference:<sup>[[8]](#references)</sup>

- Chỉ cho phép các shared library, đường dẫn model, thư mục socket và GPU device node thực sự cần thiết.
- Chủ động từ chối các capability có rủi ro cao như `sys_admin`, `sys_module`, `sys_rawio` và `sys_ptrace`.
- Để thư mục model ở chế độ chỉ đọc và chỉ giới hạn các đường dẫn có quyền ghi trong thư mục socket/cache của runtime.
- Theo dõi log từ chối vì chúng cung cấp telemetry phát hiện hữu ích khi model server hoặc payload post-exploitation tìm cách thoát khỏi hành vi dự kiến.

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

## Phantom Squatting: Tên miền do LLM ảo giác như một vector tấn công chuỗi cung ứng AI

Phantom squatting là **phiên bản tương đương domain/URL của slopsquatting**. Thay vì ảo giác ra tên package không tồn tại, LLM ảo giác ra một **domain portal, API, webhook, billing, SSO, download hoặc support** có vẻ hợp lý cho một thương hiệu có thật, rồi kẻ tấn công đăng ký namespace đó trước khi con người hoặc agent sử dụng nó.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Điều này quan trọng vì trong nhiều quy trình làm việc có AI hỗ trợ, đầu ra của model được xem như một **dependency đáng tin cậy**:
- Developer dán endpoint được đề xuất vào code hoặc các tích hợp CI/CD.
- AI agent tự động fetch tài liệu, schema, APK, ZIP hoặc webhook target.
- Runbook hoặc tài liệu được tạo ra có thể nhúng URL giả như thể đó là nguồn có thẩm quyền.

### Quy trình tấn công

1. **Thăm dò bề mặt ảo giác**: đặt câu hỏi cụ thể về thương hiệu, xoay quanh các quy trình thực tế như portal `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` hoặc `mobile app`.<sup>[[12]](#references)</sup>
2. **Chuẩn hóa các ứng viên**: phân giải URL được tạo ra, quy các phản hồi NXDOMAIN về domain cha có thể đăng ký và loại bỏ các nhóm prompt trùng lặp. Tập hợp prompt nên đa dạng, chẳng hạn loại bỏ các prompt gần trùng bằng **độ tương đồng Jaccard**.
3. **Ưu tiên các ảo giác dễ dự đoán**:
   - **Độ bền của ảo giác theo nhiệt độ (THP)**: cùng một domain giả xuất hiện ở nhiều mức temperature, kể cả mức thấp như `T=0.1`.
   - **Đồng thuận giữa các model**: nhiều họ LLM tạo ra cùng một domain giả.
4. **Đăng ký và vũ khí hóa** domain cha, sau đó lưu trữ trang phishing, bản tải APK/ZIP giả, công cụ thu thập thông tin xác thực, tài liệu độc hại hoặc endpoint API thu thập secret/webhook payload. **Ảo giác chỉ ở cấp domain** dễ kiếm tiền nhất vì kẻ tấn công kiểm soát toàn bộ namespace; ảo giác ở subdomain/path vẫn có thể bị lạm dụng nếu domain cha sau khi chuẩn hóa chưa được đăng ký.
5. **Khai thác khoảng thời gian chưa có uy tín**: domain mới đăng ký thường chưa có lịch sử blocklist, uy tín URL và telemetry đầy đủ, nên có thể vượt qua các biện pháp kiểm soát cho đến khi hệ thống phát hiện bắt kịp. Kẻ tấn công có thể kéo dài khoảng thời gian này bằng cách chỉ trả về nội dung lành tính cho crawler, cloaking bằng redirect, dùng CAPTCHA hoặc trì hoãn triển khai payload.

### Vì sao điều này nguy hiểm với agent

Với nạn nhân là con người, domain giả thường vẫn cần một cú click và một hành động khác. Trong **quy trình agentic**, LLM có thể vừa là **mồi nhử** vừa là **bên thực thi**: agent nhận URL do ảo giác tạo ra, fetch URL đó, phân tích phản hồi, rồi có thể leak token, thực thi chỉ thị, tải dependency hoặc đưa dữ liệu bị đầu độc vào CI/CD mà không có sự xem xét của con người.<sup>[[12]](#references)</sup>

### Prompt thực tế dành cho attacker

Các prompt có tỷ lệ thành công cao thường giống những tác vụ doanh nghiệp thông thường thay vì mồi nhử phishing rõ ràng:<sup>[[12]](#references)</sup>
- “URL sandbox thanh toán cho các tích hợp `<brand>` là gì?”
- “Tôi nên dùng webhook endpoint nào cho thông báo build của `<brand>`?”
- “Portal benefits / billing / SSO dành cho nhân viên của `<brand>` ở đâu?”
- “Hãy cho tôi link tải trực tiếp Android APK hoặc desktop client của `<brand>`.”

### Đảo ngược để phòng thủ

Hãy xem đây là vấn đề giám sát domain chủ động, không chỉ là vấn đề prompt injection:<sup>[[12]](#references)</sup>
- Xây dựng **tập hợp prompt về thương hiệu** và định kỳ thăm dò các LLM mà người dùng/agent của bạn dựa vào.
- Lưu các URL bị ảo giác tạo ra và theo dõi URL nào ổn định qua nhiều mức temperature/model.
- Theo dõi **Khoảng thời gian bị khai thác (AEW)**: thời gian từ lần đầu xuất hiện ảo giác đến khi attacker đăng ký domain. AEW dương nghĩa là bên phòng thủ có thể đăng ký trước, sinkhole hoặc chặn trước khi domain bị vũ khí hóa.
- Giám sát các chuyển đổi **NXDOMAIN → đã đăng ký** của domain cha.
- Khi domain được đăng ký, phân loại registrar, ngày tạo, nameserver, lớp bảo vệ quyền riêng tư, nội dung trang, ảnh chụp màn hình, trạng thái trang đỗ và mức độ tương đồng với tài sản thương hiệu.
- Thêm các cổng chính sách để agent/developer **không mặc định tin cậy domain do LLM tạo ra**: yêu cầu allowlist, xác minh quyền sở hữu, kiểm tra CT/RDAP hoặc phê duyệt của con người trước lần sử dụng đầu tiên.

Điều này đồng thời thuộc một số nhóm rủi ro AI: **tấn công chuỗi cung ứng AI**, **đầu ra model không an toàn** và **hành động ngoài dự kiến** khi agent tự động sử dụng URL bị ảo giác tạo ra.

## References

- [1] [Top 10 lỗ hổng Machine Learning của OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Khung AI an toàn) – Rủi ro](https://saif.google/secure-ai-framework/risks)
- [3] [Ma trận mối đe dọa MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Rủi ro của LLM hỗ trợ viết code: Nội dung có hại, lạm dụng và lừa đảo](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Thông tin xác thực Cloud bị đánh cắp được dùng trong cuộc tấn công AI mới](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Tổng quan về chiến dịch LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (bán lại quyền truy cập LLM bị đánh cắp)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Phân tích chuyên sâu về triển khai máy chủ LLM tại chỗ với quyền thấp](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README của máy chủ llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Đặc tả CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Domain do AI ảo giác tạo ra như một vector tấn công chuỗi cung ứng phần mềm](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Cách ảo giác của AI tiếp tay cho một lớp tấn công chuỗi cung ứng mới](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
