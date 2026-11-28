# AI trong Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Các thuật toán Machine Learning chính

Cách tốt nhất để bắt đầu tìm hiểu AI là hiểu cách hoạt động của các thuật toán Machine Learning chính. Điều này sẽ giúp bạn hiểu AI hoạt động như thế nào, cách sử dụng và tấn công AI:


{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### Chuẩn bị và đánh giá dữ liệu mô hình

Để tìm hiểu về cách chia dataset, các metric phổ biến và các cuộc tấn công vào phía câu trả lời của quy trình chấm điểm dựa trên LLM, xem [chuẩn bị và đánh giá dữ liệu mô hình](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Kiến trúc LLM

Trang sau trình bày kiến thức cơ bản về từng thành phần để xây dựng LLM cơ bản bằng transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Công cụ và nền tảng mô hình

Để chạy, fine-tune, triển khai hoặc thử nghiệm các mô hình, hãy xem [hướng dẫn về công cụ và nền tảng mô hình AI](AI-Model-Tools-and-Platforms.md).

## Bảo mật AI

### Ranh giới tin cậy của LLM Gateway

Để tìm hiểu về bảo mật gateway, xem:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Phương pháp đánh giá bảo mật AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework đánh giá rủi ro AI

Hai framework hữu ích để bắt đầu đánh giá rủi ro của hệ thống AI là OWASP Machine Learning Security Top 10 và Secure AI Framework (SAIF) của Google. Chúng bổ trợ cho nhau, nhưng không phải là danh sách toàn diện các framework đánh giá rủi ro AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic-Interpretability-Guided Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Ranh giới tin cậy của trình duyệt nhúng

Để tìm hiểu về cầu nối trình duyệt của desktop assistant, giả mạo địa chỉ tab và đọc file cục bộ từ worker context, xem [ranh giới tin cậy của trình duyệt nhúng trong AI assistant](AI-Embedded-Browser-Trust-Boundaries.md).

### Bảo mật prompt AI

LLM đã khiến việc sử dụng AI bùng nổ trong những năm gần đây, nhưng chúng không hoàn hảo và có thể bị đánh lừa bằng adversarial prompt. Đây là chủ đề rất quan trọng để hiểu cách sử dụng AI an toàn và cách tấn công AI:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE qua mô hình AI

Các nhà phát triển và công ty thường chạy mô hình tải từ Internet; tuy nhiên, chỉ cần tải mô hình cũng có thể đủ để thực thi mã tùy ý trên hệ thống. Đây là chủ đề rất quan trọng để hiểu cách sử dụng AI an toàn và cách tấn công AI:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Để tìm hiểu về rủi ro khi tải mô hình Keras `.keras`/HDF5, Lambda layer và phân tích gadget sau khi sửa lỗi, xem [giải tuần tự hóa mô hình Keras và săn tìm gadget](keras-model-deserialization-rce-and-gadget-hunting.md).

### Bypass KYC với AI hỗ trợ

Video tạo sinh có thể kết hợp với giả lập camera ảo và thao túng camera API để bypass quy trình KYC, xác minh tuổi và kiểm tra tính sống của sinh trắc học có bảo mật yếu:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol của AI

MCP (Model Context Protocol) là một giao thức mở để kết nối ứng dụng AI với công cụ và nguồn dữ liệu. Vì MCP server có thể cung cấp dữ liệu và hành động, quá trình đánh giá phải bao gồm việc xem xét quyền hạn, sự đồng thuận, xác thực đầu vào công cụ và ranh giới tin cậy.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Giao thức AI Agent-to-Agent (A2A)

A2A cho phép các agent tìm thấy nhau thông qua agent card và gửi task cho nhau qua HTTP. Hãy kiểm tra agent card, quyền thực hiện task, webhook thông báo đẩy và card mở rộng:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Dịch vụ AI tự host bị lộ

Fingerprint và kiểm tra các model runner, agent builder, giao diện demo ML, cụm máy tính và vector database bị lộ, không yêu cầu xác thực:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing và phát hiện lỗ hổng tự động có AI hỗ trợ


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Rà soát source và xác thực lỗ hổng có AI hỗ trợ

Để rà soát source/sink, taskflow của điểm vào trên mobile, kiểm tra mẫu kernel và xác thực dựa trên bằng chứng:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering có AI hỗ trợ

[Nâng mã một phần, phát hiện MBA bất biến, giải mã phụ thuộc môi trường và xác thực automated extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot AI pentest web black-box

Agent sử dụng LLM có thể tự động hóa các workflow pentest web black-box kéo dài khi được hỗ trợ bởi khả năng quan sát, điều phối, xử lý phiên đã xác thực và xác thực đối kháng:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [Top 10 bảo mật Machine Learning của OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework AI bảo mật (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Giới thiệu](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
