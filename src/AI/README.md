# AI trong An ninh mạng

{{#include ../banners/hacktricks-training.md}}

## Các thuật toán Machine Learning chính

Cách tốt nhất để bắt đầu tìm hiểu về AI là hiểu cách hoạt động của các thuật toán machine learning chính. Điều này sẽ giúp bạn hiểu AI hoạt động như thế nào, cách sử dụng và cách tấn công nó:


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

### Kiến trúc LLM

Trang sau trình bày những kiến thức cơ bản về từng thành phần cần có để xây dựng một LLM cơ bản bằng transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Công cụ và nền tảng mô hình

Để chạy, fine-tune, triển khai hoặc dùng thử các mô hình, hãy xem [hướng dẫn về công cụ và nền tảng mô hình AI](AI-Model-Tools-and-Platforms.md).

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

Hai framework hữu ích để bắt đầu đánh giá rủi ro hệ thống AI là OWASP Machine Learning Security Top 10 và Secure AI Framework (SAIF) của Google. Chúng bổ trợ cho nhau, nhưng không phải là danh sách đầy đủ các framework đánh giá rủi ro AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Tấn công đối kháng định hướng bằng Mechanistic Interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Bảo mật prompt AI

Những năm gần đây, LLM khiến việc sử dụng AI bùng nổ, nhưng chúng không hoàn hảo và có thể bị đánh lừa bằng prompt đối kháng. Đây là chủ đề rất quan trọng để hiểu cách sử dụng AI an toàn và cách tấn công nó:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE trong mô hình AI

Các nhà phát triển và công ty thường chạy những mô hình tải xuống từ Internet, nhưng chỉ cần tải một mô hình cũng có thể đủ để thực thi mã tùy ý trên hệ thống. Đây là chủ đề rất quan trọng để hiểu cách sử dụng AI an toàn và cách tấn công nó:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass KYC với AI

Video tạo sinh có thể kết hợp với kỹ thuật chèn camera ảo và thao túng camera API để bypass các quy trình KYC, xác minh tuổi và kiểm tra tính sống sinh trắc học yếu:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol của AI

MCP (Model Context Protocol) là một giao thức mở để kết nối các ứng dụng AI với công cụ và nguồn dữ liệu. Vì máy chủ MCP có thể cung cấp dữ liệu và chức năng, quá trình đánh giá phải bao gồm việc xem xét quyền hạn, sự đồng ý, xác thực đầu vào công cụ và ranh giới tin cậy.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Giao thức AI Agent-to-Agent (A2A)

A2A cho phép các agent tìm thấy nhau thông qua agent card và gửi task cho nhau qua HTTP. Hãy kiểm thử agent card, quyền hạn của task, webhook thông báo đẩy và extended card:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Dịch vụ AI tự host bị lộ

Fingerprint và kiểm thử các model runner, agent builder, giao diện demo ML, cụm máy tính và vector database bị lộ, không có xác thực:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing có AI hỗ trợ và tự động phát hiện lỗ hổng


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Rà soát mã nguồn và xác thực lỗ hổng có AI hỗ trợ

Để rà soát source/sink, taskflow điểm vào trên mobile, kiểm tra mẫu trong kernel và xác thực dựa trên bằng chứng:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering có AI hỗ trợ

[Nâng mã một phần, phát hiện MBA bất biến, giải mã phụ thuộc môi trường và xác thực extractor tự động](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot pentester AI Web Black-Box

Agent sử dụng LLM có thể tự động hóa các quy trình pentesting web black-box kéo dài khi được hỗ trợ bởi khả năng quan sát, điều phối, xử lý phiên đã xác thực và xác thực đối kháng:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework AI an toàn (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Giới thiệu](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
