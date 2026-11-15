# AI trong An ninh mạng

{{#include ../banners/hacktricks-training.md}}

## Các thuật toán Machine Learning chính

Cách tốt nhất để bắt đầu tìm hiểu AI là hiểu cách hoạt động của các thuật toán machine learning chính. Điều này sẽ giúp bạn hiểu AI hoạt động ra sao, cách sử dụng và cách tấn công nó:


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

Để tìm hiểu về cách chia dataset, các metric cổ điển và các cuộc tấn công vào phía câu trả lời trong quá trình chấm điểm dựa trên LLM, xem [chuẩn bị và đánh giá dữ liệu mô hình](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Kiến trúc LLM

Trang sau trình bày những kiến thức cơ bản về từng thành phần để xây dựng một LLM cơ bản bằng transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Công cụ và nền tảng mô hình

Để chạy, fine-tune, triển khai hoặc thử nghiệm các mô hình, hãy dùng [hướng dẫn về công cụ và nền tảng mô hình AI](AI-Model-Tools-and-Platforms.md).

## Bảo mật AI

### Ranh giới tin cậy của LLM Gateway

Để tìm hiểu về bảo mật gateway, xem:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Phương pháp luận bảo mật AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework đánh giá rủi ro AI

Hai framework hữu ích để bắt đầu đánh giá rủi ro của hệ thống AI là OWASP Machine Learning Security Top 10 và Secure AI Framework (SAIF) của Google. Chúng bổ trợ cho nhau, chứ không phải là danh sách đầy đủ các framework đánh giá rủi ro AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Tấn công đối kháng có hướng dẫn từ Mechanistic Interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Ranh giới tin cậy của browser nhúng

Để tìm hiểu về các cầu nối browser của desktop assistant, giả mạo địa chỉ tab và đọc file cục bộ trong worker context, xem [ranh giới tin cậy của browser nhúng trong AI assistant](AI-Embedded-Browser-Trust-Boundaries.md).

### Bảo mật prompt AI

LLM đã khiến việc sử dụng AI bùng nổ trong những năm gần đây, nhưng chúng không hoàn hảo và có thể bị đánh lừa bằng prompt đối kháng. Đây là chủ đề rất quan trọng để hiểu cách sử dụng AI an toàn và cách tấn công nó:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE trong mô hình AI

Các nhà phát triển và công ty thường chạy các mô hình tải xuống từ Internet; tuy nhiên, chỉ cần tải một mô hình cũng có thể đủ để thực thi mã tùy ý trên hệ thống. Đây là chủ đề rất quan trọng để hiểu cách sử dụng AI an toàn và cách tấn công nó:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass KYC có hỗ trợ AI

Video tạo sinh có thể kết hợp với virtual-camera injection và thao túng camera API để bypass các quy trình KYC, xác minh tuổi và xác thực sinh trắc học liveness yếu:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol của AI

MCP (Model Context Protocol) là một giao thức mở để kết nối ứng dụng AI với công cụ và nguồn dữ liệu. Vì MCP server có thể cung cấp dữ liệu và hành động, quá trình đánh giá phải bao gồm việc kiểm tra quyền hạn, sự đồng ý, xác thực dữ liệu đầu vào của công cụ và ranh giới tin cậy.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Giao thức AI Agent-to-Agent (A2A)

A2A cho phép các agent tìm thấy nhau thông qua agent card và gửi task cho nhau qua HTTP. Hãy kiểm tra agent card, quyền hạn của task, webhook thông báo đẩy và extended card:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Dịch vụ AI tự host bị lộ

Fingerprint và kiểm tra các model runner, agent builder, giao diện demo ML, cụm compute và vector database bị lộ, không yêu cầu xác thực:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing và phát hiện lỗ hổng tự động có hỗ trợ AI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Rà soát mã nguồn và xác thực lỗ hổng có hỗ trợ AI

Để rà soát source/sink, mobile entry-point taskflow, kiểm tra mẫu kernel và xác thực có yêu cầu bằng chứng:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering có hỗ trợ AI

[Nâng mã một phần, phát hiện MBA bất biến, giải mã phụ thuộc môi trường và xác thực trình trích xuất tự động](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot AI Pentester Web Black-Box

Agent sử dụng LLM có thể tự động hóa các quy trình pentesting web black-box kéo dài khi được hỗ trợ bởi khả năng quan sát, điều phối, xử lý phiên đã xác thực và xác thực đối kháng:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [Top 10 Bảo mật Machine Learning của OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Khung AI An toàn (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Giới thiệu](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
