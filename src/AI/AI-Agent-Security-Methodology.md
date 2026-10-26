# Phương pháp luận bảo mật tác tử AI

{{#include ../banners/hacktricks-training.md}}

Đánh giá tác tử nên lần theo **đầu vào do kẻ tấn công kiểm soát đến một tác động có thể quan sát từ bên ngoài**. Jailbreaking, thay đổi tính cách và tiết lộ system prompt chứng minh rằng kênh suy luận có thể bị tác động, nhưng phát hiện có tác động lớn là chuỗi dẫn đến truy cập dữ liệu, hành động trái phép qua tool, điểm tiếp nhận injection ở bước xử lý sau, khả năng duy trì trạng thái hoặc một tác tử khác.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) hữu ích để gắn nhãn phạm vi kiểm tra (chiếm quyền mục tiêu, lạm dụng tool, lạm dụng đặc quyền, chuỗi cung ứng, thực thi mã, đầu độc bộ nhớ, niềm tin giữa các tác tử, lỗi dây chuyền, niềm tin của con người và tác tử bất hảo). Hãy dùng các nhãn này sau khi xây dựng đường tấn công đầu cuối, thay vì xem văn bản bất ngờ từ model là điểm kết thúc của bài kiểm tra.<sup>[[1]](#references)[[2]](#references)</sup>

## Lập bản đồ mục tiêu

Trước khi viết payload, hãy ghi lại năm khía cạnh sau cho từng quy trình làm việc của tác tử:<sup>[[2]](#references)</sup>

| Khía cạnh | Những gì cần liệt kê | Câu hỏi bảo mật |
|---|---|---|
| **Đầu vào không đáng tin cậy** | Tham số Chat/API, URL, tài liệu, email, ticket, mục lịch, các đoạn truy xuất, bộ nhớ, kết quả từ tool và tin nhắn từ tác tử ngang hàng | Kẻ tấn công có thể đưa nội dung vào đâu để sau đó nội dung ấy đi vào ngữ cảnh của model? |
| **Tool** | Tên và schema của tool, tác động phụ, khả năng tự động thực thi, hành vi xác nhận và tool được tải động | Những lệnh gọi nào đọc bí mật, ghi trạng thái, gửi tin nhắn, xóa dữ liệu, thực thi mã hoặc chuyển giá trị? |
| **Quyền hạn** | Quyền ủy quyền của người dùng, tài khoản dịch vụ, API token, thời hạn hiệu lực của thông tin xác thực, phạm vi tenant/tài nguyên và khả năng truy cập mạng | Mỗi lệnh gọi chạy dưới danh tính nào, và quyền có được kiểm tra lại tại ranh giới của tool không? |
| **Xử lý** | Trình tạo truy vấn, shell, trình tải URL, template engine, trình thông dịch, parser, thao tác tệp và bộ giải tuần tự | Dữ liệu do model tạo ra trở thành cú pháp cho một trình thông dịch khác ở đâu? |
| **Đầu ra** | Phản hồi, Markdown/HTML được render, liên kết, yêu cầu tải ảnh, webhook, email, tệp, log, báo cáo, chỉ số và lưu lượng giữa các tác tử ngang hàng | Kênh có thể quan sát nào có thể mang theo bí mật hoặc kích hoạt một yêu cầu thứ cấp? |

Đừng giản lược việc này thành danh sách các tích hợp được quảng bá. Một tài liệu hữu ích sẽ ánh xạ từng nguồn đến vị trí chính xác trong ngữ cảnh mà nguồn đó đi tới, các tool khả dụng tại thời điểm đó, thông tin xác thực được từng tool sử dụng, trình thông dịch xử lý tiếp theo và mọi đường truyền dữ liệu ra ngoài. Cùng một tool có thể có tác động thấp khi dùng token chỉ đọc của từng người dùng, nhưng có mức độ nghiêm trọng cao khi dùng thông tin xác thực quản trị viên dùng chung.<sup>[[2]](#references)</sup>

## Trinh sát

### Lập bản đồ mọi đường gửi và tiếp nhận dữ liệu

Bắt đầu từ bề mặt gửi dữ liệu (web, di động, API, email, nền tảng chat, tiện ích mở rộng trình duyệt) và proxy lưu lượng giữa client với backend. Kiểm tra các trường bị ẩn khỏi giao diện người dùng, tham số tìm kiếm/tự động hoàn tất/lọc, đối tượng trạng thái hội thoại, tác vụ tải lên và lập chỉ mục, phản hồi từ tool, cũng như lưu lượng giữa các tác tử phụ. Với client chỉ có trên di động, có thể cần trình giả lập và công cụ instrument để vượt certificate pinning trước khi schema yêu cầu thực tế xuất hiện.<sup>[[2]](#references)</sup>

Tiếp đó, lập bản đồ ngăn xếp bên dưới model: framework điều phối, quá trình lắp ráp prompt, kho lưu trữ truy xuất và bộ nhớ, runtime (ví dụ Python, container hoặc WASM), volume được mount, dịch vụ trên host, API nội bộ, khả năng truy cập metadata của cloud và các mạng lân cận. Cấu hình mặc định của framework rất quan trọng vì một số “lệnh gọi tool” được triển khai bằng cách tạo hoặc đánh giá mã; ranh giới runtime/sandbox quyết định liệu kết quả đó có được giữ trong phạm vi cô lập hay không.<sup>[[2]](#references)</sup>

### Nhận diện định tuyến bằng probe không phá hoại

So sánh một yêu cầu nằm trong phạm vi với một số yêu cầu không liên quan, đồng thời lưu lại toàn bộ phản hồi, mã trạng thái, độ trễ và hành vi streaming. Việc bị từ chối ổn định trước khi có suy luận đặc thù cho tác vụ có thể cho thấy có gateway/classifier riêng; lời từ chối dựa trên ngữ cảnh cho thấy yêu cầu đã đến model; câu trả lời trống hoặc chỉ trích xuất thông tin có thể cho thấy hệ thống dùng tìm kiếm từ khóa hoặc truy xuất giới hạn. Hãy xem đây là các giả thuyết và xác nhận bằng cách gửi lại cùng probe qua những trường API và đường tiếp nhận dữ liệu khác.<sup>[[2]](#references)</sup>

Hoàn tất trinh sát khi cuộc đánh giá có thể xác định nguồn sớm nhất do kẻ tấn công kiểm soát làm thay đổi hành vi của tác tử **và** các tool, danh tính, trình thông dịch và đầu ra có thể tiếp cận từ nguồn đó.<sup>[[2]](#references)</sup>

## Khai thác: vượt qua ranh giới tin cậy

Kiểm tra các kênh, không chỉ cách diễn đạt prompt. Bắt đầu bằng injection trực tiếp để xác định những gì lối vào hiển thị chặn được, rồi lặp lại ý đồ tương tự qua các đường ít hiển thị hơn bên dưới:<sup>[[2]](#references)</sup>

- **Nội dung gián tiếp:** trang web, tệp, email, ticket, metadata, alt text, HTML comment, văn bản ngoài màn hình hoặc ký tự zero-width. Xem [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) để biết các kỹ thuật gửi payload.
- **Truy xuất và bộ nhớ:** đầu độc nội dung sẽ được truy xuất về sau hoặc trạng thái sẽ được tải lại trong các phiên sau. Ghi lại xem việc xóa nguồn ban đầu có loại bỏ hành vi đó không.
- **Đầu ra từ tool và tác tử ngang hàng:** đặt marker trong phản hồi của tool hoặc tin nhắn giữa các tác tử để kiểm tra xem lưu lượng nội bộ có bỏ qua các bộ lọc chỉ áp dụng cho đầu vào người dùng và đầu ra cuối cùng hay không.
- **Chuỗi cung ứng:** xem xét các mô tả tool, plugin, server được kết nối, skill, model và dependency như những nguồn chỉ thị đáng tin cậy. Để kiểm tra riêng MCP, xem [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Phê duyệt của con người:** so sánh lệnh gọi tool có cấu trúc thực tế với nội dung phê duyệt do model tạo. Kiểm tra xem tác động của kẻ tấn công có thể làm thiếu đích, phạm vi, đối tượng bị ảnh hưởng hoặc tác động phụ không thể đảo ngược hay không.

Trước tiên, hãy dùng một marker duy nhất, vô hại. Lưu lại hiện vật nguồn, ngữ cảnh đã lắp ráp nếu có thể quan sát, lệnh gọi tool được chọn, dữ liệu phê duyệt, yêu cầu/phản hồi backend và trạng thái cuối cùng. Việc này giúp phân biệt tác động thực sự với lời khẳng định bịa đặt rằng một hành động đã xảy ra.<sup>[[2]](#references)</sup>

### Văn bản giả dạng chính sách trong bộ đánh giá rủi ro tool

Một cổng kiểm soát tool dựa trên model có thể nhận văn bản do kẻ tấn công kiểm soát nằm trong ngữ cảnh phân loại vốn hữu ích. Ví dụ, `AutoModeMiddleware` thử nghiệm của LangChain gửi lệnh gọi tool được đề xuất, các đối số của lệnh gọi, mô tả tool tùy chọn và tối đa 30 tin nhắn gần nhất đến bộ đánh giá `is_risky` của TypeSafe. Middleware này chặn các tool được cấu hình khi xác suất Noul trả về đạt ít nhất `0.5`; các tool không được liệt kê sẽ không được middleware này phân loại.<sup>[[5]](#references)</sup> TypeSafe cũng cảnh báo rằng văn bản đối kháng trong state có thể tác động đến kết quả phân loại, ngay cả khi state được dự định chỉ là dữ liệu.<sup>[[6]](#references)</sup>

**Chính sách giả mạo** khác với việc chỉ tự nhận là system message. Nó đặt các nhãn hoặc định nghĩa rủi ro thay thế trong state có mức độ tin cậy thấp hơn và khuyến khích bộ đánh giá dùng các định nghĩa đó thay cho tiêu chí do developer xác định. Trong thử nghiệm của Datadog, `profile_description` do người dùng chỉnh sửa được sao chép vào đối số của tool cùng với `can_edit:false`. Văn bản giống chính sách lập luận rằng thao tác ghi có rủi ro thấp vì một bước kiểm tra quyền riêng sẽ từ chối thao tác đó trước khi có bất kỳ thay đổi nào. Qua 40 lần chạy, điểm `is_risky` trung bình giảm từ `0.893` xuống `0.290`, trong khi phép so sánh giả mạo vai trò trực tiếp đạt trung bình `0.905`. Việc điểm trung bình giảm xuống dưới `0.5` không chứng minh mọi lệnh gọi riêng lẻ đều vượt qua cổng kiểm soát, và thử nghiệm **không** chứng minh đã hoàn tất thao tác ghi trái phép nào.<sup>[[7]](#references)</sup>

Khi kiểm tra ranh giới này, hãy phân biệt phán quyết của bộ phân loại với kết quả cấp quyền thực tế của tool. Kiểm tra những trường có thể chỉnh sửa nào được gửi đến bộ đánh giá, so sánh cùng một hành động được đề xuất khi có và không có văn bản giống chính sách, rồi xác minh trạng thái cuối cùng độc lập. Bước kiểm tra quyền riêng vẫn phải dùng quyền hạn của người yêu cầu đã xác thực, thay vì quyền của tài khoản dịch vụ thuộc connector.<sup>[[7]](#references)</sup> Xem [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) để biết các kiểu lỗi khác của bộ phân loại; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) đề cập đến một ranh giới định tuyến và thông tin xác thực khác.

### Cách ly ngữ cảnh của subagent

Subagent Claude Agent SDK không fork nhận `AgentDefinition.prompt` riêng, prompt ủy quyền và các tool khả dụng, nhưng không nhận system prompt hoặc hội thoại của tác tử cha. Nếu bỏ qua `tools` trong định nghĩa của nó, subagent sẽ kế thừa các tool khả dụng cho subagent; `CLAUDE.md` của dự án vẫn có thể được tải. Vì vậy, một giới hạn prompt chỉ áp dụng cho tác tử cha không phải là ranh giới đáng tin cậy nếu tác tử con có thể dùng cùng công cụ hệ thống tệp hoặc thực thi.<sup>[[4]](#references)</sup>

Kiểm tra ranh giới bằng cách so sánh một yêu cầu trực tiếp mà tác tử cha từ chối với cùng tác vụ được giao cho một subagent có tên. NCC Group cho biết thao tác liệt kê tệp của hệ điều hành bị từ chối đã thành công khi được diễn đạt lại cho tác tử con như một “bản đồ bố cục” vô hại.<sup>[[3]](#references)</sup>

Kiểm tra các lệnh gọi tool thực tế của tác tử con và danh sách cho phép tool có hiệu lực, không chỉ câu trả lời cuối cùng của tác tử cha; xác nhận xem tác tử con có truy cập những tệp mà tác tử cha không được phép truy cập hay không.<sup>[[4]](#references)</sup> Đây là lỗi kế thừa guardrail, không phải bằng chứng về việc thoát khỏi [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) hoặc container.<sup>[[3]](#references)[[4]](#references)</sup>

## Thực thi: chứng minh tác động thực tế

Có hai đường riêng biệt dẫn từ việc gây ảnh hưởng đến tác động thực tế:<sup>[[2]](#references)</sup>

1. **Lạm dụng năng lực:** tool được cấp quyền vốn đã thực hiện được mục tiêu. Ví dụ: đọc bản ghi của một tenant rồi ghi bản ghi đó vào báo cáo mà kẻ tấn công xem được, gửi email, thay đổi bản ghi, xóa tệp hoặc khởi tạo khoản thanh toán. Không cần có lỗi phần mềm thứ cấp.
2. **Khai thác điểm tiếp nhận ở bước xử lý sau:** đầu ra của model bị kẻ tấn công điều hướng trở thành cú pháp cho một thành phần khác. Kiểm tra các truy vấn cơ sở dữ liệu để tìm [SQL injection](../pentesting-web/sql-injection/README.md) hoặc [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrapper để tìm [command injection](../pentesting-web/command-injection.md), URL do kẻ tấn công chọn để tìm [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), thao tác tệp để tìm path traversal, template/code evaluator để tìm RCE và object parser để tìm [unsafe deserialization](../pentesting-web/deserialization/README.md).

Với từng trường hợp có thể khai thác, hãy chứng minh chuỗi sau:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Một integration chỉ có quyền đọc vẫn có thể bị khai thác nếu bất kỳ thành phần nào về sau có thể công bố nội dung đã đọc. Kiểm tra các phản hồi thông thường cùng những kênh egress ít hiển nhiên hơn như liên kết do attacker kiểm soát, tự động tải ảnh, webhook, log, báo cáo, bộ đếm, thông báo và tin nhắn gửi cho các agent khác.<sup>[[2]](#references)</sup>

## Hành động trên mục tiêu

Sau khi xác nhận một hành động, hãy đánh giá toàn bộ phạm vi ảnh hưởng thay vì dừng lại ở hiệu ứng đầu tiên nhìn thấy được:<sup>[[2]](#references)</sup>

- **Exfiltration:** bí mật, hồ sơ người dùng, tệp nội bộ, dữ liệu hội thoại hoặc nội dung prompt/context được gửi ra ngoài qua một kênh có thể quan sát.
- **Hành động trái phép:** agent sử dụng các khả năng ghi hợp lệ để phục vụ mục tiêu của attacker.
- **Từ chối dịch vụ:** các công cụ phá hoại hoặc những hoạt động tốn kém lặp đi lặp lại ảnh hưởng đến tính toàn vẹn hoặc tính khả dụng.
- **Duy trì quyền truy cập:** memory bị đầu độc, nội dung được lập chỉ mục, trạng thái đáng tin cậy hoặc thay đổi runtime vẫn tồn tại sau khi phiên hoặc nguồn khởi tạo bị gỡ bỏ.
- **Lan truyền:** một peer đáng tin cậy tiếp nhận tin nhắn hoặc trạng thái chia sẻ từ agent bị xâm phạm, rồi lặp lại hành động bằng công cụ và thông tin xác thực của chính nó.

Mức độ nghiêm trọng nên dựa trên dữ liệu có thể truy cập, quyền hiệu lực, khả năng khai thác sink, egress, khả năng duy trì và lan truyền—chứ không phải mức độ bất ngờ trong câu chữ của model.<sup>[[2]](#references)</sup>

## Các biện pháp kiểm soát cần xác thực trong quá trình đánh giá

Bộ lọc prompt và system prompt tốt hơn có thể làm tăng chi phí cho attacker, nhưng không nên được xem là ranh giới phân quyền. Xác thực các biện pháp kiểm soát dưới đây bằng cách chạy lại cùng một chuỗi qua đầu vào trực tiếp, nội dung gián tiếp, memory, tools và các agent ngang hàng:<sup>[[2]](#references)</sup>

- Một lớp chính sách xác định kiểm tra người dùng đã xác thực, tenant, đối tượng, hành động và đích đến trong **mỗi lần gọi tool**; model không thể cung cấp hoặc ghi đè danh tính người gọi.
- Quyền đọc và ghi sử dụng thông tin xác thực riêng biệt, đặc quyền tối thiểu và có thời hạn ngắn; các tool có tác động lớn chỉ được cung cấp đúng lúc cần thiết và không bao giờ tự động thực thi dựa trên nội dung đã tiếp nhận.
- Egress mạng và các đích nội bộ được allowlist độc lập với URL do model chọn; quyền truy cập runtime tới endpoint metadata, secrets được mount và các dịch vụ lân cận bị chặn trừ khi cần thiết.
- Giao diện phê duyệt được tạo từ yêu cầu có cấu trúc chuẩn tắc và hiển thị chính xác các đối số, danh tính, đích đến, đối tượng bị ảnh hưởng và tác dụng phụ—không phải bản tóm tắt tự do do model tạo ra.
- Thành công được xác minh từ hệ thống đích hoặc hệ thống lưu trữ dữ liệu chuẩn. Lời tường thuật của agent, yêu cầu gọi tool hoặc chuyển hướng HTTP không chứng minh trạng thái được tuyên bố đã thay đổi.
- Các mục trong memory và retrieval lưu giữ provenance cùng nhãn độ tin cậy, có thể bị vô hiệu hóa và được phân quyền lại khi dùng cho hành động về sau.
- Tin nhắn giữa các agent được xác thực và phân quyền như các yêu cầu không đáng tin cậy; uy tín của peer hoặc agent card không mặc nhiên ủy quyền các tool của bên nhận.

Để tìm hiểu về agent card A2A, luồng tác vụ và bề mặt tấn công của chúng, hãy xem [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [Top 10 ứng dụng Agentic của OWASP năm 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Cẩm nang của Hacker về tấn công AI Agent](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Thực sự khó đến mức nào để thoát khỏi sandbox của AI Agent?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagent trong SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Mã nguồn middleware LangChain TypeSafe Auto Mode](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Tính gồ ghề của model TypeSafe AI Jev: nội dung đối kháng](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev với vai trò giám khảo: Chính sách giả mạo điều hướng Jev như thế nào](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
