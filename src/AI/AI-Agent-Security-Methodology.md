# Phương pháp luận bảo mật AI Agent

{{#include ../banners/hacktricks-training.md}}

Một đánh giá agent nên lần theo **đầu vào do kẻ tấn công kiểm soát đến hiệu ứng có thể quan sát từ bên ngoài**. Jailbreaking, thay đổi ký tự và làm lộ system prompt chứng minh rằng kênh suy luận có thể bị tác động, nhưng phát hiện có tác động cao là chuỗi dẫn đến truy cập dữ liệu, hành động trái phép bằng tool, sink injection ở bước sau, persistence hoặc một agent khác.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) hữu ích để gắn nhãn phạm vi kiểm thử (chiếm quyền mục tiêu, lạm dụng tool, lạm quyền, supply chain, thực thi mã, đầu độc bộ nhớ, tin cậy giữa các agent, lỗi dây chuyền, niềm tin của con người và agent bất hảo). Hãy dùng các nhãn đó sau khi xây dựng đường tấn công đầu-cuối, thay vì xem văn bản bất ngờ do model tạo ra là điểm kết thúc của bài kiểm thử.<sup>[[1]](#references)[[2]](#references)</sup>

## Lập bản đồ mục tiêu

Trước khi viết payload, hãy ghi lại năm khía cạnh sau cho mọi workflow của agent:<sup>[[2]](#references)</sup>

| Khía cạnh | Cần liệt kê | Câu hỏi bảo mật |
|---|---|---|
| **Đầu vào không đáng tin cậy** | Tham số Chat/API, URL, tài liệu, email, ticket, mục lịch, các đoạn truy xuất, bộ nhớ, kết quả tool và tin nhắn từ agent ngang hàng | Kẻ tấn công có thể đặt nội dung ở đâu để sau đó nội dung đi vào context của model? |
| **Tool** | Tên và schema của tool, tác động phụ, tự động thực thi, hành vi xác nhận và tool được tải động | Lệnh gọi nào đọc bí mật, ghi trạng thái, gửi tin nhắn, xóa dữ liệu, thực thi mã hoặc chuyển giá trị? |
| **Quyền hạn** | Ủy quyền của người dùng, service account, API token, thời hạn credential, phạm vi tenant/tài nguyên và khả năng truy cập mạng | Mỗi lệnh gọi chạy dưới danh tính nào, và quyền có được kiểm tra lại tại ranh giới tool không? |
| **Xử lý** | Trình tạo truy vấn, shell, trình tải URL, template engine, interpreter, parser, thao tác tệp và deserializer | Dữ liệu do model tạo ra trở thành cú pháp cho interpreter khác ở đâu? |
| **Đầu ra** | Phản hồi, Markdown/HTML được render, liên kết, yêu cầu tải ảnh, webhook, email, tệp, log, báo cáo, số liệu và lưu lượng giữa các agent | Kênh có thể quan sát nào có thể mang bí mật hoặc kích hoạt yêu cầu thứ cấp? |

Đừng gộp nội dung này thành danh sách các tích hợp được quảng bá. Một tài liệu hữu ích cần ánh xạ từng nguồn đến vị trí context chính xác mà nó đi vào, các tool khả dụng tại đó, credential mà mỗi tool sử dụng, interpreter ở bước sau và mọi tuyến egress. Cùng một tool có thể có tác động thấp khi dùng token đọc riêng cho từng người dùng, nhưng ở mức nghiêm trọng khi dùng chung credential quản trị viên.<sup>[[2]](#references)</sup>

## Trinh sát

### Lập bản đồ mọi đường tiếp nhận và đưa dữ liệu vào

Bắt đầu với bề mặt truy cập (web, mobile, API, email, nền tảng chat, browser extension) và proxy lưu lượng từ client đến backend. Kiểm tra các trường bị UI ẩn, tham số tìm kiếm/tự động hoàn thành/lọc, đối tượng trạng thái hội thoại, tác vụ upload và lập chỉ mục, phản hồi của tool và lưu lượng sub-agent. Client chỉ có trên mobile có thể cần emulator và instrumentation để vượt certificate pinning trước khi schema yêu cầu thực tế hiển thị.<sup>[[2]](#references)</sup>

Tiếp theo, lập bản đồ stack bên dưới model: framework điều phối, quá trình lắp ráp prompt, kho lưu trữ retrieval và memory, runtime (ví dụ Python, container hoặc WASM), volume được mount, dịch vụ host, API nội bộ, khả năng truy cập cloud metadata và các mạng lân cận. Mặc định của framework rất quan trọng vì một số “tool call” được triển khai bằng cách tạo hoặc đánh giá mã; ranh giới runtime/sandbox quyết định liệu kết quả đó có được giữ trong phạm vi cô lập hay không.<sup>[[2]](#references)</sup>

### Nhận diện tuyến xử lý bằng probe không gây phá hoại

So sánh một yêu cầu nằm trong phạm vi với một số yêu cầu không liên quan, đồng thời lưu nguyên vẹn phản hồi, status code, độ trễ và hành vi streaming. Từ chối ổn định trước khi có bất kỳ suy luận nào theo tác vụ có thể cho thấy có gateway/classifier riêng; từ chối theo ngữ cảnh cho thấy yêu cầu đã đến model; câu trả lời trống hoặc chỉ trích xuất thông tin có thể cho thấy đang dùng tìm kiếm từ khóa hoặc retrieval phạm vi hẹp. Hãy xem đây là các giả thuyết và xác nhận bằng cách gửi lại cùng probe qua các trường API và đường tiếp nhận khác.<sup>[[2]](#references)</sup>

Hoàn tất trinh sát khi đánh giá có thể xác định nguồn sớm nhất do kẻ tấn công kiểm soát làm thay đổi hành vi agent **và** các tool, danh tính, interpreter cùng đầu ra có thể tiếp cận từ nguồn đó.<sup>[[2]](#references)</sup>

## Khai thác: vượt qua ranh giới tin cậy

Kiểm thử các kênh, không chỉ cách diễn đạt prompt. Bắt đầu bằng injection trực tiếp để xác định những gì lối vào hiển thị chặn được, sau đó thử lại ý đồ tương đương qua các đường ít hiển thị hơn dưới đây:<sup>[[2]](#references)</sup>

- **Nội dung gián tiếp:** trang web, tệp, email, ticket, metadata, alt text, HTML comment, văn bản ngoài màn hình hoặc ký tự zero-width. Xem [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) để biết các kỹ thuật chuyển tải payload.
- **Retrieval và memory:** đầu độc nội dung sẽ được truy xuất sau này hoặc trạng thái sẽ được tải lại trong các phiên sau. Ghi lại hành vi có biến mất khi xóa nguồn ban đầu hay không.
- **Đầu ra của tool và agent ngang hàng:** đặt marker trong phản hồi của tool hoặc tin nhắn giữa các agent để kiểm tra xem lưu lượng nội bộ có vượt qua các bộ lọc chỉ áp dụng cho đầu vào người dùng và đầu ra cuối cùng hay không.
- **Supply chain:** xem xét mô tả tool, plugin, server được kết nối, skill, model và dependency như các nguồn chỉ dẫn đáng tin cậy. Để kiểm thử riêng cho MCP, xem [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Phê duyệt của con người:** so sánh tool call có cấu trúc thực tế với văn bản phê duyệt do model tạo ra. Kiểm tra xem tác động của kẻ tấn công có thể khiến bỏ sót đích đến, phạm vi, đối tượng bị ảnh hưởng hoặc tác động phụ không thể đảo ngược hay không.

Trước tiên, hãy dùng một marker duy nhất, vô hại. Lưu lại artifact nguồn, context đã lắp ráp nếu có thể quan sát, tool call được chọn, dữ liệu phê duyệt, request/response của backend và trạng thái cuối cùng. Việc này giúp phân biệt tác động thực sự với tuyên bố bịa đặt rằng hành động đã xảy ra.<sup>[[2]](#references)</sup>

### Văn bản giả dạng policy trong bộ đánh giá rủi ro tool

Một cổng kiểm soát tool dựa trên model có thể nhận văn bản do kẻ tấn công kiểm soát bên trong context phân loại vốn hữu ích. Ví dụ, `AutoModeMiddleware` thử nghiệm của LangChain gửi tool call được đề xuất, các đối số, mô tả tool tùy chọn và tối đa 30 tin nhắn gần nhất đến bộ đánh giá `is_risky` của TypeSafe. Bộ này chặn các tool đã cấu hình khi xác suất Noul trả về lớn hơn hoặc bằng `0.5`; middleware này không phân loại các tool không được liệt kê.<sup>[[5]](#references)</sup> TypeSafe cũng cảnh báo rằng văn bản đối kháng trong state có thể ảnh hưởng đến kết quả phân loại ngay cả khi state được xem là dữ liệu.<sup>[[6]](#references)</sup>

**Policy giả mạo** khác với việc chỉ tuyên bố mình là system message. Nó đặt các nhãn hoặc định nghĩa rủi ro thay thế bên trong state có mức độ tin cậy thấp hơn, rồi khiến bộ đánh giá sử dụng các định nghĩa đó thay cho tiêu chí do nhà phát triển xác định. Trong thử nghiệm của Datadog, `profile_description` có thể do người dùng chỉnh sửa được sao chép vào đối số tool cùng với `can_edit:false`. Văn bản giả dạng policy lập luận rằng nỗ lực ghi có rủi ro thấp vì một bước kiểm tra quyền riêng sẽ từ chối trước khi có bất kỳ thay đổi nào. Qua 40 lần chạy, điểm `is_risky` trung bình giảm từ `0.893` xuống `0.290`, trong khi phép so sánh giả mạo vai trò trực tiếp đạt trung bình `0.905`. Việc điểm trung bình giảm xuống dưới `0.5` không chứng minh rằng mọi lệnh gọi riêng lẻ đều vượt qua cổng, và thử nghiệm **không** chứng minh đã hoàn tất một thao tác ghi trái phép.<sup>[[7]](#references)</sup>

Khi kiểm thử ranh giới này, hãy phân biệt kết luận của bộ phân loại với kết quả cấp quyền thực tế của tool. Kiểm tra trường nào có thể chỉnh sửa được nhưng vẫn đến bộ đánh giá, so sánh cùng một hành động đề xuất có và không có văn bản giả dạng policy, rồi xác minh độc lập trạng thái cuối cùng. Bước kiểm tra quyền riêng vẫn phải dùng quyền hạn của người yêu cầu đã xác thực, không phải quyền của service account dùng chung của connector.<sup>[[7]](#references)</sup> Xem [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) để biết các dạng lỗi khác của bộ phân loại; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) đề cập đến một ranh giới định tuyến và credential khác.

### Cô lập context của subagent

Một subagent Claude Agent SDK không dùng fork nhận `AgentDefinition.prompt` riêng, prompt ủy quyền và các tool khả dụng, nhưng không nhận system prompt hoặc hội thoại của parent. Nếu bỏ qua `tools` trong định nghĩa, nó kế thừa các tool khả dụng cho subagent; `CLAUDE.md` của project vẫn có thể được tải. Vì vậy, hạn chế prompt chỉ áp dụng cho parent không phải là ranh giới đáng tin cậy khi child có thể dùng cùng tool filesystem hoặc thực thi.<sup>[[4]](#references)</sup>

Kiểm thử ranh giới bằng cách so sánh một yêu cầu trực tiếp mà parent từ chối với cùng tác vụ được ủy quyền cho một subagent có tên. NCC Group báo cáo rằng yêu cầu liệt kê tệp hệ điều hành bị từ chối đã thành công khi được diễn đạt lại cho child như một “sơ đồ bố cục” vô hại.<sup>[[3]](#references)</sup>

Kiểm tra các tool call thực tế của child và allowlist tool có hiệu lực, không chỉ câu trả lời cuối cùng của parent; xác nhận xem child có truy cập các tệp mà parent sẽ không truy cập hay không.<sup>[[4]](#references)</sup> Đây là lỗi kế thừa guardrail, không phải bằng chứng về [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) hay container escape.<sup>[[3]](#references)[[4]](#references)</sup>

### Agent GUI trên mobile: chỉ dẫn trên màn hình và đổi đích hành động

Agent GUI trên điện thoại có thể gửi từng ảnh chụp màn hình đến model cloud trước khi chọn hành động tiếp theo giữa các ứng dụng. Để kiểm thử **injection thị giác gián tiếp**, đặt văn bản do kẻ tấn công kiểm soát trong SMS, email hoặc trang mà agent sẽ xem trong một tác vụ được cho phép. So sánh prompt tác vụ trực tiếp với cùng chỉ dẫn chỉ hiển thị trong ảnh chụp màn hình, sau đó kiểm tra hành động tiếp theo và mọi quyết định về thao tác rủi ro cao. Trong trợ lý được đánh giá, `checkPrompt` phía client lọc văn bản tác vụ trực tiếp nhưng không áp dụng bộ lọc tương đương cho nội dung ảnh chụp màn hình. Đây là biến thể mobile, liên ứng dụng của [agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md), không phải cách vượt qua xác thực thành phần Android.<sup>[[9]](#references)</sup>

Một phép thử tác động phụ minh họa dùng biểu mẫu do kẻ tấn công kiểm soát, yêu cầu agent điền các trường nhạy cảm rồi yêu cầu con người nhấp “upload”, trong khi trang gửi các trường đã điền ngay khi chúng thay đổi. Việc chuyển giao cho con người không thể bảo vệ dữ liệu mà mã trang đã gửi; hãy xác minh lần gửi thực tế thay vì xem lời tường thuật của agent là bằng chứng. Nguồn mô tả đây là một kiểu có thể xảy ra, không phải một vụ xâm phạm đã được chứng minh trên mọi trợ lý.<sup>[[9]](#references)</sup>

**GUI TOCTOU / đổi đích hành động** là một dạng lỗi riêng: agent lập kế hoạch nhập liệu dựa trên màn hình được quan sát tại `t0`, nhưng UI ở foreground thay đổi trước khi thao tác được gửi tại `t1`.<sup>[[8]](#references)</sup> Ảnh chụp màn hình sau đó tại `t2` không thể đảo ngược hành động đã được thực hiện.<sup>[[9]](#references)</sup> Trong một bài kiểm thử Android được cho phép, workflow có thể tái sử dụng như sau:<sup>[[8]](#references)</sup>

1. Xác định tọa độ màn hình của control mục tiêu và hiển thị một control vô hại tại cùng vị trí trong một ứng dụng được kiểm soát.
2. Giữ ứng dụng mang control đó ở foreground cho đến khi agent quan sát được, sau đó kích hoạt một chuyển đổi foreground bình thường trong khoảng thời gian giữa lúc quan sát và hành động.
3. Kiểm tra xem thao tác chạm dự kiến có tác động lên control của ứng dụng mới hay không, rồi xác minh trạng thái kết quả trong ứng dụng mục tiêu thay vì dựa vào lời tường thuật của agent.

Nghiên cứu ban đầu về đổi đích hành động minh họa kỹ thuật này bằng một ứng dụng không có quyền nguy hiểm; nghiên cứu cũng mô tả việc lặp lại chuyển đổi thông qua vòng lặp phục hồi tác vụ của agent đối với workflow nhiều bước.<sup>[[8]](#references)</sup>

**Không** nên cho rằng kỹ thuật nguyên thủy này hoạt động nguyên vẹn trên mọi trợ lý. Trong đánh giá Doubao, `OpClickUI` bỏ qua thao tác nhấp nếu Activity cấp cao nhất thay đổi và so sánh ảnh chụp màn hình khi `OpOpenApp` xuất hiện trong ba bước trước đó. Vì vậy, thao tác chạm đơn, nhấn giữ và chạm đúp ít tạo ra cơ hội can thiệp thời điểm đáng tin cậy cho kẻ tấn công. `OpTypeText`, `OpSwipeUI` và `OpScrollWheelAction` không có các biện pháp bảo vệ tương đương, nhưng báo cáo đánh giá tác động thực tế của chúng là hạn chế hơn.<sup>[[9]](#references)</sup>

## Thực thi: chứng minh tác động thực tế

Có hai con đường riêng biệt từ việc gây ảnh hưởng đến tác động:<sup>[[2]](#references)</sup>

1. **Lạm dụng năng lực:** tool được cấp quyền đã có thể thực hiện mục tiêu. Ví dụ gồm đọc hồ sơ của một tenant rồi ghi hồ sơ đó vào báo cáo mà kẻ tấn công xem được, gửi email, thay đổi hồ sơ, xóa tệp hoặc khởi tạo thanh toán. Không cần có lỗi phần mềm thứ cấp.
2. **Khai thác sink ở bước sau:** đầu ra model bị kẻ tấn công điều hướng trở thành cú pháp cho một thành phần khác. Kiểm tra các truy vấn cơ sở dữ liệu để tìm [SQL injection](../pentesting-web/sql-injection/README.md) hoặc [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrapper để tìm [command injection](../pentesting-web/command-injection.md), URL được lựa chọn để tìm [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), thao tác tệp để tìm path traversal, template/code evaluator để tìm RCE và object parser để tìm [unsafe deserialization](../pentesting-web/deserialization/README.md).

Với mỗi trường hợp tiềm năng, hãy chứng minh chuỗi sau:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Một integration chỉ đọc vẫn có thể bị khai thác nếu bất kỳ thành phần nào về sau có thể phát tán nội dung nó đã đọc. Kiểm tra các phản hồi thông thường cùng những kênh rò rỉ ít rõ ràng hơn như liên kết do kẻ tấn công kiểm soát, tự động tải hình ảnh, webhook, log, báo cáo, bộ đếm, thông báo và tin nhắn gửi đến các agent khác.<sup>[[2]](#references)</sup>

## Các hành động nhằm đạt mục tiêu

Sau khi xác nhận một hành động, hãy đánh giá toàn bộ phạm vi ảnh hưởng thay vì dừng lại ở hiệu ứng đầu tiên có thể nhìn thấy:<sup>[[2]](#references)</sup>

- **Đánh cắp dữ liệu:** bí mật, hồ sơ người dùng, tệp nội bộ, dữ liệu hội thoại hoặc nội dung prompt/context bị đưa ra ngoài qua một kênh có thể quan sát được.
- **Hành động trái phép:** agent sử dụng các quyền ghi hợp lệ để phục vụ mục tiêu của kẻ tấn công.
- **Từ chối dịch vụ:** các công cụ phá hoại hoặc những thao tác tốn kém được lặp đi lặp lại làm ảnh hưởng đến tính toàn vẹn hoặc tính sẵn sàng.
- **Duy trì hiện diện:** memory bị đầu độc, nội dung đã được lập chỉ mục, trạng thái đáng tin cậy hoặc các thay đổi runtime vẫn tồn tại sau khi phiên hoặc nguồn khởi tạo bị xóa.
- **Lan truyền:** một peer đáng tin cậy tiếp nhận tin nhắn hoặc trạng thái chia sẻ từ agent bị xâm phạm rồi lặp lại hành động bằng công cụ và thông tin xác thực của chính nó.

Mức độ nghiêm trọng cần dựa trên dữ liệu có thể truy cập, đặc quyền thực tế, khả năng khai thác của sink, kênh phát tán, khả năng duy trì và lan truyền—không phải mức độ bất ngờ trong văn bản của model.<sup>[[2]](#references)</sup>

## Các biện pháp kiểm soát cần xác thực trong quá trình đánh giá

Bộ lọc prompt và system prompt tốt hơn có thể làm tăng chi phí cho kẻ tấn công, nhưng không nên được xem là ranh giới phân quyền. Hãy xác thực các biện pháp kiểm soát bên dưới bằng cách chạy lại cùng một chuỗi qua đầu vào trực tiếp, nội dung gián tiếp, memory, công cụ và các agent ngang hàng:<sup>[[2]](#references)</sup>

- Một lớp chính sách xác định kiểm tra người dùng đã xác thực, tenant, object, hành động và đích đến trong **mọi lần gọi công cụ**; model không thể cung cấp hoặc ghi đè danh tính của người gọi.
- Quyền đọc và ghi sử dụng thông tin xác thực riêng biệt, đặc quyền tối thiểu và thời hạn ngắn; các công cụ có tác động lớn chỉ được cấp quyền đúng lúc và không bao giờ tự động thực thi nội dung đã tiếp nhận.
- Kênh egress mạng và các đích nội bộ được đưa vào allowlist độc lập với URL do model chọn; chặn quyền truy cập runtime tới endpoint metadata, secret được mount và các dịch vụ lân cận, trừ khi cần thiết.
- Giao diện phê duyệt được tạo từ yêu cầu có cấu trúc chuẩn và hiển thị chính xác các tham số, danh tính, đích đến, object bị ảnh hưởng và tác dụng phụ—không chỉ là phần tóm tắt tự do của model.
- Xác minh thành công từ hệ thống đích hoặc hệ thống lưu trữ dữ liệu chuẩn. Lời mô tả của agent, yêu cầu gọi công cụ hoặc HTTP redirect không chứng minh trạng thái đã thay đổi như tuyên bố.
- Các mục memory và retrieval lưu giữ nguồn gốc cùng nhãn độ tin cậy, có thể bị vô hiệu hóa và được phân quyền lại khi dùng cho hành động về sau.
- Tin nhắn giữa các agent được xác thực và phân quyền như các yêu cầu không đáng tin cậy; danh tiếng của peer hoặc agent card không mặc nhiên trao quyền sử dụng công cụ của bên nhận.

Để tìm hiểu về agent card A2A, luồng tác vụ và bề mặt tấn công của chúng, xem [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [Top 10 ứng dụng Agentic năm 2026 của OWASP](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Cẩm nang của hacker về tấn công AI Agent](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Thực sự khó đến mức nào để đưa một AI Agent thoát khỏi sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagent trong SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Mã nguồn middleware TypeSafe Auto Mode của LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Độ gồ ghề của model TypeSafe AI Jev: nội dung đối kháng](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev làm giám khảo: Chính sách giả mạo điều hướng Jev như thế nào](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Thao túng không cần quyền: Chúng ta có thể tin các GUI Agent được hỗ trợ bởi mô hình đa phương thức lớn không?](https://arxiv.org/html/2601.12349v1)
- [9] [Khi trợ lý AI trở thành một mắt xích trong chuỗi tấn công của hacker | Phân tích bảo mật Doubao Phone](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
