# Các nghiên cứu tình huống về chính phủ và APT

{{#include ../banners/hacktricks-training.md}}

Những vụ việc công khai này cho thấy cách kết hợp các kỹ thuật bảo vệ quyền riêng tư riêng lẻ trong hoạt động thực tế. Nhãn quy kết là những nhãn được các nhà điều tra hoặc chính phủ được trích dẫn sử dụng; chỉ riêng địa chỉ IP, sự trùng khớp về công cụ hoặc mức độ phù hợp về địa chính trị không đủ để kết luận quy kết.

## APT28: truy cập Wi-Fi từ xa trong phạm vi lân cận

**Phát hiện công khai.** Volexity quy kết một vụ xâm nhập năm 2022 cho GruesomeLarch/APT28. Sau khi quyền truy cập Internet bằng thông tin xác thực đã được xác thực bị MFA chặn, tác nhân xâm nhập các tổ chức gần mục tiêu và tiếp cận Wi-Fi doanh nghiệp của mục tiêu thông qua một máy chủ có hai kết nối mạng ở gần đó. Đường truy cập Wi-Fi chấp nhận thông tin xác thực mà không yêu cầu MFA như khi truy cập từ bên ngoài.<sup>[[1]](#references)</sup>

**Ảnh hưởng đến quyền riêng tư.** Quyền truy cập cuối cùng bắt nguồn từ phạm vi phủ sóng vô tuyến thực tế, còn các tổ chức trung gian là nạn nhân. Hoạt động này tránh phải di chuyển và khiến định vị IP thông thường chỉ về một tổ chức lân cận.

**Điều gì đã làm lộ vụ việc.** Cần phân tích cảnh báo từ mục tiêu, quá trình điều tra máy chủ/mạng, hoạt động sử dụng thông tin xác thực, cấu trúc giao diện mạng và vị trí gần nhau như một chuỗi liên kết. Điểm bất thường không chỉ là một IP mới; đó là một danh tính hợp lệ được sử dụng trong bối cảnh Wi-Fi/thiết bị bất thường, đồng thời các hệ thống lân cận bị xâm nhập.

**Bài học phòng thủ.** Áp dụng phương thức truy cập Wi-Fi dựa trên chứng chỉ/thiết bị, đối chiếu RADIUS với NAC/MDM và bối cảnh vật lý, đồng thời điều tra hạ tầng lân cận thay vì cho rằng chặng cuối là của tác nhân.

## APT28: GRU tái sử dụng hạ tầng Moobot của tội phạm

**Phát hiện công khai.** Vào tháng 2 năm 2024, Bộ Tư pháp Hoa Kỳ mô tả một botnet gồm hàng trăm router Ubiquiti EdgeOS. Các tác nhân tội phạm đã cài Moobot lên những router vẫn dùng thông tin xác thực quản trị mặc định đã biết; sau đó GRU Unit 26165 thêm các tập lệnh và tệp, biến một botnet tội phạm sẵn có thành nền tảng gián điệp được dùng cho spearphishing và đánh cắp thông tin xác thực.<sup>[[2]](#references)</sup>

**Ảnh hưởng đến quyền riêng tư.** GRU không tự xây dựng toàn bộ hạ tầng. Việc mượn một mạng lưới thiết bị đã bị xâm nhập đặt các địa chỉ nhà riêng và văn phòng nhỏ không liên quan giữa tác nhân và mục tiêu, trộn lẫn hoạt động của nhà nước với hoạt động tội phạm, đồng thời giảm các dấu vết đăng ký đặc trưng của tác nhân.

**Điều gì đã làm lộ vụ việc.** Các tệp trên router, hành vi điều khiển malware và thông tin định tuyến không bao gồm nội dung đã hỗ trợ quá trình điều tra. Hoạt động triệt phá tạm thời thay đổi quy tắc firewall và xóa các tệp độc hại, trong khi DOJ cảnh báo rằng thông tin xác thực mặc định chưa được thay đổi có thể khiến thiết bị bị lây nhiễm lại.

**Bài học phòng thủ.** Thay router không còn được hỗ trợ, gỡ bỏ quyền quản trị lộ ra Internet, thay thông tin mặc định, vá lỗi, thu thập dữ liệu cấu hình/lưu lượng từ thiết bị biên và săn tìm hành vi của cả mạng lưới thiết bị. “IP dân cư tại Mỹ” không phải bằng chứng cho thấy tác nhân ở Mỹ.

## Volt Typhoon: KV Botnet kết hợp với living off the land

**Phát hiện công khai.** DOJ và một khuyến cáo chung của CISA mô tả Volt Typhoon do nhà nước Trung Quốc bảo trợ sử dụng KV Botnet, chủ yếu gồm các router SOHO Cisco và NETGEAR đã hết vòng đời, để che giấu nguồn gốc Trung Quốc của các hoạt động nhắm vào hạ tầng trọng yếu. Bên trong hệ thống của nạn nhân, tác nhân ưu tiên dùng tài khoản hợp lệ và công cụ quản trị tích hợp; các cơ quan cho biết hoạt động truy cập tại một số môi trường kéo dài ít nhất năm năm.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
                                                             |
                                                valid accounts + native tools
```

**Tác động đến quyền riêng tư.** Đường đi kiểu ORB che giấu nguồn gốc, trong khi kỹ thuật living-off-the-land giúp giảm số lượng binary mới và cơ hội bị phát hiện bằng chữ ký sau khi đã truy cập. Việc che giấu ở mạng và endpoint củng cố lẫn nhau.

**Điều khiến hoạt động bị phát hiện.** Cấu trúc router/controller, hoạt động thu thập kỹ thuật được tòa án cho phép, hoạt động lặp lại và phân tích xuyên các nạn nhân quan trọng hơn một IOC đơn lẻ. Khởi động lại router đã xóa malware KV lưu trong bộ nhớ khả biến ở các trường hợp được mô tả, nhưng không khắc phục được tình trạng thiết bị đã hết vòng đời hỗ trợ.

**Bài học phòng thủ.** Thay thế thiết bị mạng biên đã hết vòng đời hỗ trợ, tập trung hóa log xác thực và log thiết bị mạng, lập baseline hành vi quản trị viên, hạn chế kết nối outbound, và tìm kiếm chuỗi hành vi xuyên suốt các lớp identity, endpoint và network.

## China-nexus ORB networks: infrastructure as a service

**Phát hiện công khai.** Mandiant mô tả một hệ sinh thái ORB network được nhiều tác nhân gián điệp China-nexus sử dụng. Các mạng được cấp phát sử dụng node VPS thuê; các mạng không được cấp phát sử dụng thiết bị IoT và router bị xâm nhập; mạng lai kết hợp cả hai. ORB3/SPACEHOP hỗ trợ hoạt động liên quan đến APT5/APT15. ORB2/FLORAHOX kết hợp máy chủ quản trị, máy chủ thuê, lớp Tor tùy chỉnh và thiết bị Cisco, ASUS, DrayTek bị xâm nhập. Mandiant đánh giá một số mạng do các bên độc lập quản trị và cho nhiều tác nhân APT thuê.<sup>[[5]](#references)</sup>

**Tác động đến quyền riêng tư.** Hạ tầng trở thành một ranh giới dịch vụ. Một operator có thể nhận được các điểm thoát địa lý/dân cư mà không cần duy trì đội thiết bị của nạn nhân, trong khi nhiều khách hàng dùng chung hạ tầng khiến việc ánh xạ đơn giản actor với IP trở nên kém tin cậy. Việc thay mới đội thiết bị nhanh chóng đẩy nhanh “IOC extinction”.

**Điều khiến hoạt động bị phát hiện.** Địa hình mạng, ảnh máy chủ được sao chép, cổng/dịch vụ, mối liên hệ giữa các controller, implant trên router và các mẫu vòng đời vẫn có thể được gom cụm. Mandiant cho biết một số IP node chỉ tồn tại trong ORB vỏn vẹn 31 ngày.

**Bài học phòng thủ.** Theo dõi ORB như một thực thể luôn thay đổi: vai trò node, dấu vân tay dịch vụ, quan hệ upstream, hành vi quét và nhịp độ luân chuyển. Khi một chỉ báo IP hết hạn, hãy cập nhật cụm thay vì xóa hồ sơ vụ việc.

## PRC global espionage system: routers, trusted links and traffic mirroring

**Phát hiện công khai.** Một cảnh báo đa quốc gia năm 2025 mô tả hoạt động trùng lặp với các tên gọi trong báo cáo thương mại, bao gồm Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 và GhostEmperor. Các cơ quan cho biết VPS thuê và router trung gian bị xâm nhập được dùng để tiếp cận các nhà cung cấp viễn thông và mạng. Các tác nhân pivot qua các liên kết tin cậy giữa nhà cung cấp/khách hàng, sửa đổi route, tạo tunnel GRE/IPsec, sử dụng container trên thiết bị, và bật SPAN/RSPAN/ERSPAN hoặc tính năng packet capture tích hợp để thu thập thông tin xác thực và lưu lượng khách hàng.<sup>[[13]](#references)</sup>

**Tác động đến quyền riêng tư.** Router bị xâm nhập đồng thời là relay, điểm quan sát và một thành phần mạng được tin cậy. Các kết nối riêng có thể né những biện pháp kiểm soát vốn được thiết kế cho Internet công cộng, trong khi traffic mirroring thu thập thông tin xác thực mà không cần triển khai agent trên endpoint.

**Điều khiến hoạt động bị phát hiện.** Khác biệt cấu hình, quyền quản trị SNMP/SSH/web bất thường, static route/tunnel mới, phiên mirror, container Guest Shell, tệp PCAP, thay đổi đích TACACS+/RADIUS và log bị vô hiệu hóa. Cảnh báo nhấn mạnh rằng một số router trung gian không thuộc botnet công khai nào đã được nêu tên trước đó, vì vậy việc không có chỉ báo ORB đã biết không phải là bằng chứng vô can.

**Bài học phòng thủ.** Sử dụng quản trị out-of-band, tập trung hóa log cấu hình/xác thực, kiểm tra tính toàn vẹn của image đã ký và runtime, hạn chế egress từ giao diện quản trị, đồng thời tạo cảnh báo khi route/mirror/tunnel/AAA thay đổi. Khi nghi ngờ bị xâm nhập, hãy xác định phạm vi ảnh hưởng trên các peer tin cậy trước khi loại bỏ mối đe dọa.

## UNC3886 RedPenguin: passive backdoors on ISP routers

**Phát hiện công khai.** Mandiant quy kết các backdoor tùy chỉnh phát triển từ TINYSHELL trên router Juniper MX đã hết vòng đời hỗ trợ cho UNC3886. Bộ công cụ này gồm implant chủ động và thụ động, tên giả mạo daemon hợp pháp, hành vi vô hiệu hóa log, process injection vào một process đáng tin cậy, khả năng SOCKS proxy và hạ tầng được đánh giá là các node staging ORB. Các biến thể thụ động kiểm tra packet bằng `libpcap` và chỉ kích hoạt khi gặp một mẫu magic; một biến thể có thể chuyển sang callback chủ động do trigger cung cấp.<sup>[[14]](#references)</sup>

**Tác động đến quyền riêng tư.** Implant thụ động không phát beacon định kỳ để có thể phát hiện. Nó dùng chung cổng/lưu lượng với thiết bị mạng thật, chỉ kích hoạt trong thời gian ngắn và có thể relay qua ORB thay vì kết nối trực tiếp đến controller cuối cùng.

**Điều khiến hoạt động bị phát hiện.** Phân tích bộ nhớ, khác biệt giữa code trên ổ đĩa và code đang chạy, bộ lọc packet/socket có hành vi bất thường, tên process/tệp chỉ gần giống daemon hợp pháp, quản trị thông qua terminal server, log bị thiếu và mối liên hệ hai giai đoạn giữa node staging với backend controller.

**Bài học phòng thủ.** Thu thập bằng chứng bộ nhớ cùng với bằng chứng từ filesystem/cấu hình, đối chiếu process/module với image chuẩn, giám sát việc sử dụng packet capture/socket filter, bảo vệ terminal server quản trị và thay thế phần cứng mạng đã hết vòng đời hỗ trợ. Không phát hiện beacon outbound không có nghĩa là hệ thống an toàn.

## APT29: Tor domain fronting

**Phát hiện công khai.** MITRE ghi nhận APT29 sử dụng transport pluggable Tor `meek` để domain-front lưu lượng C2. Tên TLS bên ngoài có vẻ là một domain hợp pháp được CDN host, trong khi HTTP host bên trong chọn route thực tế.<sup>[[6]](#references)</sup>

**Tác động đến quyền riêng tư.** Một bên quan sát có lọc lưu lượng có thể chỉ thấy front/CDN phổ biến thay vì đích bên trong, còn việc chặn nó có nguy cơ gây ảnh hưởng ngoài dự kiến.

**Điều khiến hoạt động bị phát hiện.** CDN có thể quan sát sự không khớp giữa thông tin định tuyến, còn defender có khả năng quan sát endpoint hoặc TLS hợp pháp có thể tương quan process, authority, thời lượng kết nối, mẫu byte và hoạt động tiếp theo. Thay đổi chính sách của nhà cung cấp có thể vô hiệu hóa kỹ thuật này.

**Bài học phòng thủ.** Đừng chỉ dựa vào allowlist SNI. Thực thi kiểm soát egress có nhận biết ứng dụng, đối chiếu danh tính TLS và HTTP khi có thể quan sát, đồng thời liên kết sự kiện mạng với process khởi tạo kết nối.

## APT41 and other dead-drop resolvers

**Phát hiện công khai.** MITRE ghi nhận APT41 sử dụng các website hợp pháp như GitHub, Pastebin, Microsoft TechNet, Cloudflare và diễn đàn cộng đồng để công bố hoặc lấy thông tin C2. Các công cụ khác có liên hệ với nhà nước cũng sử dụng bài đăng, tài liệu và mạng xã hội theo cách tương tự.<sup>[[7]](#references)</sup>

**Tác động đến quyền riêng tư.** Binary chứa một dịch vụ/đối tượng hợp pháp thay vì địa chỉ C2 ổn định. Đối tượng này có thể được chỉnh sửa để luân chuyển hạ tầng, còn request ban đầu hòa lẫn vào lưu lượng TLS phổ biến.

**Điều khiến hoạt động bị phát hiện.** Đối tượng hoặc mã định danh tài khoản ổn định; các process hiếm gặp liên tục truy xuất nó; nội dung được giải mã; và sau đó có một kết nối outbound thứ hai. Bản ghi tài khoản và API của nhà cung cấp có thể liên kết việc công bố với operator.

**Bài học phòng thủ.** Lưu giữ đầy đủ đường dẫn proxy/mã định danh đối tượng và nguồn gốc process trên endpoint. Sự kiện ở cấp domain như “đã kết nối đến GitHub” quá sơ lược.

## Turla: satellite-address C2

**Phát hiện công khai.** Kaspersky đưa tin Turla lạm dụng các chương trình phát sóng downstream không mã hóa từ những dịch vụ Internet DVB-S một chiều đời cũ. Một operator trong vùng phủ sóng vệ tinh có thể chọn địa chỉ của một thuê bao hợp pháp và nhận các phản hồi được phát đến địa chỉ đó, khiến C2 trông như được host phía sau một nhà cung cấp vệ tinh ở khu vực khác.<sup>[[8]](#references)</sup>

**Tác động đến quyền riêng tư.** Địa chỉ máy chủ có vẻ là đích đến không xác định được thiết bị nhận, còn các quy trình tịch thu hosting/WHOIS thông thường kém hữu ích hơn.

**Điều khiến hoạt động bị phát hiện.** Tác nhân vẫn cần một đường outbound để gửi request, định tuyến không đối xứng, thuê bao hợp pháp không khởi tạo trao đổi C2, và việc điều tra RF/nhà cung cấp có thể thu hẹp vùng phủ sóng nhận.

**Bài học phòng thủ.** Hãy xem định vị địa lý là một giả thuyết. Xác minh tính đối xứng của đường truyền, RTT, đơn vị quản lý định tuyến và liệu endpoint được cho là nguồn có thực sự tạo ra dịch vụ quan sát được hay không.

## Cyclops Blink and VPNFilter: edge devices as durable cover

**Phát hiện công khai.** Một cảnh báo năm 2022 của NCSC/CISA/FBI/NSA mô tả malware Cyclops Blink dạng module của Sandworm trên thiết bị WatchGuard, được triển khai bền vững dưới dạng bản cập nhật firmware và có khả năng thêm module. DOJ mô tả riêng botnet VPNFilter trước đó của APT28, gồm router và thiết bị NAS có khả năng thu thập thông tin tình báo, thực hiện hoạt động phá hoại và gây quy kết nhầm.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Tác động đến quyền riêng tư.** Thiết bị mạng biên luôn trực tuyến, được tin cậy như hạ tầng và ít được EDR giám sát. Persistence trong firmware có thể tồn tại sau khi khởi động lại thông thường, biến thiết bị của nạn nhân thành relay hoặc điểm điều khiển.

**Điều khiến hoạt động bị phát hiện.** Tính toàn vẹn firmware, giao thức implant đặc thù của nhà cung cấp, quyền quản trị bị mở bất thường, thay đổi cấu hình và beacon outbound. Cần xem thiết bị mạng biên là đối tượng điều tra pháp chứng, không phải hạ tầng vô hình.

## DPRK: identity, network and financial layering

**Phát hiện công khai.** Các vụ án của DOJ mô tả người lao động DPRK tìm việc từ xa bằng giấy tờ tùy thân giả hoặc bị đánh cắp và VPN, nhận tiền mã hóa, chia nhỏ các khoản chuyển, hoán đổi tài sản/chuỗi, sử dụng NFT và trộn lẫn tiền thu được. Các vụ án khác mô tả trader OTC và công ty bình phong chuyển tiền mã hóa bị đánh cắp thành các khoản mua sắm. Bộ Tài chính và FBI đã công khai liên hệ tiền thu được của Lazarus/TraderTraitor với mixer, đồng thời xác định các địa chỉ liên quan đến những vụ trộm lớn.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Tác động đến quyền riêng tư.** Đây không phải là “một đồng tiền riêng tư”. Đó là chuỗi nhiều miền: danh tính giả và truy cập từ xa che giấu vị trí người lao động; tiền mã hóa luân chuyển giá trị; layering làm đứt gãy câu chuyện giao dịch đơn giản; trader OTC/công ty bình phong kết nối dòng tiền với hàng hóa và tiền pháp định.

**Điều khiến hoạt động bị phát hiện.** Bất thường về nhà tuyển dụng/thiết bị, các bên hỗ trợ được dùng lại, tính liên tục về thời điểm/giá trị trên blockchain, hồ sơ sàn/cầu nối, địa chỉ bị trừng phạt, danh tính tài khoản và hồ sơ vận chuyển/doanh nghiệp có thể nối lại các mắt xích.

**Bài học phòng thủ.** Các nhóm tuyển dụng, IAM, endpoint, trả lương, blockchain và tuân thủ lệnh trừng phạt cần dùng chung mô hình hồ sơ vụ việc. Xem thêm chi tiết tại [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Cross-case patterns

| Mẫu hình | Ví dụ APT | Biện pháp điều chỉnh cho defender |
|---|---|---|
| Điểm thoát là một nạn nhân khác | APT28/Moobot, Volt Typhoon/KV, ORB | điều tra và khắc phục điểm thoát; đừng đồng nhất nó với vị trí của tác nhân |
| Biện pháp kiểm soát khác nhau theo ranh giới | APT28 nearest neighbor | áp dụng mức đảm bảo danh tính cho truy cập nội bộ/không dây tương đương với truy cập Internet |
| Dịch vụ hợp pháp được dùng làm lớp định tuyến | APT29, APT41 | lưu giữ ngữ cảnh đối tượng/đường dẫn/process, không chỉ domain đích |
| Thiết bị mạng biên thiếu telemetry | KV, Moobot, Cyclops Blink, ORB | tập trung hóa log cấu hình/xác thực/luồng và xác minh firmware/danh mục thiết bị |
| Hạ tầng được chia sẻ và tồn tại ngắn hạn | China-nexus ORB | gom cụm theo hành vi/địa hình và theo dõi thay đổi vai trò theo thời gian |
| Nhiều lớp phân tách yếu kết hợp với nhau | Danh tính giả DPRK + VPN + crypto + OTC | liên kết bằng chứng về danh tính, thiết bị, mạng, thanh toán và vật lý |

## References

- [1] [Volexity — Tấn công Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Triệt phá botnet router Moobot do GRU kiểm soát](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Triệt phá botnet KV của PRC](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Tác nhân PRC xâm nhập và duy trì quyền truy cập dai dẳng vào hạ tầng trọng yếu của Hoa Kỳ](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Các tác nhân gián điệp China-nexus sử dụng ORB network](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Turla qua vệ tinh](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cảnh báo Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Triệt phá VPNFilter của APT28](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Đại diện Ngân hàng Ngoại thương DPRK bị truy tố trong các âm mưu rửa tiền mã hóa](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Lệnh trừng phạt Blender.io và tiền của Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Đối phó với hoạt động xâm nhập mạng toàn cầu của các tác nhân được nhà nước Trung Quốc bảo trợ](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Bóng ma trong router: UNC3886 nhắm vào router Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
