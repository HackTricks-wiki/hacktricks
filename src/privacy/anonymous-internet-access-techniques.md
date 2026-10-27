# Danh mục kỹ thuật truy cập Internet ẩn danh

{{#include ../banners/hacktricks-training.md}}

Đây là danh mục chuẩn về các đường truy cập. Danh mục bao quát các **nhóm** giao thức và vận hành, không liệt kê mọi tên nhà cung cấp. Không đường truy cập Internet nào bảo đảm tính ẩn danh: bằng chứng về tài khoản, trình duyệt, thiết bị đầu cuối, thời điểm, thanh toán, control plane đám mây và vị trí thực tế có thể làm lộ danh tính dù đường truy cập trông hoàn hảo.

Mỗi mục sử dụng cùng một trường thông tin. “Quy trình” nghĩa là triển khai hợp pháp hoặc mô phỏng trong lab do bạn sở hữu. Khi kỹ thuật thực tế phụ thuộc vào việc xâm nhập router, đánh cắp quyền truy cập hoặc lạm dụng một bên trung gian không đồng thuận, bản tái hiện sẽ thay thế bằng các hệ thống thuộc quyền sở hữu của bài tập.

## Ma trận phạm vi

| Nhóm | Đích đến nhìn thấy | Thuộc tính mạnh nhất | Tốc độ | Cách sử dụng |
|---|---|---|---|---|
| Shared NAT/CGNAT | địa chỉ công khai dùng chung | tạo sự mơ hồ giữa các thuê bao | cao | có thể triển khai |
| VPN, VPS, SOCKS/HTTP/SSH proxy | địa chỉ relay | tách địa chỉ nguồn nhanh chóng | cao | có thể triển khai |
| Multi-hop/split relay, MASQUE | proxy cuối | chia tách thông tin hoặc tunnel toàn bộ IP | cao/trung bình | có thể triển khai với relay đáng tin cậy |
| Tor, bridge, onion service | exit hoặc danh tính onion | đường đi qua nhiều bên và trình duyệt dùng chung | trung bình | có thể triển khai |
| I2P, GNUnet, mixnet | peer/gateway của overlay | overlay hoặc khả năng chống phân tích thời gian | thấp/thay đổi | tùy ứng dụng |
| OHTTP/ODoH, Private Relay | gateway/egress | phân tách thông tin nguồn/yêu cầu | cao | chỉ ứng dụng được hỗ trợ |
| Wi-Fi công cộng, travel router | địa chỉ của địa điểm/tunnel | thay đổi vị trí/đường truy cập | cao | cần được cho phép |
| Cellular/eSIM, vệ tinh | địa chỉ của nhà mạng/nhà cung cấp | uplink vật lý độc lập | cao/thay đổi | thuê bao/nhà cung cấp có thể quan sát |
| Trình duyệt từ xa/jump host | workspace từ xa | tách biệt thiết bị đầu cuối và egress | cao | có thể triển khai |
| Residential/mobile proxy | địa chỉ mạng dân dụng/nhà mạng | tạo cảm giác như đang dùng mạng dân dụng | cao | sự đồng thuận/nguồn gốc đặc biệt quan trọng |
| ORB/relay bị xâm nhập | địa chỉ của nạn nhân khác | che giấu nguồn gốc và mượn uy tín | cao | chỉ tái hiện trong lab do bạn sở hữu |
| CDN/fronting/redirector | địa chỉ CDN/front | bảo vệ hạ tầng back-end | cao | cần nhà cung cấp/chủ sở hữu chấp thuận |
| Fast flux/DGA/dead drop | node/dịch vụ luân phiên | chống phát hiện hạ tầng | thay đổi | chỉ tái hiện trong lab do bạn sở hữu |
| Drop/nearest-neighbor | địa chỉ gần mục tiêu trên mạng nội bộ | vượt qua ranh giới địa lý/mạng | cao | chỉ trong lab tại địa điểm do bạn sở hữu |
| Store-and-forward/offline | gateway hoặc thiết bị nhận vật lý | giảm liên kết thời gian tương tác | thấp | tùy ứng dụng |
| Pluggable/refraction transport | điểm vào Tor hoặc proxy chuyển hướng có hợp tác | khả năng truy cập chống kiểm duyệt | thay đổi | client được hỗ trợ hoặc lab nghiên cứu |
| IPFS gateway/PIR/remote fetcher | gateway hoặc dịch vụ ứng dụng | phân tách nhà phát hành/truy vấn/yêu cầu | thay đổi | chỉ ứng dụng có phạm vi giới hạn |
| Anycast/QUIC/MPTCP | broker ổn định hoặc nhiều subflow | rendezvous và duy trì phiên | cao | tăng tính sẵn sàng, không phải tính ẩn danh |
| CI/CD automation runner | địa chỉ runner do nhà cung cấp lưu trữ | egress có thể kiểm soát, tồn tại ngắn hạn | cao | chỉ workflow do bạn sở hữu |
| Chặng đầu nội bộ không dùng IP | gateway của tổ chức | loại bỏ stack Internet khỏi sensor | thấp | triển khai được chủ sở hữu chấp thuận |

## Shared NAT trực tiếp và carrier-grade NAT

**Cơ chế:** nhiều người dùng dùng chung một địa chỉ công khai; nhà cung cấp dịch vụ truy cập ánh xạ địa chỉ và port phía thuê bao sang tuple công khai.

**Ưu điểm:** nhanh; không cần client đặc biệt; chỉ nhìn địa chỉ IP phía đích có thể chỉ nhận diện được một hộ gia đình, địa điểm hoặc nhóm thuê bao của nhà mạng.

**Nhược điểm:** nhà cung cấp có thể lưu ánh xạ thuê bao/port/thời gian; tài khoản và dấu vân tay vẫn còn; người dùng khác có thể làm giảm uy tín của địa chỉ.

**Quy trình:** (1) xác nhận đường truy cập được ủy quyền có dùng NAT/CGNAT hay không; (2) ghi lại IP công khai chính xác và source port tại endpoint do bạn sở hữu; (3) tách biệt danh tính ứng dụng; (4) không xem việc dùng chung địa chỉ là biện pháp kiểm soát quyền riêng tư; (5) dùng đường truy cập mạnh hơn nếu cần ngăn ISP biết các đích đến.

**Phát hiện:** các đích đến nên lưu source port và thời gian chính xác, không chỉ IP. Nhà cung cấp đối chiếu log phân bổ NAT; điều tra viên kết hợp bằng chứng tài khoản/thiết bị/trình duyệt.

## VPN thương mại

**Cơ chế:** kết nối full-tunnel được mã hóa và kết thúc tại VPN; các đích đến nhìn thấy egress của VPN. VPN thường có thể liên kết nguồn, thời gian và đích đến.

**Ưu điểm:** nhanh; đơn giản; bảo vệ trước việc quan sát thụ động tại mạng cục bộ; có exit ổn định hoặc dùng chung; phù hợp cho egress red-team được kiểm soát.

**Nhược điểm:** tập trung niềm tin; dữ liệu thanh toán/đăng nhập; lỗi kill-switch/DNS/IPv6; exit dùng chung thường bị chặn do uy tín kém.

**Quy trình:** (1) xác định nhà cung cấp, chủ sở hữu, khu vực pháp lý, chính sách lưu trữ và đánh giá; (2) cài client chính thức có chữ ký; (3) bật full tunnel, always-on và chế độ fail-closed; (4) chủ động định tuyến DNS và IPv6; (5) xác minh IPv4/IPv6/DNS được quan sát tại endpoint do bạn sở hữu; (6) dừng/kết nối lại tunnel và xác nhận không có đường dự phòng dạng clear.<sup>[[1]](#references)</sup>

**Phát hiện:** mạng cục bộ thấy một luồng mã hóa kéo dài tới hạ tầng VPN; nhà cung cấp có bản ghi xác thực/kết nối; đích đến dùng ASN/uy tín cùng thông tin tài khoản, TLS/trình duyệt và tương quan hành vi.

## VPN tự host hoặc egress qua VPS thuê

**Cơ chế:** người vận hành kiểm soát gateway WireGuard/OpenVPN hoặc chuyển tiếp lưu lượng qua máy chủ thuê.

**Ưu điểm:** tốc độ cao, dễ dự đoán; địa chỉ cố định có thể đưa vào allowlist; tùy chỉnh logging/firewall; kiểm soát sự cố tốt.

**Nhược điểm:** nhóm ẩn danh nhỏ; tenant đám mây, thanh toán, đăng nhập nguồn, API và lịch sử image có thể liên kết người vận hành; máy chủ mới có dấu hiệu riêng biệt rất dễ bị nhóm lại.

**Quy trình:** (1) tạo project trong tổ chức dành riêng cho từng engagement; (2) cấp phát image được hỗ trợ và địa chỉ cố định; (3) chỉ cho phép quản trị bằng MFA/khóa; (4) cấu hình egress full-tunnel và DNS; (5) giới hạn chỉ các đích trong phạm vi khi có thể; (6) kiểm tra rò rỉ/hành vi khi lỗi; (7) giữ bản ghi audit của control plane; (8) hủy thông tin xác thực và tài nguyên khi kết thúc.

**Phát hiện:** tương quan ASN hosting, địa chỉ xuất hiện lần đầu, dấu vân tay certificate/service và hành vi scanning; chủ sở hữu đám mây dùng log control plane, console, billing và flow.

## Chuyển tiếp HTTP CONNECT, SOCKS và SSH

**Cơ chế:** ứng dụng yêu cầu proxy mở một luồng TCP; SOCKS cũng có thể chuyển tiếp phân giải tên và UDP tùy phiên bản; SSH chuyển tiếp luồng bên trong một phiên mã hóa.

**Ưu điểm:** gọn nhẹ; theo từng ứng dụng; nhanh; hữu ích để nối chuỗi và truy cập mạng phân đoạn.

**Nhược điểm:** ứng dụng có thể bỏ qua proxy; DNS có thể bị leak; proxy thấy các endpoint liền kề; trạng thái trình duyệt vẫn còn; open proxy có thể là bẫy hoặc hệ thống bị xâm nhập.

**Quy trình:** (1) triển khai proxy trên host do bạn sở hữu; (2) yêu cầu xác thực và giới hạn nguồn/đích; (3) cấu hình một profile ứng dụng dùng một lần; (4) đảm bảo phân giải DNS từ xa khi cần; (5) xác minh bằng endpoint DNS/HTTP do bạn sở hữu; (6) chặn egress trực tiếp của workload; (7) kiểm tra và luân chuyển thông tin xác thực proxy.

**Phát hiện:** nhận diện tiến trình có khả năng tạo tunnel, thương lượng CONNECT/SOCKS, phiên SSH dài và đích đến không phù hợp với ứng dụng; log proxy có thể tái dựng các luồng.

## Web proxy viết lại URL và browser proxy extension

**Cơ chế:** website tải một đích đến rồi viết lại liên kết/form qua origin của chính nó, hoặc extension chuyển yêu cầu trình duyệt qua proxy. Đích đến nhìn thấy dịch vụ, còn dịch vụ có thể đọc plaintext sau khi kết thúc TLS và chèn hoặc lưu nội dung.

**Ưu điểm:** không cần client toàn hệ thống; nhanh khi duyệt web đơn giản; dùng được khi không thể cài VPN.

**Nhược điểm:** proxy có thể đọc thông tin đăng nhập/nội dung, viết lại download và lấy dấu vân tay người dùng; script/WebSocket/download có thể bỏ qua; browser extension có quyền rộng; nhóm ẩn danh nhỏ và thường bị chặn.

**Quy trình:** (1) chỉ dùng proxy do tổ chức vận hành cho kiểm thử được ủy quyền; (2) cô lập proxy trong trình duyệt dùng một lần, không đăng nhập tài khoản cá nhân; (3) cấm nhập mật khẩu và tải nội dung nhạy cảm; (4) xác minh mọi subresource trên trang do bạn sở hữu đều được phân giải qua proxy; (5) kiểm thử hành vi WebSocket, download và form; (6) gỡ extension/profile sau khi dùng.

**Phát hiện:** đích đến ghi nhận proxy; proxy/DNS doanh nghiệp và danh mục extension giúp nhận diện dịch vụ; content-security/reporting hoặc subresource canary do bạn sở hữu phát hiện đường đi trực tiếp bị bỏ qua; log proxy ánh xạ phiên người dùng tới các đích.

## Multi-hop proxy hoặc VPN multi-hop của nhà cung cấp

**Cơ chế:** entry thấy nguồn trong khi một hoặc nhiều relay trung gian tách nguồn đó khỏi exit vốn nhìn thấy đích đến.

**Ưu điểm:** relay thông thường không cần biết cả hai đầu; một node bị lỗi/bị thu giữ sẽ làm lộ ít thông tin hơn; linh hoạt về địa lý.

**Nhược điểm:** cùng một bên quản trị/log có thể phá vỡ việc phân tách; độ trễ; tương quan thời gian; nhiều đường lỗi và DNS hơn; cùng tài khoản/thanh toán có thể liên kết mọi hop.

**Quy trình:** (1) xác định observer nào bị loại bỏ ở mỗi hop; (2) dùng relay do các bên độc lập quản trị, thuộc sở hữu hoặc được phê duyệt khi cần phân tách; (3) chỉ cho workload truy cập entry; (4) đảm bảo mỗi relay chỉ kết nối được tới hop kế tiếp; (5) xác minh log ở mọi lớp; (6) dừng từng hop và xác nhận chế độ fail-closed. Tái hiện bằng [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Phát hiện:** tương quan thời gian/lưu lượng NetFlow liền kề, các lần bắt tay proxy lặp lại và hạ tầng controller dùng chung; không suy đoán địa lý của người vận hành từ exit.

## Relay ứng dụng phân tách thông tin và OHTTP

**Cơ chế:** client mã hóa thông điệp HTTP phi trạng thái tới gateway rồi gửi qua relay. Relay thấy IP client nhưng không thấy yêu cầu; gateway thấy yêu cầu nhưng thường chỉ thấy IP relay.

**Ưu điểm:** phân tách quyền riêng tư mạnh, có thể kiểm toán cho các yêu cầu được hỗ trợ; overhead thấp hơn mạng ẩn danh tổng quát.

**Nhược điểm:** không hỗ trợ duyệt web tùy ý; cookie/xác thực có thể liên kết lại; thông đồng giữa relay/gateway và phân tích lưu lượng vẫn có thể xảy ra; ứng dụng phải triển khai tính năng này.

**Quy trình:** (1) chọn ứng dụng hỗ trợ rõ ràng RFC 9458; (2) xác minh khóa gateway qua đường cấu hình chính thức; (3) tránh các trường ổn định theo từng người dùng; (4) chỉ gửi yêu cầu phi trạng thái được hỗ trợ; (5) so sánh log relay, gateway và đích; (6) kiểm thử luân chuyển khóa/lỗi mà không fallback trực tiếp.<sup>[[2]](#references)</sup>

**Phát hiện:** endpoint doanh nghiệp cho biết tiến trình khởi tạo và relay OHTTP; gateway phát hiện lưu lượng sai định dạng/phát lại; thời gian và các trường payload/tài khoản ổn định có thể liên kết yêu cầu.

## MASQUE CONNECT-UDP/CONNECT-IP và HTTP privacy proxy

**Cơ chế:** HTTP Extended CONNECT qua TLS/QUIC truyền các gói UDP hoặc IP qua proxy. Cơ chế này có thể tạo tunnel hiện đại giống VPN và hòa lẫn với HTTP/3, nhưng proxy vẫn có thể quan sát.<sup>[[3]](#references)</sup>

**Ưu điểm:** ghép kênh/chuyển mạng hiệu quả; hỗ trợ UDP hoặc toàn bộ IP; triển khai qua hạ tầng HTTP hiện đại.

**Nhược điểm:** không phải mạng ẩn danh; proxy/tài khoản thấy nguồn và đích; dấu vân tay QUIC/HTTP và các path phổ biến hiển thị với endpoint/nhà cung cấp.

**Quy trình:** (1) dùng client/dịch vụ có tài liệu hỗ trợ RFC 9298/9484; (2) xác thực certificate/cấu hình proxy; (3) xác định các route đích được phép; (4) bật DNS mã hóa bên trong đường truy cập; (5) kiểm tra UDP, TCP, IPv6 và failover với endpoint do bạn sở hữu; (6) kiểm tra log yêu cầu và flow của proxy.

**Phát hiện:** endpoint thấy tiến trình client và virtual interface; mạng có thể phân loại lưu lượng QUIC/TLS kéo dài tới proxy; log proxy để lộ đích/path CONNECT và route được gán.

## Tor Browser

**Cơ chế:** Tor chọn các relay guard, middle và exit; mã hóa nhiều lớp giới hạn thông tin mỗi relay nhìn thấy. Tor Browser bổ sung một trình duyệt chuẩn hóa nhằm chống lấy dấu vân tay.

**Ưu điểm:** nhóm ẩn danh công khai lớn; không relay thông thường nào biết cả hai đầu; không cần vận hành máy chủ để tránh liên kết với đích đến.

**Nhược điểm:** chậm hơn; chủ yếu dùng TCP; exit có uy tín thấp/dễ bị chặn; đăng nhập và tiết lộ thông tin có thể nhận diện người dùng; vẫn có thể bị tương quan thời gian với mạng độ trễ thấp.

**Quy trình:** (1) tải và xác minh Tor Browser từ dự án; (2) giữ cấu hình mặc định và tránh extension; (3) chọn mức bảo mật phù hợp; (4) tạo danh tính/phiên riêng; (5) tránh tài khoản có thể nhận diện và tài liệu chủ động bên ngoài; (6) dùng HTTPS hoặc onion service có xác thực; (7) chỉ xác minh exit bằng endpoint do bạn sở hữu.<sup>[[4]](#references)</sup>

**Phát hiện:** mạng cục bộ có thể nhận diện lưu lượng tới guard đã biết, trừ khi dùng bridge/transport; đích đến thấy exit và hành vi Tor Browser; observer ở hai đầu có thể tương quan thời gian/lưu lượng.

## Tor bridge và pluggable transport

**Cơ chế:** bridge không công khai thay cho public guard; obfs4, Snowflake hoặc WebTunnel thay đổi transport của hop đầu để chống chặn/dò quét đơn giản.

**Ưu điểm:** vượt kiểm duyệt và che giấu các đích đến relay công khai dễ nhận diện; duy trì mạch Tor sau khi vào mạng.

**Nhược điểm:** vẫn có thể nhận diện pattern transport/tìm ra bridge; hiệu năng thay đổi; không tăng khả năng bảo vệ trước tài khoản hoặc tương quan thời gian toàn cục.

**Quy trình:** (1) thử Tor trực tiếp trước; (2) trong cài đặt Connection của Tor Browser, chọn transport tích hợp được hỗ trợ hoặc yêu cầu bridge chính thức; (3) không dùng binary/danh sách ngẫu nhiên; (4) kết nối và chạy kiểm thử lành tính; (5) kiểm tra kết nối lại và đồng hồ; (6) giữ các cài đặt trình duyệt khác ở chế độ chuẩn.<sup>[[5]](#references)</sup>

**Phát hiện:** bên kiểm duyệt dùng tìm kiếm đích đến, phân loại giao thức/flow và dò quét chủ động; bên phòng thủ nên phân biệt việc dùng công cụ vượt kiểm duyệt với việc bị xâm nhập, đồng thời dựa vào tiến trình/context trên endpoint.

## VPN trước Tor và Tor trước VPN

**Cơ chế:** VPN-trước-Tor che việc dùng Tor trực tiếp khỏi ISP truy cập nhưng để lộ nguồn với VPN. Tor-trước-VPN đưa lưu lượng sau Tor tới VPN và thường tạo danh tính khách hàng/tunnel ổn định.

**Ưu điểm:** loại bỏ một observer cụ thể nếu thiết kế đúng; có thể truy cập mạng chặn một lớp.

**Nhược điểm:** phức tạp, dấu vân tay không phổ biến, rò rỉ, nhóm ẩn danh nhỏ hơn và cảm giác an toàn giả; Tor Project xem các kết hợp này là nâng cao.<sup>[[6]](#references)</sup>

**Quy trình:** (1) ghi rõ observer bị loại bỏ và observer mới được đưa vào; (2) dùng môi trường dùng một lần; (3) chỉ thiết lập đường truy cập bên ngoài đã định; (4) áp dụng route bằng firewall; (5) xác minh DNS/IPv4/IPv6 và thứ tự lỗi ở từng lớp; (6) so sánh thông tin mỗi nhà cung cấp có thể thấy; (7) bỏ cấu hình nhiều lớp nếu không có lợi ích đo lường được.

**Phát hiện:** observer cục bộ/VPN/Tor thấy các lớp liền kề khác nhau; tương quan thời gian vẫn có thể thực hiện từ đầu đến cuối; dấu vân tay tunnel lồng nhau bất thường và tài khoản nhà cung cấp có thể liên kết phiên.

## Onion service

**Cơ chế:** cả client và dịch vụ đều tạo mạch Tor tới một rendezvous, che giấu IP dịch vụ và không cần exit.

**Ưu điểm:** bảo vệ nguồn và vị trí dịch vụ; xác thực onion đầu-cuối; không cần port inbound công khai; có thể yêu cầu client được cấp quyền.

**Nhược điểm:** bản cập nhật/analytics/lỗi có thể làm lộ origin; khóa onion rất quan trọng; danh tính ứng dụng/thời gian và việc host bị xâm nhập vẫn là rủi ro.

**Quy trình:** (1) cô lập ứng dụng và chỉ bind vào loopback/socket; (2) cài Tor được hỗ trợ; (3) cấu hình onion service v3 theo hướng dẫn chính thức; (4) bảo vệ/sao lưu khóa chỉ khi cần danh tính ổn định; (5) thêm client authorization khi sử dụng nội bộ; (6) bỏ các truy vấn tới bên thứ ba; (7) xác minh bên ngoài rằng origin không thể truy cập được.<sup>[[7]](#references)</sup>

**Phát hiện:** bên phòng thủ host/mạng tìm tiến trình/cấu hình Tor và các circuit outbound; lỗi ứng dụng, DNS, certificate hoặc tài nguyên bên thứ ba có thể làm lộ origin.

## Dịch vụ nội bộ I2P

**Cơ chế:** I2P dùng các tunnel inbound/outbound một chiều riêng biệt cho các đích đến bên trong overlay; outproxy ra Internet công cộng tạo thêm một điểm cần tin cậy.

**Ưu điểm:** xuất bản nội bộ phi tập trung; không phụ thuộc exit chính thức; đường inbound/outbound riêng biệt.

**Nhược điểm:** không thay thế web nói chung; hệ sinh thái nhỏ hơn; hành vi peer chạy lâu dài; outproxy có thể quan sát hoạt động duyệt web công cộng.

**Quy trình:** (1) cài từ nguồn chính thức; (2) dùng context riêng; (3) cho phép tích hợp/ổn định băng thông; (4) truy cập dịch vụ I2P do bạn sở hữu; (5) tránh outproxy trừ khi được yêu cầu rõ ràng; (6) xác minh khi tắt không có fallback trực tiếp; (7) kiểm tra log peer và dịch vụ cục bộ.<sup>[[8]](#references)</sup>

**Phát hiện:** mạng cục bộ thấy lưu lượng peer kéo dài và hành vi bootstrap; endpoint để lộ tiến trình router/ứng dụng; outproxy ghi log các phiên truy cập ra ngoài.

## Mixnet

**Cơ chế:** packet có kích thước cố định, batching, trì hoãn, sắp xếp lại và lưu lượng cover giúp giảm tương quan thời gian; gateway kết nối tới ứng dụng.

**Ưu điểm:** chống phân tích thời gian tốt hơn proxy độ trễ thấp; hữu ích cho tin nhắn/giao dịch bất đồng bộ.

**Nhược điểm:** độ trễ, overhead băng thông, triển khai hạn chế và giới hạn ứng dụng; metadata gateway/tài khoản có thể được lưu lại.

**Quy trình:** (1) chọn client được duy trì và ứng dụng được hỗ trợ; (2) đọc mô hình đe dọa thực tế; (3) cài trong compartment riêng; (4) gửi dữ liệu lành tính tới endpoint do bạn sở hữu; (5) đo độ trễ/độ tin cậy và đường phản hồi; (6) kiểm tra lỗi gateway; (7) không bao giờ tắt độ trễ/lưu lượng cover chỉ để tăng tốc.<sup>[[9]](#references)</sup>

**Phát hiện:** endpoint nhận diện client; mạng truy cập có thể phân loại gateway/nhịp packet; gateway và exit thấy vai trò liền kề, trong khi tương quan rộng hơn cần các cửa sổ thống kê dài hơn.

## Chia sẻ tệp ẩn danh GNUnet

**Cơ chế:** GNUnet có thể định tuyến yêu cầu xuất bản/tìm kiếm/tải xuống qua peer và thêm lưu lượng cover tùy mức độ ẩn danh. Tài liệu của GNUnet cảnh báo rằng mức mặc định 1 không yêu cầu lưu lượng cover và phân tích lưu lượng mạnh có thể nhận diện nguồn gốc.<sup>[[10]](#references)</sup>

**Ưu điểm:** chia sẻ phi tập trung, ẩn danh ngay trong ứng dụng; có thể điều chỉnh yêu cầu lưu lượng cover.

**Nhược điểm:** không phải truy cập web ẩn danh thông thường; tốn hiệu năng/lưu trữ; hạn chế về peer và phân tích lưu lượng; tài liệu GNUnet VPN cho biết overlay IP của nó không cung cấp tính ẩn danh tốt.

**Quy trình:** (1) cài bản dựng chính thức được duy trì; (2) cô lập peer kiểm thử; (3) giới hạn băng thông/lưu trữ; (4) xuất bản tệp kiểm thử duy nhất, vô hại với mức ẩn danh đã chọn; (5) truy xuất từ peer khác do bạn sở hữu; (6) ghi nhận lưu lượng cover và độ trễ; (7) tránh tuyên bố thành phần IP VPN cung cấp mức ẩn danh tương đương.

**Phát hiện:** bootstrap peer, lưu lượng overlay, datastore/tiến trình cục bộ và mã định danh tệp; observer diện rộng có thể phân tích lượng lưu lượng so với lưu lượng cover.

## DNS mã hóa, ODoH và ECH

**Cơ chế:** DoH/DoT/DoQ mã hóa kết nối tới resolver; ODoH phân tách địa chỉ client khỏi truy vấn giữa proxy và resolver; ECH mã hóa tên máy chủ/ClientHello TLS bên trong.

**Ưu điểm:** loại bỏ DNS/SNI dạng plaintext khỏi một số observer cục bộ; ODoH phân tách thông tin nguồn/truy vấn.

**Nhược điểm:** không phải đường truy cập ẩn danh IP; resolver/proxy/server vẫn có vai trò; IP đích/thời gian/lưu lượng và endpoint vẫn bị lộ; fallback có thể gây leak.

**Quy trình:** (1) quyết định DNS do OS, ứng dụng hay tunnel quản lý; (2) bật chế độ mã hóa nghiêm ngặt hoặc ODoH được hỗ trợ; (3) kiểm thử bằng domain riêng do bạn sở hữu; (4) capture cục bộ để xác nhận không có truy vấn rõ; (5) làm resolver lỗi và xác minh hành vi mong muốn; (6) với ECH, xác nhận chẩn đoán server cho thấy ClientHello bên trong được chấp nhận.<sup>[[11]](#references)</sup>

**Phát hiện:** log endpoint/resolver để lộ truy vấn; mạng nhận diện endpoint của encrypted resolver và các flow tới đích; trạng thái ECH hiển thị với endpoint/CDN dù bị ẩn trên đường truyền.

## Split-provider privacy relay

**Cơ chế:** sản phẩm như iCloud Private Relay dùng ingress biết client và egress do bên khác vận hành biết đích đến, đồng thời xử lý vùng địa lý ở mức khái quát.

**Ưu điểm:** phân tách thông tin dễ sử dụng; nhanh; tích hợp bảo vệ DNS/web cho lưu lượng được hỗ trợ.

**Nhược điểm:** phạm vi sản phẩm/ứng dụng bị giới hạn; nhà cung cấp nền tảng vẫn nhận diện khách hàng; không ẩn danh toàn hệ thống tùy ý; có rủi ro thông đồng/pháp lý và tương quan thời gian.

**Quy trình:** (1) xác nhận chính xác ứng dụng và loại lưu lượng được hỗ trợ; (2) bật tính năng trong context nền tảng riêng khi phù hợp; (3) chọn cách xử lý vùng; (4) kiểm tra riêng Safari/DNS và ứng dụng không được hỗ trợ; (5) kiểm tra địa chỉ phía đích; (6) thử chuyển mạng/lỗi.<sup>[[12]](#references)</sup>

**Phát hiện:** bên truy cập thấy ingress; đích đến thấy egress; log nền tảng/relay và bản ghi tài khoản bao phủ lớp tương ứng; ứng dụng không được hỗ trợ để lộ đường truy cập thông thường.

## Trình duyệt từ xa, VDI, RDP hoặc jump host của tổ chức

**Cơ chế:** hoạt động duyệt web/thực thi công cụ diễn ra trên hệ thống từ xa; đích đến thấy egress của hệ thống đó trong khi nhà cung cấp workspace thấy kết nối của người vận hành và control plane.

**Ưu điểm:** nhanh; cô lập nội dung rủi ro; egress ổn định, có kiểm soát; trạng thái dùng một lần và khả năng audit tổ chức mạnh.

**Nhược điểm:** nhà cung cấp/admin có thể quan sát phiên/tài khoản; kênh màn hình/clipboard/tệp có thể làm lộ dữ liệu; dấu vân tay trình duyệt từ xa có thể khác biệt; không ẩn danh với chủ sở hữu workspace.

**Quy trình:** (1) tạo một workspace do tổ chức sở hữu cho mỗi engagement; (2) yêu cầu MFA và giới hạn quyền quản trị; (3) tắt hoặc hạn chế clipboard/upload/download; (4) định tuyến qua egress cố định đã được phê duyệt; (5) không dùng IdP/sync cá nhân; (6) chỉ xuất bằng chứng đã được xem xét; (7) hủy workspace và thông tin xác thực theo lịch.

**Phát hiện:** log nhà cung cấp và IdP ánh xạ người dùng tới phiên; đích đến nhóm egress/trình duyệt workspace; bên phòng thủ doanh nghiệp nhận diện giao thức điều khiển từ xa và phiên đám mây bất thường.

## Wi-Fi công cộng hoặc guest

**Cơ chế:** lưu lượng đi ra qua NAT của địa điểm hoặc qua tunnel khởi tạo tại đó.

**Ưu điểm:** tốc độ cao và địa chỉ không phải địa chỉ nhà; không cần hạ tầng riêng.

**Nhược điểm:** bằng chứng liên kết với địa điểm/DHCP/captive portal, camera, giao dịch mua và vị trí; peer/AP độc hại; điều khoản sử dụng; rủi ro vật lý.

**Quy trình:** (1) xin quyền truy cập dành cho khách và xác minh SSID với nhân viên; (2) dùng thiết bị đã vá và có mức độ tin cậy thấp; (3) tắt chia sẻ/tự động kết nối và bật private MAC; (4) hoàn tất portal mà không dùng lại danh tính; (5) bật đường VPN/Tor fail-closed; (6) xác minh lưu lượng được tether; (7) xóa mạng khỏi thiết bị.

**Phát hiện:** địa điểm tương quan AP, MAC, DHCP, portal và thời gian; đích đến thấy địa điểm/tunnel; điều tra viên kết hợp bằng chứng vật lý và thiết bị. Không bao giờ vượt qua kiểm soát truy cập.

## Travel router

**Cơ chế:** router do người vận hành sở hữu kết nối Wi-Fi/Ethernet của địa điểm và cung cấp mạng nội bộ cô lập với chính sách tunnel bắt buộc.

**Ưu điểm:** cô lập workstation; kill switch/DNS tập trung; mạng client nhất quán; bảo vệ endpoint có quyền cao khỏi broadcast cục bộ.

**Nhược điểm:** router trở thành dấu vân tay radio/DHCP ổn định; tăng bề mặt tấn công; captive portal và tethering có thể bỏ qua tunnel.

**Quy trình:** (1) cập nhật firmware được hỗ trợ; (2) đặt thông tin quản trị riêng và tắt WAN admin/WPS/UPnP; (3) cấu hình MAC upstream riêng tư nếu được phép; (4) tạo SSID nội bộ riêng; (5) áp dụng chính sách firewall full-tunnel cho DNS/IPv6; (6) kiểm tra portal, kết nối lại và lỗi tunnel.

**Phát hiện:** địa điểm thấy router kết nối và hình dạng lưu lượng; nhận diện dấu vân tay RF/DHCP cục bộ; nhà cung cấp VPN thấy nguồn tại địa điểm.

## Cellular, SIM trả trước và eSIM

**Cơ chế:** modem dùng truy cập vô tuyến của nhà mạng và thường qua carrier NAT; lớp VPN/Tor có thể thay đổi exit mà đích đến nhìn thấy.

**Ưu điểm:** độc lập với mạng có dây/Wi-Fi cục bộ; di động; tốc độ cao; hữu ích làm backhaul cho drop được ủy quyền.

**Nhược điểm:** nhà mạng biết thuê bao/eSIM, IMSI, IMEI, cell, thời gian và port được gán; luật đăng ký khác nhau; ở cùng địa điểm với điện thoại cá nhân có thể liên kết thiết bị.

**Quy trình:** (1) đăng ký dịch vụ hợp pháp với thông tin bắt buộc chính xác; (2) dùng modem/thiết bị riêng do tổ chức sở hữu; (3) ghi nhận với controller của bài tập; (4) tắt radio/tài khoản không liên quan; (5) thiết lập tunnel được phê duyệt; (6) kiểm tra client tether có thực sự đi qua tunnel hay không; (7) xác minh giả định về nhà cung cấp và lưu trữ trước khi di chuyển.<sup>[[13]](#references)</sup>

**Phát hiện:** bản ghi nhà mạng và vị trí RF; inventory USB/PCI/MDM doanh nghiệp và khảo sát rogue hotspot; thời gian đích đến/tunnel.

## Internet vệ tinh và lạm dụng downlink vệ tinh

**Cơ chế:** dịch vụ thông thường dùng terminal/nhà cung cấp đã đăng ký. Kiểu lạm dụng DVB-S một chiều trước đây cho phép bộ thu nằm trong beam quan sát lưu lượng downlink không mã hóa gửi tới thuê bao hợp pháp, đồng thời dùng đường khác để gửi yêu cầu outbound.

**Ưu điểm:** vùng phủ rộng; chặng cuối độc lập; lạm dụng một chiều trong quá khứ có thể khiến C2 bị gán nhầm với địa lý của thuê bao.

**Nhược điểm:** thiết bị/bản ghi RF của nhà cung cấp; độ trễ và vùng phủ; hệ thống hai chiều hiện đại khác biệt; đường outbound và định tuyến bất đối xứng vẫn là bằng chứng.

**Quy trình:** để truy cập hợp pháp, đăng ký terminal do bạn sở hữu và tunnel lưu lượng khi cần. Để mô phỏng hành vi Turla trong lịch sử, phát lại packet capture một chiều tổng hợp trong lab không có RF và kiểm tra liệu nhà phân tích có phát hiện phản hồi tới host chưa gửi yêu cầu hay không; không chặn lưu lượng vệ tinh trực tiếp.<sup>[[14]](#references)</sup>

**Phát hiện:** telemetry của nhà cung cấp/terminal, định hướng RF, luồng bất khả thi/bất đối xứng, bất nhất RTT/định tuyến và cấu hình malware.

## Residential/mobile proxy hoặc proxyware có sự đồng thuận

**Cơ chế:** backconnect gateway cấp egress broadband di động/dân dụng, có thể cố định hoặc luân phiên. Nguồn cung có thể dựa trên sự đồng thuận, bị đóng gói kèm theo theo cách gây hiểu lầm hoặc mang tính độc hại.

**Ưu điểm:** tốc độ cao; lựa chọn địa lý; ASN dân dụng tránh được một số chặn hosting; pool lớn.

**Nhược điểm:** rủi ro về nguồn gốc/sự đồng thuận và pháp lý; broker thấy khách hàng; exit bị nhiễm làm hại nạn nhân; luân phiên tạo bất thường; tốn kém và thiếu tin cậy.

**Quy trình:** chỉ dùng agent thuộc sở hữu tổ chức, có văn bản mô tả rõ và được đồng thuận để mô phỏng: (1) đăng ký endpoint kiểm thử; (2) lập danh sách chủ sở hữu/IP; (3) cấu hình gateway; (4) luân phiên chế độ cố định/theo từng yêu cầu; (5) chỉ gửi tới target do bạn sở hữu; (6) so sánh log gateway/exit/target; (7) gỡ mọi agent.

**Phát hiện:** di chuyển bất khả thi, browser/tài khoản ổn định dù IP/ASN thay đổi nhanh, giao thức backconnect, dấu vết tiến trình/mạng proxyware và mối liên hệ broker/controller.

## ORB, botnet và relay thiết bị edge bị xâm nhập

**Cơ chế:** router/IoT/server được thuê hoặc bị xâm nhập tạo thành các vai trò access, traversal và exit do một fleet quản trị. Nhiều khách hàng APT có thể dùng chung.

**Ưu điểm:** mượn uy tín/địa lý; exit tồn tại ngắn; mesh multi-hop có khả năng chống chịu; liên kết trực tiếp giữa tác nhân và IP yếu.

**Nhược điểm:** gây hại cho nạn nhân, phạm pháp; có pattern implant/controller và fleet; trung gian có thể bị thu giữ; hiệu năng không ổn định; hồ sơ dịch vụ của người vận hành/khách hàng.

**Quy trình:** không bao giờ xâm nhập thiết bị thật. Dùng [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) tạo mạng entry/transit/target cô lập; (2) kết nối container relay hai card mạng do bạn sở hữu; (3) chỉ chuyển tiếp một test port; (4) gửi yêu cầu lành tính; (5) xác minh target chỉ thấy exit; (6) luân phiên exit; (7) gỡ toàn bộ tài sản được đặt tên.<sup>[[15]](#references)</sup>

**Phát hiện:** theo dõi topology, port/service, mối liên hệ controller, dấu vân tay implant và vòng đời node; tập trung telemetry cấu hình/flow/toàn vẹn của edge; không đồng nhất exit IP với tác nhân.

## CDN redirector, domain fronting và domainless fronting

**Cơ chế:** public edge chỉ chuyển tiếp lưu lượng khớp với một grammar; fronting dùng SNI bên ngoài trông vô hại và HTTP authority bên trong khác, hoặc SNI trống, khi intermediary cho phép.

**Ưu điểm:** che giấu/bảo vệ back-end; edge toàn cầu nhanh; hòa lẫn đích đến với dịch vụ dùng chung; chuyển đổi nhanh.

**Nhược điểm:** CDN thấy toàn bộ định tuyến và tenant; nhiều nhà cung cấp cấm fronting xuyên tenant; dấu vết SNI/Host/process/flow và tài khoản; việc tái sử dụng cấu hình giúp nhóm các chiến dịch lại với nhau.

**Quy trình:** chỉ tái hiện trên reverse proxy do bạn sở hữu bằng [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): tạo certificate/edge cục bộ, định tuyến một Host không khớp tới target do bạn sở hữu, ghi log SNI và Host, gửi yêu cầu thông thường/không khớp, sau đó gỡ container.<sup>[[16]](#references)</sup>

**Phát hiện:** so sánh SNI/ECH/Host/`:authority` tại endpoint hoặc edge kết thúc kết nối; liên kết tiến trình khởi tạo, tenant/origin, grammar yêu cầu và nhịp flow.

## Dynamic DNS, DGA, fast flux và double flux

**Cơ chế:** DDNS cập nhật một tên ổn định; DGA tạo các tên ứng viên thay đổi; fast flux luân phiên địa chỉ dịch vụ với TTL thấp; double flux cũng luân phiên name server.

**Ưu điểm:** chống chịu tốt khi phát hiện; thay thế hạ tầng nhanh; che giấu controller phía sau nhiều node.

**Nhược điểm:** DNS tạo telemetry tập trung; entropy/NXDOMAIN/churn; TTL thấp và pattern ASN rộng; thông tin đăng ký và hạ tầng authoritative vẫn còn.

**Quy trình:** dùng [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): phục vụ zone do bạn sở hữu, trả về địa chỉ RFC 5737 với TTL năm giây, truy vấn lặp lại, thay đổi epoch tổng hợp và xác thực analytics. Không bao giờ trỏ bản ghi kiểm thử tới bên thứ ba.<sup>[[17]](#references)</sup>

**Phát hiện:** số lượng answer/ASN duy nhất trong cửa sổ trượt, TTL trung vị, địa lý, churn authoritative, nhóm NXDOMAIN/đặc điểm từ vựng/thời gian của DGA và hoạt động tiếp theo của tiến trình; dùng context để loại trừ CDN hợp pháp.

## Dịch vụ web hợp pháp, dead-drop resolver và tasking một chiều

**Cơ chế:** bài đăng, repository, tài liệu, object hoặc feed công khai chứa endpoint hiện tại hoặc task đã mã hóa. Client có thể trả kết quả qua một kênh khác.

**Ưu điểm:** dịch vụ có uy tín cao và được cho phép; TLS; luân phiên endpoint mà không đổi binary; tasking bất đối xứng gây khó khăn cho việc tương quan flow đơn giản.

**Nhược điểm:** mã định danh object/tài khoản/API ổn định; bản ghi của nhà cung cấp; chuỗi giải mã endpoint/hoạt động tiếp theo; nội dung có thể bị thu giữ hoặc thay đổi.

**Quy trình:** dùng [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): host pointer đã mã hóa trên một container do bạn sở hữu, tải/giải mã từ client tồn tại ngắn hạn, kết nối tới dịch vụ thứ hai do bạn sở hữu, giữ cả hai log rồi gỡ.

**Phát hiện:** tương quan chuỗi tiến trình bất thường → đọc object ổn định → giải mã → đích mới; hash/lưu giữ nội dung và giữ toàn bộ path object, không chỉ domain.

## Serverless, container tồn tại ngắn hạn và egress cloud-NAT

**Cơ chế:** function/job chạy ngắn hạn phía sau NAT hoặc front của nhà cung cấp; dịch vụ logic vẫn ổn định trong khi instance và địa chỉ luân phiên.

**Ưu điểm:** triển khai/hủy nhanh; egress dùng chung quy mô nhà cung cấp; ít đĩa cục bộ; định tuyến vùng linh hoạt.

**Nhược điểm:** tenant, role, API, image, secret, invocation, billing và log front-to-origin tồn tại lâu; dấu vân tay cold-start/nền tảng; chính sách nhà cung cấp.

**Quy trình:** (1) dùng tenant bài tập do tổ chức sở hữu; (2) triển khai function lành tính chỉ gửi yêu cầu tới endpoint do bạn sở hữu; (3) ghi lại project/role/image/config; (4) gọi qua nhiều instance; (5) so sánh IP target với audit/request ID; (6) kiểm tra thời hạn lưu log; (7) xóa function, role và secret.

**Phát hiện:** log audit/invocation đám mây, tạo role bất thường, egress dùng chung cùng grammar yêu cầu ổn định, việc tái sử dụng image/layer và secret, tương quan front-origin.

## Drop tại chỗ được ủy quyền

**Cơ chế:** máy tính nhỏ đã được kiểm kê dùng mạng có dây/Wi-Fi cục bộ và rendezvous outbound qua VPN/cellular, tạo nguồn cục bộ.

**Ưu điểm:** kiểm thử thực tế nguồn nội bộ; tốc độ cao; có thể kiểm tra NAC, kiểm kê vật lý và kiểm soát egress.

**Nhược điểm:** bị phát hiện/đánh cắp về mặt vật lý; bằng chứng serial/MAC/USB/DHCP/PoE/RF và camera; mất thiết bị có thể làm lộ thông tin xác thực.

**Quy trình:** làm theo [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) có văn bản cho phép chính xác vị trí lắp đặt; (2) ghi serial, MAC, ảnh, vị trí và thời gian thu hồi; (3) dùng image tối giản có chữ ký và thông tin xác thực mutual tồn tại ngắn hạn; (4) chỉ giới hạn destination/capability outbound; (5) bổ sung quarantine phía server và giới hạn băng thông; (6) kiểm tra SOC có nhìn thấy và quy trình xử lý khi mất; (7) thu hồi, giữ bằng chứng cần thiết rồi sanitize theo chính sách vòng đời đã thống nhất. Không bao giờ giấu thiết bị tại địa điểm không đồng thuận.

**Phát hiện:** NAC/802.1X, switchport/PoE/DHCP, kiểm kê USB, khảo sát RF, tunnel định kỳ, thiết bị nhận/camera và kiểm tra vật lý.

## Pivot không dây nearest-neighbor

**Cơ chế:** tác nhân kiểm soát host trong tầm vô tuyến của mục tiêu, rồi dùng thông tin xác thực Wi-Fi của mục tiêu để vượt ranh giới từ xa. APT28 từng dùng cách này qua các tổ chức lân cận bị xâm nhập.<sup>[[18]](#references)</sup>

**Ưu điểm:** người vận hành không cần di chuyển; mục tiêu thấy nguồn radio cục bộ; vượt qua các kiểm soát chỉ áp dụng cho truy cập Internet.

**Nhược điểm:** cần host hai radio ở gần, bị xâm nhập hoặc thuộc quyền sở hữu và có quyền truy cập hợp lệ; có bằng chứng từ RADIUS/NAC/AP và endpoint lân cận; bất thường về tín hiệu/thiết bị.

**Quy trình:** chỉ tái hiện bằng [Lab 4 với hai AP do bạn sở hữu](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): kết nối pivot do bạn sở hữu với SSID lab lân cận và mục tiêu, chỉ chuyển tiếp một dịch vụ, thu thập log của cả hai AP/pivot, sau đó bật EAP-TLS/device posture và xác nhận lần thử thứ hai thất bại.

**Phát hiện:** tương quan danh tính RADIUS, certificate/posture được quản lý, thiết bị xuất hiện lần đầu, edge/tín hiệu AP, đăng nhập đồng thời và sự hiện diện vật lý; tìm endpoint gần đó có radio đồng thời, chuyển tiếp và tunnel.

## Community mesh, delay-tolerant và store-and-forward offline

**Cơ chế:** lưu lượng đi qua peer cục bộ, gateway bất đồng bộ, thiết bị lưu trữ tháo rời hoặc queue theo lịch thay vì một phiên Internet tương tác.

**Ưu điểm:** hoạt động khi có gián đoạn/kiểm duyệt; giao nhận trễ/theo lô làm suy yếu tương quan thời gian đơn giản; không cần chặng cuối tập trung để liên lạc cục bộ.

**Nhược điểm:** độ trễ cao; nhóm ẩn danh nhỏ; metadata về lưu trữ/di chuyển vật lý; peer độc hại; dữ liệu cuối cùng vẫn tới gateway có thể quan sát.

**Quy trình:** (1) xây mesh ba node hoặc file queue cô lập do bạn sở hữu; (2) mã hóa/xác thực nội dung đầu-cuối; (3) gỡ route Internet trực tiếp khỏi nguồn; (4) chuyển tiếp tệp lành tính sau một khoảng trễ có kiểm soát; (5) xác minh chỉ gateway liên hệ với đích đến do bạn sở hữu; (6) so sánh thông tin lưu trữ/thời gian; (7) giữ bằng chứng cần thiết, sau đó sanitize media/queue tạm thời khi kết thúc đã được phê duyệt.

**Phát hiện:** hoạt động tệp/tiến trình trên endpoint, liên kết radio giữa peer, audit media tháo rời, tính định kỳ của queue/gateway và mã định danh nội dung. Phân tích flow tương tác được thay bằng cửa sổ tương quan dài hơn.

## TURN relay và WebRTC buộc dùng relay

**Cơ chế:** Traversal Using Relays around NAT (TURN) cấp địa chỉ relay công khai và truyền lưu lượng UDP, TCP hoặc TLS giữa client và peer. Chính sách ICE có thể buộc dùng relay thay vì để lộ candidate trực tiếp. TURN giải quyết khả năng kết nối, không phải tính ẩn danh nói chung: server xác thực client và quan sát allocation, peer, thời gian và lưu lượng.<sup>[[19]](#references)</sup>

**Ưu điểm:** được triển khai rộng rãi; xử lý NAT hạn chế; hỗ trợ WebRTC di động; peer không nhận được địa chỉ transport trực tiếp của client nếu chính sách chỉ dùng relay được áp dụng đúng.

**Nhược điểm:** bên vận hành TURN thấy cả hai phía liền kề; danh tính ứng dụng, dấu vân tay media và signaling vẫn còn; chỉ dùng relay tốn băng thông/độ trễ; cấu hình sai vẫn có thể thu thập host candidate hoặc server-reflexive candidate.

**Quy trình:** (1) triển khai dịch vụ TURN do tổ chức sở hữu với TLS và thông tin xác thực tồn tại ngắn hạn; (2) giới hạn realm, peer, port, quota và thời hạn; (3) đặt ứng dụng kiểm thử dùng chính sách ICE chỉ dùng relay; (4) gọi peer do bạn sở hữu; (5) kiểm tra `getStats()` và packet capture để xác nhận chỉ relay candidate truyền media; (6) làm relay lỗi và xác nhận không có fallback trực tiếp; (7) giữ log allocation trong engagement.

**Phát hiện:** signaling, tiến trình trình duyệt và TURN allocation liên kết phiên với relay; mạng quan sát các flow kéo dài tới port TURN hoặc TLS endpoint; peer thấy relay được cấp. **Node bị thu giữ:** trạng thái ứng dụng và thông tin xác thực TURN tạm thời có thể làm lộ realm và dịch vụ rendezvous. Giảm phơi lộ bằng thông tin xác thực tồn tại ngắn hạn theo từng thiết bị và chỉ giữ xác thực của người vận hành tại controller.

## Outbound-only rendezvous hoặc reverse overlay

**Cơ chế:** node phía sau NAT khởi tạo kết nối đã xác thực tới broker do tổ chức kiểm soát. Người vận hành xác thực riêng với broker, broker cấp quyền cho kênh quản trị hẹp; không cần chuyển tiếp port inbound hay route trực tiếp từ người vận hành tới node.

**Ưu điểm:** ổn định sau NAT và qua chặng cuối captive; thu hồi và audit tập trung; địa chỉ field node thay đổi không yêu cầu người vận hành tìm lại; tách biệt danh tính người vận hành khỏi thông tin xác thực của node.

**Nhược điểm:** broker trở thành điểm tương quan có giá trị cao; keepalive định kỳ dễ nhận diện; tunnel rộng có thể trở thành pivot không an toàn; broker ngừng hoạt động sẽ chấm dứt quản trị.

**Quy trình:** làm theo [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): cấp một danh tính thiết bị có phạm vi giới hạn, chỉ cho phép broker do bạn sở hữu và dịch vụ quản trị được phê duyệt, dùng keepalive đã xác thực, áp dụng định tuyến fail-closed, kiểm thử thay đổi địa chỉ và khôi phục sau reboot, rồi thu hồi danh tính trong diễn tập mất thiết bị. WireGuard mô tả persistent keepalive 25 giây là khoảng NAT hữu ích trong nhiều trường hợp khi thực sự cần.<sup>[[20]](#references)</sup>

**Phát hiện:** log broker và identity provider ánh xạ cả hai phía; mạng truy cập thấy đích mã hóa/nhịp lặp lại; inventory endpoint nhận diện agent overlay. **Node bị thu giữ:** giả định khóa thiết bị, tên broker, địa chỉ tunnel và dữ liệu task được cache đã bị lộ. Node không được chứa khóa riêng của người vận hành, tài khoản cá nhân hoặc token controller có thể tái sử dụng.

## Pull mailbox, message queue hoặc rendezvous qua object-store

**Cơ chế:** workload thực địa polling mailbox đã xác thực để nhận job được ký và phê duyệt trước, rồi đăng kết quả có giới hạn. Người vận hành ghi vào queue qua control plane riêng; không có socket tương tác giữa hai bên.

**Ưu điểm:** chịu được kết nối gián đoạn; tách thời gian và địa chỉ; quota/schema giới hạn được capability; audit và thu hồi tập trung dễ dàng.

**Nhược điểm:** nhịp polling và tên object/queue ổn định tạo dấu vân tay hệ thống; log nhà cung cấp liên kết producer và consumer; điều khiển có độ trễ; dữ liệu queue bị thu giữ có thể làm lộ bài tập.

**Quy trình:** (1) tạo một queue cho mỗi engagement và một danh tính thiết bị; (2) xác định schema đã ký cho job lành tính, có phạm vi rõ ràng; (3) đặt TTL thông điệp, kích thước kết quả tối đa và tốc độ; (4) chỉ cho node đọc queue của nó và chỉ ghi vào prefix kết quả của nó; (5) kiểm tra tích lũy khi offline, gửi trùng và thu hồi; (6) tập trung log truy cập bất biến; (7) xóa queue sau khi đáp ứng yêu cầu lưu trữ.

**Phát hiện:** tìm API call định kỳ từ tiến trình bất thường, path bucket/object/queue ổn định, user-agent hoặc hành vi TLS giống nhau và chuỗi tải dữ liệu rồi mở kết nối mới. **Node bị thu giữ:** cache cục bộ có thể làm lộ job đang chờ và tên object; giữ cache được mã hóa, có giới hạn và dùng một lần, đồng thời bảo toàn log controller có thẩm quyền.

## Failover dual-uplink và di chuyển kết nối

**Cơ chế:** field node được phê duyệt có hai uplink độc lập—chẳng hạn Ethernet/Wi-Fi tại địa điểm và cellular của tổ chức—và duy trì phiên điều khiển qua overlay hoặc message broker khi route thay đổi. Đây là kỹ thuật tăng tính sẵn sàng, không phải tính ẩn danh.

**Ưu điểm:** chịu được lỗi của một nhà cung cấp, AP hoặc captive portal; hỗ trợ bảo trì theo kế hoạch; cho phép nhanh chóng cô lập đường truy cập đáng ngờ.

**Nhược điểm:** hai nhà cung cấp tạo hai bộ hồ sơ về vị trí/tài khoản; sử dụng đồng thời khiến việc tương quan dễ hơn; rò rỉ route/DNS khi failover; bằng chứng ở cùng vị trí với cellular vẫn còn.

**Quy trình:** (1) đăng ký cả hai giao diện và nhà cung cấp thuộc sở hữu tổ chức; (2) gán thứ tự route và health check xác định tới endpoint do bạn sở hữu; (3) gắn DNS và quản trị với overlay; (4) ngăn đường phụ nhận lưu lượng inbound; (5) ngắt từng đường và xác minh khôi phục phiên, chính sách nguồn và không truy cập đích trực tiếp; (6) cảnh báo khi đường thay đổi ngoài kế hoạch; (7) ghi rõ giới hạn sử dụng dữ liệu và roaming.

**Phát hiện:** tương quan cùng device certificate, grammar yêu cầu và thời gian qua nhiều ASN; inventory cục bộ thấy cả hai radio; nhà mạng/địa điểm giữ bản ghi riêng. **Node bị thu giữ:** có thể thấy cả mã định danh SIM/thiết bị và SSID đã biết; dùng tài sản tổ chức, không đặt node cùng vị trí hoặc ghép nối với thiết bị cá nhân.

## Private APN của tổ chức hoặc cellular tunnel được quản lý

**Cơ chế:** private APN của nhà mạng đưa SIM đã đăng ký vào miền định tuyến riêng hoặc tunnel lưu lượng tới enterprise gateway. Cơ chế này tách thiết bị khỏi Internet di động công cộng nhưng không che giấu thiết bị với nhà mạng hoặc tổ chức ký hợp đồng.

**Ưu điểm:** địa chỉ riêng ổn định; chính sách lưu lượng và đăng ký cấp nhà mạng; tránh để lộ truy cập inbound công khai; hữu ích cho thiết bị từ xa được ủy quyền.

**Nhược điểm:** có khả năng quy kết mạnh từ thuê bao, IMSI/IMEI, cell và billing; thời gian mua sắm và chi phí; sự cố nhà mạng/gateway; không ẩn danh với bên vận hành.

**Quy trình:** (1) ký hợp đồng APN dưới tên tổ chức đánh giá; (2) chỉ cho phép SIM đã đăng ký và prefix gateway; (3) bổ sung mutual authentication ở tầng ứng dụng; (4) chỉ cho route APN tới rendezvous và dịch vụ cập nhật; (5) kiểm tra tháo SIM, roaming, breakout ra Internet công cộng và thu hồi; (6) giám sát bản ghi nhà mạng và gateway; (7) hủy hoặc quarantine mọi SIM khi kết thúc.

**Phát hiện:** inventory nhà mạng và telemetry cell, flow của APN gateway, sai lệch SIM/IMEI và hồ sơ tài sản doanh nghiệp. **Node bị thu giữ:** SIM và modem xác định được hợp đồng ngay cả khi storage đã mã hóa; vì vậy, khả năng chống chịu khi bị thu giữ nghĩa là đình chỉ nhanh và cấp quyền hẹp, không phải khả năng chối bỏ.

## Cầu nối vô tuyến point-to-point tầm xa

**Cơ chế:** Wi-Fi định hướng hoặc radio point-to-point được cấp phép/không cần cấp phép kết nối hai địa điểm được chủ sở hữu cho phép, với egress Internet tại địa điểm từ xa. Cơ chế này có thể thay đổi vị trí IP hiển thị mà không dùng proxy thương mại.

**Ưu điểm:** thông lượng cao; độc lập với nhà mạng có dây trung gian; kiểm soát được RF và định tuyến; hữu ích để kiểm thử phân đoạn và giám sát địa điểm từ xa.

**Nhược điểm:** yêu cầu tầm nhìn thẳng, tuân thủ phổ tần, sự cho phép của chủ nhà và quy định; phát xạ RF và phần cứng dễ nhận diện; cả hai endpoint đều là bằng chứng vật lý; thời tiết/nguồn điện/căn chỉnh ảnh hưởng độ ổn định.

**Quy trình:** (1) có văn bản cho phép ở cả hai địa điểm và xác minh quy định phổ tần/công suất; (2) khảo sát đường truyền mà không phát ngoài tham số được phê duyệt; (3) dùng mã hóa đã xác thực và VLAN quản trị; (4) chỉ giới hạn cầu nối tới rendezvous hoặc subnet kiểm thử do bạn sở hữu; (5) kiểm tra failover, căn chỉnh, khôi phục nguồn và kiểm soát RF; (6) dán nhãn/kiểm kê cả hai radio; (7) tháo chúng và xác minh đã reset cấu hình sau bài tập.

**Phát hiện:** khảo sát RF, phân tích phổ, kiểm tra mái nhà/địa điểm, MAC/OUI của bridge, lưu lượng quản trị và log egress tại địa điểm từ xa. **Node bị thu giữ:** cấu hình làm lộ peer và miền quản trị; dùng thông tin xác thực riêng cho bài tập, không dùng tài khoản quản trị cá nhân và thu hồi khóa peer nhanh chóng.

## Cooperative hoặc community exit có sự đồng thuận

**Cơ chế:** tình nguyện viên hoặc tổ chức đối tác chủ động vận hành relay theo chính sách được công bố. Lưu lượng đi ra từ một pool cộng đồng dùng chung trong khi lớp điều phối xử lý lạm dụng và thu hồi.

**Ưu điểm:** đa dạng mạng ngoài đám mây; có sự đồng thuận rõ ràng an toàn hơn proxyware; quản trị chung có thể phân tán niềm tin; hữu ích cho nghiên cứu và nghiên cứu khả năng chống kiểm duyệt.

**Nhược điểm:** pool nhỏ và hồ sơ thành viên làm giảm tính ẩn danh; người vận hành exit nhận khiếu nại và thấy metadata lưu lượng; thành viên độc hại, thời gian hoạt động không ổn định và khác biệt pháp lý.

**Quy trình:** (1) công bố chính sách sử dụng được chấp nhận và logging; (2) lấy sự đồng thuận rõ ràng từ từng bên vận hành; (3) cấp danh tính relay riêng và giới hạn đích/tốc độ; (4) cung cấp xử lý lạm dụng và cơ chế thu hồi bằng một thao tác; (5) trong kiểm thử, chỉ gửi lưu lượng được phép tới endpoint do bạn sở hữu; (6) đo churn và mức phơi lộ do tương quan; (7) gỡ relay đúng quy trình khi hết thời hạn đồng thuận.

**Phát hiện:** bản ghi membership/control plane, relay certificate, dấu vân tay phần mềm dùng chung và hành vi exit giúp nhận diện pool. **Node bị thu giữ:** cấu hình relay có thể nhận diện cooperative nhưng không nên chứa danh tính client; lưu ánh xạ client-to-session tại controller được ủy quyền, có kiểm soát truy cập.

## IPv6 temporary address và luân phiên prefix

**Cơ chế:** IPv6 privacy extension tạo interface identifier tạm thời để không tái sử dụng một địa chỉ ổn định cho mọi kết nối outbound. Việc nhà cung cấp đổi prefix có thể tạo thêm luân phiên, nhưng delegated prefix, hồ sơ thuê bao và dấu vân tay tầng trên vẫn còn.<sup>[[21]](#references)</sup>

**Ưu điểm:** giảm theo dõi thụ động dài hạn bằng interface identifier ổn định; có sẵn trong các hệ điều hành phổ biến; không cần overhead relay.

**Nhược điểm:** không ẩn danh nguồn; ISP và mạng cục bộ vẫn biết prefix/thiết bị; DNS, tài khoản và trạng thái trình duyệt liên kết các phiên; địa chỉ thay đổi gây khó khăn cho allowlist và logging.

**Quy trình:** (1) kiểm tra địa chỉ ổn định và tạm thời hiện tại trên client do bạn sở hữu; (2) bật mặc định địa chỉ riêng tư được OS hỗ trợ thay vì giả mạo bằng công cụ bên thứ ba; (3) gửi yêu cầu lặp lại tới endpoint IPv6 do bạn sở hữu qua nhiều vòng đời địa chỉ; (4) xác nhận dịch vụ inbound chỉ bind vào địa chỉ ổn định dự định dùng; (5) lưu log DHCPv6/RA/neighbor và endpoint có thời gian chính xác; (6) kiểm tra hành vi VPN/firewall cho mọi địa chỉ IPv6.

**Phát hiện:** tương quan delegated prefix, danh tính layer 2, neighbor discovery, tài khoản và telemetry endpoint thay vì xem một địa chỉ là một thiết bị. **Node bị thu giữ:** profile mạng và interface identifier vẫn còn; dùng địa chỉ tạm thời ngăn một định danh thụ động, không ngăn quy kết pháp chứng.

## Tor pluggable transport: Snowflake, WebTunnel, obfs4 và meek

**Cơ chế:** pluggable transport thay đổi cách kết nối Tor đầu tiên xuất hiện hoặc cách kết nối tới bridge. Snowflake dùng proxy WebRTC tình nguyện tồn tại ngắn hạn, WebTunnel trông giống HTTPS thông thường, obfs4 chống nhận diện giao thức đơn giản và dò quét chủ động, còn meek chuyển tiếp qua hạ tầng web được hỗ trợ. Đây là transport vượt kiểm duyệt để vào Tor, không phải lớp ẩn danh đầu-cuối bổ sung.<sup>[[22]](#references)</sup>

**Ưu điểm:** hữu ích khi Tor trực tiếp hoặc relay đã biết bị chặn; Snowflake tránh địa chỉ bridge công khai ổn định; tích hợp trong client Tor được duy trì; đích đến vẫn nhận các thuộc tính thông thường của Tor.

**Nhược điểm:** hiệu năng thấp hơn hoặc thay đổi; broker/front/bridge và mạng cục bộ quan sát metadata khác nhau; vẫn có thể nhận diện dấu vân tay transport và chặn; proxy tình nguyện không thay thế Tor và không nên được tin cậy với plaintext ứng dụng.

**Quy trình:** (1) cài và xác minh Tor Browser chính thức hoặc client Tor được hỗ trợ; (2) chọn transport tích hợp trong Connection/Bridges; (3) chỉ kết nối tới trang chẩn đoán do bạn sở hữu; (4) xác nhận trang thấy Tor exit chứ không phải peer Snowflake/WebTunnel; (5) so sánh bootstrap và hiệu năng; (6) làm transport lỗi và xác nhận client không âm thầm kết nối trực tiếp; (7) sau kiểm thử, quay lại cấu hình chuẩn được hỗ trợ.

**Phát hiện:** bên kiểm duyệt có thể kết hợp allowlist đích đến, hành vi TLS/WebRTC, phát hiện broker và phân tích flow; endpoint cho thấy Tor và cấu hình transport. **OPSEC chống chịu khi bị thu giữ:** dùng client chuẩn, không bao giờ chép trạng thái trình duyệt cá nhân vào đó và giả định lịch sử bridge/broker có thể khôi phục. **Giám sát:** theo dõi log bootstrap Tor, nỗ lực kết nối/DNS trực tiếp bất ngờ và quan sát trang do bạn sở hữu từ phía controller; transport lỗi không chứng minh đã bị phát hiện.

## Refraction networking hoặc decoy routing

**Cơ chế:** nhà vận hành mạng hợp tác phát hiện tín hiệu bí mật trong lưu lượng có vẻ gửi tới decoy được cho phép rồi chuyển hướng flow tới proxy vượt kiểm duyệt. Cần triển khai hạ tầng trên đường truyền; client không thể tự tạo cơ chế này chỉ bằng cách chọn một website vô hại.<sup>[[23]](#references)</sup>

**Ưu điểm:** kiểm duyệt có thể khó chặn đích đến hiển thị mà không gây ảnh hưởng ngoài ý muốn; không cần phân phối địa chỉ bridge công khai; mô hình nghiên cứu hữu ích cho cơ chế vượt kiểm duyệt có hỗ trợ trên đường truyền.

**Nhược điểm:** cần ISP/transit tham gia chuyên biệt; khả năng triển khai và hiệu năng phụ thuộc định tuyến; flow client-to-decoy và hoạt động phía proxy vẫn còn; observer toàn cục hoặc có hợp tác có thể tương quan thời gian.

**Quy trình:** không phát tín hiệu qua mạng của bên không liên quan. Tái hiện kiến trúc trong lab cô lập: (1) tạo namespace client, router, decoy và proxy do bạn sở hữu; (2) dùng yêu cầu kiểm thử có gắn tag lành tính; (3) để router do bạn sở hữu chỉ chuyển hướng tag đó tới proxy; (4) ghi log tuple trước/sau định tuyến và request ID; (5) so sánh flow thông thường với flow có tín hiệu; (6) kiểm tra false positive và gỡ cấu hình; (7) xóa route lab.

**Phát hiện:** nhà vận hành mạng được ủy quyền có thể kiểm tra sai lệch định tuyến, hành vi client hello/tag bất thường và khác biệt giữa flow decoy với back-end. **OPSEC chống chịu khi bị thu giữ:** client nghiên cứu chỉ nên giữ khóa kiểm thử và địa chỉ tài liệu. **Giám sát:** so sánh quyết định của lab-router có chữ ký với yêu cầu đến proxy; không thăm dò nhà cung cấp transit production để xác định họ có phát hiện tín hiệu hay không.

## Content-addressed gateway hoặc truy xuất peer có cache

**Cơ chế:** HTTP gateway truy xuất content identifier (CID) của IPFS, có thể từ cache hoặc peer, rồi trả nội dung có thể xác minh cho client. Nhà phát hành ban đầu có thể thấy gateway hoặc peer khác thay vì người đọc cuối; gateway thấy IP người đọc và CID được yêu cầu. Truy xuất ngang hàng nguyên bản làm lộ client với peer và bên tham gia DHT/định tuyến.<sup>[[24]](#references)</sup>

**Ưu điểm:** cache có thể tách nhà phát hành khỏi người đọc; nội dung bất biến có thể xác minh bằng hash; dữ liệu sao chép vẫn tồn tại khi một host ngừng hoạt động; HTTP client không cần stack peer nguyên bản.

**Nhược điểm:** CID công khai và log gateway làm lộ mối quan tâm; thời điểm truy xuất lần đầu có thể liên kết nhà phát hành/người đọc; nội dung web độc hại và nguy cơ same-origin từ path-style; gateway công khai hoạt động theo nỗ lực tốt nhất và cấm lạm dụng.

**Quy trình:** (1) xuất bản tệp kiểm thử vô hại lên private IPFS swarm hoặc gateway do bạn sở hữu; (2) ghi CID; (3) truy xuất qua HTTP gateway riêng do bạn sở hữu, dùng cô lập subdomain; (4) xác minh byte theo CID; (5) lặp lại sau khi cache; (6) so sánh log publisher, peer và gateway; (7) unpin và xóa nội dung kiểm thử khi hết thời hạn lưu giữ.

**Phát hiện:** gateway ghi log nguồn/CID; kết nối DHT và peer làm lộ quá trình truy xuất; lịch sử endpoint và hash tệp nhận diện nội dung. **OPSEC chống chịu khi bị thu giữ:** không lưu khóa xuất bản riêng tư trên field client chỉ đọc và mã hóa nội dung nhạy cảm trước khi content-addressing. **Giám sát:** cảnh báo pin bất ngờ, thay đổi peer-set, yêu cầu CID ngoài allowlist hoặc thông báo lạm dụng từ gateway.

## Dịch vụ private information retrieval

**Cơ chế:** Private Information Retrieval (PIR) cho phép client truy xuất một bản ghi từ cơ sở dữ liệu mà máy chủ không biết chỉ mục được chọn, theo mô hình đe dọa một hoặc nhiều máy chủ đã nêu. PIR bảo vệ lựa chọn truy vấn cho tập dữ liệu có giới hạn; đây không phải truy cập web tổng quát hay ẩn danh IP.<sup>[[25]](#references)</sup>

**Ưu điểm:** quyền riêng tư truy vấn chuyên biệt cho ứng dụng mạnh; mô hình rò rỉ có thể đo lường; hữu ích cho thư mục khóa, blocklist hoặc cơ sở dữ liệu công khai nhỏ; giảm nhu cầu tiết lộ chính xác từ khóa tra cứu.

**Nhược điểm:** overhead tính toán/băng thông; máy chủ vẫn biết thời gian/IP kết nối nếu không kết hợp relay; phiên bản tập dữ liệu, kích thước phản hồi và trạng thái ứng dụng có thể phân biệt người dùng; mức độ hoàn thiện triển khai khác nhau.

**Quy trình:** (1) triển khai implementation PIR đã được audit trên cơ sở dữ liệu tổng hợp do bạn sở hữu; (2) công bố phiên bản tập dữ liệu và tham số; (3) truy xuất một số chỉ mục với kích thước yêu cầu giống nhau; (4) xác minh tính đúng đắn cục bộ; (5) so sánh log máy chủ và xác nhận chỉ mục không xuất hiện; (6) kiểm tra phản hồi độc hại/bị cắt và sai phiên bản; (7) ghi rõ giả định quyền riêng tư thay vì gọi đây là duyệt web ẩn danh.

**Phát hiện:** mạng thấy việc sử dụng dịch vụ và lưu lượng; telemetry endpoint làm lộ client và việc sử dụng bản ghi cuối; máy chủ bị xâm nhập có thể thao túng tập dữ liệu hoặc thời gian. **OPSEC chống chịu khi bị thu giữ:** chỉ giữ tham số cơ sở dữ liệu công khai và cache có giới hạn trên client. **Giám sát:** xác thực root tập dữ liệu đã ký, hình dạng yêu cầu cố định, thay đổi tỷ lệ lỗi và việc luân chuyển server key.

## Fetcher phía server, preview hoặc dịch vụ render có giới hạn

**Cơ chế:** dịch vụ từ xa fetch hoặc render URL rồi trả screenshot, metadata hoặc nội dung đã làm sạch. Đích đến thấy địa chỉ fetcher; dịch vụ thấy người yêu cầu, URL và kết quả. Lạm dụng link-preview bot, security scanner hoặc dịch vụ fetch URL của bên thứ ba không phải là sử dụng proxy được ủy quyền.

**Ưu điểm:** cô lập nội dung chủ động khỏi workstation; đích đến nhận dấu vân tay fetcher có kiểm soát; có thể áp dụng giới hạn loại tệp, kích thước, đích đến và render; môi trường thực thi dùng một lần.

**Nhược điểm:** dịch vụ biết toàn bộ yêu cầu; có bản ghi tài khoản/API/billing; rủi ro SSRF và rò rỉ dữ liệu; script, xác thực và website tương tác có thể không hoạt động; URL riêng có thể liên kết người yêu cầu với lượt fetch.

**Quy trình:** (1) triển khai fetcher do tổ chức sở hữu với allowlist nghiêm ngặt chỉ gồm domain kiểm thử của bạn; (2) chặn địa chỉ private, link-local, metadata và redirect tới địa chỉ không được phê duyệt; (3) giới hạn method, redirect, byte và thời gian render; (4) loại bỏ thông tin xác thực/cookie; (5) gửi URL do bạn sở hữu; (6) so sánh log người yêu cầu, fetcher và target; (7) hủy instance render và lưu audit tập trung theo chính sách.

**Phát hiện:** target thấy ASN/dấu vân tay dịch vụ; log nhà cung cấp/controller ánh xạ người yêu cầu tới URL; tiến trình/API call trên endpoint cho thấy việc gửi yêu cầu. **OPSEC chống chịu khi bị thu giữ:** dùng một project token tồn tại ngắn hạn, không có quyền truy cập đích đến tùy ý. **Giám sát:** cảnh báo từ chối allowlist, vi phạm redirect, fetch không có controller job ID và thông báo lạm dụng từ nhà cung cấp.

## Anycast rendezvous pool

**Cơ chế:** nhiều node do tổ chức kiểm soát quảng bá hoặc đứng trước một địa chỉ dịch vụ ổn định; định tuyến chọn instance gần nhất. Anycast tăng tính sẵn sàng và che giấu back-end riêng lẻ với client, nhưng người vận hành vẫn kiểm soát mọi instance và địa chỉ dịch vụ vẫn ổn định.<sup>[[26]](#references)</sup>

**Ưu điểm:** ingress vùng có khả năng chống chịu; không cần cấu hình lại field khi một instance lỗi; phân phối DDoS/tải; chính sách tập trung có thể chuyển phiên giữa các node đã biết.

**Nhược điểm:** hồ sơ BGP/CDN và nhà cung cấp nhận diện tổ chức; thay đổi đường đi có thể làm hỏng phiên có trạng thái; monitoring khác nhau theo vị trí client; địa chỉ ổn định duy nhất dễ bị chặn hoặc nhóm theo uy tín.

**Quy trình:** dùng project của tổ chức được nhà cung cấp hỗ trợ hoặc lab định tuyến cô lập: (1) triển khai hai health endpoint đã xác thực giống nhau; (2) công khai một địa chỉ dịch vụ có tài liệu; (3) giữ trạng thái phiên tại broker thay vì edge; (4) rút một node và xác minh kết nối lại; (5) kiểm tra tính nhất quán certificate, chính sách và log; (6) cảnh báo origin/vùng không được ủy quyền; (7) gỡ quảng bá và thông tin xác thực khi kết thúc.

**Phát hiện:** BGP/RPKI/lịch sử, tenant nhà cung cấp, certificate và hành vi dịch vụ giống nhau giúp nhận diện pool. **OPSEC chống chịu khi bị thu giữ:** edge chỉ giữ danh tính dịch vụ vùng, không giữ khóa đăng ký của người vận hành hoặc fleet. **Giám sát:** thăm dò mọi vùng từ monitor được ủy quyền, so sánh route origin và configuration digest, xem origin bất ngờ là sự cố.

## Duy trì kết nối QUIC migration và Multipath TCP

**Cơ chế:** connection ID của QUIC có thể duy trì phiên client qua NAT rebinding hoặc thay đổi địa chỉ; Multipath TCP có thể truyền cùng một byte stream đáng tin cậy qua nhiều subflow. Chúng tăng tính liên tục khi chuyển giữa Wi-Fi/cellular nhưng làm lộ các đường cũ và mới với cùng peer, đồng thời có thể khiến tương quan giữa các đường dễ hơn.<sup>[[27]](#references)</sup>

**Ưu điểm:** khôi phục nhanh hơn khi uplink thay đổi; phiên ứng dụng không cần khởi động lại; MPTCP có thể kết hợp khả năng chống chịu và thông lượng; hữu ích cho field node được phê duyệt.

**Nhược điểm:** không ẩn danh; peer thấy quá trình di chuyển/subflow; connection identifier và lưu lượng đồng thời liên kết các đường; hỗ trợ của middlebox/nhà mạng khác nhau; hồ sơ từ nhiều nhà cung cấp làm tăng phơi lộ.

**Quy trình:** (1) chỉ bật transport được hỗ trợ giữa field client do bạn sở hữu và rendezvous; (2) xác thực ứng dụng độc lập với IP; (3) bắt đầu truyền dữ liệu có giới hạn qua Wi-Fi được phê duyệt; (4) chuyển sang cellular của tổ chức; (5) xác nhận kiểm tra đường đi, tính toàn vẹn dữ liệu và không fallback trực tiếp/dạng clear; (6) kiểm tra idle timeout và chuyển lại; (7) giữ bản ghi broker về mọi lần chuyển đường.

**Phát hiện:** peer trực tiếp thấy địa chỉ thay đổi hoặc MPTCP subflow; nhà cung cấp truy cập thấy phần của họ; connection ID, danh tính TLS và thời gian liên kết cả hai. **OPSEC chống chịu khi bị thu giữ:** chỉ lưu session material theo thiết bị và hết hạn trạng thái resume nhanh chóng. **Giám sát:** cảnh báo thay đổi đường đi bất khả thi, mạng không được phê duyệt dùng đồng thời, migration storm và resume sau quarantine.

## Egress từ CI/CD runner được quản lý hoặc automation runner tồn tại ngắn hạn

**Cơ chế:** workflow do tổ chức sở hữu thực hiện kiểm tra mạng có giới hạn trên runner do nhà cung cấp lưu trữ. Đích đến thấy địa chỉ cloud runner, còn nền tảng giữ thông tin quy kết repository, actor, workflow, token, log và billing. Đây là thực thi từ xa với egress có thể quy trách nhiệm, không phải ẩn danh với nhà cung cấp.<sup>[[28]](#references)</sup>

**Ưu điểm:** môi trường sạch, dùng một lần; định nghĩa job có thể tái lập; không cần kết nối inbound; hữu ích cho kiểm tra tính sẵn sàng phân tán địa lý; audit controller mạnh.

**Nhược điểm:** nền tảng và tổ chức nhận diện người khởi tạo; workflow token rộng và pull request không tin cậy nguy hiểm; uy tín IP dùng chung; log/artifact có thể lưu secret hoặc dữ liệu target.

**Quy trình:** (1) tạo repository và environment riêng tư của tổ chức cho bài đánh giá; (2) chỉ cho phép job lành tính, cố định, được phê duyệt thủ công để kiểm tra endpoint do bạn sở hữu; (3) dùng quyền workflow chỉ đọc tối thiểu và không có secret production; (4) chạy kiểm tra; (5) so sánh bản ghi workflow, nhà cung cấp và target; (6) xác minh artifact không chứa thông tin xác thực; (7) xóa environment token và giữ audit cần thiết.

**Phát hiện:** audit nhà cung cấp và log workflow cung cấp quy kết trực tiếp; target nhận diện ASN/range của runner và grammar yêu cầu ổn định. **OPSEC chống chịu khi bị thu giữ:** không bao giờ đặt secret của field device, signing, wallet hoặc quản trị đám mây trong biến runner. **Giám sát:** yêu cầu phê duyệt branch/environment và cảnh báo chỉnh sửa workflow, thực thi fork, đọc secret và đích đến bất ngờ.

## Chặng đầu nội bộ không dùng IP tới gateway do bạn sở hữu

**Cơ chế:** Bluetooth mesh, Wi-Fi Aware/Direct, radio công suất thấp hoặc kết nối serial/quang truyền các thông điệp có giới hạn từ sensor gần đó tới gateway Internet được chủ sở hữu cho phép. Field device không có route Internet; gateway là egress duy nhất. Phạm vi radio và giới hạn giao thức khiến đây là thiết kế telemetry/store-and-forward, không phải Internet tương tác ẩn danh.

**Ưu điểm:** loại bỏ stack Internet và thông tin xác thực khỏi field device nhỏ nhất; tiêu thụ ít điện; gateway tập trung chính sách; có thể bắc cầu qua vùng mất kết nối tạm thời.

**Nhược điểm:** bị phát hiện qua RF/vật lý, ghép nối và mã định danh thiết bị; băng thông/phạm vi nhỏ; gateway vẫn liên kết mọi thông điệp; quy định phổ tần và mã hóa khác nhau; khi bị thu giữ có thể lộ dữ liệu đang chờ.

**Quy trình:** (1) xin phê duyệt địa điểm và phổ tần; (2) ghép nối một sensor do bạn sở hữu với một gateway do bạn sở hữu bằng khóa riêng; (3) xác định loại thông điệp cố định đã ký, TTL và tốc độ; (4) không cấp default IP route cho sensor; (5) để gateway chỉ chuyển tiếp tới collector do bạn sở hữu; (6) kiểm thử replay, mất phạm vi và lỗi gateway; (7) kiểm kê và thu hồi cả hai thiết bị.

**Phát hiện:** khảo sát RF, cơ sở dữ liệu ghép nối, kiểm tra vật lý và log tiến trình/flow gateway làm lộ đường truy cập. **OPSEC chống chịu khi bị thu giữ:** sensor chỉ giữ khóa pairwise và queue mã hóa có giới hạn, không bao giờ giữ thông tin xác thực của người vận hành, Wi-Fi, cellular hoặc controller. **Giám sát:** cảnh báo peer mới, sequence rollback, lỗi khóa, tốc độ RF bất thường và thông điệp đến qua gateway chưa đăng ký.

## Ma trận phơi lộ khi bị thu giữ/xâm nhập

Bảng này áp dụng kiểm tra khả năng chống chịu khi bị thu giữ cho mọi nhóm ở trên. “Giảm thiểu” nghĩa là giảm secret và phạm vi ảnh hưởng trên tài sản được ủy quyền; không bao giờ có nghĩa là xóa bằng chứng hoặc che giấu khỏi điều tra.

| Nhóm kỹ thuật | Endpoint/relay bị thu giữ có thể làm lộ | Kiểm soát tối thiểu được ủy quyền |
|---|---|---|
| NAT/CGNAT, Wi-Fi công cộng, travel router | mạng đã biết, lịch sử DHCP/portal, MAC, peer tunnel | thiết bị riêng của tổ chức; private MAC nếu được hỗ trợ; không dùng tài khoản cá nhân; inventory controller |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | nhà cung cấp/hostname, khóa, route, log và hop liền kề | một danh tính cho mỗi engagement; TTL ngắn; route hẹp; thu hồi phía broker; không có khóa chủ |
| OHTTP/ODoH, MASQUE, split-provider relay | cấu hình relay/gateway, mã định danh ứng dụng và yêu cầu đã cache | giảm trường định danh payload; pin cấu hình được phê duyệt; cache có giới hạn; nghiêm cấm fallback trực tiếp |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | phần mềm đã cài, bridge/onion material, trạng thái cục bộ và lịch sử peer | client chuẩn; khóa dịch vụ riêng; trạng thái tối thiểu được mã hóa; luân chuyển danh tính dịch vụ bị xâm phạm |
| Trình duyệt từ xa/VDI/jump host | workspace token, clipboard/tệp và tenant từ xa | MFA chống phishing tại gateway; tắt kênh truyền dữ liệu; thu hồi phiên nhanh |
| Cellular, vệ tinh, private APN | SIM/eSIM, danh tính IMEI/terminal, nhà cung cấp và vị trí gần đúng | hợp đồng của tổ chức; không đặt cùng thiết bị cá nhân; chính sách APN/overlay hẹp; quy trình đình chỉ từ nhà cung cấp |
| Residential/cooperative proxy, ORB lab | danh tính agent, controller/hop tiếp theo, lưu lượng cache | chỉ node có sự đồng thuận/thuộc sở hữu; agent có chữ ký; thông tin xác thực riêng từng node; mapping participant do controller giữ |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API token, tài liệu triển khai và billing | project riêng; role theo least privilege; deploy token tồn tại ngắn hạn; giữ audit nhà cung cấp ở nơi tập trung |
| Dead drop, pull mailbox, store-and-forward | tên object, queue, job/kết quả đã cache và dữ liệu lưu trữ | job có chữ ký và giới hạn; TTL; cache mã hóa; danh tính producer riêng; log máy chủ bất biến |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, khóa thiết bị, dấu vết vị trí vật lý | văn bản cho phép lắp đặt; danh tính thiết bị riêng; không có secret của người vận hành; telemetry chống can thiệp/trạng thái; thu hồi và khôi phục |
| TURN, reverse overlay, dual-uplink | realm/broker, thông tin xác thực thiết bị, peer/route và profile uplink | dịch vụ outbound-only, phạm vi hẹp; thông tin xác thực thiết bị tồn tại ngắn hạn; đăng nhập người vận hành độc lập; đường fail-closed |
| IPv6 temporary addressing | profile, lịch sử prefix và trạng thái endpoint/ứng dụng | chỉ xem là biện pháp chống theo dõi; giữ log mạng; kết hợp compartmentation endpoint |
| Pluggable transport/refraction lab | cài đặt bridge/broker/decoy, trạng thái Tor và khóa nghiên cứu | client chuẩn hoặc lab cô lập; không dùng trạng thái trình duyệt cá nhân; không phát tín hiệu production |
| IPFS/PIR/fetcher | client truy vấn CID/query, nội dung cache, token gateway/dịch vụ | cache mã hóa có giới hạn; chỉ tham số công khai; service token allowlist tồn tại ngắn hạn |
| Anycast/QUIC/MPTCP | node dịch vụ, connection ID, trạng thái resume và mọi đường đã biết | chỉ danh tính theo vùng; thời hạn resume ngắn; thu hồi route/phiên tập trung |
| CI/CD runner được quản lý | repository, workflow, token nhà cung cấp, log và artifact | workflow theo least privilege; không có secret production/field/wallet; phê duyệt environment |
| Chặng nội bộ không dùng IP | peer radio, khóa pairwise, thông điệp trong queue và danh tính gateway | khóa pairwise riêng; schema thông điệp cố định; không có thông tin xác thực Wi-Fi/cellular/người vận hành |

## Giám sát khả năng bị phát hiện với mọi nhóm truy cập

Không phép kiểm tra phía client nào chứng minh được điều tra viên hoặc bên phòng thủ đang theo dõi. Giám sát các hệ thống thuộc quyền sở hữu của engagement, đối chiếu với controller/client và dừng lại thay vì thăm dò observer. Các dòng dưới đây bao quát mọi kỹ thuật ở trên; kết hợp với [trạng thái cảnh báo field node và runbook ứng phó](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Kỹ thuật được bao quát | Tín hiệu an toàn phía controller | Điều kiện quarantine/dừng |
|---|---|---|
| NAT/CGNAT, Wi-Fi công cộng/guest, travel router, cellular/eSIM, vệ tinh, private APN | phiên lease/portal/nhà mạng, tuple công khai, thay đổi BSSID/cell/đường đi, thông báo nhà cung cấp | mạng/SIM/thiết bị không được phê duyệt, di chuyển không giải thích được hoặc nhà cung cấp/SOC nâng cấp sự cố |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | xác thực peer, trạng thái tunnel, rò rỉ route/DNS, sự kiện admin/API mới, khiếu nại | thông tin xác thực bị trùng/đánh cắp, admin lạ, fallback trực tiếp hoặc egress ngoài phạm vi |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | allocation relay/gateway, phiên bản khóa/config, kết nối trực tiếp không được hỗ trợ, tỷ lệ lỗi/replay | khóa không khớp, fallback trực tiếp, realm/peer lạ hoặc thông báo lạm dụng từ nhà cung cấp |
| Tor Browser, bridge, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | trạng thái bootstrap, lỗi circuit, descriptor onion/tình trạng dịch vụ và canary page do bạn sở hữu | dùng lẫn tài khoản cá nhân, kết nối không phải Tor bất ngờ hoặc khóa dịch vụ bị xâm phạm |
| I2P, mixnet, GNUnet, mesh/store-forward, chặng nội bộ không dùng IP | peer set, tuổi/thứ tự queue, gateway nhận, liên kết radio và hash nội dung | peer/gateway lạ, sequence rollback, nội dung không được ủy quyền hoặc thiếu hồ sơ lưu trữ |
| Trình duyệt từ xa/VDI/jump host, CI/CD runner, serverless | phiên IdP, thay đổi workflow/image/config, lượt dùng token mới, artifact/export và audit đám mây | đăng nhập/chỉnh sửa workflow lạ, đọc secret, đích đến bất ngờ hoặc nâng quyền project/role |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | inventory node do bạn sở hữu, truy cập DNS/edge/object, đồ thị controller, chữ ký job và TTL | node/origin/object writer lạ, job không ký/được phát lại, topology thoát khỏi lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | heartbeat có chữ ký, hash boot/config, trạng thái vỏ thiết bị, context AP/switch, danh tính trùng | node bị di chuyển/mở, boot/hash/đường đi bất ngờ, sentinel được sử dụng hoặc có báo cáo từ địa điểm |
| IPv6 temporary address, QUIC migration, MPTCP | delegated prefix, connection ID/subflow, xác thực đường đi và broker session | di chuyển bất khả thi, các đường không được phê duyệt hoạt động đồng thời hoặc phiên resume sau thu hồi |
| IPFS/cache, PIR, fetcher có giới hạn | CID/query-shape/root version, thay đổi peer/gateway, từ chối redirect/allowlist | pin/query/đích đến bất ngờ, dataset root không ký hoặc thông báo lạm dụng từ nhà cung cấp |
| Refraction/decoy-routing lab, anycast rendezvous | quyết định chuyển hướng thuộc quyền sở hữu, proxy nhận, BGP/RPKI origin, config digest theo vùng | tín hiệu qua đường production, route origin lạ, vùng/config không nhất quán |

## Chọn và kiểm thử đường truy cập

1. Xác định observer cần loại bỏ và dữ liệu cần che giấu.
2. Chọn nhóm kỹ thuật ít phức tạp nhất có thể loại bỏ observer đó.
3. Vẽ sơ đồ observer nguồn, entry, traversal, exit, DNS, tài khoản và thanh toán.
4. Dùng danh tính endpoint/ứng dụng riêng.
5. Xác minh IPv4, IPv6, DNS, WebRTC/việc ứng dụng bỏ qua proxy và góc nhìn của đích đến.
6. Làm lỗi từng hop và xác nhận kết nối bị đóng an toàn.
7. So sánh log tại mọi thành phần bạn kiểm soát.
8. Ghi nhận các liên kết còn lại về thời gian, nhà cung cấp, endpoint và vật lý.

## References

- [1] [EFF — Chọn VPN phù hợp với bạn](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — HTTP ẩn danh](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Chuyển tiếp UDP qua HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Các biện pháp bảo vệ của Tor](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Bỏ chặn Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Dùng Tor Browser với VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Tổng quan về onion service](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Mô hình đe dọa](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Mô hình đe dọa](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Chia sẻ tệp ẩn danh](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — DoH ẩn danh](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — Bảo mật iCloud Private Relay](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Đăng ký SIM bắt buộc](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Turla vệ tinh](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — Các tác nhân gián điệp liên hệ Trung Quốc sử dụng mạng ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — Tấn công Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT và duy trì khả năng xuyên qua firewall](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Extension địa chỉ tạm thời cho Stateless Address Autoconfiguration trong IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transport và bridge](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — Nghiên cứu dự án và triển khai](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — Khái niệm HTTP Gateway và vòng đời yêu cầu](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Tổng quan về Private Information Retrieval](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Hoạt động của dịch vụ Anycast](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — Di chuyển kết nối QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — Tài liệu tham khảo về runner do GitHub lưu trữ](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
{{#include ../banners/hacktricks-training.md}}
