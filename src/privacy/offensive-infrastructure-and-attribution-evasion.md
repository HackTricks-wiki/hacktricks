# Hạ tầng tấn công và né tránh quy kết

{{#include ../banners/hacktricks-training.md}}

Một operator hiếm khi có được mức độ ẩn danh đáng kể chỉ nhờ một proxy. Các chiến dịch thực tế xây dựng một **đồ thị phân tách**: operator truy cập một access node, các traversal node che giấu access node khỏi exit, redirector bảo vệ C2 thực, còn các tên miền dùng một lần trỏ đến public edge.

Sử dụng [Danh mục kỹ thuật truy cập Internet ẩn danh](anonymous-internet-access-techniques.md) để xem tổng quan chuẩn hóa về ưu điểm/nhược điểm/triển khai/phát hiện của từng đường đi. Trang này đi sâu hơn vào cách kết hợp hạ tầng đối kháng.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Địa chỉ cuối cùng mà mục tiêu nhìn thấy là bằng chứng về một đường đi, chứ không phải bằng chứng cho biết ai đã điều khiển bàn phím. MITRE ánh xạ các thành phần chính sang Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) và Web Service (T1102).<sup>[[1]](#references)</sup>

## Các lớp hạ tầng

| Lớp | Lý do tác nhân sử dụng | Dấu vết tồn tại lâu dài | Điểm pivot tốt nhất cho người phòng thủ |
|---|---|---|---|
| VPS/cloud thuê | Nhanh, ổn định, có thể định tuyến, dễ dựng lại | tenant, thanh toán, console, lịch sử đăng nhập nguồn và image | sự kiện tài khoản/control plane và dấu vân tay máy chủ lặp lại |
| VPN thương mại/Tor | Tập hợp egress dùng chung lớn; không cần quản trị máy chủ | khả năng giám sát của nhà cung cấp/giám sát viên và tương quan thời gian đầu-cuối | hành vi đích, bằng chứng endpoint và tương quan luồng |
| Proxy dân dụng/di động | ASN người dùng và vị trí địa lý có vẻ hợp lý | hồ sơ của broker/khách hàng; hành vi của proxyware hoặc host bị nhiễm | di chuyển bất khả thi, giao thức proxy và thay đổi địa chỉ theo phiên |
| Máy chủ/router/IoT bị xâm nhập | Mượn uy tín và thẩm quyền pháp lý của nạn nhân | implant, luồng quản lý và controller upstream lặp lại | telemetry thiết bị và cấu trúc ORB, không phải một IP thoát đơn lẻ |
| CDN/redirector | Tách edge công khai khỏi C2 back-end | dấu vết TLS/HTTP, chứng chỉ, định tuyến và tài khoản cloud | tương quan edge-to-origin và phân cụm hình dạng request |
| Web service hợp pháp | Hòa lẫn vào lưu lượng GitHub/cloud/mạng xã hội được cho phép | API token, mã định danh tenant/object và dòng tiến trình bất thường | tiến trình endpoint cùng ngữ nghĩa service/API |
| Đường truyền vật lý/di động/vệ tinh | Thay đổi nguồn gốc vật lý được hiển thị | hồ sơ RF, nhà mạng, thuê bao, thiết bị và vị trí | kết hợp bằng chứng vô tuyến/vật lý và mạng |

## Mạng relay box vận hành

**Mạng ORB** là một đội proxy được quản lý, dùng làm dịch vụ trung gian. Mandiant chia chúng thành mạng được cung cấp sẵn gồm máy chủ thuê, mạng không được cung cấp sẵn gồm router/IoT bị xâm nhập và mạng lai. Một cấu trúc liên kết trưởng thành có bốn vai trò logic:<sup>[[2]](#references)</sup>

1. **Máy chủ quản trị (ACOS):** duy trì danh mục, thông tin xác thực, trạng thái hoạt động và chính sách định tuyến.
2. **Nút truy cập/relay:** xác thực khách hàng hoặc người vận hành; đây là điểm vào ổn định tới một mạng lưới thường xuyên thay đổi.
3. **Nút trung chuyển:** một hoặc nhiều hệ thống thuê hoặc bị xâm nhập relay các kết nối không rõ nội dung.
4. **Nút thoát/staging:** hiển thị địa chỉ nguồn cuối cùng cho các mục tiêu trinh sát, khai thác hoặc C2.

Mạng lưới có thể chọn nút thoát theo quốc gia, ASN, độ trễ hoặc tình trạng sẵn sàng, đồng thời thay thế các nút hoạt động không ổn định. Nhiều nhóm đe dọa có thể cùng thuê một mạng. Mandiant quan sát thấy một địa chỉ IPv4 chỉ gắn với một số ORB trong thời gian ngắn nhất là 31 ngày; do đó, tổ chức này khuyến nghị xem **mạng là một thực thể đang biến đổi, có đặc tính như tác nhân**, thay vì chặn một danh sách IP đã lỗi thời.<sup>[[2]](#references)</sup>

### Những gì cách này mang lại — và làm lộ

- Mục tiêu nhìn thấy một nút thoát có thể ở gần về mặt địa lý và có vẻ là địa chỉ dân dụng.
- Nút thoát nhìn thấy mục tiêu và hop đứng trước nó, nhưng không nhất thiết thấy người vận hành.
- Dịch vụ truy cập nhìn thấy khách hàng và yêu cầu định tuyến. Một mạng lưới do đơn vị độc lập quản lý có thể tách khách hàng khỏi các nút thoát, nhưng lại tạo ra hồ sơ đối tác có giá trị cao.
- Cổng, thứ tự bắt tay, banner máy chủ, chứng chỉ, khoảng thời gian hoạt động và mối liên hệ với controller lặp lại có thể làm lộ cả đội máy dù IP liên tục thay đổi.
- Router bị xâm nhập thường thiếu telemetry endpoint, nhưng ISP của nó vẫn có dữ liệu thuê bao và luồng; việc thu giữ sẽ làm lộ các dấu vết implant/cấu hình.

{% hint style="info" %}
Trong một bài thực hành được cấp phép, hãy tái tạo cấu trúc liên kết bằng VM hoặc router do tổ chức sở hữu và lưu giữ bản đồ quy kết của controller. Không huy động open proxy hoặc thiết bị của bên thứ ba. [Hướng dẫn lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) tạo ra cùng cấu trúc hop mà người phòng thủ có thể quan sát, nhưng không biến một bên trung gian thành nạn nhân.
{% endhint %}

## Mạng proxy dân dụng và di động

Dịch vụ proxy dân dụng cấp các phiên sử dụng địa chỉ băng thông rộng của người tiêu dùng; proxy di động egress qua các pool NAT của nhà mạng. Nguồn cung có thể đến từ thiết bị được đăng ký rõ ràng, SDK/proxyware đi kèm ứng dụng dành cho người tiêu dùng, bên bán lại hoặc malware. Các nguồn này không tương đương: nếu thiếu sự đồng thuận đầy đủ thông tin, dịch vụ bảo vệ quyền riêng tư sẽ trở thành hạ tầng bị xâm nhập.

Các chế độ xoay vòng ảnh hưởng đến việc phát hiện:

- **xoay vòng theo từng request** tạo ra sự gián đoạn nhanh về IP và ASN/vị trí địa lý trong khi danh tính ở các lớp cao hơn vẫn ổn định;
- **phiên cố định** giữ nguyên một nút thoát trong vài phút hoặc vài giờ, trông giống một thuê bao thông thường;
- **backconnect gateway** cung cấp cho khách hàng một endpoint broker duy nhất và tự chọn nút thoát ở phía trong;
- **pool di động** đặt nhiều thuê bao thật sau một số ít địa chỉ NAT của nhà mạng, khiến việc chặn IP gây tốn kém.

Người phòng thủ nên tương quan IP với phiên đã xác thực, dấu vân tay TLS/client, thứ tự HTTP, cookie thiết bị và hành vi. Một lần đăng nhập dân dụng được cho là tại địa phương, sau đó xuất hiện ở một quốc gia khác trong khi mọi đặc điểm ở các lớp cao hơn vẫn giống hệt nhau, là tín hiệu mạnh hơn chỉ dựa vào uy tín. Ngược lại, việc chia sẻ địa chỉ và chuyển giao giữa các mạng di động tạo ra thay đổi hợp lệ, vì vậy đừng bao giờ xem phân loại dân dụng/proxy là kết luận cuối cùng.

### Control plane của proxyware và sự chồng lấn giữa các bên bán lại

Đừng mô hình hóa một pool dân dụng như một danh sách phẳng các nút thoát. Phân tích hệ sinh thái IPIDEA cho thấy một **control plane hai tầng có thể tái sử dụng**: SDK nhúng trước tiên gửi metadata thiết bị/đăng ký tới một domain Tier One và nhận thông tin lập lịch cùng các cặp IP:port `connect`/`proxy` của Tier Two. Nút này định kỳ truy vấn cổng connect Tier Two để lấy một tác vụ được mã hóa, mở kết nối thứ hai tới cổng proxy tương ứng, rồi relay các byte được cung cấp tới đích được yêu cầu. Các SDK và thương hiệu proxy bề ngoài khác nhau có domain khám phá riêng, nhưng hội tụ vào hạ tầng Tier Two dùng chung và các pool nút thoát chồng lấn thông qua mối quan hệ sở hữu chung và bán lại.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Điều này tạo ra các pivot săn tìm bền vững hơn một dải IP dân dụng:<sup>[[13]](#references)</sup>

- một tiến trình tiện ích, VPN, game hoặc thiết bị nhúng bất ngờ gửi ID thiết bị/khóa khách hàng ổn định và nhận về danh sách máy chủ thay đổi;
- endpoint thăm dò một IP trực tiếp trên cổng bất thường, rồi kết nối đến một cổng khác trên cùng địa chỉ ngay trước khi mở socket đến đích mới;
- nhiều thương hiệu có vẻ khác nhau dùng chung địa chỉ Tier Two, cú pháp giao thức, mã SDK hoặc các node thoát trùng lặp;
- các ứng dụng riêng biệt liên hệ với những domain Tier One khác nhau nhưng nhận địa chỉ từ cùng một pool Tier Two.

Sự trùng lặp này cũng hạn chế khả năng quy kết: việc thấy một IP trong pool được một vendor quảng bá không xác định được reseller, khách hàng hay threat actor nào đã sử dụng IP đó vào thời điểm liên quan. Hãy lưu giữ dấu thời gian luồng, lineage tiến trình, nội dung phản hồi Tier One và mã định danh tác vụ Tier Two.<sup>[[13]](#references)</sup> Trong một bài tập được ủy quyền, chỉ mô phỏng hệ thống phân cấp này bằng các endpoint thuộc sở hữu của tổ chức; tuyệt đối không đăng ký thiết bị tiêu dùng hoặc proxyware của bên thứ ba.

## Chuỗi proxy nhiều hop

MITRE phân biệt proxy bên ngoài với **multi-hop proxies (T1090.003)**. Đặc tính quan trọng không phải số lượng hop mà là sự tách biệt về thông tin và quyền quản trị.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Nếu một bên vận hành A và B, các log dùng chung hoặc thời điểm lưu lượng có thể giúp tái dựng circuit. Thêm các VPN thương mại nối tiếp từ cùng endpoint/account có thể làm tăng độ trễ nhưng vẫn để lộ bằng chứng về danh tính, thanh toán và thời điểm chung. Tor giảm vấn đề này bằng các relay được chọn độc lập và thiết kế client dùng chung, nhưng một mạng tương tác có độ trễ thấp không thể đảm bảo chống lại một observer đo được cả hai đầu.

Các lỗi phổ biến gồm DNS hoặc IPv6 bypass, ứng dụng tự mở socket, lưu lượng quản lý kết nối trực tiếp tới relay, hoạt động đồng bộ, dùng lại SSH key và đăng nhập vào các tài khoản có thể nhận diện danh tính. Cách xác minh đúng là kiểm tra lỗi: lần lượt dừng từng relay và chứng minh rằng workload không thể chuyển sang đường truyền không được mã hóa.

### Sụp đổ tunnel và rò rỉ upstream

Kiến trúc relay thường dễ bị quy kết nhất khi xảy ra lỗi. Unit 42 ghi nhận một đường đi gián điệp nhiều tầng sử dụng VPS hướng tới nạn nhân, VPS relay, proxy residential, Tor và các dịch vụ proxy khác; khi một tunnel bị bỏ sót hoặc sụp đổ, hạ tầng upstream ẩn kết nối trực tiếp tới relay và các hệ thống hướng tới nạn nhân. Cuộc điều tra tương tự cũng dùng một certificate X.509 tạm thời bị lộ trên hạ tầng upstream làm điểm pivot giữa các tầng.<sup>[[14]](#references)</sup>

Tách riêng **data plane** (`victim <-> exit`) khỏi **control plane** (`operator/upstream -> relay administration`). Lưu giữ log ingress và xác thực ở mọi tầng do bạn sở hữu, lịch sử certificate và các kết nối lỗi ngắn—không chỉ các phiên C2 thành công. Một nguồn chỉ xuất hiện khi relay gặp sự cố hoặc trực tiếp quản trị nhiều node hướng tới nạn nhân là ứng viên upstream đáng chú ý hơn một exit thông thường, nhưng ASN/vị trí địa lý vẫn chỉ là giả thuyết, không phải bằng chứng về danh tính operator.

Trong lab được ủy quyền, workload phải fail closed. Với workload được cô lập trong Linux network namespace, route đầu tiên phải đi qua tunnel; sau khi gỡ tunnel, cả request lẫn tra cứu route đều phải thất bại thay vì chọn uplink vật lý:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Lặp lại kiểm tra với DNS và IPv6, cũng như tại mỗi ranh giới relay. Nếu bất kỳ phép thăm dò nào thành công, hãy ghi lại giao diện/địa chỉ nguồn thực tế trước khi sửa policy routing hoặc firewall; quan sát đó chính là attribution leak mà điều tra viên sẽ thấy.

## Các tầng redirector và điều chỉnh lưu lượng

Một **redirector** công khai tiếp nhận lưu lượng phù hợp với grammar dành riêng cho từng chiến dịch và chuyển tiếp đến team server được bảo vệ. Mọi thứ khác có thể bị từ chối hoặc được trả về nội dung vô hại.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Nhiều tầng giúp hạn chế lộ diện: việc đốt một public domain không nhất thiết làm lộ team server. CDN cung cấp năng lực anycast và một domain bên ngoài có uy tín, nhưng tài khoản CDN và log ở edge trở thành điểm có thể dùng để quy kết. TLS fingerprint, lịch sử chứng chỉ, path/thứ tự header đặc trưng, kích thước phản hồi, cách chuyển hướng và allowlist origin có thể liên kết các front tưởng như không liên quan.

Để phát hiện, hãy ghi lại các trường reverse proxy trước khi chuẩn hóa, so sánh SNI/Host/authority, kiểm tra các tổ hợp header hiếm, phân nhóm nội dung phản hồi và TLS fingerprint, đồng thời tìm các cấu hình trùng lặp trong audit log của cloud/CDN. Với red team được ủy quyền, tránh sao chép thương hiệu thật hoặc đặt chức năng thu thập thông tin xác thực sau một bên thứ ba không liên quan.

## Domain fronting và domainless fronting

Với **domain fronting (T1090.004)** kiểu cổ điển, kết nối TLS quảng bá một front domain được cho phép trong SNI, trong khi HTTP `Host` hoặc HTTP/2 `:authority` đã mã hóa yêu cầu một domain back-end khác. CDN phối hợp sẽ định tuyến dựa trên giá trị bên trong. Người quan sát mạng không giải mã TLS chỉ thấy front; CDN thấy cả hai giá trị và origin.<sup>[[4]](#references)</sup> Trong các biến thể domainless, SNI có thể để trống trong khi một trường định tuyến khác chọn đích đến.

Đây không phải là giả mạo thần kỳ: kỹ thuật này chỉ hoạt động khi intermediary cố ý hoặc vô tình cho phép sự không khớp và biết cách định tuyến theo tên bên trong. Các nhà cung cấp lớn đã hạn chế fronting xuyên tài khoản. Encrypted ClientHello (ECH) thay đổi những gì người quan sát trên đường truyền có thể thấy, nhưng không xóa log của CDN, endpoint hay ứng dụng.

Các điểm cần phát hiện gồm:

- quan hệ tiến trình trên endpoint và đích đến không mong đợi đối với ứng dụng đó;
- SNI không khớp với HTTP authority, trong trường hợp việc kiểm tra TLS hợp pháp và khả thi;
- log CDN cho thấy một tenant/front định tuyến đến authority/origin khác;
- các phiên kéo dài bất thường hoặc có chu kỳ đến một dịch vụ vốn thường được tương tác;
- kích thước và nhịp luồng mã hóa ổn định khi front domain thay đổi.

Lab an toàn mô phỏng sự không khớp định tuyến trên reverse proxy do mình sở hữu; không lạm dụng CDN công cộng.

## Dynamic resolution: DDNS, DGA và fast flux

Dynamic resolution tách một dịch vụ logic khỏi hạ tầng cố định:

- **DDNS:** client đã xác thực cập nhật một tên ổn định sau khi địa chỉ của nó thay đổi.
- **DGA:** cả endpoint lẫn controller đều tạo các domain ứng viên từ seed thời gian/khóa; operator đăng ký một nhóm nhỏ.
- **Fast flux:** một tên trả về tập địa chỉ bị xâm nhập/proxy thay đổi nhanh, thường có TTL thấp.
- **Double flux:** cả địa chỉ dịch vụ lẫn địa chỉ name server có thẩm quyền đều luân phiên, qua đó che giấu cả lớp điều khiển.

Fast flux là một mô hình phân phối tải được sử dụng với mục đích đối kháng, không đơn thuần là “nhiều câu trả lời DNS”. Bằng chứng mạnh hơn kết hợp TTL thấp, số lượng địa chỉ duy nhất cao, phân tán rộng theo ASN/địa lý, vòng đời node ngắn, hành vi ứng dụng lặp lại và lịch sử đăng ký đáng ngờ. CDN cũng có thể hợp pháp sở hữu một số đặc điểm này. MITRE khuyến nghị đối chiếu hành vi DNS với tiến trình và các kết nối tiếp theo.<sup>[[5]](#references)</sup>

Có thể phát hiện DGA qua entropy từ vựng, mẫu phụ âm/chữ số, các đợt NXDOMAIN, domain mới xuất hiện đồng bộ và ngữ cảnh tiến trình. DGA dùng wordlist và mô hình sinh có thể qua mặt các quy tắc entropy đơn giản, khiến việc phân cụm theo thời gian trên toàn bộ đội máy và truy vết nguồn gốc endpoint trở nên quan trọng hơn.

## Domain bị xâm nhập và domain shadowing

Actor có thể chiếm quyền tài khoản registrar/DNS, chiếm một subdomain bị bỏ quên hoặc thêm bản ghi bên dưới một domain vốn có uy tín. **Domain shadowing** giữ nguyên apex hợp pháp trong khi tạo số lượng lớn subdomain do attacker kiểm soát, trỏ đến các máy chủ phân phối hoặc C2 thay đổi liên tục. Cách này tận dụng tuổi đời và uy tín của domain, đồng thời có thể né việc chặn toàn bộ domain.<sup>[[6]](#references)</sup>

Defender cần audit log của registrar và DNS có thẩm quyền, MFA, khóa registry/registrar, cảnh báo khi có delegation/API token/name server mới, theo dõi certificate transparency và kiểm kê tài nguyên cloud được DNS tham chiếu. Hãy điều tra quá trình phân giải và lịch sử chứng chỉ của từng subdomain độc lập với uy tín của apex.

## Web services và dead-drop resolver

**Dead-drop resolver (T1102.001)** lưu một con trỏ đã mã hóa đến C2 hiện tại bên trong một bài đăng, hồ sơ, tài liệu, repository, cloud object hoặc trường blockchain hợp pháp. Malware tải object công khai, giải mã domain/IP rồi kết nối đến stage tiếp theo. Các biến thể hai chiều trao đổi lệnh hoặc tệp qua API dịch vụ.<sup>[[7]](#references)</sup>

Một biến thể resolver riêng cho GitHub chỉ dùng Issues Search API khi kênh repository đã xác thực không hoạt động. Client tìm các issue khớp ngày hiện tại, repository và loại issue, mở URL comments của từng issue rồi trích ciphertext nằm giữa các dấu `<!--` và `-->`. Sau khi giải mã theo từng host bằng khóa được tạo từ ngày, các trường như `Owner`, `LicRepo` và `LicToken` thay thế owner, path và token của repository chính. Nhờ vậy operator có thể luân phiên thông tin xác thực và endpoint mà không cần thay client; comment của issue đóng vai trò resolver, còn các tệp repository vẫn là kênh tasking.<sup>[[15]](#references)</sup>

Một biến thể Android chọn một trong hai trang Telegram công khai khi khởi động và trích ciphertext nằm giữa hai lần xuất hiện của một marker được nhúng trong APK. Nó giải mã giá trị bằng Base64URL rồi giải mã bằng AES-128-CBC: 16 byte đầu của `SHA-256(marker)` là khóa, 16 byte còn lại là IV. Plaintext là URL cơ sở C2 thực tế, không phải URL trang Telegram. Khi tái tạo quá trình phân giải, hãy giữ nguyên nội dung trang và marker chính xác; thay đổi trang công khai sẽ xoay endpoint mà không cần dựng lại APK.<sup>[[16]](#references)</sup>

Cách này tăng khả năng phục hồi và che giấu back-end C2 khỏi phân tích tĩnh binary. Tuy nhiên, nó cũng tạo ra các định danh ổn định về object, tenant, repository, API và mẫu truy cập. Defender nên liên kết:

1. tiến trình đã kết nối đến dịch vụ;
2. API path/object chính xác và hash phản hồi;
3. hoạt động giải mã hoặc xử lý chuỗi;
4. kết nối outbound mới ngay sau đó; và
5. hành vi giống hệt ở nơi khác trong đội máy.

Chặn toàn bộ GitHub, cloud storage hoặc mạng xã hội hiếm khi khả thi. Chính sách egress nhận biết dịch vụ và đối chiếu ở cấp tiến trình hiệu quả hơn chặn chỉ dựa trên domain.

## Persona, tài khoản và các ngăn cách trong quy trình mua sắm

Tính ẩn danh của hạ tầng thất bại khi persona, email khôi phục, điện thoại, phương thức thanh toán, browser hoặc IP quản trị nối liền các ngăn cách. Các chiến dịch có liên hệ với nhà nước đã xây dựng hồ sơ mạng xã hội, danh tính email và tài khoản cloud từ lâu trước khi sử dụng; ATT&CK ghi nhận việc này là Establish Accounts (T1585), bao gồm các kỹ thuật con về mạng xã hội, email và cloud.<sup>[[8]](#references)</sup>

Defender hoặc điều tra viên xây dựng đồ thị từ:

- thời điểm tạo và đăng nhập lần đầu, locale, múi giờ và lịch làm việc;
- thông tin khôi phục, thiết bị MFA, giấy tờ định danh và phương tiện thanh toán;
- TLS fingerprint của browser và lịch sử mạng nguồn;
- việc dùng lại avatar, nguồn gốc hình ảnh, văn phong và tốc độ phát triển đồ thị xã hội;
- registrant domain, name server, chứng chỉ, analytics ID hoặc commit repository dùng chung;
- các thao tác trên management plane bỏ qua kiến trúc public relay.

Với red team được ủy quyền, persona tổng hợp cần được ghi lại cho người điều phối cuộc diễn tập, sử dụng kênh khôi phục/thanh toán do tổ chức sở hữu, tránh mạo danh người thật không liên quan và có kế hoạch ngừng sử dụng. SOC có thể vẫn chưa biết; nhưng hoạt động không được trở thành thứ không ai chịu trách nhiệm.

## Các mẫu kết hợp mới nổi cần mô hình hóa mối đe dọa

Những nội dung sau là **các mô hình kết hợp do defender xây dựng**, không phải khẳng định rằng một actor cụ thể đã triển khai chính xác từng thiết kế. Chúng kết hợp các thành phần đã được ghi nhận và hữu ích làm giả thuyết cho purple team.

### Tasking bất đối xứng một chiều

Lệnh đến qua một nguồn công khai, broadcast hoặc chỉ cho phép ghi nối tiếp, trong khi kết quả được gửi qua một kênh không liên quan sau một khoảng trễ. Các thành phần ví dụ gồm liên lạc một chiều qua web service và dead drop. Việc tách kênh ngăn một luồng đơn lẻ trông như liên lạc hai chiều và cản trở việc đối chiếu request/response đơn giản.<sup>[[9]](#references)</sup>

**Phát hiện:** lưu lại các lần đọc ở cấp object, sau đó đối chiếu thay đổi trạng thái tiến trình với các lần truyền outbound sau đó trong một khoảng thời gian rộng hơn. Tìm tiến trình hiếm đọc cùng một object công khai dù không có phản hồi ngay lập tức.

### Nâng cấp kênh nhiều giai đoạn

Stage đầu ít gây chú ý thực hiện kiểm kê và chỉ nâng cấp một số hệ thống được chọn sang kênh stage thứ hai không liên quan. Endpoint, protocol và process thứ hai có thể không dùng chung hạ tầng nào với stage đầu. Cách này hạn chế việc lộ hạ tầng có năng lực cao và được mô hình hóa rõ ràng trong ATT&CK T1104.<sup>[[10]](#references)</sup>

**Phát hiện:** liên kết `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; đừng kết thúc sự cố sau khi chặn domain đầu tiên.

### Dịch chuyển tiếp xuyên protocol

Các hop khác nhau chuyển đổi HTTPS, QUIC, WebSocket, DNS, SSH hoặc API message-queue thay vì chuyển tiếp packet một cách trong suốt. Việc chuyển đổi loại bỏ một TLS fingerprint đầu cuối duy nhất, nhưng tạo ra các gateway có timing, buffering và chuyển đổi ngữ nghĩa đặc trưng. Có thể kết hợp protocol tunneling (T1572) với proxy và giả mạo dịch vụ.<sup>[[11]](#references)</sup>

**Phát hiện:** tìm các gateway host nhận một protocol rồi khởi tạo protocol khác với hành vi byte/thời gian gắn kết chặt chẽ; so sánh mục đích của endpoint với protocol thực tế được truyền tải.

### Kích hoạt thụ động trên thiết bị edge

Thay vì beacon, implant giám sát lưu lượng vốn đã đến router/VPN và chỉ kích hoạt khi gặp magic value, mẫu source-port hoặc token đã xác thực. Lưu lượng bình thường vẫn tiếp tục đến dịch vụ thật. ATT&CK gọi kỹ thuật này là Traffic Signaling (T1205), với các ví dụ đã được ghi nhận trên thiết bị mạng và APT.<sup>[[12]](#references)</sup>

**Phát hiện:** kiểm tra tính toàn vẹn firmware/tệp, capture packet thô trong một cuộc hunt được ủy quyền, tìm socket filter bất thường và hành vi dịch vụ khác biệt. Không có beacon định kỳ không chứng minh thiết bị edge sạch.

### Xoay vòng origin serverless và ephemeral

Một front duy trì danh tính logic ổn định trong khi các function/container tồn tại ngắn xử lý từng stage ở nhiều region/tài khoản. Cách này giảm thời gian tồn tại trên disk và tránh IP origin cố định, nhưng hoạt động tạo tài nguyên trên control plane, image/layer, role, secret, request ID và dữ liệu billing trở thành đồ thị bền vững.

**Phát hiện:** lưu audit log và invocation log của cloud bên ngoài workload; phân nhóm deployment template, role, environment key và quan hệ front-to-origin.

### Đa dạng lớp quyền riêng tư

Một chiến dịch có thể cố ý tránh dùng một chuỗi đồng nhất: chẳng hạn, một kênh dùng relay thuê, tasking dùng object công khai, exit dùng liên kết cellular lab do mình sở hữu, còn quản trị dùng một mạng tổ chức riêng. Cách này giảm giá trị của việc xâm nhập một nhà cung cấp, nhưng làm tăng rủi ro đối chiếu thời gian giữa các lớp và rủi ro sai sót vận hành.

**Phát hiện:** xây dựng dòng thời gian chiến dịch trên các cảm biến identity, DNS, SaaS, network và cloud. Tìm các chuyển đổi trạng thái đồng bộ thay vì indicator giống hệt nhau.

### Dead drop trên hệ thống phi tập trung hoặc transparency log

Actor có thể đặt một con trỏ mã hóa nhỏ trong bất kỳ hệ thống công khai bền vững nào có tính nối tiếp, kho lưu trữ content-addressed hoặc feed dạng transparency. Object công khai có khả năng tồn tại lâu, nhưng index/hash nội dung chính xác và hành vi polling của client trở thành định danh ổn định.

**Phát hiện:** ghi lại đầy đủ API/object identifier và hash phản hồi; cảnh báo khi process không phổ biến polling các object bất biến rồi giải mã hoặc tạo kết nối mới.

### Hoạt động store-and-forward có độ trễ

C2 tương tác tạo ra tương quan thời gian mạnh. Thiết kế store-and-forward gom các job đã mã hóa theo đợt và trả kết quả sau vài phút hoặc vài giờ qua queue khác hoặc phương thức truyền vật lý. Cách này đánh đổi tốc độ phản hồi để giảm tương quan thời gian đầu-cuối.

**Phát hiện:** kéo dài khoảng thời gian đối chiếu, mô hình hóa việc truy cập queue định kỳ và kiểm tra hoạt động staging trên endpoint. Gom theo đợt chuyển tín hiệu từ timing packet sang hành vi tiến trình/tệp theo lịch; không xóa được tín hiệu.

## Rà soát thiết kế: suy nghĩ theo góc nhìn của observer

Với mỗi đường đi, hãy điền bảng này trước khi triển khai và sau khi thu thập dữ liệu:

| Lớp | Thấy nguồn? | Thấy đích? | Thấy nội dung? | Định danh ổn định | Thời hạn lưu trữ/chủ thể pháp lý |
|---|---:|---:|---:|---|---|
| mạng nội bộ/nhà mạng | | | | | |
| dịch vụ entry/access | | | | | |
| operator trung chuyển | | | | | |
| exit/redirector/CDN | | | | | |
| DNS có thẩm quyền/registrar | | | | | |
| mục tiêu | | | | | |
| nhà cung cấp tài khoản/thanh toán | | | | | |

Nếu một nhà cung cấp thông thường có thể điền mọi cột, kiến trúc chỉ che giấu hoạt động khỏi mục tiêu chứ không tạo được sự phân tách vững chắc. Nếu không controller nội bộ nào có thể liên kết hoạt động với một cuộc diễn tập, kiến trúc đó không phù hợp cho red teaming chuyên nghiệp.

## References

- [1] [MITRE ATT&CK — Thu thập hạ tầng (T1583), Xâm nhập hạ tầng (T1584) và Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Các actor gián điệp có liên hệ với Trung Quốc sử dụng mạng ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Xâm nhập hạ tầng: Domain (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Thiết lập tài khoản (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: Liên lạc một chiều (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Kênh nhiều giai đoạn (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Phá vỡ mạng proxy dân cư lớn nhất thế giới](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Các chiến dịch Shadow: Phát hiện hoạt động gián điệp toàn cầu](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Chiến dịch Blinder Tunnel nhắm vào hạ tầng Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI xây dựng các lớp phủ. Nạn nhân mất mã PIN](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
