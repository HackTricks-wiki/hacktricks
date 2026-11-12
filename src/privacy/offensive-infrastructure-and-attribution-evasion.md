# Hạ tầng tấn công và né tránh quy kết

{{#include ../banners/hacktricks-training.md}}

Một operator hiếm khi có được tính ẩn danh đáng kể chỉ nhờ một proxy. Các chiến dịch thực tế xây dựng **đồ thị phân tách**: operator kết nối đến một access node, các traversal node che giấu node đó khỏi exit, redirector bảo vệ C2 thực sự, còn các tên miền dùng một lần trỏ đến edge công khai.

Sử dụng [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) để xem tổng quan đã chuẩn hóa về ưu/nhược điểm, cách triển khai và phát hiện của từng đường kết nối. Trang này đi sâu hơn vào cách kết hợp hạ tầng đối kháng.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Địa chỉ cuối cùng mà mục tiêu nhìn thấy do đó là bằng chứng về một đường đi, chứ không phải bằng chứng về người đã điều khiển bàn phím. MITRE ánh xạ các thành phần chính với Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) và Web Service (T1102).<sup>[[1]](#references)</sup>

## Các lớp hạ tầng

| Lớp | Vì sao tác nhân sử dụng | Dấu vết phơi lộ lâu dài | Điểm pivot tốt nhất cho bên phòng thủ |
|---|---|---|---|
| VPS/cloud thuê | Nhanh, dễ dự đoán, có thể định tuyến, dễ dựng lại | tenant, thanh toán, console, lịch sử đăng nhập nguồn và image | sự kiện tài khoản/control plane và dấu vân tay máy chủ lặp lại |
| VPN thương mại/Tor | Tập hợp egress dùng chung lớn; không cần quản trị máy chủ | khả năng quan sát của nhà cung cấp/bên giám sát và timing đầu-cuối | hành vi đích, bằng chứng endpoint và tương quan luồng |
| Proxy residential/mobile | ASN của người dùng và tính hợp lý về địa lý | hồ sơ broker/khách hàng; hành vi proxyware hoặc host bị nhiễm | di chuyển bất khả thi, giao thức proxy và biến động địa chỉ theo phiên |
| Máy chủ/router/IoT bị xâm nhập | Mượn uy tín và thẩm quyền tài phán của nạn nhân | implant, luồng quản lý và controller thượng nguồn lặp lại | telemetry thiết bị và cấu trúc ORB, không phải một IP thoát đơn lẻ |
| CDN/redirector | Tách edge công khai khỏi C2 back-end | dấu vết TLS/HTTP, certificate, định tuyến và tài khoản cloud | tương quan edge với origin và phân cụm hình dạng request |
| Dịch vụ web hợp pháp | Hòa lẫn vào lưu lượng GitHub/cloud/social được cho phép | API token, tenant/object identifier và lineage tiến trình bất thường | tiến trình endpoint cùng ngữ nghĩa service/API |
| Đường truyền vật lý/di động/vệ tinh | Thay đổi nguồn gốc vật lý được nhìn thấy | hồ sơ RF, nhà mạng, thuê bao, thiết bị và vị trí | kết hợp bằng chứng vô tuyến/vật lý với bằng chứng mạng |

## Các mạng ORB relay vận hành

**Mạng ORB** là một đội proxy được quản lý, dùng làm dịch vụ trung gian. Mandiant chia chúng thành các mạng được cung cấp sẵn gồm máy chủ thuê, mạng không được cung cấp sẵn gồm router/IoT bị xâm nhập và mạng lai. Một cấu trúc trưởng thành có bốn vai trò logic:<sup>[[2]](#references)</sup>

1. **Máy chủ quản trị (ACOS):** duy trì danh mục, thông tin xác thực, tình trạng hoạt động và chính sách định tuyến.
2. **Node truy cập/relay:** xác thực khách hàng hoặc người vận hành; đây là điểm vào ổn định của một mesh luôn thay đổi.
3. **Node chuyển tiếp:** một hoặc nhiều hệ thống thuê hoặc bị xâm nhập chuyển tiếp các kết nối không đọc được nội dung.
4. **Node thoát/staging:** cung cấp địa chỉ nguồn cuối cùng cho các mục tiêu trinh sát, khai thác hoặc C2.

Mesh có thể chọn node thoát theo quốc gia, ASN, độ trễ hoặc tình trạng sẵn sàng, đồng thời thay thế các node không khỏe. Nhiều nhóm đe dọa có thể thuê cùng một mạng. Mandiant quan sát thấy một địa chỉ IPv4 chỉ còn được liên kết với một số ORB trong 31 ngày; vì vậy, họ khuyến nghị xem **mạng như một thực thể đang tiến hóa, có đặc điểm giống tác nhân**, thay vì chặn một danh sách IP đã lỗi thời.<sup>[[2]](#references)</sup>

### Cách này mang lại lợi ích gì—và nó làm lộ những gì

- Mục tiêu nhìn thấy một node thoát có thể nằm gần về mặt địa lý và có vẻ là residential.
- Node thoát nhìn thấy mục tiêu và hop trước đó, nhưng không nhất thiết biết người vận hành.
- Dịch vụ truy cập nhìn thấy khách hàng và yêu cầu định tuyến. Một mesh được quản lý độc lập có thể giữ tách biệt thông tin khách hàng với các node thoát, nhưng lại tạo ra hồ sơ đối tác có giá trị lớn.
- Cổng lặp lại, thứ tự handshake, banner máy chủ, certificate, khoảng thời gian hoạt động và mối quan hệ với controller có thể làm lộ đội node ngay cả khi IP liên tục thay đổi.
- Router bị xâm nhập thường thiếu telemetry endpoint, nhưng ISP của nó vẫn có dữ liệu thuê bao và luồng; việc thu giữ sẽ làm lộ các dấu vết implant/cấu hình.

{% hint style="info" %}
Trong một bài diễn tập được cho phép, hãy tái tạo cấu trúc liên kết bằng VM hoặc router thuộc sở hữu của tổ chức và lưu giữ bản đồ quy kết của controller. Không huy động proxy công khai hoặc thiết bị của bên thứ ba. [Hướng dẫn lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) tạo ra cùng cấu trúc hop mà bên phòng thủ có thể quan sát mà không biến một bên trung gian thành nạn nhân.
{% endhint %}

## Mạng proxy residential và mobile

Các dịch vụ proxy residential gán phiên cho địa chỉ băng thông rộng của người dùng; proxy mobile egress thông qua các pool NAT của nhà mạng. Nguồn cung có thể đến từ thiết bị được đăng ký rõ ràng, SDK/proxyware được đóng gói trong ứng dụng dành cho người dùng, đại lý bán lại hoặc malware. Những nguồn này không tương đương nhau: thiếu sự đồng thuận đầy đủ biến một dịch vụ bảo vệ quyền riêng tư thành hạ tầng bị xâm nhập.

Các chế độ xoay vòng ảnh hưởng đến khả năng phát hiện:

- **xoay vòng theo từng request** tạo ra biến động nhanh về IP và ASN/địa lý trong khi danh tính ở các lớp cao hơn vẫn ổn định;
- **phiên cố định (sticky sessions)** giữ nguyên một node thoát trong vài phút hoặc vài giờ, trông giống một thuê bao thông thường;
- **cổng backconnect** chỉ hiển thị một endpoint broker cho khách hàng và tự chọn node thoát ở bên trong;
- **pool mobile** đưa nhiều thuê bao thật vào sau một số ít địa chỉ NAT của nhà mạng, khiến việc chặn IP gây tốn kém.

Bên phòng thủ nên tương quan IP với phiên đã xác thực, dấu vân tay TLS/client, thứ tự HTTP, cookie thiết bị và hành vi. Một lần đăng nhập residential được cho là tại địa phương rồi tiếp theo là một lần đăng nhập từ quốc gia khác, trong khi mọi đặc điểm ở các lớp cao hơn vẫn giống hệt nhau, là tín hiệu mạnh hơn chỉ dựa vào danh tiếng. Ngược lại, việc dùng chung địa chỉ và chuyển giao giữa các trạm di động tạo ra biến động hợp lệ, vì vậy đừng bao giờ xem phân loại residential/proxy là kết luận cuối cùng.

### Control plane của proxyware và sự trùng lặp giữa các đại lý bán lại

Đừng mô hình hóa một pool residential như một danh sách node thoát phẳng. Phân tích hệ sinh thái IPIDEA cho thấy một **control plane hai tầng có thể tái sử dụng**: SDK được nhúng trước tiên gửi metadata thiết bị/đăng ký đến một domain Tier One, rồi nhận thông tin lập lịch cùng các cặp IP:port `connect`/`proxy` của Tier Two. Node định kỳ thăm dò cổng connect Tier Two để lấy một tác vụ được mã hóa, mở kết nối thứ hai đến cổng proxy tương ứng, rồi chuyển tiếp các byte được cung cấp đến đích được yêu cầu. Các SDK và thương hiệu proxy có vẻ khác nhau sử dụng domain discovery riêng, nhưng lại hội tụ vào hạ tầng Tier Two dùng chung và các pool node thoát chồng lấn thông qua quan hệ sở hữu chung và đại lý bán lại.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Điều này tạo ra các pivot săn tìm bền vững hơn một block IP dân dụng:<sup>[[13]](#references)</sup>

- một tiến trình tiện ích, VPN, trò chơi hoặc thiết bị nhúng bất ngờ gửi ID thiết bị/khóa khách hàng ổn định và nhận về danh sách máy chủ thay đổi;
- endpoint thăm dò một IP trực tiếp trên cổng bất thường, rồi kết nối đến một cổng khác trên cùng địa chỉ ngay trước khi mở socket đích mới;
- một số thương hiệu có vẻ khác nhau dùng chung địa chỉ Tier Two, cú pháp giao thức, mã SDK hoặc vùng giao nhau của các exit node;
- các ứng dụng riêng biệt liên hệ với những domain Tier One khác nhau nhưng nhận địa chỉ từ cùng một pool Tier Two.

Sự trùng lặp này cũng hạn chế khả năng quy kết: việc thấy một IP trong pool được một nhà cung cấp quảng bá không chứng minh reseller, khách hàng hay threat actor nào đã sử dụng IP đó vào thời điểm liên quan. Hãy lưu lại timestamp của luồng, nguồn gốc tiến trình, nội dung phản hồi Tier One và mã định danh tác vụ Tier Two.<sup>[[13]](#references)</sup> Trong một bài tập được cấp phép, chỉ mô phỏng cấu trúc phân cấp này bằng endpoint thuộc tổ chức; tuyệt đối không đăng ký thiết bị của người tiêu dùng hoặc proxyware của bên thứ ba.

## Chuỗi proxy nhiều hop

MITRE phân biệt external proxies với **multi-hop proxies (T1090.003)**. Đặc tính quan trọng không phải là số hop mà là sự tách biệt về thông tin và quản trị.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Nếu một bên vận hành cả A và B, log dùng chung hoặc thời điểm lưu lượng có thể giúp tái dựng circuit. Thêm nhiều VPN thương mại nối tiếp từ cùng endpoint/account có thể làm tăng độ trễ nhưng vẫn để lộ bằng chứng về danh tính, thanh toán và thời điểm chung. Tor giảm vấn đề này nhờ các relay được chọn độc lập và thiết kế client dùng chung, nhưng một mạng tương tác có độ trễ thấp không thể đảm bảo chống lại một bên quan sát đo lường cả hai đầu.

Các lỗi thường gặp gồm DNS hoặc IPv6 bypass, ứng dụng tự mở socket, lưu lượng quản lý kết nối trực tiếp đến relay, hoạt động đồng bộ, dùng lại SSH key và đăng nhập vào các account định danh. Cách xác minh đúng là kiểm tra khi xảy ra lỗi: lần lượt dừng từng relay và chứng minh workload không thể chuyển sang đường truyền không mã hóa.

### Sụp đổ tunnel và rò rỉ upstream

Kiến trúc relay thường dễ bị quy kết nhất khi xảy ra lỗi. Unit 42 ghi nhận một đường đi gián điệp nhiều tầng sử dụng VPS hướng đến nạn nhân, relay VPS, residential proxy, Tor và các dịch vụ proxy khác; khi một tunnel bị bỏ sót hoặc sụp đổ, hạ tầng upstream ẩn kết nối trực tiếp đến relay và các hệ thống hướng đến nạn nhân. Cuộc điều tra tương tự cũng dùng một chứng chỉ X.509 tạm thời bị lộ trên hạ tầng upstream làm điểm pivot xuyên tầng.<sup>[[14]](#references)</sup>

Tách riêng **data plane** (`victim <-> exit`) khỏi **control plane** (`operator/upstream -> relay administration`). Lưu giữ log ingress và xác thực ở mọi tầng do bạn sở hữu, lịch sử chứng chỉ và các kết nối lỗi ngắn—không chỉ các phiên C2 thành công. Một nguồn chỉ xuất hiện khi relay gặp sự cố hoặc trực tiếp quản trị nhiều node hướng đến nạn nhân là ứng viên upstream đáng chú ý hơn một exit thông thường, nhưng ASN/geolocation vẫn chỉ là giả thuyết, không phải bằng chứng về danh tính operator.

Một lab được cấp phép cần khiến workload fail closed. Với workload được cô lập trong Linux network namespace, route đầu tiên phải đi qua tunnel; sau khi gỡ tunnel, cả request lẫn tra cứu route đều phải thất bại thay vì chọn uplink vật lý:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Lặp lại bài kiểm tra với DNS và IPv6, cũng như tại mỗi ranh giới relay. Nếu bất kỳ probe nào thành công, hãy ghi lại interface/địa chỉ nguồn thực tế trước khi sửa policy routing hoặc firewall; quan sát đó chính là attribution leak mà điều tra viên sẽ thấy.

## Các tầng redirector và định hình lưu lượng

Một **redirector** công khai chấp nhận lưu lượng khớp với grammar dành riêng cho từng operation và chuyển tiếp lưu lượng đó đến team server được bảo vệ. Mọi thứ khác có thể bị từ chối hoặc được phản hồi bằng nội dung vô hại.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Nhiều tầng giúp hạn chế mức độ lộ diện: để lộ một tên miền công khai không nhất thiết phải làm lộ team server. CDN bổ sung năng lực anycast và một tên miền bên ngoài có uy tín, nhưng tài khoản CDN và log tại edge trở thành điểm có thể dùng để quy kết. TLS fingerprint, lịch sử chứng chỉ, đường dẫn/thứ tự header đặc trưng, kích thước phản hồi, hành vi chuyển hướng và danh sách cho phép của origin có thể liên kết các front tưởng như không liên quan.

Để phát hiện, hãy ghi lại các trường reverse-proxy trước khi chuẩn hóa, so sánh SNI/Host/authority, kiểm tra các tổ hợp header hiếm gặp, phân cụm nội dung phản hồi và TLS fingerprint, đồng thời tìm các cấu hình trùng lặp trong audit log của cloud/CDN. Với red team được ủy quyền, tránh sao chép thương hiệu thật hoặc đặt hệ thống thu thập thông tin xác thực sau một bên thứ ba không liên quan.

## Domain fronting và domainless fronting

Với **domain fronting (T1090.004)** cổ điển, kết nối TLS quảng bá một front domain được cho phép trong SNI, trong khi `Host` HTTP hoặc `:authority` của HTTP/2 được mã hóa lại yêu cầu một back-end domain khác. CDN phối hợp sẽ định tuyến dựa trên giá trị bên trong. Người quan sát mạng không giải mã TLS chỉ thấy front; CDN thấy cả hai giá trị và origin. Trong các biến thể domainless, SNI có thể để trống trong khi một trường định tuyến khác chọn đích.<sup>[[4]](#references)</sup>

Đây không phải là giả mạo thần kỳ: kỹ thuật này chỉ hoạt động khi intermediary cố ý hoặc vô tình cho phép sự không khớp và biết cách định tuyến theo tên bên trong. Các nhà cung cấp lớn đã hạn chế domain fronting xuyên tài khoản. Encrypted ClientHello (ECH) thay đổi những gì người quan sát trên đường truyền có thể thấy, nhưng không xóa các bản ghi của CDN, endpoint hoặc ứng dụng.

Các điểm cần kiểm tra để phát hiện gồm:

- quan hệ tiến trình của endpoint và đích đến không được ứng dụng đó mong đợi;
- SNI không khớp với HTTP authority, trong trường hợp việc kiểm tra TLS hợp pháp và khả dụng;
- log CDN cho thấy một tenant/front định tuyến đến authority/origin khác;
- các phiên kéo dài bất thường hoặc định kỳ đến một dịch vụ vốn thường có tương tác;
- kích thước và nhịp luồng mã hóa ổn định dù front domain thay đổi.

Lab an toàn mô phỏng sự không khớp định tuyến trên reverse proxy do mình sở hữu; không lạm dụng CDN công khai.

## Phân giải động: DDNS, DGA và fast flux

Phân giải động tách một dịch vụ logic khỏi hạ tầng cố định:

- **DDNS:** một client đã xác thực cập nhật tên ổn định sau khi địa chỉ của nó thay đổi.
- **DGA:** endpoint suy ra tên miền từ một seed, thường là thời gian hoặc khóa nhưng đôi khi là nội dung công khai có thể thay đổi; operator cấu hình DNS cho tên đang hoạt động.<sup>[[17]](#references)</sup>
- **Fast flux:** một tên miền trả về một tập hợp địa chỉ bị xâm nhập/proxy thay đổi nhanh chóng, thường có TTL thấp.
- **Double flux:** cả địa chỉ dịch vụ lẫn địa chỉ của name server có thẩm quyền đều luân phiên, khiến cả lớp điều khiển cũng bị che giấu.

Fast flux là một kiểu phân phối tải được dùng với mục đích đối kháng, chứ không chỉ đơn giản là “nhiều câu trả lời DNS”. Bằng chứng mạnh hơn kết hợp TTL thấp, số lượng địa chỉ duy nhất cao, độ phân tán lớn về ASN/địa lý, thời gian tồn tại ngắn của node, hành vi ứng dụng lặp lại và lịch sử đăng ký đáng ngờ. CDN cũng có nhiều đặc điểm tương tự một cách hợp pháp. MITRE khuyến nghị tương quan hành vi DNS với tiến trình và các kết nối tiếp theo.<sup>[[5]](#references)</sup>

Có thể phát hiện DGA qua entropy từ vựng, mẫu phụ âm/chữ số, các đợt NXDOMAIN, những domain lần đầu xuất hiện đồng bộ và ngữ cảnh tiến trình. DGA dùng wordlist và mô hình tạo sinh có thể vượt qua các quy tắc entropy đơn giản, vì vậy việc phân cụm theo thời gian trên toàn bộ hệ thống và truy vết nguồn gốc endpoint càng quan trọng.

### Seed ảnh có thể thay đổi cho DGA dùng wordlist

DGA không nhất thiết phải phụ thuộc vào thời gian. Một loader tải trang của một kênh Telegram công khai, đọc `src` của phần tử `tgme_page_photo_image`, tải ảnh hồ sơ đó xuống và băm **50 byte cuối cùng của tệp** thay vì các pixel đã giải mã. Bốn seed hash chọn một tính từ, danh từ, động từ và số. Thay đổi ảnh sẽ làm thay đổi tên DNS được suy ra mà không cần phát hành client mới. Hãy giữ nguyên chính xác byte của ảnh đã tải xuống và cùng thứ tự word list ở cả hai phía; mã hóa lại ảnh hoặc sắp xếp lại danh sách sẽ tạo ra các tên khác.<sup>[[17]](#references)</sup>

Khi đã khôi phục được word list từ client, cách này tái tạo bước chọn tên. Hash theo byte của mã nguồn sử dụng bộ tích lũy 64-bit, hệ số nhân `0x1000193` và seed riêng cho từng thành phần:<sup>[[17]](#references)</sup>

<details>
<summary>Tái tạo bước chọn tên từ word list được seed bằng ảnh</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

Khác với [dead-drop resolver](#web-services-and-dead-drop-resolvers) công bố chính endpoint, đối tượng công khai ở đây chỉ cung cấp một seed có thể thay đổi; client tự suy ra endpoint tại chỗ.

Sau đó, tên được tạo ra sẽ được dùng để truy vấn bản ghi DNS TXT thông qua `https://dns.google/resolve?name=<domain>&type=TXT`. Client giải mã Base64 trường `data` trong phản hồi JSON, xác minh chữ ký Ed25519 bằng public key được nhúng, rồi mới giải mã command bằng AES-ECB. Plaintext được quan sát bắt đầu bằng một bộ chọn phương thức và URL trỏ đến payload đã mã hóa. Việc kiểm tra chữ ký có nghĩa là chỉ riêng một bản ghi TXT phân giải được thì không thể cung cấp tasking được chấp nhận.<sup>[[17]](#references)</sup>

## Các domain bị xâm phạm và domain shadowing

Một tác nhân có thể chiếm quyền tài khoản registrar/DNS, tiếp quản một subdomain bị bỏ quên, hoặc thêm bản ghi bên dưới một domain vốn có uy tín. **Domain shadowing** giữ nguyên apex hợp pháp trong khi một số lượng lớn subdomain do kẻ tấn công kiểm soát trỏ đến các máy chủ phân phối hoặc C2 thay đổi liên tục. Cách này tận dụng tuổi đời và uy tín, đồng thời có thể né tránh việc chặn trên toàn domain.<sup>[[6]](#references)</sup>

Đội phòng thủ cần nhật ký kiểm tra registrar và authoritative DNS, MFA, khóa registry/registrar, cảnh báo về delegation/API token/name server mới, giám sát certificate transparency và kiểm kê tài nguyên cloud được DNS tham chiếu. Hãy điều tra lịch sử phân giải và chứng chỉ của subdomain độc lập với uy tín của apex.

## Web service và dead-drop resolver

**Dead-drop resolver (T1102.001)** lưu trữ một con trỏ đã mã hóa đến C2 hiện tại bên trong một bài đăng, hồ sơ, tài liệu, repository, cloud object hoặc trường blockchain hợp pháp. Malware tải đối tượng công khai, giải mã domain/IP rồi liên hệ với giai đoạn tiếp theo. Các biến thể hai chiều trao đổi command hoặc file thông qua API của dịch vụ.<sup>[[7]](#references)</sup>

Một biến thể resolver dành riêng cho GitHub chỉ sử dụng Issues Search API khi kênh repository đã xác thực gặp lỗi. Client tìm các issue khớp với ngày hiện tại, repository và loại issue, truy cập URL bình luận của từng issue, rồi trích xuất ciphertext nằm giữa các dấu `<!--` và `-->`. Sau khi giải mã bằng khóa riêng cho từng host và được suy ra từ ngày, các trường như `Owner`, `LicRepo` và `LicToken` thay thế owner, đường dẫn và token của repository chính. Điều này cho phép operator xoay vòng thông tin xác thực và endpoint mà không cần thay client; bình luận issue đóng vai trò resolver, còn các file trong repository vẫn là kênh tasking.<sup>[[15]](#references)</sup>

Một biến thể Android chọn một trong hai trang Telegram công khai khi khởi động và trích xuất ciphertext nằm giữa hai lần xuất hiện của một marker được nhúng trong APK. Nó giải mã giá trị bằng Base64URL rồi giải mã bằng AES-128-CBC: 16 byte đầu tiên của `SHA-256(marker)` là key, 16 byte tiếp theo là IV. Plaintext là URL cơ sở C2 thực tế, không phải URL trang Telegram. Khi tái tạo quy trình phân giải, hãy giữ nguyên nội dung trang và marker chính xác; thay đổi trang công khai sẽ xoay vòng endpoint mà không cần dựng lại APK.<sup>[[16]](#references)</sup>

Cách này tăng khả năng chống chịu và che giấu C2 phía sau khỏi việc phân tích tĩnh binary. Tuy nhiên, nó cũng tạo ra các định danh ổn định như đối tượng, tenant, repository, API và mẫu truy cập. Đội phòng thủ nên liên kết:

1. tiến trình đã liên hệ với dịch vụ;
2. đường dẫn API/đối tượng chính xác và hash phản hồi;
3. hoạt động giải mã hoặc xử lý chuỗi;
4. kết nối outbound mới ngay sau đó; và
5. hành vi giống hệt ở nơi khác trong toàn bộ hệ thống.

Việc chặn toàn bộ GitHub, cloud storage hoặc mạng xã hội hiếm khi khả thi. Chính sách egress nhận biết dịch vụ và đối chiếu ở cấp tiến trình hiệu quả hơn chặn chỉ dựa trên domain.

## Persona, tài khoản và các ngăn cách biệt trong khâu mua sắm

Tính ẩn danh của hạ tầng thất bại khi persona, email khôi phục, điện thoại, thanh toán, trình duyệt hoặc IP quản trị nối liền các ngăn cách biệt. Các chiến dịch có liên hệ với nhà nước đã xây dựng hồ sơ mạng xã hội, danh tính email và tài khoản cloud từ lâu trước khi sử dụng; ATT&CK ghi nhận việc này là Establish Accounts (T1585), bao gồm các kỹ thuật con về mạng xã hội, email và cloud.<sup>[[8]](#references)</sup>

Đội phòng thủ hoặc điều tra viên xây dựng đồ thị dựa trên:

- thời điểm tạo và đăng nhập lần đầu, locale, múi giờ và lịch hoạt động;
- trường khôi phục, thiết bị MFA, giấy tờ tùy thân và phương tiện thanh toán;
- fingerprint trình duyệt/TLS và lịch sử mạng nguồn;
- việc tái sử dụng avatar, nguồn gốc hình ảnh, văn phong và sự phát triển của đồ thị xã hội;
- registrant domain, name server, chứng chỉ, analytics ID hoặc commit repository dùng chung;
- các hành động trên management plane bỏ qua kiến trúc relay công khai.

Với red team được ủy quyền, persona tổng hợp cần được ghi lại để người điều phối diễn tập nắm được, sử dụng kênh khôi phục/thanh toán thuộc sở hữu của tổ chức, tránh mạo danh người thật không liên quan và có kế hoạch ngừng sử dụng. SOC có thể vẫn không biết; nhưng hoạt động không được trở thành vô trách nhiệm.

## Các mô hình kết hợp mới nổi cần threat-model

Dưới đây là các **cách kết hợp do đội phòng thủ xây dựng**, không phải tuyên bố rằng một tác nhân cụ thể đã triển khai chính xác từng thiết kế. Chúng kết hợp các thành phần cơ bản đã được quan sát và hữu ích làm giả thuyết cho purple team.

### Tasking một chiều bất đối xứng

Command đến từ một nguồn công khai, broadcast hoặc append-only, trong khi kết quả được gửi qua một kênh không liên quan sau một khoảng trễ. Các thành phần cơ bản gồm giao tiếp một chiều qua web service và dead drop. Việc tách kênh khiến một luồng đơn lẻ không có vẻ giao tiếp hai chiều và gây khó khăn cho việc đối chiếu yêu cầu/phản hồi đơn giản.<sup>[[9]](#references)</sup>

**Phát hiện:** lưu giữ dữ liệu đọc ở cấp đối tượng, sau đó đối chiếu các thay đổi trạng thái tiến trình với những lần truyền outbound sau đó trong một khoảng thời gian rộng hơn. Tìm tiến trình hiếm đọc cùng một đối tượng công khai, kể cả khi không có phản hồi ngay lập tức.

### Nâng cấp kênh nhiều giai đoạn

Giai đoạn đầu ít gây chú ý thực hiện kiểm kê và chỉ chuyển một số hệ thống được chọn sang kênh giai đoạn hai không liên quan. Endpoint, giao thức và tiến trình thứ hai có thể không dùng chung hạ tầng nào với giai đoạn đầu. Cách này hạn chế việc để lộ hạ tầng có năng lực và được mô hình hóa rõ ràng trong ATT&CK T1104.<sup>[[10]](#references)</sup>

**Phát hiện:** liên kết `tiến trình mạng đầu tiên -> trạng thái đã tải xuống/được cấu hình -> tiến trình mới hoặc injection -> đích không liên quan`; đừng kết thúc sự cố sau khi chặn domain đầu tiên.

### Chuyển dịch relay xuyên giao thức

Các hop khác nhau chuyển đổi HTTPS, QUIC, WebSocket, DNS, SSH hoặc API message queue thay vì chuyển tiếp packet một cách trong suốt. Việc chuyển đổi loại bỏ một fingerprint giao thức đầu-cuối duy nhất, nhưng tạo ra các gateway có đặc điểm riêng về thời gian, buffering và chuyển đổi ngữ nghĩa. Protocol tunneling (T1572) có thể kết hợp với proxy và giả mạo dịch vụ.<sup>[[11]](#references)</sup>

**Phát hiện:** tìm các host gateway nhận một giao thức rồi khởi tạo giao thức khác với hành vi byte/thời gian gắn kết chặt chẽ; so sánh mục đích của endpoint với giao thức thực tế được truyền tải.

### Kích hoạt thụ động trên thiết bị biên

Thay vì beacon, implant theo dõi lưu lượng vốn đã đến router/VPN và chỉ kích hoạt khi nhận một giá trị magic, mẫu source-port hoặc token đã xác thực. Lưu lượng bình thường vẫn tiếp tục đến dịch vụ thực. ATT&CK gọi kỹ thuật này là Traffic Signaling (T1205), với các ví dụ đã ghi nhận về thiết bị mạng và APT.<sup>[[12]](#references)</sup>

**Phát hiện:** kiểm tra tính toàn vẹn firmware/file, capture packet thô trong quá trình hunt được ủy quyền, socket filter bất thường và hành vi dịch vụ khác biệt. Không có beacon định kỳ không chứng minh được thiết bị biên sạch.

### Xoay vòng origin serverless và tồn tại ngắn hạn

Một front giữ danh tính logic ổn định trong khi các function/container tồn tại ngắn hạn xử lý từng giai đoạn ở nhiều region/account. Cách này giảm thời gian tồn tại trên đĩa và loại bỏ IP origin cố định, nhưng việc tạo tài nguyên trên control plane, image/layer, role, secret, request ID và dữ liệu billing trở thành đồ thị bền vững.

**Phát hiện:** lưu giữ nhật ký audit và invocation của cloud bên ngoài workload; phân cụm deployment template, role, environment key và mối quan hệ front-to-origin.

### Đa dạng hóa lớp bảo vệ quyền riêng tư

Một chiến dịch có thể chủ ý tránh một chuỗi đồng nhất: chẳng hạn, một kênh dùng relay thuê, tasking dùng đối tượng công khai, exit đến từ liên kết cellular phòng lab thuộc sở hữu riêng, còn hoạt động quản trị dùng mạng tổ chức riêng. Cách này giảm giá trị của việc xâm nhập một nhà cung cấp, nhưng làm tăng rủi ro đối chiếu thời gian giữa các lớp và sai sót vận hành.

**Phát hiện:** xây dựng dòng thời gian chiến dịch trên các cảm biến identity, DNS, SaaS, network và cloud. Tìm các chuyển đổi trạng thái đồng bộ thay vì chỉ báo giống hệt nhau.

### Dead drop phi tập trung hoặc trên transparency log

Một tác nhân có thể đặt một con trỏ mã hóa nhỏ trong bất kỳ hệ thống append-only công khai, kho lưu trữ content-addressed hoặc luồng kiểu transparency nào có tính bền vững. Đối tượng công khai có khả năng chống chịu cao, nhưng index/hash nội dung chính xác và hành vi polling của client trở thành các định danh ổn định.

**Phát hiện:** ghi lại đầy đủ định danh API/đối tượng và hash phản hồi; cảnh báo khi tiến trình bất thường polling các đối tượng bất biến rồi giải mã hoặc tạo kết nối mới.

### Hoạt động store-and-forward có độ trễ

C2 tương tác tạo ra tương quan thời gian rõ rệt. Thiết kế store-and-forward gom các job mã hóa thành lô và trả kết quả sau vài phút hoặc vài giờ thông qua một queue khác hoặc chuyển giao vật lý. Cách này hy sinh khả năng phản hồi để làm yếu tương quan thời gian đầu-cuối.

**Phát hiện:** kéo dài cửa sổ đối chiếu, mô hình hóa việc truy cập queue định kỳ và kiểm tra hoạt động staging trên endpoint. Việc gom lô chuyển tín hiệu từ thời gian packet sang hành vi tiến trình/file theo lịch; nó không xóa bỏ tín hiệu.

## Rà soát thiết kế: suy nghĩ theo góc nhìn của các bên quan sát

Với mỗi đường đi, hãy điền bảng này trước khi triển khai và sau khi thu thập dữ liệu:

| Lớp | Thấy nguồn? | Thấy đích? | Thấy nội dung? | Định danh ổn định | Chủ thể lưu giữ/pháp lý |
|---|---:|---:|---:|---|---|
| mạng cục bộ/nhà mạng | | | | | |
| dịch vụ truy cập/đầu vào | | | | | |
| operator trung chuyển | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| mục tiêu | | | | | |
| nhà cung cấp tài khoản/thanh toán | | | | | |

Nếu một nhà cung cấp thông thường có thể điền mọi cột, kiến trúc đó giúp che giấu trước mục tiêu nhưng không tạo ra sự phân tách vững chắc. Nếu không có người điều phối nội bộ nào có thể quy hoạt động về một đợt diễn tập, kiến trúc đó không phù hợp với red teaming chuyên nghiệp.

## References

- [1] [MITRE ATT&CK — Thu thập hạ tầng (T1583), Xâm phạm hạ tầng (T1584) và Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Các tác nhân gián điệp có liên hệ với Trung Quốc sử dụng mạng ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Xâm phạm hạ tầng: Domain (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Thiết lập tài khoản (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: Giao tiếp một chiều (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Kênh nhiều giai đoạn (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Phá vỡ mạng proxy residential lớn nhất thế giới](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Các chiến dịch Shadow: Phát hiện hoạt động gián điệp toàn cầu](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Chiến dịch Blinder Tunnel nhắm vào hạ tầng Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI tạo các lớp phủ. Nạn nhân mất mã PIN](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Thủ thuật cũ được triển khai thông qua binary ChatGPT và Claude có chữ ký](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
