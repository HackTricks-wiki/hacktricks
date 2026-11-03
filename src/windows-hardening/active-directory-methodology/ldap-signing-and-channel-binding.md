# Tăng cường bảo mật LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Vì sao điều này quan trọng

Các cuộc tấn công LDAP relay/MITM chuyển tiếp quá trình xác thực đến domain controller để lấy ngữ cảnh LDAP đã xác thực. [Tổng quan về đầu độc phân giải tên và relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) trình bày quy trình tổng thể. Hai biện pháp kiểm soát liên quan giúp giảm thiểu các hướng tấn công này:

- **LDAP channel binding (CBT)** liên kết quá trình xác thực tương ứng với chứng chỉ/kênh TLS của máy chủ được dùng bởi LDAPS, gây khó khăn cho relay xuyên kênh.
- **LDAP signing** yêu cầu bảo vệ tính toàn vẹn cho các LDAP bind qua SASL. Cơ chế này không bổ sung tính bảo mật; hãy dùng TLS nếu nội dung LDAP cũng cần được mã hóa.<sup>[[2]](#references)</sup>

**Kiểm tra nhanh trạng thái bảo mật**: các công cụ như `netexec ldap <dc> -u user -p pass` báo cáo chính sách signing và channel binding được quan sát. `(signing:None)` và `(channel binding:Never)` cho thấy thiếu các biện pháp kiểm soát này, nhưng relay thành công vẫn phụ thuộc vào loại xác thực bị thu thập, hành vi EPA, đặc quyền tài khoản, giao thức đích và các biện pháp bảo vệ relay. Khi principal bị relay có đủ quyền cần thiết, các công cụ như KrbRelayUp có thể ghi `msDS-AllowedToActOnBehalfOfOtherIdentity`, cấu hình resource-based constrained delegation (RBCD) và sử dụng đường dẫn delegation thu được để mạo danh một principal đặc quyền.<sup>[[4]](#references)</sup>

**Các DC chạy Server 2025** giới thiệu GPO mới (**LDAP server signing requirements Enforcement**), mặc định đặt thành **Require Signing** nếu để **Not Configured**. Để tránh việc thực thi chính sách, bạn phải đặt rõ chính sách này thành **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (chỉ LDAPS)

- **Yêu cầu**:
  - Bản vá CVE-2017-8563 (2017) bổ sung hỗ trợ Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) bổ sung telemetry “what-if” cho LDAPS CBT.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (mặc định, không dùng CBT)
  - `When Supported` (thực thi một phần: client hỗ trợ CBT phải cung cấp token hợp lệ; client không hỗ trợ CBT vẫn có thể bind và các sự kiện audit được ghi lại)
  - `Always` (thực thi: từ chối LDAPS bind không có CBT hợp lệ)<sup>[[1]](#references)</sup>
- **Audit**: đặt thành **When Supported** để ghi nhận:
  - **3074** – LDAPS bind sẽ không vượt qua bước xác thực CBT nếu được thực thi.
  - **3075** – LDAPS bind không gửi dữ liệu CBT và sẽ bị từ chối nếu được thực thi.
  - (Sự kiện **3039** vẫn báo hiệu lỗi CBT trên các bản dựng cũ hơn.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Thực thi**: đặt thành **Always** khi client LDAPS gửi CBT; chỉ có hiệu lực với **LDAPS** (không áp dụng cho cổng 389 thuần).<sup>[[1]](#references)</sup>

`When Supported` không chỉ dùng cho audit: chính sách này xác thực CBT đối với client có hỗ trợ, đồng thời cho phép client không hỗ trợ CBT. [Tài liệu tham khảo chính sách của Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) mô tả các giá trị mặc định tùy theo phiên bản. LDAP signing áp dụng cho các bind tương ứng trên LDAP/389; channel binding áp dụng cho xác thực LDAP được bảo vệ bằng TLS.

## LDAP Signing

- **GPO client**: `Network security: LDAP client signing requirements` = `Require signing` (thay vì `Negotiate signing`, giá trị mặc định trên Windows hiện đại).<sup>[[1]](#references)</sup>
- **GPO DC**:
  - Cũ: `Domain controller: LDAP server signing requirements` = `Require signing` (mặc định là `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: giữ chính sách cũ ở `None` và đặt `LDAP server signing requirements Enforcement` = `Enabled` (mặc định sẽ thực thi nếu để Not Configured; đặt thành `Disabled` để tránh thực thi).<sup>[[1]](#references)</sup>
- **Khả năng tương thích**: kiểm kê các thiết bị và ứng dụng không chạy Windows đang dùng simple bind hoặc SASL bind không ký. Microsoft có tài liệu về hỗ trợ trên các phiên bản Windows còn được duy trì; cần xác minh các tuyên bố về khả năng tương thích với client cũ bằng stack client thực tế, thay vì rút gọn thành mốc phiên bản XP.<sup>[[2]](#references)</sup>

## Các đường relay và xác thực lại signed-SASL

Nếu **chỉ yêu cầu signing**, relay đến LDAPS vẫn có thể hoạt động khi channel binding chưa được thực thi: TLS cung cấp tính toàn vẹn cho kênh truyền tải. Nếu **chỉ yêu cầu channel binding**, LDAP thuần không có kênh TLS để liên kết; relay có thể xác thực qua TCP 389 rồi dùng StartTLS cho các thao tác cần TLS, miễn là danh tính bị relay có đủ quyền cần thiết. Thực thi cả hai sẽ đóng các phương án thông thường này, nhưng không ngăn được lỗ hổng sau trên các domain controller chưa vá.<sup>[[5]](#references)</sup>

### Xếp một thao tác LDAP sau Bind bị relay

Trên các domain controller Windows Server 2016–2025 bị ảnh hưởng, trước tiên hãy thiết lập **kết nối LDAP SASL NTLM đã ký** qua TCP 389 dưới danh tính X, bằng thông tin xác thực có session key mà bạn biết (hoặc ngữ cảnh NTLM SASL ẩn danh nếu được chấp nhận). Ép danh tính Y xác thực **qua SMB** đến relay. Chuyển tiếp NTLM NEGOTIATE của Y và CHALLENGE của DC qua các yêu cầu GSS-SPNEGO Bind trên kết nối LDAP hiện có của X. Windows SMB client đặt `NTLMSSP_NEGOTIATE_SIGN`, vì vậy LDAP bind được tạo ra yêu cầu lớp SASL đã ký; trao đổi bắt nguồn từ HTTP/WebDAV thường không có flag đó nên không thể thay thế trong trường hợp này.<sup>[[5]](#references)</sup>

Khi Y gửi NTLM AUTHENTICATE, đặt **hai thông điệp LDAP riêng biệt trong cùng một bản ghi SASL có tiền tố độ dài**: một BindRequest chứa phản hồi đó, sau đó là một ModifyRequest. Ký toàn bộ bản ghi bằng key đã biết của X. DC dễ bị tấn công xác minh bản ghi bằng key của X, hoàn tất Bind và chuyển quyền cấp phép của kết nối sang Y, rồi thực thi ModifyRequest còn lại dưới danh nghĩa Y mà không xác minh lại bản ghi bằng key của Y. Cách này không tiết lộ mật khẩu hoặc session key của Y; bản ghi tiếp theo được ký bằng X sẽ thất bại. Việc ghi RBCD vào `msDS-AllowedToActOnBehalfOfOtherIdentity` hoặc ghi shadow credential vào `msDS-KeyCredentialLink` vẫn yêu cầu Y có quyền trên đối tượng đích. Xem [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md), và [DCSync](dcsync.md) nếu relay tài khoản máy của DC.<sup>[[5]](#references)</sup>

Đây là cách vượt qua trên **LDAP thuần**, không phải cách vượt qua LDAPS channel binding. Trên LDAPS, TLS bảo vệ kết nối và Windows không thiết lập lớp ký NTLM SASL bằng key của X cần cho đường tấn công xếp bản ghi này. Nếu không khả dụng TCP 389, kỹ thuật này không thể đơn giản chuyển sang TCP 636. Các bản cập nhật bảo mật tháng 10/2026 ngăn thao tác trong cùng bản ghi bằng cách loại bỏ dữ liệu còn lại sau khi Bind thay đổi danh tính kết nối.<sup>[[5]](#references)</sup> KB5126646 là bản cập nhật dành cho Windows Server 2025; các bản Server bị ảnh hưởng khác có số KB riêng.<sup>[[7]](#references)</sup>

Công cụ [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) của nhà nghiên cứu sử dụng một bản `ntlmrelayx.py` đã chỉnh sửa cho quy trình này. Công cụ cần nguồn ép xác thực **SMB**, một cây Impacket được ghim phiên bản có các API LDAP signing/security-context (Impacket 0.13.1 trên PyPI không đáp ứng yêu cầu) và một tài khoản do kẻ tấn công kiểm soát để thực hiện signed bind ban đầu. Để ghi RBCD, cung cấp DN của đối tượng nạn nhân và SID của máy tính delegating do bạn kiểm soát; dùng `-attribute` cùng với `-value` hoặc `-value-hex` để ghi một giá trị khác được phép. Hãy xác nhận bằng thao tác đọc lại có ký độc lập của công cụ, thay vì xem thông báo `FAILED` ở phía relay là bằng chứng ModifyRequest thất bại.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Kích hoạt xác thực SMB riêng; xem [ép buộc xác thực NTLM với đặc quyền](printers-spooler-service-abuse.md) để biết một bề mặt cưỡng ép và [tổng quan về relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) để biết các bề mặt khác. Lệnh và cách triển khai của công cụ được tài liệu hóa trong repository của nó.<sup>[[6]](#references)</sup>

## Triển khai ưu tiên kiểm tra (khuyến nghị khoảng 30 ngày)

1. Bật chẩn đoán giao diện LDAP trên mỗi DC để ghi nhật ký các bind không ký (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Đặt GPO trên DC `LDAP server channel binding token requirements` = **When Supported** để thực thi CBT một phần và thu thập telemetry; trước tiên hãy xác thực khả năng tương thích với các client cũ.<sup>[[1]](#references)</sup>
3. Theo dõi các sự kiện Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – các bind không ký/cho phép không ký (không tuân thủ yêu cầu ký).
   - **3074/3075** – các bind LDAPS sẽ thất bại hoặc không có CBT (cần KB4520412 trên 2019/2022 và bước 2 ở trên).
4. Thực thi trong các thay đổi riêng biệt:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (client).
   - `LDAP server signing requirements` = **Require signing** (DC) **hoặc** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP Channel Binding và LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Yêu cầu LDAP channel binding và signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Bản cập nhật giảm thiểu LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (tắt LDAP signing → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Đã ký, niêm phong và relay theo kiểu NTLM](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Bằng chứng khái niệm LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Thông tin phát hành Windows Server](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
