# Tăng cường bảo mật LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Vì sao điều này quan trọng

Các cuộc tấn công LDAP relay/MITM chuyển tiếp quá trình xác thực đến domain controller để lấy ngữ cảnh LDAP đã xác thực. [Tổng quan về đầu độc phân giải tên và relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) trình bày quy trình tổng quát. Hai biện pháp kiểm soát liên quan giúp giảm thiểu các hướng tấn công này:

- **LDAP channel binding (CBT)** liên kết quá trình xác thực tương ứng với chứng chỉ/kênh TLS được LDAPS sử dụng, gây khó khăn cho relay xuyên kênh.
- **LDAP signing** yêu cầu bảo vệ tính toàn vẹn cho các LDAP bind dùng SASL. Tính năng này không bổ sung tính bảo mật; hãy dùng TLS nếu nội dung LDAP cũng cần được mã hóa.<sup>[[2]](#references)</sup>

**Kiểm tra nhanh trạng thái**: các công cụ như `netexec ldap <dc> -u user -p pass` báo cáo chính sách signing và channel binding được quan sát. `(signing:None)` và `(channel binding:Never)` cho thấy thiếu các biện pháp kiểm soát, nhưng relay thành công vẫn phụ thuộc vào loại xác thực thu được, hành vi EPA, quyền của tài khoản, giao thức đích và các biện pháp bảo vệ relay. Khi principal được relay có đủ quyền cần thiết, các công cụ như KrbRelayUp có thể ghi `msDS-AllowedToActOnBehalfOfOtherIdentity`, cấu hình resource-based constrained delegation (RBCD) và sử dụng đường dẫn delegation thu được để mạo danh một principal có đặc quyền.<sup>[[4]](#references)</sup>

**Các DC Server 2025** giới thiệu GPO mới (**LDAP server signing requirements Enforcement**), mặc định là **Require Signing** nếu để ở trạng thái **Not Configured**. Để tránh việc thực thi chính sách, bạn phải đặt rõ chính sách đó thành **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (chỉ LDAPS)

- **Yêu cầu**:
  - Bản vá CVE-2017-8563 (2017) bổ sung hỗ trợ Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) bổ sung telemetry “what-if” cho LDAPS CBT.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (mặc định, không dùng CBT)
  - `When Supported` (thực thi một phần: client hỗ trợ CBT phải cung cấp token hợp lệ; client không hỗ trợ CBT vẫn có thể bind và các audit event sẽ được phát ra)
  - `Always` (thực thi: từ chối LDAPS bind không có CBT hợp lệ)<sup>[[1]](#references)</sup>
- **Audit**: đặt thành **When Supported** để phát hiện:
  - **3074** – LDAPS bind sẽ không vượt qua xác thực CBT nếu được thực thi.
  - **3075** – LDAPS bind không có dữ liệu CBT và sẽ bị từ chối nếu được thực thi.
  - (Event **3039** vẫn báo hiệu lỗi CBT trên các bản build cũ hơn.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Thực thi**: đặt thành **Always** khi client LDAPS gửi CBT; chỉ có hiệu lực với **LDAPS** (không áp dụng cho cổng 389 không mã hóa).<sup>[[1]](#references)</sup>

`When Supported` không chỉ dùng cho audit: chính sách xác thực CBT cho client có hỗ trợ, đồng thời cho phép client không hỗ trợ CBT. [Tài liệu tham khảo chính sách của Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) mô tả các giá trị mặc định tùy theo phiên bản. LDAP signing áp dụng cho các bind tương ứng trên LDAP/389; channel binding áp dụng cho xác thực LDAP được bảo vệ bằng TLS.


## LDAP Signing

- **GPO client**: `Network security: LDAP client signing requirements` = `Require signing` (thay vì mặc định `Negotiate signing` trên Windows hiện đại).<sup>[[1]](#references)</sup>
- **GPO DC**:
  - Bản cũ: `Domain controller: LDAP server signing requirements` = `Require signing` (mặc định là `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: giữ chính sách cũ ở `None` và đặt `LDAP server signing requirements Enforcement` = `Enabled` (mặc định được thực thi khi để Not Configured; đặt `Disabled` để tránh thực thi).<sup>[[1]](#references)</sup>
- **Tương thích**: kiểm kê các thiết bị và ứng dụng không chạy Windows sử dụng simple bind hoặc SASL bind không signing. Microsoft nêu tài liệu hỗ trợ trên các phiên bản Windows còn được duy trì; cần xác minh các tuyên bố về khả năng tương thích với client cũ dựa trên stack client thực tế, thay vì chỉ dựa vào ngưỡng phiên bản XP.<sup>[[2]](#references)</sup>

## Triển khai ưu tiên audit (khuyến nghị khoảng 30 ngày)

1. Bật chẩn đoán giao diện LDAP trên từng DC để ghi log các bind không signing (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Đặt GPO DC `LDAP server channel binding token requirements` = **When Supported** để thực thi CBT một phần và thu thập telemetry; trước tiên hãy xác thực khả năng tương thích với client cũ.<sup>[[1]](#references)</sup>
3. Giám sát các sự kiện Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – các bind không ký/cho phép không ký (không tuân thủ yêu cầu signing).
   - **3074/3075** – các bind LDAPS sẽ thất bại hoặc không có CBT (cần KB4520412 trên 2019/2022 và bước 2 ở trên).
4. Thực thi bằng các thay đổi riêng biệt:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (client).
   - `LDAP server signing requirements` = **Require signing** (DC) **hoặc** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Ràng buộc kênh LDAP và LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Yêu cầu ràng buộc kênh LDAP & signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Bản cập nhật giảm thiểu LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (tắt LDAP signing → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
