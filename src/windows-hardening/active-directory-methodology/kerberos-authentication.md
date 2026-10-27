# Xác thực Kerberos

{{#include ../../banners/hacktricks-training.md}}

Để xem hướng dẫn từng bước ở cấp giao thức về các lượt trao đổi được tóm tắt bên dưới, hãy tham khảo bài viết về Kerberos của Tarlogic.<sup>[[3]](#references)</sup>

## TL;DR dành cho attacker
- Kerberos là giao thức xác thực AD mặc định; hầu hết chuỗi lateral movement đều liên quan đến giao thức này.
- Hãy nghĩ theo **ba giai đoạn vận hành**:<sup>[[3]](#references)</sup>
  - **AS-REQ / AS-REP** → dùng password/hash/certificate để lấy **TGT**. Đây là nơi diễn ra **AS-REP roasting**, **over-pass-the-hash / pass-the-key** và **PKINIT**.
  - **TGS-REQ / TGS-REP** → dùng TGT để lấy **service ticket**. Đây là lúc **Kerberoasting**, **S4U abuse**, **delegation abuse** và hầu hết **ticket-forging tradecraft** trở nên hữu ích.
  - **AP-REQ / AP-REP** → trình ticket cho service. Đây là lúc diễn ra **pass-the-ticket** và lateral movement đặc thù cho từng service.
- Để xem cheatsheet thực hành (AS-REP/Kerberoasting, ticket forgery, delegation abuse, v.v.), hãy xem:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Dùng trang này làm chỉ mục **tổng quan / “những thay đổi gần đây”**, sau đó chuyển đến các trang chuyên biệt về [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) hoặc [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Ghi chú tấn công mới (2024-2026)
- **RC4 hardening thay đổi các giá trị mặc định, không thay đổi Kerberos** – việc hardening DC hiện đại tập trung vào **các loại mã hóa mặc định được giả định** cho những account **không** đặt rõ `msDS-SupportedEncryptionTypes`. Sau đợt triển khai năm 2026, các account đó ngày càng mặc định chỉ dùng **AES** trên DC đã được vá, vì vậy những giả định Kerberoast `/rc4` không kiểm tra dễ thất bại hơn. Tuy nhiên, các service account **được bật RC4 rõ ràng** vẫn là mục tiêu offline-crack rất tốt.<sup>[[1]](#references)</sup>
- **Việc thực thi xác thực PAC rất quan trọng đối với ticket giả mạo** – hardening chữ ký PAC năm 2024 có nghĩa là các kiểu abuse **golden/diamond/sapphire/extraSID** cần dữ liệu PAC thực tế hơn và đúng ngữ cảnh ký. Các domain chưa được vá hoặc vẫn dùng cấu hình tương thích/kiểm tra kiểu audit sẽ là mục tiêu dễ bị khai thác hơn.<sup>[[2]](#references)</sup>
- **Kerberos dựa trên certificate đã thay đổi hai lần**:
  - **Strong certificate binding** (theo lộ trình KB5014754) khiến việc ánh xạ certificate-to-account cẩu thả kém tin cậy hơn trong các môi trường đã thực thi đầy đủ.
  - **CVE-2025-26647** bổ sung một lớp hardening khác cho các ánh xạ `altSecurityIdentities` sử dụng Subject Key Identifier của certificate. Vì vậy, khi đánh giá pass-the-certificate và các đường tấn công dựa trên certificate liên quan, cần xem xét mức độ vá, trạng thái enforcement hoặc audit, cũng như cấu hình ánh xạ tường minh.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Với PKINIT, KDC cũng xác thực đường dẫn certificate và kiểm tra issuer có được tin cậy thông qua NTAuth store hay không.<sup>[[8]](#references)</sup>
- **Abuse delegation xuyên domain / xuyên forest vẫn rất phổ biến** – Windows hỗ trợ các luồng **S4U2Self/S4U2Proxy** hiện đại xuyên realm, nên các thuộc tính delegation có thể ghi trong domain khác vẫn rất có giá trị. Trở ngại thường nằm ở độ chính xác của tooling và các chi tiết về trust/policy, chứ không phải do giao thức không hỗ trợ.
- **RBCD đệ quy qua nhiều domain có ý nghĩa thực tế** – trong forest có từ 3 domain trở lên, **S4U2Self/S4U2Proxy** có thể đệ quy qua các trust referral, còn việc abuse **SPN-less** có thể cần thêm một bước cuối **`S4U2Self+U2U`** cùng với xử lý ticket phụ thuộc RC4. Xem [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 giới thiệu delegated Managed Service Accounts (dMSA)** cùng logic migration của chúng. Nếu thấy quyền delegated trên OU hoặc object service-account trong domain 2025, hãy xem [trang BadSuccessor](acl-persistence-abuse/BadSuccessor.md) chuyên biệt thay vì coi đây là “một gMSA khác”.<sup>[[7]](#references)</sup>

## Kiểm tra nhanh cho operator trong domain hiện đại

Trước khi chọn hướng tấn công Kerberos, hãy nhanh chóng trả lời bốn câu hỏi:

1. **Những account nào vẫn tương thích với RC4?**
2. **Những user nào không yêu cầu pre-auth?**
3. **Những object nào có thể bị abuse delegation?**
4. **Những phần nào của domain đủ mới để thực thi các biện pháp hardening gần đây?**

```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
  -Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
  -Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
  -Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
  -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
  -Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
  $_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```

Diễn giải thực tế:
- Nếu các tài khoản SPN đáng chú ý **được cấu hình rõ ràng để hỗ trợ RC4**, Kerberoasting vẫn nhanh và ít tốn công.
- Nếu hầu hết tài khoản dịch vụ **không có cấu hình etype rõ ràng**, hãy dự kiến hành vi **chỉ dùng AES** trên các DC được cập nhật trong năm 2026 và chuẩn bị cho việc crack offline chậm hơn hoặc chọn hướng khác.
- Nếu có **RBCD / KCD / unconstrained delegation**, S4U thường hiệu quả hơn brute-force.
- Nếu có **certificate auth**, hãy nhớ rằng PKINIT thất bại **không phải lúc nào cũng có nghĩa là cert vô dụng**; trong nhiều môi trường, cert đó vẫn dùng được để lạm dụng **Schannel/LDAPS** (xem [AD Certificates / lạm dụng PKINIT](ad-certificates.md)).

## Các lỗi Kerberos phổ biến làm thay đổi kế hoạch tấn công
- **`KDC_ERR_ETYPE_NOTSUPP`** → Tài khoản mục tiêu / DC sẽ không dùng encryption type mà bạn yêu cầu. Đừng tiếp tục thử chỉ với RC4; hãy cung cấp **AES keys** hoặc yêu cầu dữ liệu roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Có thể bạn đang dùng **service key sai**, **SPN sai**, hoặc ticket giả mạo không khớp với tài khoản dịch vụ thực sự giải mã nó.
- **`KRB_AP_ERR_SKEW`** → Đồng hồ của bạn bị lệch. Hãy đồng bộ thời gian với DC trước khi kiểm tra bất kỳ vấn đề nào khác.
- **`KDC_ERR_BADOPTION`** trong các luồng S4U / delegation → thường có nghĩa là **người dùng nhạy cảm/không thể ủy quyền**, dùng sai mô hình delegation, hoặc bạn đang thử **classic KCD** trong khi chỉ **RBCD** mới chấp nhận ticket S4U2Self không thể forward.

## References
- [1] [Microsoft Learn - Phát hiện và khắc phục việc sử dụng RC4 trong Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Hướng dẫn hardening Windows mới nhất và các mốc thời gian quan trọng](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Kerberos hoạt động như thế nào? – Lý thuyết](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Khai thác RBCD trong môi trường Cross-Domain & Cross-Forest: Phần 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Các thay đổi về xác thực dựa trên certificate KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - Lỗ hổng ánh xạ certificate Kerberos CVE-2025-26647](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Tổng quan về Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Yêu cầu đối với certificate smart card và xác thực KDC](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
