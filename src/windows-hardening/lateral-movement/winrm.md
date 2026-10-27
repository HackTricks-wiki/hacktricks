# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM là một trong những phương tiện **lateral movement** tiện lợi nhất trong môi trường Windows vì cung cấp shell từ xa qua **WS-Man/HTTP(S)** mà không cần đến các thủ thuật tạo service SMB. Nếu mục tiêu mở **5985/5986** và tài khoản của bạn được phép dùng remoting, bạn thường có thể nhanh chóng chuyển từ “thông tin xác thực hợp lệ” sang “shell tương tác”.

Để tìm hiểu về **enumeration** giao thức/service, listeners, bật WinRM, `Invoke-Command` và cách dùng client nói chung, hãy xem:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Vì sao operator ưa dùng WinRM

- Dùng **HTTP/HTTPS** thay vì SMB/RPC, nên thường hoạt động trong các môi trường chặn thực thi kiểu PsExec.
- Với **Kerberos**, không cần gửi thông tin xác thực có thể tái sử dụng đến mục tiêu.
- Hoạt động tốt trên **Windows**, **Linux** và các công cụ **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Luồng PowerShell remoting tương tác khởi chạy **`wsmprovhost.exe`** trên mục tiêu trong ngữ cảnh người dùng đã xác thực; về mặt vận hành, cách này khác với thực thi dựa trên service.

## Mô hình truy cập và các điều kiện tiên quyết

Trên thực tế, lateral movement qua WinRM thành công phụ thuộc vào **ba** yếu tố:

1. Mục tiêu có **WinRM listener** (`5985`/`5986`) và các quy tắc firewall cho phép truy cập.
2. Tài khoản có thể **xác thực** với endpoint.
3. Tài khoản được phép **mở phiên remoting**.

Các cách phổ biến để có quyền truy cập đó:

- Là **Local Administrator** trên mục tiêu.
- Thuộc nhóm **Remote Management Users** trên các hệ thống mới hơn hoặc **WinRMRemoteWMIUsers__** trên các hệ thống/thành phần vẫn còn áp dụng nhóm đó.
- Được cấp quyền remoting rõ ràng thông qua security descriptor cục bộ / thay đổi ACL của PowerShell remoting.

Nếu bạn đã kiểm soát một máy với quyền admin, hãy nhớ rằng bạn cũng có thể **ủy quyền truy cập WinRM mà không cần là thành viên của nhóm admin** bằng các kỹ thuật được mô tả tại đây:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Những lưu ý về xác thực cần biết khi lateral movement

- **Kerberos yêu cầu hostname/FQDN**. Nếu kết nối bằng IP, client thường chuyển sang **NTLM/Negotiate**.
- Trong các trường hợp workgroup hoặc ranh giới trust chéo, NTLM thường yêu cầu **HTTPS** hoặc phải thêm mục tiêu vào **TrustedHosts** trên client.
- Với tài khoản cục bộ dùng Negotiate trong workgroup, các hạn chế UAC từ xa có thể ngăn truy cập, trừ khi dùng tài khoản Administrator tích hợp sẵn hoặc đặt `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting mặc định dùng **SPN `HTTP/<host>`**. Trong các môi trường mà `HTTP/<host>` đã được đăng ký cho một service account khác, WinRM Kerberos có thể lỗi với `0x80090322`; hãy dùng SPN có kèm port hoặc chuyển sang **`WSMAN/<host>`** nếu SPN đó tồn tại.<sup>[[3]](#references)</sup>

Nếu thu thập được thông tin xác thực hợp lệ trong quá trình password spraying, xác thực chúng qua WinRM thường là cách nhanh nhất để kiểm tra xem chúng có thể giúp bạn mở shell hay không:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement từ Linux sang Windows

### NetExec / CrackMapExec để xác thực và thực thi one-shot

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM cho shell tương tác

`evil-winrm` vẫn là lựa chọn tương tác tiện lợi nhất trên Linux vì hỗ trợ **mật khẩu**, **NT hashes**, **Kerberos tickets**, **client certificates**, truyền tệp và tải PowerShell/.NET vào bộ nhớ.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Trường hợp đặc biệt của Kerberos SPN: `HTTP` và `WSMAN`

Khi SPN mặc định **`HTTP/<host>`** gây ra lỗi Kerberos, hãy thử yêu cầu/sử dụng ticket **`WSMAN/<host>`** thay thế. Tình huống này có thể xảy ra trong các môi trường doanh nghiệp được harden hoặc thiết lập bất thường, nơi **`HTTP/<host>`** đã được gắn với một service account khác.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Điều này cũng hữu ích sau khi lạm dụng **RBCD / S4U**, khi bạn chủ ý giả mạo hoặc yêu cầu service ticket **WSMAN** thay vì ticket `HTTP` thông thường.

### Xác thực bằng chứng chỉ

WinRM cũng hỗ trợ **xác thực bằng chứng chỉ client**, nhưng chứng chỉ phải được ánh xạ trên máy đích tới một **local account**. Từ góc độ tấn công, điều này hữu ích khi:

- bạn đã đánh cắp/xuất một chứng chỉ client hợp lệ cùng private key đã được ánh xạ cho WinRM;
- bạn lạm dụng **AD CS / Pass-the-Certificate** để lấy chứng chỉ cho một principal rồi pivot sang một đường xác thực khác;
- bạn đang hoạt động trong các môi trường cố tình tránh remoting dựa trên mật khẩu.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

WinRM xác thực bằng client certificate ít phổ biến hơn nhiều so với xác thực bằng password/hash/Kerberos, nhưng khi có thể sử dụng, nó cung cấp một con đường **lateral movement không cần password** vẫn hoạt động sau khi password được đổi.

### Python / automation với `pypsrp`

Nếu bạn cần automation thay vì operator shell, `pypsrp` cung cấp WinRM/PSRP từ Python với hỗ trợ **NTLM**, **xác thực bằng certificate**, **Kerberos** và **CredSSP**.<sup>[[2]](#references)</sup>

```python
from pypsrp.client import Client

client = Client(
    "srv01.domain.local",
    username="DOMAIN\\user",
    password="Password123!",
    ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```


Nếu cần kiểm soát chi tiết hơn so với lớp bọc cấp cao `Client`, các API cấp thấp hơn `WSMan` + `RunspacePool` hữu ích để xử lý hai vấn đề thường gặp của người vận hành:

- buộc dùng **`WSMAN`** làm dịch vụ/SPN Kerberos thay vì kỳ vọng mặc định là **`HTTP`** của nhiều PowerShell client;
- kết nối đến **PSRP endpoint không mặc định**, chẳng hạn cấu hình phiên **JEA** / tùy chỉnh, thay vì `Microsoft.PowerShell`.

```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
    "srv01.domain.local",
    auth="kerberos",
    ssl=False,
    negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
    ps.add_script("whoami; Get-Command")
    output = ps.invoke()
    print(output)
```

### Các endpoint PSRP tùy chỉnh và JEA rất quan trọng trong lateral movement

Xác thực WinRM thành công **không** phải lúc nào cũng có nghĩa là bạn sẽ vào endpoint `Microsoft.PowerShell` mặc định, không bị hạn chế. Các môi trường được quản lý tốt có thể cung cấp **cấu hình phiên tùy chỉnh** hoặc endpoint **JEA** với ACL và hành vi run-as riêng.<sup>[[1]](#references)</sup>

Nếu bạn đã có khả năng thực thi mã trên một máy chủ Windows và muốn tìm hiểu các bề mặt remoting hiện có, hãy liệt kê các endpoint đã đăng ký:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Khi có endpoint hữu ích, hãy target trực tiếp endpoint đó thay vì shell mặc định:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Các hệ quả thực tiễn đối với offensive security:

- Một endpoint **restricted** vẫn có thể đủ để lateral movement nếu nó chỉ cung cấp đúng các cmdlet/function cần thiết để điều khiển service, truy cập file, tạo process hoặc thực thi lệnh .NET / lệnh bên ngoài tùy ý.
- Một role **JEA misconfigured** đặc biệt có giá trị khi nó cung cấp các lệnh nguy hiểm như `Start-Process`, wildcard quá rộng, provider có quyền ghi hoặc custom proxy function cho phép thoát khỏi các hạn chế dự kiến.
- Endpoint sử dụng **RunAs virtual account** hoặc **gMSA** sẽ thay đổi security context thực tế của các lệnh bạn chạy. Cụ thể, endpoint dùng gMSA có thể cung cấp **network identity ở second hop**, ngay cả khi một phiên WinRM thông thường gặp vấn đề delegation kinh điển.

Với endpoint restricted tùy chỉnh, hãy kiểm tra riêng quyền đối với command và script thực tế: danh sách `Get-Command` ngắn không chứng minh rằng một file `.ps1` có sẵn không thể chạy. [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) quy định rõ những đường dẫn script nào có thể được gọi; các endpoint tùy chỉnh khác có thể áp dụng quy tắc session khác. Nếu một script được phép dùng `SecureString` đã lưu để tạo credential cho host khác, blob được tạo mà không chỉ định key sẽ dùng [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) và thường cần đúng user context cùng machine context đã bảo vệ nó để giải mã. Trước khi xem source có quyền ghi hoặc blob được sao chép là đường dẫn leo thang đặc quyền xuyên host, hãy kiểm tra ACL của script, quyền gọi script, danh tính run-as và quyền của credential ở các hệ thống tiếp theo. Không in giá trị được bảo vệ trong quá trình enumeration thụ động.

Với custom function JEA nhận đường dẫn file, hãy kiểm tra đồng thời ACL của endpoint đã đăng ký, role capability được ánh xạ và danh tính run-as thực tế. Caller có thể bị giới hạn ở `NoLanguage`, trong khi phần thân function chạy ở language mode mặc định của hệ thống; virtual account cũng có thể có quyền local administrator. Nếu function kiểm tra thư mục được phép bằng tiền tố chuỗi thô rồi đọc đường dẫn được cung cấp, các thành phần `..` có thể phân giải ra ngoài thư mục đó. Ranh giới cần xét là đường dẫn đã phân giải dưới danh tính của function, không phải language mode của caller hay tiền tố nhìn thấy được. Hãy xác nhận function có thể truy cập và việc kiểm tra đường dẫn cuối cùng trước khi xem file `.psrc` hoặc `.pssc` có thể đọc được là một phát hiện đọc file đặc quyền. Xem hướng dẫn của Microsoft về [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) và [các vấn đề bảo mật](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Lateral movement qua WinRM bằng công cụ tích hợp sẵn của Windows

### `winrs.exe`

`winrs.exe` được tích hợp sẵn và hữu ích khi bạn muốn **thực thi lệnh bằng WinRM nguyên bản** mà không cần mở một phiên PowerShell remoting tương tác:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Hai flag thường dễ bị quên nhưng rất quan trọng trong thực tế:

- `/noprofile` thường cần thiết khi principal từ xa **không** phải là quản trị viên cục bộ.
- `/allowdelegate` cho phép remote shell sử dụng thông tin xác thực của bạn để truy cập **máy chủ thứ ba** (ví dụ: khi lệnh cần `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Về mặt vận hành, `winrs.exe` thường tạo ra một chuỗi tiến trình từ xa tương tự như:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Điều này đáng ghi nhớ vì nó khác với exec dựa trên service và các phiên PSRP tương tác.

### `winrm.cmd` / WS-Man COM thay vì PowerShell remoting

Bạn cũng có thể thực thi qua **WinRM transport** mà không cần `Enter-PSSession` bằng cách gọi các lớp WMI qua WS-Man. Cách này giữ nguyên transport là WinRM, còn primitive thực thi từ xa chuyển thành **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Cách tiếp cận đó hữu ích khi:

- PowerShell logging bị giám sát chặt chẽ.
- Bạn muốn dùng **WinRM transport** nhưng không muốn dùng quy trình PS remoting cổ điển.
- Bạn đang xây dựng hoặc sử dụng tooling tùy chỉnh dựa trên đối tượng COM **`WSMan.Automation`**.

## NTLM relay tới WinRM (WS-Man)

Khi SMB relay bị chặn do signing và LDAP relay bị hạn chế, **WS-Man/WinRM** vẫn có thể là mục tiêu relay hấp dẫn. `ntlmrelayx.py` hiện đại có **WinRM relay servers** và có thể relay tới các mục tiêu **`wsman://`** hoặc **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Hai lưu ý thực tế:

- Relay hữu ích nhất khi target chấp nhận **NTLM** và principal được relay có quyền sử dụng WinRM.
- Mã Impacket gần đây xử lý riêng các yêu cầu **`WSMANIDENTIFY: unauthenticated`**, để các probe kiểu `Test-WSMan` không làm gián đoạn luồng relay.

Để biết về các giới hạn multi-hop sau khi có được phiên WinRM đầu tiên, hãy xem:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Lưu ý về OPSEC và phát hiện

- **Interactive PowerShell remoting** thường tạo tiến trình **`wsmprovhost.exe`** trên target.
- **`winrs.exe`** thường tạo **`winrshost.exe`**, sau đó là tiến trình con được yêu cầu.
- Các endpoint **JEA** tùy chỉnh có thể thực thi hành động dưới dạng virtual account **`WinRM_VA_*`** hoặc **gMSA** đã cấu hình. Điều này làm thay đổi cả telemetry lẫn hành vi second-hop so với shell chạy trong context của người dùng thông thường.<sup>[[1]](#references)</sup>
- Nếu dùng PSRP thay vì `cmd.exe` thuần, hãy dự kiến có telemetry về **network logon**, các sự kiện dịch vụ WinRM và ghi log hoạt động/script block của PowerShell.
- Nếu chỉ cần chạy một lệnh, `winrs.exe` hoặc thực thi WinRM một lần có thể ít gây chú ý hơn một phiên remoting tương tác kéo dài.
- Nếu có Kerberos, hãy ưu tiên **FQDN + Kerberos** thay vì IP + NTLM để giảm cả vấn đề trust lẫn việc phải thay đổi `TrustedHosts` ở phía client.

## References

- [1] [Microsoft: Các lưu ý bảo mật về JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Lỗi `0x80090322` khi kết nối PowerShell với máy chủ từ xa qua WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
