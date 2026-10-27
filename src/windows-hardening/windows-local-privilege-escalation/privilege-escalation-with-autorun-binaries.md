# Leo thang đặc quyền bằng Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** có thể được dùng để chạy chương trình khi **khởi động**. Xem những binary nào được thiết lập để chạy khi khởi động bằng lệnh:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Tác vụ đã lên lịch

**Tasks** có thể được lên lịch để chạy với **tần suất cụ thể**. Dùng các lệnh sau để xem những binary nào được lên lịch chạy:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Một tác vụ được bật và chạy với quyền SYSTEM cần được xem xét, ngay cả khi định nghĩa tác vụ và tệp hành động được bảo vệ. [Task Scheduler yêu cầu quyền thực thi trên tác vụ để chạy tác vụ theo yêu cầu](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Nếu người dùng có đặc quyền thấp có quyền đó, hãy kiểm tra chính xác hành động của tác vụ, đặc biệt là các script PowerShell sửa đổi ACL của Active Directory hoặc đặt lại các thiết lập bảo vệ tài khoản. Kiểm tra thiết lập `AllowDemandStart` của tác vụ và xác minh đầu vào cũng như tác động của script; chỉ có quyền khởi chạy một tác vụ cố định không đồng nghĩa với khả năng thực thi mã tùy ý.

## Thư mục

Tất cả binary trong **thư mục Startup sẽ được thực thi khi khởi động**. Các thư mục Startup phổ biến được liệt kê bên dưới, nhưng thư mục Startup được chỉ định trong registry. [Đọc nội dung này để tìm vị trí.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Mục Startup của người dùng có đặc quyền cao hơn có thể khởi chạy một script được bảo vệ, script này liên tục mở các tệp trong một thư mục mà người dùng khác có thể ghi. Hãy kiểm tra **danh tính đăng nhập thực tế** của mục đó, thư mục đầu vào của script và ACL, cũng như hành động chính xác trước khi xem thư mục đó là một đường dẫn leo thang đặc quyền. Cụ thể, [`hh.exe` mở các tệp HTML Help đã biên dịch (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); script chuyển các tệp do người gọi cung cấp cho chương trình này vượt qua ranh giới tin cậy nội dung, ngay cả khi script kiểm tra tên tệp hoặc các byte đầu tiên. [Các chính sách HTML Help có thể hạn chế shortcut thực thi](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), vì vậy hãy xác nhận chính sách đã cài đặt và hành vi nội dung có thể truy cập. Chỉ riêng phần mở rộng `.chm` hoặc các byte magic không chứng minh được việc thực thi mã với đặc quyền cao hơn. Hãy kiểm tra autorun, command line của tiến trình và quyền truy cập đường dẫn mà không mở tệp không đáng tin cậy trong quá trình liệt kê.

Ranh giới nội dung tương tự cũng tồn tại khi người có đặc quyền cao hơn **mở thủ công** tệp `.chm` từ một thư mục tài liệu mà người dùng khác có thể thay thế nội dung. Hãy xác nhận chính xác tệp và quyền ghi của thư mục cha, danh tính thực tế của trình xem và sự kiện mở tệp, cũng như chính sách HTML Help có hiệu lực. Thư mục có thể ghi hoặc yêu cầu xem lại tài liệu không chứng minh được rằng danh tính có đặc quyền cao hơn đã mở nội dung do kẻ tấn công kiểm soát.

> **FYI**: Các lỗ hổng *path traversal* trong quá trình giải nén archive (chẳng hạn lỗ hổng bị khai thác trong WinRAR trước phiên bản 7.13 – CVE-2025-8088) có thể được tận dụng để **đặt payload trực tiếp vào các thư mục Startup trong quá trình giải nén**, dẫn đến code execution vào lần đăng nhập tiếp theo của người dùng. Để tìm hiểu sâu về kỹ thuật này, xem:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Ghi chú tại đây](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Mục registry **Wow6432Node** cho biết bạn đang chạy phiên bản Windows 64-bit. Hệ điều hành sử dụng khóa này để hiển thị một chế độ xem riêng của HKEY_LOCAL_MACHINE\SOFTWARE dành cho các ứng dụng 32-bit chạy trên phiên bản Windows 64-bit.

### Runs

Các registry AutoRun **thường gặp**:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Các registry key có tên **Run** và **RunOnce** được thiết kế để tự động thực thi chương trình mỗi khi người dùng đăng nhập vào hệ thống. Command line được gán làm giá trị dữ liệu của một key bị giới hạn tối đa 260 ký tự.<sup>[[2]](#references)</sup>

**Service runs** (có thể kiểm soát việc tự động khởi động các dịch vụ trong quá trình boot):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Trên Windows Vista và các phiên bản mới hơn, các registry key **Run** và **RunOnce** không được tự động tạo. Các mục trong những key này có thể khởi chạy chương trình trực tiếp hoặc chỉ định chương trình dưới dạng dependency. Ví dụ, để tải tệp DLL khi đăng nhập, có thể dùng registry key **RunOnceEx** cùng với key "Depend". Có thể thực hiện việc này bằng cách thêm một registry entry để thực thi "C:\temp\evil.dll" khi hệ thống khởi động:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Nếu bạn có thể ghi vào bất kỳ registry nào được đề cập bên trong **HKLM**, bạn có thể leo thang đặc quyền khi một người dùng khác đăng nhập.

> [!TIP]
> **Exploit 2**: Nếu bạn có thể ghi đè bất kỳ tệp nhị phân nào được chỉ định trong registry bên trong **HKLM**, bạn có thể sửa đổi tệp nhị phân đó bằng một backdoor khi một người dùng khác đăng nhập và leo thang đặc quyền.

```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```

### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Các shortcut được đặt trong thư mục **Startup** sẽ tự động kích hoạt dịch vụ hoặc ứng dụng khi người dùng đăng nhập hoặc hệ thống khởi động lại. Vị trí của thư mục **Startup** được xác định trong registry cho cả phạm vi **Local Machine** và **Current User**. Điều này có nghĩa là mọi shortcut được thêm vào các vị trí **Startup** đã chỉ định sẽ đảm bảo dịch vụ hoặc chương trình được liên kết khởi chạy sau khi đăng nhập hoặc khởi động lại, khiến đây trở thành một phương pháp đơn giản để lên lịch chạy chương trình tự động.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Nếu bạn có thể ghi đè bất kỳ User Shell Folder nào dưới **HKLM**, bạn sẽ có thể trỏ nó đến một thư mục do bạn kiểm soát và đặt một backdoor sẽ được thực thi mỗi khi người dùng đăng nhập vào hệ thống, qua đó leo thang đặc quyền.

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```

### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Giá trị registry theo từng người dùng này có thể trỏ đến một script hoặc lệnh được thực thi khi người dùng đó đăng nhập. Đây chủ yếu là một primitive **persistence** vì nó chỉ chạy trong ngữ cảnh của người dùng bị ảnh hưởng, nhưng vẫn đáng kiểm tra trong quá trình post-exploitation và rà soát autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Nếu bạn có thể ghi giá trị này cho người dùng hiện tại, bạn có thể kích hoạt lại việc thực thi vào lần đăng nhập tương tác tiếp theo mà không cần quyền admin. Nếu bạn có thể ghi vào hive của người dùng khác, bạn có thể thực thi mã khi người dùng đó đăng nhập.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notes:

- Ưu tiên dùng đường dẫn đầy đủ đến các file `.bat`, `.cmd`, `.ps1` hoặc file khởi chạy khác mà người dùng mục tiêu đã có quyền đọc.
- Cách này vẫn tồn tại sau khi đăng xuất/khởi động lại cho đến khi giá trị bị xóa.
- Không giống `HKLM\...\Run`, cách này **không** tự cấp elevation; đây là persistence ở phạm vi người dùng.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Thông thường, key **Userinit** được đặt thành **userinit.exe**. Tuy nhiên, nếu key này bị sửa đổi, executable được chỉ định cũng sẽ được **Winlogon** khởi chạy khi người dùng đăng nhập. Tương tự, key **Shell** được thiết kế để trỏ đến **explorer.exe**, shell mặc định của Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Nếu bạn có thể ghi đè giá trị registry hoặc binary, bạn sẽ có thể leo thang đặc quyền.

### Cài đặt chính sách

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Kiểm tra khóa **Run**.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Thay đổi Command Prompt trong Safe Mode

Trong Windows Registry tại `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, có một giá trị **`AlternateShell`** mặc định được đặt là `cmd.exe`. Điều này có nghĩa là khi bạn chọn "Safe Mode with Command Prompt" trong lúc khởi động (bằng cách nhấn F8), `cmd.exe` sẽ được sử dụng. Tuy nhiên, bạn có thể thiết lập máy tính tự động khởi động ở chế độ này mà không cần nhấn F8 và chọn thủ công.

Các bước tạo tùy chọn khởi động để tự động vào "Safe Mode with Command Prompt":<sup>[[5]](#references)</sup>

1. Thay đổi thuộc tính của tệp `boot.ini` để xóa các cờ chỉ đọc, hệ thống và ẩn: `attrib c:\boot.ini -r -s -h`
2. Mở `boot.ini` để chỉnh sửa.
3. Chèn một dòng như sau: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Lưu các thay đổi vào `boot.ini`.
5. Khôi phục các thuộc tính ban đầu của tệp: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Thay đổi khóa registry **AlternateShell** cho phép thiết lập command shell tùy chỉnh, có khả năng tạo điều kiện truy cập trái phép.
- **Exploit 2 (Quyền ghi PATH):** Có quyền ghi vào bất kỳ phần nào của biến hệ thống **PATH**, đặc biệt là trước `C:\Windows\system32`, cho phép bạn chạy một `cmd.exe` tùy chỉnh, có thể đóng vai trò backdoor nếu hệ thống được khởi động trong Safe Mode.
- **Exploit 3 (Quyền ghi PATH và boot.ini):** Có quyền ghi vào `boot.ini` cho phép tự động khởi động Safe Mode, tạo điều kiện truy cập trái phép trong lần khởi động lại tiếp theo.

Để kiểm tra thiết lập **AlternateShell** hiện tại, hãy dùng các lệnh sau:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Thành phần đã cài đặt

Active Setup là một tính năng trong Windows **khởi chạy trước khi môi trường desktop được tải hoàn toàn**. Tính năng này ưu tiên thực thi một số lệnh nhất định, các lệnh này phải hoàn tất trước khi quá trình đăng nhập của người dùng tiếp tục. Quá trình này diễn ra trước cả khi các mục khởi động khác, chẳng hạn như những mục trong các khóa registry Run hoặc RunOnce, được kích hoạt.

Active Setup được quản lý thông qua các khóa registry sau:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Trong các khóa này có nhiều khóa con, mỗi khóa tương ứng với một thành phần cụ thể. Các giá trị khóa đáng chú ý gồm:

- **IsInstalled:**
  - `0` cho biết lệnh của thành phần sẽ không được thực thi.
  - `1` nghĩa là lệnh sẽ được thực thi một lần cho mỗi người dùng; đây là hành vi mặc định nếu thiếu giá trị `IsInstalled`.
- **StubPath:** Xác định lệnh mà Active Setup sẽ thực thi. Đây có thể là bất kỳ dòng lệnh hợp lệ nào, chẳng hạn như khởi chạy `notepad`.

**Thông tin bảo mật:**

- Sửa đổi hoặc ghi vào khóa có **`IsInstalled`** được đặt thành `"1"` cùng một **`StubPath`** cụ thể có thể dẫn đến việc thực thi lệnh trái phép, tiềm ẩn nguy cơ leo thang đặc quyền.
- Thay đổi tệp nhị phân được tham chiếu trong bất kỳ giá trị **`StubPath`** nào cũng có thể giúp leo thang đặc quyền nếu có đủ quyền.

Có thể dùng các lệnh sau để kiểm tra cấu hình **`StubPath`** trên các thành phần Active Setup:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Tổng quan về Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) là các module DLL bổ sung tính năng cho Internet Explorer của Microsoft. Chúng được tải vào Internet Explorer và Windows Explorer mỗi khi khởi động. Tuy nhiên, có thể chặn chúng thực thi bằng cách đặt khóa **NoExplorer** thành 1, ngăn chúng tải cùng các phiên bản Windows Explorer.<sup>[[1]](#references)</sup>

BHO tương thích với Windows 10 thông qua Internet Explorer 11 nhưng không được hỗ trợ trong Microsoft Edge, trình duyệt mặc định trên các phiên bản Windows mới hơn.

Để xem các BHO đã đăng ký trên hệ thống, bạn có thể kiểm tra các khóa registry sau:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Mỗi BHO được biểu thị bằng **CLSID** trong registry, đóng vai trò là mã định danh duy nhất. Có thể tìm thông tin chi tiết về từng CLSID tại `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Có thể sử dụng các lệnh sau để truy vấn BHO trong registry:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Tiện ích mở rộng Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Lưu ý rằng registry sẽ chứa một registry mới cho mỗi dll và registry đó sẽ được biểu thị bằng **CLSID**. Bạn có thể tìm thông tin CLSID tại `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Trình điều khiển phông chữ

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Lệnh mở

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Trình xử lý COM menu ngữ cảnh

Các trình xử lý menu ngữ cảnh của Explorer là phần mở rộng shell được đăng ký dưới các khóa như `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` và `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Giá trị mặc định của trình xử lý, hoặc đôi khi là tên khóa, là một CLSID. Theo CLSID đó đến `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; giá trị mặc định tại đây cho biết DLL được tải khi trình xử lý được gọi.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Kiểm tra cả registry view 32-bit và 64-bit. `HKCR` hợp nhất các đăng ký lớp theo từng người dùng và trên toàn máy, vì vậy hãy xác minh tiến trình sẽ truy cập khóa nền nào. Một danh tính có đặc quyền thấp nhưng có thể thay đổi giá trị `InprocServer32` trên toàn máy có thể chuyển hướng một tiến trình có đặc quyền cao hơn sang DLL khác, nhưng việc leo thang đặc quyền đòi hỏi tiến trình đó phải gọi handler. Đường dẫn DLL có thể ghi cũng tạo ra rủi ro tương tự, ngay cả khi bản thân giá trị registry được bảo vệ.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Lưu ý rằng tất cả các vị trí có thể chứa autoruns **đã được**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **kiểm tra**. Tuy nhiên, để có **danh sách đầy đủ hơn các file tự động thực thi**, bạn có thể dùng [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)của systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Xem thêm

**Tìm thêm các Autoruns như registry tại** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Các cơ chế duy trì persistence phổ biến của malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Các danh mục Autostart (Khắc phục sự cố bằng Windows Sysinternals Tools, ấn bản thứ 2)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Làm cách nào để thêm tùy chọn khởi động mở một shell thay thế?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit – Tổng kết ngày 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
