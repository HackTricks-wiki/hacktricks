# Leo thang đặc quyền với Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** có thể được dùng để chạy các chương trình khi **khởi động**. Xem những binary nào được thiết lập để chạy khi khởi động bằng lệnh:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Tác vụ đã lên lịch

**Tác vụ** có thể được lên lịch để chạy với **tần suất cụ thể**. Sử dụng các lệnh sau để xem những binary nào được lên lịch chạy:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Một task được tạo bằng `/sc ONLOGON /rl HIGHEST` yêu cầu run level cao nhất **có sẵn cho principal đã đăng ký**; chỉ riêng switch này không thay đổi principal đó hay vượt qua UAC. Một process có quyền thấp không thể đăng ký task với run level cao nhất hoặc chọn SYSTEM làm danh tính của task. Hãy xem ví dụ trên là một hành động dành cho caller đã được nâng quyền, không phải con đường để một user thông thường có được quyền SYSTEM.<sup>[[8]](#references)</sup>

Một task được bật và chạy với quyền SYSTEM cần được kiểm tra ngay cả khi định nghĩa task và file action được bảo vệ. [Task Scheduler yêu cầu quyền thực thi trên task để chạy task theo yêu cầu](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Nếu một user có quyền thấp có quyền đó, hãy kiểm tra chính xác action, đặc biệt là các script PowerShell sửa đổi ACL của Active Directory hoặc đặt lại các cài đặt bảo vệ tài khoản. Kiểm tra cài đặt `AllowDemandStart` của task và xác minh đầu vào cũng như tác động của script; chỉ có quyền khởi chạy một task cố định không đồng nghĩa với khả năng thực thi code tùy ý.

## Thư mục

Tất cả các binary nằm trong **Startup folders sẽ được thực thi khi khởi động**. Các Startup folder phổ biến là những thư mục được liệt kê tiếp theo, nhưng Startup folder được chỉ định trong registry. [Đọc nội dung này để tìm hiểu vị trí.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Một mục Startup của người dùng có đặc quyền cao hơn có thể khởi chạy một script được bảo vệ nhưng liên tục mở các tệp từ thư mục mà người dùng khác có quyền ghi. Hãy kiểm tra **danh tính đăng nhập thực tế** của mục đó, thư mục đầu vào và ACL của script, cùng hành động chính xác trước khi xem thư mục đó là con đường leo thang đặc quyền. Cụ thể, [`hh.exe` mở các tệp HTML Help đã biên dịch (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); một script truyền các tệp do người gọi cung cấp cho chương trình này sẽ vượt qua ranh giới tin cậy nội dung, ngay cả khi script kiểm tra tên tệp hoặc các byte đầu tiên. [Các chính sách HTML Help có thể hạn chế shortcut thực thi](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), vì vậy hãy xác nhận chính sách đang được cài đặt và hành vi nội dung có thể truy cập. Chỉ riêng phần mở rộng `.chm` hoặc magic bytes không chứng minh được khả năng thực thi mã với đặc quyền cao hơn. Hãy kiểm tra autorun, dòng lệnh của tiến trình và quyền trên đường dẫn mà không mở tệp không đáng tin cậy trong quá trình liệt kê.

Ranh giới nội dung tương tự cũng tồn tại khi một người có đặc quyền cao hơn **mở thủ công** tệp `.chm` từ thư mục tài liệu mà người dùng khác có thể thay thế. Hãy xác nhận chính xác tệp và quyền ghi trên thư mục cha, danh tính thực tế của người xem cùng sự kiện mở tệp, và chính sách HTML Help có hiệu lực. Một thư mục có quyền ghi hoặc yêu cầu xem lại tài liệu không chứng minh rằng danh tính có đặc quyền cao hơn đã mở nội dung do kẻ tấn công kiểm soát.

> **FYI**: Các lỗ hổng *path traversal* khi giải nén archive (chẳng hạn lỗ hổng bị khai thác trong WinRAR trước phiên bản 7.13 – CVE-2025-8088) có thể được tận dụng để **đưa trực tiếp payload vào các thư mục Startup trong quá trình giải nén**, dẫn đến thực thi mã vào lần đăng nhập tiếp theo của người dùng. Để tìm hiểu sâu về kỹ thuật này, xem:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Ghi chú tại đây](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Mục registry **Wow6432Node** cho biết bạn đang chạy phiên bản Windows 64-bit. Hệ điều hành sử dụng khóa này để hiển thị một chế độ xem riêng của HKEY_LOCAL_MACHINE\SOFTWARE dành cho các ứng dụng 32-bit chạy trên phiên bản Windows 64-bit.

### Runs

Các registry AutoRun **thường được biết đến**:

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

Các khóa registry có tên **Run** và **RunOnce** được thiết kế để tự động thực thi chương trình mỗi khi người dùng đăng nhập vào hệ thống. Dòng lệnh được gán làm giá trị dữ liệu của khóa bị giới hạn ở tối đa 260 ký tự.<sup>[[2]](#references)</sup>

**Các khóa Service runs** (có thể kiểm soát việc tự động khởi động dịch vụ trong quá trình boot):

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

Trên Windows Vista và các phiên bản mới hơn, các khóa registry **Run** và **RunOnce** không được tự động tạo. Các mục trong những khóa này có thể khởi chạy chương trình trực tiếp hoặc chỉ định chương trình dưới dạng dependency. Ví dụ, để tải một tệp DLL khi đăng nhập, có thể dùng khóa registry **RunOnceEx** cùng với khóa "Depend". Có thể minh họa bằng cách thêm một mục registry để thực thi "C:\temp\evil.dll" trong quá trình khởi động hệ thống:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Nếu bạn có thể ghi vào bất kỳ registry nào được đề cập bên trong **HKLM**, bạn có thể leo thang đặc quyền khi một người dùng khác đăng nhập.

> [!TIP]
> **Exploit 2**: Nếu bạn có thể ghi đè bất kỳ binary nào được chỉ định trong registry bên trong **HKLM**, bạn có thể sửa đổi binary đó bằng backdoor khi một người dùng khác đăng nhập và leo thang đặc quyền.

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

### Đường dẫn khởi động

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Các shortcut được đặt trong thư mục **Startup** sẽ tự động kích hoạt dịch vụ hoặc ứng dụng khởi chạy khi người dùng đăng nhập hoặc hệ thống khởi động lại. Vị trí của thư mục **Startup** được xác định trong registry cho cả phạm vi **Local Machine** và **Current User**. Điều này có nghĩa là mọi shortcut được thêm vào các vị trí **Startup** đã chỉ định sẽ đảm bảo dịch vụ hoặc chương trình được liên kết khởi chạy sau khi đăng nhập hoặc khởi động lại, trở thành một phương pháp đơn giản để lên lịch chạy chương trình tự động.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Nếu bạn có thể ghi đè bất kỳ Shell Folder nào của [User] trong **HKLM**, bạn sẽ có thể trỏ nó đến một thư mục do bạn kiểm soát và đặt một backdoor sẽ được thực thi mỗi khi người dùng đăng nhập vào hệ thống, từ đó leo thang đặc quyền.

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
> Nếu bạn có thể ghi giá trị này cho người dùng hiện tại, bạn có thể kích hoạt lại việc thực thi vào lần đăng nhập tương tác tiếp theo mà không cần quyền admin. Nếu có thể ghi vào hive của người dùng khác, bạn có thể thực thi code khi người dùng đó đăng nhập.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Ghi chú:

- Ưu tiên dùng đường dẫn đầy đủ đến các tệp `.bat`, `.cmd`, `.ps1` hoặc tệp launcher khác mà người dùng mục tiêu đã có quyền đọc.
- Thiết lập này vẫn còn hiệu lực sau khi đăng xuất/khởi động lại cho đến khi giá trị bị xóa.
- Không giống `HKLM\...\Run`, thiết lập này **không tự cấp quyền nâng cao**; đây là cơ chế persistence trong phạm vi người dùng.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Thông thường, khóa **Userinit** được đặt thành **userinit.exe**. Tuy nhiên, nếu khóa này bị sửa đổi, tệp thực thi được chỉ định cũng sẽ được **Winlogon** khởi chạy khi người dùng đăng nhập. Tương tự, khóa **Shell** được thiết kế để trỏ đến **explorer.exe**, shell mặc định của Windows.<sup>[[1]](#references)</sup>

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

Kiểm tra key **Run**.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Thay đổi Command Prompt trong Safe Mode

Trong Windows Registry, tại `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, có một giá trị **`AlternateShell`** mặc định được đặt thành `cmd.exe`. Điều này có nghĩa là khi bạn chọn "Safe Mode with Command Prompt" lúc khởi động (bằng cách nhấn F8), `cmd.exe` sẽ được sử dụng. Tuy nhiên, bạn có thể thiết lập máy tính tự động khởi động ở chế độ này mà không cần nhấn F8 và chọn thủ công.

Các bước tạo tùy chọn khởi động để tự động vào "Safe Mode with Command Prompt":<sup>[[5]](#references)</sup>

1. Thay đổi thuộc tính của tệp `boot.ini` để xóa các cờ chỉ đọc, hệ thống và ẩn: `attrib c:\boot.ini -r -s -h`
2. Mở `boot.ini` để chỉnh sửa.
3. Thêm một dòng như sau: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Lưu thay đổi vào `boot.ini`.
5. Khôi phục các thuộc tính ban đầu của tệp: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Thay đổi khóa registry **AlternateShell** cho phép thiết lập command shell tùy chỉnh, có khả năng tạo điều kiện cho truy cập trái phép.
- **Exploit 2 (Quyền ghi PATH):** Có quyền ghi vào bất kỳ phần nào của biến **PATH** hệ thống, đặc biệt là trước `C:\Windows\system32`, cho phép bạn chạy một `cmd.exe` tùy chỉnh. Đây có thể là backdoor nếu hệ thống được khởi động trong Safe Mode.
- **Exploit 3 (Quyền ghi PATH và boot.ini):** Có quyền ghi vào `boot.ini` cho phép tự động khởi động Safe Mode, tạo điều kiện cho truy cập trái phép trong lần khởi động lại tiếp theo.

Để kiểm tra cài đặt **AlternateShell** hiện tại, hãy dùng các lệnh sau:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Thành phần đã cài đặt

Active Setup là một tính năng của Windows **khởi chạy trước khi môi trường desktop được tải hoàn toàn**. Tính năng này ưu tiên thực thi một số lệnh nhất định, các lệnh này phải hoàn tất trước khi quá trình đăng nhập của người dùng tiếp tục. Quá trình này diễn ra ngay cả trước khi các mục khởi động khác, chẳng hạn như những mục trong các khóa registry Run hoặc RunOnce, được kích hoạt.

Active Setup được quản lý thông qua các khóa registry sau:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Trong các khóa này có nhiều khóa con, mỗi khóa tương ứng với một thành phần cụ thể. Các giá trị khóa đáng chú ý gồm:

- **IsInstalled:**
  - `0` cho biết lệnh của thành phần sẽ không được thực thi.
  - `1` nghĩa là lệnh sẽ được thực thi một lần cho mỗi người dùng. Đây là hành vi mặc định nếu thiếu giá trị `IsInstalled`.
- **StubPath:** Xác định lệnh Active Setup sẽ thực thi. Đây có thể là bất kỳ dòng lệnh hợp lệ nào, chẳng hạn như khởi chạy `notepad`.

**Thông tin bảo mật:**

- Việc sửa đổi hoặc ghi vào một khóa có **`IsInstalled`** được đặt thành `"1"` cùng với **`StubPath`** cụ thể có thể dẫn đến thực thi lệnh trái phép, tiềm ẩn nguy cơ leo thang đặc quyền.
- Thay đổi tệp nhị phân được tham chiếu trong bất kỳ giá trị **`StubPath`** nào cũng có thể giúp leo thang đặc quyền, nếu có đủ quyền.

Có thể dùng các lệnh sau để kiểm tra cấu hình **`StubPath`** trên các thành phần Active Setup:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Tổng quan về Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) là các module DLL bổ sung tính năng cho Internet Explorer của Microsoft. Chúng được tải vào Internet Explorer và Windows Explorer mỗi khi khởi động. Tuy nhiên, có thể chặn việc thực thi bằng cách đặt khóa **NoExplorer** thành 1, ngăn chúng tải cùng các phiên bản Windows Explorer.<sup>[[1]](#references)</sup>

BHOs tương thích với Windows 10 thông qua Internet Explorer 11 nhưng không được hỗ trợ trong Microsoft Edge, trình duyệt mặc định ở các phiên bản Windows mới hơn.

Để xem các BHO đã đăng ký trên hệ thống, bạn có thể kiểm tra các khóa registry sau:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Mỗi BHO được biểu thị bằng **CLSID** trong registry, đóng vai trò là mã định danh duy nhất. Bạn có thể tìm thông tin chi tiết về từng CLSID tại `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Có thể sử dụng các lệnh sau để truy vấn BHO trong registry:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Tiện ích mở rộng Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Lưu ý rằng registry sẽ chứa một registry mới cho mỗi DLL và registry đó sẽ được biểu thị bằng **CLSID**. Bạn có thể tìm thông tin CLSID tại `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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

### Trình xử lý COM của menu ngữ cảnh

Các trình xử lý menu ngữ cảnh của Explorer là phần mở rộng shell được đăng ký dưới các khóa như `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` và `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Giá trị mặc định của trình xử lý, hoặc đôi khi là tên khóa của nó, là một CLSID. Theo CLSID đó đến `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; giá trị mặc định của khóa này chỉ định DLL được tải khi trình xử lý được gọi.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Kiểm tra cả registry view 32-bit và 64-bit. `HKCR` hợp nhất các đăng ký class theo từng người dùng và trên toàn máy, vì vậy hãy xác minh process sẽ phân giải đến key nền nào. Một identity có đặc quyền thấp nhưng có thể thay đổi giá trị `InprocServer32` trên toàn máy có thể chuyển hướng một process có đặc quyền cao hơn đến DLL khác, nhưng việc nâng quyền chỉ xảy ra nếu process đó gọi handler. Đường dẫn DLL có thể ghi cũng tạo ra rủi ro tương tự, ngay cả khi bản thân giá trị registry được bảo vệ.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Lưu ý rằng mọi vị trí có thể chứa autorun đều **đã được**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)** tìm kiếm**. Tuy nhiên, để có danh sách **toàn diện hơn về các file tự động thực thi**, bạn có thể dùng [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)của systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Thêm

**Tìm thêm các mục Autoruns như registry tại** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Các cơ chế duy trì sự tồn tại phổ biến của malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Thực thi tự động khi khởi động hoặc đăng nhập: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Script khởi tạo khi khởi động hoặc đăng nhập: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Các danh mục tự động khởi động (Khắc phục sự cố bằng Windows Sysinternals Tools, Ấn bản thứ 2)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Làm cách nào để thêm tùy chọn khởi động chạy một shell thay thế?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Tổng kết Metasploit 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – Ngữ cảnh bảo mật cho tác vụ](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
