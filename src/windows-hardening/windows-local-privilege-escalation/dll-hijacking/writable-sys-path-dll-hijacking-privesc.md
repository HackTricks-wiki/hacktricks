# Leo thang đặc quyền bằng DLL Hijacking qua System PATH có thể ghi

{{#include ../../../banners/hacktricks-training.md}}

## Giới thiệu

Nếu bạn có thể **ghi vào một thư mục trong `PATH` toàn hệ thống** (không chỉ `PATH` của người dùng), bạn có thể **leo thang đặc quyền** trên hệ thống.

Có thể lạm dụng điều này thông qua **DLL hijacking** khi một dịch vụ hoặc tiến trình có đặc quyền cao hơn cố tải một DLL không tồn tại ở các vị trí tìm kiếm trước đó và cuối cùng tìm trong thư mục system `PATH` có thể ghi.

Một mục Machine `PATH` có thể ghi chỉ là một **primitive**, không phải bằng chứng cho thấy mã sẽ được thực thi. Với ứng dụng không đóng gói sử dụng thứ tự tìm kiếm tiêu chuẩn, `PATH` được xét sau redirection, API sets, SxS, danh sách module đã tải, KnownDLLs, thư mục ứng dụng và Windows, cũng như thư mục hiện tại. Chính sách dùng đường dẫn đầy đủ hoặc `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` có thể loại trừ hoàn toàn `PATH`.<sup>[[4]](#references)</sup>

Để biết thêm thông tin về **DLL hijacking**, xem:

{{#ref}}
./
{{#endref}}

## Leo thang đặc quyền bằng DLL Hijacking

### Tìm DLL bị thiếu

Trước tiên, **xác định một tiến trình** đang chạy với **đặc quyền cao hơn** và cố **tải DLL từ một thư mục system `PATH` có thể ghi**.

Hãy nhớ rằng kỹ thuật này phụ thuộc vào mục **Machine/System PATH**, không chỉ **User PATH** của bạn. Vì vậy, trước khi mất thời gian dùng Procmon, bạn nên liệt kê các mục **Machine PATH** và kiểm tra xem mục nào có thể ghi:<sup>[[1]](#references)</sup>

```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
    $path = $_.Trim()
    if ($path) {
        Write-Host "`n[*] $path"
        icacls $path 2>$null
    }
}
```

ACL text có thể gây hiểu nhầm vì tư cách thành viên nhóm, các deny ACE và quyền kế thừa ảnh hưởng đến kết quả. Trong một cuộc kiểm thử được ủy quyền, phép thử tạo/xóa sẽ kiểm tra **quyền truy cập hiệu lực của token hiện tại** (có tính xâm nhập và có thể tạo cảnh báo):<sup>[[1]](#references)</sup>

```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
    ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
    Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
    $probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
    catch { }
}
```

### Xác nhận `PATH` hiệu lực của mục tiêu

`PATH` của Machine được đọc từ registry là dữ liệu cấu hình; loader sử dụng environment block của **process mục tiêu**. Mỗi process có environment block riêng, và process con thường kế thừa một bản sao môi trường của process cha. Vì vậy, một service chạy lâu có thể giữ giá trị cũ, còn service được khởi chạy với môi trường tùy chỉnh có thể khác với giá trị bạn thấy trong shell. Hãy xem Procmon ghi nhận probe của PID mục tiêu đến đúng thư mục là dữ liệu xác thực; sau khi thay đổi `PATH` trong lab, hãy khởi động lại cây process liên quan hoặc reboot trước khi kết luận rằng việc tra cứu không xảy ra.<sup>[[5]](#references)</sup>

Vấn đề trong những trường hợp này là các process đó có thể đã chạy từ trước. Để xác định các DLL mà service cố tải nhưng không thành công, hãy khởi chạy Procmon sớm nhất có thể (trước khi các process khởi chạy), sau đó:

> [!WARNING]
> Thêm một thư mục mà user có thể ghi vào Machine `PATH` **sẽ tạo ra điều kiện dễ bị tấn công**. Chỉ thực hiện việc này trong một research VM cô lập để phát hiện những process đặc quyền nào truy cập `PATH`; trên host đang được đánh giá, hãy theo dõi entry có quyền ghi sẵn có mà không thay đổi cấu hình hệ thống.<sup>[[1]](#references)</sup>

- **Tạo** thư mục `C:\privesc_hijacking` và thêm đường dẫn `C:\privesc_hijacking` vào **biến môi trường System Path**. Bạn có thể thực hiện việc này **thủ công** hoặc bằng **PS**:

```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
    New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
    $newPath = "$envPath;$folderPath"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```

- Khởi chạy **`procmon`**, vào **`Options`** --> **`Enable boot logging`** rồi nhấn **`OK`** trong lời nhắc.
- Sau đó, **khởi động lại**. Khi máy tính khởi động lại, **`procmon`** sẽ bắt đầu **ghi lại** sự kiện ngay lập tức.
- Sau khi **Windows** **khởi động**, chạy lại `procmon`. Chương trình sẽ thông báo rằng nó đã chạy và **hỏi bạn có muốn lưu** sự kiện vào tệp hay không. Chọn yes và **lưu sự kiện vào tệp**.
- **Sau khi** **tệp** được **tạo**, **đóng** cửa sổ **`procmon`** đang mở rồi **mở tệp sự kiện**.
- Thêm các **bộ lọc** sau để tìm tất cả DLL mà một **process đã thử tải** từ thư mục System Path có quyền ghi:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Chỉ cần bật **Boot logging** đối với các service khởi động quá sớm để có thể quan sát theo cách khác. Nếu bạn có thể **kích hoạt service/program mục tiêu theo yêu cầu** (ví dụ: tương tác với giao diện COM, khởi động lại service hoặc chạy lại scheduled task), thì thường sẽ nhanh hơn nếu dùng Procmon để capture thông thường với các bộ lọc như **`Path contains .dll`**, **`Result is NAME NOT FOUND`** và **`Path begins with <writable_machine_path>`**.

### Các DLL bị bỏ sót

Khi chạy thử trên một máy ảo **Windows 11** miễn phí (**vmware**), tôi nhận được kết quả sau:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Trong trường hợp này, hãy bỏ qua các kết quả `.exe`. Các lần dò tìm DLL bị thiếu đến từ:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Ví dụ sau sử dụng kỹ thuật được mô tả trong bài viết này về [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Các ứng viên khác đáng để phân loại

`WptsExtensions.dll` là một ví dụ điển hình, nhưng không phải là **phantom DLL** duy nhất thường xuất hiện trong các service có đặc quyền. Các quy tắc hunting hiện đại và danh mục hijack công khai vẫn theo dõi những tên như sau:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Ứng viên **SYSTEM** kinh điển trên các hệ thống client. Phù hợp khi thư mục có quyền ghi nằm trong **Machine PATH** và service dò tìm DLL lúc khởi động. |
| NetMan trên Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Đáng chú ý trên các **phiên bản server** vì service chạy với quyền **SYSTEM** và trong một số bản dựng, **người dùng thông thường có thể kích hoạt theo yêu cầu**, khiến trường hợp này tốt hơn những trường hợp chỉ xảy ra khi khởi động lại. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Thường trước tiên sẽ cho kết quả **`NT AUTHORITY\LOCAL SERVICE`**. Điều đó thường vẫn đủ vì token có **`SeImpersonatePrivilege`**, nên bạn có thể kết hợp nó với [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Hãy xem các tên này là **gợi ý để phân loại**, không phải kết quả chắc chắn: chúng **phụ thuộc vào SKU/bản dựng**, và Microsoft có thể thay đổi hành vi giữa các phiên bản phát hành. Điểm quan trọng là tìm các **DLL bị thiếu trong những service có đặc quyền truy vấn Machine PATH**, đặc biệt nếu có thể **kích hoạt lại service mà không cần khởi động lại**.

### Xác thực ứng viên trước khi weaponize

Một sự kiện `NAME NOT FOUND` riêng lẻ là chưa đủ. Trước khi đặt payload, hãy xác minh toàn bộ chuỗi:<sup>[[1]](#references)[[4]](#references)</sup>

1. Sự kiện thuộc về **PID, command line, tài khoản service và mức độ toàn vẹn** dự kiến, đồng thời đường dẫn bị thiếu chính là thư mục Machine `PATH` có quyền ghi.
2. Với cùng một tên DLL cơ sở, không có thư mục nào đứng trước trả về `SUCCESS`, và module không được tìm thấy trong danh sách module đã nạp, KnownDLLs, cơ chế chuyển hướng hoặc manifest SxS.
3. Lần dò tìm lặp lại khi người dùng có đặc quyền thấp gọi trigger dự kiến. Tra cứu chỉ xảy ra lúc khởi động vẫn có thể dùng được, nhưng kém thuận tiện hơn nhiều so với trigger theo yêu cầu.
4. Kiến trúc của payload phải khớp với process. Nếu ứng dụng sau đó phân giải các export, hãy proxy DLL hợp lệ hoặc export các symbol mà ứng dụng mong đợi; xem [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Trước tiên, hãy dùng một DLL canary vô hại để ghi lại PID, danh tính và dấu thời gian. Trong Procmon, hãy xác nhận có sự kiện **`Load Image`** thành công từ đường dẫn đã đặt DLL, thay vì cho rằng một lần dò tìm tệp trước đó đã khiến DLL được thực thi.

### Khai thác

Để **leo thang đặc quyền**, hãy hijack **`WptsExtensions.dll`**. Khi đã biết **đường dẫn** và **tên**, hãy tạo DLL độc hại.

Bạn có thể [**thử dùng bất kỳ ví dụ nào trong số này**](README.md#creating-and-compiling-dlls). Bạn có thể chạy các payload như: lấy rev shell, thêm người dùng, thực thi beacon...

> [!WARNING]
> Lưu ý rằng **không phải service nào cũng chạy** với quyền **`NT AUTHORITY\SYSTEM`**. Một số chạy với quyền **`NT AUTHORITY\LOCAL SERVICE`**, vốn có **ít đặc quyền hơn**, nên abuse một trong các service này có thể không cho phép bạn tạo người dùng mới.\
> Tuy nhiên, tài khoản đó có user right **`SeImpersonatePrivilege`**, vì vậy bạn có thể dùng [**bộ công cụ Potato để leo thang đặc quyền**](../roguepotato-and-printspoofer.md). Trong trường hợp này, reverse shell là lựa chọn tốt hơn so với việc cố tạo người dùng.

Service **Task Scheduler** thường chạy với quyền **`NT AUTHORITY\SYSTEM`**, nhưng hãy xác minh môi trường triển khai thực tế và đừng suy đoán danh tính thực thi chỉ dựa trên tên service:<sup>[[3]](#references)</sup>

```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```

Sau khi **tạo DLL độc hại** (_trong trường hợp của tôi, tôi dùng x64 rev shell và nhận được shell, nhưng Defender đã kill nó vì nó được tạo bằng msfvenom_), hãy lưu nó vào System Path có quyền ghi với tên **WptsExtensions.dll** rồi **khởi động lại** máy tính (hoặc khởi động lại service hay làm bất cứ điều gì cần thiết để chạy lại service/chương trình bị ảnh hưởng).

Khi service khởi động lại, **DLL sẽ được tải và thực thi** (bạn có thể **dùng lại** thủ thuật **Procmon** để kiểm tra xem **thư viện có được tải như mong đợi hay không**).

> [!NOTE]
> Hãy lên kế hoạch cleanup trước khi kích hoạt. Service có thể giữ DLL được map và khóa file cho đến khi dừng; với `WptsExtensions.dll`, cần quyền elevated để dừng Task Scheduler. Sau khi có được context mong muốn, hãy dừng target một cách an toàn, xóa payload và khôi phục mọi thay đổi `PATH` chỉ dùng trong lab.<sup>[[1]](#references)</sup>

### Khắc phục / phát hiện

Xóa các quyền ghi yếu khỏi mọi thư mục trong Machine `PATH` và xóa các mục cũ. Developer nên tải các library đáng tin cậy bằng full path hoặc giới hạn cơ chế tìm kiếm bằng các cờ `SetDefaultDllDirectories` / `LoadLibraryEx`. Defender có thể đối chiếu các thay đổi đối với Machine `PATH` với những tiến trình có đặc quyền tải DLL từ các thư mục không thuộc hệ thống và cho phép người dùng ghi.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking (hy vọng đã được giải thích rõ)](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [DLL đáng ngờ được tải để duy trì truy cập hoặc leo thang đặc quyền](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Leo thang đặc quyền trên Windows](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Thứ tự tìm kiếm thư viện liên kết động](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Biến môi trường](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
