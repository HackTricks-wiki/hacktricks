# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Si puedes **escribir en un directorio del `PATH` de todo el sistema** (no solo en el `PATH` de tu usuario), es posible que puedas **escalar privilegios** en el sistema.

Esto puede aprovecharse mediante **DLL hijacking** cuando un servicio o proceso con más privilegios intenta cargar una DLL que no existe en sus ubicaciones de búsqueda anteriores y finalmente busca en el directorio escribible del `PATH` del sistema.

Una entrada escribible en el `PATH` de Machine es solo una **primitiva**, no una prueba de ejecución de código. Para una aplicación sin empaquetar que utiliza el orden de búsqueda estándar, se llega a `PATH` después de la redirección, los API sets, SxS, la lista de módulos cargados, KnownDLLs, los directorios de la aplicación y de Windows, y el directorio actual. Una ruta completa o una política `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` puede excluir completamente `PATH`.<sup>[[4]](#references)</sup>

Para obtener más información sobre **DLL hijacking**, consulta:

{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

Primero, **identifica un proceso** que se ejecute con **más privilegios** e intente **cargar una DLL desde un directorio escribible del `PATH` del sistema**.

Recuerda que esta técnica depende de una entrada del `PATH` de Machine/System, no únicamente de tu **User PATH**. Por lo tanto, antes de dedicar tiempo a Procmon, vale la pena enumerar las entradas del **Machine PATH** y comprobar cuáles son escribibles:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
El texto de las ACL puede ser engañoso porque la pertenencia a grupos, las ACE de denegación y los permisos heredados afectan al resultado. En una prueba autorizada, una comprobación de creación/eliminación verifica el **acceso efectivo del token actual** (es intrusiva y puede generar alertas):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Confirmar el `PATH` efectivo del objetivo

El `PATH` de Machine leído del registro son datos de configuración; el loader utiliza el bloque de entorno del **proceso objetivo**. Cada proceso posee un bloque de entorno, y normalmente un proceso hijo hereda una copia del entorno de su proceso padre. En consecuencia, un servicio de larga duración puede conservar un valor antiguo, y un servicio iniciado con un entorno personalizado puede diferir del valor visible en tu shell. Trata una comprobación de Procmon del directorio exacto realizada por el PID objetivo como la fuente de verdad; después de cambiar `PATH` en un laboratorio, reinicia el árbol de procesos relevante o reinicia el sistema antes de concluir que la búsqueda no se produce.<sup>[[5]](#references)</sup>

El problema en estos casos es que esos procesos probablemente ya están en ejecución. Para identificar las DLL que los servicios intentan cargar sin éxito, inicia Procmon lo antes posible (antes de que se inicien los procesos) y, a continuación:

> [!WARNING]
> Añadir un directorio escribible por el usuario al `PATH` de Machine **crea la condición vulnerable**. Hazlo únicamente en una VM de investigación aislada para revelar qué procesos privilegiados acceden al `PATH`; en un host evaluado, monitoriza la entrada escribible existente sin cambiar la configuración del sistema.<sup>[[1]](#references)</sup>

- **Crea** la carpeta `C:\privesc_hijacking` y añade la ruta `C:\privesc_hijacking` a la **variable de entorno System Path**. Puedes hacerlo **manualmente** o con **PS**:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Inicia **`procmon`**, ve a **`Options`** --> **`Enable boot logging`** y pulsa **`OK`** en el aviso.
- Después, **reinicia** el equipo. Cuando se reinicie, **`procmon`** comenzará a **registrar** eventos lo antes posible.
- Una vez que **Windows** se haya **iniciado, ejecuta `procmon`** de nuevo. Te indicará que ha estado ejecutándose y te **preguntará si quieres guardar** los eventos en un archivo. Responde **sí** y **guarda los eventos en un archivo**.
- **Después** de que se haya **generado el archivo**, cierra la ventana de **`procmon`** abierta y **abre el archivo de eventos**.
- Añade estos **filtros** para encontrar todas las DLLs que un **proceso intentó cargar** desde la carpeta writable del System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** solo es necesario para los servicios que se inician demasiado pronto como para observarlos de otro modo. Si puedes **activar el servicio/programa objetivo bajo demanda** (por ejemplo, interactuando con su interfaz COM, reiniciando el servicio o volviendo a iniciar una tarea programada), normalmente es más rápido mantener una captura normal de Procmon con filtros como **`Path contains .dll`**, **`Result is NAME NOT FOUND`** y **`Path begins with <writable_machine_path>`**.

### DLLs no detectadas

Al ejecutar esto en una máquina **virtual (vmware) Windows 11** gratuita, obtuve estos resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

En este caso, ignora los resultados `.exe`. Las búsquedas de DLLs faltantes procedían de:

| Servicio                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

El siguiente ejemplo utiliza la técnica descrita en este artículo sobre [**abusar de `WptsExtensions.dll` para realizar una escalada de privilegios**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Otros candidatos que vale la pena analizar

`WptsExtensions.dll` es un buen ejemplo, pero no es la única **phantom DLL** recurrente que aparece en servicios privilegiados. Las reglas modernas de hunting y los catálogos públicos de hijacking todavía registran nombres como:<sup>[[2]](#references)</sup>

| Servicio / Escenario | DLL faltante | Notas |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidato clásico de **SYSTEM** en sistemas cliente. Es útil cuando el directorio writable está en el **Machine PATH** y el servicio busca la DLL durante el inicio. |
| NetMan en Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Es interesante en **ediciones de servidor** porque el servicio se ejecuta como **SYSTEM** y, en algunas builds, un **usuario normal puede activarlo bajo demanda**, lo que lo hace mejor que los casos que solo funcionan tras un reinicio. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Normalmente obtiene primero **`NT AUTHORITY\LOCAL SERVICE`**. A menudo esto sigue siendo suficiente porque el token tiene **`SeImpersonatePrivilege`**, por lo que puedes encadenarlo con [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considera estos nombres como **indicadores para el análisis**, no como resultados garantizados: dependen de la **SKU/build**, y Microsoft puede cambiar el comportamiento entre versiones. La conclusión importante es buscar **DLLs faltantes en servicios privilegiados que recorren el Machine PATH**, especialmente si el servicio puede **activarse de nuevo sin reiniciar**.

### Valida un candidato antes de weaponizarlo

Un evento `NAME NOT FOUND` por sí solo no es suficiente. Antes de colocar un payload, verifica la cadena completa:<sup>[[1]](#references)[[4]](#references)</sup>

1. El evento pertenece al **PID, command line, cuenta de servicio y nivel de integridad** esperados, y la ruta faltante es exactamente el directorio writable del Machine `PATH`.
2. Para el mismo basename de DLL, ningún directorio anterior devuelve `SUCCESS`, y el módulo no se satisface mediante la lista de módulos cargados, KnownDLLs, redirection o un manifiesto SxS.
3. La búsqueda se repite cuando un usuario con pocos privilegios invoca el trigger previsto. Una búsqueda que solo ocurre durante el arranque es utilizable, pero operativamente mucho peor que una activable bajo demanda.
4. La arquitectura del payload coincide con la del proceso. Si la aplicación resuelve exports posteriormente, utiliza como proxy la DLL legítima o exporta los símbolos esperados; consulta [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Primero utiliza una DLL canary inofensiva que registre el PID, la identidad y la marca de tiempo. En Procmon, exige un **`Load Image`** exitoso desde la ruta plantada en lugar de asumir que una búsqueda previa del archivo provocó la ejecución.

### Explotación

Para **escalar privilegios**, realiza un hijacking de **`WptsExtensions.dll`**. Una vez conocidos la **ruta** y el **nombre**, genera la DLL maliciosa.

Puedes [**intentar utilizar cualquiera de estos ejemplos**](README.md#creating-and-compiling-dlls). Podrías ejecutar payloads como: obtener una rev shell, añadir un usuario, ejecutar un beacon...

> [!WARNING]
> Ten en cuenta que **no todos los servicios se ejecutan** como **`NT AUTHORITY\SYSTEM`**. Algunos se ejecutan como **`NT AUTHORITY\LOCAL SERVICE`**, que tiene **menos privilegios**, por lo que abusar de uno de estos servicios podría no permitirte crear un usuario.\
> Sin embargo, esa cuenta tiene el derecho de usuario **`SeImpersonatePrivilege`**, por lo que puedes utilizar la [**Potato suite para escalar privilegios**](../roguepotato-and-printspoofer.md). En este caso, una reverse shell es una opción mejor que intentar crear un usuario.

El servicio **Task Scheduler** normalmente se ejecuta como **`NT AUTHORITY\SYSTEM`**, pero verifica el despliegue real y no deduzcas la identidad de ejecución únicamente a partir del nombre del servicio:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Habiendo **generado la Dll maliciosa** (_en mi caso usé una reverse shell x64 y obtuve una shell, pero Defender la eliminó porque provenía de msfvenom_), guárdala en el System Path escribible con el nombre **WptsExtensions.dll** y **reinicia** el equipo (o reinicia el servicio, o haz lo necesario para volver a ejecutar el servicio/programa afectado).

Cuando se reinicie el servicio, la **DLL debería cargarse y ejecutarse** (puedes **reutilizar** el truco de **Procmon** para comprobar si la **biblioteca se cargó como se esperaba**).

> [!NOTE]
> Planifica la limpieza antes de activar el payload. Un servicio puede mantener la DLL mapeada y bloquear el archivo hasta que se detenga; para `WptsExtensions.dll`, detener Task Scheduler requiere permisos elevados. Después de obtener el contexto previsto, detén el objetivo de forma segura, elimina el payload y restaura cualquier cambio de `PATH` realizado solo para el laboratorio.<sup>[[1]](#references)</sup>

### Remediation / detection

Elimina los permisos de escritura débiles de todos los directorios de Machine `PATH` y elimina las entradas obsoletas. Los desarrolladores deberían cargar bibliotecas de confianza mediante la ruta completa o limitar la resolución con `SetDefaultDllDirectories` / las flags de búsqueda de `LoadLibraryEx`. Los defensores pueden correlacionar los cambios en Machine `PATH` con procesos privilegiados que carguen DLL desde directorios que no sean del sistema y en los que los usuarios puedan escribir.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Secuestro de DLL de Windows (con suerte) aclarado](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [DLL sospechosa cargada para persistencia o escalada de privilegios](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Orden de búsqueda de bibliotecas de enlace dinámico](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Variables de entorno](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
