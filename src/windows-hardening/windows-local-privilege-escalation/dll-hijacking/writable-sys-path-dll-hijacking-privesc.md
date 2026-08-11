# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Si puedes **escribir en un directorio de la `PATH` de todo el sistema** (no solo en la `PATH` de tu usuario), es posible que puedas **escalar privilegios** en el sistema.

Esto se puede aprovechar mediante **DLL hijacking** cuando un servicio o proceso con más privilegios intenta cargar una DLL que no existe en sus ubicaciones de búsqueda anteriores y finalmente busca en el directorio de la `PATH` del sistema que permite escritura.

Para obtener más información sobre **DLL hijacking**, consulta:


{{#ref}}
./
{{#endref}}

## Privesc con Dll Hijacking

### Encontrar una DLL faltante

Primero, **identifica un proceso** que se ejecute con **más privilegios** y que intente **cargar una DLL desde un directorio de la `PATH` del sistema que permita escritura**.

Recuerda que esta técnica depende de una entrada `PATH` de **Machine/System**, no únicamente de tu `User PATH`. Por lo tanto, antes de dedicar tiempo a Procmon, vale la pena enumerar las entradas de `Machine PATH` y comprobar cuáles permiten escritura:<sup>[[1]](#references)</sup>
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
El problema en estos casos es que esos procesos probablemente ya están en ejecución. Para identificar las DLL que los servicios intentan cargar sin éxito, inicia Procmon lo antes posible (antes de que se inicien los procesos) y, a continuación:

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
- Después, **reinicia** el equipo. Cuando se reinicie el equipo, **`procmon`** comenzará a **registrar** eventos lo antes posible.
- Una vez que **Windows** se haya **iniciado, ejecuta `procmon`** de nuevo. Te indicará que ha estado ejecutándose y te **preguntará si quieres almacenar** los eventos en un archivo. Responde **sí** y **almacena los eventos en un archivo**.
- **Después** de que se haya **generado el archivo**, cierra la ventana de **`procmon`** abierta y **abre el archivo de eventos**.
- Añade estos **filtros** para encontrar todas las DLL que un **proceso intentó cargar** desde la carpeta writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** solo es necesario para servicios que se inician **demasiado pronto** como para observarlos de otro modo. Si puedes **activar el servicio/programa objetivo bajo demanda** (por ejemplo, interactuando con su interfaz COM, reiniciando el servicio o volviendo a iniciar una tarea programada), normalmente es más rápido mantener una captura normal de Procmon con filtros como **`Path contains .dll`**, **`Result is NAME NOT FOUND`** y **`Path begins with <writable_machine_path>`**.

### DLL omitidas

Al ejecutar esto en una máquina **virtual (vmware) gratuita con Windows 11**, obtuve estos resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

En este caso, ignora los resultados `.exe`. Las búsquedas de DLL ausentes procedían de:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

El siguiente ejemplo utiliza la técnica descrita en este artículo sobre [**abusar de `WptsExtensions.dll` para la escalada de privilegios**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Otros candidatos que merece la pena analizar

`WptsExtensions.dll` es un buen ejemplo, pero no es la única **phantom DLL** recurrente que aparece en servicios privilegiados. Las reglas modernas de hunting y los catálogos públicos de hijacking todavía registran nombres como:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidato clásico de **SYSTEM** en sistemas cliente. Es útil cuando el directorio writable está en el **Machine PATH** y el servicio busca la DLL durante el inicio. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesante en **ediciones de servidor** porque el servicio se ejecuta como **SYSTEM** y, en algunas builds, un **usuario normal puede activarlo bajo demanda**, lo que lo hace mejor que los casos que solo funcionan tras un reinicio. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Normalmente obtiene primero **`NT AUTHORITY\LOCAL SERVICE`**. A menudo sigue siendo suficiente porque el token tiene **`SeImpersonatePrivilege`**, por lo que puedes encadenarlo con [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considera estos nombres como **pistas para el análisis**, no como éxitos garantizados: dependen de la **SKU/build**, y Microsoft puede cambiar el comportamiento entre versiones. La conclusión importante es buscar **DLL ausentes en servicios privilegiados que recorren el Machine PATH**, especialmente si el servicio puede **volver a activarse sin reiniciar**.

### Exploitation

Para **escalar privilegios**, realiza hijacking de **`WptsExtensions.dll`**. Una vez que se conocen la **ruta** y el **nombre**, genera la DLL maliciosa.

Puedes [**intentar utilizar cualquiera de estos ejemplos**](#creating-and-compiling-dlls). Podrías ejecutar payloads como: obtener una reverse shell, añadir un usuario, ejecutar un beacon...

> [!WARNING]
> Ten en cuenta que **no todos los servicios se ejecutan** como **`NT AUTHORITY\SYSTEM`**. Algunos se ejecutan como **`NT AUTHORITY\LOCAL SERVICE`**, que tiene **menos privilegios**, por lo que abusar de uno de estos servicios podría no permitirte crear un usuario nuevo.\
> Sin embargo, esa cuenta tiene el derecho de usuario **`SeImpersonatePrivilege`**, por lo que puedes utilizar la [**suite Potato para escalar privilegios**](../roguepotato-and-printspoofer.md). En este caso, una reverse shell es una opción mejor que intentar crear un usuario.

En el momento de redactar este documento, el servicio **Task Scheduler** se ejecuta con **Nt AUTHORITY\SYSTEM**.

Después de **generar la DLL maliciosa** (_en mi caso utilicé una reverse shell x64 y obtuve una shell, pero Defender la eliminó porque procedía de msfvenom_), guárdala en el writable System Path con el nombre **WptsExtensions.dll** y **reinicia** el equipo (o reinicia el servicio, o haz lo necesario para volver a ejecutar el servicio/programa afectado).

Cuando se reinicie el servicio, la **DLL debería cargarse y ejecutarse** (puedes **reutilizar** el truco de **procmon** para comprobar si la **biblioteca se cargó como se esperaba**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [DLL sospechosa cargada para persistencia o escalada de privilegios](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Escalada de privilegios en Windows](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
