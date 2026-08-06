# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Si descubriste que puedes **escribir en una carpeta de System Path** (ten en cuenta que esto no funcionará si puedes escribir en una carpeta de User Path), es posible que puedas **escalar privilegios** en el sistema.

Para hacerlo, puedes abusar de un **Dll Hijacking**, mediante el cual vas a **secuestrar una librería que está siendo cargada** por un servicio o proceso con **más privilegios** que tú y, como ese servicio está cargando una Dll que probablemente ni siquiera exista en todo el sistema, intentará cargarla desde el System Path en el que puedes escribir.

Para obtener más información sobre **qué es Dll Hijackig**, consulta:


{{#ref}}
./
{{#endref}}

## Privesc con Dll Hijacking

### Encontrar una Dll inexistente

Lo primero que necesitas es **identificar un proceso** que se esté ejecutando con **más privilegios** que tú y que intente **cargar una Dll desde el System Path** en el que puedes escribir.

Recuerda que esta técnica depende de una entrada **Machine/System PATH**, no solo de tu **User PATH**. Por lo tanto, antes de dedicar tiempo a Procmon, vale la pena enumerar las entradas de **Machine PATH** y comprobar cuáles permiten escritura:<sup>[[1]](#references)</sup>
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
El problema en estos casos es que probablemente esos procesos ya se están ejecutando. Para encontrar qué DLLs necesitan los servicios, debes iniciar procmon lo antes posible (antes de que se carguen los procesos). Por lo tanto, para encontrar los `.dll` que faltan:

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
- Después, **reinicia**. Cuando el equipo se reinicie, **`procmon`** comenzará a **registrar** eventos lo antes posible.
- Una vez que **Windows** se haya **iniciado, ejecuta `procmon`** de nuevo. Te indicará que ha estado ejecutándose y te **preguntará si quieres almacenar** los eventos en un archivo. Responde **sí** y **guarda los eventos en un archivo**.
- **Después** de que se haya **generado el archivo**, cierra la ventana de **`procmon`** que está abierta y **abre el archivo de eventos**.
- Añade estos **filtros** y encontrarás todas las DLL que algún **proceso intentó cargar** desde la carpeta writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging solo es necesario para los servicios que se inician demasiado pronto** como para observarlos de otra forma. Si puedes **activar el servicio/programa objetivo bajo demanda** (por ejemplo, interactuando con su interfaz COM, reiniciando el servicio o volviendo a iniciar una tarea programada), normalmente es más rápido mantener una captura normal de Procmon con filtros como **`Path contains .dll`**, **`Result is NAME NOT FOUND`** y **`Path begins with <writable_machine_path>`**.

### DLL no detectadas

Al ejecutar esto en una máquina **virtual (vmware) Windows 11** gratuita, obtuve estos resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

En este caso, los .exe son inútiles, así que ignóralos. Las DLL no detectadas procedían de:

| Servicio                         | DLL                | Línea de CMD                                                             |
| ------------------------------- | ------------------ | ------------------------------------------------------------------------ |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Después de encontrar esto, descubrí esta interesante publicación de blog que también explica cómo [**abusar de WptsExtensions.dll para privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Esto es lo que **vamos a hacer ahora**.<sup>[[3]](#references)</sup>

### Otros candidatos que merece la pena analizar

`WptsExtensions.dll` es un buen ejemplo, pero no es la única **phantom DLL** recurrente que aparece en servicios privilegiados. Las reglas modernas de hunting y los catálogos públicos de hijacking todavía siguen nombres como:<sup>[[2]](#references)</sup>

| Servicio / Escenario | DLL ausente | Notas |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidato clásico de **SYSTEM** en sistemas cliente. Es una buena opción cuando el directorio writable está en el **Machine PATH** y el servicio busca la DLL durante el inicio. |
| NetMan en Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesante en **ediciones de servidor** porque el servicio se ejecuta como **SYSTEM** y, en algunas builds, un usuario normal puede **activarlo bajo demanda**, lo que lo hace mejor que los casos que solo funcionan tras reiniciar. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Normalmente proporciona primero **`NT AUTHORITY\LOCAL SERVICE`**. A menudo esto sigue siendo suficiente porque el token tiene **`SeImpersonatePrivilege`**, por lo que puedes encadenarlo con [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Considera estos nombres como **pistas para el análisis**, no como resultados garantizados: dependen de la **SKU/build**, y Microsoft puede cambiar el comportamiento entre versiones. La conclusión importante es buscar **DLL ausentes en servicios privilegiados que recorren el Machine PATH**, especialmente si el servicio puede **volver a activarse sin reiniciar**.

### Exploitation

Por tanto, para **escalar privilegios** vamos a secuestrar la library **WptsExtensions.dll**. Como tenemos la **ruta** y el **nombre**, solo necesitamos **generar la DLL maliciosa**.

Puedes [**intentar utilizar cualquiera de estos ejemplos**](#creating-and-compiling-dlls). Podrías ejecutar payloads como: obtener una reverse shell, añadir un usuario, ejecutar un beacon...

> [!WARNING]
> Ten en cuenta que **no todos los servicios se ejecutan** con **`NT AUTHORITY\SYSTEM`**; algunos también se ejecutan con **`NT AUTHORITY\LOCAL SERVICE`**, que tiene **menos privilegios**, y **no podrás crear un usuario nuevo** abusando de sus permisos.\
> Sin embargo, ese usuario tiene el privilegio **`seImpersonate`**, por lo que puedes utilizar la [**potato suite para escalar privilegios**](../roguepotato-and-printspoofer.md). Por tanto, en este caso una reverse shell es una opción mejor que intentar crear un usuario.

En el momento de redactar esto, el servicio **Task Scheduler** se ejecuta con **Nt AUTHORITY\SYSTEM**.

Después de haber **generado la DLL maliciosa** (_en mi caso utilicé una reverse shell x64 y obtuve una shell, pero Defender la eliminó porque procedía de msfvenom_), guárdala en el System Path writable con el nombre **WptsExtensions.dll** y **reinicia** el equipo (o reinicia el servicio, o haz lo necesario para volver a ejecutar el servicio/programa afectado).

Cuando se reinicie el servicio, la **DLL debería cargarse y ejecutarse** (puedes **reutilizar** el truco de **procmon** para comprobar si la **library se cargó como se esperaba**).

## Referencias

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
