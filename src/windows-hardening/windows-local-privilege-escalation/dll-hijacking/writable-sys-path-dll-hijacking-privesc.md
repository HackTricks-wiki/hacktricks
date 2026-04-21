# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Si has encontrado que puedes **escribir en una carpeta del System Path** (nota que esto no funcionará si puedes escribir en una carpeta del User Path), es posible que puedas **escalar privilegios** en el sistema.

Para hacerlo, puedes abusar de un **Dll Hijacking** en el que vas a **secuestrar una librería que está siendo cargada** por un servicio o proceso con **más privilegios** que tú, y como ese servicio está cargando una Dll que probablemente ni siquiera exista en todo el sistema, intentará cargarla desde el System Path en el que puedes escribir.

Para más información sobre **qué es Dll Hijackig** consulta:


{{#ref}}
./
{{#endref}}

## Privesc con Dll Hijacking

### Encontrar una Dll faltante

Lo primero que necesitas es **identificar un proceso** que se esté ejecutando con **más privilegios** que tú y que esté intentando **cargar una Dll desde el System Path** en el que puedes escribir.

Recuerda que esta técnica depende de una entrada **Machine/System PATH**, no solo de tu **User PATH**. Por lo tanto, antes de perder tiempo en Procmon, merece la pena enumerar las entradas del **Machine PATH** y comprobar cuáles son escribibles:
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
El problema en estos casos es que probablemente esos procesos ya se están ejecutando. Para encontrar qué Dlls les faltan a los servicios, necesitas lanzar procmon lo antes posible (antes de que se carguen los procesos). Así que, para encontrar las .dll que faltan, haz lo siguiente:

- **Create** la carpeta `C:\privesc_hijacking` y añade la ruta `C:\privesc_hijacking` a la **System Path env variable**. Puedes hacerlo **manual**mente o con **PS**:
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
- Lanza **`procmon`** y ve a **`Options`** --> **`Enable boot logging`** y pulsa **`OK`** en el aviso.
- Luego, **reinicia**. Cuando el ordenador se reinicie, **`procmon`** empezará a **registrar** eventos lo antes posible.
- Una vez que **Windows** haya arrancado, **ejecuta `procmon`** otra vez; te dirá que ha estado ejecutándose y te **preguntará si quieres guardar** los eventos en un archivo. Di **yes** y **guarda los eventos en un archivo**.
- **Después** de que se **genere** el **archivo**, **cierra** la ventana abierta de **`procmon`** y **abre el archivo de eventos**.
- Añade estos **filtros** y encontrarás todos los Dlls que algún **process** intentó cargar desde la carpeta writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging is only required for services that start too early** to observe otherwise. If you can **trigger the target service/program on demand** (for example, by interacting with its COM interface, restarting the service, or relaunching a scheduled task), it is usually faster to keep a normal Procmon capture with filters such as **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, and **`Path begins with <writable_machine_path>`**.

### Missed Dlls

Ejecutando esto en una máquina **virtual (vmware) Windows 11** gratuita obtuve estos resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

En este caso los .exe no sirven, así que ignóralos; las DLLs no encontradas eran estas:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Después de encontrar esto, encontré este blog post interesante que también explica cómo [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Que es lo que **vamos a hacer ahora**.

### Other candidates worth triaging

`WptsExtensions.dll` es un buen ejemplo, pero no es la única **phantom DLL** recurrente que aparece en servicios privilegiados. Las reglas modernas de hunting y los catálogos públicos de hijack siguen rastreando nombres como:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Classic **SYSTEM** candidate on client systems. Good when the writable directory is in the **Machine PATH** and the service probes the DLL during startup. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesting on **server editions** because the service runs as **SYSTEM** and can be **triggered on demand by a normal user** in some builds, making it better than reboot-only cases. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Usually yields **`NT AUTHORITY\LOCAL SERVICE`** first. That is often still enough because the token has **`SeImpersonatePrivilege`**, so you can chain it with [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Trata estos nombres como **pistas de triage**, no como victorias garantizadas: dependen de la **SKU/build**, y Microsoft puede cambiar el comportamiento entre versiones. La conclusión importante es buscar **DLLs ausentes en servicios privilegiados que recorren el Machine PATH**, especialmente si el servicio puede **reactivarse sin reiniciar**.

### Exploitation

Así que, para **elevar privilegios** vamos a secuestrar la librería **WptsExtensions.dll**. Teniendo la **ruta** y el **nombre** solo necesitamos **generar la dll maliciosa**.

Puedes [**probar a usar cualquiera de estos ejemplos**](#creating-and-compiling-dlls). Podrías ejecutar payloads como: obtener una rev shell, añadir un usuario, ejecutar un beacon...

> [!WARNING]
> Ten en cuenta que **no todos los service se ejecutan** con **`NT AUTHORITY\SYSTEM`**; algunos también se ejecutan con **`NT AUTHORITY\LOCAL SERVICE`**, que tiene **menos privilegios** y no podrás crear un usuario nuevo para abusar de sus permisos.\
> Sin embargo, ese usuario tiene el privilegio **`seImpersonate`**, así que puedes usar la[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Por tanto, en este caso una rev shell es una mejor opción que intentar crear un usuario.

En el momento de escribir esto, el servicio **Task Scheduler** se ejecuta con **Nt AUTHORITY\SYSTEM**.

Una vez **generada la Dll maliciosa** (_en mi caso usé una rev shell x64 y obtuve una shell, pero Defender la mató porque venía de msfvenom_), guárdala en el System Path writable con el nombre **WptsExtensions.dll** y **reinicia** el ordenador (o reinicia el servicio o haz lo que haga falta para volver a ejecutar el servicio/programa afectado).

Cuando el servicio se reinicie, la **dll debería cargarse y ejecutarse** (puedes **reutilizar** el truco de **procmon** para comprobar si la **librería se cargó como se esperaba**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
