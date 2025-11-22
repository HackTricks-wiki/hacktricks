# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Si encontraste que puedes **escribir en una carpeta de System Path** (ten en cuenta que esto no funcionará si puedes escribir en una carpeta de User Path) es posible que puedas **escalar privilegios** en el sistema.

Para ello puedes abusar de un **Dll Hijacking** donde vas a **hijack una biblioteca que está siendo cargada** por un servicio o proceso con **más privilegios** que los tuyos, y dado que ese servicio está cargando un Dll que probablemente ni siquiera exista en todo el sistema, intentará cargarlo desde el System Path donde puedes escribir.

Para más información sobre **qué es Dll Hijackig** consulta:


{{#ref}}
./
{{#endref}}

## Privesc con Dll Hijacking

### Encontrar un Dll faltante

Lo primero que necesitas es **identificar un proceso** que se esté ejecutando con **más privilegios** que tú y que esté intentando **cargar un Dll desde el System Path** en el que puedes escribir.

El problema en estos casos es que probablemente esos procesos ya estén en ejecución. Para encontrar qué Dlls faltan en los servicios necesitas lanzar procmon lo antes posible (antes de que se carguen los procesos). Entonces, para encontrar .dlls faltantes haz:

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
- Launch **`procmon`** and go to **`Options`** --> **`Enable boot logging`** and press **`OK`** in the prompt.
- Then, **reboot**. When the computer is restarted **`procmon`** will start **recording** events asap.
- Once **Windows** is **started execute `procmon`** again, it'll tell you that it has been running and will **ask you if you want to store** the events in a file. Say **yes** and **store the events in a file**.
- **After** the **file** is **generated**, **close** the opened **`procmon`** window and **open the events file**.
- Add these **filters** and you will find all the Dlls that some **proccess tried to load** from the writable System Path folder:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### DLLs perdidas

Running this in a free **virtual (vmware) Windows 11 machine** I got these results:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In this case the .exe are useless so ignore them, the missed DLLs where from:

| Servicio                        | Dll                | Línea CMD                                                            |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

After finding this, I found this interesting blog post that also explains how to [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Which is what we **are going to do now**.

### Explotación

So, to **escalate privileges** we are going to hijack the library **WptsExtensions.dll**. Having the **path** and the **name** we just need to **generate the malicious dll**.

You can [**try to use any of these examples**](#creating-and-compiling-dlls). You could run payloads such as: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Ten en cuenta que **no todos los servicios se ejecutan** con **`NT AUTHORITY\SYSTEM`**; algunos también se ejecutan con **`NT AUTHORITY\LOCAL SERVICE`**, que tiene **menos privilegios** y **no podrás crear un nuevo usuario** aprovechando sus permisos.\
> Sin embargo, ese usuario tiene el privilegio **`seImpersonate`**, por lo que puedes usar la [ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Por tanto, en este caso un rev shell es una mejor opción que intentar crear un usuario.

At the moment of writing the **Task Scheduler** service is run with **Nt AUTHORITY\SYSTEM**.

Having **generated the malicious Dll** (_in my case I used x64 rev shell and I got a shell back but defender killed it because it was from msfvenom_), save it in the writable System Path with the name **WptsExtensions.dll** and **restart** the computer (or restart the service or do whatever it takes to rerun the affected service/program).

When the service is re-started, the **dll should be loaded and executed** (you can **reuse** the **procmon** trick to check if the **library was loaded as expected**).

{{#include ../../../banners/hacktricks-training.md}}
