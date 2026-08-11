# Triage du réseau local et des sockets

{{#include ../../banners/hacktricks-training.md}}

Après avoir obtenu un shell sur un hôte Linux, les cibles réseau les plus utiles ne sont souvent pas exposées de manière externe. Les services limités au loopback, les réseaux veth, les sockets Unix, les listeners temporaires, les captures de paquets et les règles de pare-feu locales peuvent exposer des identifiants ou des surfaces d’attaque accessibles uniquement localement.

Cette page se concentre sur les techniques pratiques de post-exploitation locale, et non sur le pentesting général de réseaux distants.

## Énumération du loopback et des services locaux

Commencez par identifier les services en écoute, leurs adresses de bind et le processus propriétaire lorsque les permissions le permettent.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Schémas importants :

- `127.0.0.1:<port>` ou `[::1]:<port>` : accessible uniquement depuis l’hôte par défaut.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>` : accessible sur toutes les interfaces IPv4, sauf filtrage.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` ou `192.168.0.0/16` sur `veth*`, `docker*`, `br-*`, `cni*` : probablement des réseaux de conteneurs ou de lab local.<sup>[[23]](#references)[[24]](#references)</sup>
- Sockets Unix sous `/run`, `/var/run`, `/tmp` ou dans les répertoires des applications : surfaces IPC locales.<sup>[[5]](#references)</sup>

Cartographiez les ports locaux avec des sondes légères.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Utilisez `nmap` localement lorsqu’il est disponible.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## veth et sous-réseaux de conteneurs

Les environnements conteneurisés ou de lab exposent souvent les services uniquement sur un bridge ou un sous-réseau veth. Énumérez les interfaces et les routes avant de supposer qu’un service est inaccessible.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Trouvez les sous-réseaux locaux probables.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Sondez soigneusement un sous-réseau découvert.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
La technique est utile lorsqu’un panneau web, un endpoint de debug ou un service auxiliaire est masqué des scans externes, mais accessible depuis l’hôte compromis ou le réseau du conteneur.

## Pivot local avec socat ou SSH

Si un service est lié à loopback, exposez-le via un canal autorisé au lieu de modifier le service lui-même.

Faites suivre un service HTTP local uniquement avec SSH.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Bridger un port local avec `socat` lorsque vous avez déjà un accès shell.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Rediriger un socket Unix vers TCP pour des tests locaux.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Cela n’exploite rien en soi. Cela rend une surface accessible uniquement localement disponible depuis vos outils afin que vous puissiez interagir avec elle comme avec un service normal.

## Banner Grabbing et protocoles simples

Tous les services n’utilisent pas HTTP. De nombreux services locaux leak suffisamment d’informations via une bannière ou un protocole sur une seule ligne.

Sondes de base.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Vérification HTTP sans navigateur.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Pour TLS.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
L’objectif est d’identifier le protocole, le schéma d’authentification, la version et si le service fait confiance aux clients locaux.

## Capture du trafic Loopback

Le trafic local peut exposer des en-têtes, des bearer tokens, des identifiants Basic Auth ou des secrets propres à l’application.<sup>[[17]](#references)[[25]](#references)</sup> Effectuez des captures uniquement dans des environnements autorisés.

Capturez le trafic HTTP Loopback.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Capturer un service local spécifique.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Décoder Basic Auth à partir d’un en-tête capturé ou journalisé.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Chaînes utiles à rechercher dans les captures de texte :
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## Journalisation des clés TLS

Si vous pouvez contrôler l’environnement du processus client dans un lab, `SSLKEYLOGFILE` peut rendre les sessions TLS déchiffrables dans Wireshark ou avec des outils compatibles.<sup>[[19]](#references)[[20]](#references)</sup> Cela est utile pour comprendre le trafic HTTPS local sans attaquer TLS lui-même.

Exécutez un client avec la journalisation des clés activée.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Capturez le trafic en même temps.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Chargez ensuite `/tmp/tls.pcap` et `/tmp/sslkeys.log` dans Wireshark. Cela ne fonctionne que lorsque la bibliothèque cliente prend en charge la journalisation des clés au format NSS et que vous pouvez définir l’environnement avant l’établissement de la connexion.<sup>[[20]](#references)[[21]](#references)</sup>

## Interaction avec les sockets Unix et injection de commandes

Les sockets Unix sont des points de terminaison IPC locaux.<sup>[[5]](#references)</sup> Ils peuvent exposer des API HTTP, des protocoles personnalisés ou des gestionnaires de commandes non sécurisés.<sup>[[12]](#references)[[14]](#references)</sup>

Trouvez les sockets.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interagir avec HTTP via un socket Unix.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interagir avec une socket brute.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Si des données de socket contrôlées par l'utilisateur sont transmises à un shell ou à un helper privilégié, cela peut devenir une command injection.<sup>[[26]](#references)</sup> Pour un exemple ciblé, consultez [Socket Command Injection](socket-command-injection.md).

## Examen de nftables et modifications autorisées des règles

Les règles du pare-feu local peuvent expliquer pourquoi un service est visible localement mais bloqué à distance, ou pourquoi un port élevé semble inaccessible depuis une interface.<sup>[[22]](#references)</sup>

Examinez les règles.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Recherchez les drops affectant un port cible.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Dans un laboratoire autorisé, supprimez une règle de blocage spécifique par son handle.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Préférez la suppression du handle exact plutôt que le vidage de tables entières. La technique consiste à identifier le filtre précis à l’origine du comportement et à ne modifier que cette règle.<sup>[[22]](#references)</sup>

## Workflow rapide
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Privilégiez les services qui sont uniquement locaux, s’exécutent avec un utilisateur plus privilégié, exposent des fonctions d’administration/de débogage ou font confiance aux clients du loopback/réseau de conteneurs.

## References

- [1] [ss(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — page de manuel Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291 : Architecture d’adressage IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — page de manuel Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirections (Manuel de référence Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Invocation de timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Techniques de scan de ports (Guide de référence Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Découverte d’hôtes (Guide de référence Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Spécification des ports et ordre des scans (Guide de référence Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — page de manuel Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — page de manuel OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Manuel de l’outil en ligne de commande curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Documentation OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617 : Le schéma d’authentification HTTP « Basic »](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Invocation de base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Documentation OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki Wireshark](https://wiki.wireshark.org/tls)
- [21] [Guide de l’utilisateur Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Manuel nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Allocation d’adresses pour les réseaux Internet privés (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Le cadre d’autorisation OAuth 2.0 : utilisation des bearer tokens (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78 : Neutralisation incorrecte des éléments spéciaux utilisés dans une commande OS](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
