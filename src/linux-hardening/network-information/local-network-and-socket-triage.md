# Triage du réseau local et des sockets

{{#include ../../banners/hacktricks-training.md}}

Après avoir obtenu un shell sur un hôte Linux, les cibles réseau les plus utiles sont souvent celles qui ne sont pas exposées à l'extérieur. Les services limités au loopback, les réseaux veth, les sockets Unix, les listeners temporaires, les captures de paquets et les règles du firewall peuvent exposer des identifiants ou des surfaces d'attaque accessibles uniquement localement.

Cette page se concentre sur les techniques pratiques de post-exploitation locale, et non sur le pentesting réseau distant général.

## Énumération du loopback et des services locaux

Commencez par identifier les services en écoute, leurs adresses de bind et le processus propriétaire lorsque les permissions le permettent :
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Schémas importants :

- `127.0.0.1:<port>` ou `[::1]:<port>` : accessible uniquement depuis l’hôte par défaut.
- `0.0.0.0:<port>` : accessible sur toutes les interfaces IPv4, sauf filtrage.
- `172.x`, `10.x` ou `192.168.x` sur `veth*`, `docker*`, `br-*`, `cni*` : probablement des réseaux de conteneurs ou de lab local.
- Sockets Unix dans `/run`, `/var/run`, `/tmp` ou les répertoires des applications : surfaces d’IPC locales.

Mappez les ports locaux avec des sondes légères :
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Utilisez `nmap` localement lorsqu'il est disponible :
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Sous-réseaux veth et de conteneurs cachés

Les environnements conteneurisés ou de laboratoire exposent souvent des services uniquement sur un bridge ou un sous-réseau veth. Énumérez les interfaces et les routes avant de supposer qu’un service est inaccessible :
```bash
ip -br addr
ip route
ip neigh
```
Trouver les sous-réseaux locaux probables :
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Sondez soigneusement un sous-réseau découvert :
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
La technique est utile lorsqu’un panneau web, un endpoint de debug ou un service auxiliaire est masqué aux scans externes, mais accessible depuis l’hôte compromis ou le réseau du conteneur.

## Pivot local avec socat ou SSH

Si un service est lié à l’interface loopback, exposez-le via un canal autorisé au lieu de modifier le service lui-même.

Transférez un service HTTP local uniquement avec SSH :
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Bridger un port local avec `socat` lorsque vous avez déjà accès à un shell :
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Transférer un socket Unix vers TCP pour les tests locaux :
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Cela n’exploite rien en soi. Cela rend une surface accessible uniquement localement joignable depuis vos outils, afin que vous puissiez interagir avec elle comme avec un service normal.

## Banner Grabbing et protocoles simples

Tous les services ne sont pas HTTP. De nombreux services locaux leak suffisamment d’informations via une bannière ou un protocole à une ligne.

Sondes de base :
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Vérification HTTP sans navigateur :
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Pour TLS :
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
L’objectif est d’identifier le protocole, le schéma d’authentification, la version et si le service fait confiance aux clients locaux.

## Capture du trafic loopback

Le trafic local peut exposer des en-têtes, des bearer tokens, des identifiants Basic Auth ou des secrets spécifiques à l’application. Effectuez des captures uniquement dans des environnements autorisés.

Capturez le trafic HTTP loopback :
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Capturer un service local spécifique :
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Décoder Basic Auth depuis un en-tête capturé ou journalisé :
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Chaînes utiles à rechercher dans les captures de texte :
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## Journalisation des clés TLS

Si vous pouvez contrôler l’environnement du processus client dans un lab, `SSLKEYLOGFILE` peut rendre les sessions TLS déchiffrables dans Wireshark ou avec des outils compatibles. Cela est utile pour comprendre le trafic HTTPS local sans attaquer TLS lui-même.

Lancez un client avec la journalisation des clés activée :
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Capturez le trafic en même temps :
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Chargez ensuite `/tmp/tls.pcap` et `/tmp/sslkeys.log` dans Wireshark. Cela ne fonctionne que lorsque la bibliothèque cliente prend en charge la journalisation des clés au format NSS et que vous pouvez définir l’environnement avant l’établissement de la connexion.

## Interaction avec les sockets Unix et injection de commandes

Les sockets Unix sont des points de terminaison IPC locaux. Ils peuvent exposer des API HTTP, des protocoles personnalisés ou des gestionnaires de commandes dangereux.

Rechercher les sockets :
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interagir avec HTTP via un socket Unix :
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interagir avec un socket brut :
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Si une entrée de socket contrôlée par l’utilisateur est transmise à un shell ou à un helper privilégié, elle peut devenir une injection de commandes. Pour un exemple ciblé, voir [Socket Command Injection](socket-command-injection.md).

## Examen de nftables et modifications autorisées des règles

Les règles du pare-feu local peuvent expliquer pourquoi un service est visible localement mais bloqué à distance, ou pourquoi un port élevé semble inaccessible depuis une interface.

Examiner les règles :
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Recherchez les drops affectant un port cible :
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Dans un laboratoire autorisé, supprimez une règle de blocage spécifique par handle :
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Préférez la suppression du handle exact plutôt que le flush de tables entières. La technique consiste à identifier le filtre précis à l’origine du comportement et à modifier uniquement cette règle.

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
Priorisez les services qui sont uniquement locaux, s'exécutent avec un utilisateur plus privilégié, exposent des fonctions d'administration/de débogage ou font confiance aux clients du loopback/réseau de conteneurs.
