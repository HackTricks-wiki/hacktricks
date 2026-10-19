# Triage du réseau local et des sockets

{{#include ../../banners/hacktricks-training.md}}

Après avoir obtenu un shell sur un hôte Linux, les cibles réseau les plus utiles ne sont souvent pas exposées à l’extérieur. Les services accessibles uniquement via loopback, les réseaux veth, les sockets Unix, les écouteurs temporaires, les captures de paquets et les règles de pare-feu locales peuvent révéler des identifiants ou des surfaces d’attaque accessibles uniquement depuis l’hôte.

Cette page se concentre sur des techniques pratiques de post-exploitation locale, et non sur le pentesting général de réseaux distants.

## Énumération du loopback et des services locaux

Commencez par identifier les services en écoute, leurs adresses de liaison et, lorsque les permissions le permettent, le processus propriétaire.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Motifs importants :

- `127.0.0.1:<port>` ou `[::1]:<port>` : accessible uniquement depuis l’hôte par défaut.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>` : accessible sur toutes les interfaces IPv4, sauf filtrage.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` ou `192.168.0.0/16` sur `veth*`, `docker*`, `br-*`, `cni*` : probablement des réseaux de conteneurs ou de lab local.<sup>[[23]](#references)[[24]](#references)</sup>
- Sockets Unix sous `/run`, `/var/run`, `/tmp` ou dans des répertoires d’application : surfaces IPC locales.<sup>[[5]](#references)</sup>

Pour le problème historique d’analyse du socket [snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), examinez le daemon en cours d’exécution, son socket API local et la révision du paquet ou du snap installé, puis comparez-les au correctif publié pour cette distribution. Le bug concernait la validation par snapd de l’adresse du socket d’un pair, et non `snap-confine` ; la présence d’un fichier `snap-confine` avec set-user-ID ou d’une chaîne de version upstream ne suffit pas à établir l’exposition. Ubuntu a publié des correctifs dans des versions de paquet propres à chaque release, et snapd peut avoir été mis à jour depuis un snap indépendamment du paquet de la distribution. Vérifiez le build réellement exécuté et l’accessibilité du socket local avant d’évaluer la frontière de l’API privilégiée. L’énumération passive ne doit ni envoyer une requête de socket forgée ni installer un snap.

Un service en écoute sur loopback, lancé via [`socat` avec `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html), peut transmettre l’entrée d’un client local à un programme distinct. Recoupez la commande du service en écoute, le chemin de l’exécutable, l’identité effective du processus enfant, l’accessibilité locale et l’authentification avant de considérer un service personnalisé appartenant à root comme une piste d’escalade de privilèges. Une vulnérabilité de sûreté mémoire ou un chemin non sûr entre une entrée et une commande nécessite des éléments propres au binaire et au build concernés ; le numéro de port, le processus `socat` ou le propriétaire root ne suffisent pas à l’établir. L’énumération passive doit s’en tenir aux métadonnées des processus, des sockets et des fichiers, sans envoyer d’entrée au service.

Un master Salt local peut écouter sur les ports TCP 4505 et 4506, y compris sur loopback ou sur un port hôte publié par un conteneur. Les [notes de version 3000.2 de Salt](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) décrivent une faille d’accès aux méthodes sans authentification, CVE-2020-11651, corrigée dans les versions upstream 2019.2.4 et 3000.2. Recoupez le service en écoute avec le processus `salt-master` réel, l’interface accessible, le paquet installé et les correctifs du fournisseur, ainsi que l’identité effective du conteneur ou de l’hôte, avant de considérer cela comme une piste d’escalade ; un port ou une version upstream ne constitue pas une preuve à lui seul. Si un master s’exécute dans un conteneur, l’impact sur les privilèges root de l’hôte est une frontière distincte : vérifiez qu’un socket d’API du runtime de l’hôte est monté et accessible depuis ce conteneur. L’énumération passive ne doit pas interroger le serveur de requêtes Salt ni créer de conteneur pour évaluer l’exposition. Voir la [documentation des ports de Salt](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) et le [triage de l’API runtime](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Cartographiez les ports locaux à l’aide de sondes légères.<sup>[[6]](#references)[[7]](#references)</sup>

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

## Sous-réseaux veth et de conteneurs cachés

Les environnements conteneurisés ou de laboratoire exposent souvent des services uniquement sur un sous-réseau de bridge ou de veth. Énumérez les interfaces et les routes avant de supposer qu’un service est inaccessible.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Repérer les sous-réseaux locaux probables.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Sondez soigneusement un sous-réseau découvert.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

La technique est utile lorsqu’un panneau web, un endpoint de debug ou un service auxiliaire est masqué aux scans externes, mais accessible depuis l’hôte compromis ou le réseau du conteneur.

## Jetons de service Notebook entre utilisateurs

Un service Notebook lié à loopback peut s’authentifier à l’aide d’un jeton de démarrage affiché dans la sortie de son processus. Si cette sortie est redirigée vers un journal lisible par un autre compte local, le jeton peut franchir la frontière entre utilisateurs et permettre l’exécution de code sous le compte du serveur Notebook. Avant de considérer un chemin de journal comme une piste d’élévation de privilèges, recoupez le propriétaire du processus à l’écoute, la destination et les permissions du journal, la configuration actuelle du jeton et les contrôles d’accès à Notebook. Lors d’une énumération passive, relevez les métadonnées des journaux ; n’affichez pas les jetons et ne vous connectez pas au service dans le seul but de classifier l’hôte.

Un service Jupyter Lab peut aussi exposer son jeton dans un `ExecStart` systemd lisible ou dans la ligne de commande du processus en cours (`ps auxww`), et pas seulement dans les journaux de démarrage. Dans l’exemple rapporté, `User=analyst` et `--ServerApp.token` indiquaient à la fois l’identifiant et le compte associé à un listener `127.0.0.1:8888`. Avec un accès à l’hôte, le jeton et `ssh -L 8888:127.0.0.1:8888 user@host` ont permis d’accéder au Terminal de Jupyter Lab en tant que cet utilisateur de service. Vérifiez ensemble l’utilisateur effectif de l’unité, les arguments du processus, le listener et la validité du jeton ; une liaison à loopback ne constitue pas une frontière d’autorisation.<sup>[[28]](#references)</sup>

## Pivot local avec socat ou SSH

Si un service est lié à loopback, exposez-le via un canal autorisé plutôt que de modifier le service lui-même.

Transférez un service HTTP accessible uniquement en local avec SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Reliez un port local avec `socat` lorsque vous avez déjà un accès shell.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Transférez un socket Unix vers TCP pour les tests locaux.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Cela n’exploite rien en soi. Cela rend une surface accessible uniquement en local joignable depuis vos outils, afin que vous puissiez interagir avec elle comme avec un service normal.

## Banner Grabbing et protocoles simples

Tous les services ne sont pas des services HTTP. De nombreux services locaux divulguent suffisamment d’informations via une bannière ou un protocole à une ligne.

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

L’objectif est d’identifier le protocole, le mécanisme d’authentification, la version et si le service fait confiance aux clients locaux.

Pour un listener aiohttp, examinez sa configuration des routes statiques ainsi que sa version. CVE-2024-23334 affecte aiohttp avant la version 3.9.2 lorsqu’une route statique active `follow_symlinks=True` : les requêtes vers cette route peuvent lire des fichiers situés en dehors de la racine statique. Si le service s’exécute en tant que root, il peut exposer les fichiers lisibles par root, à condition que la route soit accessible. Une bannière de version ou une écoute sur loopback ne suffit pas à établir que la configuration est vulnérable ou que les fichiers sont accessibles.<sup>[[27]](#references)</sup>

## Capture du trafic loopback

Le trafic local peut exposer des en-têtes, des jetons bearer, des identifiants Basic Auth ou des secrets propres à l’application.<sup>[[17]](#references)[[25]](#references)</sup> Effectuez des captures uniquement dans des environnements autorisés.

Capturez le trafic HTTP loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Capturer un service local spécifique.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Décoder le Basic Auth à partir d’un en-tête capturé ou enregistré.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Chaînes utiles à rechercher dans les captures de texte :

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Journalisation des clés TLS

Si vous pouvez contrôler l’environnement du processus client dans un lab, `SSLKEYLOGFILE` peut permettre de déchiffrer les sessions TLS dans Wireshark ou avec des outils compatibles.<sup>[[19]](#references)[[20]](#references)</sup> Cela permet de comprendre le trafic HTTPS local sans attaquer TLS lui-même.

Lancez un client avec la journalisation des clés activée.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Capturez le trafic en même temps.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Chargez ensuite `/tmp/tls.pcap` et `/tmp/sslkeys.log` dans Wireshark. Cela ne fonctionne que si la bibliothèque cliente prend en charge la journalisation des clés au format NSS et si vous pouvez définir l’environnement avant d’établir la connexion.<sup>[[20]](#references)[[21]](#references)</sup>

## Interaction avec les sockets Unix et Command Injection

Les sockets Unix sont des points de terminaison IPC locaux.<sup>[[5]](#references)</sup> Ils peuvent exposer des API HTTP, des protocoles personnalisés ou des gestionnaires de commandes non sécurisés.<sup>[[12]](#references)[[14]](#references)</sup>

Un socket appartenant à root et accessible en écriture au groupe constitue une frontière d’autorisation, mais n’est pas en soi une vulnérabilité. Comparez son groupe et son mode avec ceux du compte actuel, identifiez le processus à l’écoute et examinez les données qu’il accepte des clients avant d’évaluer le risque. En particulier, un service privilégié qui exécute le PHP soumis peut franchir une seconde frontière s’il fait également confiance à un chemin `php.ini` choisi par l’appelant ou s’il lui permet de modifier `disable_functions` ou `open_basedir`; inspectez la configuration effective et le mécanisme de validation du service. Le [guide de configuration PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) explique ces directives. Les métadonnées du socket ne suffisent pas à établir qu’il y a exécution de code.

Recherchez les sockets.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Interagir avec HTTP via un socket Unix.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Interagir avec un socket brut.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Si une entrée socket contrôlée par l’utilisateur est transmise à un shell ou à un helper privilégié, cela peut entraîner une command injection.<sup>[[26]](#references)</sup> Pour un exemple ciblé, consultez [Socket Command Injection](socket-command-injection.md).

## Examen de nftables et modifications autorisées des règles

Les règles du pare-feu local peuvent expliquer pourquoi un service est visible localement, mais bloqué à distance, ou pourquoi un port élevé semble inaccessible depuis une interface.<sup>[[22]](#references)</sup>

Examinez les règles.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Repérez les pertes de paquets affectant un port cible.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

Dans un laboratoire autorisé, supprimer une règle de blocage spécifique à l’aide de son handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Privilégiez la suppression du handle exact plutôt que la vidange des tables entières. La technique consiste à identifier le filtre précis à l’origine du comportement et à modifier uniquement cette règle.<sup>[[22]](#references)</sup>

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

Privilégiez les services accessibles uniquement localement, exécutés par un utilisateur plus privilégié, exposant des fonctions d’administration/de débogage ou faisant confiance aux clients du loopback/réseau de conteneurs.

## References

- [1] [ss(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — page de manuel Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291 : Architecture d’adressage de la version 6 du protocole IP](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — page de manuel Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirections (manuel de référence de Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Invocation de timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Techniques d’analyse de ports (guide de référence Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Découverte d’hôtes (guide de référence Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Spécification des ports et ordre d’analyse (guide de référence Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — page de manuel Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — page de manuel OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Manuel de l’outil en ligne de commande curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Documentation OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617 : Schéma d’authentification HTTP « Basic »](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Invocation de base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Documentation OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki Wireshark](https://wiki.wireshark.org/tls)
- [21] [Guide de l’utilisateur Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Manuel nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Allocation d’adresses pour les réseaux privés (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Cadre d’autorisation OAuth 2.0 : utilisation des jetons Bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78 : Neutralisation incorrecte des éléments spéciaux utilisés dans une commande du système d’exploitation](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Avis du mainteneur d’aiohttp : traversée de route statique avec follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB : DevHub — jeton Jupyter exposé via systemd et les arguments de processus](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
