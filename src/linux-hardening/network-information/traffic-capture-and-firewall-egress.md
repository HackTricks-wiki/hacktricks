# Capture du trafic, pare-feu et triage de l’egress

{{#include ../../banners/hacktricks-training.md}}

Après avoir localisé les [listeners locaux et les sockets Unix](local-network-and-socket-triage.md), vérifiez quelles interfaces transportent leur trafic et quelles règles de pare-feu ou de proxy affectent leur accessibilité. Un service accessible uniquement via loopback peut transporter des en-têtes HTTP sensibles même s’il n’est pas accessible depuis un autre hôte.

## Vérifier les permissions de capture et choisir une interface

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` peut disposer de capacités de capture de paquets même si l’utilisateur actuel n’a pas accès à sudo. Vérifiez les capacités réelles de l’exécutable et les permissions du groupe. Limitez la capture à l’interface, à la durée et au filtre les plus restreints possibles ; une capture peut contenir des identifiants ou des données personnelles.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` reconstitue les flux TCP en clair ; `tshark` peut filtrer une capture et en extraire des champs. Pour le trafic TLS, le déchiffrement nécessite les clés des points de terminaison ou un client compatible configuré avec `SSLKEYLOGFILE` avant la connexion. La [page de triage du réseau local](local-network-and-socket-triage.md#tls-key-logging) présente cette procédure. Ne considérez pas une capture chiffrée comme du texte en clair lisible.

Les artefacts d’incident stockés peuvent changer cette évaluation. Un [core dump Linux est une image de la mémoire d’un processus](https://man7.org/linux/man-pages/man5/core.5.html), qui peut conserver une clé de session ; si un dump lisible et une capture de paquets proviennent du même processus et de la même session, un analyste peut être en mesure de déchiffrer ce trafic. Commencez par inventorier les chemins et les permissions des artefacts, puis vérifiez séparément l’identité du processus, l’heure de la capture, le protocole et le format de la clé. Du trafic déchiffré ou une archive récupérée constitue une piste de divulgation, pas une preuve d’accès au compte d’un tiers : tout fragment de clé SSH doit encore être reconstitué, comparé à la clé publique correspondante et accepté par la politique SSH de ce compte. Évitez d’afficher le contenu des core dumps ou des charges utiles des captures dans les résultats d’énumération généraux.

## Identifier les couches de pare-feu

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` et `iptables` peuvent être exposés par des wrappers de distribution comme UFW ou firewalld. Consultez les règles actives et la configuration persistante du wrapper : une règle visible sous une forme peut avoir été générée par un autre outil. Examinez l’interface, le sens, la source, la destination, le protocole, le port et l’état de la connexion avant d’attribuer le blocage d’un service à une règle précise. Consultez [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) pour un exemple ciblé.

## Tester le trafic sortant et le comportement du proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Distinguez les échecs DNS des échecs TCP, TLS ou proxy. Testez la destination et le protocole pertinents pour l’évaluation ; la joignabilité ICMP ne signifie pas que TCP ou UDP est autorisé. Si un proxy est configuré, comparez la requête censée passer par le proxy avec une requête vers la même cible en appliquant les règles `no_proxy` correspondantes. Une redirection de port locale peut également rendre un service loopback accessible ailleurs ; si la vue du pare-feu et l’exposition observée ne concordent pas, vérifiez les listeners actifs et les tunnels SSH.
{{#include ../../banners/hacktricks-training.md}}
