# Labs d’émulation d’adversaire autorisés

Ces exercices reproduisent une **architecture observable**, et non une compromission non autorisée. Exécutez-les sur un hôte Linux de lab dédié avec Docker, sans identifiants sensibles et sans route vers des cibles tierces. Les noms sont fixes afin que le teardown soit explicite.

{% hint style="danger" %}
Ne remplacez pas les conteneurs, points d’accès, routeurs, comptes ou transactions synthétiques possédés ci-dessous par des proxies publics, le Wi-Fi d’un voisin, un tenant CDN de production que vous ne contrôlez pas ou de véritables fonds illicites. Une autorisation écrite doit couvrir chaque système et chaque environnement radio.
{% endhint %}

## Lab 1 : chaîne ORB et redirector possédés

**Objectif :** montrer qu’une cible n’enregistre que l’exit, tandis que chaque relais voit les hops adjacents. Cela émule la structure T1090.003/T1584 sans utiliser d’appareils compromis.

**Prérequis :** Docker Engine et des noms de conteneurs inutilisés commençant par `ht-orb-`.

### Construction
```bash
docker network create ht-orb-entry
docker network create ht-orb-transit
docker network create ht-orb-target

docker run -d --name ht-orb-target --network ht-orb-target nginx:alpine

docker run -d --name ht-orb-r2 --network ht-orb-transit \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-target:80
docker network connect ht-orb-target ht-orb-r2

docker run -d --name ht-orb-r1 --network ht-orb-entry \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-r2:8080
docker network connect ht-orb-transit ht-orb-r1

docker run --rm --network ht-orb-entry curlimages/curl:latest \
-sS http://ht-orb-r1:8080/ >/dev/null
```
### Vérifier les limites de visibilité
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Résultat attendu : Nginx enregistre l’adresse de `ht-orb-r2` sur `ht-orb-target`, et non celle du client ponctuel. Les logs des relais montrent des connexions provenant uniquement de leur réseau adjacent. L’inspection du control plane Docker permet toujours de reconstituer l’intégralité du chemin — de manière analogue aux preuves fournies par le provider/controller.

### Expériences de détection

1. Répétez les requêtes toutes les 60 secondes et représentez graphiquement le temps entre les arrivées et le nombre d’octets.
2. Remplacez `ht-orb-r2` par un nouveau conteneur/adresse nommé, tout en conservant la même cadence et la même requête applicative ; confirmez qu’une règle basée uniquement sur l’IP perd la chaîne, tandis que le comportement continue de la relier.
3. Capturez le trafic sur les trois bridges Docker avec `tcpdump` sur l’hôte du lab et comparez les horodatages.
4. Arrêtez `ht-orb-r2` ; vérifiez qu’il n’existe aucun fallback direct entre l’entrée et la cible.

### Démantèlement
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Labo 2 : SNI/Host mismatch et logging du redirector

**Objectif :** reproduire la primitive de routage derrière le domain fronting sur un edge local privé et montrer où elle est visible. Aucun CDN public n'est impliqué.

### Construire un edge TLS local
```bash
ht_front_dir="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
-subj '/CN=front.lab' \
-keyout "$ht_front_dir/key.pem" -out "$ht_front_dir/cert.pem"

cat >"$ht_front_dir/default.conf" <<'EOF'
log_format routing '$remote_addr sni=$ssl_server_name host=$host request="$request"';
server {
listen 443 ssl;
server_name front.lab;
ssl_certificate /etc/nginx/tls/cert.pem;
ssl_certificate_key /etc/nginx/tls/key.pem;
access_log /var/log/nginx/access.log routing;
location / {
if ($host != origin.lab) { return 404; }
proxy_pass http://ht-front-target:80;
}
}
EOF

docker network create ht-front-net
docker run -d --name ht-front-target --network ht-front-net nginx:alpine
docker run -d --name ht-front-edge --network ht-front-net -p 127.0.0.1:8443:443 \
-v "$ht_front_dir/default.conf:/etc/nginx/conf.d/default.conf:ro" \
-v "$ht_front_dir:/etc/nginx/tls:ro" nginx:alpine
```
### Envoyer et observer la divergence
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Les champs de journalisation attendus incluent `sni=front.lab host=origin.lab`. La capture de paquets entre le client et l’edge expose le SNI, sauf si ECH est utilisé ; le Host HTTP est chiffré sur cette liaison. L’edge qui termine la connexion voit les deux.

Envoyez maintenant une requête normale et confirmez que la policy la rejette :
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Assertion de détection

Déclencher une alerte sur `sni != host` uniquement après avoir normalisé les ports et la casse, et vérifié les exceptions connues des reverse proxies. Ajouter le contexte du processus et du tenant/origin avant d'attribuer un niveau de gravité.

### Démantèlement
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Objectif :** générer un dataset DNS sûr, de type low-TTL/multi-ASN, et valider un analytic. Les adresses de documentation RFC 5737 renvoyées sont non routables à cette fin.

### Exécuter un serveur faisant autorité
```bash
ht_dns_dir="$(mktemp -d)"
cat >"$ht_dns_dir/Corefile" <<'EOF'
.:53 {
log
errors
file /zones/db.lab lab
}
EOF

mkdir -p "$ht_dns_dir/zones"
cat >"$ht_dns_dir/zones/db.lab" <<'EOF'
$ORIGIN lab.
@ 60 IN SOA ns.lab. hostmaster.lab. 1 60 60 60 5
@ 60 IN NS ns.lab.
ns 60 IN A 192.0.2.53
flux 5 IN A 192.0.2.10
flux 5 IN A 198.51.100.20
flux 5 IN A 203.0.113.30
EOF

docker run -d --name ht-flux-dns -p 127.0.0.1:1053:53/udp \
-v "$ht_dns_dir/Corefile:/Corefile:ro" \
-v "$ht_dns_dir/zones:/zones:ro" coredns/coredns:latest -conf /Corefile

for query_number in 1 2 3 4 5; do
dig @127.0.0.1 -p 1053 flux.lab A +noall +answer
done
docker logs ht-flux-dns
```
Résultat attendu : chaque réponse contient trois IP de documentation et un TTL de 5 secondes. Le fast flux réel fait également tourner des sous-ensembles au fil du temps ; modifiez le numéro de série/les adresses de la zone et redémarrez ce serveur jetable pour créer plusieurs époques.

### Validation analytique

Pour une fenêtre de cinq minutes, calculez `median(TTL)`, le nombre de réponses distinctes, le nombre de libellés ASN/géographiques synthétiques distincts et la rotation des réponses. Exigez au moins deux dimensions suspectes ainsi qu’un événement de processus/de suivi. Exécutez la même analyse sur un échantillon CDN connu afin de mesurer les faux positifs.

### Teardown
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4 : pivot wireless vers le voisin le plus proche

**Objectif :** reproduire le boundary mismatch d’APT28 avec deux « organisations » que vous contrôlez. Comme les commandes du matériel/driver Wi-Fi varient, ce lab spécifie des rôles et des éléments de preuve vérifiables plutôt que de prétendre qu’une seule commande `hostapd` convient à toutes les radios.

### Équipement

- deux AP que vous contrôlez, sur des canaux/SSID de lab isolés `HT-NEIGHBOR` et `HT-TARGET` ;
- un service cible accessible uniquement depuis `HT-TARGET` ;
- un pivot Linux à double radio que vous contrôlez, capable de s’associer aux deux AP ;
- un poste de contrôle distant derrière `HT-NEIGHBOR` ;
- des logs RADIUS/NAC ou d’association AP, des logs DHCP et des logs d’audit/process du pivot.

### Procédure

1. Isolez physiquement la configuration ou atténuez le signal afin qu’aucun SSID ne sorte de la zone autorisée. Confirmez-le avec un survey.
2. Configurez `HT-TARGET` avec une identité d’exercice et omettez délibérément la validation du device certificate/de la posture pour le premier run. Enregistrez cela comme condition testée.
3. Connectez la première interface du pivot à `HT-NEIGHBOR` et la seconde à `HT-TARGET`. N’activez **pas** de bridge général ; n’autorisez que le service/port cible via un host firewall.
4. Depuis le poste de travail, ouvrez un tunnel authentifié vers le pivot et demandez le service cible via ce tunnel.
5. Enregistrez la création du process/de l’interface du pivot, les deux associations AP, l’événement RADIUS cible, le bail DHCP et l’adresse source cible.
6. Demandez à l’équipe de détection de reconstruire la chaîne sans la carte du controller.
7. Activez EAP-TLS/la posture managed-device sur `HT-TARGET`, supprimez le certificat cible approuvé du pivot et recommencez. L’accès doit échouer lors de l’admission.
8. Recommencez avec une MAC randomized vue pour la première fois. Vérifiez que la décision relative au certificat/device fonctionne toujours et qu’aucune règle ne traite la MAC seule comme une identité.

### Critères de réussite

- La cible voit initialement un client Wi-Fi local plutôt que le poste de travail.
- La télémétrie des connexions identifie un pivot avec des chemins simultanés vers le contrôle du voisin et la radio cible.
- L’admission basée sur le certificat/device bloque le second run.
- Aucun paquet n’atteint un réseau situé en dehors du lab isolé.

## Lab 5 : séquence de resolver dead-drop

**Objectif :** détecter un process qui lit un objet ayant l’apparence d’un objet légitime, décode un pointeur et contacte immédiatement un second service.

### Construction
```bash
docker network create ht-ddr-net
docker run -d --name ht-ddr-c2 --network ht-ddr-net nginx:alpine

docker run -d --name ht-ddr-web --network ht-ddr-net python:3-alpine \
sh -c 'mkdir -p /srv && printf aHR0cDovL2h0LWRkci1jMjo4MC8= > /srv/profile.txt && python -m http.server 8000 -d /srv'

docker run --rm --name ht-ddr-client --network ht-ddr-net python:3-alpine \
python -c 'import base64,urllib.request; p=urllib.request.urlopen("http://ht-ddr-web:8000/profile.txt").read(); u=base64.b64decode(p).decode(); print(urllib.request.urlopen(u).status)'

docker logs ht-ddr-web
docker logs ht-ddr-c2
```
Le contenu encodé est `http://ht-ddr-c2:80/`. Une détection fonctionnelle relie le même processus/conteneur éphémère lisant `/profile.txt`, décodant le contenu et contactant `ht-ddr-c2` en quelques secondes. Hachez et préservez la réponse de l’objet.

### Démantèlement
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6 : peel-chain synthétique et graphe de bridge

**Objectif :** pratiquer le traçage de valeur sans actifs, comptes ni services réels.

### Créer et tracer le jeu de données
```bash
ht_graph_dir="$(mktemp -d)"
cat >"$ht_graph_dir/edges.csv" <<'EOF'
time,chain,source,destination,amount,label
10:00,A,theft,a1,100,source
10:10,A,a1,shop1,3,payment
10:10,A,a1,a2,96.9,change
10:20,A,a2,shop2,4,payment
10:20,A,a2,a3,92.8,change
10:30,A,a3,bridge_in,90,bridge_deposit
10:36,X,bridge_in,bridge_out,89.5,bridge_link_inference
10:36,B,bridge_out,b1,89.5,bridge_withdrawal
10:50,B,b1,exchange,89,service_deposit
EOF

python3 - "$ht_graph_dir/edges.csv" <<'PY'
import csv, sys
edges = list(csv.DictReader(open(sys.argv[1], newline="")))
frontier, seen = {"theft"}, set()
while frontier:
src = frontier.pop()
for e in edges:
if e["source"] == src and (src, e["destination"]) not in seen:
seen.add((src, e["destination"]))
print(f'{e["time"]} {e["chain"]}: {src} -> {e["destination"]} {e["amount"]} [{e["label"]}]')
frontier.add(e["destination"])
PY
```
Les analystes doivent identifier le pattern peel/change, traiter le lien de bridge comme une inférence prise en charge séparément, calculer la différence de frais/valeur et marquer l’échange comme une demande de preuves off-chain. Modifiez une valeur ou une heure et documentez l’évolution du niveau de confiance.

### Démontage
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: capteur passif de signalisation du trafic

**Objectif :** émuler la signature réseau d’un implant passif activé par une valeur magique, sans créer de shell, de persistence ou d’accès distant. Le listener se lie uniquement à loopback et enregistre un événement bénin.
```bash
ht_signal_dir="$(mktemp -d)"
cat >"$ht_signal_dir/listener.py" <<'PY'
import hmac, socket

token = b"HT-LAB-ACTIVATE"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 45679))
for _ in range(2):
data, peer = sock.recvfrom(1024)
if hmac.compare_digest(data, token):
print(f"authorized lab activation from {peer[0]}", flush=True)
PY

python3 "$ht_signal_dir/listener.py" >"$ht_signal_dir/events.log" &
ht_signal_pid=$!
sleep 1

python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"ordinary-traffic", ("127.0.0.1", 45679))
s.sendto(b"HT-LAB-ACTIVATE", ("127.0.0.1", 45679))
PY

wait "$ht_signal_pid"
cat "$ht_signal_dir/events.log"
rm -rf -- "$ht_signal_dir"
```
Résultat attendu : le trafic ordinaire ne produit aucun événement applicatif ; seul le token désigné en produit un. Capturez le trafic loopback pendant l’exécution et vérifiez qu’un network sensor peut toujours voir les deux datagrammes. Évaluez ensuite les contrôles hôte qui détectent un packet listener actif pendant une période anormalement longue ou un packet-capture filter inattendu. Les passive implants réels de RedPenguin inspectaient le trafic sur un router et offraient des fonctionnalités dangereuses ; ce lab ne fait délibérément ni l’un ni l’autre.

## Modèle de rapport d’exercice

Pour chaque lab, consignez :

- l’autorisation et le périmètre isolé ;
- l’hypothèse et la technique ATT&CK ;
- la topologie et le tableau des observateurs ;
- les heures exactes de début et de fin, ainsi que les hashes de configuration ;
- les événements attendus pour chaque sensor ;
- les événements effectivement observés et les lacunes de rétention ;
- la logique analytique, le seuil et un échantillon de faux positif ;
- si l’équipe cible a reconstitué le chemin ;
- le résultat du retest de mitigation ; et
- les preuves de teardown/recovery.

Un exercice est incomplet tant que la détection n’a pas été relancée après la mitigation et que toutes les ressources du lab n’ont pas été supprimées.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — L’attaque The Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
