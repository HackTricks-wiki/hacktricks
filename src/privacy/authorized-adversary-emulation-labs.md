# Gemagtigde Adversary-Emulation-laboratoriums

{{#include ../banners/hacktricks-training.md}}

Hierdie oefeninge reproduseer **waarneembare argitektuur**, nie ongemagtigde kompromittering nie. Voer dit op ’n toegewyde Linux-labgasheer met Docker uit, sonder sensitiewe credentials en sonder ’n roete na derdeparty-teikens. Die name is vasgestel sodat teardown eksplisiet is.

{% hint style="danger" %}
Moenie die besitte containers, AP's, routers, accounts of sintetiese transaksies hieronder vervang met openbare proxies, ’n buurman se Wi-Fi, ’n production CDN-tenant wat jy nie beheer nie, of werklike onwettige fondse nie. Skriftelike magtiging moet elke stelsel en radio-omgewing dek.
{% endhint %}

## Lab 1: besitte ORB- en redirector-ketting

**Doelwit:** wys dat ’n target slegs die exit aanteken terwyl elke relay aangrensende hops sien. Dit emuleer T1090.003/T1584-struktuur sonder gekompromitteerde toestelle.

**Vereistes:** Docker Engine en ongebruikte containernames wat met `ht-orb-` begin.

### Bou
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
### Verifieer die sigbaarheidsgrense
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Verwagte resultaat: Nginx teken die `ht-orb-r2`-adres op `ht-orb-target` aan, nie die eenmalige client nie. Relay-logs toon slegs verbindings vanaf hul aangrensende netwerk. Docker-control-plane-inspeksie rekonstrueer steeds die volledige pad—analoog aan provider/controller-bewyse.

### Opsporingseksperimente

1. Herhaal versoeke elke 60 sekondes en karteer die tyd tussen aankomste en grepe.
2. Vervang `ht-orb-r2` met ’n nuwe benoemde container/adres, maar behou dieselfde ritme en application request; bevestig dat ’n slegs-IP-reël die ketting verloor, terwyl die gedrag dit steeds koppel.
3. Neem verkeer op die drie Docker-bridges vas met `tcpdump` op die lab-host en vergelyk tydstempels.
4. Stop `ht-orb-r2`; verifieer dat daar geen direkte fallback vanaf die entry na die target is nie.

### Afbou
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch and redirector logging

**Doelstelling:** reproduseer die routing-primitief agter domain fronting op ’n private plaaslike edge en wys waar dit sigbaar is. Geen publieke CDN is betrokke nie.

### Bou ’n plaaslike TLS-edge
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
### Stuur en observeer die wanpassing
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Verwagte log-velde sluit `sni=front.lab host=origin.lab` in. Die client-to-edge-packet capture stel SNI bloot tensy ECH gebruik word; die HTTP Host is op daardie verbinding geënkripteer. Die terminating edge sien albei.

Stuur nou ’n normale versoek en bevestig dat die beleid dit verwerp:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Detection assertion

Genereer slegs 'n alert op `sni != host` nadat poorte/hoofletters genormaliseer is en bekende reverse-proxy-uitsonderings nagegaan is. Voeg proses- en tenant/origin-konteks by voordat erns toegeken word.

### Afbreek
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Doelwit:** genereer ’n veilige DNS-datastel met lae TTL/multi-ASN-agtige eienskappe en valideer ’n analitiese reël. Die teruggestuurde RFC 5737-dokumentasieadresse is vir hierdie doel nie-roeteerbaar nie.

### Begin ’n authoritative server
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
Verwagte resultaat: elke antwoord bevat drie documentation IPs en ’n TTL van 5 sekondes. Regte fast flux roteer ook subsets met verloop van tyd; verander die zone serial/addresses en herbegin hierdie disposable server om veelvuldige epochs te skep.

### Analitiese validering

Bereken vir ’n vyfminutevenster `median(TTL)`, unieke antwoorde, unieke synthetic ASN/geography labels en answer churn. Vereis ten minste twee verdagte dimensies plus ’n process/follow-on event. Voer dieselfde analise teen ’n bekende CDN-sample uit om false positives te meet.

### Opruiming
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**Doelwit:** reproduseer die APT28-grenswanpassing met twee “organisasies” wat jy besit. Omdat Wi-Fi-hardeware/driver-opdragte verskil, spesifiseer hierdie lab verifieerbare rolle en bewysmateriaal eerder as om voor te gee dat een `hostapd`-opdrag vir elke radio werk.

### Toerusting

- twee APs wat jy besit, op geïsoleerde lab-kanale/SSIDs `HT-NEIGHBOR` en `HT-TARGET`;
- een target-diens wat slegs vanaf `HT-TARGET` bereikbaar is;
- een dual-radio Linux pivot wat jy besit en wat aan albei APs kan assosieer;
- een remote-control-werkstasie agter `HT-NEIGHBOR`;
- RADIUS/NAC- of AP-assosiasielogboeke, DHCP-logboeke en pivot-oudit-/proseslogboeke.

### Prosedure

1. Isoleer of verswak die opstelling fisies sodat geen SSID die gemagtigde gebied verlaat nie. Bevestig dit met ’n survey.
2. Konfigureer `HT-TARGET` met ’n oefenidentiteit en laat toestelsertifikaat-/posture-validasie doelbewus vir die eerste uitvoering weg. Teken dit aan as die toestand wat getoets word.
3. Assosieer die pivot se eerste interface met `HT-NEIGHBOR` en die tweede interface met `HT-TARGET`. Moenie ’n algemene bridge aktiveer nie; laat slegs die target-diens/-poort deur ’n host firewall toe.
4. Open vanaf die werkstasie ’n geauthentiseerde tunnel na die pivot en versoek die target-diens daardeur.
5. Teken die pivot-proses-/interface-skepping, albei AP-assosiasies, die target se RADIUS-gebeurtenis, DHCP-lease en target-bronadres aan.
6. Vra die detection-span om die ketting sonder die controller map te rekonstrueer.
7. Aktiveer EAP-TLS/managed-device posture op `HT-TARGET`, verwyder die pivot se goedgekeurde target-sertifikaat en herhaal. Toegang behoort tydens toelating te misluk.
8. Herhaal met ’n eerste-gesiene randomized MAC. Verifieer dat die sertifikaat-/toestelbesluit steeds werk en dat geen reël die MAC alleen as identiteit behandel nie.

### Sukseskriteria

- Die target sien aanvanklik ’n plaaslike Wi-Fi-kliënt eerder as die werkstasie.
- Joined telemetry identifiseer een pivot met gelyktydige neighbor-control- en target-radio-paaie.
- Sertifikaat-/toestelgebaseerde toelating blokkeer die tweede uitvoering.
- Geen packet bereik ’n netwerk buite die geïsoleerde lab nie.

## Lab 5: dead-drop resolver sequence

**Doelwit:** bespeur ’n proses wat ’n legitiem lykende objek lees, ’n pointer dekodeer en onmiddellik met ’n tweede diens kontak maak.

### Bou ('n opstelling)
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
Die geënkodeerde inhoud is `http://ht-ddr-c2:80/`. ’n Werkende detection koppel dieselfde kortstondige process/container wat `/profile.txt` lees, die inhoud decodeer en binne sekondes met `ht-ddr-c2` verbinding maak. Hash en bewaar die object response.

### Teardown
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: synthetic peel-chain and bridge graph

**Doelwit:** oefen waardenasporing sonder werklike bates, rekeninge of dienste.

### Skep en spoor die datastel na
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
Ontleders moet die peel/change-patroon identifiseer, die bridge link as ’n afsonderlik ondersteunde afleiding hanteer, die fooi/waardeverskil bereken en die exchange as ’n off-chain-bewysversoek merk. Verander een waarde/tyd en dokumenteer hoe die vertroue verander.

### Afbreek
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: passiewe traffic-signaling sensor

**Doelwit:** emuleer die netwerksignatuur van ’n passiewe, deur ’n magic value geaktiveerde implant sonder om ’n shell, persistence of remote access te skep. Die listener bind slegs aan loopback en teken ’n onskadelike gebeurtenis aan.
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
Verwagte resultaat: gewone verkeer lewer geen application event nie; slegs die aangewese token doen dit. Capture loopback-verkeer tydens die uitvoering en verifieer dat ’n network sensor steeds albei datagrams kan sien. Evalueer dan host controls wat ’n onverwagte langlopende packet listener of packet-capture filter opspoor. Werklike RedPenguin passive implants het verkeer op ’n router geïnspekteer en gevaarlike funksionaliteit gebied; hierdie lab doen doelbewus geen van die twee nie.

## Labverslagtemplate

Teken vir elke lab die volgende aan:

- authorization en geïsoleerde scope;
- hypothesis en ATT&CK technique;
- topology en observer table;
- presiese begin-/eindtyd en configuration hashes;
- verwagte events per sensor;
- events wat werklik waargeneem is en retention gaps;
- analytic logic, threshold en false-positive sample;
- of die target team die path gerekonstrueer het;
- mitigation retest-resultaat; en
- teardown/recovery-bewyse.

’n Exercise is onvolledig totdat die detection ná mitigation herhaal is en elke lab-resource verwyder is.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
