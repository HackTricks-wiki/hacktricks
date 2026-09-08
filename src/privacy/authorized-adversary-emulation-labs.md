# Maabara za Uigaji wa Adui Zilizoidhinishwa

Mazoezi haya yanazalisha upya **usanifu unaoonekana**, si compromise isiyoidhinishwa. Yaendeshe kwenye host maalum ya Linux ya maabara yenye Docker, bila credentials nyeti na bila route kuelekea targets za wahusika wengine. Majina yamewekwa maalum ili teardown iwe wazi.

{% hint style="danger" %}
Usibadilishe containers, APs, routers, accounts au synthetic transactions zinazomilikiwa zilizo hapa chini kwa public proxies, Wi-Fi ya jirani, production CDN tenant usiyoidhibiti, au fedha halisi za kifisadi. Uidhinishaji wa maandishi lazima ujumuishe kila mfumo na mazingira ya radio.
{% endhint %}

## Lab 1: owned ORB na redirector chain

**Lengo:** kuonyesha kwamba target hurekodi exit pekee, huku kila relay ikiona hops zilizo karibu nayo. Hii inaiga muundo wa T1090.003/T1584 bila vifaa vilivyocompromise.

**Mahitaji:** Docker Engine na majina ya containers ambayo hayatumiki na yanaoanza na `ht-orb-`.

### Build
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
### Thibitisha mipaka ya mwonekano
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Matokeo yanayotarajiwa: Nginx inarekodi anwani ya `ht-orb-r2` kwenye `ht-orb-target`, si ya mteja wa ombi moja. Relay logs zinaonyesha miunganisho kutoka kwenye mtandao wao wa karibu pekee. Ukaguzi wa Docker control-plane bado unatengeneza upya njia nzima—sawa na ushahidi wa provider/controller.

### Majaribio ya utambuzi

1. Rudia maombi kila baada ya sekunde 60 na uchorie grafu ya muda kati ya maombi na idadi ya bytes.
2. Badilisha `ht-orb-r2` na container/anwani mpya yenye jina, lakini dumisha cadence na ombi lilelile la application; thibitisha kuwa rule ya IP-only inapoteza chain huku behavior ikiendelea kuihusisha.
3. Nasa trafiki kwenye Docker bridges zote tatu kwa kutumia `tcpdump` kwenye lab host na ulinganishe timestamps.
4. Simamisha `ht-orb-r2`; thibitisha kuwa hakuna fallback ya moja kwa moja kutoka entry kwenda target.

### Kuvunja mazingira
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch na redirector logging

**Lengo:** kuzalisha tena routing primitive iliyo nyuma ya domain fronting kwenye private local edge na kuonyesha inapoonekana. Hakuna public CDN inayohusika.

### Unda local TLS edge
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
### Tuma na uangalie kutolingana
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Sehemu za log zinazotarajiwa zinajumuisha `sni=front.lab host=origin.lab`. Ukamataji wa pakiti kutoka kwa client hadi edge unaonyesha SNI isipokuwa ECH inatumika; HTTP Host imesimbwa kwa njia fiche kwenye kiungo hicho. Edge inayokamilisha muunganisho inaona zote mbili.

Sasa tuma request ya kawaida na uthibitishe kuwa policy inaikataa:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Assertion ya ugunduzi

Toa alert kwenye `sni != host` tu baada ya kusawazisha ports/case na kuangalia exceptions zinazojulikana za reverse-proxy. Ongeza muktadha wa process na tenant/origin kabla ya kuweka severity.

### Uondoaji wa usanidi
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Lengo:** tengeneza dataset salama ya DNS inayofanana na low-TTL/multi-ASN na uthibitishe analytic. Anwani za documentation za RFC 5737 zilizorejeshwa hazipitishi traffic kwa madhumuni haya.

### Endesha authoritative server
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
Matokeo yanayotarajiwa: kila jibu lina IP tatu za documentation na TTL ya sekunde 5. Real fast flux pia huzungusha subsets kwa muda; badilisha serial/addresses za zone na uwashe upya server hii ya muda ili kuunda epochs nyingi.

### Uthibitishaji wa uchanganuzi

Kwa kipindi cha dakika tano, hesabu `median(TTL)`, majibu tofauti, labels tofauti za synthetic ASN/geography na answer churn. Hitaji angalau vipengele viwili vya kutiliwa shaka pamoja na tukio la mchakato/follow-on. Endesha uchanganuzi huo dhidi ya sampuli inayojulikana ya CDN ili kupima false positives.

### Kusitisha
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**Lengo:** kuiga mismatch ya boundary ya APT28 kwa kutumia “organizations” mbili unazomiliki. Kwa sababu amri za Wi-Fi hardware/driver hutofautiana, lab hii inabainisha roles na ushahidi unaoweza kuthibitishwa badala ya kujifanya kuwa amri moja ya `hostapd` inafaa kwa kila radio.

### Vifaa

- AP mbili unazomiliki, kwenye channels/SSIDs zilizotengwa za lab `HT-NEIGHBOR` na `HT-TARGET`;
- target service moja inayoweza kufikiwa tu kutoka `HT-TARGET`;
- Linux pivot yenye dual-radio unayomiliki, inayoweza ku-associate na AP zote mbili;
- remote-control workstation moja iliyo nyuma ya `HT-NEIGHBOR`;
- RADIUS/NAC au AP association logs, DHCP logs na pivot audit/process logs.

### Utaratibu

1. Tenga au punguza nguvu ya setup kimwili ili SSID zote zisitoke nje ya eneo lililoidhinishwa. Thibitisha kwa survey.
2. Configure `HT-TARGET` kwa exercise identity na uondoe kwa makusudi device-certificate/posture validation kwa run ya kwanza. Rekodi hili kama condition inayojaribiwa.
3. Jiunge na pivot's first interface kwenye `HT-NEIGHBOR` na second interface kwenye `HT-TARGET`. **Usi-enable general bridge**; ruhusu tu target service/port kupitia host firewall.
4. Kutoka workstation, fungua authenticated tunnel kwenda pivot na uombe target service kupitia humo.
5. Rekodi pivot process/interface creation, AP associations zote mbili, target RADIUS event, DHCP lease na target source address.
6. Waombe detection team wajenge upya chain bila controller map.
7. Enable EAP-TLS/managed-device posture kwenye `HT-TARGET`, ondoa pivot's approved target certificate kisha urudie. Access inapaswa kushindikana wakati wa admission.
8. Rudia kwa first-seen randomized MAC. Thibitisha kuwa certificate/device decision bado inafanya kazi na hakuna rule inayochukulia MAC pekee kama identity.

### Vigezo vya mafanikio

- Target mwanzoni inaona local Wi-Fi client badala ya workstation.
- Joined telemetry inamtambua pivot mmoja mwenye neighbor-control na target-radio paths zinazofanya kazi kwa wakati mmoja.
- Certificate/device-backed admission inazuia run ya pili.
- Hakuna packet inayofika kwenye network iliyo nje ya lab iliyotengwa.

## Lab 5: dead-drop resolver sequence

**Lengo:** kugundua process inayosoma object inayoonekana halali, ku-decode pointer na kuwasiliana mara moja na service ya pili.

### Build
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
Maudhui yaliyosimbwa ni `http://ht-ddr-c2:80/`. Detection inayofanya kazi huunganisha mchakato/container hiyo hiyo ya muda mfupi inayosoma `/profile.txt`, kusimbua maudhui na kuwasiliana na `ht-ddr-c2` ndani ya sekunde chache. Tengeneza hash na uhifadhi response ya object.

### Usafishaji
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: synthetic peel-chain na bridge graph

**Lengo:** kufanya mazoezi ya ufuatiliaji wa thamani bila mali, akaunti au huduma halisi.

### Unda na ufuatilie dataset
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
Wachambuzi wanapaswa kutambua muundo wa peel/change, kuchukulia bridge link kama inference inayoungwa mkono kando, kukokotoa tofauti ya fee/value, na kuashiria exchange hiyo kama ombi la ushahidi wa off-chain. Badilisha value/time moja na uandike jinsi confidence inavyobadilika.

### Teardown
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: kihisi cha passive traffic-signaling

**Lengo:** kuiga network signature ya passive, magic-value-activated implant bila kuunda shell, persistence au remote access. Listener hufungamana na loopback pekee na kurekodi tukio lisilo na madhara.
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
Matokeo yanayotarajiwa: traffic ya kawaida haitoi application event; token iliyoteuliwa pekee ndiyo hufanya hivyo. Nasa traffic ya loopback wakati wa utekelezaji na uthibitishe kuwa network sensor bado inaweza kuona datagram zote mbili. Kisha tathmini host controls zinazotambua packet listener inayotarajiwa kuwa hai kwa muda mrefu au packet-capture filter isiyotarajiwa. Real RedPenguin passive implants zilikagua traffic kwenye router na kutoa utendaji hatari; lab hii haifanyi hivyo kimakusudi.

## Exercise report template

Kwa kila lab, rekodi:

- authorization na isolated scope;
- hypothesis na ATT&CK technique;
- topology na observer table;
- muda kamili wa kuanza/kumaliza na configuration hashes;
- events zinazotarajiwa kwa kila sensor;
- events zilizotazamwa na retention gaps;
- analytic logic, threshold na mfano wa false-positive;
- ikiwa target team ilireconstruct path;
- matokeo ya mitigation retest; na
- ushahidi wa teardown/recovery.

Exercise haijakamilika hadi detection iendeshwe tena baada ya mitigation na kila lab resource iondolewe.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
