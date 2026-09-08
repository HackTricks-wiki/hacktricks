# अधिकृत Adversary-Emulation Labs

{{#include ../banners/hacktricks-training.md}}

ये exercises unauthorized compromise के बजाय **observable architecture** को पुन: प्रस्तुत करते हैं। इन्हें Docker वाले dedicated Linux lab host पर चलाएँ, जहाँ कोई sensitive credentials न हों और third-party targets तक कोई route न हो। Teardown को स्पष्ट रखने के लिए names fixed हैं।

{% hint style="danger" %}
नीचे दिए गए owned containers, APs, routers, accounts या synthetic transactions को public proxies, पड़ोसी के Wi-Fi, ऐसे production CDN tenant जिसे आप control नहीं करते, या वास्तविक illicit funds से replace न करें। Written authorization में प्रत्येक system और radio environment शामिल होना चाहिए।
{% endhint %}

## Lab 1: owned ORB और redirector chain

**Objective:** दिखाना कि target केवल exit record करता है, जबकि प्रत्येक relay को adjacent hops दिखाई देते हैं। यह compromised devices के बिना T1090.003/T1584 structure का emulation करता है।

**Requirements:** Docker Engine और `ht-orb-` से शुरू होने वाले unused container names।

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
### दृश्यता की सीमाओं को सत्यापित करें
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Expected result: Nginx `ht-orb-target` पर `ht-orb-r2` address रिकॉर्ड करता है, one-shot client का नहीं। Relay logs केवल अपने adjacent network से connections दिखाते हैं। Docker control-plane inspection अभी भी पूरे path को reconstruct करता है—यह provider/controller evidence के अनुरूप है।

### Detection experiments

1. हर 60 seconds में requests दोहराएँ और inter-arrival time तथा bytes का graph बनाएँ।
2. `ht-orb-r2` को नए named container/address से बदलें, लेकिन वही cadence और application request रखें; पुष्टि करें कि IP-only rule chain खो देता है, जबकि behavior अभी भी इसे link करता है।
3. Lab host पर `tcpdump` के साथ तीनों Docker bridges पर capture करें और timestamps की तुलना करें।
4. `ht-orb-r2` को stop करें; verify करें कि entry से target तक कोई direct fallback नहीं है।

### Teardown
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch और redirector logging

**Objective:** private local edge पर domain fronting के पीछे मौजूद routing primitive को reproduce करें और दिखाएं कि यह कहां दिखाई देता है। इसमें किसी public CDN का उपयोग नहीं किया गया है।

### स्थानीय TLS edge बनाएं
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
### mismatch भेजें और निरीक्षण करें
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
अपेक्षित log fields में `sni=front.lab host=origin.lab` शामिल हैं। client-to-edge packet capture में SNI दिखाई देता है, जब तक कि ECH का उपयोग न किया जा रहा हो; उस link पर HTTP Host encrypted होता है। terminating edge दोनों को देखता है।

अब एक सामान्य request भेजें और पुष्टि करें कि policy इसे reject करती है:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Detection assertion

` sni != host` पर alert केवल ports/case को normalize करने और ज्ञात reverse-proxy exceptions की जाँच करने के बाद ही करें। severity निर्धारित करने से पहले process और tenant/origin context जोड़ें।

### Teardown
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## लैब 3: fast-flux DNS telemetry

**उद्देश्य:** एक सुरक्षित low-TTL/multi-ASN-जैसा DNS dataset तैयार करना और एक analytic को validate करना। लौटाए गए RFC 5737 documentation addresses इस उद्देश्य के लिए non-routable हैं।

### एक authoritative server चलाएँ
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
अपेक्षित परिणाम: प्रत्येक answer में तीन documentation IPs और 5-second TTL हो। Real fast flux समय के साथ subsets को भी rotate करता है; कई epochs बनाने के लिए zone serial/addresses बदलें और इस disposable server को restart करें।

### Analytic validation

पाँच मिनट की window के लिए `median(TTL)`, distinct answers, distinct synthetic ASN/geography labels और answer churn की गणना करें। कम से कम दो suspicious dimensions के साथ एक process/follow-on event भी आवश्यक रखें। False positives मापने के लिए उसी analytic को एक ज्ञात CDN sample पर चलाएँ।

### Teardown
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**उद्देश्य:** दो स्वामित्व वाली “organizations” के साथ APT28 boundary mismatch को पुन: उत्पन्न करना। क्योंकि Wi-Fi hardware/driver commands अलग-अलग होते हैं, यह lab किसी एक `hostapd` command को हर radio के लिए उपयुक्त मानने के बजाय सत्यापित की जा सकने वाली भूमिकाएं और evidence निर्दिष्ट करती है।

### Equipment

- आपके स्वामित्व वाले दो APs, अलग-अलग lab channels/SSIDs `HT-NEIGHBOR` और `HT-TARGET` पर;
- एक target service, जो केवल `HT-TARGET` से पहुंच योग्य हो;
- आपके स्वामित्व वाला एक dual-radio Linux pivot, जो दोनों APs से associate कर सके;
- `HT-NEIGHBOR` के पीछे एक remote-control workstation;
- RADIUS/NAC या AP association logs, DHCP logs और pivot audit/process logs।

### Procedure

1. Setup को भौतिक रूप से isolate या attenuate करें ताकि कोई भी SSID authorized area से बाहर न पहुंचे। Survey से पुष्टि करें।
2. `HT-TARGET` को एक exercise identity के साथ configure करें और पहले run के लिए device-certificate/posture validation को जानबूझकर omit करें। इसे परीक्षणाधीन condition के रूप में record करें।
3. Pivot के first interface को `HT-NEIGHBOR` और second interface को `HT-TARGET` से join करें। General bridge enable **न** करें; host firewall के माध्यम से केवल target service/port को अनुमति दें।
4. Workstation से pivot के लिए एक authenticated tunnel खोलें और उसके माध्यम से target service का request करें।
5. Pivot process/interface creation, दोनों AP associations, target RADIUS event, DHCP lease और target source address को record करें।
6. Detection team से controller map के बिना chain को reconstruct करने के लिए कहें।
7. `HT-TARGET` पर EAP-TLS/managed-device posture enable करें, pivot का approved target certificate हटाएं और दोहराएं। Access admission पर fail होना चाहिए।
8. First-seen randomized MAC के साथ दोहराएं। सत्यापित करें कि certificate/device decision अब भी काम करता है और कोई rule अकेले MAC को identity नहीं मानता।

### Success criteria

- Target को workstation के बजाय एक local Wi-Fi client दिखाई देता है।
- Joined telemetry simultaneous neighbor-control और target-radio paths वाले एक pivot की पहचान करती है।
- Certificate/device-backed admission second run को block करता है।
- Isolated lab के बाहर किसी network तक कोई packet नहीं पहुंचता।

## Lab 5: dead-drop resolver sequence

**उद्देश्य:** ऐसे process का पता लगाना, जो किसी legitimate-looking object को पढ़ता है, एक pointer को decode करता है और तुरंत दूसरे service से contact करता है।

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
Encoded content `http://ht-ddr-c2:80/` है। एक प्रभावी detection उसी short-lived process/container को जोड़ता है जो `/profile.txt` पढ़ता है, content को decode करता है और कुछ ही सेकंड में `ht-ddr-c2` से संपर्क करता है। Object response का hash बनाकर उसे सुरक्षित रखें।

### Teardown
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: synthetic peel-chain और bridge graph

**Objective:** real assets, accounts या services के बिना value tracing का अभ्यास करें।

### dataset बनाएँ और trace करें
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
Analysts को peel/change pattern की पहचान करनी चाहिए, bridge link को अलग से समर्थित inference के रूप में देखना चाहिए, fee/value difference की गणना करनी चाहिए, और exchange को off-chain evidence request के रूप में चिह्नित करना चाहिए। एक value/time बदलें और document करें कि confidence कैसे बदलता है।

### Teardown
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: passive traffic-signaling sensor

**उद्देश्य:** shell, persistence या remote access बनाए बिना passive, magic-value-activated implant के network signature का emulation करना। listener केवल loopback से bind होता है और एक benign event रिकॉर्ड करता है।
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
अपेक्षित परिणाम: सामान्य traffic से कोई application event उत्पन्न न हो; केवल designated token से हो। Run के दौरान loopback traffic capture करें और verify करें कि network sensor दोनों datagrams को अभी भी देख सकता है। इसके बाद उन host controls का मूल्यांकन करें जो किसी unexpected long-running packet listener या packet-capture filter का पता लगाते हैं। वास्तविक RedPenguin passive implants ने router पर traffic का निरीक्षण किया और खतरनाक functionality प्रदान की; यह lab जानबूझकर इनमें से कुछ भी नहीं करती।

## Exercise report template

प्रत्येक lab के लिए रिकॉर्ड करें:

- authorization और isolated scope;
- hypothesis और ATT&CK technique;
- topology और observer table;
- exact start/end time और configuration hashes;
- प्रत्येक sensor के लिए expected events;
- वास्तव में observed events और retention gaps;
- analytic logic, threshold और false-positive sample;
- क्या target team ने path को reconstruct किया;
- mitigation retest result; और
- teardown/recovery evidence।

जब तक mitigation के बाद detection को फिर से run न किया जाए और प्रत्येक lab resource को हटा न दिया जाए, exercise incomplete है।

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
