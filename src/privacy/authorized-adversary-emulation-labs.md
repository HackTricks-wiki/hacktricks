# Εξουσιοδοτημένα Adversary-Emulation Labs

Αυτές οι ασκήσεις αναπαράγουν **παρατηρήσιμη αρχιτεκτονική**, όχι μη εξουσιοδοτημένο compromise. Εκτελέστε τες σε έναν αποκλειστικό Linux lab host με Docker, χωρίς ευαίσθητα credentials και χωρίς διαδρομή προς targets τρίτων. Τα ονόματα είναι προκαθορισμένα, ώστε το teardown να είναι ρητό.

{% hint style="danger" %}
Μην αντικαταστήσετε τα containers, τα APs, τους routers, τους λογαριασμούς ή τις synthetic transactions που σας ανήκουν παρακάτω με public proxies, το Wi-Fi ενός γείτονα, έναν production CDN tenant που δεν ελέγχετε ή πραγματικά illicit funds. Η γραπτή authorization πρέπει να καλύπτει κάθε σύστημα και radio environment.
{% endhint %}

## Lab 1: owned ORB και αλυσίδα redirectors

**Objective:** δείξτε ότι ένα target καταγράφει μόνο το exit, ενώ κάθε relay βλέπει τα γειτονικά hops. Αυτό προσομοιώνει τη δομή T1090.003/T1584 χωρίς compromised devices.

**Requirements:** Docker Engine και αχρησιμοποίητα container names που αρχίζουν με `ht-orb-`.

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
### Επαλήθευση των ορίων ορατότητας
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Αναμενόμενο αποτέλεσμα: Το Nginx καταγράφει τη διεύθυνση `ht-orb-r2` στο `ht-orb-target`, όχι τον one-shot client. Τα Relay logs εμφανίζουν συνδέσεις μόνο από το γειτονικό τους δίκτυο. Η επιθεώρηση του Docker control-plane εξακολουθεί να ανασυνθέτει ολόκληρη τη διαδρομή—ανάλογα με τα στοιχεία provider/controller.

### Πειράματα ανίχνευσης

1. Επανάλαβε τα requests κάθε 60 δευτερόλεπτα και δημιούργησε γράφημα του χρόνου μεταξύ διαδοχικών συνδέσεων και των bytes.
2. Αντικατάστησε το `ht-orb-r2` με ένα νέο named container/address, αλλά διατήρησε τον ίδιο ρυθμό και το ίδιο application request· επιβεβαίωσε ότι ένας κανόνας που βασίζεται μόνο σε IP χάνει την αλυσίδα, ενώ η συμπεριφορά εξακολουθεί να τη συνδέει.
3. Κατέγραψε την κίνηση στα τρία Docker bridges με `tcpdump` στο lab host και σύγκρινε τα timestamps.
4. Σταμάτησε το `ht-orb-r2`· επιβεβαίωσε ότι δεν υπάρχει άμεσο fallback από το entry στο target.

### Κατάργηση
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch and redirector logging

**Στόχος:** αναπαραγωγή του routing primitive πίσω από το domain fronting σε ένα ιδιωτικό τοπικό edge και ανάδειξη του σημείου όπου είναι ορατό. Δεν εμπλέκεται δημόσιο CDN.

### Δημιουργία ενός τοπικού TLS edge
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
### Αποστολή και παρατήρηση της ασυμφωνίας
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Τα αναμενόμενα πεδία log περιλαμβάνουν `sni=front.lab host=origin.lab`. Η καταγραφή πακέτων client-to-edge εκθέτει το SNI, εκτός αν χρησιμοποιείται ECH· το HTTP Host είναι κρυπτογραφημένο σε αυτήν τη σύνδεση. Το terminating edge βλέπει και τα δύο.

Τώρα στείλτε ένα κανονικό request και επιβεβαιώστε ότι η policy το απορρίπτει:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Assertion ανίχνευσης

Ειδοποιήστε για `sni != host` μόνο αφού κανονικοποιήσετε τις θύρες/την πεζογράφηση και ελέγξετε τις γνωστές εξαιρέσεις reverse-proxy. Προσθέστε το context της διεργασίας και του tenant/origin πριν αντιστοιχίσετε severity.

### Κατάργηση
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Στόχος:** δημιουργία ενός ασφαλούς dataset DNS τύπου low-TTL/multi-ASN και επικύρωση ενός analytic. Οι διευθύνσεις τεκμηρίωσης RFC 5737 που επιστρέφονται είναι non-routable για αυτόν τον σκοπό.

### Εκτέλεση authoritative server
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
Αναμενόμενο αποτέλεσμα: κάθε απάντηση περιέχει τρεις documentation IPs και TTL 5 δευτερολέπτων. Το πραγματικό fast flux περιστρέφει επίσης υποσύνολα με την πάροδο του χρόνου· αλλάξτε το zone serial/τις διευθύνσεις και επανεκκινήστε αυτόν τον disposable server για να δημιουργήσετε πολλαπλές epochs.

### Αναλυτική επικύρωση

Για ένα παράθυρο πέντε λεπτών, υπολογίστε τα `median(TTL)`, distinct answers, distinct synthetic ASN/geography labels και answer churn. Απαιτήστε τουλάχιστον δύο ύποπτες διαστάσεις, καθώς και ένα process/follow-on event. Εκτελέστε την ίδια ανάλυση σε ένα γνωστό CDN sample για να μετρήσετε τα false positives.

### Κατάργηση
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Εργαστήριο 4: nearest-neighbor wireless pivot

**Στόχος:** αναπαραγωγή του boundary mismatch του APT28 με δύο ιδιόκτητες «οργανώσεις». Επειδή οι εντολές για Wi-Fi hardware/driver διαφέρουν, αυτό το lab καθορίζει επαληθεύσιμους ρόλους και τεκμήρια, αντί να προσποιείται ότι μία εντολή `hostapd` ταιριάζει σε κάθε radio.

### Εξοπλισμός

- δύο AP που σας ανήκουν, σε απομονωμένα lab κανάλια/SSID `HT-NEIGHBOR` και `HT-TARGET`;
- μία target service προσβάσιμη μόνο από το `HT-TARGET`;
- ένα dual-radio Linux pivot που σας ανήκει και μπορεί να συνδεθεί και στα δύο AP;
- ένα remote-control workstation πίσω από το `HT-NEIGHBOR`;
- RADIUS/NAC ή AP association logs, DHCP logs και pivot audit/process logs.

### Διαδικασία

1. Απομονώστε φυσικά ή μειώστε την ισχύ του setup, ώστε κανένα SSID να μην διαφεύγει από την authorized περιοχή. Επιβεβαιώστε το με survey.
2. Ρυθμίστε το `HT-TARGET` με exercise identity και παραλείψτε σκόπιμα το device-certificate/posture validation για την πρώτη εκτέλεση. Καταγράψτε το ως την condition under test.
3. Συνδέστε το πρώτο interface του pivot στο `HT-NEIGHBOR` και το δεύτερο interface στο `HT-TARGET`. **Μην** ενεργοποιήσετε general bridge· επιτρέψτε μόνο τη target service/port μέσω host firewall.
4. Από το workstation, ανοίξτε authenticated tunnel προς το pivot και ζητήστε την target service μέσω αυτού.
5. Καταγράψτε τη δημιουργία process/interface στο pivot, και τις δύο AP associations, το target RADIUS event, το DHCP lease και το target source address.
6. Ζητήστε από την detection team να ανακατασκευάσει την αλυσίδα χωρίς το controller map.
7. Ενεργοποιήστε EAP-TLS/managed-device posture στο `HT-TARGET`, αφαιρέστε το approved target certificate του pivot και επαναλάβετε. Η πρόσβαση θα πρέπει να αποτύχει κατά την admission.
8. Επαναλάβετε με first-seen randomized MAC. Επαληθεύστε ότι η certificate/device απόφαση εξακολουθεί να λειτουργεί και ότι κανένας κανόνας δεν αντιμετωπίζει το MAC από μόνο του ως identity.

### Κριτήρια επιτυχίας

- Η target βλέπει αρχικά έναν local Wi-Fi client και όχι το workstation.
- Τα joined telemetry δεδομένα αναγνωρίζουν ένα pivot με ταυτόχρονες neighbor-control και target-radio διαδρομές.
- Η certificate/device-backed admission αποκλείει τη δεύτερη εκτέλεση.
- Κανένα packet δεν φτάνει σε network εκτός του isolated lab.

## Εργαστήριο 5: dead-drop resolver sequence

**Στόχος:** εντοπισμός process που διαβάζει ένα αντικείμενο που φαίνεται legitimate, αποκωδικοποιεί έναν pointer και επικοινωνεί αμέσως με δεύτερη service.

### Κατασκευή
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
Το encoded περιεχόμενο είναι `http://ht-ddr-c2:80/`. Μια λειτουργική ανίχνευση συσχετίζει την ίδια βραχύβια διεργασία/container που διαβάζει το `/profile.txt`, αποκωδικοποιεί το περιεχόμενο και επικοινωνεί με το `ht-ddr-c2` μέσα σε λίγα δευτερόλεπτα. Υπολόγισε το hash και διατήρησε την απόκριση του object.

### Εκκαθάριση
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Εργαστήριο 6: synthetic peel-chain και bridge graph

**Στόχος:** εξάσκηση στην ιχνηλάτηση αξίας χωρίς πραγματικά assets, accounts ή services.

### Δημιουργία και ιχνηλάτηση του dataset
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
Οι αναλυτές πρέπει να εντοπίζουν το μοτίβο peel/change, να αντιμετωπίζουν το bridge link ως ξεχωριστά υποστηριζόμενο συμπέρασμα, να υπολογίζουν τη διαφορά fee/value και να επισημαίνουν το exchange ως αίτημα off-chain evidence. Αλλάξτε μία value/time και τεκμηριώστε πώς μεταβάλλεται η confidence.

### Αποδόμηση
```bash
rm -rf -- "$ht_graph_dir"
```
## Εργαστήριο 7: passive traffic-signaling sensor

**Στόχος:** προσομοίωση του network signature ενός passive, magic-value-activated implant χωρίς δημιουργία shell, persistence ή remote access. Ο listener κάνει bind μόνο στο loopback και καταγράφει ένα benign event.
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
Αναμενόμενο αποτέλεσμα: η συνηθισμένη κίνηση δεν παράγει κανένα application event· μόνο το καθορισμένο token το κάνει. Καταγράψτε την loopback κίνηση κατά την εκτέλεση και επαληθεύστε ότι ένας network sensor εξακολουθεί να βλέπει και τα δύο datagrams. Στη συνέχεια αξιολογήστε τα host controls που εντοπίζουν έναν απρόσμενο packet listener μακράς διάρκειας ή ένα packet-capture filter. Τα πραγματικά παθητικά implants του RedPenguin επιθεωρούσαν την κίνηση σε router και προσέφεραν επικίνδυνες λειτουργίες· αυτό το lab σκόπιμα δεν κάνει τίποτα από τα δύο.

## Πρότυπο αναφοράς άσκησης

Για κάθε lab καταγράψτε:

- authorization και isolated scope·
- υπόθεση και τεχνική ATT&CK·
- topology και πίνακα observers·
- ακριβή ώρα έναρξης/λήξης και configuration hashes·
- αναμενόμενα events ανά sensor·
- events που παρατηρήθηκαν στην πράξη και κενά retention·
- analytic logic, threshold και δείγμα false positive·
- αν η target team ανασύνθεσε τη διαδρομή·
- αποτέλεσμα mitigation retest· και
- evidence για teardown/recovery.

Μια άσκηση είναι incomplete έως ότου το detection εκτελεστεί ξανά μετά το mitigation και αφαιρεθεί κάθε lab resource.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — Η επίθεση The Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
