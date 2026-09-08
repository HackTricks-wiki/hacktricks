# Εργαστήρια Authorized Adversary-Emulation

{{#include ../banners/hacktricks-training.md}}

Αυτές οι ασκήσεις αναπαράγουν **παρατηρήσιμη αρχιτεκτονική**, όχι μη εξουσιοδοτημένη παραβίαση. Εκτελέστε τις σε έναν αποκλειστικό Linux lab host με Docker, χωρίς ευαίσθητα διαπιστευτήρια και χωρίς διαδρομή προς στόχους τρίτων. Τα ονόματα είναι προκαθορισμένα, ώστε το teardown να είναι σαφές.

{% hint style="danger" %}
Μην αντικαταστήσετε τα containers, τα APs, τους routers, τους λογαριασμούς ή τις συνθετικές συναλλαγές που ανήκουν σε εσάς παρακάτω με public proxies, το Wi-Fi ενός γείτονα, έναν production CDN tenant που δεν ελέγχετε ή πραγματικά παράνομα κεφάλαια. Η γραπτή εξουσιοδότηση πρέπει να καλύπτει κάθε σύστημα και περιβάλλον radio.
{% endhint %}

## Lab 1: owned ORB και αλυσίδα redirector

**Objective:** δείξτε ότι ένας στόχος καταγράφει μόνο την έξοδο, ενώ κάθε relay βλέπει τα γειτονικά hops. Αυτό προσομοιώνει τη δομή T1090.003/T1584 χωρίς compromised devices.

**Requirements:** Docker Engine και αχρησιμοποίητα ονόματα containers που αρχίζουν με `ht-orb-`.

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
### Επαληθεύστε τα όρια ορατότητας
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Αναμενόμενο αποτέλεσμα: Το Nginx καταγράφει τη διεύθυνση `ht-orb-r2` στο `ht-orb-target`, όχι αυτήν του one-shot client. Τα relay logs εμφανίζουν συνδέσεις μόνο από το γειτονικό τους δίκτυο. Η επιθεώρηση του Docker control-plane εξακολουθεί να ανακατασκευάζει ολόκληρη τη διαδρομή — ανάλογα με τα στοιχεία provider/controller.

### Πειράματα ανίχνευσης

1. Επανάλαβε τα requests κάθε 60 δευτερόλεπτα και δημιούργησε γράφημα με τον χρόνο μεταξύ αφίξεων και τα bytes.
2. Αντικατάστησε το `ht-orb-r2` με ένα νέο named container/address, διατηρώντας τον ίδιο ρυθμό και το ίδιο application request· επιβεβαίωσε ότι ένας κανόνας που βασίζεται μόνο σε IP χάνει την αλυσίδα, ενώ η συμπεριφορά εξακολουθεί να τη συνδέει.
3. Κατέγραψε κίνηση στα τρία Docker bridges με `tcpdump` στο lab host και σύγκρινε τα timestamps.
4. Σταμάτησε το `ht-orb-r2`· επαλήθευσε ότι δεν υπάρχει άμεσο fallback από το entry προς το target.

### Κατάργηση
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: Ασυμφωνία SNI/Host και logging του redirector

**Στόχος:** αναπαραγωγή του routing primitive πίσω από το domain fronting σε ένα ιδιωτικό local edge και επίδειξη του σημείου όπου είναι ορατό. Δεν εμπλέκεται public CDN.

### Δημιουργία ενός local TLS edge
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
Τα αναμενόμενα πεδία log περιλαμβάνουν `sni=front.lab host=origin.lab`. Η καταγραφή πακέτων από τον client προς το edge εκθέτει το SNI, εκτός αν χρησιμοποιείται ECH· το HTTP Host είναι κρυπτογραφημένο σε αυτήν τη σύνδεση. Το edge που τερματίζει τη σύνδεση βλέπει και τα δύο.

Τώρα στείλτε ένα κανονικό request και επιβεβαιώστε ότι η policy το απορρίπτει:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Assertion ανίχνευσης

Σημάνετε συναγερμό για `sni != host` μόνο αφού κανονικοποιήσετε τις θύρες και τα πεζά/κεφαλαία και ελέγξετε τις γνωστές εξαιρέσεις reverse-proxy. Προσθέστε το πλαίσιο της διεργασίας και του tenant/origin πριν αντιστοιχίσετε severity.

### Εκκαθάριση
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Στόχος:** δημιουργία ενός ασφαλούς dataset DNS με low-TTL/όπως multi-ASN και επικύρωση ενός analytic. Οι RFC 5737 documentation διευθύνσεις που επιστρέφονται είναι non-routable για αυτόν τον σκοπό.

### Εκτέλεση ενός authoritative server
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
Αναμενόμενο αποτέλεσμα: κάθε απάντηση περιλαμβάνει τρεις documentation IPs και TTL 5 δευτερολέπτων. Το πραγματικό fast flux περιστρέφει επίσης υποσύνολα με την πάροδο του χρόνου· αλλάξτε το serial/τις διευθύνσεις του zone και επανεκκινήστε αυτόν τον disposable server για να δημιουργήσετε πολλαπλές epochs.

### Αναλυτική επικύρωση

Για ένα παράθυρο πέντε λεπτών, υπολογίστε τα `median(TTL)`, distinct answers, distinct synthetic ASN/geography labels και answer churn. Απαιτήστε τουλάχιστον δύο ύποπτες διαστάσεις, καθώς και ένα process/follow-on event. Εκτελέστε την ίδια ανάλυση σε ένα γνωστό CDN sample για να μετρήσετε τα false positives.

### Κατάργηση setup
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Εργαστήριο 4: wireless pivot προς κοντινό γειτονικό δίκτυο

**Στόχος:** αναπαραγωγή της ασυμφωνίας ορίων του APT28 με δύο ιδιόκτητους «οργανισμούς». Επειδή οι εντολές hardware/driver του Wi-Fi διαφέρουν, αυτό το εργαστήριο καθορίζει επαληθεύσιμους ρόλους και στοιχεία τεκμηρίωσης, αντί να προσποιείται ότι μία εντολή `hostapd` ταιριάζει σε κάθε radio.

### Εξοπλισμός

- δύο AP που σας ανήκουν, σε απομονωμένα κανάλια/SSID εργαστηρίου `HT-NEIGHBOR` και `HT-TARGET`;
- μία target υπηρεσία προσβάσιμη μόνο από το `HT-TARGET`;
- ένα dual-radio Linux pivot που σας ανήκει και μπορεί να συνδεθεί και στα δύο AP;
- ένας remote-control workstation πίσω από το `HT-NEIGHBOR`;
- αρχεία καταγραφής RADIUS/NAC ή AP association, DHCP και pivot audit/process.

### Διαδικασία

1. Απομονώστε φυσικά ή μειώστε την εμβέλεια της εγκατάστασης, ώστε κανένα SSID να μην ξεφεύγει από την εξουσιοδοτημένη περιοχή. Επιβεβαιώστε το με survey.
2. Ρυθμίστε το `HT-TARGET` με μια identity για την άσκηση και παραλείψτε σκόπιμα την επικύρωση device-certificate/posture για την πρώτη εκτέλεση. Καταγράψτε το ως την υπό εξέταση συνθήκη.
3. Συνδέστε το πρώτο interface του pivot στο `HT-NEIGHBOR` και το δεύτερο interface στο `HT-TARGET`. **Μην** ενεργοποιήσετε γενικό bridge· επιτρέψτε μόνο την target service/port μέσω host firewall.
4. Από τον workstation, ανοίξτε authenticated tunnel προς το pivot και ζητήστε την target service μέσω αυτού.
5. Καταγράψτε τη δημιουργία διεργασίας/interface του pivot, τις συνδέσεις και στα δύο AP, το target RADIUS event, το DHCP lease και την target source address.
6. Ζητήστε από την detection team να ανασυνθέσει την αλυσίδα χωρίς το controller map.
7. Ενεργοποιήστε EAP-TLS/managed-device posture στο `HT-TARGET`, αφαιρέστε το εγκεκριμένο target certificate του pivot και επαναλάβετε. Η πρόσβαση θα πρέπει να αποτύχει στο admission.
8. Επαναλάβετε με randomized MAC που εμφανίζεται για πρώτη φορά. Επαληθεύστε ότι η απόφαση certificate/device εξακολουθεί να λειτουργεί και ότι κανένας κανόνας δεν αντιμετωπίζει το MAC από μόνο του ως identity.

### Κριτήρια επιτυχίας

- Η target βλέπει αρχικά έναν τοπικό Wi-Fi client και όχι τον workstation.
- Η joined telemetry αναγνωρίζει ένα pivot με ταυτόχρονες διαδρομές προς το neighbor-control και το target-radio.
- Το certificate/device-backed admission αποκλείει τη δεύτερη εκτέλεση.
- Κανένα packet δεν φτάνει σε δίκτυο εκτός του απομονωμένου εργαστηρίου.

## Εργαστήριο 5: dead-drop resolver sequence

**Στόχος:** ανίχνευση μιας διεργασίας που διαβάζει ένα αντικείμενο με νόμιμη εμφάνιση, αποκωδικοποιεί έναν pointer και επικοινωνεί αμέσως με μια δεύτερη υπηρεσία.

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
Το κωδικοποιημένο περιεχόμενο είναι `http://ht-ddr-c2:80/`. Μια λειτουργική ανίχνευση συσχετίζει την ίδια βραχύβια διεργασία/container που διαβάζει το `/profile.txt`, αποκωδικοποιεί το περιεχόμενο και επικοινωνεί με το `ht-ddr-c2` μέσα σε λίγα δευτερόλεπτα. Υπολογίστε το hash και διατηρήστε την απόκριση του object.

### Αποδόμηση
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Εργαστήριο 6: synthetic peel-chain και bridge graph

**Στόχος:** εξάσκηση στο value tracing χωρίς πραγματικά assets, accounts ή services.

### Δημιουργία και tracing του dataset
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
Οι Analysts θα πρέπει να εντοπίσουν το μοτίβο peel/change, να αντιμετωπίσουν το bridge link ως ξεχωριστά υποστηριζόμενο συμπέρασμα, να υπολογίσουν τη διαφορά fee/value και να επισημάνουν το exchange ως αίτημα για off-chain στοιχεία. Αλλάξτε μία value/ώρα και καταγράψτε πώς αλλάζει η confidence.

### Teardown
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: παθητικός αισθητήρας σηματοδότησης traffic

**Στόχος:** προσομοίωση του network signature ενός παθητικού implant που ενεργοποιείται μέσω magic value, χωρίς δημιουργία shell, persistence ή remote access. Ο listener συνδέεται μόνο στο loopback και καταγράφει ένα benign event.
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
Αναμενόμενο αποτέλεσμα: η συνήθης κίνηση δεν παράγει κανένα application event· μόνο το καθορισμένο token παράγει event. Καταγράψτε την κίνηση loopback κατά την εκτέλεση και επαληθεύστε ότι ένα network sensor μπορεί να δει και τα δύο datagrams. Στη συνέχεια αξιολογήστε τα host controls που εντοπίζουν έναν απρόσμενο packet listener μακράς διάρκειας ή ένα packet-capture filter. Τα πραγματικά παθητικά implants του RedPenguin επιθεωρούσαν την κίνηση σε router και παρείχαν επικίνδυνη λειτουργικότητα· αυτό το lab σκόπιμα δεν κάνει τίποτα από τα δύο.

## Πρότυπο αναφοράς άσκησης

Για κάθε lab καταγράψτε:

- την authorization και το isolated scope·
- την υπόθεση και την ATT&CK technique·
- την topology και τον πίνακα observers·
- την ακριβή ώρα έναρξης/λήξης και τα configuration hashes·
- τα αναμενόμενα events ανά sensor·
- τα events που παρατηρήθηκαν πραγματικά και τα retention gaps·
- την analytic logic, το threshold και ένα false-positive sample·
- αν η target team ανακατασκεύασε τη διαδρομή·
- το αποτέλεσμα του mitigation retest· και
- τα στοιχεία teardown/recovery.

Μια άσκηση είναι incomplete μέχρι να εκτελεστεί ξανά το detection μετά το mitigation και να αφαιρεθεί κάθε lab resource.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — Η επίθεση του πλησιέστερου γείτονα](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
