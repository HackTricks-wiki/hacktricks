# Laboratorije za emulaciju ovlašćenog protivnika

Ove vežbe reprodukuju **uočljivu arhitekturu**, a ne neovlašćeni kompromis. Pokrećite ih na namenskom Linux lab hostu sa Docker-om, bez osetljivih akreditiva i bez rute ka ciljevima trećih strana. Nazivi su fiksni kako bi teardown bio eksplicitan.

{% hint style="danger" %}
Nemojte zameniti navedene kontejnere, AP-ove, rutere, naloge ili sintetičke transakcije u vašem vlasništvu javnim proxy-jima, Wi-Fi mrežom komšije, production CDN tenant-om kojim ne upravljate ili stvarnim nezakonitim sredstvima. Pisano ovlašćenje mora obuhvatiti svaki sistem i radio-okruženje.
{% endhint %}

## Lab 1: owned ORB i redirector lanac

**Cilj:** pokazati da target beleži samo izlaznu tačku, dok svaki relay vidi susedne hop-ove. Ovo emulira strukturu T1090.003/T1584 bez kompromitovanih uređaja.

**Zahtevi:** Docker Engine i nekorišćena imena kontejnera koja počinju sa `ht-orb-`.

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
### Proverite granice vidljivosti
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Očekivani rezultat: Nginx beleži adresu `ht-orb-r2` na `ht-orb-target`, a ne jednokratnog klijenta. Relay logovi prikazuju konekcije samo sa njihove susedne mreže. Docker control-plane inspekcija i dalje rekonstruiše čitavu putanju — analogno dokazima provajdera/kontrolera.

### Eksperimenti detekcije

1. Ponavljajte zahteve svakih 60 sekundi i grafički prikažite vreme između dolazaka i broj bajtova.
2. Zamenite `ht-orb-r2` novim imenovanim containerom/adresom, ali zadržite isti ritam i aplikacioni zahtev; potvrdite da pravilo zasnovano samo na IP adresi gubi lanac, dok ga ponašanje i dalje povezuje.
3. Snimajte saobraćaj na tri Docker bridge-a pomoću `tcpdump` na lab hostu i uporedite vremenske oznake.
4. Zaustavite `ht-orb-r2`; proverite da ne postoji direktni fallback od ulaza do cilja.

### Rušenje okruženja
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch i redirector logging

**Cilj:** reprodukovati routing primitive iza domain fronting-a na privatnom lokalnom edge-u i prikazati gde je vidljiv. Nije uključen nijedan javni CDN.

### Izgradite lokalni TLS edge
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
### Pošaljite i posmatrajte nepodudaranje
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Očekivana polja loga uključuju `sni=front.lab host=origin.lab`. Hvatanje paketa između klijenta i edge-a otkriva SNI, osim ako se koristi ECH; HTTP Host je šifrovan na toj vezi. Edge koji terminira vezu vidi oba.

Sada pošaljite normalan zahtev i potvrdite da ga policy odbija:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Asertacija detekcije

Upozori na `sni != host` tek nakon normalizovanja portova i velikih/malih slova i provere poznatih izuzetaka za reverse-proxy. Dodaj kontekst procesa i tenant/origin kontekst pre dodeljivanja ozbiljnosti.

### Uklanjanje postavke
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetrija

**Cilj:** generisati bezbedan DNS dataset sa niskim TTL-om/sličan multi-ASN-u i validirati analitiku. Vraćene RFC 5737 documentation adrese nisu routable za ovu svrhu.

### Pokrenite authoritative server
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
Expected result: svaki odgovor sadrži tri documentation IP adrese i TTL od 5 sekundi. Pravi fast flux takođe rotira podskupove tokom vremena; promenite serijski broj zone/adrese i restartujte ovaj disposable server da biste kreirali više epoha.

### Analitička validacija

Za period od pet minuta izračunajte `median(TTL)`, različite odgovore, različite sintetičke ASN/geografske oznake i churn odgovora. Zahtevajte najmanje dve sumnjive dimenzije, uz proces i/ili naknadni događaj. Pokrenite istu analitiku nad poznatim CDN uzorkom da biste izmerili broj false positive rezultata.

### Uklanjanje
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: wireless pivot preko najbližeg suseda

**Cilj:** reprodukovati APT28 nepodudaranje granica sa dve „organizacije” koje posedujete. Pošto se Wi-Fi hardverske/driver komande razlikuju, ovaj lab definiše uloge i proverljive dokaze umesto da se pretvara da jedna `hostapd` komanda odgovara svakom radio-uređaju.

### Oprema

- dva AP-a koja posedujete, na izolovanim lab kanalima/SSID-ovima `HT-NEIGHBOR` i `HT-TARGET`;
- jedna ciljna usluga dostupna samo sa `HT-TARGET`;
- jedan dual-radio Linux pivot koji posedujete i koji može da se poveže sa oba AP-a;
- jedna radna stanica za daljinsku kontrolu iza `HT-NEIGHBOR`;
- RADIUS/NAC ili logovi AP asocijacija, DHCP logovi i audit/procesni logovi pivota.

### Procedura

1. Fizički izolujte ili oslabite postavku tako da nijedan SSID ne napusti autorizovanu oblast. Potvrdite to pregledom.
2. Konfigurišite `HT-TARGET` sa identitetom za vežbu i namerno izostavite validaciju sertifikata uređaja/posture-a za prvo pokretanje. Zabeležite ovo kao uslov koji se testira.
3. Povežite prvi interfejs pivota sa `HT-NEIGHBOR`, a drugi interfejs sa `HT-TARGET`. **Nemojte** omogućiti opšti bridge; dozvolite samo ciljnu uslugu/port kroz host firewall.
4. Sa radne stanice otvorite autentifikovani tunel ka pivotu i zatražite ciljnu uslugu kroz njega.
5. Zabeležite kreiranje procesa/interfejsa pivota, obe AP asocijacije, ciljni RADIUS događaj, DHCP lease i ciljnu izvornu adresu.
6. Zatražite od detection tima da rekonstruiše lanac bez mape kontrolera.
7. Omogućite EAP-TLS/posture upravljanog uređaja na `HT-TARGET`, uklonite odobreni ciljni sertifikat pivota i ponovite postupak. Pristup treba da bude odbijen tokom prijema.
8. Ponovite postupak sa randomizovanom MAC adresom koja je prvi put viđena. Proverite da odluka zasnovana na sertifikatu/uređaju i dalje funkcioniše i da nijedno pravilo ne tretira samu MAC adresu kao identitet.

### Kriterijumi uspeha

- Cilj u početku vidi lokalnog Wi-Fi klijenta, a ne radnu stanicu.
- Prikupljena telemetrija identifikuje jedan pivot sa istovremenim putanjama ka susednoj kontrolnoj mreži i ciljnom radiju.
- Prijem zasnovan na sertifikatu/uređaju blokira drugo pokretanje.
- Nijedan paket ne dospeva do mreže izvan izolovanog laba.

## Lab 5: sekvenca resolvera sa dead-drop lokacijom

**Cilj:** detektovati proces koji čita objekat legitimnog izgleda, dekodira pokazivač i odmah kontaktira drugu uslugu.

### Izgradnja
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
Kodirani sadržaj je `http://ht-ddr-c2:80/`. Funkcionalna detekcija povezuje isti kratkotrajni proces/kontejner koji čita `/profile.txt`, dekodira sadržaj i u roku od nekoliko sekundi kontaktira `ht-ddr-c2`. Izračunajte hash i sačuvajte odgovor objekta.

### Čišćenje
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: synthetic peel-chain i bridge graph

**Cilj:** vežbanje praćenja vrednosti bez stvarnih assets, naloga ili services.

### Kreiranje i praćenje dataseta
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
Analitičari treba da identifikuju obrazac peel/change, tretiraju bridge link kao zasebno potkrepljeni zaključak, izračunaju razliku u fee/value i označe exchange kao zahtev za off-chain dokazima. Promenite jednu vrednost/vreme i dokumentujte kako se confidence menja.

### Rastavljanje
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: pasivni senzor za signalizaciju saobraćaja

**Cilj:** emulirati mrežni potpis pasivnog implant-a aktiviranog magic-value vrednošću bez kreiranja shell-a, persistence-a ili remote access-a. Listener se vezuje samo za loopback i beleži benigni događaj.
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
Očekivani rezultat: uobičajeni saobraćaj ne proizvodi nijedan događaj aplikacije; samo određeni token ga proizvodi. Snimite loopback saobraćaj tokom rada i proverite da li network sensor i dalje može da vidi oba datagrama. Zatim procenite host kontrole koje otkrivaju neočekivani dugotrajni packet listener ili packet-capture filter. Pravi RedPenguin pasivni implantati pregledali su saobraćaj na ruteru i nudili opasne funkcionalnosti; ovaj lab namerno ne radi ni jedno ni drugo.

## Exercise report template

Za svaki lab zabeležite:

- autorizaciju i izolovani scope;
- hipotezu i ATT&CK tehniku;
- topologiju i tabelu posmatrača;
- tačno vreme početka/završetka i hash-eve konfiguracije;
- očekivane događaje po sensoru;
- stvarno uočene događaje i nedostatke u retention-u;
- analitičku logiku, prag i primer false-positive rezultata;
- da li je ciljni tim rekonstruisao putanju;
- rezultat ponovnog testiranja mitigation-a; i
- dokaze o teardown-u/recovery-ju.

Vežba je nepotpuna dok se detection ponovo ne pokrene nakon mitigation-a i dok se svaki lab resource ne ukloni.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — Napad najbližeg suseda](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
