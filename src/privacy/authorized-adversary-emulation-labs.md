# Autoryzowane laboratoria emulacji adversary

{{#include ../banners/hacktricks-training.md}}

Te ćwiczenia odtwarzają **obserwowalną architekturę**, a nie nieautoryzowane przejęcie. Uruchamiaj je na dedykowanym hoście laboratoryjnym Linux z Docker, bez wrażliwych danych uwierzytelniających i bez trasy do celów należących do osób trzecich. Nazwy są ustalone, aby teardown był jednoznaczny.

{% hint style="danger" %}
Nie zastępuj należących do Ciebie kontenerów, AP, routerów, kont ani syntetycznych transakcji poniżej publicznymi proxy, siecią Wi-Fi sąsiada, tenantem produkcyjnego CDN, nad którym nie masz kontroli, ani prawdziwymi nielegalnymi środkami. Pisemna autoryzacja musi obejmować każdy system i środowisko radiowe.
{% endhint %}

## Lab 1: należący do Ciebie ORB i łańcuch redirectorów

**Cel:** pokazać, że target rejestruje tylko exit, podczas gdy każdy relay widzi sąsiednie hopi. Emuluje to strukturę T1090.003/T1584 bez użycia przejętych urządzeń.

**Wymagania:** Docker Engine i nieużywane nazwy kontenerów zaczynające się od `ht-orb-`.

### Budowanie
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
### Zweryfikuj granice widoczności
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Oczekiwany rezultat: Nginx rejestruje adres `ht-orb-r2` na `ht-orb-target`, a nie klienta jednorazowego. Logi relay pokazują połączenia wyłącznie z ich sąsiedniej sieci. Inspekcja Docker control-plane nadal pozwala odtworzyć całą ścieżkę — analogicznie do dowodów po stronie providera/controllera.

### Eksperymenty wykrywania

1. Powtarzaj żądania co 60 sekund i sporządź wykres czasu między kolejnymi żądaniami oraz liczby bajtów.
2. Zastąp `ht-orb-r2` nowym nazwanym kontenerem/adresem, zachowując tę samą częstotliwość i żądanie aplikacji; potwierdź, że reguła oparta wyłącznie na adresie IP traci łańcuch, podczas gdy zachowanie nadal go łączy.
3. Przechwytuj ruch na trzech mostach Docker za pomocą `tcpdump` na hoście labu i porównaj znaczniki czasu.
4. Zatrzymaj `ht-orb-r2`; sprawdź, czy nie istnieje bezpośredni fallback z entry do target.

### Demontaż
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: Niezgodność SNI/Host i logging redirectora

**Cel:** odtworzyć mechanizm routingu wykorzystywany przez domain fronting na prywatnym lokalnym edge oraz pokazać, gdzie jest on widoczny. Nie jest używany żaden publiczny CDN.

### Zbuduj lokalny edge TLS
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
### Wyślij i obserwuj rozbieżność
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Oczekiwane pola logów obejmują `sni=front.lab host=origin.lab`. Przechwycenie pakietów na odcinku client-to-edge ujawnia SNI, chyba że używany jest ECH; HTTP Host jest szyfrowany na tym odcinku. Kończący połączenie edge widzi oba.

Teraz wyślij normalne żądanie i potwierdź, że policy je odrzuca:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Asercja wykrywania

Generuj alert dla `sni != host` dopiero po normalizacji portów i wielkości liter oraz sprawdzeniu znanych wyjątków reverse-proxy. Przed przypisaniem poziomu severity dodaj kontekst procesu oraz tenantu/origin.

### Demontaż
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Laboratorium 3: fast-flux DNS telemetry

**Cel:** wygenerować bezpieczny zbiór danych DNS typu low-TTL/multi-ASN i zweryfikować analitykę. Zwracane adresy dokumentacyjne RFC 5737 są w tym celu nieroutowalne.

### Uruchomienie authoritative server
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
Oczekiwany rezultat: każda odpowiedź zawiera trzy adresy IP dokumentacji oraz TTL wynoszący 5 sekund. Prawdziwy fast flux również rotuje podzbiory w czasie; zmień numer seryjny strefy/adresy i uruchom ponownie ten jednorazowy serwer, aby utworzyć wiele epok.

### Walidacja analityczna

Dla pięciominutowego okna oblicz `median(TTL)`, unikalne odpowiedzi, unikalne etykiety syntetycznych ASN/geografii oraz churn odpowiedzi. Wymagaj co najmniej dwóch podejrzanych wymiarów oraz zdarzenia procesowego/dalszego. Uruchom tę samą analizę na znanej próbce CDN, aby zmierzyć liczbę false positives.

### Demontaż
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**Cel:** odtworzyć mismatch granicy APT28 przy użyciu dwóch należących do nas „organizacji”. Ponieważ polecenia sprzętu/drivera Wi-Fi różnią się zależnie od platformy, ten lab określa weryfikowalne role i dowody, zamiast udawać, że jedno polecenie `hostapd` pasuje do każdego radia.

### Sprzęt

- dwa należące do nas AP, działające na izolowanych kanałach/SSID labowych `HT-NEIGHBOR` i `HT-TARGET`;
- jedna usługa docelowa dostępna wyłącznie z `HT-TARGET`;
- jeden należący do nas dual-radio Linux pivot, zdolny do łączenia się z oboma AP;
- jedna stacja robocza do zdalnego sterowania za `HT-NEIGHBOR`;
- logi RADIUS/NAC lub logi skojarzeń AP, logi DHCP oraz logi audytowe/procesów pivotu.

### Procedura

1. Fizycznie odizoluj lub osłab konfigurację, aby żaden SSID nie wydostał się poza autoryzowany obszar. Potwierdź to za pomocą survey.
2. Skonfiguruj `HT-TARGET` z tożsamością ćwiczeniową i podczas pierwszego uruchomienia celowo pomiń walidację certyfikatu urządzenia/posture. Zapisz to jako warunek poddawany testowi.
3. Połącz pierwszy interfejs pivotu z `HT-NEIGHBOR`, a drugi interfejs z `HT-TARGET`. **Nie** włączaj ogólnego bridge; zezwól przez host firewall wyłącznie na docelową usługę/port.
4. Ze stacji roboczej otwórz uwierzytelniony tunel do pivotu i zażądaj za jego pośrednictwem docelowej usługi.
5. Zapisz utworzenie procesu/interfejsu pivotu, skojarzenia z oboma AP, zdarzenie RADIUS celu, dzierżawę DHCP oraz źródłowy adres celu.
6. Poproś zespół detection o odtworzenie łańcucha bez mapy kontrolera.
7. Włącz EAP-TLS/managed-device posture na `HT-TARGET`, usuń zatwierdzony certyfikat celu pivotu i powtórz test. Dostęp powinien zakończyć się niepowodzeniem na etapie admission.
8. Powtórz test z użyciem losowego MAC widzianego po raz pierwszy. Zweryfikuj, że decyzja dotycząca certyfikatu/urządzenia nadal działa i że żadna reguła nie traktuje samego MAC jako tożsamości.

### Kryteria powodzenia

- Cel początkowo widzi lokalnego klienta Wi-Fi, a nie stację roboczą.
- Telemetria skojarzeń identyfikuje jeden pivot z jednoczesnymi ścieżkami do kontroli sąsiada i radia celu.
- Admission oparte na certyfikacie/urządzeniu blokuje drugi test.
- Żaden pakiet nie dociera do sieci poza izolowanym labem.

## Lab 5: dead-drop resolver sequence

**Cel:** wykryć proces odczytujący obiekt wyglądający na legalny, dekodujący wskaźnik i natychmiast kontaktujący się z drugą usługą.

### Budowa
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
Zakodowana zawartość to `http://ht-ddr-c2:80/`. Skuteczne wykrywanie łączy ten sam krótkotrwały proces/kontener, odczytujący `/profile.txt`, dekodujący zawartość i kontaktujący się z `ht-ddr-c2` w ciągu kilku sekund. Oblicz hash odpowiedzi obiektu i zachowaj ją.

### Usuwanie
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: synthetic peel-chain and bridge graph

**Cel:** przećwiczyć śledzenie wartości bez używania rzeczywistych aktywów, kont ani usług.

### Tworzenie i śledzenie datasetu
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
Analitycy powinni zidentyfikować wzorzec peel/change, potraktować bridge link jako oddzielnie potwierdzaną inferencję, obliczyć różnicę opłaty/wartości i oznaczyć exchange jako żądanie dowodów off-chain. Należy zmienić jedną wartość/czas i udokumentować, jak zmienia się poziom pewności.

### Demontaż
```bash
rm -rf -- "$ht_graph_dir"
```
## Laboratorium 7: pasywny sensor sygnalizujący ruch

**Cel:** emulacja sygnatury sieciowej pasywnego implantu aktywowanego magic value bez tworzenia shell, persistence ani remote access. Listener nasłuchuje wyłącznie na loopback i rejestruje niegroźne zdarzenie.
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
Oczekiwany rezultat: zwykły ruch nie generuje żadnego zdarzenia aplikacyjnego; robi to wyłącznie wyznaczony token. Podczas uruchomienia przechwyć ruch loopback i zweryfikuj, czy sensor sieciowy nadal widzi oba datagramy. Następnie oceń mechanizmy kontroli hosta wykrywające nieoczekiwany, długo działający packet listener lub filtr packet-capture. Rzeczywiste passive implants RedPenguin analizowały ruch na routerze i oferowały niebezpieczne funkcje; to laboratorium celowo nie robi żadnej z tych rzeczy.

## Szablon raportu z ćwiczenia

Dla każdego laboratorium zapisz:

- autoryzację i odizolowany zakres;
- hipotezę i technikę ATT&CK;
- topologię i tabelę obserwatorów;
- dokładny czas rozpoczęcia i zakończenia oraz hashe konfiguracji;
- oczekiwane zdarzenia dla każdego sensora;
- faktycznie zaobserwowane zdarzenia i luki w retencji;
- logikę analityczną, próg i przykład false positive;
- informację, czy zespół docelowy odtworzył ścieżkę;
- wynik ponownego testu mitigacji; oraz
- dowody teardown/recovery.

Ćwiczenie jest nieukończone, dopóki detekcja nie zostanie ponownie uruchomiona po zastosowaniu mitigacji, a każdy zasób laboratorium nie zostanie usunięty.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — Atak Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
