# Laboratori di emulazione di avversari autorizzati

Questi esercizi riproducono **un'architettura osservabile**, non una compromissione non autorizzata. Eseguili su un host Linux di laboratorio dedicato con Docker, senza credenziali sensibili e senza route verso target di terze parti. I nomi sono fissi per rendere esplicito il teardown.

{% hint style="danger" %}
Non sostituire i container, gli AP, i router, gli account o le transazioni sintetiche di proprietà indicati di seguito con proxy pubblici, la rete Wi-Fi di un vicino, un tenant CDN di produzione che non controlli o fondi illeciti reali. L'autorizzazione scritta deve coprire ogni sistema e ambiente radio.
{% endhint %}

## Lab 1: catena ORB e redirector di proprietà

**Obiettivo:** dimostrare che un target registra solo l'uscita, mentre ogni relay vede gli hop adiacenti. Questo emula la struttura T1090.003/T1584 senza dispositivi compromessi.

**Requisiti:** Docker Engine e nomi di container non utilizzati che iniziano con `ht-orb-`.

### Costruzione
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
### Verifica i confini di visibilità
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Risultato atteso: Nginx registra l'indirizzo `ht-orb-r2` su `ht-orb-target`, non quello del client one-shot. I log del relay mostrano connessioni provenienti solo dalla rete adiacente. L'ispezione del control-plane di Docker ricostruisce comunque l'intero percorso, in modo analogo alle evidenze del provider/controller.

### Esperimenti di rilevamento

1. Ripeti le richieste ogni 60 secondi e traccia il tempo tra gli arrivi e i byte.
2. Sostituisci `ht-orb-r2` con un nuovo container/indirizzo denominato, mantenendo la stessa cadenza e la stessa richiesta applicativa; conferma che una regola basata solo sull'IP perda la catena, mentre il comportamento continui a collegarla.
3. Cattura il traffico sui tre bridge Docker con `tcpdump` sull'host del lab e confronta i timestamp.
4. Arresta `ht-orb-r2`; verifica che non esista alcun fallback diretto dall'entry al target.

### Smantellamento
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: mismatch SNI/Host e logging del redirector

**Obiettivo:** riprodurre la primitiva di routing alla base del domain fronting su un edge locale privato e mostrare dove è visibile. Non è coinvolto alcun CDN pubblico.

### Creare un edge TLS locale
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
### Invia e osserva la discrepanza
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
I campi di log attesi includono `sni=front.lab host=origin.lab`. La packet capture client-to-edge espone l'SNI, a meno che non sia in uso ECH; l'HTTP Host è cifrato su quel collegamento. Il terminating edge vede entrambi.

Ora invia una richiesta normale e conferma che la policy la rifiuti:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Assertion di rilevamento

Genera un alert su `sni != host` solo dopo aver normalizzato porte/maiuscole e verificato le eccezioni note del reverse-proxy. Aggiungi il contesto del processo e del tenant/origin prima di assegnare la gravità.

### Teardown
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Obiettivo:** generare un dataset DNS sicuro, simile a low-TTL/multi-ASN, e validare un'analisi. Gli indirizzi di documentazione RFC 5737 restituiti sono non instradabili per questo scopo.

### Esegui un authoritative server
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
Risultato previsto: ogni risposta contiene tre IP di documentazione e un TTL di 5 secondi. Il fast flux reale ruota anche sottoinsiemi nel tempo; modifica il seriale della zona/gli indirizzi e riavvia questo server usa e getta per creare più epoche.

### Validazione analitica

Per una finestra di cinque minuti, calcola `median(TTL)`, le risposte distinte, le etichette ASN/geografiche sintetiche distinte e il churn delle risposte. Richiedi almeno due dimensioni sospette oltre a un evento di processo/successivo. Esegui la stessa analisi su un campione CDN noto per misurare i falsi positivi.

### Smantellamento
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**Obiettivo:** riprodurre il boundary mismatch di APT28 con due “organizzazioni” di proprietà. Poiché i comandi relativi all'hardware/driver Wi-Fi variano, questo lab specifica ruoli ed evidenze verificabili invece di fingere che un singolo comando `hostapd` sia adatto a ogni radio.

### Apparecchiatura

- due AP di tua proprietà, su canali/SSID isolati del lab `HT-NEIGHBOR` e `HT-TARGET`;
- un target service raggiungibile solo da `HT-TARGET`;
- un pivot Linux dual-radio di tua proprietà, in grado di associarsi a entrambi gli AP;
- una workstation per il remote-control dietro `HT-NEIGHBOR`;
- log RADIUS/NAC o di associazione degli AP, log DHCP e log di audit/processo del pivot.

### Procedura

1. Isola fisicamente o attenua la configurazione in modo che nessun SSID fuoriesca dall'area autorizzata. Conferma con un survey.
2. Configura `HT-TARGET` con un'identità per l'esercitazione e ometti deliberatamente la validazione del certificato del dispositivo/posture per la prima esecuzione. Registra questa condizione come oggetto del test.
3. Connetti la prima interfaccia del pivot a `HT-NEIGHBOR` e la seconda interfaccia a `HT-TARGET`. **Non** abilitare un bridge generale; consenti solo il target service/port tramite un host firewall.
4. Dalla workstation, apri un tunnel autenticato verso il pivot e richiedi il target service attraverso di esso.
5. Registra il processo/creazione delle interfacce del pivot, entrambe le associazioni agli AP, l'evento RADIUS del target, il lease DHCP e l'indirizzo sorgente del target.
6. Chiedi al team di detection di ricostruire la catena senza la mappa del controller.
7. Abilita EAP-TLS/posture del managed device su `HT-TARGET`, rimuovi il certificato target approvato del pivot e ripeti. L'accesso dovrebbe fallire in fase di ammissione.
8. Ripeti usando un MAC randomizzato first-seen. Verifica che la decisione relativa a certificato/dispositivo continui a funzionare e che nessuna regola consideri il solo MAC come identità.

### Criteri di successo

- Il target inizialmente vede un client Wi-Fi locale anziché la workstation.
- La telemetria degli accessi identifica un pivot con percorsi simultanei verso il neighbor-control e la radio target.
- L'ammissione basata su certificato/dispositivo blocca la seconda esecuzione.
- Nessun pacchetto raggiunge una rete esterna al lab isolato.

## Lab 5: dead-drop resolver sequence

**Obiettivo:** rilevare un processo che legge un oggetto dall'aspetto legittimo, decodifica un puntatore e contatta immediatamente un secondo service.

### Preparazione
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
Il contenuto codificato è `http://ht-ddr-c2:80/`. Una detection efficace collega lo stesso processo/container di breve durata che legge `/profile.txt`, decodifica il contenuto e contatta `ht-ddr-c2` entro pochi secondi. Esegui l’hash e conserva la risposta dell’oggetto.

### Smantellamento
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: synthetic peel-chain e bridge graph

**Obiettivo:** esercitarsi nel value tracing senza asset, account o servizi reali.

### Crea e traccia il dataset
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
Gli analisti dovrebbero identificare il pattern di peel/change, trattare il bridge link come un'inferenza supportata separatamente, calcolare la differenza tra fee e valore e contrassegnare l'exchange come una richiesta di evidenze off-chain. Modificate un valore/tempo e documentate come cambia il livello di confidenza.

### Smantellamento
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: sensore passivo di segnalazione del traffico

**Obiettivo:** emulare la network signature di un implant passivo attivato da un magic value senza creare una shell, persistence o remote access. Il listener si associa solo al loopback e registra un evento benigno.
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
Risultato atteso: il traffico ordinario non produce alcun evento applicativo; lo produce solo il token designato. Cattura il traffico loopback durante l'esecuzione e verifica che un sensore di rete possa comunque visualizzare entrambi i datagrammi. Valuta quindi i controlli sull'host che rilevano un listener di pacchetti imprevisto e di lunga durata o un filtro di packet-capture. I passive implant reali di RedPenguin ispezionavano il traffico su un router e offrivano funzionalità pericolose; questo lab non fa deliberatamente nessuna delle due cose.

## Modello di report dell'esercizio

Per ogni lab, registra:

- autorizzazione e ambito isolato;
- ipotesi e tecnica ATT&CK;
- topologia e tabella degli observer;
- ora esatta di inizio/fine e hash della configurazione;
- eventi attesi per ogni sensore;
- eventi effettivamente osservati e lacune di conservazione;
- logica analitica, soglia e campione di falsi positivi;
- se il team target ha ricostruito il percorso;
- risultato del retest della mitigazione; e
- prove di teardown/recovery.

Un esercizio è incompleto finché il rilevamento non viene eseguito nuovamente dopo la mitigazione e ogni risorsa del lab non è stata rimossa.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — L'attacco del vicino più prossimo](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
