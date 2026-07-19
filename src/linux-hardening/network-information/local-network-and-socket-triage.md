# Triage della rete locale e dei socket

{{#include ../../banners/hacktricks-training.md}}

Dopo aver ottenuto una shell su un host Linux, i target di rete più utili spesso non sono esposti esternamente. I servizi accessibili solo tramite loopback, le reti veth, i socket Unix, i listener temporanei, le catture di pacchetti e le regole del firewall locale possono esporre credenziali o superfici di attacco accessibili solo localmente.

Questa pagina si concentra sulle tecniche pratiche di post-exploitation locale, non sul pentesting generale di reti remote.

## Enumerazione di loopback e servizi locali

Inizia identificando i servizi in ascolto, i relativi indirizzi di bind e il processo proprietario, quando i permessi lo consentono:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Pattern importanti:

- `127.0.0.1:<port>` o `[::1]:<port>`: raggiungibili solo dall'host per impostazione predefinita.
- `0.0.0.0:<port>`: raggiungibili su tutte le interfacce IPv4, salvo filtri.
- `172.x`, `10.x` o `192.168.x` su `veth*`, `docker*`, `br-*`, `cni*`: probabilmente reti di container o laboratori locali.
- Socket Unix in `/run`, `/var/run`, `/tmp` o nelle directory delle applicazioni: superfici IPC locali.

Mappa le porte locali con probe leggere:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Usa `nmap` localmente quando disponibile:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## veth e subnet dei container

Gli ambienti containerizzati o di laboratorio espongono spesso i servizi solo su una subnet bridge o veth. Enumera le interfacce e le route prima di presumere che un servizio sia irraggiungibile:
```bash
ip -br addr
ip route
ip neigh
```
Individua le probabili subnet locali:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Esegui il probing su una subnet scoperta con attenzione:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
La tecnica è utile quando un pannello web, un endpoint di debug o un servizio helper è nascosto dalle scansioni esterne, ma è raggiungibile dall'host compromesso o dalla rete del container.

## Pivot locale con socat o SSH

Se un servizio è associato all'interfaccia loopback, esponilo tramite un canale consentito invece di modificare il servizio stesso.

Inoltra un servizio HTTP accessibile solo localmente con SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Collega una porta locale con `socat` quando hai già accesso alla shell:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Inoltra un socket Unix a TCP per i test locali:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Questo, da solo, non sfrutta nulla. Rende una superficie accessibile solo localmente raggiungibile dai tuoi strumenti, così puoi interagirvi come con un servizio normale.

## Banner Grabbing e protocolli semplici

Non tutti i servizi usano HTTP. Molti servizi locali fanno leak di informazioni sufficienti tramite un banner o un protocollo a una riga.

Probe di base:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Controllo HTTP senza un browser:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Per TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
L'obiettivo è identificare il protocollo, lo schema di autenticazione, la versione e se il servizio considera affidabili i client locali.

## Cattura del traffico di loopback

Il traffico locale può esporre header, bearer token, credenziali Basic Auth o secret specifici dell'applicazione. Esegui la cattura solo in ambienti autorizzati.

Cattura il traffico HTTP di loopback:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Catturare un servizio locale specifico:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Decodifica la Basic Auth da un header catturato o registrato:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Stringhe utili da cercare nelle catture di testo:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Se puoi controllare l'ambiente del processo client in un laboratorio, `SSLKEYLOGFILE` può rendere le sessioni TLS decifrabili in Wireshark o strumenti compatibili. Questo è utile per comprendere il traffico HTTPS locale senza attaccare direttamente TLS.

Esegui un client con il key logging abilitato:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Cattura il traffico allo stesso tempo:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Quindi carica `/tmp/tls.pcap` e `/tmp/sslkeys.log` in Wireshark. Funziona solo quando la client library supporta il key logging in stile NSS e puoi impostare l'ambiente prima che venga effettuata la connessione.

## Interazione con Unix Socket e Command Injection

I Unix socket sono endpoint IPC locali. Possono esporre API HTTP, protocolli personalizzati o gestori di comandi non sicuri.

Trova i socket:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interagire con HTTP tramite un socket Unix:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interagire con un raw socket:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Se un input socket controllato dall'utente viene passato a una shell o a un helper privilegiato, può trasformarsi in command injection. Per un esempio mirato, consulta [Socket Command Injection](socket-command-injection.md).

## Revisione di nftables e modifiche autorizzate alle regole

Le regole del firewall locale possono spiegare perché un servizio è visibile localmente ma bloccato da remoto, oppure perché una porta alta risulta irraggiungibile da un'interfaccia.

Esamina le regole:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Cerca i drop che interessano una porta di destinazione:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
In un laboratorio autorizzato, rimuovi una regola di blocco specifica tramite handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Preferisci eliminare l'handle esatto invece di svuotare intere tabelle. La tecnica consiste nell'identificare il filtro preciso che causa il comportamento e modificare solo quella regola.

## Workflow rapido
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Dai priorità ai servizi esclusivamente locali, eseguiti da un utente con privilegi maggiori, che espongono funzioni di amministrazione/debug o si fidano dei client della rete loopback/dei container.
{{#include ../../banners/hacktricks-training.md}}
