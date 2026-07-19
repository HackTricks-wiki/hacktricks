# Triage della rete locale e dei socket

{{#include ../../banners/hacktricks-training.md}}

Dopo aver ottenuto una shell su un host Linux, i target di rete più utili spesso non sono esposti esternamente. I servizi accessibili solo tramite loopback, le reti veth, i socket Unix, i listener temporanei, le catture di pacchetti e le regole del firewall locale possono esporre credenziali o superfici di attacco accessibili solo localmente.

Questa pagina si concentra sulle tecniche pratiche di post-exploitation locale, non sul pentesting generale delle reti remote.

## Enumerazione dei servizi loopback e locali

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
- `172.x`, `10.x` o `192.168.x` su `veth*`, `docker*`, `br-*`, `cni*`: probabilmente reti di container o lab locali.
- Unix sockets in `/run`, `/var/run`, `/tmp` o nelle directory delle applicazioni: superfici IPC locali.

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
## veth nascosti e sottoreti dei container

Gli ambienti containerizzati o di laboratorio spesso espongono i servizi solo su una bridge o su una sottorete veth. Enumera le interfacce e le route prima di presumere che un servizio sia irraggiungibile:
```bash
ip -br addr
ip route
ip neigh
```
Individua le probabili subnet locali:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Esegui con cautela il probing di una subnet scoperta:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
La tecnica è utile quando un pannello web, un endpoint di debug o un servizio helper è nascosto dalle scansioni esterne, ma raggiungibile dall’host compromesso o dalla rete del container.

## Pivot locale con socat o SSH

Se un servizio è associato all’interfaccia di loopback, esponilo tramite un canale consentito invece di modificare il servizio stesso.

Inoltra un servizio HTTP accessibile solo localmente con SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Collegare una porta locale con `socat` quando si dispone già dell'accesso a una shell:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Inoltra un socket Unix a TCP per i test locali:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Questo, da solo, non sfrutta nulla. Rende una superficie accessibile solo localmente raggiungibile dai tuoi strumenti, così puoi interagirvi come con un normale servizio.

## Banner Grabbing e protocolli semplici

Non tutti i servizi sono HTTP. Molti servizi locali fanno leak di informazioni sufficienti tramite un banner o un protocollo a una riga.

Probe di base:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Verifica HTTP senza un browser:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Per TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
L'obiettivo è identificare il protocollo, lo schema di autenticazione, la versione e se il servizio si fida dei client locali.

## Acquisizione del traffico Loopback

Il traffico locale può esporre header, bearer token, credenziali Basic Auth o segreti specifici dell'applicazione. Esegui acquisizioni solo in ambienti autorizzati.

Acquisisci il traffico HTTP loopback:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Cattura un servizio locale specifico:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Decodifica l'autenticazione Basic da un header catturato o registrato:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Stringhe utili da cercare nelle catture di testo:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## Registrazione delle chiavi TLS

Se puoi controllare l'ambiente del processo client in un lab, `SSLKEYLOGFILE` può rendere le sessioni TLS decifrabili in Wireshark o strumenti compatibili. È utile per comprendere il traffico HTTPS locale senza attaccare direttamente TLS.

Esegui un client con il key logging abilitato:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Cattura il traffico contemporaneamente:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Quindi carica `/tmp/tls.pcap` e `/tmp/sslkeys.log` in Wireshark. Funziona solo quando la libreria client supporta il key logging in stile NSS e puoi impostare l'ambiente prima che venga effettuata la connessione.

## Interazione con socket Unix e command injection

I socket Unix sono endpoint IPC locali. Possono esporre API HTTP, protocolli personalizzati o gestori di comandi non sicuri.

Individua i socket:
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
Se l'input del socket controllato dall'utente viene passato a una shell o a un helper privilegiato, può trasformarsi in command injection. Per un esempio mirato, consulta [Socket Command Injection](socket-command-injection.md).

## Revisione di nftables e modifiche autorizzate alle regole

Le regole del firewall locale possono spiegare perché un servizio è visibile localmente ma bloccato da remoto, oppure perché una porta alta risulta irraggiungibile da un'interfaccia.

Esamina le regole:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Cerca i drops che interessano una porta target:
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
Dai priorità ai servizi accessibili solo localmente, eseguiti da un utente con privilegi più elevati, che espongono funzioni di amministrazione/debug o che considerano attendibili i client della rete loopback/dei container.
