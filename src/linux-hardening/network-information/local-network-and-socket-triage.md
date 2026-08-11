# Triage della rete locale e dei socket

{{#include ../../banners/hacktricks-training.md}}

Dopo aver ottenuto una shell su un host Linux, i target di rete più utili spesso non sono esposti esternamente. I servizi accessibili solo tramite loopback, le reti veth, i socket Unix, i listener temporanei, le catture di pacchetti e le regole del firewall locale possono esporre credenziali o superfici di attacco accessibili solo localmente.

Questa pagina si concentra sulle tecniche pratiche di post-exploitation locale, non sul pentesting generale delle reti remote.

## Enumerazione di loopback e dei servizi locali

Inizia identificando i servizi in ascolto, i relativi indirizzi di bind e il processo proprietario, quando i permessi lo consentono.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Pattern importanti:

- `127.0.0.1:<port>` o `[::1]:<port>`: raggiungibile solo dall'host per impostazione predefinita.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: raggiungibile su tutte le interfacce IPv4, salvo filtraggio.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` o `192.168.0.0/16` su `veth*`, `docker*`, `br-*`, `cni*`: probabilmente reti di container o di laboratorio locali.<sup>[[23]](#references)[[24]](#references)</sup>
- Socket Unix in `/run`, `/var/run`, `/tmp` o nelle directory delle applicazioni: superfici IPC locali.<sup>[[5]](#references)</sup>

Mappa le porte locali con probe leggeri.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Usa `nmap` localmente quando disponibile.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## veth e subnet dei container nascosti

Gli ambienti containerizzati o di laboratorio spesso espongono i servizi solo su una subnet bridge o veth. Enumera le interfacce e le route prima di presumere che un servizio sia irraggiungibile.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Individua le probabili subnet locali.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Sonda con cautela la subnet scoperta.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
La tecnica è utile quando un pannello web, un endpoint di debug o un servizio ausiliario è nascosto dalle scansioni esterne, ma raggiungibile dall'host compromesso o dalla rete del container.

## Local Pivot With socat or SSH

Se un servizio è associato al loopback, esponilo tramite un canale consentito invece di modificare il servizio stesso.

Inoltra un servizio HTTP accessibile solo localmente con SSH.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Collega una porta locale con `socat` quando hai già accesso alla shell.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Inoltra un socket Unix a TCP per i test locali.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Questo non sfrutta nulla di per sé. Rende raggiungibile una superficie accessibile solo localmente dai tuoi strumenti, così puoi interagirci come con un servizio normale.

## Banner Grabbing e protocolli semplici

Non tutti i servizi sono HTTP. Molti servizi locali fanno leak di informazioni sufficienti tramite un banner o un protocollo a una riga.

Probe di base.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Verifica HTTP senza un browser.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Per TLS.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
L'obiettivo è identificare il protocollo, lo schema di autenticazione, la versione e se il servizio si fida dei client locali.

## Cattura del traffico Loopback

Il traffico locale può esporre header, bearer token, credenziali Basic Auth o segreti specifici dell'applicazione.<sup>[[17]](#references)[[25]](#references)</sup> Esegui la cattura solo in ambienti autorizzati.

Cattura il traffico HTTP loopback.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Cattura un servizio locale specifico.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Decodifica l'autenticazione Basic da un header acquisito o registrato.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Stringhe utili da cercare nelle acquisizioni di testo:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Se puoi controllare l'ambiente del processo client in un lab, `SSLKEYLOGFILE` può rendere le sessioni TLS decifrabili in Wireshark o con strumenti compatibili.<sup>[[19]](#references)[[20]](#references)</sup> È utile per comprendere il traffico HTTPS locale senza attaccare direttamente TLS.

Esegui un client con il key logging abilitato.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Cattura il traffico contemporaneamente.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Quindi carica `/tmp/tls.pcap` e `/tmp/sslkeys.log` in Wireshark. Questo funziona solo quando la libreria client supporta il key logging in stile NSS e puoi impostare l'ambiente prima che venga effettuata la connessione.<sup>[[20]](#references)[[21]](#references)</sup>

## Interazione con socket Unix e Command Injection

I socket Unix sono endpoint IPC locali.<sup>[[5]](#references)</sup> Possono esporre API HTTP, protocolli personalizzati o gestori di comandi non sicuri.<sup>[[12]](#references)[[14]](#references)</sup>

Trova i socket.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interagire con HTTP tramite un socket Unix.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interagire con un raw socket.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Se l'input del socket controllato dall'utente viene passato a una shell o a un helper privilegiato, può diventare command injection.<sup>[[26]](#references)</sup> Per un esempio mirato, vedere [Socket Command Injection](socket-command-injection.md).

## Revisione di nftables e modifiche autorizzate alle regole

Le regole del firewall locale possono spiegare perché un servizio è visibile localmente ma bloccato da remoto, oppure perché una porta alta risulta irraggiungibile da un'interfaccia.<sup>[[22]](#references)</sup>

Esaminare le regole.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Cerca i drop che riguardano una porta di destinazione.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
In un laboratorio autorizzato, rimuovi una regola di blocco specifica tramite handle.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Preferisci eliminare l’handle esatto invece di svuotare intere tabelle. La tecnica consiste nell’identificare il filtro preciso che causa il comportamento e modificare solo quella regola.<sup>[[22]](#references)</sup>

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
Dai priorità ai servizi accessibili solo localmente, eseguiti da un utente con privilegi più elevati, che espongono funzioni di amministrazione/debug o che si fidano dei client loopback/container-network.

## References

- [1] [ss(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — pagina del manuale Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Architettura degli indirizzi IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — pagina del manuale Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirections (Manuale di riferimento di Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout invocation (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Tecniche di Port Scanning (Nmap Reference Guide)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host Discovery (Nmap Reference Guide)](https://nmap.org/book/man-host-discovery.html)
- [10] [Specifiche delle porte e ordine di scansione (Nmap Reference Guide)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — pagina del manuale Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — pagina del manuale OpenBSD](https://man.openbsd.org/nc.1)
- [14] [manuale dello strumento da riga di comando curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Documentazione di OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Lo schema di autenticazione HTTP 'Basic'](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 invocation (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Documentazione di OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki di Wireshark](https://wiki.wireshark.org/tls)
- [21] [Guida per l'utente di Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [manuale di nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Allocazione degli indirizzi per Internet privati (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Il framework di autorizzazione OAuth 2.0: utilizzo dei Bearer Token (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Neutralizzazione impropria degli elementi speciali utilizzati in un comando del sistema operativo](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
