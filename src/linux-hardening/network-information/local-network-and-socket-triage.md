# Triage della rete locale e dei socket

{{#include ../../banners/hacktricks-training.md}}

Dopo aver ottenuto una shell su un host Linux, i target di rete più utili spesso non sono esposti all'esterno. I servizi accessibili solo tramite loopback, le reti veth, i socket Unix, i listener temporanei, le catture di pacchetti e le regole del firewall locale possono esporre credenziali o superfici di attacco accessibili solo localmente.

Questa pagina si concentra su tecniche pratiche di post-exploitation locale, non sul pentesting generale delle reti remote.

## Enumerazione dei servizi locali e di loopback

Inizia identificando i servizi in ascolto, i relativi indirizzi di bind e, se i permessi lo consentono, il processo proprietario.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Pattern importanti:

- `127.0.0.1:<port>` o `[::1]:<port>`: per impostazione predefinita, raggiungibile solo dall'host.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: raggiungibile su tutte le interfacce IPv4, salvo filtri.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` o `192.168.0.0/16` su `veth*`, `docker*`, `br-*`, `cni*`: probabilmente reti di container o di lab locale.<sup>[[23]](#references)[[24]](#references)</sup>
- Socket Unix in `/run`, `/var/run`, `/tmp` o nelle directory delle applicazioni: superfici IPC locali.<sup>[[5]](#references)</sup>

Per il problema storico di parsing dei socket di [snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), esamina il daemon in esecuzione, il relativo socket API locale e la versione del pacchetto o della snap installata, verificando che includa la correzione per quella distribuzione. Il bug riguardava la validazione, da parte di snapd, dell'indirizzo socket di un peer, non `snap-confine`; la presenza di un file `snap-confine` set-user-ID o la sola stringa della versione upstream non bastano a stabilire l'esposizione. Ubuntu ha distribuito le correzioni con versioni del pacchetto specifiche per ogni release, e snapd potrebbe essere stato aggiornato tramite una snap indipendentemente dal pacchetto della distribuzione. Verifica la build effettivamente in esecuzione e la raggiungibilità del socket locale prima di valutare il confine dell'API con privilegi. L'enumerazione passiva non deve inviare richieste socket appositamente create né installare una snap.

Un listener loopback avviato tramite [`socat` con `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) può inoltrare l'input di un client locale a un programma separato. Prima di considerare un servizio personalizzato di proprietà di root come una pista per l'escalation dei privilegi, correla il comando del listener, il percorso dell'eseguibile, l'identità effettiva del processo figlio, la raggiungibilità locale e l'autenticazione. Una vulnerabilità di memory safety o un percorso non sicuro dall'input al comando richiede prove relative al binario e alla build specifici; il numero di porta, il processo `socat` o la proprietà root, da soli, non bastano a dimostrarla. L'enumerazione passiva deve limitarsi ai metadati di processi, socket e file, senza inviare input al servizio.

Un master Salt locale può essere in ascolto sulle porte TCP 4505 e 4506, anche su loopback o su una porta dell'host pubblicata da un container. Le [note di rilascio Salt 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) descrivono una vulnerabilità nell'accesso ai metodi senza autenticazione, CVE-2020-11651, corretta nelle versioni upstream 2019.2.4 e 3000.2. Prima di considerarlo una pista per l'escalation dei privilegi, correla il listener con il processo `salt-master` effettivamente in esecuzione, l'interfaccia raggiungibile, il pacchetto installato e le patch del vendor, nonché l'identità effettiva del container o dell'host; una porta o una versione upstream, da sole, non sono prove. Se il master è in esecuzione dentro un container, l'impatto su root dell'host riguarda un confine separato: verifica che in quel container sia montato e accessibile un socket API utilizzabile del runtime dell'host. Per determinare l'esposizione, l'enumerazione passiva non deve interrogare il server di richieste Salt né creare un container. Vedi la [documentazione Salt sulle porte](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) e il [triage dell'API del runtime](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

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

## Subnet veth e dei container nascosti

Gli ambienti containerizzati o di laboratorio spesso espongono i servizi solo su una subnet bridge o veth. Enumera le interfacce e le route prima di concludere che un servizio sia irraggiungibile.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Individua le probabili subnet locali.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Esamina attentamente una subnet individuata.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

La tecnica è utile quando un pannello web, un endpoint di debug o un servizio helper è nascosto alle scansioni esterne, ma raggiungibile dall'host compromesso o dalla rete del container.

Un servizio notebook in loopback può autenticarsi con un token di avvio stampato nell'output del processo. Se tale output viene reindirizzato a un log leggibile da un altro account locale, il token può superare il confine tra utenti e consentire l'esecuzione di codice nell'account del server notebook. Prima di considerare un percorso di log come una possibile via di escalation, verifica il proprietario del processo in ascolto, la destinazione e i permessi del log, la configurazione attuale del token e i controlli di accesso al notebook. Durante l'enumerazione passiva, elenca i metadati dei log; non stampare i token né connetterti al servizio solo per classificare l'host.

## Pivot locale con socat o SSH

Se un servizio è associato a loopback, esponilo tramite un canale consentito invece di modificare il servizio stesso.

Inoltra un servizio HTTP accessibile solo localmente tramite SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Collega una porta locale tramite `socat` quando hai già accesso alla shell.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Inoltra un socket Unix su TCP per i test locali.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Questo non sfrutta nulla di per sé. Rende raggiungibile dai tuoi strumenti una superficie accessibile solo localmente, così puoi interagirci come con un normale servizio.

## Banner Grabbing e protocolli semplici

Non tutti i servizi usano HTTP. Molti servizi locali forniscono informazioni sufficienti tramite un banner o un protocollo a una riga.

Probe di base.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

Controllo HTTP senza un browser.<sup>[[13]](#references)[[14]](#references)</sup>

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

Per un listener aiohttp, verifica la configurazione delle route statiche e la versione. CVE-2024-23334 riguarda aiohttp prima della versione 3.9.2 quando una route statica abilita `follow_symlinks=True`: le richieste a quella route possono leggere file al di fuori della directory root statica. Se il servizio viene eseguito come root, potrebbe esporre file leggibili da root, a condizione che la route sia raggiungibile. Un banner della versione o un bind su loopback, da soli, non dimostrano che la configurazione sia vulnerabile o che i file siano accessibili.<sup>[[27]](#references)</sup>

## Acquisizione del traffico loopback

Il traffico locale può esporre header, bearer token, credenziali Basic Auth o segreti specifici dell'applicazione.<sup>[[17]](#references)[[25]](#references)</sup> Acquisisci traffico solo in ambienti autorizzati.

Acquisisci il traffico HTTP loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Cattura un servizio locale specifico.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Decodifica Basic Auth da un header acquisito o registrato.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Stringhe utili da cercare nelle acquisizioni di testo:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Registrazione delle chiavi TLS

Se in un lab puoi controllare l’ambiente del processo client, `SSLKEYLOGFILE` può consentire di decifrare le sessioni TLS in Wireshark o con strumenti compatibili.<sup>[[19]](#references)[[20]](#references)</sup> È utile per comprendere il traffico HTTPS locale senza attaccare TLS direttamente.

Avvia un client con la registrazione delle chiavi abilitata.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Cattura il traffico contemporaneamente.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Quindi carica `/tmp/tls.pcap` e `/tmp/sslkeys.log` in Wireshark. Funziona solo se la libreria client supporta il logging delle chiavi in stile NSS e puoi impostare l'ambiente prima di stabilire la connessione.<sup>[[20]](#references)[[21]](#references)</sup>

## Interazione con i socket Unix e Command Injection

I socket Unix sono endpoint IPC locali.<sup>[[5]](#references)</sup> Possono esporre API HTTP, protocolli personalizzati o handler di comandi non sicuri.<sup>[[12]](#references)[[14]](#references)</sup>

Un socket di proprietà di root con permessi di scrittura per il gruppo costituisce un confine di autorizzazione, ma non è di per sé una vulnerabilità. Confronta il gruppo e i permessi con l'account corrente, identifica il processo in ascolto e verifica quali dati accetta dai client prima di valutare il rischio. In particolare, un servizio privilegiato che esegue PHP inviato dal client può oltrepassare un secondo confine se si fida anche del percorso `php.ini` scelto dal chiamante o gli consente di modificare `disable_functions` o `open_basedir`; controlla la configurazione effettiva e il percorso di convalida del servizio. La [guida alla configurazione di PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) spiega queste direttive. I soli metadati del socket non dimostrano l'esecuzione di codice.

Individua i socket.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Interagire con HTTP tramite un socket Unix.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Interagisci con un socket raw.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Se l'input del socket controllato dall'utente viene passato a una shell o a un helper con privilegi, può causare command injection.<sup>[[26]](#references)</sup> Per un esempio mirato, vedi [Socket Command Injection](socket-command-injection.md).

## Revisione di nftables e modifiche autorizzate alle regole

Le regole del firewall locale possono spiegare perché un servizio è visibile localmente ma bloccato da remoto, oppure perché una porta alta risulta irraggiungibile da un'interfaccia.<sup>[[22]](#references)</sup>

Esamina le regole.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Cerca le regole di drop che interessano una porta di destinazione.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

In un laboratorio autorizzato, rimuovi una regola di blocco specifica tramite handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Preferisci eliminare l'handle esatto invece di svuotare intere tabelle. La tecnica consiste nell'identificare il filtro preciso che causa il comportamento e modificare solo quella regola.<sup>[[22]](#references)</sup>

## Flusso di lavoro rapido

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Dai priorità ai servizi accessibili solo localmente, eseguiti da un utente con privilegi più elevati, che espongono funzioni di amministrazione/debug o si fidano dei client sulla loopback/rete dei container.

## References

- [1] [ss(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — pagina del manuale Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Architettura di indirizzamento IP versione 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — pagina del manuale Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Reindirizzamenti (Manuale di riferimento di Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Invocazione di timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Tecniche di scansione delle porte (Guida di riferimento di Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Rilevamento degli host (Guida di riferimento di Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Specifiche delle porte e ordine di scansione (Guida di riferimento di Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — pagina del manuale Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — pagina del manuale OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Manuale dello strumento a riga di comando curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Documentazione di OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Schema di autenticazione HTTP «Basic»](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Invocazione di base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Documentazione di OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki di Wireshark](https://wiki.wireshark.org/tls)
- [21] [Guida utente di Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Manuale di nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Allocazione degli indirizzi per reti private (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Il framework di autorizzazione OAuth 2.0: uso dei token bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Neutralizzazione impropria di elementi speciali usati in un comando del sistema operativo](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Avviso dei manutentori di aiohttp: attraversamento dei percorsi statici con follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
{{#include ../../banners/hacktricks-training.md}}
