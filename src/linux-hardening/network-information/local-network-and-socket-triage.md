# Trijaža lokalne mreže i socket-a

Nakon dobijanja shell-a na Linux hostu, najkorisnije mrežne mete često nisu eksterno izložene. Servisi dostupni samo preko loopback-a, veth mreže, Unix socket-i, privremeni listener-i, packet capture-i i lokalna firewall pravila mogu otkriti credential-e ili lokalne attack surface-e.

Ova stranica se fokusira na praktične lokalne post-exploitation tehnike, a ne na opšti remote network pentesting.

## Enumeracija loopback-a i lokalnih servisa

Započnite identifikovanjem servisa koji osluškuju, njihovih bind adresa i procesa koji ih poseduje, kada dozvole to omogućavaju.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Važni obrasci:

- `127.0.0.1:<port>` ili `[::1]:<port>`: podrazumevano dostupno samo sa hosta.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: dostupno na svim IPv4 interfejsima, osim ako je filtrirano.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` ili `192.168.0.0/16` na `veth*`, `docker*`, `br-*`, `cni*`: verovatno container ili lokalne lab mreže.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix socketi u `/run`, `/var/run`, `/tmp` ili direktorijumima aplikacija: lokalne IPC površine.<sup>[[5]](#references)</sup>

Mapirajte lokalne portove pomoću laganih proba.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Koristite `nmap` lokalno kada je dostupan.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Skriveni veth i subneti kontejnera

Kontejnerizovana ili laboratorijska okruženja često izlažu servise samo na bridge ili veth subnetu. Izlistajte interfejse i rute pre nego što pretpostavite da je servis nedostupan.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Pronađite verovatne lokalne podmreže.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Pažljivo ispitajte otkrivenu podmrežu.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Tehnika je korisna kada su web panel, debug endpoint ili pomoćni servis skriveni od eksternih skeniranja, ali dostupni sa kompromitovanog hosta ili iz mreže kontejnera.

## Local Pivot With socat or SSH

Ako je servis vezan za loopback, izložite ga kroz dozvoljeni kanal umesto da menjate sam servis.

Prosledite lokalni HTTP servis dostupan samo na lokalnom interfejsu pomoću SSH-a.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Povežite lokalni port pomoću `socat` kada već imate pristup shell-u.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Prosledite Unix socket na TCP radi lokalnog testiranja.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Ovo samo po sebi ne iskorišćava ništa. Čini lokalno dostupnu površinu dostupnom vašim alatima, tako da možete da komunicirate s njom kao sa uobičajenom uslugom.

## Banner Grabbing i jednostavni protokoli

Nije svaka usluga HTTP. Mnoge lokalne usluge otkrivaju dovoljno informacija kroz banner ili protokol u jednom redu.

Osnovne probe.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
HTTP provera bez browsera.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Za TLS.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Cilj je identifikovati protokol, šemu autentifikacije, verziju i da li servis veruje lokalnim klijentima.

## Hvatanje Loopback saobraćaja

Lokalni saobraćaj može otkriti zaglavlja, bearer tokene, Basic Auth akreditive ili tajne specifične za aplikaciju.<sup>[[17]](#references)[[25]](#references)</sup> Snimajte saobraćaj samo u autorizovanim okruženjima.

Snimite loopback HTTP saobraćaj.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Snimite određenu lokalnu uslugu.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Dekodirajte Basic Auth iz presretnutog ili zabeleženog header-a.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Korisni stringovi koje treba potražiti u tekstualnim zapisima:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Ako možete da kontrolišete okruženje klijentskog procesa u laboratoriji, `SSLKEYLOGFILE` može omogućiti dešifrovanje TLS sesija u Wireshark-u ili kompatibilnim alatima.<sup>[[19]](#references)[[20]](#references)</sup> Ovo je korisno za razumevanje lokalnog HTTPS saobraćaja bez napadanja samog TLS-a.

Pokrenite klijenta sa omogućenim beleženjem ključeva.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Istovremeno presretite saobraćaj.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Zatim učitajte `/tmp/tls.pcap` i `/tmp/sslkeys.log` u Wireshark. Ovo funkcioniše samo kada client library podržava NSS-style key logging i kada možete da podesite environment pre uspostavljanja konekcije.<sup>[[20]](#references)[[21]](#references)</sup>

## Interakcija sa Unix socketima i Command Injection

Unix socketi su lokalne IPC krajnje tačke.<sup>[[5]](#references)</sup> Oni mogu izložiti HTTP API-je, custom protokole ili nebezbedne command handlere.<sup>[[12]](#references)[[14]](#references)</sup>

Pronađite sockete.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interagujte sa HTTP-om preko Unix socket-a.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interagujte sa raw socketom.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Ako se ulaz iz socket-a pod kontrolom korisnika prosledi shell-u ili privilegovanom pomoćnom programu, može doći do command injection-a.<sup>[[26]](#references)</sup> Fokusirani primer pogledajte u [Socket Command Injection](socket-command-injection.md).

## Pregled nftables-a i autorizovane izmene pravila

Lokalna firewall pravila mogu objasniti zašto je servis lokalno vidljiv, ali je blokiran sa udaljene strane, ili zašto se čini da je port visokog broja nedostupan sa jednog interfejsa.<sup>[[22]](#references)</sup>

Pregledajte pravila.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Potražite drop-ove koji utiču na ciljni port.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
U ovlašćenoj laboratoriji uklonite određeno pravilo blokiranja pomoću handle-a.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Prednost dajte brisanju tačnog handle-a u odnosu na pražnjenje celih tabela. Tehnika je da identifikujete precizan filter koji uzrokuje ponašanje i promenite samo to pravilo.<sup>[[22]](#references)</sup>

## Brzi tok rada
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Dajte prioritet servisima koji su dostupni samo lokalno, pokreću se sa privilegovanijim korisnikom, izlažu admin/debug funkcije ili veruju klijentima iz loopback/container-network okruženja.

## References

- [1] [ss(8) — Linux priručnik](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux priručnik](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux priručnik](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Arhitektura adresiranja IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux priručnik](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Preusmeravanja (Bash referentni priručnik)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout invocation (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Tehnike skeniranja portova (Nmap referentni vodič)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Otkrivanje hostova (Nmap referentni vodič)](https://nmap.org/book/man-host-discovery.html)
- [10] [Specifikacija portova i redosled skeniranja (Nmap referentni vodič)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux priručnik](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux priručnik](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD priručnik](https://man.openbsd.org/nc.1)
- [14] [curl alat komandne linije — priručnik](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL dokumentacija](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux priručnik](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 'Basic' HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 invocation (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL dokumentacija](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark korisnički vodič](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables priručnik](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Dodela adresa za privatne Internet mreže (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux priručnik](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Nepravilna neutralizacija posebnih elemenata korišćenih u OS komandi](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
