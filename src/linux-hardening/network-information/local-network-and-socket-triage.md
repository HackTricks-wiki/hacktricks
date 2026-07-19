# Lokalna mreža i trijaža socket-a

{{#include ../../banners/hacktricks-training.md}}

Nakon dobijanja shell-a na Linux hostu, najkorisnije mrežne mete često nisu eksterno izložene. Servisi dostupni samo preko loopback-a, veth mreže, Unix socket-i, privremeni listener-i, packet capture-i i lokalna firewall pravila mogu otkriti credentials ili lokalne attack surface-e.

Ova stranica se fokusira na praktične lokalne post-exploitation tehnike, a ne na opšti remote network pentesting.

## Enumeracija loopback-a i lokalnih servisa

Započnite identifikovanjem servisa koji osluškuju, njihovih bind adresa i procesa koji ih poseduje, kada dozvole to omogućavaju:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Važni obrasci:

- `127.0.0.1:<port>` ili `[::1]:<port>`: podrazumevano dostupno samo sa hosta.
- `0.0.0.0:<port>`: dostupno na svim IPv4 interfejsima osim ako nije filtrirano.
- `172.x`, `10.x` ili `192.168.x` na `veth*`, `docker*`, `br-*`, `cni*`: verovatno kontejnerske ili lokalne lab mreže.
- Unix socketi u `/run`, `/var/run`, `/tmp` ili direktorijumima aplikacija: lokalne IPC površine.

Mapirajte lokalne portove laganim sondama:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Koristite `nmap` lokalno kada je dostupan:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Skriveni veth i podmreže kontejnera

Kontejnerizovana ili lab okruženja često izlažu servise samo na bridge ili veth podmreži. Enumerišite interfejse i rute pre nego što pretpostavite da je servis nedostupan:
```bash
ip -br addr
ip route
ip neigh
```
Pronađite verovatne lokalne podmreže:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Pažljivo ispitajte otkriveni subnet:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Tehnika je korisna kada su web panel, debug endpoint ili pomoćni servis skriveni od eksternih skeniranja, ali dostupni sa kompromitovanog hosta ili iz mreže kontejnera.

## Lokalni pivot pomoću socat ili SSH

Ako je servis vezan za loopback, izložite ga kroz dozvoljeni kanal umesto da menjate sam servis.

Prosledite lokalni HTTP servis dostupan samo na lokalnom računaru pomoću SSH-a:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Preusmerite lokalni port pomoću `socat` kada već imate shell pristup:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Prosledi Unix socket na TCP za lokalno testiranje:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Ovo samo po sebi ne iskorišćava ništa. Čini lokalno dostupnu površinu dostupnom vašim alatima, tako da možete da komunicirate s njom kao sa uobičajenom uslugom.

## Banner Grabbing and Simple Protocols

Nije svaka usluga HTTP. Mnoge lokalne usluge leak-uju dovoljno informacija kroz banner ili protokol od jedne linije.

Osnovne provere:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
HTTP provera bez browsera:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Za TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Cilj je da se identifikuju protokol, šema autentikacije, verzija i da li servis veruje lokalnim klijentima.

## Hvatanje Loopback saobraćaja

Lokalni saobraćaj može otkriti zaglavlja, bearer tokene, Basic Auth akreditive ili tajne specifične za aplikaciju. Hvatajte saobraćaj samo u ovlašćenim okruženjima.

Hvatanje loopback HTTP saobraćaja:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Presretanje određene lokalne usluge:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Dekodirajte Basic Auth iz uhvaćenog ili evidentiranog zaglavlja:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Korisni stringovi koje treba potražiti u tekstualnim zapisima:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Ako možete da kontrolišete okruženje klijentskog procesa u laboratoriji, `SSLKEYLOGFILE` može učiniti TLS sesije dešifrujućim u Wireshark-u ili kompatibilnim alatima. Ovo je korisno za razumevanje lokalnog HTTPS saobraćaja bez napada na sam TLS.

Pokrenite klijenta sa omogućenim key logging-om:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Istovremeno snimajte saobraćaj:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Zatim učitajte `/tmp/tls.pcap` i `/tmp/sslkeys.log` u Wireshark. Ovo funkcioniše samo kada client library podržava NSS-style key logging i kada možete podesiti environment pre uspostavljanja konekcije.

## Interakcija sa Unix socketima i Command Injection

Unix socketi su lokalne IPC krajnje tačke. Mogu izložiti HTTP API-je, custom protokole ili unsafe command handlere.

Pronađite sockete:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interagujte sa HTTP-om preko Unix socket-a:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interagujte sa raw socket-om:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Ako se ulaz sa socket-a kojim upravlja korisnik prosledi shell-u ili privilegovanom pomoćniku, to može dovesti do command injection-a. Za fokusirani primer pogledajte [Socket Command Injection](socket-command-injection.md).

## Pregled nftables pravila i ovlašćene izmene pravila

Lokalna firewall pravila mogu objasniti zašto je servis lokalno vidljiv, ali je blokiran sa udaljene strane, ili zašto se visoki port čini nedostupnim sa jednog interfejsa.

Pregledajte pravila:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Potražite drop-ove koji utiču na ciljni port:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
U ovlašćenoj laboratoriji uklonite određeno pravilo blokiranja pomoću njegovog handle-a:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Prednost dajte brisanju tačnog handle-a umesto pražnjenja čitavih tabela. Tehnika podrazumeva identifikovanje preciznog filtera koji izaziva takvo ponašanje i izmenu samo tog pravila.

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
Dajte prioritet servisima koji su dostupni samo lokalno, pokreću se kao privilegovaniji korisnik, izlažu admin/debug funkcije ili veruju klijentima sa loopback/container-network mreže.
{{#include ../../banners/hacktricks-training.md}}
