# Triage lokalne mreže i socket-a

{{#include ../../banners/hacktricks-training.md}}

Nakon dobijanja shell-a na Linux hostu, najkorisnije mrežne mete često nisu eksterno izložene. Servisi dostupni samo preko loopback-a, veth mreže, Unix socket-i, privremeni listener-i, packet capture-i i lokalna firewall pravila mogu otkriti credentials ili lokalne attack surface-e.

Ova stranica se fokusira na praktične lokalne post-exploitation tehnike, a ne na opšti remote network pentesting.

## Enumeracija loopback-a i lokalnih servisa

Započnite identifikovanjem listening servisa, njihovih bind adresa i procesa koji ih poseduje, kada dozvole to omogućavaju:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Važni obrasci:

- `127.0.0.1:<port>` ili `[::1]:<port>`: podrazumevano dostupno samo sa hosta.
- `0.0.0.0:<port>`: dostupno na svim IPv4 interfejsima, osim ako nije filtrirano.
- `172.x`, `10.x` ili `192.168.x` na `veth*`, `docker*`, `br-*`, `cni*`: verovatno kontejnerske ili lokalne lab mreže.
- Unix socketi u `/run`, `/var/run`, `/tmp` ili direktorijumima aplikacija: lokalne IPC površine.

Mapirajte lokalne portove pomoću laganih provera:
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
## Skrivene veth i podmreže kontejnera

Kontejnerizovana ili laboratorijska okruženja često izlažu servise samo na bridge ili veth podmreži. Pre nego što pretpostavite da servis nije dostupan, izlistajte interfejse i rute:
```bash
ip -br addr
ip route
ip neigh
```
Pronađi verovatne lokalne podmreže:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Pažljivo ispitajte otkriveni subnet:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Tehnika je korisna kada su web panel, debug endpoint ili pomoćni servis skriveni od eksternih skeniranja, ali dostupni sa kompromitovanog hosta ili iz mreže containera.

## Lokalni Pivot sa socat ili SSH

Ako je servis vezan za loopback, izložite ga kroz dozvoljeni kanal umesto da menjate sam servis.

Prosledite lokalni HTTP servis dostupan samo na lokalnom sistemu pomoću SSH-a:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Premostite lokalni port pomoću `socat` kada već imate pristup shell-u:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Prosledite Unix socket na TCP radi lokalnog testiranja:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Ovo samo po sebi ne iskorišćava ništa. Omogućava da lokalno dostupna površina bude dostupna vašim alatima, tako da možete da komunicirate s njom kao sa uobičajenom uslugom.

## Banner Grabbing i jednostavni protokoli

Nije svaka usluga HTTP. Mnoge lokalne usluge otkrivaju dovoljno informacija kroz banner ili protokol u jednoj liniji.

Osnovne provere:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
HTTP provera bez pregledača:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Za TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Cilj je identifikovati protokol, šemu autentifikacije, verziju i da li servis veruje lokalnim klijentima.

## Hvatanje Loopback saobraćaja

Lokalni saobraćaj može otkriti zaglavlja, bearer tokene, Basic Auth akreditive ili tajne specifične za aplikaciju. Hvatajte saobraćaj samo u autorizovanim okruženjima.

Uhvatite loopback HTTP saobraćaj:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Presretanje određene lokalne usluge:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Dekodirajte Basic Auth iz uhvaćenog ili zabeleženog header-a:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Korisni stringovi koje treba potražiti u tekstualnim zapisima:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Ako možete da kontrolišete okruženje client procesa u labu, `SSLKEYLOGFILE` može učiniti TLS sesije dešifrujućim u Wireshark-u ili kompatibilnim alatima. Ovo je korisno za razumevanje lokalnog HTTPS saobraćaja bez napadanja samog TLS-a.

Pokrenite client sa omogućenim key logging-om:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Istovremeno uhvatite saobraćaj:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Zatim učitajte `/tmp/tls.pcap` i `/tmp/sslkeys.log` u Wireshark. Ovo funkcioniše samo kada client library podržava NSS-style key logging i kada možete podesiti environment pre uspostavljanja konekcije.

## Unix Socket Interaction i Command Injection

Unix socketi su lokalne IPC krajnje tačke. Mogu izložiti HTTP API-je, prilagođene protokole ili nebezbedne command handlere.

Pronađite sockete:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interakcija sa HTTP-om preko Unix socketa:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interagujte sa raw socket-om:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Ako se socket input kojim upravlja korisnik prosledi shell-u ili privileged helper-u, može doći do command injection-a. Za fokusiran primer pogledajte [Socket Command Injection](socket-command-injection.md).

## Pregled nftables pravila i autorizovane izmene pravila

Lokalna firewall pravila mogu objasniti zašto je servis lokalno vidljiv, ali je blokiran sa udaljene strane, ili zašto se čini da je port sa visokim brojem nedostupan sa jednog interfejsa.

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
U ovlašćenom labu, uklonite određeno pravilo za blokiranje pomoću handle-a:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Prednost dajte brisanju tačnog handle-a u odnosu na pražnjenje celih tabela. Tehnika podrazumeva identifikovanje preciznog filtera koji uzrokuje ponašanje i menjanje samo tog pravila.

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
Prioritet dajte servisima koji su dostupni samo lokalno, pokreću se kao privilegovaniji korisnik, izlažu admin/debug funkcije ili veruju klijentima sa loopback/container mreže.

{{#include ../../banners/hacktricks-training.md}}
