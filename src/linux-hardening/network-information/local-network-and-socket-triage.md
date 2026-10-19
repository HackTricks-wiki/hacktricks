# Lokalna mreža i trijaža socket-a

{{#include ../../banners/hacktricks-training.md}}

Nakon što dobijete shell na Linux hostu, najkorisnije mrežne mete često nisu izložene spolja. Servisi dostupni samo preko Loopback interfejsa, veth mreže, Unix socket-i, privremeni listener-i, snimci mrežnih paketa i lokalna firewall pravila mogu otkriti kredencijale ili lokalne attack surface-ove.

Ova stranica se fokusira na praktične lokalne post-exploitation tehnike, a ne na opšti remote network pentesting.

## Enumeracija Loopback i lokalnih servisa

Počnite identifikovanjem servisa koji osluškuju, njihovih bind adresa i procesa koji ih poseduje, kada dozvole to omogućavaju.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Važni obrasci:

- `127.0.0.1:<port>` ili `[::1]:<port>`: podrazumevano dostupno samo sa hosta.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: dostupno na svim IPv4 interfejsima, osim ako nije filtrirano.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` ili `192.168.0.0/16` na interfejsima `veth*`, `docker*`, `br-*`, `cni*`: verovatno kontejnerske ili lokalne lab mreže.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix soketi u direktorijumima `/run`, `/var/run`, `/tmp` ili direktorijumima aplikacija: lokalne IPC površine.<sup>[[5]](#references)</sup>

Za istorijski problem parsiranja soketa u [snapd-u, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), proverite pokrenuti daemon, njegov lokalni API soket i instalirani paket ili snap reviziju u odnosu na ispravku za tu distribuciju. Greška je bila u snapd-ovoj validaciji adrese soketa klijenta, a ne u `snap-confine`; datoteka `snap-confine` sa set-user-ID bitom ili samo upstream string verzije ne mogu da potvrde izloženost. Ubuntu je isporučivao ispravke u verzijama paketa specifičnim za izdanje, a snapd je mogao nezavisno da se osveži iz snap-a, mimo paketa distribucije. Pre procene granice privilegovanog API-ja, potvrdite stvarnu pokrenutu verziju i dostupnost lokalnog soketa. Pasivno nabrajanje ne bi trebalo da šalje posebno oblikovan zahtev soketu niti da instalira snap.

Loopback listener pokrenut pomoću [`socat`-a sa `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) može da prosledi ulaz lokalnog klijenta zasebnom programu. Pre nego što prilagođenu uslugu u vlasništvu root-a tretirate kao trag za eskalaciju privilegija, povežite komandu listener-a, putanju izvršne datoteke, efektivni identitet podređenog procesa, lokalnu dostupnost i autentifikaciju. Greška bezbednosti memorije ili nebezbedna putanja od ulaza do komande zahtevaju dokaze iz konkretne binarne datoteke i verzije; sam broj porta, `socat` proces ili vlasnik root ne potvrđuju takav problem. Pasivno nabrajanje treba da se ograniči na metapodatke procesa, soketa i datoteka, bez slanja ulaza usluzi.

Lokalni Salt master može da osluškuje TCP portove 4505 i 4506, uključujući loopback ili host port objavljen iz kontejnera. [Napomene uz Salt izdanje 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) opisuju grešku u metodi za pristup bez autentifikacije, CVE-2020-11651, ispravljenu u upstream verzijama 2019.2.4 i 3000.2. Pre nego što ovo tretirate kao trag za eskalaciju privilegija, povežite listener sa stvarnim `salt-master` procesom, dostupnim interfejsom, instaliranim paketom i ispravkama dobavljača, kao i efektivnim identitetom kontejnera ili hosta; sam port ili upstream verzija nisu dokaz. Ako master radi unutar kontejnera, uticaj na root hosta predstavlja zasebnu granicu: potvrdite da je upotrebljiv socket API-ja runtime-a hosta montiran i dostupan iz tog kontejnera. Pasivno nabrajanje ne bi trebalo da šalje upite Salt request server-u niti da kreira kontejner radi procene izloženosti. Pogledajte [Salt-ovu dokumentaciju o portovima](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) i [triage API-ja runtime-a](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

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

## Skriveni veth i podmreže kontejnera

Kontejnerizovana ili laboratorijska okruženja često izlažu usluge samo na bridge ili veth podmreži. Popišite interfejse i rute pre nego što pretpostavite da je usluga nedostupna.<sup>[[2]](#references)</sup>

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

Tehnika je korisna kada je veb panel, debug endpoint ili pomoćni servis sakriven od spoljnih skeniranja, ali mu se može pristupiti sa kompromitovanog hosta ili mreže kontejnera.

## Notebook service tokeni preko granica korisnika

Lokalni notebook servis može da se autentifikuje tokenom za pokretanje ispisanim u izlazu procesa. Ako se taj izlaz preusmerava u log koji može da čita drugi lokalni nalog, token može preći granicu korisnika i omogućiti izvršavanje koda pod nalogom notebook servera. Pre nego što putanju do loga uzmete u obzir kao mogući pravac za eskalaciju, proverite vlasnika procesa koji sluša, odredište loga i dozvole, trenutnu konfiguraciju tokena i kontrole pristupa notebooku. Tokom pasivne enumeracije pregledajte metapodatke loga; nemojte ispisivati tokene niti se povezivati sa servisom samo da biste klasifikovali host.

Jupyter Lab servis takođe može da izloži svoj token u čitljivom `ExecStart` параметру systemd јединице или у командној линији покренутог процеса (`ps auxww`), уместо само у логовима при покретању. У наведеном примеру, `User=analyst` и `--ServerApp.token` открили су и приступни податак и налог иза слушача `127.0.0.1:8888`. Уз приступ хосту, токен и `ssh -L 8888:127.0.0.1:8888 user@host` омогућили су приступ Jupyter Lab Terminal-у као корисник тог сервиса. Заједно проверите ефективног корисника јединице, аргументе процеса, слушач и важење токена; везивање само за loopback није граница ауторизације.<sup>[[28]](#references)</sup>

## Локални pivot преко socat или SSH

Ако је сервис везан за loopback, изложите га преко дозвољеног канала уместо да мењате сам сервис.

Проследите HTTP сервис доступан само локално преко SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Prosledite lokalni port pomoću `socat` kada već imate shell pristup.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Prosledite Unix socket na TCP za lokalno testiranje.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Ovo samo po sebi ne iskorišćava ništa. Omogućava da površina dostupna samo lokalno postane dostupna vašim alatima, kako biste mogli da komunicirate s njom kao s običnom uslugom.

## Banner Grabbing i jednostavni protokoli

Nije svaka usluga HTTP. Mnoge lokalne usluge otkrivaju dovoljno informacija putem bannera ili jednolinijskog protokola.

Osnovne provere.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

HTTP provera bez pregledača.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Za TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Cilj je da se utvrde protokol, šema autentifikacije, verzija i da li servis veruje lokalnim klijentima.

Za aiohttp listener proverite konfiguraciju static-route-a, kao i njegovu verziju. CVE-2024-23334 utiče na aiohttp verzije pre 3.9.2 kada je za static route omogućeno `follow_symlinks=True`: zahtevi ka toj ruti mogu da čitaju datoteke izvan static root direktorijuma. Ako servis radi kao root, može da izloži datoteke koje root može da čita, pod uslovom da je ruta dostupna. Verzija prikazana u baneru ili bind na loopback adresu sami po sebi ne potvrđuju ranjivu konfiguraciju niti pristup datotekama.<sup>[[27]](#references)</sup>

## Hvatanje loopback saobraćaja

Lokalni saobraćaj može da otkrije zaglavlja, bearer tokene, Basic Auth akreditive ili tajne specifične za aplikaciju.<sup>[[17]](#references)[[25]](#references)</sup> Snimajte saobraćaj samo u ovlašćenim okruženjima.

Snimite loopback HTTP saobraćaj.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Snimite saobraćaj određene lokalne usluge.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Dekodirajte Basic Auth iz presretnutog ili zabeleženog zaglavlja.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Korisni nizovi koje treba tražiti u tekstualnim zapisima:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

Ako u laboratoriji možeš da kontrolišeš okruženje klijentskog procesa, `SSLKEYLOGFILE` može da omogući dešifrovanje TLS sesija u Wireshark-u ili kompatibilnim alatima.<sup>[[19]](#references)[[20]](#references)</sup> Ovo je korisno za razumevanje lokalnog HTTPS saobraćaja bez napada na sam TLS.

Pokreni klijent sa omogućenim evidentiranjem ključeva.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Istovremeno snimajte saobraćaj.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Zatim učitajte `/tmp/tls.pcap` i `/tmp/sslkeys.log` u Wireshark. Ovo funkcioniše samo ako klijentska biblioteka podržava NSS-style key logging i ako možete da podesite okruženje pre uspostavljanja veze.<sup>[[20]](#references)[[21]](#references)</sup>

## Interakcija sa Unix socket-ima i Command Injection

Unix socket-i su lokalne IPC krajnje tačke.<sup>[[5]](#references)</sup> Mogu da izlože HTTP API-je, prilagođene protokole ili nesigurne rukovaoce komandama.<sup>[[12]](#references)[[14]](#references)</sup>

Socket u vlasništvu root-a sa dozvolom za upis za grupu predstavlja granicu autorizacije, ali sam po sebi nije ranjivost. Uporedite njegovu grupu i režim dozvola sa trenutnim nalogom, utvrdite koji proces osluškuje i proverite šta taj proces prihvata od klijenata pre nego što procenite rizik. Konkretno, privilegovana usluga koja izvršava dostavljeni PHP može preći drugu granicu ako istovremeno veruje putanji do `php.ini` koju bira pozivalac ili mu dozvoljava da menja `disable_functions` ili `open_basedir`; proverite efektivnu konfiguraciju i putanju validacije usluge. [PHP configuration guide](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) objašnjava te direktive. Sami metapodaci socket-a ne potvrđuju izvršavanje koda.

Pronađite socket-e.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Komunicirajte sa HTTP-om preko Unix soketa.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Interakcija sa sirovim socket-om.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Ako se ulazna vrednost za socket koju kontroliše korisnik prosledi shell-u ili privilegovanom pomoćnom programu, to može dovesti do command injection-a.<sup>[[26]](#references)</sup> Za konkretan primer pogledajte [Socket Command Injection](socket-command-injection.md).

## Pregled nftables pravila i njihove dozvoljene izmene

Lokalna firewall pravila mogu objasniti zašto je servis vidljiv lokalno, ali blokiran sa udaljene lokacije, ili zašto se čini da je port visokog broja nedostupan sa jednog interfejsa.<sup>[[22]](#references)</sup>

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

U ovlašćenoj laboratoriji uklonite određeno pravilo za blokiranje pomoću handle-a.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Dajte prednost brisanju konkretnog handle-a umesto pražnjenju celih tabela. Tehnika je da identifikujete precizan filter koji izaziva ponašanje i promenite samo to pravilo.<sup>[[22]](#references)</sup>

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

Dajte prioritet servisima koji su dostupni samo lokalno, rade pod privilegovanijim korisnikom, izlažu administratorske/debug funkcije ili veruju klijentima sa loopback adrese/mreže kontejnera.

## References

- [1] [ss(8) — stranica Linux priručnika](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — stranica Linux priručnika](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — stranica Linux priručnika](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Arhitektura adresiranja IP verzije 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — stranica Linux priručnika](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Preusmeravanja (Bash referentni priručnik)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [poziv komande timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Tehnike skeniranja portova (Nmap referentni vodič)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Otkrivanje hostova (Nmap referentni vodič)](https://nmap.org/book/man-host-discovery.html)
- [10] [Navođenje portova i redosled skeniranja (Nmap referentni vodič)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — stranica Linux priručnika](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — stranica Linux priručnika](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — stranica OpenBSD priručnika](https://man.openbsd.org/nc.1)
- [14] [Priručnik za alat komandne linije curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL dokumentacija](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — stranica Linux priručnika](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: HTTP šema autentifikacije „Basic”](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [poziv komande base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL dokumentacija](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Korisnički vodič za Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [priručnik za nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Dodela adresa za privatne internet mreže (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — stranica Linux priručnika](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Okvir za autorizaciju OAuth 2.0: upotreba bearer tokena (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Nepravilna neutralizacija specijalnih elemenata korišćenih u OS komandi](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Obaveštenje održavaoca aiohttp-a: prolazak kroz direktorijume u statičkoj ruti uz follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — Jupyter token izložen preko systemd-a i argumenata procesa](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
