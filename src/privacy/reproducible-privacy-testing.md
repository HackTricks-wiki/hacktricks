# Testiranje privatnosti koje se može ponoviti

{{#include ../banners/hacktricks-training.md}}

Podešavanje privatnosti nije završeno kada se poveže. Završeno je tek kada je njegova deklarisana granica testirana tokom uobičajene upotrebe, u slučaju otkaza, oporavka i uklanjanja. Testirajte infrastrukturu čiji ste vlasnik ili za čiju ste proveru ovlašćeni; javni sajtovi za „leak test“ postaju još jedan posmatrač.

## Napravite malo autorizovano testno okruženje

Koristite tri uloge, po mogućstvu na odvojenim provajderima/mrežama:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Pre svakog testa zabeležite:

- ID testa, vreme početka/završetka u UTC-u, operatera i autorizaciju;
- endpoint/OS/verzije klijenta i hash konfiguracije;
- očekivana IPv4, IPv6, DNS, TLS, zapažanja o nalogu, plaćanju i fizičkom okruženju;
- koji logovi će biti pregledani i njihove satove/vremenske zone;
- pravilo prolaza/pada testa i vreme uklanjanja postavki.

Nikada nemojte prvo testirati osetljiv identitet. Koristite sintetički nalog i bezopasne, jedinstvene canary vrednosti u vlasništvu testera.

## Test mrežne putanje

### 1. Snimite početno stanje

Pre uključivanja privatne putanje zabeležite lokalne rute i resolver-e:
```bash
ip route
ip -6 route
resolvectl status
```
Na macOS-u koristite `route -n get default`, `netstat -rn -f inet6` i `scutil --dns`. Sačuvajte izlaz isključivo u kontrolisanom spremištu dokaza; može sadržati lokalne identifikatore.

### 2. Povežite se i proverite rutiranje

Omogućite VPN/Tor/workload namespace, zatim proverite rutu odabranu za kontrolisane javne adrese:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Zamenite adrese iz dokumentacije adresama test servera. Potvrdite da izabrani interface/tabela odgovara dizajnu.

### 3. Posmatrajte sa obe strane

Postavite URL endpointa u vašem vlasništvu, a zatim zatražite jedinstvenu bezopasnu putanju:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Koristite domen kojim upravlja tester, authenticated TLS i token putanje koji nije osetljiv. Pregledajte server log za:

- izvornu adresu/ASN i očekivani egress;
- IPv4 naspram IPv6;
- Host/SNI ponašanje vidljivo na endpointu;
- user agent i application headers;
- tačno vreme i ponovno korišćenje requesta.

Nemojte dodavati `X-Forwarded-For`, jedinstvene debug headers ili cookies koji sadrže identitet u navodno odvojen request.

### 4. Testirajte DNS pomoću owned canary-ja

Konfigurišite authoritative test zone čije query logove kontrolišete. Pošaljite upit za jedinstveni nasumični label kroz compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Proverite authoritative log. On obično vidi recursive resolver, a ne nužno client. Uporedite taj resolver sa predviđenim VPN/Tor/application DNS dizajnom. Nasumični javni DNS leak sajt nije potreban.

### 5. Testirajte fail-closed ponašanje

Održavajte bezopasnu petlju zahteva usmerenu ka endpointu koji je u vašem vlasništvu, zatim zaustavite privacy putanju. Workload mora da otkaže, a ne da se prebaci na fizički interfejs. Proverite obe address families i DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Ponovite tokom:

- pada tunnel procesa;
- prebacivanja sa Wi-Fi-ja na Ethernet ili hotspot;
- uspavljivanja/buđenja;
- obnove DHCP-a;
- stanja captive portala;
- ponovnog povezivanja provajdera/isteka ključa.

Za Linux namespace/container, zaustavite njegov tunnel i proverite da nema drugu podrazumevanu rutu ili resolver:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Nazivi i komande se razlikuju u zavisnosti od implementacije. Nemojte ih nalepiti na udaljeni production host bez oporavka putem konzole.

### 6. Pregled lokalnih socket-a i paketa

Uz odobrenje, proverite koji proces/interfejs zapravo komunicira:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Zamenite `TEST_SERVER_IP` eksplicitno posedovanom adresom; izbegavajte široko hvatanje podataka o nepovezanim korisnicima. Fizički interfejs treba da vidi peer tunela/bridge-a, dok saobraćaj sa jasnom destinacijom treba da postoji samo na predviđenom sloju.

## Tor i test onion-service-a

1. U Tor Browser-u posetite stranicu Tor Project-a za proveru konekcije i potvrdite korišćenje Tor-a. Nemojte to smatrati dokazom identiteta.<sup>[[1]](#references)</sup>
2. Posetite posedovani HTTPS endpoint sa jedinstvenim canary-jem i potvrdite da vidi Tor exit, da nema identifikujućih kolačića i da koristi standardni kontekst browser-a.
3. Izaberite **New Identity**, ponovo posetite stranicu sa drugačijim canary-jem i proverite da li je lokalno stanje očišćeno kako se očekuje. Promena exit IP adrese nije garantovana niti predstavlja svrhu opcije New Identity.
4. Za onion-service, pristupajte mu samo kroz Tor Browser. Potvrdite da host service-a nema javni listener pomoću autorizovanog eksternog skeniranja i da odgovori aplikacije ne sadrže javni hostname/IP.
5. Pregledajte odlazni DNS/HTTP sa origin-a, template-e, error page-ove, email/webhook-e i assets-e trećih strana. Svako direktno preuzimanje može otkriti origin ili operatorski nalog.
6. Ako je omogućena autorizacija klijenata, potvrdite da čist Tor Browser bez credential-a ne može da se poveže, a da onaj sa credential-om može.
7. Rotirajte test authorization key i potvrdite da opozvani klijent gubi pristup bez promene onion identiteta.

## Test browser-compartment-a

Kreirajte kontrolisanu stranicu koja beleži samo polja potrebna za test, uz kratak period zadržavanja. Uporedite personalni i privacy compartment za:

- cookies/local storage/service workers i cache;
- browser sync/login stanje;
- jezik, vremensku zonu, dimenzije ekrana/prozora i fontove;
- WebRTC/network kandidate;
- dozvole i izmene vidljive ekstenzijama;
- TLS/HTTP user-agent podatke na serveru.

Ne pokušavajte da Tor Browser učinite „nasumičnijim“. Uslov prolaska je sličnost sa njegovim standardnim anonymity set-om i odsustvo personalnog stanja, a ne maksimalna razlika u odnosu na personalni browser.

Testirajte copy/paste, drag/drop, otvaranje preuzetih fajlova, predloge password manager-a i dugmad identity provider-a. To su česti mostovi između compartment-a.

## Test izolacije operativnog sistema

### Tails

1. Započnite sa benignim fajlom/canary-jem u session-u bez Persistent Storage-a.
2. Potpuno ugasite sistem, restartujte ga i potvrdite da je fajl nestao.
3. Omogućite samo jednu potrebnu kategoriju persistence-a, ponovite postupak i potvrdite da nepovezano stanje browser-a/aplikacija nije zadržano.
4. Proverite da se Unsafe Browser ne može koristiti nakon portal login-a za osetljive aktivnosti i da se Tor aplikacije normalno ponovo povezuju.

### Whonix/Qubes

1. Zaustavite Gateway/net qube i dokažite da Workstation/app qube ne može da pristupi IPv4, IPv6 ili DNS-u.
2. Pokušajte samo eksplicitno konfigurisan inter-qube clipboard/file path i potvrdite da drugi shared-folder/device path-ovi ne postoje.
3. Otvorite benigni test dokument u disposable qube-u, zatvorite ga i potvrdite da njegovo stanje nestaje.
4. Proverite da vault qube nema NetVM i da ne može da ga dobije kroz promenu template/default podešavanja.
5. Napravite snapshot/restore test VM-a i proverite da li se stanje koje nosi identitet neočekivano vraća.

## Test komunikacionih metadata podataka

Za svaki odabrani messenger:

1. Kreirajte učesnike namenjene samo testiranju na kontrolisanim uređajima.
2. Zabeležite šta je potrebno za registraciju: telefon, app-store nalog, IP, push service, username ili invitation.
3. Pošaljite jednu benignu poruku i pritom pregledajte notification preview-e, povezane desktop računare, wearables i backup-e.
4. Proverite safety/security kodove nezavisnim putem.
5. Isključite receipts/push ili omogućite Tor/lokalne transport-e jedan po jedan i posmatrajte promene pouzdanosti/metadata podataka.
6. Izvezite ili vratite test backup i precizno dokumentujte koje profile, kontakte i istoriju sadrži.
7. Izgubite/opozovite test uređaj i potvrdite da preostali učesnici vide očekivanu promenu key/device-a.

Nemojte testirati kontaktiranjem nepovezanih osoba ili generisanjem abuse saobraćaja.

## Test sanitizacije fajlova

1. Hash-ujte i sačuvajte original u encrypted evidence storage-u:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Napravite očišćenu kopiju koristeći proces specifičan za format u [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md).
3. Uporedite inventare metapodataka:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Render/open the copy in a disposable context. Proverite skriveni sadržaj, priloge, linkove, obrasce, slojeve, sličice i vizuelne identifikatore.
5. Pretražite samo pripremljenu kopiju za poznate canary stringove autora/e-pošte/putanje.
6. Izračunajte hash konačnog izlaza i neka druga osoba proveri tačan fajl koji se objavljuje.

Odsustvo iz ExifTool izlaza nije dokaz anonimnosti; interne strukture formata, pikseli, tekst i evidencije distribucije ostaju.

## Test privatnosti plaćanja

Koristite najmanji dozvoljeni iznos ili zvaničnu testnu mrežu/sandbox:

1. Zapišite očekivani pregled za platioca, primaoca/trgovca, izdavaoca/menjačnicu, mrežu/čvor, javni ledger i računovođu/kontrolora.
2. Kreirajte jedinstveni testni kontekst fakture/trgovca bez lažnog identiteta.
3. Platite jednom, zatim prikupite **sopstvenu** potvrdu, izvod, kontrolnu tablu trgovca, wallet/node log i prikaz javnog lanca gde je primenljivo.
4. Proverite da li se iznos, vremenska oznaka, adresa/token, nalog, IP/uređaj, isporuka i putanja refundacije podudaraju sa tabelom posmatrača.
5. Za Bitcoin proverite ponovnu upotrebu adrese, izabrane ulaze, kusur i kasniju konsolidaciju u prikazu coin-control walleta.
6. Za shielded protokole proverite stvarni pool/path i šta viewing key otkriva; ne zaključujte o privatnosti na osnovu brendiranja walleta.
7. Za e-cash/Taler testirajte backup/recovery, refundaciju i redemption sa malom vrednošću; dokumentujte evidencije granica mint/exchange/federation.
8. Opozovite virtuelnu karticu/testni credential i potvrdite da kasnija autorizacija ne uspeva, dok razumevanje legitimne obrade refundacije ostaje očuvano.
9. Uskladite i čuvajte potrebne poreske/autorizacione dokaze u šifrovanom obliku.

Nikada ne kreirajte kružne transfere, deljenje iznosa radi izbegavanja pragova, lažne kupovine ili sumnjive refundacije kao „test privatnosti“.

## Vežba odgovornosti ovlašćenog red-team-a

Pre vežbe sprovedite tabletop i tehničku vežbu:

1. Operator pokreće benigni canary iz svake odobrene izvorne putanje.
2. Ciljni SOC beleži šta detektuje, bez primanja identiteta operatora ako je predviđeno slepo testiranje.
3. Kontrolor vežbe razrešava source → engagement → operator iz escrowed mape i potpisanog job record-a.
4. Kontrolor šalje emergency stop; operator i vlasnik infrastrukture demonstriraju gašenje u roku definisanom ROE-om.
5. Provider abuse dobija tačan 24/7 kontakt i referencu autorizacije.
6. Dokazi pokazuju cilj, vreme, alat/job i operatora, bez zadržavanja nepotrebnog sadržaja payload-a.
7. Drugi operator proverava opoziv credentiala i uklanjanje resursa.

Oborite proveru spremnosti ako SOC može trivijalno da vidi ličnu/kućnu infrastrukturu **ILI** ako kontrolor ne može brzo da pripiše i zaustavi izvor.

## Šablon testnog zapisa
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Provera veze](https://check.torproject.org/)
- [2] [WireGuard — Rutiranje i mrežni namespace-ovi](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ i smernice za metapodatke](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Tehnički vodič za testiranje i procenu bezbednosti informacija](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
