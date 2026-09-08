# Reproducibilno testiranje privatnosti

Postavka privatnosti nije završena kada se poveže. Završena je tek kada je njena deklarisana granica testirana tokom uobičajene upotrebe, otkaza, oporavka i uklanjanja. Testirajte u odnosu na infrastrukturu čiji ste vlasnik ili koju ste ovlašćeni da proveravate; javni sajtovi za „leak test“ postaju još jedan posmatrač.

## Napravite malo ovlašćeno testno okruženje

Koristite tri uloge, idealno na odvojenim providerima/mrežama:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Zabeležite pre svakog testa:

- ID testa, UTC vreme početka/završetka, operatora i autorizaciju;
- endpoint/OS/client verzije i hash konfiguracije;
- očekivana IPv4, IPv6, DNS, TLS, account, payment i fizička zapažanja;
- koje logove ćete pregledati i njihove satove/vremenske zone;
- pravilo za prolaz/neuspeh i vreme teardown-a.

Nikada prvo ne testirajte osetljivi identitet. Koristite synthetic account i bezopasne, jedinstvene canary vrednosti u vlasništvu testera.

## Test mrežne putanje

### 1. Snimite baseline

Pre omogućavanja privacy path-a, zabeležite lokalne rute i resolvere:
```bash
ip route
ip -6 route
resolvectl status
```
Na macOS-u koristite `route -n get default`, `netstat -rn -f inet6` i `scutil --dns`. Sačuvajte izlaz isključivo u kontrolisanom spremištu dokaza; može sadržati lokalne identifikatore.

### 2. Povežite se i proverite rutiranje

Omogućite VPN/Tor/workload namespace, zatim proverite rutu izabranu za kontrolisane javne adrese:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Zamenite dokumentacione adrese adresama testnog servera. Potvrdite da izabrani interfejs/tabela odgovara dizajnu.

### 3. Posmatrajte sa oba kraja

Podesite URL endpointa u vašem vlasništvu, zatim zatražite jedinstvenu bezopasnu putanju:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Koristite domain kojim upravlja tester, authenticated TLS i token putanje koji nije osetljiv. Pregledajte server log za:

- izvornu adresu/ASN i očekivani egress;
- IPv4 naspram IPv6;
- Host/SNI ponašanje vidljivo na endpointu;
- user agent i application headers;
- tačno vreme i ponovno korišćenje requesta.

Nemojte dodavati `X-Forwarded-For`, jedinstvene debug headers ili cookies koji sadrže identitet u navodno odvojen request.

### 4. Testirajte DNS pomoću canary-ja pod vašom kontrolom

Konfigurišite authoritative test zone čije query logove kontrolišete. Pošaljite upit za jedinstvenu nasumičnu labelu kroz compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Proverite merodavan log. On obično vidi rekurzivni resolver, a ne nužno klijenta. Uporedite taj resolver sa predviđenim VPN/Tor/application DNS dizajnom. Nasumični javni DNS leak sajt nije potreban.

### 5. Testirajte fail-closed ponašanje

Održavajte benignu petlju zahteva usmerenu ka endpointu u vašem vlasništvu, a zatim zaustavite privacy putanju. Workload mora da otkaže, umesto da se prebaci na fizički interfejs. Proverite obe familije adresa i DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Ponovite tokom:

- rušenja tunnel procesa;
- prebacivanja sa Wi-Fi-ja na Ethernet ili hotspot;
- sleep/wake;
- DHCP obnavljanja;
- stanja captive-portal-a;
- ponovnog povezivanja provajdera/isteka ključa.

Za Linux namespace/container, zaustavite njegov tunnel i proverite da nema drugu default route ili resolver:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Nazivi i komande razlikuju se u zavisnosti od deployment-a. Nemojte ih nalepiti na udaljeni production host bez mogućnosti oporavka putem konzole.

### 6. Proverite lokalne sokete i pakete

Uz odobrenje, proverite koji proces/interface zapravo komunicira:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Zamenite `TEST_SERVER_IP` eksplicitnom adresom u vašem vlasništvu; izbegavajte široko prikupljanje podataka o nepovezanim korisnicima. Fizički interfejs treba da vidi peer tunela/bridge-a, dok jasan saobraćaj ka odredištu treba da postoji samo na predviđenom sloju.

## Tor i test onion-service-a

1. U Tor Browser-u posetite stranicu Tor Project-a za proveru konekcije i potvrdite korišćenje Tor-a. Nemojte to smatrati dokazom identiteta.<sup>[[1]](#references)</sup>
2. Posetite HTTPS endpoint u vašem vlasništvu sa jedinstvenim canary-em i potvrdite da vidi Tor exit, da nema identifikujućih kolačića i da koristi standardni kontekst pregledača.
3. Izaberite **New Identity**, ponovo posetite stranicu sa drugačijim canary-em i proverite da li je lokalno stanje očišćeno kako je očekivano. Promena izlazne IP adrese nije zagarantovana niti je svrha opcije New Identity.
4. Za onion service pristupajte mu isključivo kroz Tor Browser. Potvrdite da host service-a nema javni listener pomoću autorizovanog eksternog skeniranja i da odgovori aplikacije ne sadrže javni hostname/IP.
5. Pregledajte odlazni DNS/HTTP sa origin-a, template-e, stranice sa greškama, email/webhook-e i asset-e trećih strana. Svako direktno preuzimanje može otkriti origin ili nalog operatora.
6. Ako je omogućena autorizacija klijenata, potvrdite da se neautorizovani čist Tor Browser ne može povezati, a da autorizovani može.
7. Rotirajte testni authorization key i potvrdite da opozvani klijent gubi pristup bez promene onion identiteta.

## Test browser-compartment-a

Kreirajte kontrolisanu stranicu koja beleži samo polja potrebna za test, uz kratak period zadržavanja podataka. Uporedite lični compartment i privacy compartment za:

- cookies/local storage/service workers i cache;
- browser sync/login stanje;
- jezik, vremensku zonu, dimenzije ekrana/prozora i fontove;
- WebRTC/network candidates;
- dozvole i izmene vidljive ekstenzijama;
- TLS/HTTP user-agent podatke na serveru.

Ne pokušavajte da Tor Browser učinite „nasumičnijim“. Uslov prolaza je sličnost sa njegovim standardnim anonymity set-om i odsustvo ličnog stanja, a ne maksimalna različitost u odnosu na lični browser.

Testirajte copy/paste, drag/drop, otvaranje preuzetih fajlova, predloge password manager-a i dugmad identity provider-a. To su česti mostovi između compartment-a.

## Test izolacije operativnog sistema

### Tails

1. Počnite sa bezopasnim fajlom/canary-em u sesiji bez Persistent Storage-a.
2. Potpuno ugasite sistem, ponovo ga pokrenite i potvrdite da je fajl nestao.
3. Omogućite samo jednu potrebnu kategoriju persistence-a, ponovite test i potvrdite da nepovezano stanje browser-a/aplikacija nije zadržano.
4. Proverite da se Unsafe Browser ne može koristiti nakon prijavljivanja na portal za osetljive aktivnosti i da se Tor aplikacije normalno ponovo povezuju.

### Whonix/Qubes

1. Zaustavite Gateway/net qube i dokažite da Workstation/app qube ne može da pristupi IPv4, IPv6 ili DNS-u.
2. Pokušajte samo eksplicitno konfigurisani inter-qube clipboard/file path i potvrdite da drugi shared-folder/device path-ovi ne postoje.
3. Otvorite bezopasan testni dokument u disposable qube-u, zatvorite ga i potvrdite da njegovo stanje nestaje.
4. Proverite da vault qube nema NetVM i da ga ne može dobiti promenom template-a/default-a.
5. Napravite snapshot/restore testnog VM-a i proverite da li se stanje koje nosi identitet neočekivano vraća.

## Test metapodataka komunikacije

Za svaki izabrani messenger:

1. Kreirajte učesnike namenjene samo testiranju na kontrolisanim uređajima.
2. Zabeležite šta registracija zahteva: telefon, app-store nalog, IP, push service, username ili pozivnicu.
3. Pošaljite jednu bezopasnu poruku uz pregled notification preview-a, povezanih desktop računara, nosivih uređaja i backup-a.
4. Proverite safety/security kodove nezavisnim putem.
5. Isključite receipts/push ili omogućite Tor/lokalne transport-e, jedan po jedan, i posmatrajte promene pouzdanosti/metapodataka.
6. Izvezite ili vratite testni backup i tačno dokumentujte koje profile, kontakte i istoriju sadrži.
7. Izgubite/opozovite testni uređaj i potvrdite da preostali učesnici vide očekivanu promenu ključa/uređaja.

Nemojte testirati kontaktiranjem nepovezanih ljudi ili generisanjem zloupotrebljavajućeg saobraćaja.

## Test sanitizacije fajlova

1. Izračunajte hash i sačuvajte original u šifrovanom skladištu dokaza:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Napravite očišćenu kopiju koristeći proces specifičan za format u dokumentu [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md).
3. Uporedite inventare metapodataka:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Render/open kopiju u disposable kontekstu. Proverite skriveni sadržaj, priloge, links, forms, layers, thumbnails i vizuelne identifikatore.
5. Pretražite samo staged kopiju za poznatim canary author/email/path stringovima.
6. Hashujte konačni output i neka druga osoba proveri tačno file koji se objavljuje.

Odsustvo iz ExifTool outputa nije dokaz anonimnosti; interni detalji formata, pixels, prozni tekst i zapisi o distribuciji i dalje ostaju.

## Test privatnosti plaćanja

Koristite najmanji dozvoljeni iznos ili zvaničnu testnu mrežu/sandbox:

1. Zapišite očekivani prikaz za payera, payee/merchant, issuer/exchange, network/node, javni ledger i accountant/controller.
2. Kreirajte jedinstveni testni invoice/merchant kontekst bez lažnog identiteta.
3. Platite jednom, zatim prikupite **sopstveni** receipt, statement, merchant dashboard, wallet/node log i prikaz javnog chaina gde je primenljivo.
4. Proverite da li se amount, timestamp, address/token, account, IP/device, delivery i refund ruta podudaraju sa tabelom posmatrača.
5. Za Bitcoin proverite ponovno korišćenje adrese, odabrane inputs, change i kasniju konsolidaciju u wallet coin-control prikazu.
6. Za shielded protocols proverite stvarni pool/path i ono što viewing key otkriva; ne zaključujte o privatnosti na osnovu wallet brendiranja.
7. Za e-cash/Taler testirajte backup/recovery, refund i redemption sa malom vrednošću; dokumentujte mint/exchange/federation boundary records.
8. Opozovite virtual card/test credential i potvrdite da kasnija authorization ne uspeva, dok pravilno postupanje sa refundom ostaje razumljivo.
9. Uskladite i zadržite potrebne tax/authorization dokaze šifrovane.

Nikada ne kreirajte circular transfers, threshold-splitting, fake purchases ili sumnjive refundove kao „test privatnosti“.

## Authorized red-team drill odgovornosti

Pre vežbe sprovedite tabletop i technical drill:

1. Operator pokreće benigni canary sa svakog odobrenog source patha.
2. Target SOC beleži šta detektuje, bez prijema identiteta operatora ako je predviđeno blind testing.
3. Exercise controller razrešava source → engagement → operator iz escrowed mape i potpisanog job recorda.
4. Controller šalje emergency stop; operator i infrastructure owner demonstriraju shutdown u roku definisanom ROE-om.
5. Provider abuse dobija tačan 24/7 kontakt i authorization reference.
6. Evidence pokazuje target, vreme, tool/job i operatora, bez zadržavanja nepotrebnog payload sadržaja.
7. Drugi operator proverava credential revocation i resource teardown.

Oborite readiness review ako SOC može trivijalno da vidi ličnu/kućnu infrastrukturu **ILI** ako controller ne može brzo da pripiše i zaustavi source.

## Template zapisa testa
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
- [3] [ExifTool — Česta pitanja i smernice za metapodatke](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Tehnički vodič za testiranje i procenu informacione bezbednosti](https://csrc.nist.gov/pubs/sp/800/115/final)
