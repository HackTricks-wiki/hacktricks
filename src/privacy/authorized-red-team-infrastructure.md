# Infrastruktura ovlašćenog red team-a

Za trajne onsite uređaje koristite dizajn [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) i runbook za sumnju na otkrivanje.

Za profesionalni red team, cilj je **kontrolisana atribucija**, a ne imunitet od odgovornosti. Meta ne bi trebalo trivijalno da vidi kućnu IP adresu operatora ili njegove lične naloge, dok vlasnik angažmana mora moći da identifikuje izvor, zaustavi operaciju, obradi prijave zloupotrebe, sačuva dokaze i dokaže ovlašćenje.

Ova stranica predstavlja osnovu za zakonit angažman. Za adversary tradecraft koji treba emulirati — uključujući kompromitovane ORB-ove, residential relays, fronting, dead drops i obližnje wireless pivots — počnite od stranica [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) i [Government and APT Case Studies](government-and-apt-case-studies.md), a zatim reprodukujte potrebnu telemetriju u [ovlašćenim labovima](authorized-adversary-emulation-labs.md).

NIST definiše rules of engagement (ROE) kao unapred utvrđena ograničenja koja daju ovlašćenje za definisane aktivnosti testiranja.<sup>[[1]](#references)</sup> Privacy architecture ne može proširiti to ovlašćenje.

## Izaberite obrazac izlaza

| Obrazac | Najbolja upotreba | Šta meta vidi | Šta provider/lokalni posmatrač vidi | Odgovornost |
|---|---|---|---|---|
| VPN/jump host koji obezbeđuje klijent | Većina procena | Klijentski opseg adresa | Identitet klijenta i pristup operatora | Najjača |
| Bastion red-team organizacije | Ponovljiv kontrolisani izlaz | Opseg organizacije | Hosting provider i organizacija | Jaka |
| VPS namenjen angažmanu | Izolovanje klijenata/kampanja | VPS adresa | Nalog kod hosta, billing, control-plane i access logovi | Jaka ako je dokumentovana |
| Odobreni komercijalni VPN | Istraživanje/scanning koje provider i ROE dozvoljavaju | Zajednički/namenski VPN izlaz | VPN nalog i izvorna konekcija | Srednja |
| Tor Browser | Web istraživanje koje zahteva unlinkability od destinacije | Tor exit | Lokalna mreža vidi Tor/bridge; destinacija vidi Tor | Loš izbor za allowlisted source attribution |
| Client-approved on-site drop | Interna simulacija | On-site uređaj/adresa | Mreža lokacije i remote tunnel provider | Jaka ako je inventarisan |
| Zakoniti guest Wi-Fi | Administrativna/istraživačka upotreba niskog rizika | Javni IP venue-a ili tunnel izlaz | Venue, ISP, VPN/Tor | Slaba i fizički uočljiva |

Za većinu aktivnosti, fixed egress koji obezbeđuje klijent ili kontroliše organizacija bezbedniji je i brži od consumer anonymity servisa. Takođe omogućava defenderima da allowlistuju, nadziru ili namerno **ne allowlistuju** poznate source range-ove u skladu sa dizajnom vežbe.

## Aneks infrastrukture ROE-a

Zabeležite pre deployment-a:

- pravna lica koja daju i primaju ovlašćenje;
- tačne mete i eksplicitna izuzeća;
- vreme početka/završetka, vremensku zonu i dozvoljene tehnike;
- source IP adrese, nazive autonomous system/provider-a, domene, redirectore, mail infrastrukturu i identifikatore on-site uređaja;
- da li su phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence ili usluge trećih strana dozvoljeni;
- odobrenja klijenta i provider-a, uključujući eventualnu referencu pre-notifikacije;
- emergency stop phrase, 24/7 abuse kontakte klijenta i provider-a i maksimalno vreme reakcije;
- klase podataka koje se mogu prikupljati, enkripciju, pristup, zadržavanje i brisanje;
- zahteve za evidence i logging, uključujući osobu koja čuva mapiranje javne infrastrukture na operatora;
- teardown, isticanje domena, opoziv sertifikata, rotaciju credential-a, povraćaj uređaja i završnu potvrdu.

Proverite da javne IP adrese i domeni zaista pripadaju strani koja daje ovlašćenje ili da su eksplicitno uključeni u scope. NIST SP 800-115 preporučuje potvrdu da su javne adrese meta u nadležnosti organizacije pre testiranja.<sup>[[2]](#references)</sup>

## Brzi izlaz specifičan za angažman

### Workflow izgradnje

1. **Kreirajte engagement account/project** u okviru red-team organizacije, koristeći tačne billing podatke i podatke o vlasništvu. Odvojite role, API keys, budžete i audit logove od drugih klijenata.
2. **Proverite policy svakog provider-a.** Cloud, VPS, CDN, domain, email i VPN provider-i imaju različita pravila. AWS, na primer, dozvoljava određene procene, ali zahteva prethodno odobrenje za hosted C2/covert simulations i zabranjuje navedene aktivnosti.<sup>[[3]](#references)</sup>
3. **Dodelite fixed egress adrese** i unesite ih u ROE aneks. Izbegavajte brzo menjanje IP/resource elemenata; to otežava incident response i može kršiti policy provider-a.
4. **Ojačajte management:** SSH samo uz ključeve ili identity-aware management plane, phishing-resistant MFA, odvojena admin mreža, least privilege, zakrpane image datoteke, bez javnih admin portova i enkriptovano čuvanje secret-a.
5. **Kreirajte full-tunnel putanju** od endpointa operatora do bastiona. Namerno usmeravajte DNS i IPv6 i primenite firewall deny kada je tunnel nedostupan.
6. **Ograničite outbound destinacije i portove** na ovlašćeni scope kada je izvodljivo. Ograničite rate scanner-a i stavite irreversible/destructive tehnike iza posebnog approval gate-a.
7. **Logujte radi odgovornosti, ne nadzora:** authentication operatora, promene konfiguracije, start/stop, source address, scoped destination i tool/job identifikatore. Izbegavajte payload/credential capture osim ako je potreban za vežbu i zaštićen data planom.
8. **Validirajte preko kontrolisanog endpointa** u vlasništvu organizacije: uočeni IPv4/IPv6, DNS putanja, reverse DNS, clock, ponašanje source port-a, failure/reconnect i abuse kontakt provider-a.
9. **Bezbedno podelite attribution map** sa controller-om vežbe ili dogovorenim escrow kontaktom. Ne objavljujte je timu mete ako je blind detection deo testa.

### Arhitektura
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
VPS je pseudoniman samo u odnosu na odredište. Host može imati zapise o kontaktu, naplati, identitetu, izvorišnoj IP adresi, API-ju, uređaju, lokaciji i korišćenju; sama istorija AWS CloudTrail-a vidljiva korisniku može otkriti aktivnosti upravljanja.<sup>[[4]](#references)</sup> Plaćanje hostinga cryptocurrency-jem ne briše te zapise.

## Domeni i sertifikati

- Koristite registrar nalog specifičan za angažman, u vlasništvu organizacije.
- Omogućite registrar lock, DNSSEC gde je podržan, MFA/security keys i automatsko obnavljanje samo za odobreni period.
- Koristite privacy zaštitu registracije radi smanjenja javne izloženosti, a ne radi lažnog predstavljanja podataka o registrantu. ICANN politika zahteva od registrara da prikupljaju podatke o registraciji čak i kada je javni prikaz redigovan ili proxied.<sup>[[5]](#references)</sup>
- Izbegavajte nazive koji nezakonito imitiraju nepovezane strane. Typosquatting/lookalike domeni zahtevaju izričito odobrenje klijenta i provajdera.
- Popišite DNS, sertifikate, CDN/redirector konfiguraciju i third-party analytics koji bi mogli da leak-uju operatore ili klijente.
- Prilikom teardown-a uklonite zapise, opozovite sertifikate/tokene, sačuvajte dogovorene dokaze i odlučite da li domen treba zadržati radi odbrane.

## Authorized on-site drop nodes

Raspberry Pi ili sličan uređaj prihvatljiv je samo kada vlasnik objekta/mreže i klijent izričito odobre njegovu tačnu lokaciju i ponašanje. Bezbedan plan:

1. Zabeležite serijski broj uređaja, MAC/private-MAC politiku, fotografiju, vlasnika, tačnu odobrenu lokaciju, izvor napajanja, rok za preuzimanje i kontakt za slučaj neovlašćenog pristupa.
2. Koristite minimalni potpisani image, šifrovane secrets, read-only ili oporavljivu memoriju, host firewall, automatske security updates gde je praktično i bez podrazumevanih credentialsa.
3. Konfigurišite komunikaciju samo u odlaznom smeru prema imenovanom endpointu angažmana. Ne izlažite unauthenticated listener.
4. Dozvolite samo odredišta i capabilities sa allowliste. Packet capture, prikupljanje credentialsa, wireless impersonation i lateral movement moraju biti izričito odobreni.
5. Koristite mutual authentication, kratkotrajne ključeve, remote kill, izveštavanje o stanju i ograničenja bandwidth-a.
6. Obezbedite da gubitak ili krađa ne otkriju ponovo upotrebljive credentialse ili podatke klijenta.
7. Unesite preuzimanje i secure wipe/decommission u kalendar; pribavite potpisanu evidenciju preuzimanja.

Ne skrivajte hardware u kafiću, hotelu, zajedničkoj kancelariji, na imovini komšije ili na javnom mestu bez pisane dozvole vlasnika/operatora.

## Guest networks and travel routers

Ako ovlašćeni scenario zahteva pristup guest mreži:

- proverite SSID i acceptable-use policy sa objektom/klijentom;
- koristite travel router u vlasništvu organizacije ili low-trust bridge uređaj za izolaciju privileged workstation-a;
- završite captive portals izvan privileged workstation-a;
- pokrenite odobreni tunnel pre assessment saobraćaja;
- potvrdite da povezani uređaji zaista koriste taj tunnel;
- pretpostavite da objekat može povezati radio asocijaciju, portal, fizičko prisustvo i zapise sa kamera/plaćanja;
- nikada ne zaobilazite kontrolu pristupa, ne klonirajte drugi uređaj, ne napadajte Wi-Fi i ne ostavljajte opremu.

## Operational separation

- Jedan klijent/angažman po endpoint compartment-u, cloud projektu, skupu secrets-a, grupi domena, skupu redirector-a i evidence store-u.
- Ne koristite lični email, browser sync, broj telefona, cloud drive, SSH/GPG ključ, identitet za code-signing ili refundaciju plaćanja izvan odobrenih sistema organizacije.
- Nemojte ponovo koristiti prepoznatljivu konfiguraciju payload-a, callback paths, sertifikate ili javne repozitorijume između klijenata, osim ako dizajn vežbe prihvata fingerprinting.
- Dodelite infrastructure-i datum gašenja i budget alert. Napušteni sistemi postaju rizik i za klijenta i za Internet.
- Sačuvajte dovoljno interne atribucije za istragu incidenata. „Bez logova“ obično nije spojivo sa profesionalnim obavezama u vezi sa dokazima i bezbednošću.

## Blind to defenders, attributable to the controller

Kada je cilj vežbe merenje detekcije, a ne testiranje allowliste, ciljni SOC može ostati neobavešten bez gubitka odgovornosti operacije:

1. Controller vežbe odobrava svaki javni source, domen, sertifikat i on-site uređaj, ali listu uskraćuje SOC-u.
2. Controller čuva mapiranje source-to-engagement/operator u zasebnom šifrovanom vault-u sa emergency access-om za dve osobe.
3. Svaki operatorski job dobija potpisani manifest koji sadrži scope, vremenski prozor, source compartment i neponovljivi job identifier. Target ne mora da vidi manifest tokom uobičajenog rada.
4. Bastion audit events se ulančavaju ili šalju append-only u storage controller-a, tako da operator ne može neprimetno da izmeni atribuciju nakon incidenta.
5. 24/7 kontakt za provider abuse čuva verification phrase/reference koja potvrđuje ovlašćenje bez javnog otkrivanja klijenta.
6. Svaki path implementira out-of-band stop channel koji ne zavisi od assessment C2, target mreže ili naloga jednog operatora.
7. Pre live testiranja pošaljite benigne canaries sa svakog source-a. Potvrdite da controller može da ih identifikuje i zaustavi u response time-u definisanom u ROE.
8. Nakon vežbe uporedite SOC telemetriju sa ledger-om controller-a, otkrijte listu source-ova i objasnite propuštene/pogrešne detekcije.

Ne dodajte anti-forensics, uništavanje logova, kompromitovane relays ili lažne subscriber identitete. Oni podrivaju odgovorno testiranje umesto da ga poboljšaju.

## Teardown checklist

- [ ] Controller vežbe potvrđuje zaustavljanje.
- [ ] C2, tuneli, redirectors, mail, VPN i scheduled jobs su onemogućeni.
- [ ] On-site uređaji su fizički preuzeti i usklađeni sa evidencijom.
- [ ] Tokeni, API ključevi, SSH ključevi, sertifikati i prikupljeni credentialsi su opozvani/rotirani.
- [ ] DNS i cloud resources su uklonjeni ili preneti radi zadržavanja u odbrambene svrhe.
- [ ] Podaci klijenta su vraćeni, zadržani ili uništeni u skladu sa ugovorom.
- [ ] Obavezni finansijski, audit i authorization zapisi ostaju šifrovani i zaštićeni kontrolom pristupa.
- [ ] Provider abuse slučajevi su zatvoreni, a klijent je dobio konačne source indikatore.
- [ ] Drugi operator potvrđuje da nijedna infrastructure više nije aktivna.

## References

- [1] [NIST CSRC — Pravila angažmana](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Tehnički vodič za testiranje i procenu bezbednosti informacija](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Politika korisničke podrške za Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Obaveštenje o privatnosti](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Politika podataka o registraciji](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
