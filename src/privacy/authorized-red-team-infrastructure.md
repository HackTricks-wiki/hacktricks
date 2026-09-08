# Authorized Red-Team Infrastructure

{{#include ../banners/hacktricks-training.md}}

Za dugotrajne uređaje na lokaciji koristite dizajn [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) i runbook za slučaj sumnje na otkrivanje.

Za profesionalni red team, cilj je **kontrolisana atribucija**, a ne imunitet od odgovornosti. Meta ne bi trebalo trivijalno da vidi kućni IP ili lične naloge operatora, dok vlasnik angažmana mora moći da identifikuje izvor, zaustavi operaciju, obradi prijave zloupotrebe, sačuva dokaze i dokaže autorizaciju.

Ova stranica predstavlja osnovu za deployment zakonitog angažmana. Za adversary tradecraft koji treba emulirati — uključujući kompromitovane ORB-ove, residential relay-e, fronting, dead drop-ove i obližnje wireless pivot-e — počnite sa [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) i [Government and APT Case Studies](government-and-apt-case-studies.md), a zatim reprodukujte potrebnu telemetriju u [authorized labs](authorized-adversary-emulation-labs.md).

NIST definiše rules of engagement (ROE) kao unapred utvrđena ograničenja koja daju ovlašćenje za definisane aktivnosti testiranja.<sup>[[1]](#references)</sup> Privacy arhitektura ne može proširiti to ovlašćenje.

## Choose an egress pattern

| Obrazac | Najbolja upotreba | Meta vidi | Provider/lokalni posmatrač vidi | Odgovornost |
|---|---|---|---|---|
| VPN/jump host koji obezbeđuje klijent | Većina procena | Opseg klijentovih adresa | Identitet klijenta i pristup operatora | Najjača |
| Bastion red-team organizacije | Ponovljiv kontrolisani egress | Opseg organizacije | Hosting provider i organizaciju | Jaka |
| VPS specifičan za angažman | Izolovanje klijenata/kampanja | VPS adresu | Nalog hosta, billing, control-plane i access logove | Jaka ako je dokumentovana |
| Odobreni komercijalni VPN | Istraživanje/scanning koje provider i ROE dozvoljavaju | Deljeni/namenski VPN egress | VPN nalog i izvornu konekciju | Srednja |
| Tor Browser | Web istraživanje kojem je potrebna ne povezivost sa destinacijom | Tor exit | Lokalna mreža vidi Tor/bridge; destinacija vidi Tor | Loš izbor za atribuciju izvora putem allowliste |
| Drop na lokaciji koji je odobrio klijent | Interna simulacija | Uređaj/adresu na lokaciji | Mrežu lokacije i remote tunnel provider | Jaka ako je inventarisan |
| Zakoniti guest Wi-Fi | Administrativna upotreba/istraživanje niskog rizika | Javni IP lokacije ili tunnel egress | Lokaciju, ISP, VPN/Tor | Slaba i fizički uočljiva |

Za većinu aktivnosti, fiksni egress koji obezbeđuje klijent ili kontroliše organizacija bezbedniji je i brži od consumer anonymity servisa. Takođe omogućava defenderima da dozvole, nadgledaju ili namerno **ne dozvole putem allowliste** poznate izvorne opsege, u skladu sa dizajnom vežbe.

## ROE infrastructure annex

Pre deployment-a zabeležite:

- pravna lica koja daju i primaju autorizaciju;
- tačne mete i izričita izuzeća;
- vreme početka/završetka, vremensku zonu i dozvoljene tehnike;
- izvorne IP adrese, nazive autonomnih sistema/provider-a, domene, redirector-e, mail infrastrukturu i identifikatore uređaja na lokaciji;
- da li su phishing, C2, credential capture, wireless testing, fizički pristup, denial-of-service, persistence ili third-party servisi dozvoljeni;
- odobrenja klijenta i provider-a, uključujući eventualnu referencu za pre-notifikaciju;
- emergency stop phrase, 24/7 abuse kontakte klijenta i provider-a i maksimalno vreme odziva;
- klase podataka koje mogu biti prikupljene, encryption, pristup, retention i brisanje;
- zahteve za dokaze i logging, uključujući osobu koja čuva mapiranje javne infrastrukture na operatora;
- teardown, isticanje domena, opoziv sertifikata, rotaciju kredencijala, povrat uređaja i završnu potvrdu.

Proverite da li su javne IP adrese i domeni zaista pod kontrolom strane koja daje autorizaciju ili su izričito uključeni u scope. NIST SP 800-115 preporučuje potvrdu da su javne adrese meta pod nadležnošću organizacije pre testiranja.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Kreirajte nalog/projekat za angažman** u okviru red-team organizacije, koristeći tačne podatke za billing i vlasništvo. Odvojite role, API ključeve, budžete i audit logove od drugih klijenata.
2. **Proverite policy svakog provider-a.** Cloud, VPS, CDN, domain, email i VPN provider-i imaju različita pravila. AWS, na primer, dozvoljava određene procene, ali zahteva prethodno odobrenje za hosted C2/covert simulations i zabranjuje navedene aktivnosti.<sup>[[3]](#references)</sup>
3. **Dodelite fiksne egress adrese** i unesite ih u ROE annex. Izbegavajte brzu rotaciju IP adresa/resursa; ona otežava incident response i može kršiti policy provider-a.
4. **Ojačajte management:** SSH samo putem ključeva ili identity-aware management plane, phishing-resistant MFA, odvojena admin mreža, least privilege, ažurirane image datoteke, bez javnih admin portova i encrypted secret storage.
5. **Kreirajte full-tunnel putanju** od operator endpoint-a do bastion-a. Namerno rutirajte DNS i IPv6 i primenite firewall deny kada je tunnel nedostupan.
6. **Ograničite outbound destinacije i portove** na autorizovani scope kada je to izvodljivo. Ograničite brzinu scanner-a i stavite ireverzibilne/destruktivne tehnike iza zasebnog approval gate-a.
7. **Logujte radi odgovornosti, a ne nadzora:** autentikaciju operatora, izmene konfiguracije, start/stop, izvornu adresu, destinaciju u scope-u i identifikatore alata/job-a. Izbegavajte payload/credential capture osim ako je to potrebno za vežbu i zaštićeno data planom.
8. **Validirajte preko kontrolisanog endpoint-a** u vlasništvu organizacije: uočeni IPv4/IPv6, DNS putanju, reverse DNS, clock, ponašanje source port-a, failure/reconnect i abuse kontakt provider-a.
9. **Bezbedno podelite mapu atribucije** sa controller-om vežbe ili dogovorenim escrow kontaktom. Ne objavljujte je red team-u mete ako je blind detection deo testa.

### Architecture
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
VPS je pseudoniman samo prema odredištu. Host može imati evidenciju kontakata, naplate, identiteta, izvornih IP adresa, API-ja, uređaja, lokacije i korišćenja; sama istorija AWS CloudTrail aktivnosti vidljiva korisniku može otkriti aktivnosti upravljanja.<sup>[[4]](#references)</sup> Plaćanje hostinga kriptovalutom ne briše tu evidenciju.

## Domeni i sertifikati

- Koristite nalog registrara namenjen konkretnom angažmanu, u vlasništvu organizacije.
- Omogućite zaključavanje registrara, DNSSEC gde je podržan, MFA/security keys i automatsko obnavljanje samo za odobreni period.
- Koristite privatnost registracije da smanjite javnu izloženost, a ne da lažno predstavite podatke o registrantu. ICANN politika zahteva od registrara da prikupljaju podatke o registraciji čak i kada je javni prikaz uklonjen ili proxied.<sup>[[5]](#references)</sup>
- Izbegavajte nazive koji nezakonito oponašaju nepovezane strane. Typosquatting/lookalike domains zahtevaju izričito odobrenje klijenta i provajdera.
- Inventarišite DNS, sertifikate, CDN/redirector konfiguraciju i analitiku trećih strana koja bi mogla da leakuje operatore ili klijente.
- Prilikom uklanjanja infrastrukture, uklonite zapise, opozovite sertifikate/tokene, sačuvajte dogovorene dokaze i odlučite da li domen treba zadržati radi odbrambene zaštite.

## Ovlašćeni on-site drop čvorovi

Raspberry Pi ili sličan uređaj prihvatljiv je samo kada vlasnik objekta/mreže i klijent izričito odobre njegovu tačnu lokaciju i ponašanje. Bezbedan plan:

1. Zabeležite serijski broj uređaja, MAC/private-MAC policy, fotografiju, vlasnika, tačnu odobrenu lokaciju, izvor napajanja, rok za preuzimanje i kontakt za slučaj neovlašćenog pristupa.
2. Koristite minimalni potpisani image, šifrovane secrets, read-only ili obnovljivu memoriju, host firewall, automatske security updates gde je praktično i bez podrazumevanih kredencijala.
3. Konfigurišite komunikaciju samo u odlaznom smeru prema imenovanom endpointu angažmana. Ne izlažite listener bez autentikacije.
4. Dozvolite samo odobrena odredišta i mogućnosti. Packet capture, credential collection, wireless impersonation i lateral movement moraju biti izričito ovlašćeni za svaki slučaj.
5. Koristite mutual authentication, short-lived keys, remote kill, izveštavanje o stanju i ograničenja bandwidth-a.
6. Obezbedite da gubitak ili krađa ne otkriju ponovo upotrebljive kredencijale ili podatke klijenta.
7. Unesite preuzimanje i secure wipe/decommission u kalendar; pribavite potpisanu evidenciju preuzimanja.

Ne skrivajte hardware u kafiću, hotelu, deljenoj kancelariji, na imovini suseda ili javnom mestu bez pisane dozvole vlasnika/operatora.

## Guest networks i travel routers

Ako ovlašćeni scenario zahteva pristup guest mreži:

- proverite SSID i acceptable-use policy sa objektom/klijentom;
- koristite travel router u vlasništvu organizacije ili low-trust bridge uređaj za izolovanje privilegovane radne stanice;
- završite captive portals izvan privilegovane radne stanice;
- pokrenite odobreni tunnel pre assessment saobraćaja;
- potvrdite da povezani uređaji zaista koriste taj tunnel;
- pretpostavite da objekat može povezati radio association, portal, fizičko prisustvo i evidenciju kamera/plaćanja;
- nikada ne zaobilazite kontrolu pristupa, ne klonirajte drugi uređaj, ne napadajte Wi-Fi i ne ostavljajte opremu za sobom.

## Operativno razdvajanje

- Po jedan klijent/angažman za svaki endpoint compartment, cloud project, secrets set, domain group, redirector set i evidence store.
- Bez ličnog emaila, browser sync-a, broja telefona, cloud drive-a, SSH/GPG ključa, code-signing identiteta ili refundacije plaćanja izvan odobrenih sistema organizacije.
- Ne ponavljajte karakterističnu konfiguraciju payload-a, callback paths, sertifikate ili javne repozitorijume između klijenata, osim ako dizajn vežbe prihvata fingerprinting.
- Dodelite infrastrukturi datum gašenja i budžetsko upozorenje. Napušteni sistemi predstavljaju rizik i za klijenta i za Internet.
- Sačuvajte dovoljno interne atribucije za istragu incidenata. „Bez logova“ obično nije spojivo sa profesionalnim dokazima i bezbednosnim obavezama.

## Nevidljivo braniocima, ali pripisivo kontroloru

Kada je cilj vežbe merenje detekcije, a ne testiranje allowlist-e, ciljni SOC može ostati neobavešten bez gubitka odgovornosti operacije:

1. Kontrolor vežbe odobrava svaki javni source, domen, sertifikat i on-site uređaj, ali listu uskraćuje SOC-u.
2. Kontrolor čuva mapu source-to-engagement/operator u zasebnom šifrovanom vault-u sa hitnim pristupom za dve osobe.
3. Svaki operatorski posao dobija potpisani manifest koji sadrži scope, vremenski prozor, source compartment i nepovratni job identifier. Cilj ne mora da vidi manifest tokom normalnog rada.
4. Bastion audit događaji se ulančavaju ili šalju append-only u memoriju kontrolora, tako da operator ne može neprimetno da izmeni atribuciju nakon incidenta.
5. Provider-abuse kontakt dostupan 24/7 čuva verifikacionu frazu/reference koja potvrđuje ovlašćenje bez javnog otkrivanja klijenta.
6. Svaka putanja implementira out-of-band stop channel koji ne zavisi od assessment C2, ciljne mreže ili naloga jednog operatora.
7. Pre testiranja uživo, pošaljite benigne canaries sa svakog source-a. Potvrdite da kontrolor može da ih identifikuje i zaustavi u roku za reakciju definisanom u ROE.
8. Nakon vežbe, uporedite SOC telemetriju sa ledger-om kontrolora, otkrijte listu source-ova i objasnite propuštene/pogrešne detekcije.

Ne dodajte anti-forensics, uništavanje logova, kompromitovane relays ili lažne identitete pretplatnika. To onemogućava odgovorno testiranje umesto da ga unapredi.

## Kontrolna lista za uklanjanje infrastrukture

- [ ] Kontrolor vežbe potvrđuje zaustavljanje.
- [ ] C2, tunnels, redirectors, mail, VPN i zakazani poslovi su onemogućeni.
- [ ] On-site uređaji su fizički preuzeti i usklađeni sa evidencijom.
- [ ] Tokeni, API keys, SSH keys, sertifikati i prikupljeni kredencijali su opozvani/rotirani.
- [ ] DNS i cloud resursi su uklonjeni ili preneti radi odbrambenog zadržavanja.
- [ ] Podaci klijenta su vraćeni, zadržani ili uništeni u skladu sa ugovorom.
- [ ] Zahtevani finansijski, audit i authorization zapisi ostaju šifrovani, uz kontrolisan pristup.
- [ ] Provider abuse slučajevi su zatvoreni, a klijent je primio konačne source indicators.
- [ ] Drugi operator potvrđuje da nijedna infrastruktura nije ostala aktivna.

## References

- [1] [NIST CSRC — Pravila angažovanja](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Tehnički vodič za testiranje i procenu bezbednosti informacija](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Politika korisničke podrške za Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Obaveštenje o privatnosti](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Politika podataka o registraciji](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
