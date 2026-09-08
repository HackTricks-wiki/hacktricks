# Privatna digitalna plaćanja

Privatnost plaćanja predstavlja kontrolisano otkrivanje podataka o transakciji. Ona nije način da se nezakonita sredstva učine legitimnim, izbegnu porez ili sankcije, zaobiđe KYC, koriste lažni identiteti ili sakrije neovlašćeni angažman. Plaćanje može biti privatno u odnosu na trgovca, a i dalje potpuno vidljivo izdavaocu, mreži, poslodavcu, poreskom organu ili istražitelju.

[Katalog tehnika anonimnih plaćanja](anonymous-payment-techniques.md) predstavlja normalizovani pregled sa stavkama `Pros`, `Cons`, zakonitom stavkom `Procedure` korak po korak i stavkom `Detection` za svaku grupu. Ova stranica proširuje konvencionalne metode plaćanja.

{% hint style="danger" %}
Nikada ne koristite ukradene naloge, sintetičke identitete, money mule posrednike, izmišljeno prebivalište ili netačne tvrdnje o poreklu sredstava, deljenje transakcija („structuring“) radi izbegavanja prijave ili neproverene posrednike za „no-KYC card“. Proverite važeće zakone i uslove provajdera u svakoj relevantnoj jurisdikciji.
{% endhint %}

## Definišite svojstvo privatnosti

Pre izbora payment rail-a navedite posmatrača:

| Posmatrač | Tipični podaci | Korisna kontrola | Ono što ostaje |
|---|---|---|---|
| Trgovac | Ime, email, adresa, card token, IP/uređaj, sadržaj korpe | Guest checkout, minimum opcionih podataka, merchant-specific virtual card | Podaci o isporuci, nalogu i fraud telemetrija |
| Izdavalac/payment processor | Pravni identitet, izvor sredstava, trgovac, iznos, vreme, uređaj | Izaberite regulisanog provajdera sa dobrim uslovima privatnosti/bezbednosti | Provajder i dalje obrađuje i može zadržati/otkriti zapise |
| Poslodavac/vlasnik angažmana | Trošak, operator i svrha | Odvojen budžet angažmana i ledger sa kontrolisanim pristupom | Legitimno upravljanje zahteva internu atribuciju |
| Posmatrač javnog blockchain-a | Adrese, tokovi, iznosi i vreme, u zavisnosti od chain-a | Odgovarajući protokol i disciplina korišćenja wallet-a | Nabavka, krajnje tačke i kasnija potrošnja mogu ponovo povezati aktivnost |
| Mrežni/RPC/node operator | IP, wallet upiti, emitovanje transakcija | Lokalni node ili odgovarajuća privacy network | Vremenski obrasci i ponašanje krajnje tačke i dalje mogu biti korelisani |
| Fizički posmatrač | Lice, lokacija, vozilo, CCTV, račun | Uobičajena situaciona privatnost | Cash ne čini osobu fizički nevidljivom |

CFPB navodi da payment apps mogu prikupljati podatke o identitetu, uređaju, lokaciji, kontaktima, transakcijama i ponašanju; pravila o privatnosti pojedinačnih država ne sprečavaju nužno monetizaciju ili svaku sekundarnu upotrebu.<sup>[[1]](#references)</sup> Pročitajte stvarno obaveštenje provajdera umesto da privatnost zaključujete na osnovu naziva proizvoda.

## Uporedite metode plaćanja

| Metoda | Korist za privatnost | Glavni posmatrači/veze | Odgovarajuća upotreba |
|---|---|---|---|
| Cash | Nema payment-network ledger-a | Primalac, kamere, svedoci, pravila o prijavljivanju gotovine | Zakonite lokalne kupovine tamo gde je prihvaćen |
| Open-loop prepaid/gift card | Razdvaja broj kartice od glavne kartice | Prodavac, provajder aktivacije/registracije, izvor sredstava, trgovac | Budžetiranje ili ograničena compartmentalization kod trgovaca |
| Virtual/one-time card number | Sakriva ponovo upotrebljivi PAN od trgovca; laka revokacija | Izdavalac i dalje zna identitet i transakciju | Compartmentalization kod online trgovaca |
| Mobile-wallet token | Uređaj/trgovac dobija token umesto izvornog PAN-a | Wallet provajder, izdavalac, payment network i trgovac | Bezbednost credential-a, ne anonimnost |
| Bank transfer/app | Pogodan audit trail | Banka/app, druga strana i povezani identitet | Odgovorna organizaciona plaćanja |
| Cryptocurrency | Zavisi od protokola; self-custody može smanjiti izloženost custodian-u | Javni ledger ili privacy protocol, exchange, endpoint, druga strana | Zakoniti transferi nakon analize specifične za protokol |

## Cash

Cash se i dalje smatra važnim za privatnost i finansijsku uključenost, a izbegava zapis u payment network-u.<sup>[[2]](#references)</sup> Ne sprečava CCTV, svedoke, lokaciju uređaja, račune, praćenje serijskih brojeva u posebnim slučajevima niti zakonsko prijavljivanje.

### Zakonit workflow

1. Pre transakcije proverite prihvatanje i lokalna ograničenja za cash. Ograničenja se razlikuju prema zemlji i vrsti strane i menjaju se tokom vremena.
2. Obavite uobičajenu kupovinu u jednoj poštenoj transakciji. **Nikada je ne delite** radi izbegavanja praga ili prijave.
3. Odbijte opciono loyalty praćenje ili prikupljanje marketinških podataka. Istinito navedite podatke potrebne za garanciju, bezbednost, isporuku, porez ili zakon.
4. Neophodan dokaz o kupovini i obavezne računovodstvene zapise čuvajte u šifrovanom storage-u sa datumom brisanja.
5. Za organizaciju, izvršite refundaciju kroz odobreni proces i zabeležite operatora, autorizaciju, svrhu, iznos, datum i račun.

U Sjedinjenim Državama, određene trgovine ili poslovni subjekti podnose Form 8300 za cash uplate veće od 10.000 USD, uključujući povezane transakcije; namerno razdvajanje transakcija može samo po sebi predstavljati nezakonito structuring.<sup>[[3]](#references)</sup> Druge jurisdikcije se razlikuju — na primer, Španija objavljuje sopstveno zakonsko ograničenje cash plaćanja.<sup>[[4]](#references)</sup>

## Prepaid i gift cards

„Prepaid“ ne znači anonimno. Prodavnica, izdavalac, program manager, banka koja obezbeđuje sredstva i trgovac mogu povezati kupovinu, aktivaciju, uređaj, IP, lokaciju i potrošnju. Reload-ovi, ATM pristup, međunarodna upotreba, viši limiti ili zaštita u slučaju gubitka obično zahtevaju registraciju.

Smernice za potrošače u SAD objašnjavaju da izdavaoci mogu tražiti podatke o identitetu radi zakonske verifikacije i odbiti registrovanu karticu kada verifikacija ne uspe.<sup>[[5]](#references)</sup> FinCEN pravila definišu koji prepaid programi i učesnici imaju AML obaveze.<sup>[[6]](#references)</sup> U EU, uski izuzeci za anonimni e-money smanjeni su Direktivom (EU) 2018/843; Regulation (EU) 2024/1624 ponovo menja okvir, ali se uglavnom primenjuje od **10. jula 2027.**, zato ga nemojte opisivati kao već operativan 2026. godine.<sup>[[7]](#references)</sup>

Prepaid vrednost koristite samo kada je zakonito pribavljena od identifikovanog izdavaoca, kada uslovi izdavaoca dozvoljavaju predviđenu upotrebu i kada je korist u budžetiranju ili odvajanju od primarnog payment credential-a. Izbegavajte resale tržišta i posrednike koji oglašavaju neproverljive „no-name“ kartice: vrednost može biti ukradena, već iskorišćena, geografski ograničena ili predmet zaplene.

## Virtual cards i wallet tokens

Virtual card number (VCN) obično se izdaje u okviru stvarnog, verifikovanog naloga. Merchant-specific ili single-use brojevi smanjuju rizik od breach-a i korelacije PAN-a između trgovaca; oni **ne** skrivaju transakciju od izdavaoca. Network tokenization na sličan način zamenjuje card credential ograničenim tokenom.<sup>[[8]](#references)</sup>

### Workflow sa compartmentalization-om po trgovcu

1. Otvorite nalog kod regulisanog izdavaoca koristeći tačne podatke o identitetu, prebivalištu i finansiranju.
2. Zaštitite ga jedinstvenom lozinkom, phishing-resistant MFA kada je dostupna, login alert-ima i recovery kodovima sačuvanim offline.
3. Generišite merchant-locked ili one-time VCN. Postavite razumno ograničenje iznosa/vremena ako je podržano.
4. Koristite guest checkout i izostavite samo **opciona** polja profila, loyalty programa i marketinga. Kada je potrebno, navedite tačne podatke za billing, isporuku i porez.
5. Izbegavajte prijavljivanje na nepovezane identity provider-e; koristite browser compartment za angažman/nalog i odobreni network path.
6. Sačuvajte račun i mapiranje VCN-a prema svrsi u šifrovanom internom ledger-u.
7. Zamrznite ili opozovite broj nakon isteka roka za refund/chargeback; pratite parent account zbog neočekivanih autorizacija.

Capital One i Google navode da virtual numbers ostaju povezani sa osnovnim nalogom, dok EMVCo/Visa opisuju tokenization kao zamenu credential-a i ograničavanje domena, a ne anonimnost platioca.<sup>[[8]](#references)</sup>

## Isporuka, nalozi i refundacije

Plaćanje je samo jedna ivica u graph-u povezivanja:

- Jedinstvena kartica postaje beskorisna za privatnost ako ponovo koristite lični email, telefon, browser profile, IP adresu ili loyalty nalog.
- Fizička isporuka obično zahteva zakonitog primaoca i lokaciju. Ne koristite adresu osobe koja nije uključena niti se predstavljajte kao rezident. Odobrene poslovne receiving usluge bezbednije su od izmišljenih podataka.
- Digitalna roba može beležiti identitet naloga, IP, fingerprint uređaja, aktivaciju licence i preuzimanja.
- Refundacije se obično vraćaju na originalni rail. Zahtevi da primite sredstva i prosledite/refundirate ih drugde predstavljaju upozorenje na fraud i money mule aktivnost.
- Merchant descriptors, tekst fakture i obaveštenja o isporuci mogu otkriti osetljivu kupovinu delegatima naloga; namerno podesite pristup i alert-e.

## Authorized Red-Team kupovine

Angažman treba da bude diskretan spolja i odgovoran iznutra:

1. Pribavite pisani scope, svrhu, limit potrošnje, odobravaoca, dozvoljene trgovce/imovinu i pravilo refundacije.
2. Koristite payment account pod kontrolom organizacije i zaseban VCN ili sub-account za svaki angažman ili trgovca.
3. Kod provajdera zadržite tačne billing i registracione podatke. Privatnost javne registracije može smanjiti izloženost, ali nije dozvola za laganje.
4. Održavajte šifrovani ledger sa operatorom, odobrenjem, svrhom, datumom, iznosom, drugom stranom, identifikatorom imovine i računom.
5. Proveravajte druge strane kada je potrebno i poštujte obaveze provajdera, sankcija, poreza i prijavljivanja.
6. Finansijama dajte samo pristup koji im je potreban; operatorima dajte samo ograničenu spending sposobnost koja im je potrebna.
7. Tokom teardown-a zatvorite ili zamrznite payment credential-e, uskladite pending charges/refunds i čuvajte zapise u skladu sa politikom.

Za izbore specifične za crypto nastavite na [Cryptocurrency Privacy](cryptocurrency-privacy.md). Za infrastrukturu koju te kupovine podržavaju pogledajte [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Kontrolna lista za verifikaciju

- [ ] Željeno svojstvo privatnosti i posmatrači su zapisani.
- [ ] Pravila provajdera, trgovca i jurisdikcije nedavno su proverena.
- [ ] Izjave o identitetu i poreklu sredstava su istinite.
- [ ] Opcioni podaci trgovca su svedeni na minimum bez zaobilaženja obavezne verifikacije.
- [ ] Povezanosti finansiranja, uređaja, mreže, naloga, isporuke i refundacije su shvaćene.
- [ ] Nema izbegavanja praga, zabranjene druge strane, mule, ukradenog credential-a niti identiteta treće strane.
- [ ] Obavezni računi, odobrenja, poreski zapisi i podaci za oporavak su šifrovani i zaštićeni kontrolom pristupa.

## References

- [1] [US CFPB — Zahtev za informacije u vezi sa prikupljanjem, upotrebom i monetizacijom podataka o potrošačkim plaćanjima i drugih ličnih finansijskih podataka](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Studija o stavovima potrošača prema plaćanjima u eurozoni (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Uputstvo za Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Prijavljivanje cash plaćanja](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Zašto se od mene traže lični podaci za aktivaciju ili registraciju prepaid kartice?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) i [Da li mogu biti odbijen za prepaid karticu?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Završno pravilo o Prepaid Access-u](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Direktiva (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Korišćenje virtual credit cards](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
