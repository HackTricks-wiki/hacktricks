# Privatna digitalna plaćanja

{{#include ../banners/hacktricks-training.md}}

Privatnost plaćanja je kontrolisano otkrivanje podataka o transakciji. Ona nije način da se nezakonita sredstva učine legitimnim, izbegne plaćanje poreza ili poštovanje sankcija, zaobiđe KYC, koriste lažni identiteti ili sakrije neovlašćeni angažman. Plaćanje može biti privatno u odnosu na trgovca, a da istovremeno bude potpuno vidljivo izdavaocu, mreži, poslodavcu, poreskom organu ili istražitelju.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) je standardizovani inventar sa odeljcima `Pros`, `Cons`, zakonitom `Procedure` korak po korak i odeljkom `Detection` za svaku grupu. Ova stranica proširuje konvencionalne metode plaćanja.

{% hint style="danger" %}
Nikada ne koristite ukradene naloge, sintetičke identitete, money mules, izmišljeno prebivalište ili tvrdnje o poreklu sredstava, razbijanje transakcija („structuring“) ili neproverene posrednike za „no-KYC card“. Proverite važeće zakone i uslove pružaoca usluga u svakoj relevantnoj jurisdikciji.
{% endhint %}

## Definišite svojstvo privatnosti

Identifikujte posmatrača pre izbora payment rail-a:

| Posmatrač | Tipični podaci | Korisna kontrola | Šta ostaje |
|---|---|---|---|
| Trgovac | Ime, e-mail, adresa, card token, IP/uređaj, korpa | Guest checkout, minimum opcionih podataka, merchant-specific virtual card | Dostava, podaci o nalogu i fraud telemetrija |
| Izdavalac/payment processor | Pravni identitet, izvor sredstava, trgovac, iznos, vreme, uređaj | Izbor regulisanog pružaoca sa dobrim uslovima privatnosti/bezbednosti | Pružalac i dalje obrađuje i može zadržati/otkriti zapise |
| Poslodavac/vlasnik angažmana | Trošak, operater i svrha | Odvojen budžet angažmana i ledger sa kontrolisanim pristupom | Legitimno upravljanje zahteva internu atribuciju |
| Posmatrač javnog blockchain-a | Adrese, tokovi, iznosi i vreme, u zavisnosti od chain-a | Odgovarajući protokol i wallet disciplina | Nabavka, endpoint-i i kasnija potrošnja mogu ponovo povezati aktivnost |
| Operator mreže/RPC/node-a | IP, wallet upiti, emitovanje transakcija | Lokalni node ili odgovarajuća privacy network | Vremensko podudaranje i ponašanje endpoint-a i dalje mogu biti povezani |
| Fizički posmatrač | Lice, lokacija, vozilo, CCTV, račun | Uobičajena situaciona privatnost | Gotovina osobu ne čini fizički nevidljivom |

CFPB navodi da payment apps mogu prikupljati podatke o identitetu, uređaju, lokaciji, kontaktima, transakcijama i ponašanju; državni propisi o privatnosti ne sprečavaju nužno monetizaciju niti svaku sekundarnu upotrebu.<sup>[[1]](#references)</sup> Pročitajte stvarno obaveštenje pružaoca umesto da privatnost zaključujete na osnovu naziva proizvoda.

## Uporedite metode plaćanja

| Metoda | Korist za privatnost | Glavni posmatrači/veze | Odgovarajuća upotreba |
|---|---|---|---|
| Gotovina | Ne postoji ledger payment network-a | Primalac, kamere, svedoci, pravila o prijavljivanju gotovine | Zakonite lokalne kupovine gde je prihvaćena |
| Open-loop prepaid/gift card | Odvaja broj kartice od glavne kartice | Prodavac, pružalac aktivacije/registracije, izvor sredstava, trgovac | Budžetiranje ili ograničena compartmentalization u odnosu na trgovca |
| Virtual/one-time card number | Sakriva ponovo upotrebljivi PAN od trgovca; lako opozivanje | Izdavalac i dalje zna identitet i transakciju | Compartmentalization online trgovca |
| Mobile-wallet token | Uređaj/trgovac dobija token umesto osnovnog PAN-a | Wallet provider, issuer, payment network i trgovac | Bezbednost credential-a, ne anonimnost |
| Bank transfer/app | Pogodan audit trail | Banka/app, druga strana i povezani identitet | Odgovorna organizaciona plaćanja |
| Cryptocurrency | Zavisi od protokola; self-custody može smanjiti izloženost custodian-u | Javni ledger ili privacy protocol, exchange, endpoint, druga strana | Zakoniti transferi nakon analize specifične za protokol |

## Gotovina

Gotovina se i dalje smatra važnom za privatnost i finansijsku inkluziju, a izbegava zapis u payment network-u.<sup>[[2]](#references)</sup> Ona ne sprečava CCTV, svedoke, lokaciju uređaja, račune, praćenje serijskih brojeva u posebnim slučajevima niti zakonsko prijavljivanje.

### Zakonit workflow

1. Proverite prihvatanje i lokalna ograničenja gotovine pre transakcije. Ograničenja se razlikuju po zemlji i vrsti strane i menjaju se tokom vremena.
2. Obavite uobičajenu kupovinu u jednoj poštenoj transakciji. **Nikada je ne razbijajte** da biste izbegli prag ili prijavljivanje.
3. Odbijte opciono praćenje loyalty programa ili prikupljanje podataka za marketing. Podatke potrebne za garanciju, bezbednost, dostavu, porez ili zakon navedite istinito.
4. Sačuvajte potreban dokaz o kupovini i obavezne računovodstvene zapise u šifrovanom storage-u sa datumom brisanja.
5. Za organizaciju, izvršite refundaciju kroz odobreni proces i zabeležite operatera, odobrenje, svrhu, iznos, datum i račun.

U Sjedinjenim Državama, određene delatnosti i preduzeća podnose Form 8300 za gotovinske račune veće od 10.000 USD, uključujući povezane transakcije; namerno razdvajanje transakcija može samo po sebi predstavljati nezakonito structuring ponašanje.<sup>[[3]](#references)</sup> Druge jurisdikcije se razlikuju — na primer, Španija objavljuje sopstveno zakonsko ograničenje gotovinskih plaćanja.<sup>[[4]](#references)</sup>

## Prepaid i gift cards

„Prepaid“ ne znači anoniman. Prodavnica, izdavalac, program manager, banka koja obezbeđuje sredstva i trgovac mogu povezati kupovinu, aktivaciju, uređaj, IP, lokaciju i potrošnju. Dopune, ATM pristup, međunarodna upotreba, viši limiti ili zaštita u slučaju gubitka obično zahtevaju registraciju.

Smernice za potrošače u SAD objašnjavaju da izdavaoci mogu zahtevati podatke o identitetu radi zakonske verifikacije i mogu odbiti registrovanu karticu kada verifikacija ne uspe.<sup>[[5]](#references)</sup> Pravila FinCEN-a definišu koji prepaid programi i učesnici imaju AML obaveze.<sup>[[6]](#references)</sup> U EU su uski izuzeci za anonimni e-money smanjeni Direktivom (EU) 2018/843; Uredba (EU) 2024/1624 ponovo menja okvir, ali se uglavnom primenjuje od **10. jula 2027.**, zato je nemojte opisivati kao već važeću 2026. godine.<sup>[[7]](#references)</sup>

Prepaid value koristite samo kada je zakonito pribavljen od identifikovanog izdavaoca, kada njegovi uslovi dozvoljavaju predviđenu upotrebu i kada je korist budžetiranje ili odvajanje od primarnog payment credential-a. Izbegavajte resale markets i brokers koji oglašavaju neproverljive „no-name“ cards: value može biti ukraden, već iskorišćen, geografski ograničen ili predmet zaplene.

## Virtual cards i wallet tokens

Virtual card number (VCN) se obično izdaje iza stvarnog, verifikovanog naloga. Merchant-specific ili single-use brojevi smanjuju rizik od breach-a i korelacije PAN-a između trgovaca; oni **ne** skrivaju transakciju od izdavaoca. Network tokenization na sličan način zamenjuje card credential ograničenim tokenom.<sup>[[8]](#references)</sup>

### Workflow sa odvajanjem trgovaca

1. Otvorite nalog kod regulisanog izdavaoca koristeći tačne podatke o identitetu, prebivalištu i izvoru sredstava.
2. Zaštitite ga jedinstvenom lozinkom, phishing-resistant MFA kada je dostupan, login alert-ima i recovery kodovima sačuvanim offline.
3. Generišite merchant-locked ili one-time VCN. Postavite razumno ograničenje iznosa/vremena ako je podržano.
4. Koristite guest checkout i izostavite samo **opciona** polja profila, loyalty programa i marketinga. Kada je potrebno, navedite tačne billing, delivery i tax podatke.
5. Izbegavajte prijavljivanje na nepovezane identity providers; koristite browser compartment za angažman/nalog i odobreni network path.
6. Sačuvajte račun i mapiranje VCN-a prema svrsi u šifrovanom internom ledger-u.
7. Zamrznite ili opozovite broj nakon isteka perioda za refund/chargeback; pratite parent account zbog neočekivanih autorizacija.

Capital One i Google dokumentuju da virtual numbers ostaju povezani sa osnovnim nalogom, dok EMVCo/Visa opisuju tokenization kao zamenu credential-a i ograničavanje domena, a ne kao anonimnost platioca.<sup>[[8]](#references)</sup>

## Dostava, nalozi i refunds

Plaćanje je samo jedna ivica u linkage graph-u:

- Jedinstvenu karticu poništava ponovno korišćenje ličnog e-maila, telefona, browser profila, IP adrese ili loyalty naloga.
- Za fizičku dostavu obično su potrebni zakoniti primalac i lokacija. Ne koristite adresu nepovezane osobe niti se predstavljajte kao stanovnik. Odobrene poslovne receiving services bezbednije su od izmišljenih podataka.
- Digitalna roba može beležiti identitet naloga, IP, fingerprint uređaja, aktivaciju licence i downloads.
- Refunds se obično vraćaju na originalni rail. Zahtevi da primite sredstva i prosledite/refundujete ih drugde predstavljaju upozorenje na fraud i money-mule aktivnost.
- Merchant descriptors, tekst računa i obaveštenja o slanju mogu account delegates izložiti osetljivoj kupovini; pažljivo podesite pristup i alerts.

## Authorized red-team purchases

Angažman treba da bude diskretan prema spolja, a odgovoran iznutra:

1. Pribavite pisani scope, svrhu, limit potrošnje, odobravaoca, dozvoljene trgovce/assets i pravilo refundacije.
2. Koristite payment account pod kontrolom organizacije i zaseban VCN ili sub-account za svaki angažman ili trgovca.
3. Kod pružalaca zadržite tačne billing i registrant podatke. Privatnost javne registracije može smanjiti izloženost, ali nije dozvola za laganje.
4. Vodite šifrovani ledger sa podacima o operateru, odobrenju, svrsi, datumu, iznosu, drugoj strani, identifikatoru asset-a i računu.
5. Proveravajte druge strane kada je potrebno i poštujte obaveze pružaoca, sankcija, poreza i prijavljivanja.
6. Finansijama dajte samo pristup koji im je potreban; operaterima dajte samo ograničenu spending capability koja im je potrebna.
7. Tokom teardown-a zatvorite ili zamrznite payment credentials, uskladite pending charges/refunds i čuvajte zapise u skladu sa politikom.

Za izbore specifične za crypto nastavite na [Cryptocurrency Privacy](cryptocurrency-privacy.md). Za infrastrukturu koju te kupovine podržavaju pogledajte [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Verification checklist

- [ ] Željeno svojstvo privatnosti i posmatrači su zapisani.
- [ ] Pravila pružaoca, trgovca i jurisdikcije nedavno su proverena.
- [ ] Izjave o identitetu i poreklu sredstava su istinite.
- [ ] Opcioni podaci trgovca su svedeni na minimum bez zaobilaženja obavezne verifikacije.
- [ ] Povezanosti funding-a, uređaja, mreže, naloga, dostave i refundacije su shvaćene.
- [ ] Nisu uključeni izbegavanje praga, zabranjena druga strana, mule, ukradeni credential ili identitet treće strane.
- [ ] Obavezni računi, odobrenja, poreski zapisi i recovery informacije su šifrovani i zaštićeni kontrolom pristupa.

## References

- [1] [US CFPB — Zahtev za informacije u vezi sa prikupljanjem, korišćenjem i monetizacijom podataka o potrošačkim plaćanjima i drugih ličnih finansijskih podataka](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Studija o stavovima potrošača prema plaćanju u evrozoni (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Uputstvo za Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Prijavljivanje gotovinskih plaćanja](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Zašto se od mene traže lični podaci za aktiviranje ili registraciju prepaid kartice?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) i [Da li mogu biti odbijen za prepaid karticu?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Finalno pravilo o Prepaid Access-u](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Direktiva (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Korišćenje virtual credit cards](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
