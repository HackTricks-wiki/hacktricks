# Red teaming Web3 sistema usmerenog na vrednost (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

MITRE-ov okvir Adversarial Actions in Digital Asset Payment Techniques (AADAPT) kategorizuje protivničke aktivnosti i tehnike usmerene na sisteme digitalne imovine.<sup>[[1]](#references)</sup> Tretirajte ga kao **osnovu za modelovanje pretnji**: popišite svaku komponentu koja može da kreira, vrednuje, autorizuje ili usmerava imovinu, mapirajte te tačke kontakta na AADAPT tehnike, a zatim osmislite red-team scenarije kojima se procenjuje može li okruženje da spreči nepovratan ekonomski gubitak.

## 1. Popišite komponente koje nose vrednost
Napravite mapu svega što može da utiče na stanje vrednosti, čak i ako se nalazi van lanca.<sup>[[2]](#references)</sup>

- **Custodial signing servisi** (HSM/KMS klasteri, Vault/KMaaS, API-ji za potpisivanje koje koriste botovi ili pozadinski poslovi). Zabeležite ID-jeve ključeva, pravila, identitete za automatizaciju i tokove odobravanja.
- **Administrativne i nadogradne putanje** za ugovore (proxy administratori, governance timelock-i, ključevi za hitno pauziranje, registri parametara). Navedite ko ili šta može da ih poziva i pod kojim kvorumom ili odlaganjem.
- **On-chain protokolska logika** za pozajmljivanje, AMM-ove, vault-ove, staking, bridge-ove ili rail-ove za poravnanje. Dokumentujte pretpostavljene invarijante (cene orakla, odnosi kolaterala, učestalost rebalansiranja…).
- **Off-chain automatizacija** koja sklapa transakcije (market-making botovi, CI/CD pipeline-ovi, cron poslovi, serverless funkcije). Često raspolažu API ključevima ili service principal-ima koji mogu da zatraže potpise.
- **Orakli i data feed-ovi** (sastav agregatora, kvorum, pragovi odstupanja, učestalost ažuriranja). Zabeležite svaki upstream izvor na koji se oslanja automatizovana logika za upravljanje rizikom.
- **Bridge-ovi i cross-chain ruteri** (ugovori za zaključavanje/kreiranje tokena, relayer-i, poslovi za poravnanje) koji povezuju lance ili custodial sisteme.

Rezultat: dijagram toka vrednosti koji prikazuje kako se imovina kreće, ko odobrava njeno kretanje i koji spoljašnji signali utiču na poslovnu logiku.

## 2. Mapirajte komponente na AADAPT ponašanja
Pretvorite AADAPT taksonomiju u konkretne kandidate za napade po komponentama.<sup>[[2]](#references)</sup>

| Komponenta | Primarni fokus AADAPT-a |
| --- | --- |
| Signing/KMS sistemi | Krađa kredencijala, zaobilaženje pravila, zloupotreba potpisivanja, preuzimanje governance-a |
| Orakli/feed-ovi | Trovanje ulaznih podataka, manipulacija agregacijom, izbegavanje pragova odstupanja |
| On-chain protokoli | Ekonomska manipulacija flash loan-om, narušavanje invarijanti, ponovna konfiguracija parametara |
| Pipeline-ovi za automatizaciju | Kompromitovani bot/CI identiteti, ponavljanje batch-a, neovlašćeno postavljanje |
| Bridge-ovi/ruteri | Cross-chain izbegavanje, brzo prebacivanje radi pranja, desinhronizacija poravnanja |

Ovo mapiranje osigurava da testirate ne samo ugovore, već i svaki identitet/automatizaciju koji mogu indirektno da usmeravaju vrednost.

## 3. Odredite prioritete prema izvodljivosti napadača i poslovnom uticaju

1. **Operativne slabosti**: izloženi CI kredencijali, IAM uloge sa prevelikim privilegijama, pogrešno konfigurisana KMS pravila, automation nalozi koji mogu da zatraže proizvoljne potpise, javni bucket-i sa bridge konfiguracijama itd.
2. **Slabosti specifične za vrednost**: krhki parametri orakla, nadogradivi ugovori bez odobrenja više strana, likvidnost podložna flash loan napadima, governance radnje koje zaobilaze timelock-e.

Radite kroz red kao protivnik: počnite od operativnih uporišnih tačaka koje bi mogle da uspeju već danas, a zatim pređite na dublje putanje protokolske/ekonomske manipulacije.<sup>[[2]](#references)</sup>

## 4. Izvršavajte scenarije u kontrolisanim okruženjima koja realistično odražavaju produkciju
- **Fork-ovi mainnet-a / izolovani testnet-i**: replicirajte bytecode, skladište i likvidnost kako bi flash-loan putanje, odstupanja orakla i bridge tokovi mogli da se izvrše od početka do kraja bez dodirivanja stvarnih sredstava.<sup>[[2]](#references)</sup>
- **Planiranje dometa uticaja**: definišite circuit breaker-e, module koji mogu da se pauziraju, runbook-ove za rollback i admin ključeve namenjene samo za testiranje pre aktiviranja scenarija.
- **Koordinacija sa zainteresovanim stranama**: obavestite custodiane, operatere orakla, bridge partnere i timove za usklađenost kako bi njihovi timovi za nadzor očekivali saobraćaj.
- **Pravno odobrenje**: dokumentujte opseg, ovlašćenje i uslove za prekid kada bi simulacije mogle da obuhvate regulisane tokove.

## 5. Telemetrija usklađena sa AADAPT tehnikama
Prikupite telemetriju tako da svaki scenario proizvede podatke za detekciju na osnovu kojih se može delovati.<sup>[[2]](#references)</sup>

- **Traces na nivou lanca**: potpuni grafovi poziva, potrošnja gasa, nonce transakcija, vremenske oznake blokova — za rekonstrukciju flash-loan paketa, struktura nalik reentrancy-ju i poziva između ugovora.
- **Aplikaциони/API logovi**: povežite svaku on-chain transakciju sa ljudskim ili automatizovanim identitetom (ID sesije, OAuth klijent, API ključ, ID CI posla), uz IP adrese i metode autentifikacije.
- **KMS/HSM logovi**: ID ključa, pozivajući principal, rezultat provere pravila, odredišna adresa i šifre razloga za svaki potpis. Postavite osnovne vrednosti za vremenske prozore promena i visokorizične operacije.
- **Metapodaci orakla/feed-a**: sastav izvora podataka za svako ažuriranje, prijavljena vrednost, odstupanje od pokretnih proseka, aktivirani pragovi i korišćene putanje za prebacivanje na rezervni izvor.
- **Bridge/swap traces**: povežite događaje zaključavanja/kreiranja tokena/otključavanja između lanaca pomoću ID-jeva korelacije, ID-jeva lanaca, identiteta relayer-a i vremena između hop-ova.
- **Oznake anomalija**: izvedene metrike kao što su skokovi slippage-a, neuobičajeni odnosi kolaterala, neuobičajena gustina gasa ili brzina kretanja između lanaca.

Označite sve ID-jevima scenarija ili sintetičkim ID-jevima korisnika kako bi analitičari mogli da povežu uočene podatke sa AADAPT tehnikom koja se testira.

## 6. Purple-team ciklus i metrike zrelosti
1. Pokrenite scenario u kontrolisanom okruženju i zabeležite detekcije (upozorenja, kontrolne table, obavešteni reagovaoci).<sup>[[2]](#references)</sup>
2. Povežite svaki korak sa konkretnim AADAPT tehnikama i uočenim podacima u slojevima chain/app/KMS/oracle/bridge.
3. Formulišite i postavite hipoteze za detekciju (pravila praga, pretrage korelacija, provere invarijanti).
4. Ponavljajte testove dok srednje vreme detekcije (MTTD) i srednje vreme obuzdavanja (MTTC) ne budu u okviru poslovnih tolerancija, a uputstva za postupanje pouzdano zaustavljaju gubitak vrednosti.

Pratite zrelost programa na tri ose:<sup>[[2]](#references)</sup>
- **Vidljivost**: svaka kritična putanja vrednosti ima telemetriju u svakom sloju.
- **Pokrivenost**: udeo prioritetnih AADAPT tehnika testiranih od početka do kraja.
- **Reagovanje**: mogućnost pauziranja ugovora, opoziva ključeva ili zamrzavanja tokova pre nepovratnog gubitka.

Tipične prekretnice: (1) završen popis vrednosti i AADAPT mapiranje, (2) prvi scenario od početka do kraja sa implementiranim detekcijama, (3) kvartalni purple-team ciklusi koji proširuju pokrivenost i skraćuju MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Predlošci scenarija
Koristite ove ponovljive nacrte za osmišljavanje simulacija koje se direktno mapiraju na AADAPT ponašanja.<sup>[[2]](#references)</sup>

### Scenario A – Ekonomska manipulacija flash loan-om
- **Cilj**: pozajmiti privremeni kapital u okviru jedne transakcije kako bi se izmenile AMM cene/likvidnost i pokrenulo precenjeno pozajmljivanje, likvidacije ili kreiranje tokena pre vraćanja sredstava.
- **Izvršenje**:
  1. Napravite fork ciljnog lanca i napunite pool-ove likvidnošću nalik produkcionoj.
  2. Pozajmite veliku nominalnu vrednost putem flash loan-a.
  3. Izvršite precizno podešene swap-ove da biste prešli granice cena/pragova na koje se oslanja logika pozajmljivanja, vault-a ili derivata.
  4. Odmah nakon izmene pozovite ugovor koji je meta (pozajmite, likvidirajte, kreirajte tokene) i vratite flash loan.
- **Merenje**: Da li je narušavanje invarijante uspelo? Da li su aktivirani nadzori za slippage/odstupanje cena, circuit breaker-i ili governance hook-ovi za pauziranje? Koliko je vremena bilo potrebno da analitika označi neuobičajen obrazac gasa/grafa poziva?

### Scenario B – Trovanje orakla/data feed-a
- **Cilj**: utvrditi mogu li manipulisani feed-ovi da pokrenu destruktivne automatizovane radnje (masovne likvidacije, pogrešna poravnanja).
- **Izvršenje**:
  1. U fork-u/testnet-u postavite zlonamerni feed ili prilagodite ponderisanje agregatora/kvorum/učestalost ažuriranja tako da odstupanje premaši dozvoljene granice.
  2. Sačekajte da zavisni ugovori preuzmu zatrovane vrednosti i izvrše svoju standardnu logiku.
- **Merenje**: Vanpojasna upozorenja na nivou feed-a, aktiviranje rezervnog orakla, sprovođenje minimalnih/maksimalnih granica i kašnjenje između početka anomalije i reakcije operatera.

### Scenario C – Zloupotreba kredencijala/potpisivanja
- **Cilj**: testirati da li kompromitovanje jednog potpisnika ili identiteta za automatizaciju omogućava neovlašćene nadogradnje, izmene parametara ili pražnjenje trezora.
- **Izvršenje**:
  1. Popišite identitete sa osetljivim pravima za potpisivanje (operateri, CI tokeni, service nalozi koji pozivaju KMS/HSM, učesnici multisig-a).
  2. Simulirajte kompromitovanje (ponovo upotrebite njihove kredencijale/ključeve u okviru laboratorijskog opsega).
  3. Pokušajte privilegovane radnje: nadogradite proxy-je, promenite parametre rizika, kreirajte/pauzirajte imovinu ili pokrenite governance predloge.
- **Merenje**: Da li KMS/HSM logovi generišu upozorenja o anomalijama (doba dana, promena odredišta, nalet visokorizičnih operacija)? Mogu li pravila ili multisig pragovi da spreče jednostranu zloupotrebu? Da li su primenjeni throttling/ograničenja brzine ili dodatna odobrenja?

### Scenario D – Izbegavanje između lanaca i nedostaci u sledljivosti
- **Cilj**: proceniti koliko dobro branioci mogu da prate i zaustavljaju imovinu koja se brzo pere preko bridge-ova, DEX rutera i privacy hop-ova.
- **Izvršenje**:
  1. Povežite operacije zaključavanja/kreiranja tokena preko uobičajenih bridge-ova, umetnite swap-ove/mixere na svaki hop i održavajte ID-jeve korelacije za svaki hop.
  2. Ubrzajte transfere da biste opteretili brzinu nadzora (više hop-ova u roku od nekoliko minuta/blokova).
- **Merenje**: Vreme potrebno da se događaji povežu između telemetrijskih sistema i komercijalne analitike lanca, potpunost rekonstruisane putanje, mogućnost identifikovanja tačaka za zamrzavanje u stvarnom incidentu i preciznost upozorenja za neuobičajenu brzinu/vrednost kretanja između lanaca.

## References

- [1] [AADAPT(TM) okvir za sajber pretnje digitalnoj imovini (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT okvir kao red-team putokaz (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
