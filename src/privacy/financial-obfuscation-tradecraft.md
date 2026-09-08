# Tradecraft finansijskog prikrivanja

{{#include ../banners/hacktricks-training.md}}

Privatnost plaćanja je problem atribucije, a ne problem brenda plaćanja. Operacija ostavlja dokaze kada se vrednost pribavi, premesti, konvertuje, potroši i isporuči. Adresa na javnom blockchainu može biti pseudonimna, dok exchange, izdavalac kartice, trgovac, mobilni uređaj ili kamera za praćenje isporuke mogu identifikovati osobu koja stoji iza nje.

Ova stranica objašnjava obrasce finansijskog prikrivanja koji se koriste u cybercrime-u i operacijama povezanim sa državama, kako bi ih defenderi mogli prepoznati. Ona **ne** pruža proceduru za pranje novca, izbegavanje sankcija, korišćenje lažnog identiteta ili zaobilaženje KYC-a.

## Graf vrednosti od početka do kraja
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Akter pokušava da spreči bilo kog posmatrača da vidi oba kraja. Istražitelji rade suprotno: čuvaju zapise na svakoj granici, normalizuju vreme/vrednost/naknade i identifikuju **tačku ponovnog spajanja** gde različite persone ponovo koriste istog posrednika, uređaj, nalog, trgovca ili odredište.

## Instrumenti i njihovi stvarni posmatrači

| Instrument | Skriveno od trgovca/javnosti | I dalje vidljivo |
|---|---|---|
| Virtuelna kartica/token izdavaoca | osnovni broj kartice | izdavaocu, mreži/token provideru, walletu, nalogu trgovca i sistemima za dostavu |
| Prepaid/gift vrednost | ponekad pravno ime pri uobičajenoj kupovini | trgovcu/payment rail-u, servisu za aktivaciju/iskorišćavanje, kamerama, uređaju i dostavi |
| Gotovina | javni ledger i udaljeni izdavalac | drugim učesnicima, kamerama, kontrolama podizanja/serijskih brojeva gde je primenljivo, fizičkom pretresu |
| Bitcoin/novi address | direktno pravno ime | svakom blockchain posmatraču; wallet/network peer-ovima; servisima za kupovinu/izlaz |
| CoinJoin/PayJoin | jednostavne heuristike zajedničkih inputa/plaćanja | javnoj transakciji, coordinator/peer/network metapodacima i kasnijem ponašanju pri trošenju |
| Privacy coin | javni pošiljalac/primalac/iznos, u zavisnosti od protokola | servisu za kupovinu/izlaz, wallet endpointu, network posmatraču i drugoj strani |
| Centralized mixer | direktna veza između depozita i povlačenja | operatoru/logovima mixera, blockchain skupovima ulaza/izlaza i drugim stranama |
| Cross-chain bridge/swap | kontinuitet na jednom chainu | oba chaina, bridge/swap servisu, vremenu/vrednosti i ograničenjima likvidnosti |
| OTC/P2P broker | direktnom exchange nalogu u nekim slučajevima | brokeru, komunikacijama, kretanju novca/gotovine, drugim stranama i uređajima |

## Kartice, prepaid vrednost, nominees i mules

### Virtuelne i maskirane kartice

Izdavalac može da kreira merchant-locked ili disposable broj kartice. To smanjuje izloženost trgovca i ponovnu upotrebu broja kod više trgovaca. Izdavalac ga i dalje povezuje sa korisnikom, funding nalogom, uređajem, IP adresom i transakcijom. Billing descriptors, nalog trgovca, adresa za dostavu i podaci browsera ostaju povezivi.

Marketing kartica „bez imena“ ne podrazumeva anonimno poravnanje. Regulisan izdavalac i distributeri mogu vršiti identity checks, čuvati zapise, nametati geografska/novčana ograničenja i odgovarati na pravne zahteve. Kartica pribavljena korišćenjem ukradenog identiteta predstavlja identity theft; ona ne uklanja telemetriju izdavaoca/uređaja/trgovca.

### Prepaid i gift vrednost

Prepaid kartice i gift kodovi razdvajaju kasnije iskorišćavanje od prvobitnog payment instrumenta, ali stvaraju numerisani objekat sa događajima kupovine, aktivacije, provere stanja i iskorišćavanja. Relevantni obrasci uključuju kupovine velikog obima, ponovljene denominacije neposredno ispod kontrolnih pragova, brza iskorišćavanja na udaljenim lokacijama, jedan uređaj koji proverava mnogo stanja ili mnogo kartica koje se spajaju kod jednog trgovca/naloga.

### Nominees, money mules i merchant fronts

Nominee ili mule obezbeđuje nalog i pravni identitet koji se nalazi između operatora i servisa. Mreže mogu uključivati recruitere, vlasnike naloga, payment processore, shell merchants i cash-out brokere. To stvara udaljenost, ali svaki učesnik dodaje komunikacije, naknade, ponašanje koje nije u skladu i potencijalnog svedoka koji može sarađivati. Front companies dodaju zapise o osnivanju, porezima, bankama, direktorima, fakturama, hostingu i pošiljkama.

Defenders treba da istraže deljene uređaje/IP adrese, ponovnu upotrebu korisnika sredstava, geografske kontradikcije, brzinu aktivnosti koja nije u skladu sa istorijom naloga, kružne transfere, više nepovezanih pošiljalaca koji se spajaju i neposredno prosleđivanje sredstava. Ne treba pretpostaviti da je imenovani vlasnik naloga akter koji kontroliše aktivnosti; treba ga tretirati kao node čiju ulogu treba utvrditi.

## Obrasci obfuscacije transakcija na javnom chainu

### Rotacija addressa i coin control

Kreiranje novog addressa za svaki prijem sprečava trivijalnu ponovnu upotrebu addressa, ali transakcije se i dalje mogu povezati kroz zajedničke inpute, detekciju change-a, identičnu vrednost/vreme i kasniju konsolidaciju. **Coin control** omogućava walletu da izabere koje outpute će potrošiti i izbegne spajanje compartmenta. Poboljšava higijenu; ne može ukloniti već javno dostupnu vezu.

### Peel chains

Peel chain neprekidno troši veliki saldo, šaljući manji iznos ka spolja i vraćajući ostatak na novi address:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Adresa se menja u svakom koraku, ali kontinuitet vrednosti, ritam i struktura transakcija često formiraju prepoznatljiv lanac. Legitimni hot wallets menjačnica mogu se ponašati slično, pa atribucija zahteva dokaze o servisu/kontekstu. DOJ je koristio analizu peel-chain obrazaca u slučajevima zaplene imovine povezanim sa DPRK.<sup>[[1]](#references)</sup>

### Structuring and fan-out/fan-in

- **Fan-out:** jedan izvor deli sredstva na mnoge adrese kako bi povećao istražni teret ili pripremio paralelnu konverziju.
- **Fan-in:** mnogi izvori konsoliduju sredstva u jednom sakupljaču, otkrivajući zajedničku kontrolu ili servis.
- **Structuring:** ponovljeni manji transferi nastoje da izbegnu pragove za proveru ili da se uklope u uobičajeni obim transakcija.
- **Commingling:** nezakonita i nepovezana sredstva dele wallets, pool-ove ili servise, zbog čega su pojednostavljene proporcionalne tvrdnje nepouzdane.

Oblik grafa je trag, a ne dokaz. Analitičari treba da uzmu u obzir naknade, UTXO/account model, ponašanje servisa i konvencije za kusur.

### CoinJoin and PayJoin

U tipičnom CoinJoin-u, više učesnika doprinosi inputima i prima outpute u jednoj kolaborativnoj transakciji, često sa jednakim apoenima outputa. Time se narušava pretpostavka da svaki input i output u transakciji ima jednog vlasnika. Anonimity set je ograničen brojem učesnika i kasnijim ponašanjem: nejednaki kusur, toxic change, konsolidacija ili prelazak preko poznatog servisa mogu ponovo uspostaviti veze.

PayJoin menja običnu uplatu tako da i platioc i primalac doprinose inputima, čime se direktno poništava heuristika vlasništva zasnovana na zajedničkim inputima za tu transakciju. To je prvenstveno protokol za privatnost plaćanja, a ne servis za masovno pranje novca. Detekcija treba da izbegava proglašavanje svih inputa zajedničkim vlasništvom i treba da izrazi neizvesnost, umesto da nameće lažni klaster.

### Centralized mixers and tumblers

Centralized mixer prihvata depozite, a kasnije isplaćuje druge coine iz zajedničke rezerve, često nakon naknada i odlaganja. Njegova privatnost zavisi od veličine pool-a, politike povlačenja, logova, poštenja operatora i otpornosti na zaplenu. Analiza vremena i vrednosti ulaza i izlaza, depozitnih adresa, klasterizacije wallet-a servisa i evidencija može suziti skup mogućnosti. Operatori mogu ukrasti sredstva ili zadržati potpuno mapiranje.

Pravna izloženost je značajna i zavisi od jurisdikcije. Slučajevi DOJ protiv ChipMixer-a, Samourai Wallet-a i developera/operatora Tornado Cash-a, kao i promenljivi sporovi u vezi sa sankcijama, pokazuju da su činjenice o protokolu, custody-ju, kontroli i prenosu novca bitne; oznaka poput „decentralizovano” nije pravni zaključak.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps and bridges

Chain hopping konvertuje imovinu ili je prebacuje kroz bridge, čime prekida upit nad jednom ledger evidencijom, ali ne i ekonomsku kontinuitet:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analitičari povezuju bridge contracts/service deposit addresses, redosled transakcija, vremenski prozor, kurs, naknade, likvidnost i jedinstveni iznos. Ponovljeni swaps mogu povećati nejasnoću, uz dodavanje telemetrije provajdera/API-ja/wallet-a. FATF posebno navodi chain hopping, mixers, peer-to-peer services i anonymity-enhanced currencies kao indikatore rizika kada se kombinuju sa sumnjivim kontekstom.<sup>[[3]](#references)</sup>

### NFT-ovi, kockanje i kupovine kod trgovaca

Samoposlujuće ili koluzivne NFT trgovine mogu sredstvima dati prividnu priču o prodaji; kockanje može zameniti depozite za isplate; roba može digitalnu vrednost pretvoriti u inventar koji se može preprodati. Ovi putevi ostavljaju marketplace naloge, veze sa kreatorima/royalty-jem, grafove wash-trading-a, istoriju kvota/igre, device logove, dokaze o isporuci i preprodaji. Gubitak ili naknada nisu dokaz da je poreklo nestalo.

## Kriptovalute koje štite privatnost

Privacy protokoli se tehnički razlikuju:

- **Monero** koristi jednokratne adrese, ring signatures i poverljive iznose, čime se smanjuje javna vidljivost pošiljaoca/primaoca/iznosa. Posmatranje mreže, kompromitovanje wallet-a, zapisi o nabavci/off-ramp-u i evidencije druge ugovorne strane ostaju izvan tih on-chain zaštita.
- **Zcash shielded pools** mogu sakriti pošiljaoca, primaoca i iznos kada se koriste shielded transakcije; transparentne adrese i prelazi između pool-ova ostaju javni, a obrasci korišćenja utiču na efektivni anonymity set.
- **Bitcoin** je po podrazumevanim postavkama transparentan. Nove adrese, CoinJoin, PayJoin i Lightning menjaju određene pretpostavke o povezivanju, ali ne čine sve slojeve privatnim.

Privacy tehnologija ima legitimne bezbednosne i komercijalne upotrebe. Iz istražne perspektive, kada ledger pruža manje informacija, endpoint, service, network i human dokazi postaju važniji. Nikada ne zaključujte da postoji kriminal samo na osnovu izbora privacy-preserving protokola.

## DPRK višeslojni model slučaja

Javne optužbe DOJ-a i postupci zaplene opisuju složen proces, a ne jednu tehniku:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. radnici su koristili izmišljene/ukradene identifikacione podatke i VPN-ove da bi dobili remote employment;
2. poslodavci su plaćali cryptocurrency, uključujući stablecoins;
3. sredstva su premeštana u manjim iznosima, prelazila između chains ili tokens, korišćena za kupovinu NFT-ova ili commingled;
4. druga ukradena sredstva ulazila su u mixers;
5. OTC traders i front companies pretvarali su vrednost u fiat payments ili robu;
6. ponovljeni facilitatori, nalozi i blockchain putevi omogućili su istražiteljima da ponovo povežu slojeve.

Treasury je naveo da je Lazarus koristio Blender.io za obradu dela krađe Axie Infinity/Ronin, dok je FBI objavio adrese i pozvao bridges, exchanges, RPC operators i analytics firms da blokiraju sredstva povezana sa kasnijim TraderTraitor krađama.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Pouka je dvosmerna: državni akteri koriste uobičajene komercijalne/kriminalne servise, a javni blockchains omogućavaju defenderima da prate vrednost čak i kada su imena u početku nepoznata.

## Workflow za detekciju

1. **Sačuvajte sirove identifikatore transakcija i zapise.** Screenshots i zaokružene fiat vrednosti nisu dovoljni.
2. **Normalizujte assets i vreme.** Zabeležite chain, token contract, units, block time, service time zone, fees i izvor exchange rate-a.
3. **Označite pouzdanost dokaza.** Razlikujte adresu koju je objavio service, deterministički contract event, clustering heuristic i external intelligence.
4. **Pratite oba smera.** Pronađite izvor finansiranja, neposredno rasipanje, ponovno spajanje, bridge exits, service deposits i spend/delivery.
5. **Povežite off-chain dokaze.** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping i communication records često rešavaju nejasnoću.
6. **Testirajte alternativna objašnjenja.** Exchanges, custodians, payroll i privacy protocols mogu proizvesti fan-in/out ili co-spends bez zajedničkog stvarnog vlasništva.
7. **Pratite umesto da prerano zatvorite slučaj.** Dormant output kasnije može postati pripisiv kada stigne do service-a.
8. **Primenjujte važeće sanctions/AML obaveze uz savet pravnika.** Pravila i designations se menjaju; istorijska povezanost nije zamena za trenutnu pravnu analizu.

## Model bezbedne red-team nabavke

Ovlašćenom timu može biti potrebno da ciljni SOC ne prepozna hosting payment, dok engagement controller zadržava odgovornost:

- koristite engagement-specific organization card ili dokumentovani corporate wallet;
- održavajte billing, tax i provider records tačnim;
- odvojite operatora od procurement dužnosti i ograničite pristup attribution mapi;
- nikada ne koristite mulu, lažni identitet, ukradenu karticu, sanctions workaround ili nelicenciranog exchanger-a;
- zabeležite asset, amount, owner, service, date, refund path i teardown evidence;
- nakon vežbe otkrijte controller-u relevantne payment/provider indikatore.

Time se stvara **slepoća prema učesniku vežbe**, a ne slepoća prema zakonu, provider-u ili governance-u.

## References

- [1] [US DOJ — Okvir za sprovođenje zakona u oblasti cryptocurrency-ja (primer peel-chain-a i istrage DPRK-a)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Obaranje ChipMixer-a](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Indikatori upozorenja za Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Predstavnik spoljne trgovinske banke DPRK-a optužen u zaverama za crypto-laundering](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Zahtev za zaplenu u vezi sa navodnim pranjem 7,74 miliona dolara za DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sankcije protiv Blender.io i sredstva Lazarus-a](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Severna Koreja odgovorna za krađu sa Bybit-a 2025. godine](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Primena propisa na korisnike, administratore i exchangers virtual currency-ja](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
