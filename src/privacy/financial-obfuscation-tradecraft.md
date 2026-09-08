# Tradecraft za prikrivanje finansijskih tokova

Privatnost plaćanja je problem atribucije, a ne problem brenda platnog sredstva. Operacija ostavlja dokaze kada se vrednost pribavlja, premešta, konvertuje, troši i isporučuje. Adresa na javnom blockchainu može biti pseudonimna, dok berza, izdavalac kartice, trgovac, mobilni uređaj ili kamera za nadzor isporuke identifikuju osobu koja stoji iza nje.

Ova stranica objašnjava obrasce finansijskog prikrivanja koji se koriste u sajberkriminalu i operacijama povezanim sa državama, kako bi ih branioci mogli prepoznati. Ona **ne** pruža proceduru za pranje novca, izbegavanje sankcija, korišćenje lažnog identiteta ili KYC-bypass.

## Grafikon toka vrednosti od početka do kraja
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Akter pokušava da spreči bilo kog posmatrača da vidi oba kraja. Istražitelji rade suprotno: čuvaju zapise na svakoj granici, normalizuju vreme/vrednost/provizije i identifikuju **tačku ponovnog ukrštanja** u kojoj različite persone ponovo koriste istog posrednika, uređaj, nalog, trgovca ili odredište.

## Instrumenti i njihovi stvarni posmatrači

| Instrument | Skriveno od trgovca/javnosti | I dalje vidljivo |
|---|---|---|
| Virtuelna kartica/token izdavaoca | osnovni broj kartice | izdavalac, mreža/token provider, wallet, merchant nalog i sistemi isporuke |
| Prepaid/gift vrednost | ponekad pravno ime pri uobičajenoj kupovini | prodavac/payment rail, servis za aktivaciju/iskorišćavanje, kamere, uređaj i isporuka |
| Gotovina | javni ledger i udaljeni izdavalac | druge ugovorne strane, kamere, kontrole podizanja/serijskih brojeva gde je primenljivo, fizički pretres |
| Bitcoin/novа adresa | direktno pravno ime | svaki blockchain posmatrač; wallet/network peers; acquisition/off-ramp servisi |
| CoinJoin/PayJoin | jednostavne heuristike zajedničkih ulaza/plaćanja | javna transakcija, metapodaci coordinator/peer/network i kasnije ponašanje pri trošenju |
| Privacy coin | javni pošiljalac/primalac/iznos, u zavisnosti od protokola | acquisition/off-ramp, wallet endpoint, network observer i druga ugovorna strana |
| Centralized mixer | direktna veza između depozita i isplate | operator/logovi mixera, blockchain skupovi ulaza/izlaza i druge ugovorne strane |
| Cross-chain bridge/swap | kontinuitet na jednom chainu | oba chaina, bridge/swap servis, vremenska/vrednosna i liquidity ograničenja |
| OTC/P2P broker | direktni exchange nalog u nekim slučajevima | broker, komunikacije, kretanje novca preko banke/gotovine, druge ugovorne strane i uređaji |

## Kartice, prepaid vrednost, nominees i mules

### Virtuelne i maskirane kartice

Izdavalac može da kreira merchant-locked ili disposable broj kartice. Time se smanjuje izloženost trgovca i ponovna upotreba broja kod različitih trgovaca. Izdavalac ga i dalje povezuje sa klijentom, funding nalogom, uređajem, IP adresom i transakcijom. Billing descriptors, merchant nalog, adresa za isporuku i podaci browsera ostaju povezivi.

Marketing kartica „bez imena“ ne podrazumeva anonimni settlement. Regulisani izdavaoci i distributeri mogu sprovoditi identity checks, čuvati zapise, nametati geografska/novčana ograničenja i odgovarati na pravne zahteve. Kartica pribavljena pomoću ukradenog identiteta predstavlja identity theft; ona ne uklanja issuer/device/merchant telemetry.

### Prepaid i gift vrednost

Prepaid kartice i gift kodovi odvajaju kasnije iskorišćavanje od prvobitnog payment instrumenta, ali stvaraju numerisani objekat sa događajima kupovine, aktivacije, provere stanja i iskorišćavanja. Važni obrasci uključuju kupovine velikog obima, ponovljene apoene neposredno ispod kontrolnih pragova, brzu iskorišćavanje na udaljenoj lokaciji, jedan uređaj koji proverava mnogo stanja ili mnogo kartica koje se slivaju ka jednom merchant/account.

### Nominees, money mules i merchant fronts

Nominee ili mule obezbeđuje nalog i pravni identitet koji se nalazi između operatora i servisa. Mreže mogu uključivati recruitere, vlasnike naloga, payment processore, shell merchants i cash-out brokere. To stvara distancu, ali svaki učesnik dodaje komunikacije, provizije, ponašajnu nedoslednost i potencijalnog svedoka koji može sarađivati. Front companies dodaju zapise o registraciji, porezima, bankama, direktorima, fakturama, hostingu i pošiljkama.

Branioci treba da istraže zajedničke uređaje/IP adrese, ponovnu upotrebu beneficiary-ja, geografske protivrečnosti, brzinu transakcija koja nije u skladu sa istorijom naloga, kružne transfere, više nepovezanih pošiljalaca koji se slivaju na jedno mesto i neposredno prosleđivanje sredstava. Ne treba pretpostaviti da je imenovani vlasnik naloga ujedno i kontrolni akter; treba ga posmatrati kao čvor čiju ulogu treba utvrditi.

## Obrasci obfuscation-a transakcija na javnim chainovima

### Rotacija adresa i coin control

Kreiranje nove adrese za svaki prijem sprečava trivijalnu ponovnu upotrebu adrese, ali transakcije se i dalje mogu povezati kroz zajedničke ulaze, detekciju kusura, tačnu vrednost/vreme i kasniju konsolidaciju. **Coin control** omogućava wallet-u da izabere koje outpute će potrošiti i izbegne spajanje odvojenih celina. Poboljšava higijenu; ne može ukloniti već javno dostupnu vezu.

### Peel chains

Peel chain iznova troši veliki saldo, šaljući manji iznos ka spolja i vraćajući ostatak na novu adresu:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Adresa se menja u svakom koraku, ali kontinuitet vrednosti, ritam i struktura transakcija često formiraju prepoznatljiv lanac. Hot wallets legitimnih menjačnica mogu se ponašati slično, pa atribucija zahteva dokaze o servisu/kontekstu. DOJ je koristio analizu peel-chain-a u slučajevima konfiskacije povezanim sa DPRK.<sup>[[1]](#references)</sup>

### Structuring i fan-out/fan-in

- **Fan-out:** jedan izvor deli sredstva na mnoge adrese kako bi povećao istražni posao ili pripremio paralelnu konverziju.
- **Fan-in:** mnogi izvori konsoliduju sredstva u jednom collector-u, otkrivajući zajedničku kontrolu ili servis.
- **Structuring:** ponovljeni manji transferi nastoje da izbegnu pragove za proveru ili da se uklope u uobičajeni obim.
- **Commingling:** nezakonita i nepovezana sredstva dele wallets, pools ili services, zbog čega su pojednostavljene proporcionalne tvrdnje nepouzdane.

Oblik grafa je trag, a ne dokaz. Analitičari treba da uzmu u obzir naknade, UTXO/account model, ponašanje servisa i konvencije za kusur.

### CoinJoin i PayJoin

U tipičnom CoinJoin-u, više učesnika doprinosi inputima i prima outpute u jednoj kolaborativnoj transakciji, često sa jednakim denominacijama outputa. Time se narušava pretpostavka da svaki input i output u transakciji imaju jednog vlasnika. Anonimity set je ograničen brojem učesnika i kasnijim ponašanjem: nejednak kusur, toxic change, konsolidacija ili prelazak preko poznatog servisa mogu ponovo uspostaviti veze.

PayJoin menja običnu uplatu tako da i platilac i primalac doprinose inputima, čime direktno obara heuristic zajedničkog vlasništva inputa za tu transakciju. To je prvenstveno protokol za privatnost plaćanja, a ne bulk laundering servis. Detekcija treba da izbegava proglašavanje svih inputa za zajedničko vlasništvo i treba da izražava neizvesnost umesto da nameće lažni klaster.

### Centralized mixers i tumblers

Centralized mixer prihvata depozite, a kasnije isplaćuje druge coins iz zajedničke rezerve, često nakon naknada i odlaganja. Njegova privatnost zavisi od veličine pool-a, politike povlačenja, logova, poštenja operatora i otpornosti na zaplenu. Analiza vremena i vrednosti ulaza i izlaza, deposit adrese, klasterizacija service wallet-a i zapisi mogu suziti skup. Operator može ukrasti sredstva ili zadržati kompletnu mapu.

Pravna izloženost je značajna i zavisi od jurisdikcije. Slučajevi DOJ-a protiv ChipMixer-a, Samourai Wallet-a i developera/operatora Tornado Cash-a, kao i promenljivi sporovi u vezi sa sankcijama, pokazuju da su činjenice u vezi sa protokolom, custody-jem, kontrolom i prenosom novca važne; oznaka kao što je „decentralizovano” nije pravni zaključak.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps i bridges

Chain hopping konvertuje asset ili ga premešta kroz bridge, prekidajući upit nad jednom ledger-om, ali ne i ekonomsku kontinuitet:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analitičari povezuju bridge contracts/service deposit addresses, redosled transakcija, vremenski okvir, kurs, naknade, likvidnost i jedinstveni iznos. Ponovljeni swap-ovi mogu povećati dvosmislenost, uz dodavanje telemetry-ja provajdera/API-ja/wallet-a. FATF posebno navodi chain hopping, mixers, peer-to-peer services i anonymity-enhanced currencies kao indikatore rizika kada se kombinuju sa sumnjivim kontekstom.<sup>[[3]](#references)</sup>

### NFT-ovi, gambling i kupovine kod trgovaca

Samostalne ili dogovorene NFT trgovine mogu sredstvima dati prividnu prodajnu priču; gambling može zameniti depozite za isplate; roba može digitalnu vrednost pretvoriti u inventar koji se može preprodati. Ovi putevi ostavljaju marketplace naloge, veze sa kreatorima/royalty-jima, grafikone wash-trading-a, istoriju kvota/igara, device logove, dokaze o isporuci i preprodaji. Gubitak ili naknada nisu dokaz da je poreklo nestalo.

## Cryptocurrency koje čuvaju privatnost

Privacy protokoli se tehnički razlikuju:

- **Monero** koristi one-time addresses, ring signatures i confidential amounts, čime smanjuje javnu vidljivost pošiljaoca/primaoca/iznosa. Network observation, kompromitovanje wallet-a, acquisition/off-ramp i records counterparty-ja ostaju izvan tih on-chain zaštita.
- **Zcash shielded pools** mogu sakriti pošiljaoca, primaoca i iznos kada se koriste shielded transactions; transparent addresses i prelazi između pool-ova ostaju javni, a obrasci korišćenja utiču na efektivni anonymity set.
- **Bitcoin** je podrazumevano transparentan. New addresses, CoinJoin, PayJoin i Lightning menjaju određene pretpostavke o povezivanju, ali ne čine sve slojeve privatnim.

Privacy tehnologija ima legitimne bezbednosne i komercijalne primene. Iz istražne perspektive, kada ledger pruža manje informacija, endpoint, service, network i human dokazi postaju važniji. Nikada ne zaključujte da postoji kriminal samo na osnovu izbora privacy-preserving protokola.

## DPRK višeslojni model slučaja

Javne tvrdnje DOJ-a i postupci forfeiture opisuju sastavljen proces, a ne jedan trik:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. radnici su koristili fiktivne/ukradene identifikacione materijale i VPN-ove da bi dobili remote employment;
2. poslodavci su plaćali cryptocurrency, uključujući stablecoins;
3. sredstva su se kretala u manjim iznosima, prelazila između chain-ova ili tokena, koristila za kupovinu NFT-ova ili su bila commingled;
4. druga ukradena sredstva ulazila su u mixers;
5. OTC traders i front companies pretvarali su vrednost u fiat payments ili robu;
6. ponovljeni facilitatori, nalozi i blockchain putevi omogućili su istražiteljima da ponovo povežu slojeve.

Treasury je naveo da je Lazarus koristio Blender.io za obradu dela krađe Axie Infinity/Ronin, dok je FBI objavio addresses i pozvao bridges, exchanges, RPC operators i analytics firms da blokiraju sredstva povezana sa kasnijim TraderTraitor krađama.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Pouka je dvosmerna: državni akteri koriste uobičajene komercijalne/kriminalne services, a javni blockchains omogućavaju defender-ima da prate vrednost čak i kada su imena u početku nepoznata.

## Workflow detekcije

1. **Sačuvajte sirove identifikatore transakcija i zapise.** Screenshots i zaokružene fiat vrednosti nisu dovoljne.
2. **Normalizujte asset-e i vreme.** Zabeležite chain, token contract, jedinice, block time, vremensku zonu service-a, fees i source exchange rate-a.
3. **Označite pouzdanost dokaza.** Razlikujte address koji je objavio service, deterministički contract event, clustering heuristic i external intelligence.
4. **Pratite oba smera.** Pronađite izvor finansiranja, neposredno rasipanje, ponovno spajanje, bridge exits, service deposits i spend/delivery.
5. **Povežite off-chain dokaze.** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping i communication records često razrešavaju dvosmislenost.
6. **Testirajte alternativna objašnjenja.** Exchanges, custodians, payroll i privacy protocols mogu proizvesti fan-in/out ili co-spends bez zajedničkog beneficial ownership-a.
7. **Pratite umesto da prerano zaključite slučaj.** Dormant output može postati pripisiv kada kasnije stigne do service-a.
8. **Primenu važećih sanctions/AML obaveza vršite uz pravnog savetnika.** Pravila i designations se menjaju; istorijska povezanost nije zamena za važeću pravnu analizu.

## Bezbedan red-team procurement model

Ovlašćenom timu može biti potrebno da ciljni SOC ne prepozna njegovo plaćanje hosting-a, dok engagement controller zadržava odgovornost:

- koristite engagement-specific organization card ili dokumentovani corporate wallet;
- billing, tax i provider records moraju biti tačni;
- odvojite operator-a od procurement duties i ograničite pristup attribution map-i;
- nikada ne koristite mule, false identity, stolen card, sanctions workaround ili unlicensed exchanger;
- zabeležite asset, amount, owner, service, date, refund path i teardown evidence;
- nakon vežbe otkrijte controller-u relevantne payment/provider indikatore.

Ovo stvara **slepost prema učesniku vežbe**, a ne slepost prema zakonu, provider-u ili governance-u.

## References

- [1] [US DOJ — Okvir za sprovođenje zakona u oblasti cryptocurrency-ja (primer peel-chain-a i istrage DPRK-a)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Uklanjanje ChipMixer-a](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Indikatori upozorenja za Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Predstavnik Foreign Trade Bank-a DPRK-a optužen za conspiracies u vezi sa crypto-laundering-om](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Complaint za forfeiture u vezi sa navodnih 7,74 miliona USD opranih za DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions i sredstva Lazarus-a](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Severna Koreja odgovorna za krađu sa Bybit-a 2025. godine](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Primena regulations na users, administrators i exchangers virtual currency-ja](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
