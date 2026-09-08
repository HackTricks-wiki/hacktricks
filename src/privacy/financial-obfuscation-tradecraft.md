# Finansiële obfuskasie-handelsvaardighede

Betalingsprivaatheid is ’n attribusieprobleem, nie ’n betalingshandelsmerkprobleem nie. ’n Operasie laat bewyse wanneer waarde verkry, verskuif, omgeskakel, bestee en afgelewer word. ’n Openbare-kettingadres kan pseudoniem wees, terwyl ’n exchange, kaartuitreiker, handelaar, mobiele toestel of versendingskamera die persoon daaragter identifiseer.

Hierdie bladsy verduidelik finansiële-obfuskasiepatrone wat in kubermisdaad en staatsgekoppelde operasies gebruik word, sodat verdedigers dit kan herken. Dit verskaf **nie** ’n prosedure vir geldwassery, sanksie-ontduiking, vals identiteit of KYC-omseiling nie.

## Die end-tot-end-waardegrafiek
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
'n Akteur probeer verhoed dat enige waarnemer albei kante sien. Ondersoekers doen die omgekeerde: bewaar rekords by elke grens, normaliseer tyd/waarde/fooie en identifiseer die **rekonvergensiepunt** waar afsonderlike personas een fasiliteerder, toestel, rekening, handelaar of bestemming hergebruik.

## Instrumente en hul werklike waarnemers

| Instrument | Versteek van handelaar/publiek | Steeds sigbaar vir |
|---|---|---|
| Virtuele kaart/token van uitreiker | onderliggende kaartnommer | uitreiker, netwerk-/tokenverskaffer, wallet, handelaarrekening en afleweringstelsels |
| Voorafbetaalde-/geskenkwaarde | soms wettige naam by gewone aankoop | kleinhandelaar/betalingsnetwerk, aktiverings-/inlossingsdiens, kameras, toestel en aflewering |
| Kontant | openbare grootboek en afgeleë uitreiker | teenpartye, kameras, onttrekkings-/reeksnommerkontroles waar van toepassing, fisiese deursoeking |
| Bitcoin/nuwe adres | direkte wettige naam | elke blockchain-waarnemer; wallet-/netwerk-eweknieë; verkrygings-/off-ramp-dienste |
| CoinJoin/PayJoin | eenvoudige heuristieke gebaseer op gemeenskaplike invoere/betalings | openbare transaksie, koördineerder-/eweknie-/netwerkmetadata en latere bestedingsgedrag |
| Privacy coin | openbare sender/ontvanger/bedrag, afhangend van die protokol | verkrygings-/off-ramp-diens, wallet-endpoint, netwerkwaarnemer en teenparty |
| Gesentraliseerde mixer | direkte deposito-na-onttrekkingskakel | mixer-operateur/logboeke, blockchain-in-/uitgangstelle en teenpartye |
| Cross-chain bridge/swap | kontinuïteit op een chain | albei chains, bridge-/swap-diens, tydsberekening/waarde en likiditeitsbeperkings |
| OTC/P2P-makelaar | direkte ruilrekening in sommige gevalle | makelaar, kommunikasie, bank-/kontantbeweging, teenpartye en toestelle |

## Kaarte, voorafbetaalde waarde, gevolmagtigdes en mules

### Virtuele en gemaskerde kaarte

'n Uitreiker kan 'n handelaar-geslote of weggooibare kaartnommer skep. Dit verminder die handelaar se blootstelling en hergebruik van die nommer by verskeie handelaars. Die uitreiker koppel dit steeds aan die kliënt, befondsingsrekening, toestel, IP en transaksie. Faktureringsbeskrywings, handelaarrekening, afleweringsadres en blaaierdata bly koppelbaar.

“No-name”-kaartbemarking impliseer nie anonieme vereffening nie. Gereguleerde uitreikers en verspreiders kan identiteitskontroles uitvoer, rekords behou, geografiese-/bedraglimiete toepas en op regsprosesse reageer. 'n Kaart wat deur 'n gesteelde identiteit verkry is, voeg identiteitsdiefstal by; dit verwyder nie uitreiker-/toestel-/handelaartelemetrie nie.

### Voorafbetaalde en geskenkwaarde

Voorafbetaalde kaarte en geskenkkodes skei 'n latere inlossing van die oorspronklike betaalinstrument, maar skep 'n genommerde objek met gebeurtenisse vir aankoop, aktivering, saldo-navraag en inlossing. Patrone wat saak maak, sluit in grootmaataankope, herhaalde denominasies net onder kontroles, vinnige inlossing op 'n ver plek, een toestel wat baie saldo's nagaan, of baie kaarte wat by een handelaar/rekening bymekaarkom.

### Gevolmagtigdes, geldmules en handelaarfronts

'n Gevolmagtigde of mule verskaf 'n rekening en wettige identiteit wat tussen die operateur en 'n diens staan. Netwerke kan werwers, rekeninghouers, betalingsverwerkers, dophandelaars en kontantonttrekkingsmakelaars in lae rangskik. Dit skep afstand, maar elke deelnemer voeg kommunikasie, fooie, gedragsinkonsekwentheid en 'n potensiële samewerkende getuie by. Frontmaatskappye voeg registrasie-, belasting-, bank-, direkteur-, faktuur-, hosting- en verskepingsrekords by.

Verdedigers behoort gedeelde toestelle/IP's, hergebruik van begunstigdes, geoliggingteenstrydighede, snelheid wat nie met rekeninggeskiedenis ooreenstem nie, sirkeltransfers, verskeie onverwante senders wat bymekaarkom, en onmiddellike verdere beweging te ondersoek. Moenie aanvaar dat die genoemde rekeninghouer die beherende akteur is nie; behandel hulle as 'n node waarvan die rol bepaal moet word.

## Patrone vir transaksie-obfuskasie op openbare chains

### Adresrotasie en muntbeheer

Die skep van 'n nuwe adres vir elke ontvangs verhoed eenvoudige adreshergebruik, maar transaksies kan steeds eienaarskap deur gemeenskaplike invoere, veranderingopsporing, presiese waarde/tyd en latere konsolidasie verbind. **Coin control** laat 'n wallet kies watter outputs bestee moet word en vermy die samevoeging van kompartemente. Dit verbeter higiëne; dit kan nie 'n reeds openbare skakel verwyder nie.

### Peel chains

'n Peel chain bestee herhaaldelik 'n groot saldo, stuur 'n kleiner bedrag uitwaarts en stuur die res na 'n nuwe adres terug:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Die adres verander by elke stap, maar waarde-kontinuïteit, tempo en transaksiestruktuur vorm dikwels ’n herkenbare ketting. Legitieme exchange hot wallets kan soortgelyk optree, dus vereis attribution bewyse uit die diens/konteks. DOJ het peel-chain analysis gebruik in DPRK-gekoppelde verbeurdverklaringsake.<sup>[[1]](#references)</sup>

### Structuring en fan-out/fan-in

- **Fan-out:** een bron verdeel fondse oor baie adresse om die ondersoekslas te verhoog of parallelle omskakeling voor te berei.
- **Fan-in:** baie bronne konsolideer fondse in een collector, wat gemeenskaplike beheer of ’n diens onthul.
- **Structuring:** herhaalde kleiner oordragte poog om review-drempels te vermy of by gewone volume in te skakel.
- **Commingling:** onwettige en onverwante fondse deel wallets, pools of dienste, wat simplistiese proporsionele aansprake onveilig maak.

Graph-vorm is ’n leidraad, nie bewys nie. Analysts moet rekening hou met fooie, UTXO/account model, diensgedrag en change-konvensies.

### CoinJoin en PayJoin

In ’n tipiese CoinJoin dra verskeie deelnemers inputs by en ontvang hulle outputs in een samewerkende transaksie, dikwels met gelyke output-denominasies. Dit verbreek die aanname dat elke input en output in ’n transaksie een eienaar het. Die anonymity set word beperk deur die aantal deelnemers en latere gedrag: ongelyke change, toxic change, consolidation of die kruising van ’n bekende diens kan skakels herinstel.

PayJoin wysig ’n gewone betaling sodat beide die payer en payee inputs bydra, wat die common-input ownership heuristic vir daardie transaksie direk ongeldig maak. Dit is hoofsaaklik ’n payment privacy protocol, nie ’n bulk laundering service nie. Detection moet vermy om alle inputs as mede-besit te verklaar en moet onsekerheid uitdruk eerder as om ’n valse cluster af te dwing.

### Centralized mixers en tumblers

’n Centralized mixer aanvaar deposits en betaal later verskillende coins uit ’n saamgevoegde reserwe, dikwels ná fooie en vertragings. Die privaatheid daarvan hang af van pool-grootte, withdrawal policy, logs, operator-honesty en weerstand teen seizure. Analise van entry- en exit-tydsberekening/-waarde, deposit addresses, service wallet clustering en rekords kan die stel verklein. Operators kan fondse steel of ’n volledige kartering behou.

Legal exposure is aansienlik en jurisdiction-specific. DOJ-sake teen ChipMixer, Samourai Wallet en Tornado Cash developers/operators, asook veranderende sanctions litigation, toon dat protokol-, custody-, beheer- en money-transmission-feite saak maak; ’n etiket soos “decentralized” is nie ’n legal conclusion nie.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps en bridges

Chain hopping skakel ’n asset om of beweeg dit deur ’n bridge, wat ’n een-ledger-navraag verbreek, maar nie ekonomiese kontinuïteit nie:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Ontleders korreleer bridge-kontrakte/service-deposito-addresses, transaksievolgorde, tydvenster, wisselkoers, fooie, likiditeit en unieke bedrae. Herhaalde swaps kan dubbelsinnigheid vergroot terwyl dit provider/API/wallet-telemetrie byvoeg. FATF identifiseer chain hopping, mixers, peer-to-peer-dienste en anonymity-enhanced currencies spesifiek as risiko-aanwysers wanneer dit met verdagte konteks gekombineer word.<sup>[[3]](#references)</sup>

### NFTs, dobbelary en handelaankope

Self-handel of kollusiewe NFT-trades kan fondse ’n skynbare verkoopsnarratief gee; dobbelary kan deposito’s vir onttrekkings verruil; goedere kan digitale waarde in herverkoopbare voorraad omskakel. Hierdie paaie laat marketplace-rekeninge, creator/royalty-skakels, wash-trading-grafieke, kansspel-/speelgeskiedenis, device-logs, aflewerings- en herverkoopbewyse agter. ’n Verlies of fooi is nie bewys dat herkoms verdwyn het nie.

## Privaatheidsbewarende cryptocurrencies

Privaatheidsprotokolle verskil tegnies:

- **Monero** gebruik eenmalige addresses, ring signatures en confidential amounts, wat openbare sigbaarheid van senders/ontvangers/bedrae verminder. Network-observasie, wallet-compromise, acquisition/off-ramp- en teenpartyrekords bly buite daardie on-chain-beskerming.
- **Zcash shielded pools** kan sender, ontvanger en bedrag verberg wanneer shielded-transaksies gebruik word; transparent addresses en oorgange tussen pools bly publiek, en gebruikspatrone beïnvloed die effektiewe anonymity set.
- **Bitcoin** is by verstek deursigtig. Nuwe addresses, CoinJoin, PayJoin en Lightning verander bepaalde koppelingsaannames, maar maak nie alle lae privaat nie.

Privaatheidstegnologie het wettige veiligheids- en kommersiële gebruike. Vanuit ’n ondersoeksperspektief, wanneer die ledger minder inligting verskaf, word endpoint-, diens-, netwerk- en menslike bewyse belangriker. Moet nooit bloot uit die keuse van ’n privaatheidsbewarende protokol alleen kriminaliteit aflei nie.

## DPRK multi-layer-saakmodel

Openbare DOJ-aantygings en forfeiture-aksies beskryf ’n saamgestelde proses, nie een truuk nie:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. werkers het fiktiewe/gesteelde identiteitsmateriaal en VPNs gebruik om afgeleë werk te bekom;
2. werkgewers het cryptocurrency, insluitend stablecoins, betaal;
3. fondse het in kleiner bedrae beweeg, chains of tokens gekruis, NFTs gekoop of is saamgevoeg;
4. ander gesteelde fondse het mixers binnegegaan;
5. OTC-traders en dopmaatskappye het waarde in fiat-betalings of goedere omgeskakel;
6. herhaalde fasiliteerders, rekeninge en blockchain-paaie het ondersoekers toegelaat om die lae weer aan mekaar te koppel.

Treasury het verklaar dat Lazarus Blender.io gebruik het om ’n deel van die Axie Infinity/Ronin-diefstal te verwerk, terwyl die FBI addresses gepubliseer het en bridges, exchanges, RPC-operateurs en analytics-maatskappye versoek het om fondse wat aan latere TraderTraitor-diefstalle gekoppel is, te blokkeer.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Die les is tweerigting: staatsakteurs gebruik gewone kommersiële/kriminele dienste, en openbare blockchains laat verdedigers toe om waarde te volg selfs wanneer name aanvanklik onbekend is.

## Opsporingswerkvloei

1. **Bewaar die rou transaksie-identifiseerders en rekords.** Screenshots en afgeronde fiat-waardes is onvoldoende.
2. **Normaliseer assets en tyd.** Teken chain, token-kontrak, eenhede, block-tyd, diens se tydsone, fooie en die bron van die wisselkoers aan.
3. **Etiketteer bewysvertroue.** Onderskei tussen ’n adres wat deur ’n diens gepubliseer is, ’n deterministiese kontrak-event, ’n clustering-heuristiek en eksterne intelligensie.
4. **Volg albei rigtings.** Vind die befondsingsoorsprong, onmiddellike verspreiding, herkonsentrasie, bridge-uitgange, diensdeposito’s en besteding/aflewering.
5. **Koppel off-chain-bewyse.** Account-KYC, device-, IP-, support-ticket-, API-key-, bank/betalings-, versendings- en kommunikasie-rekords los dikwels dubbelsinnigheid op.
6. **Toets alternatiewe verklarings.** Exchanges, custodians, payroll en privaatheidsprotokolle kan fan-in/out of co-spends veroorsaak sonder gemeenskaplike beneficial ownership.
7. **Monitor eerder as om voortydig af te sluit.** ’n Dormante output kan toeskryfbaar word wanneer dit later ’n diens bereik.
8. **Pas huidige sanctions/AML-verpligtinge met regsadvies toe.** Reëls en designations verander; historiese assosiasie is nie ’n plaasvervanger vir huidige regsontleding nie.

## Veilige red-team-aankoopmodel

’n Gemagtigde span mag nodig hê dat die teiken-SOC nie sy hosting-betaling herken nie, terwyl die engagement-controller aanspreeklikheid behou:

- gebruik ’n engagement-spesifieke organisasiekaart of gedokumenteerde korporatiewe wallet;
- hou billing-, belasting- en provider-rekords akkuraat;
- skei die operateur van procurement-pligte en beperk toegang tot die attribution map;
- moet nooit ’n mule, vals identiteit, gesteelde kaart, sanctions-omseiling of ongelisensieerde exchanger gebruik nie;
- teken asset, bedrag, eienaar, diens, datum, refund path en teardown-bewyse aan;
- openbaar relevante betalings/provider-aanwysers aan die controller ná die oefening.

Dit skep **blindheid teenoor die oefeningdeelnemer**, nie blindheid teenoor die wet, provider of governance nie.

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework (peel-chain-voorbeeld en DPRK-ondersoeke)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer-afsluiting](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Rooi-vlag-aanwysers vir Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Verteenwoordiger van DPRK Foreign Trade Bank aangekla in crypto-wassery-sameswerings](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Forfeiture-klag met betrekking tot $7.74 miljoen wat na bewering vir DPRK gewas is](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io-sanctions en Lazarus-fondse](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Noord-Korea verantwoordelik vir die 2025 Bybit-diefstal](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Toepassing van regulasies op virtual-currency-gebruikers, administrators en exchangers](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
