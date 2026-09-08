# Finansiële Obfuskasie-Tradecraft

{{#include ../banners/hacktricks-training.md}}

Betalingsprivaatheid is ’n attribusieprobleem, nie ’n betalingshandelsmerkprobleem nie. ’n Operasie laat bewyse agter wanneer waarde verkry, verskuif, omgeskakel, bestee en afgelewer word. ’n Adres op ’n publieke chain kan pseudoniem wees, terwyl ’n exchange, kaartuitreiker, handelaar, mobiele toestel of versendingskamera die persoon daaragter identifiseer.

Hierdie bladsy verduidelik finansiële-obfuskasiepatrone wat in kubermisdaad en staatsgekoppelde operasies gebruik word, sodat verdedigers dit kan herken. Dit verskaf **nie** ’n prosedure vir geldwassery, sanksie-ontduiking, vals identiteite of KYC-omseiling nie.

## Die end-tot-end-waardegrafiek
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
’n Akteur probeer verhoed dat enige waarnemer albei kante sien. Ondersoekers doen die omgekeerde: bewaar rekords by elke grens, normaliseer tyd/waarde/fooie en identifiseer die **reconvergence point** waar afsonderlike personas een fasiliteerder, toestel, rekening, handelaar of bestemming hergebruik.

## Instruments en hul werklike waarnemers

| Instrument | Versteek van handelaar/publiek | Steeds sigbaar vir |
|---|---|---|
| Issuer virtual card/token | onderliggende kaartnommer | issuer, network/token provider, wallet, merchant account en delivery systems |
| Prepaid/gift value | soms wettige naam by gewone aankoop | retailer/payment rail, activation/redemption service, cameras, device en delivery |
| Cash | openbare grootboek en afgeleë issuer | counterparties, cameras, withdrawal/serial controls waar van toepassing, physical search |
| Bitcoin/new address | direkte wettige naam | elke blockchain observer; wallet/network peers; acquisition/off-ramp services |
| CoinJoin/PayJoin | eenvoudige common-input/payment heuristics | public transaction, coordinator/peer/network metadata en later spending behavior |
| Privacy coin | openbare sender/receiver/amount, afhangend van die protocol | acquisition/off-ramp, wallet endpoint, network observer en counterparty |
| Centralized mixer | direkte deposit-to-withdraw link | mixer operator/logs, blockchain entry/exit sets en counterparties |
| Cross-chain bridge/swap | kontinuïteit op een chain | albei chains, bridge/swap service, timing/value en liquidity constraints |
| OTC/P2P broker | direkte exchange account in sommige gevalle | broker, communications, bank/cash movement, counterparties en devices |

## Cards, prepaid value, nominees en mules

### Virtual en masked cards

’n Issuer kan ’n merchant-locked of disposable card number skep. Dit verminder merchant exposure en hergebruik van die nommer oor verskillende handelaars. Die issuer koppel dit steeds aan die customer, funding account, device, IP en transaction. Billing descriptors, merchant account, shipping address en browser data bly koppelbaar.

“No-name”-kaartbemarking impliseer nie anonymous settlement nie. Regulated issuers en distributors kan identity checks uitvoer, rekords behou, geography/amount limits toepas en op legal process reageer. ’n Kaart wat deur middel van ’n stolen identity verkry is, voeg identity theft by; dit verwyder nie issuer/device/merchant telemetry nie.

### Prepaid en gift value

Prepaid cards en gift codes skei ’n latere redemption van die oorspronklike payment instrument, maar skep ’n genommerde objek met purchase-, activation-, balance-query- en redemption-events. Patrone wat saak maak, sluit in bulk purchases, herhaalde denominations net onder controls, vinnige redemption op ’n verafgeleë plek, een device wat baie balances nagaan, of baie cards wat by een merchant/account saamkom.

### Nominees, money mules en merchant fronts

’n Nominee of mule verskaf ’n rekening en legal identity wat tussen die operator en ’n service staan. Networks kan recruiters, account holders, payment processors, shell merchants en cash-out brokers in lae rangskik. Dit skep afstand, maar elke deelnemer voeg communications, fees, behavioral inconsistency en ’n moontlike cooperating witness by. Front companies voeg incorporation-, tax-, banking-, director-, invoice-, hosting- en shipment records by.

Defenders behoort shared devices/IPs, beneficiary reuse, geolocation contradictions, velocity wat nie met account history ooreenstem nie, circular transfers, verskeie onverwante senders wat saamkom, en onmiddellike onward movement te ondersoek. Moenie aanvaar dat die named account holder die controlling actor is nie; behandel hulle as ’n node waarvan die rol bepaal moet word.

## Public-chain transaction-obfuscation patterns

### Address rotation en coin control

Die skep van ’n nuwe address vir elke receipt voorkom eenvoudige address reuse, maar transactions kan steeds ownership verbind deur common inputs, change detection, exact value/time en latere consolidation. **Coin control** laat ’n wallet kies watter outputs om te spend en voorkom dat compartments saamgevoeg word. Dit verbeter hygiene; dit kan nie ’n reeds openbare link verwyder nie.

### Peel chains

’n Peel chain spandeer herhaaldelik ’n groot balance, stuur ’n kleiner amount outward en stuur die remainder terug na ’n nuwe address:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Die adres verander by elke stap, maar waardekontinuïteit, tempo en transaksiestruktuur vorm dikwels ’n herkenbare ketting. Wettige exchange hot wallets kan soortgelyk optree, dus vereis toeskrywing diens-/kontekstevidensie. DOJ het peel-chain-analise in DPRK-gekoppelde verbeurdverklaringsake gebruik.<sup>[[1]](#references)</sup>

### Structuring en fan-out/fan-in

- **Fan-out:** een bron verdeel fondse na baie adresse om die ondersoekwerklading te verhoog of parallelle omskakeling voor te berei.
- **Fan-in:** baie bronne konsolideer fondse by een versamelaar, wat gemeenskaplike beheer of ’n diens onthul.
- **Structuring:** herhaalde kleiner oordragte probeer hersieningsdrempels vermy of by gewone volume inskakel.
- **Commingling:** onwettige en onverwante fondse deel wallets, pools of dienste, wat simplistiese proporsionele bewerings onveilig maak.

Grafiekvorm is ’n leidraad, nie bewys nie. Ontleders moet rekening hou met fooie, UTXO/account model, diensgedrag en change-konvensies.

### CoinJoin en PayJoin

In ’n tipiese CoinJoin dra verskeie deelnemers inputs by en ontvang hulle outputs in een samewerkende transaksie, dikwels met gelyke output-denominasies. Dit verbreek die aanname dat elke input en output in ’n transaksie een eienaar het. Die anonimiteitstel word beperk deur die aantal deelnemers en latere gedrag: ongelyke change, toksiese change, konsolidasie of die kruising van ’n bekende diens kan skakels weer instel.

PayJoin verander ’n gewone betaling sodat beide die betaler en ontvanger inputs bydra, wat die algemene heuristiek van gemeenskaplike input-eienaarskap vir daardie transaksie direk ongeldig maak. Dit is hoofsaaklik ’n betalingsprivaatheidsprotokol, nie ’n grootmaat-wassingsdiens nie. Opsporing moet vermy om alle inputs as mede-besit te verklaar en moet onsekerheid uitdruk eerder as om ’n vals cluster af te dwing.

### Gesentraliseerde mixers en tumblers

’n Gesentraliseerde mixer aanvaar deposits en betaal later verskillende coins uit ’n saamgevoegde reserwe, dikwels ná fooie en vertragings. Die privaatheid daarvan hang af van poolgrootte, withdrawal-beleid, logs, operateur-eerlikheid en weerstand teen beslaglegging. Ontleding van intree- en uittreetydsberekening/-waarde, deposit-adresse, diens-wallet-clustering en rekords kan die stel verklein. Operateurs kan fondse steel of ’n volledige kartering behou.

Regsrisiko is aansienlik en jurisdiksiespesifiek. DOJ-sake teen ChipMixer, Samourai Wallet en Tornado Cash-ontwikkelaars/-operateurs, asook veranderende sanksie-litigasie, toon dat protokol-, bewaring-, beheer- en geldtransmissie-feite saak maak; ’n etiket soos “decentralized” is nie ’n regsgevolgtrekking nie.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps en bridges

Chain hopping omskep ’n bate of beweeg dit deur ’n bridge, wat ’n een-grootboek-navraag verbreek, maar nie ekonomiese kontinuïteit nie:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Analiste korreleer bridge contracts/service-depositadresse, transaksievolgorde, tydsvenster, wisselkoers, fooie, likiditeit en unieke bedrae. Herhaalde swaps kan dubbelsinnigheid vergroot terwyl provider/API/wallet-telemetrie bygevoeg word. FATF identifiseer spesifiek chain hopping, mixers, peer-to-peer services en anonymity-enhanced currencies as risiko-aanwysers wanneer dit met verdagte konteks gekombineer word.<sup>[[3]](#references)</sup>

### NFTs, dobbelary en handelaaraankope

Selfhandel of kollusiewe NFT-trades kan fondse 'n oënskynlike verkoopsnarratief gee; dobbelary kan deposits vir withdrawals ruil; goedere kan digitale waarde in herverkoopbare voorraad omskep. Hierdie paaie laat marketplace-rekeninge, creator/royalty-skakels, wash-trading-grafieke, odds/play-geskiedenis, toestel-logboeke, aflewerings- en herverkoopbewyse agter. 'n Verlies of fooi is nie bewys dat provenance verdwyn het nie.

## Privaatheidsbewarende cryptocurrencies

Privacy protocols verskil tegnies:

- **Monero** gebruik eenmalige adresse, ring signatures en confidential amounts, wat publieke sigbaarheid van sender/ontvanger/bedrag verminder. Network observation, wallet compromise, acquisition/off-ramp en counterparty records bly buite daardie on-chain protections.
- **Zcash shielded pools** kan sender, ontvanger en bedrag verberg wanneer shielded transactions gebruik word; transparent addresses en oorgange tussen pools bly publiek, en gebruikspatrone beïnvloed die effektiewe anonymity set.
- **Bitcoin** is by verstek deursigtig. Nuwe adresse, CoinJoin, PayJoin en Lightning verander bepaalde linkage assumptions, maar maak nie alle lae private nie.

Privacy technology het wettige veiligheids- en kommersiële gebruike. Vanuit 'n ondersoeksperspektief, wanneer die ledger minder inligting verskaf, word endpoint-, service-, network- en human evidence belangriker. Moet nooit criminality aflei slegs uit die keuse van 'n privacy-preserving protocol nie.

## DPRK multi-layer case model

Openbare DOJ allegations en forfeiture actions beskryf 'n saamgestelde proses, nie een truuk nie:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workers het fictitious/stolen identity material en VPNs gebruik om remote employment te verkry;
2. employers het cryptocurrency, insluitend stablecoins, betaal;
3. fondse het in kleiner bedrae beweeg, chains of tokens gekruis, NFTs gekoop of saamgevoeg;
4. ander stolen funds het mixers binnegegaan;
5. OTC traders en front companies het waarde in fiat payments of goedere omskep;
6. herhaalde facilitators, rekeninge en blockchain paths het ondersoekers toegelaat om die lae weer te herkoppel.

Treasury het verklaar dat Lazarus Blender.io gebruik het om 'n deel van die Axie Infinity/Ronin theft te verwerk, terwyl die FBI addresses gepubliseer het en bridges, exchanges, RPC operators en analytics firms aangespoor het om fondse wat aan latere TraderTraitor thefts gekoppel is, te blokkeer.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Die les is bidirectional: state actors gebruik gewone kommersiële/criminal services, en public blockchains laat defenders toe om waarde te volg selfs wanneer name aanvanklik onbekend is.

## Detection workflow

1. **Preserveer die raw transaction identifiers en records.** Screenshots en afgeronde fiat values is onvoldoende.
2. **Normaliseer assets en tyd.** Teken chain, token contract, units, block time, service time zone, fees en exchange-rate source aan.
3. **Label evidence confidence.** Onderskei tussen 'n service-published address, deterministic contract event, clustering heuristic en external intelligence.
4. **Traceer albei rigtings.** Vind funding origin, immediate dispersal, reconvergence, bridge exits, service deposits en spend/delivery.
5. **Join off-chain evidence.** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping en communication records los dikwels dubbelsinnigheid op.
6. **Toets alternative explanations.** Exchanges, custodians, payroll en privacy protocols kan fan-in/out of co-spends voortbring sonder common beneficial ownership.
7. **Monitor eerder as om voortydig af te sluit.** 'n Dormant output kan attributable word wanneer dit later 'n service bereik.
8. **Pas current sanctions/AML obligations met counsel toe.** Rules en designations verander; historical association is nie 'n plaasvervanger vir current legal analysis nie.

## Safe red-team procurement model

'n Gemagtigde span mag nodig hê dat die target SOC nie sy hosting payment herken nie, terwyl die engagement controller accountability behou:

- gebruik 'n engagement-specific organization card of documented corporate wallet;
- hou billing, tax en provider records akkuraat;
- skei die operator van procurement duties en beperk access tot die attribution map;
- moet nooit 'n mule, false identity, stolen card, sanctions workaround of unlicensed exchanger gebruik nie;
- teken asset, amount, owner, service, date, refund path en teardown evidence aan;
- disclose relevante payment/provider indicators aan die controller ná die oefening.

Dit skep **blindness to the exercise participant**, nie blindness to law, provider of governance nie.

## References

- [1] [US DOJ — Cryptocurrency Enforcement Framework (peel-chain example and DPRK investigations)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — ChipMixer takedown](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Forfeiture complaint concerning $7.74 million allegedly laundered for DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Blender.io sanctions and Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — North Korea responsible for the 2025 Bybit theft](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Application of regulations to virtual-currency users, administrators and exchangers](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
