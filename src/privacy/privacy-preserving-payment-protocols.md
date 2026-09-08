# Betalingsprotokolle wat privaatheid bewaar

{{#include ../banners/hacktricks-training.md}}

Gevorderde betalingstelsels kan 'n betaler vir die merchant verberg, 'n ontvanger of bedrag vir 'n publieke grootboek verberg, of voorkom dat 'n mint 'n onttrekking aan 'n inlossing koppel. Dit is verskillende eienskappe. Geen hiervan verwyder rekords van verkryging, toestel, netwerk, aflewering, rekeningkunde, sanksies of eindpunte nie.

Die [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) verskaf 'n gestandaardiseerde `Pros`, `Cons`, stap-vir-stap `Procedure` en `Detection`-inskrywing vir elke betalingsfamilie. Hierdie bladsy brei die gevorderde protokolle uit.

{% hint style="danger" %}
Gebruik slegs wettige fondse en teenpartye. Moenie privaatheidsprotokolle gebruik om vereiste identifikasie, sanksies, belasting, bron-van-fondse-kontroles of transaksieverslagdoening te omseil nie. Moenie 'n exchange, mint of transmissiediens bedryf sonder om lisensiëring-, bewaring-, AML- en verbruikersbeskermingsverpligtinge te verstaan nie.
{% endhint %}

## Vergelyk die gevorderde opsies

| Protokol | Verberg van publiek/merchant | Vertroude of waarnemende party | Volwassenheid/beskikbaarheid |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Buitestaanders kan nie 'n herbruikbare betalingskode aan sy eenmalige uitsette koppel nie | Publieke Bitcoin-grafiek bly bestaan; wallet/index-bediener kan skanderings sien | Spesifikasie voltooi; wallet-ondersteuning wissel |
| Zcash fully shielded Orchard | Sender, ontvanger en bedrag word on-chain geënkripteer | Wallet-backend/netwerk en verkryging/off-ramp bly sigbaar | Ontplooi; shielded-ondersteuning wissel per wallet/exchange |
| GNU Taler | Merchant hoef nie die betaler se identiteit te ken nie; merchant-inkomste bly verantwoordbaar | Taler exchange/bank sien befondsing; merchant sien bestelling | Ontplooiings is geografies beperk |
| Federated Chaumian e-cash | Federation behoort nie uitgereikte note aan interne oorplasings/inlossing te koppel nie | Guardian-kworum bewaar reserwes; gateways sien grensaktiwiteit | Ontluikende gemeenskapsontplooiings |
| Lightning BOLT 12/route blinding | Verminder openbaarmaking van ontvanger/node en roete | Eindpunte, geselekteerde hops, befondsingsketting en wallet-dienste | Ondersteuning hang van die wallet af |
| Virtual card/token | Merchant ontvang 'n beperkte credential, nie 'n herbruikbare PAN nie | Issuer/netwerk behou betaler en transaksie | Volwasse en wyd beskikbaar |

## Bitcoin Silent Payments (BIP 352)

Silent Payments laat 'n ontvanger toe om een statiese betalingskode te publiseer terwyl elke sender 'n unieke Taproot-uitset aflei. 'n Eksterne kettingwaarnemer kan nie daardie uitsette direk aan die gepubliseerde kode koppel nie, en geen interaktiewe adresversoek of on-chain-kennisgewing-uitset word vereis nie. BIP 352 is gemerk as **Complete**, maar dit stel skanderingskoste bekend en is onversoenbaar met wallets wat dit nie geïmplementeer het nie.<sup>[[1]](#references)</sup>

### Ontvanger-werkvloei

1. Kies 'n onderhoude wallet wat uitdruklik BIP 352-ontvangs ondersteun; verifieer die funksie teen die wallet se huidige dokumentasie, nie 'n sosiale-media-eis nie.
2. Rugsteun die wallet-seed en Silent Payment-beskrywer/sleutelmateriaal met behulp van die wallet se gedokumenteerde herstelmetode. Toets opsporing met 'n klein testnet/mainnet-bedrag voordat jy die kode publiseer.
3. Genereer afsonderlike **labels** vir veldtogte, fakture of teenpartye waar die wallet BIP 352-labels ondersteun. Labels help met plaaslike rekeningkunde sonder om koppelbare adresse te publiseer.
4. Publiseer die statiese Silent Payment-kode oor 'n geverifieerde kanaal. Dit is herbruikbaar, maar 'n bedrieër kan hul eie kode daarvoor vervang.
5. Skandeer deur 'n plaaslike full node wanneer prakties. 'n Derdeparty-indeks-/skanderingsbediener kan versoektydsberekening of filterdata leer, selfs al kan dit nie spandeer nie.
6. Hou ontdekte UTXOs gelabel en pas dieselfde coin-control-reëls as vir gewone Bitcoin toe. Die besteding of konsolidasie daarvan kan eienaarskapsverhoudings openbaar.
7. Bevestig dat herstel betalings ontdek sonder om op 'n eksterne indeks staat te maak wat nie gerugsteun is nie.

### Sender-werkvloei

1. Bevestig dat die wallet stuur na die adresweergawe ondersteun en verifieer die ontvanger se lang statiese kode.
2. Laat die wallet die uitset saamstel; moet nooit die kode handmatig omskakel of verkort nie.
3. Hersien geselekteerde inputs noukeurig. Silent Payments verbeter ontvangeradres-privaatheid, maar sender-inputs bly op die publieke grafiek.
4. Gebruik wallet-ondersteunde fee bumping/PSBT-gedrag. BIP 352 vereis dat uitsette weer afgelei word as inputs verander, en sommige ondertekeningsmodusse is onveilig.
5. Bewaar 'n geënkripteerde kwitansie of bewys wat vir dispute/rekeningkunde benodig word.

Silent Payments los herhaalde publikasie van ontvangeradresse op. Dit verberg nie bedrag, transaksietydsberekening, sender-cluster, verkrygingsgeskiedenis of latere medebesteding nie.

## Zcash fully shielded payments

Zcash ondersteun deursigtige en shielded-waardepoele. Orchard shielded-transaksies gebruik zero-knowledge proofs sodat nodes geldigheid kan verifieer terwyl transaksiebesonderhede geënkripteer is; Unified Addresses kan verskeie ontvangertipes bevat.<sup>[[2]](#references)</sup> Privaatheid hang af van die werklike pad wat deur die wallet gekies word, nie van die eerste karakter van 'n vertoonde adres nie.

### Shielded-werkvloei

1. Kies 'n onderhoude wallet wat **shielded-by-default**-gedrag en huidige Orchard-ondersteuning duidelik identifiseer. Verifieer die aflaai en rugsteun/toets die seed.
2. Verkry ZEC wettiglik en teken basis/bron aan. 'n Exchange weet steeds van die verkryging en onttrekking.
3. Ontvang by 'n Unified Address wat deur die wallet ondersteun word, en ondersoek dan of die transaksie in 'n shielded-poel beland het. Moenie outomatiese shielding aanvaar sonder om die wallet se gedrag te bevestig nie.
4. Verkies **shielded-to-shielded**-oorplasings. Transparent-to-shielded- en shielded-to-transparent-grensbewegings openbaar publieke waardes/tydsberekening en kan bedragkorrelasie moontlik maak; die Orchard-spesifikasie meld dat besteding na 'n nie-Orchard-adres die transaksiewaarde openbaar.<sup>[[3]](#references)</sup>
5. Vermy kenmerkende heen-en-weer-transaksies met presiese bedrae en onmiddellike grensoorsteekings. Dit is privaatheidshigiëne, nie toestemming om eienaarskap of verslagdoening te verdoesel nie.
6. Gebruik die wallet se ondersteunde netwerk-privaatheidspad. Shielded-kriptografie verberg nie IP/tydsberekening van wallet-bedieners of peers nie.
7. Hou interne nakomingsrekords en gebruik viewing keys slegs vir doelbewuste oudit/openbaarmaking nadat jy die omvang daarvan verstaan.
8. Bevestig die ontvanger-wallet/exchange se ondersteuning voordat jy stuur; 'n gedwonge deursigtige ontvanger verander die privaatheidseienskap.

## GNU Taler: anonieme betaler, verantwoordbare merchant

GNU Taler is 'n oop elektroniese-betalingsprotokol wat tradisionele geldeenhede, blind signatures en gereguleerde exchange/bank-integrasie gebruik. Die ontwerp poog om kliënte anoniem teenoor merchants te hou terwyl merchants identifiseerbaar en belasbaar bly.<sup>[[4]](#references)</sup> Dit is nie 'n cryptocurrency nie, en beskikbaarheid hang af van 'n versoenbare streeks-exchange, bank, wallet en merchant.

### Gebruiker-werkvloei waar ontplooi

1. Identifiseer 'n operasionele Taler-exchange en merchant in die relevante geldeenheid/jurisdiksie; lees hul huidige bepalings, fooie, KYC- en privaatheidskennisgewings.
2. Installeer die amptelike wallet en verifieer die bron daarvan. Beskerm wallet-rugsteun/hersteldata soos kontant, omdat wallet-waarde 'n bearer asset kan wees.
3. Onttrek waarde deur die ondersteunde bank/exchange-vloei met waarheidsgetroue inligting te gebruik. Die befondsingsinstelling/exchange kan die onttrekking ken, selfs al verbreek blind signatures die direkte coin-tot-onttrekking-skakel.
4. Hersien die merchant-kontrak in die wallet: merchant-identiteit, item/opsomming, bedrag, fooie, terugbetaling- en afleweringsbepalings.
5. Betaal en bewaar die kwitansiedata wat vir terugbetaling, waarborg, rekeningkunde of belasting benodig word.
6. Moenie opsionele merchant-sessie-/rekening-identifiseerders hergebruik as merchant-onkoppelbaarheid vereis word nie.
7. Hou wallet-, netwerk- en afleweringsmetadata in die threat model; Taler se betalingskriptografie verberg nie 'n versendingsadres of gekompromitteerde eindpunt nie.

Die merchant en exchange bly verantwoordbaar, en die bedryf van enige komponent kan 'n gereguleerde betalingsdiensaktiwiteit wees.

## Federated Chaumian e-cash

Chaumian e-cash gebruik blind signatures sodat 'n mint 'n token onderteken sonder om die later gespandeerde ontblote token te sien. Fedimint versprei reserwebewaring en ondertekening oor 'n guardian-federation; die dokumentasie stel dat guardians totale reserwes/uitstaande note sien, maar nie individuele saldo's of wie binne die federation aan wie betaal het behoort te sien nie.<sup>[[5]](#references)</sup>

Dit is **custodial bearer value**. 'n Voldoende guardian-kworum beheer reserwes; federation-mislukking, oneerlike guardians, sagtewarefoute of verlore kliënttoestand kan verlies veroorsaak. Deposito's, onttrekkings en Lightning-gateways is sigbare grensgebeure en kan tydsberekening/bedrag korreleer.

### Beperkte-risiko-werkvloei

1. Gebruik slegs 'n klein bedrag wat jy kan bekostig om te verloor. Behandel publieke/onbekende federations as hoër risiko as guardians met werklike aanspreeklikheid.
2. Verifieer die federation-uitnodiging deur 'n geverifieerde kanaal en teken guardian-identiteite, kworum, jurisdiksie, fooie, herstel- en afsluitingsbeleid aan.
3. Installeer 'n onderhoude versoenbare wallet, verifieer dit en verstaan die rugsteunskema daarvan voordat jy deponeer.
4. Deponeer wettig verkreë Bitcoin deur die gedokumenteerde pad. Teken die peg-in vir rekeningkunde aan en aanvaar dat die tydsberekening/bedrag by die grens publiek of bekend is.
5. Gebruik binne die federation vars betalingsversoeke en vermy die byvoeging van rekening/klets/afleweringsidentifiseerders wat die skakel wat deur die blind signature verwyder is, herskep.
6. Vir Lightning-betalings, behandel die gateway as 'n bykomende waarnemer van fakture en grens-tydsberekening.
7. Los/inlossing/onttrekking volgens beleid, met die verwagting dat 'n kenmerkende bedrag en onmiddellike tydsberekening met 'n deposito of eksterne betaling gekorreleer kan word.
8. Hou belasting-/bron-/magtigingsrekords privaat; moenie guardians of gateways vra om aktiwiteit verkeerd voor te stel nie.

Moenie federated e-cash as trustless, self-custodial of gewaarborg anoniem beskryf nie.

## BOLT 12 offers and route blinding

BOLT 12 offers kan herbruikbaar wees sonder om 'n stabiele on-chain-adres te publiseer en kan blinded paths gebruik sodat 'n betaler nie die ontvanger se duidelike node-identiteit/-pad hoef te leer nie. Dit vul Lightning se bestaande onion routing aan, maar vervang dit nie.

Voor gebruik:

1. Bevestig dat sender- en ontvanger-wallets dieselfde huidige BOLT 12-funksies ondersteun; moenie ondersteuning uit generiese “Lightning”-handelsmerk aflei nie.
2. Verifieer die offer out-of-band en kontroleer bedrag, issuer/beskrywing en herhalingsreëls.
3. Gebruik 'n vars invoice/payment-context wat uit die offer gegenereer is.
4. Hou node aliases, publieke kontakinligting en stabiele netwerk-eindpunte minimaal.
5. Aanvaar dat sender/ontvanger, eerste/laaste hop, wallet-diens, kanaalgrafiek en on-chain-befondsing/sluiting steeds dele van die verhouding openbaar.

## Ouditbaarheid sonder publieke openbaarmaking

Privaatheid en oudit kan saam bestaan:

- Hou labels, fakture, magtiging, kostebasis en eienaarskapkartering geënkripteer buite die publieke protokol.
- Skei 'n **view/audit key** van 'n spandeersleutel wanneer die protokol een verskaf; toets eers die presiese openbaarmaking daarvan op 'n voorbeeldwallet.
- Gee aan 'n ouditeur die minimum omvangsbeperkte bewys eerder as 'n seed of onbeperkte spending credential.
- Teken sagtewareweergawe, protokol/poel, transaksie-ID of bewys, teenpartydoel en wisselkoersbron tydens transaksietyd aan.
- Definieer bewaring en verwydering eerder as om 'n permanente ongeënkripteerde identiteitsgrafiek op te bou.

## Keuringslys

- [ ] Die verborge veld en waarnemer word presies benoem.
- [ ] Wallet-/protokolondersteuning is vanaf die transaksiedatum geverifieer.
- [ ] Skakels met verkryging, netwerk, node/RPC, teenparty, aflewering en latere besteding is gedokumenteer.
- [ ] Bewarings-, herstel-, likiditeits-, issuer/federation-solvensie- en terugbetalingsrisiko's word aanvaar.
- [ ] Vereiste identiteit-, belasting-, sanksie-, bron- en organisatoriese rekords bly akkuraat.
- [ ] 'n Klein end-tot-end-toets, insluitend herstel- en ouditbewys, was suksesvol.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler-dokumentasie](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Hoe dit werk](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
