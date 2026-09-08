# Cryptocurrency-privaatheid

Cryptocurrency-privaatheid is 'n protokol- en bedryfsvraagstuk, nie 'n sinoniem vir geheimhouding of immuniteit nie. Publieke grootboeke, exchanges, wallet-bedieners, netwerkpeers, handelaars en latere transaksies stel verskillende dele van die grafiek bloot.

Begin met die [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) vir die per-tegniek-voordele/nadele/prosedure/detectie-formaat. Hierdie bladsy brei uit oor cryptocurrency-spesifieke meganika en operasionele beperkings.

{% hint style="danger" %}
Hierdie hoofstuk is vir wettige self-custody en dataminimalisering. Moenie dit gebruik om opbrengste te was, sanksies/belasting/rapportering te ontduik, met verbode partye transaksies te doen, 'n gereguleerde verskaffer te mislei, of 'n ongelisensieerde transmissiediens te bedryf nie. Privaatheidstegnologie verander nie die wettige oorsprong of eienaarskap van fondse nie.
{% endhint %}

## Bedreigingsmodel volgens laag

| Laag | Waarnemer | Algemene openbaarmaking |
|---|---|---|
| Verkryging/off-ramp | Exchange, bank, makelaar, P2P-teenparty | Identiteit, befondsingsrekening, bestemming, toestel, IP, tyd |
| Grootboek | Enigiemand wat analytics uitvoer | Adresse/uitsette, bedrae en tyd op deursigtige kettings; protokolspesifieke metadata elders |
| Wallet-backend | RPC-verskaffer, explorer, afgeleë node | Adresnavrae, saldo's, IP, transaksie-uitsending |
| Netwerk | ISP, peers, anonimiteitsnetwerk-ingang | IP, tydsberekening, volume en protokolgebruik |
| Teenparty | Betaler/begunstigde | Faktuur/adres, aflewering, gesprek, rekening en tydsberekening |
| Eindpunt | Malware, cloud-rugsteun, fisiese beslaglegging | Seed, sleutels, etikette, geskiedenis, skermkiekies en clipboard |

Self-custody kan 'n bewaarder uit die beheerpadaanwyser verwyder, maar dit wis nie die grootboek, verkrygingsrekord, netwerkmetadata of eindpuntbewyse uit nie.

## Protokolvergelyking

| Metode | Nuttige privaatheidseienskap | Belangrike beperkings |
|---|---|---|
| Bitcoin on-chain | Self-custody; vars adresse vermy eenvoudige adreshergebruik | Publieke permanente transaksiegrafiek; bedrag/tydsberekening en bestedingsheuristieke |
| Bitcoin PayJoin | Ontvangerinset kan die algemene-inset-eienaarskapheuristiek verbreek | Albei wallets moet ondersteuning hê; transaksie bly publiek; ondersteuning is ongelyk |
| Bitcoin CoinJoin | Skep dubbelsinnigheid onder gekoördineerde deelnemers | Herkenbare patrone, voor-/naskakels, konsolidasie, beleid/wetlike/verskafferrisiko |
| Lightning | Onion-gerouteerde betalings word nie wêreldwyd as gewone oordragte gepubliseer nie | Kanale word on-chain oopgemaak/gesluit; eindpunte, peers, probes of bewaarder kan data aflei |
| Monero | Sterker verstek-on-chain-vertroulikheid vir ontvanger, bedrag en senderstel | Exchange-, node-, tydsberekening-, eindpunt- en teenpartyskakels bly bestaan |
| Ethereum/stablecoins | Wye beskikbaarheid en interoperabiliteit met smart contracts | Publieke toestand/aksies; RPC-metadata; gesentraliseerde uitreikers kan blokkeer/vries/rapporteer |

## Bitcoin: privaatheidsbewarende basislyn

Bitcoin is pseudoniem, nie anoniem nie. Bevestigde transaksies is publiek en duursaam; adreshergebruik, algemene-inset-eienaarskap, veranderingdeteksie en publiek geïdentifiseerde adresse kan klusters bou.<sup>[[1]](#references)</sup>

### Werkvloei

1. **Kies 'n onderhoude self-custody-wallet.** Laai dit van die amptelike projek af, verifieer handtekeninge/hashes wanneer dit aangebied word, en pas sekuriteitsopdaterings toe.
2. **Skep die wallet op 'n betroubare eindpunt.** Teken die recovery seed offline aan; plaas dit nooit in e-pos, chat, skermkiekies of gewone cloud-notas nie. Toets herstel voordat jy beduidende waarde hou.
3. **Hou slegs operasionele waarde hot.** Gebruik geskikte offline/hardware-custody vir langtermynwaarde, met 'n herstelplan wat nie die seed aan 'n enkele kwesbare ligging blootstel nie.
4. **Genereer 'n vars ontvangadres/faktuur vir elke transaksie.** Moenie 'n statiese adres publiseer wanneer 'n faktuurbediener of geverifieerde private aflewering moontlik is nie.
5. **Gebruik jou eie full node wanneer dit haalbaar is.** 'n Derdeparty-explorer/Electrum-bediener kan navraagde adresse en IP-metadata leer. Stel slegs wallet-ondersteunde Tor/proxy-gedrag op; Tor versteek 'n netwerkrand, nie die blockchain-grafiek nie.
6. **Merk elke UTXO privaat** met bron, eienaar, doel en nakomingstoestand. Aktiveer coin control sodat onverwante identiteitskontekste nie saam bestee word nie.
7. **Voorskou die transaksie:** geselekteerde insette, veranderingsbestemming, bedrag, fooi, teenparty en of die besteding kompartemente saamsmelt. Vermy onnodige konsolidasie.
8. **Hou wettige rekords apart en geënkripteer.** Bewaar verkrygingsbasis, fakture, magtiging en belasting-/rapporteringinligting sonder om die kartering te publiseer.
9. **Behandel latere besteding as deel van dieselfde privaatheidsbesluit.** 'n Goed geskeide ontvangs kan herkoppel word wanneer sy uitset saam met geïdentifiseerde fondse bestee word.

Bitcoin Core se privaatheidsdokumentasie verduidelik dat 'n full node voorkom dat wallet-navrae aan derdeparty-bedieners blootgestel word, maar dat transaksie-uitsending en publieke geskiedenis steeds ontleding vereis.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin is 'n samewerkende betaling waarin die ontvanger 'n inset byvoeg. Dit verydel die simplistiese aanname dat alle insette aan die sender behoort. BIP 78 beskryf die oorspronklike interaktiewe protokol; konsep-BIP 77 definieer 'n asinchroniese v2-ontwerp wat 'n geënkripteerde posbus/OHTTP gebruik.<sup>[[3]](#references)</sup>

Veilige gebruik:

1. Bevestig dat albei onderhoude wallets dieselfde PayJoin-weergawe ondersteun.
2. Verkry die PayJoin-bekwame faktuur oor 'n geverifieerde kanaal; beskerm dit soos enige betalingsversoek.
3. Kontroleer die oorspronklike bedrag en bestemming, en laat die wallet die voorstel/PSBT, fooi-bydrae en verbode vervangings valideer.
4. Bevestig die finale wallet-opsomming. Moenie 'n onverwagte uitset, bedrag of buitensporige fooi handmatig goedkeur nie.
5. Indien onderhandeling misluk, verstaan of die wallet veilig na 'n gewone betaling terugval en of 'n nuwe faktuur vereis word.
6. Behou die private ontvangs/rekords wat vir eienaarskap, boekhouding en dispute vereis word.

PayJoin verbeter een blockchain-analiseheuristiek; dit verberg nie die betaling vir die partye, verkrygingsplatform, eindpunte of publieke grootboek nie.

## CoinJoin: voordele en beperkings

CoinJoin koördineer verskeie gebruikers in een transaksie om inset-na-uitset-kartering minder seker te maak. Navorsing oor spesifieke historiese Wasabi- en Samourai-ontwerpe het hoogs herkenbare transaksies gevind en getoon dat voor-/nasmeltgedrag anonimiteit aansienlik kan vernou.<sup>[[4]](#references)</sup> Daardie resultaat moet nie na elke implementering of toekomstige weergawe veralgemeen word nie, maar dit demonstreer waarom 'n “anonymity-set”-nommer nie 'n waarborg is nie.

Voor enige wettige gebruik:

- kontroleer huidige plaaslike wetgewing, sanksiestatus, exchange-/bewaarderbeleid en belasting-/rapporteringpligte;
- gebruik onderhoude, nie-bewarende sagteware wat van die amptelike projek verkry is;
- verstaan die koördineerdermodel, fooie, diensweieringsbeheermaatreëls en of die huidige diens nog bedryf word—zkSNACKs het sy koördineerder in 2024 beëindig, hoewel ander Wasabi-koördineerders kan bestaan;
- bewaar bron-van-fondse- en transaksie-rekords privaat;
- aanvaar nooit onbekende fondse namens iemand anders nie en gebruik nie 'n bewarende “mixer” wat onnaspeurbare onttrekkings belowe nie;
- hou uitsette volgens bron/konteks geskei en vermy latere konsolidasie wat die bedoelde dubbelsinnigheid vernietig.

Wetlike uitkomste is feit- en jurisdiksiespesifiek. Die 2025-Samourai-skuldigpleitings het gehandel oor die wetende bedryf van 'n ongelisensieerde geldoordraer wat kriminele opbrengste verskuif het; dit bepaal nie dat elke samewerkende transaksie of gebruiker wat privaatheid nastreef krimineel is nie.<sup>[[5]](#references)</sup>

## Lightning Network

Lightning se Sphinx-onion-routing is ontwerp sodat 'n tussengangerhop sy voorganger en opvolger leer, eerder as die hele roete.<sup>[[6]](#references)</sup> Dit is nie omvattende anonimiteit nie: kanaalbefondsing/-sluiting is publiek, nodes adverteer topologie, teenpartye ken eindpunte, routing/probing kan saldo's of partye aflei, en 'n bewarende wallet sien sy gebruiker se rekeningaktiwiteit.

Vir beter privaatheid:

1. Verkies 'n onderhoude nie-bewarende wallet indien tussengangerprivaatheid belangrik is; beplan eers kanaalrugsteun/herstel.
2. Gebruik 'n vars faktuur of offer vir elke betaling. Verifieer of die presiese wallet BOLT 12/route blinding ondersteun, eerder as om dit te aanvaar.
3. Vermy die publikasie van onnodige node-aliasse, kontakbesonderhede en stabiele netwerk-eindpunte.
4. Koppel deur 'n ondersteunde privaatheidsnetwerk indien toepaslik, met die begrip dat uptime-/tydsberekeningspatrone steeds kan korreleer.
5. Moenie aflei dat 'n off-chain-betaling geen rekords het nie: sender, ontvanger, peers, watchtowers, likiditeitsverskaffers en wallet-dienste kan waarnemings behou.

Gepubliseerde navorsing het sender-/ontvanger- en kanaalsaldo-afleiding uit publieke data en aktiewe probing gedemonstreer, hoewel aanvalle en versagtings ontwikkel.<sup>[[7]](#references)</sup>

## Monero

Monero gebruik eenmalige stealth addresses vir uitsette, RingCT om bedrae te verberg, en ring signatures om waarskynlikheidsgebaseerde senderdubbelsinnigheid te verskaf; sy huidige tegniese spesifikasies dokumenteer 'n ringgrootte van 16 (15 decoys).<sup>[[8]](#references)</sup> Dit is sterker verstekke vir on-chain-vertroulikheid as deursigtige grootboeke, nie magiese beskerming teen eindpunt- of operasionele foute nie.

### Wettige werkvloei

1. **Verkry dit wettig.** 'n Gereguleerde exchange kan die aankoop en onttrekking ken, selfs wanneer latere on-chain-besonderhede vertroulik is. Hou bron-, basis- en rapporteringsrekords.
2. **Installeer die amptelike onderhoude wallet** en verifieer die aflaai volgens projekinstruksies. Rugsteun die seed offline en toets herstel met 'n klein bedrag.
3. **Verkies 'n plaaslike node** vir maksimum wallet-navraagprivaatheid. Indien dit onprakties is, kies 'n betroubare afgeleë node wat deur 'n amptelik ondersteunde onion/I2P-konfigurasie bereikbaar is. 'n Afgeleë node kan IP, versoeke, tydsberekening en transaksie-ID's aanteken; sommige lightweight-ontwerpe openbaar 'n view key.
4. **Gebruik 'n nuwe subaddress per betaler, veldtog of faktuur.** 'n Betaler kan herhaalde gebruik van dieselfde subaddress korreleer.<sup>[[9]](#references)</sup>
5. **Merk inkomende kontekste plaaslik.** Vermy die operasionele samesmelting van geskeide ontvangste waar 'n ingeligte betaler daaropvolgende gedrag kan herken.
6. **Beskerm netwerkmetadata.** Volg die amptelike anonimiteitsnetwerkkonfigurasie; herken gedokumenteerde leaks van tydstempels, intermitterende sinchronisasie, bandwydtevorm en stroomhergebruik.<sup>[[10]](#references)</sup>
7. **Hou nakomings-/ouditdata privaat.** Openbaar 'n view key of transaksiebewys slegs doelbewus, aan die bedoelde ouditeur/party, en verstaan presies wat dit openbaar.

Historiese naspeurbaarheidstudies sluit foute en decoy-seleksie-eras in wat sedertdien verander het; moenie ou suksespersentasies op huidige transaksies toepas nie. Net so bly FCMP++ roadmap-werk vanaf hierdie hoofstuk se navorsingsafsnydatum in September 2026, nie 'n ontplooide beskerming nie.<sup>[[11]](#references)</sup>

## Ethereum en stablecoins

Ethereum se eie privaatheidsmateriaal merk op dat on-chain-aksies sigbaar is en dat wallet-/RPC-infrastruktuur IP- en metadata-blootstelling byvoeg.<sup>[[12]](#references)</sup> Token-oordragte, goedkeurings, smart-contract-interaksies, naamdienste en gasbefondsing kan almal identiteite verbind.

Gesentraliseerde stablecoins voeg uitreikerbeheer by. Huidige USDC- en Tether-voorwaardes behou magte voor om adresse of bates te blokkeer/vries en aan wetlike/prosesverpligtinge te voldoen.<sup>[[13]](#references)</sup> Hulle kan nuttige betalingsinstrumente wees, maar is swak keuses wanneer die vereiste sensuurweerstand of on-chain-anonimiteit is.

## Nakomingsgrense

- FATF-aanbevelings word deur nasionale wetgewing geïmplementeer en verander met verloop van tyd; die 2026-opdatering beklemtoon VASP-lisensiëring/registrasie en Travel Rule-implementering.<sup>[[14]](#references)</sup>
- In die VSA onderskei FinCEN tussen 'n persoon wat convertible virtual currency vir hul eie goedere/dienste gebruik en 'n besigheid wat dit aanvaar en oordra of ruil; feite en latere reëls is belangrik.<sup>[[15]](#references)</sup>
- Die EU Transfer of Funds Regulation vereis oorsprongsteller-/begunstigde-inligting waar 'n crypto-asset service provider betrokke is en voeg verifikasiereëls by vir sekere oordragte na/van self-hosted adresse.<sup>[[16]](#references)</sup>
- Sanksies en belastingpligte bly van toepassing. Sift soos vereis, weier verbode partye en hou rekords; lyste en wetlike status kan vinnig verander.<sup>[[17]](#references)</sup>

Verkry huidige professionele advies vir die relevante jurisdiksies voordat jy beduidende waarde, oorgrensaktiwiteit, privaatheidsversterkende koördinering of besigheidsagtige ruil/oordrag aanpak.

Vir Bitcoin Silent Payments, volledig shielded Zcash, GNU Taler, gefedereerde Chaumian e-cash en BOLT 12, gaan voort na [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Beskerm jou privaatheid](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privaatheidskenmerke](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — 'n Eenvoudige PayJoin-voorstel](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Aanvaarding en werklike privaatheid van gedesentraliseerde CoinJoin-implementerings in Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Stigters van Samourai Wallet pleit skuldig (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion-routing-protokol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — 'n Empiriese ontleding van privaatheid in die Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html), en [Tegniese spesifikasies](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Netwerke](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Ondersoek na die evolusie van Monero se privaatheid (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privaatheid op Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC-voorwaardes](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — 2026-gefokusde opdatering oor virtuele bates en VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Toepassing van FinCEN se regulasies op persone wat virtuele geldeenhede administreer, ruil of gebruik](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulasie (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Sanksienakomingsriglyne vir die virtuele-geldeenheidbedryf](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
