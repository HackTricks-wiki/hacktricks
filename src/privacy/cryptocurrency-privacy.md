# Cryptocurrency-privaatheid

{{#include ../banners/hacktricks-training.md}}

Cryptocurrency-privaatheid is 'n protokol- en bedryfsvraagstuk, nie 'n sinoniem vir geheimhouding of immuniteit nie. Publieke grootboeke, exchanges, wallet servers, netwerk-peers, handelaars en latere transaksies stel verskillende dele van die grafiek bloot.

Begin met die [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) vir die per-tegniek-voordele/nadele/prosedure/detection-formaat. Hierdie bladsy brei cryptocurrency-spesifieke meganika en operasionele beperkings uit.

{% hint style="danger" %}
Hierdie hoofstuk is vir wettige self-custody en dataminimalisering. Moenie dit gebruik om opbrengste te was, sanksies/belasting/rapportering te ontduik, met verbode partye transaksies te doen, 'n gereguleerde verskaffer te mislei of 'n ongelisensieerde transmissiediens te bedryf nie. Privaatheidstegnologie verander nie die wettige oorsprong of eienaarskap van fondse nie.
{% endhint %}

## Bedreigingsmodel volgens laag

| Laag | Waarnemer | Algemene blootstelling |
|---|---|---|
| Verkryging/off-ramp | Exchange, bank, broker, P2P-teenparty | Identiteit, befondsingsrekening, bestemming, toestel, IP, tyd |
| Grootboek | Enigiemand wat analytics uitvoer | Adresse/outputs, bedrae en tyd op deursigtige chains; protokolspesifieke metadata elders |
| Wallet backend | RPC-verskaffer, explorer, remote node | Adresnavrae, saldo's, IP, transaksie-uitsending |
| Netwerk | ISP, peers, anonymity-network entry | IP, tydsberekening, volume en protokolgebruik |
| Teenparty | Betaler/begunstigde | Invoice/adres, aflewering, gesprek, rekening en tydsberekening |
| Endpoint | Malware, cloud-backup, fisiese beslaglegging | Seed, sleutels, etikette, geskiedenis, screenshots en clipboard |

Self-custody kan 'n custodian uit die beheerpad verwyder, maar vee nie die grootboek, verkrygingsrekord, netwerkmetadata of endpoint-bewyse uit nie.

## Protokolvergelyking

| Metode | Nuttige privaatheidseienskap | Belangrike beperkings |
|---|---|---|
| Bitcoin on-chain | Self-custody; vars adresse vermy eenvoudige adreshergebruik | Publieke permanente transaksiegrafiek; bedrag/timing en bestedingsheuristieke |
| Bitcoin PayJoin | Receiver input kan die common-input-ownership-heuristic verbreek | Albei wallets moet dit ondersteun; transaksie bly publiek; ondersteuning is ongelyk |
| Bitcoin CoinJoin | Skep dubbelsinnigheid onder gekoördineerde deelnemers | Herkenbare patrone, pre/post-skakels, konsolidasie, beleids-/regs-/verskafferrisiko |
| Lightning | Onion-gerouteerde betalings word nie wêreldwyd as gewone transfers gepubliseer nie | Channels open/close on-chain; endpoints, peers, probes of custodian kan data aflei |
| Monero | Sterker verstek-on-chain-vertroulikheid vir ontvanger, bedrag en senderstel | Exchange-, node-, tydsberekening-, endpoint- en teenpartyskakels bly bestaan |
| Ethereum/stablecoins | Wye beskikbaarheid en smart-contract-interoperabiliteit | Publieke state/actions; RPC-metadata; gesentraliseerde issuers kan blokkeer/freeze/rapporteer |

## Bitcoin: privaatheidsbehoudende basislyn

Bitcoin is pseudoniem, nie anoniem nie. Bevestigde transaksies is publiek en duursaam; adreshergebruik, common-input ownership, change detection en publiek geïdentifiseerde adresse kan clusters bou.<sup>[[1]](#references)</sup>

### Werksvloei

1. **Kies 'n onderhoude self-custody-wallet.** Laai dit van die amptelike projek af, verifieer signatures/hashes wanneer dit aangebied word, en pas security updates toe.
2. **Skep die wallet op 'n betroubare endpoint.** Teken die recovery seed offline aan; plaas dit nooit in e-pos, chat, screenshots of gewone cloud-notas nie. Toets recovery voor beduidende waarde.
3. **Hou slegs operasionele waarde hot.** Gebruik geskikte offline/hardware-custody vir langtermynwaarde, met 'n recovery plan wat nie die seed aan een enkele kwesbare ligging blootstel nie.
4. **Genereer 'n vars receive address/invoice vir elke transaksie.** Moenie 'n statiese adres publiseer wanneer 'n invoice server of geauthentiseerde private aflewering moontlik is nie.
5. **Gebruik jou eie full node waar uitvoerbaar.** 'n Derdeparty-explorer/electrum-server kan navraagde adresse en IP-metadata leer. Stel slegs wallet-ondersteunde Tor/proxy-gedrag op; Tor verberg 'n netwerkedge, nie die blockchain-grafiek nie.
6. **Etiketteer elke UTXO privaat** met bron, eienaar, doel en compliance-status. Aktiveer coin control sodat onverwante identiteitskontekste nie saam bestee word nie.
7. **Voorskou die transaksie:** geselekteerde inputs, change-bestemming, bedrag, fooi, teenparty en of die besteding kompartemente saamsmelt. Vermy onnodige konsolidasie.
8. **Hou wettige rekords apart en geënkripteer.** Bewaar verkrygingsbasis, fakture, magtiging en belasting-/rapporteringinligting sonder om die koppeling te publiseer.
9. **Behandel latere besteding as deel van dieselfde privaatheidsbesluit.** 'n Goed geskeide ontvangs kan herkoppel word wanneer sy output saam met geïdentifiseerde fondse bestee word.

Bitcoin Core se privaatheidsdokumentasie verduidelik dat 'n full node voorkom dat wallet-navrae aan derdepartydienste blootgelê word, maar dat transaksie-uitsending en publieke geskiedenis steeds ontleding vereis.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin is 'n samewerkende betaling waarin die ontvanger 'n input byvoeg. Dit verydel die simplistiese aanname dat alle inputs aan die sender behoort. BIP 78 beskryf die oorspronklike interaktiewe protokol; draft BIP 77 definieer 'n asynchronous v2-ontwerp wat 'n geënkripteerde mailbox/OHTTP gebruik.<sup>[[3]](#references)</sup>

Veilige gebruik:

1. Bevestig dat albei onderhoude wallets dieselfde PayJoin-weergawe ondersteun.
2. Verkry die PayJoin-bekwame invoice oor 'n geauthentiseerde kanaal; beskerm dit soos enige betalingsversoek.
3. Kontroleer die oorspronklike bedrag en bestemming, en laat die wallet die voorstel/PSBT, fee contribution en verbode substitusies valideer.
4. Bevestig die finale wallet-opsomming. Moenie 'n onverwagte output, bedrag of buitensporige fooi handmatig goedkeur nie.
5. Indien onderhandeling misluk, verstaan of die wallet veilig na 'n gewone betaling terugval of 'n nuwe invoice vereis.
6. Behou die private ontvangs/rekords wat vir eienaarskap, rekeningkunde en dispute vereis word.

PayJoin verbeter een chain-analysis-heuristiek; dit verberg nie die betaling vir die partye, verkrygingsplatform, endpoints of publieke grootboek nie.

## CoinJoin: voordele en beperkings

CoinJoin koördineer verskeie gebruikers in een transaksie om input-output-koppeling minder seker te maak. Navorsing oor spesifieke historiese Wasabi- en Samourai-ontwerpe het hoogs herkenbare transaksies gevind en getoon dat pre/post-mix-gedrag anonimiteit aansienlik kan verklein.<sup>[[4]](#references)</sup> Daardie resultaat behoort nie na elke implementering of toekomstige weergawe veralgemeen te word nie, maar dit demonstreer waarom 'n “anonymity-set”-getal nie 'n waarborg is nie.

Voor enige wettige gebruik:

- kontroleer huidige plaaslike wetgewing, sanksiestatus, exchange-/custodian-beleid en belasting-/rapporteringverpligtinge;
- gebruik onderhoude, non-custodial sagteware wat van die amptelike projek verkry is;
- verstaan die coordinator-model, fooie, denial-of-service-kontroles en of die huidige diens steeds bedryf word—zkSNACKs het sy coordinator in 2024 beëindig, hoewel ander Wasabi-coordinators kan bestaan;
- bewaar source-of-funds- en transaksie-rekords privaat;
- aanvaar nooit onbekende fondse namens iemand anders nie en gebruik nie 'n custodial “mixer” wat ontraceerbare withdrawals belowe nie;
- hou outputs volgens bron/konteks geskei en vermy latere konsolidasie wat die beoogde dubbelsinnigheid vernietig.

Regsuitkomste is feit- en jurisdiksiespesifiek. Die 2025 Samourai-skuldigpleitings het gehandel oor die bewustelike bedryf van 'n ongelisensieerde money transmitter wat kriminele opbrengste verskuif het; dit bepaal nie dat elke samewerkende transaksie of gebruiker wat privaatheid soek, krimineel is nie.<sup>[[5]](#references)</sup>

## Lightning Network

Lightning se Sphinx onion routing is ontwerp sodat 'n intermediêre hop sy voorganger en opvolger leer, eerder as die hele roete.<sup>[[6]](#references)</sup> Dit is nie blanket anonymity nie: channel funding/closure is publiek, nodes adverteer topology, teenpartye ken endpoints, routing/probing kan saldo's of partye aflei, en 'n custodial wallet sien sy gebruiker se rekeningaktiwiteit.

Vir beter privaatheid:

1. Verkies 'n onderhoude non-custodial wallet indien intermediary privacy belangrik is; beplan channel backup/recovery eerste.
2. Gebruik 'n vars invoice of offer vir elke betaling. Verifieer of die presiese wallet BOLT 12/route blinding ondersteun eerder as om dit te aanvaar.
3. Vermy die publikasie van onnodige node aliases, kontakbesonderhede en stabiele netwerk-endpoints.
4. Koppel deur 'n ondersteunde privacy network indien toepaslik, met die begrip dat uptime-/tydspatrone steeds kan korreleer.
5. Moenie aflei dat 'n off-chain-betaling geen rekords het nie: sender, ontvanger, peers, watchtowers, liquidity providers en wallet-dienste kan waarnemings behou.

Gepubliseerde navorsing het sender-/ontvanger- en channel-balance-inferensie uit publieke data en aktiewe probing gedemonstreer, hoewel attacks en mitigations ontwikkel.<sup>[[7]](#references)</sup>

## Monero

Monero gebruik one-time stealth addresses vir outputs, RingCT om bedrae te verberg, en ring signatures om waarskynlikheidsgebaseerde sender-dubbelsinnigheid te verskaf; sy huidige tegniese spesifikasies dokumenteer 'n ring size van 16 (15 decoys).<sup>[[8]](#references)</sup> Dit is sterker verstekke vir on-chain-vertroulikheid as deursigtige grootboeke, nie magiese beskerming teen endpoint- of operasionele foute nie.

### Wettige werksvloei

1. **Verkry dit wettig.** 'n Gereguleerde exchange kan die aankoop en withdrawal ken, selfs wanneer latere on-chain-besonderhede vertroulik is. Hou bron-, basis- en rapporteringsrekords.
2. **Installeer die amptelike onderhoude wallet** en verifieer die download volgens projekinstruksies. Rugsteun die seed offline en toets restoration met 'n klein bedrag.
3. **Verkies 'n plaaslike node** vir maksimum wallet-query-privaatheid. Indien dit onprakties is, kies 'n betroubare remote node wat oor 'n amptelik ondersteunde onion/I2P-konfigurasie bereikbaar is. 'n Remote node kan IP, versoeke, tydsberekening en transaction IDs log; sommige lightweight-ontwerpe stel 'n view key bloot.
4. **Gebruik 'n nuwe subaddress per betaler, veldtog of invoice.** 'n Betaler kan herhaalde gebruik van dieselfde subaddress korreleer.<sup>[[9]](#references)</sup>
5. **Etiketteer inkomende kontekste plaaslik.** Vermy die operasionele samesmelting van geskeide ontvangstes waar 'n kundige betaler daaropvolgende gedrag kan herken.
6. **Beskerm netwerkmetadata.** Volg die amptelike anonymity-network-konfigurasie; erken gedokumenteerde leaks uit timestamps, intermitterende sinkronisering, bandbreedtevorm en stream-hergebruik.<sup>[[10]](#references)</sup>
7. **Hou compliance-/auditdata privaat.** Openbaar 'n view key of transaksiebewys slegs doelbewus, aan die bedoelde auditor/party, en verstaan presies wat dit openbaar.

Historiese traceability-studies sluit bugs en decoy-selection-eras in wat sedertdien verander het; moenie ou suksespersentasies op huidige transaksies toepas nie. Net so bly FCMP++ roadmap-werk vanaf hierdie hoofstuk se September 2026-navorsingsafsnydatum, nie 'n ontplooide beskerming nie.<sup>[[11]](#references)</sup>

## Ethereum en stablecoins

Ethereum se eie privaatheidsmateriaal merk op dat on-chain-actions sigbaar is en dat wallet-/RPC-infrastruktuur IP- en metadata-blootstelling byvoeg.<sup>[[12]](#references)</sup> Token transfers, approvals, smart-contract-interaksies, name services en gas funding kan almal identiteite verbind.

Gesentraliseerde stablecoins voeg issuer-beheer by. Huidige USDC- en Tether-terme behou magte voor om adresse of bates te blokkeer/freeze en aan wetlike/prosesverpligtinge te voldoen.<sup>[[13]](#references)</sup> Hulle kan nuttige betalingsinstrumente wees, maar is swak keuses wanneer die vereiste censorship resistance of on-chain-anonimiteit is.

## Compliance-grense

- FATF-aanbevelings word deur nasionale wetgewing geïmplementeer en verander met verloop van tyd; sy 2026-opdatering beklemtoon VASP-lisensiëring/registrasie en Travel Rule-implementering.<sup>[[14]](#references)</sup>
- In die VSA onderskei FinCEN tussen 'n persoon wat convertible virtual currency vir hul eie goedere/dienste gebruik en 'n besigheid wat dit aanvaar en transmit of exchange; feite en latere reëls is belangrik.<sup>[[15]](#references)</sup>
- Die EU Transfer of Funds Regulation vereis originator-/beneficiary-inligting waar 'n crypto-asset service provider betrokke is en voeg verifikasiereëls by vir sekere transfers na/van self-hosted adresse.<sup>[[16]](#references)</sup>
- Sanksies en belastingverpligtinge bly van toepassing. Screen soos vereis, weier verbode partye en hou rekords; lyste en wettige status kan vinnig verander.<sup>[[17]](#references)</sup>

Voor beduidende waarde, grensoverschrijdende aktiwiteit, privacy-enhancing coordination of besigheidsagtige exchange/transmission, verkry huidige professionele advies vir die betrokke jurisdiksies.

Vir Bitcoin Silent Payments, fully shielded Zcash, GNU Taler, federated Chaumian e-cash en BOLT 12, gaan voort na [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Beskerm jou privaatheid](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privaatheidskenmerke](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — 'n Eenvoudige Payjoin-voorstel](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Aanneming en werklike privaatheid van gedesentraliseerde CoinJoin-implementerings in Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Stigters van Samourai Wallet pleit skuldig (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — 'n Empiriese ontleding van privaatheid in die Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html), en [Tegniese spesifikasies](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Netwerke](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Verkenning van die ontwikkeling van Monero se privaatheid (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privaatheid op Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC-terme](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — 2026-gerigte opdatering oor virtuele bates en VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Toepassing van FinCEN se regulasies op persone wat virtuele geldeenhede administreer, exchange of gebruik](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulasie (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Sanksie-compliance-riglyne vir die virtuele-geldeenheidbedryf](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
