# Privatnost cryptocurrency-ja

Privatnost cryptocurrency-ja je pitanje protokola i operacija, a ne sinonim za tajnost ili imunitet. Javne knjige transakcija, menjačnice, wallet serveri, mrežni peer-ovi, trgovci i kasnije transakcije otkrivaju različite delove grafa.

Počnite od [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) za format prednosti/mana/procedure/detekcije po tehnici. Ova stranica proširuje mehanizme i operativna ograničenja specifična za cryptocurrency.

{% hint style="danger" %}
Ovo poglavlje je namenjeno zakonitom self-custody-ju i minimizaciji podataka. Nemojte ga koristiti za pranje prihoda, izbegavanje sankcija/poreza/obaveza izveštavanja, transakcije sa zabranjenim stranama, obmanjivanje regulisanog pružaoca usluga ili rad neregistrovanog servisa za prenos novca. Tehnologija privatnosti ne menja zakonito poreklo ili vlasništvo nad sredstvima.
{% endhint %}

## Model pretnji po slojevima

| Sloj | Posmatrač | Uobičajeno otkrivanje |
|---|---|---|
| Nabavka/off-ramp | Menjačnica, banka, broker, P2P counterparty | Identitet, račun za finansiranje, odredište, uređaj, IP, vreme |
| Ledger | Bilo ko ko pokreće analitiku | Adrese/izlazi, iznosi i vreme na transparentnim chain-ovima; metapodaci specifični za protokol drugde |
| Wallet backend | RPC provider, explorer, remote node | Upiti adresa, stanja, IP, emitovanje transakcije |
| Mreža | ISP, peer-ovi, ulazna tačka anonymity-network-a | IP, vremenski obrasci, obim i korišćenje protokola |
| Counterparty | Payer/payee | Faktura/adresa, isporuka, razgovor, nalog i vreme |
| Endpoint | Malware, cloud backup, fizička zaplena | Seed, ključevi, oznake, istorija, screenshots i clipboard |

Self-custody može ukloniti custodian-a iz kontrolnog toka, ali ne briše ledger, zapis o nabavci, mrežne metapodatke ili dokaze sa endpoint-a.

## Poređenje protokola

| Metod | Korisno svojstvo privatnosti | Važna ograničenja |
|---|---|---|
| Bitcoin on-chain | Self-custody; sveže adrese izbegavaju jednostavnu ponovnu upotrebu adrese | Javni trajni graf transakcija; heuristike iznosa/vremena i trošenja |
| Bitcoin PayJoin | Input receiver-a može prekinuti heuristiku zajedničkog vlasništva nad input-ima | Oba wallet-a moraju imati podršku; transakcija ostaje javna; podrška je neujednačena |
| Bitcoin CoinJoin | Stvara nejasnoću među koordinisanim učesnicima | Prepoznatljivi obrasci, veze pre/posle, konsolidacija, rizik politike/prava/provajdera |
| Lightning | Onion-routed plaćanja nisu globalno objavljena kao obični transferi | Channel-i se otvaraju/zatvaraju on-chain; endpoint-i, peer-ovi, probe-ovi ili custodian mogu izvesti podatke |
| Monero | Jača podrazumevana on-chain poverljivost za receiver-a, iznos i skup sender-a | Veze sa exchange-om, node-om, vremenom, endpoint-om i counterparty-jem ostaju |
| Ethereum/stablecoins | Široka dostupnost i interoperabilnost sa smart-contract-ima | Javno stanje/radnje; RPC metapodaci; centralizovani issuer-i mogu blokirati/zamrznuti/prijaviti |

## Bitcoin: osnovni nivo koji čuva privatnost

Bitcoin je pseudoniman, a ne anoniman. Potvrđene transakcije su javne i trajne; ponovna upotreba adresa, zajedničko vlasništvo nad input-ima, detekcija kusura i javno identifikovane adrese mogu izgraditi klastere.<sup>[[1]](#references)</sup>

### Workflow

1. **Izaberite održavan self-custody wallet.** Preuzmite ga sa zvaničnog projekta, proverite potpise/hash-eve kada su ponuđeni i primenite security updates.
2. **Kreirajte wallet na pouzdanom endpoint-u.** Zapišite recovery seed offline; nikada ga ne stavljajte u email, chat, screenshots ili obične cloud beleške. Testirajte recovery pre nego što u wallet stavite značajnu vrednost.
3. **Držite samo operativnu vrednost hot.** Za dugoročnu vrednost koristite odgovarajući offline/hardware custody, uz recovery plan koji ne izlaže seed jednoj krhkoj lokaciji.
4. **Generišite svežu receive adresu/fakturu za svaku transakciju.** Nemojte objavljivati statičku adresu kada su mogući invoice server ili authenticated private delivery.
5. **Koristite sopstveni full node kada je izvodljivo.** Third-party explorer/electrum server može saznati upitane adrese i IP metapodatke. Konfigurišite samo Tor/proxy ponašanje koje wallet podržava; Tor skriva mrežnu ivicu, a ne blockchain graf.
6. **Privatno označite svaki UTXO** izvorom, vlasnikom, svrhom i statusom usklađenosti. Omogućite coin control kako nepovezani identitetski konteksti ne bi bili potrošeni zajedno.
7. **Pregledajte transakciju:** izabrane input-e, odredište kusura, iznos, fee, counterparty i da li spend spaja compartment-e. Izbegavajte nepotrebnu konsolidaciju.
8. **Zakonite evidencije čuvajte odvojeno i enkriptovano.** Sačuvajte osnov nabavke, fakture, ovlašćenje i poreske/informacije za izveštavanje bez objavljivanja mapiranja.
9. **Kasnije trošenje posmatrajte kao deo iste odluke o privatnosti.** Dobro odvojen prijem može biti ponovo povezan kada se njegov output potroši zajedno sa identifikovanim sredstvima.

Bitcoin Core dokumentacija o privatnosti objašnjava da full node sprečava otkrivanje wallet upita third-party server-ima, ali da emitovanje transakcija i javna istorija i dalje zahtevaju analizu.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin je saradničko plaćanje u kojem receiver dodaje input. Time se obara pojednostavljena pretpostavka da svi input-i pripadaju sender-u. BIP 78 opisuje originalni interaktivni protokol; draft BIP 77 definiše asinhroni v2 dizajn koji koristi enkriptovani mailbox/OHTTP.<sup>[[3]](#references)</sup>

Bezbedna upotreba:

1. Potvrdite da oba održavana wallet-a podržavaju istu PayJoin verziju.
2. Nabavite PayJoin-capable fakturu preko authenticated channel-a; zaštitite je kao svaki payment request.
3. Proverite originalni iznos i odredište, a zatim dozvolite wallet-u da validira predlog/PSBT, doprinos za fee i zabranjene zamene.
4. Potvrdite konačni wallet summary. Nemojte ručno odobriti neočekivani output, iznos ili prekomeran fee.
5. Ako pregovaranje ne uspe, utvrdite da li wallet bezbedno prelazi na običnu uplatu ili zahteva novu fakturu.
6. Sačuvajte privatni receipt/evidencije potrebne za vlasništvo, računovodstvo i sporove.

PayJoin poboljšava jednu heuristiku chain-analysis-a; ne skriva plaćanje od strana u transakciji, acquisition platform-e, endpoint-a ili javnog ledger-a.

## CoinJoin: koristi i ograničenja

CoinJoin koordinira više korisnika u jednoj transakciji kako bi mapiranje input-output bilo manje izvesno. Istraživanje konkretnih istorijskih Wasabi i Samourai dizajna pronašlo je veoma prepoznatljive transakcije i pokazalo da ponašanje pre/posle mix-a može značajno suziti anonymity.<sup>[[4]](#references)</sup> Taj rezultat ne treba generalizovati na svaku implementaciju ili buduću verziju, ali pokazuje zašto broj „anonymity-set“ nije garancija.

Pre svake zakonite upotrebe:

- proverite važeći lokalni zakon, status sankcija, politiku exchange/custodian-a i poreske/obaveze izveštavanja;
- koristite održavan, non-custodial software preuzet od zvaničnog projekta;
- razumite model coordinator-a, fee-jeve, kontrole denial-of-service-a i da li trenutni servis i dalje radi—zkSNACKs je ugasio svoj coordinator 2024. godine, iako drugi Wasabi coordinator-i mogu postojati;
- privatno čuvajte evidencije o poreklu sredstava i transakcijama;
- nikada ne prihvatajte nepoznata sredstva u ime druge osobe niti koristite custodial „mixer“ koji obećava withdrawals bez mogućnosti praćenja;
- držite output-e odvojene prema izvoru/kontekstu i izbegavajte kasniju konsolidaciju koja uništava željenu nejasnoću.

Pravni ishodi zavise od činjenica i jurisdikcije. Priznanja krivice Samourai-ja iz 2025. odnosila su se na svesno vođenje neregistrovanog money transmitter-a koji je prenosio kriminalne prihode; ona ne utvrđuju da je svaka saradnička transakcija ili korisnik koji traži privatnost kriminalac.<sup>[[5]](#references)</sup>

## Lightning Network

Lightning-ov Sphinx onion routing dizajniran je tako da posredni hop sazna svog prethodnika i sledbenika, a ne celu rutu.<sup>[[6]](#references)</sup> To nije potpuna anonymity: funding/closure channel-a je javan, node-ovi objavljuju topologiju, counterparties znaju endpoint-e, routing/probing može otkriti stanja ili strane, a custodial wallet vidi aktivnost svog korisnika.

Za bolju privatnost:

1. Preferirajte održavan non-custodial wallet ako je privatnost posrednika važna; prvo planirajte channel backup/recovery.
2. Koristite svežu fakturu ili offer za svako plaćanje. Proverite da li konkretan wallet podržava BOLT 12/route blinding, umesto da pretpostavite da podržava.
3. Izbegavajte objavljivanje nepotrebnih node alias-a, kontaktnih podataka i stabilnih mrežnih endpoint-a.
4. Povežite se preko podržane privacy network kada je odgovarajuće, uz razumevanje da se obrasci dostupnosti/vremena i dalje mogu korelisati.
5. Nemojte zaključiti da off-chain plaćanje nema evidencije: sender, receiver, peer-ovi, watchtower-i, liquidity provider-i i wallet servisi mogu zadržati zapažanja.

Objavljena istraživanja pokazala su mogućnost zaključivanja sender-a/recipient-a i channel balance-a na osnovu javnih podataka i aktivnog probing-a, iako se napadi i mere zaštite razvijaju.<sup>[[7]](#references)</sup>

## Monero

Monero koristi one-time stealth addresses za output-e, RingCT za skrivanje iznosa i ring signatures za pružanje probabilističke nejasnoće sender-a; njegove aktuelne tehničke specifikacije navode ring size od 16 (15 decoys).<sup>[[8]](#references)</sup> To su jače podrazumevane mere za on-chain poverljivost u odnosu na transparentne ledgere, a ne magična zaštita od grešaka na endpoint-u ili u operacijama.

### Zakoniti workflow

1. **Nabavljajte zakonito.** Regulisani exchange može znati kupovinu i withdrawal čak i kada su kasniji on-chain detalji poverljivi. Čuvajte evidencije o izvoru, osnovu i izveštavanju.
2. **Instalirajte zvanični održavani wallet** i proverite download prema uputstvima projekta. Napravite backup seed-a offline i testirajte restoration sa malim iznosom.
3. **Preferirajte lokalni node** radi maksimalne privatnosti wallet upita. Ako je to nepraktično, izaberite pouzdan remote node dostupan preko zvanično podržane onion/I2P konfiguracije. Remote node može beležiti IP, zahteve, vreme i transaction ID-jeve; neki lightweight dizajni otkrivaju view key.
4. **Koristite novu subaddress za svakog payer-a, kampanju ili fakturu.** Payer može povezati ponovnu upotrebu iste subaddress.<sup>[[9]](#references)</sup>
5. **Lokalno označite incoming kontekste.** Izbegavajte operativno spajanje odvojenih prijema kada bi upućeni payer mogao prepoznati kasnije ponašanje.
6. **Zaštitite mrežne metapodatke.** Pratite zvaničnu konfiguraciju anonymity-network-a; imajte u vidu dokumentovane leak-ove iz timestamp-ova, povremene sinhronizacije, oblika bandwidth-a i ponovne upotrebe stream-ova.<sup>[[10]](#references)</sup>
7. **Podatke za compliance/audit čuvajte privatno.** View key ili dokaz transakcije otkrijte samo namerno, predviđenom auditoru/strani, i tačno razumite šta otkriva.

Istorijske studije traceability-ja uključuju bug-ove i periode izbora decoy-ja koji su se u međuvremenu promenili; nemojte primenjivati stare procente uspeha na aktuelne transakcije. Isto tako, FCMP++ je i dalje roadmap rad prema istraživačkom preseku ovog poglavlja iz septembra 2026, a ne uvedena zaštita.<sup>[[11]](#references)</sup>

## Ethereum i stablecoins

Ethereum-ov materijal o privatnosti navodi da su on-chain radnje vidljive i da wallet/RPC infrastruktura dodaje izloženost IP-a i metapodataka.<sup>[[12]](#references)</sup> Token transferi, approvals, smart-contract interakcije, name services i gas funding mogu povezati identitete.

Centralizovani stablecoins dodaju kontrolu issuer-a. Aktuelni uslovi za USDC i Tether zadržavaju ovlašćenja za blokiranje/zamrzavanje adresa ili sredstava i ispunjavanje zakonskih/procesnih obaveza.<sup>[[13]](#references)</sup> Mogu biti korisni payment instrumenti, ali su loš izbor kada je zahtev otpornost na censorship ili on-chain anonymity.

## Granice usklađenosti

- FATF preporuke se sprovode kroz nacionalne zakone i vremenom se menjaju; njegovo ažuriranje iz 2026. naglašava VASP licensing/registration i primenu Travel Rule-a.<sup>[[14]](#references)</sup>
- U SAD, FinCEN razlikuje osobu koja koristi convertible virtual currency za sopstvenu robu/usluge od poslovanja koje je prihvata i prenosi ili razmenjuje; činjenice i kasnija pravila su važni.<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation zahteva podatke o originator-u/beneficiary-ju kada je crypto-asset service provider uključen i dodaje pravila verifikacije za određene transfere ka/sa self-hosted adresa.<sup>[[16]](#references)</sup>
- Sankcije i poreske obaveze i dalje važe. Sprovodite screening kada je zahtevano, odbijajte zabranjene strane i vodite evidencije; liste i pravni status mogu se brzo promeniti.<sup>[[17]](#references)</sup>

Pre transakcija značajne vrednosti, prekogranične aktivnosti, koordinacije koja poboljšava privatnost ili poslovne razmene/prenosa, pribavite aktuelni profesionalni savet za relevantne jurisdikcije.

Za Bitcoin Silent Payments, potpuno shielded Zcash, GNU Taler, federated Chaumian e-cash i BOLT 12, nastavite na [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Zaštitite svoju privatnost](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Funkcije privatnosti](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Jednostavan Payjoin predlog](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Usvajanje i stvarna privatnost decentralizovanih CoinJoin implementacija u Bitcoin-u (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Osnivači Samourai Wallet-a priznaju krivicu (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Empirijska analiza privatnosti u Lightning Network-u](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) i [Tehničke specifikacije](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Mreže](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Istraživanje razvoja Monero privatnosti (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privatnost na Ethereum-u](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC uslovi](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Ciljano ažuriranje o virtualnoj imovini i VASP-ovima za 2026.](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Primena FinCEN propisa na osobe koje administriraju, razmenjuju ili koriste virtualne valute](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Smernice za usklađenost sa sankcijama za industriju virtualnih valuta](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
