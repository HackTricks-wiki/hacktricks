# Privatnost kriptovaluta

{{#include ../banners/hacktricks-training.md}}

Privatnost kriptovaluta je pitanje protokola i operacija, a ne sinonim za tajnost ili imunitet. Javne knjige, berze, wallet serveri, mrežni peer-ovi, trgovci i kasnije transakcije otkrivaju različite delove grafa.

Počnite od [Kataloga tehnika anonimnih plaćanja](anonymous-payment-techniques.md) za format prednosti/mana/procedure/detekcije po tehnici. Ova stranica proširuje mehanizme i operativna ograničenja specifična za kriptovalute.

{% hint style="danger" %}
Ovo poglavlje je namenjeno zakonitom self-custody pristupu i minimizaciji podataka. Nemojte ga koristiti za pranje prihoda, izbegavanje sankcija/poreza/obaveza izveštavanja, transakcije sa zabranjenim stranama, obmanjivanje regulisanog pružaoca usluga ili rad neregistrovanog servisa za prenos. Tehnologija privatnosti ne menja zakonito poreklo ili vlasništvo nad sredstvima.
{% endhint %}

## Model pretnji po slojevima

| Sloj | Posmatrač | Uobičajeno otkrivanje |
|---|---|---|
| Akvizicija/off-ramp | Berza, banka, broker, P2P counterpart | Identitet, račun za finansiranje, odredište, uređaj, IP, vreme |
| Ledger | Bilo ko ko pokreće analitiku | Adrese/outputs, iznosi i vreme na transparentnim chain-ovima; metapodaci specifični za protokol drugde |
| Wallet backend | RPC provajder, explorer, remote node | Upiti adresa, stanja, IP, emitovanje transakcija |
| Mreža | ISP, peer-ovi, ulaz u anonymity-network | IP, vreme, obim i korišćenje protokola |
| Counterparty | Platilac/primalac | Faktura/adresa, isporuka, razgovor, nalog i vreme |
| Endpoint | Malware, cloud backup, fizičko zaplenjivanje | Seed, ključevi, oznake, istorija, screenshots i clipboard |

Self-custody može ukloniti custodiana iz kontrolnog toka, ali ne briše ledger, zapis o akviziciji, mrežne metapodatke ili dokaze na endpoint-u.

## Poređenje protokola

| Metod | Korisno svojstvo privatnosti | Važna ograničenja |
|---|---|---|
| Bitcoin on-chain | Self-custody; sveže adrese izbegavaju jednostavno ponovno korišćenje adresa | Javni trajni graf transakcija; heuristike iznosa/vremena i potrošnje |
| Bitcoin PayJoin | Input primaoca može prekinuti heuristiku zajedničkog vlasništva inputa | Oba wallet-a moraju imati podršku; transakcija ostaje javna; podrška je neujednačena |
| Bitcoin CoinJoin | Stvara neizvesnost među koordinisanim učesnicima | Prepoznatljivi obrasci, veze pre/posle, konsolidacija, policy/legal/provider rizik |
| Lightning | Onion-routed plaćanja nisu globalno objavljena kao obični transferi | Channel-i se otvaraju/zatvaraju on-chain; endpoint-i, peer-ovi, probes ili custodian mogu zaključivati podatke |
| Monero | Jača podrazumevana on-chain poverljivost primaoca, iznosa i skupa pošiljalaca | Veze sa berzom, node-om, vremenom, endpoint-om i counterparty-jem ostaju |
| Ethereum/stablecoins | Široka dostupnost i interoperabilnost sa smart-contract-ima | Javno stanje/radnje; RPC metapodaci; centralizovani emitenti mogu blokirati/zamrznuti/prijaviti |

## Bitcoin: baseline koji čuva privatnost

Bitcoin je pseudoniman, a ne anoniman. Potvrđene transakcije su javne i trajne; ponovno korišćenje adresa, zajedničko vlasništvo inputa, otkrivanje kusura i javno identifikovane adrese mogu izgraditi klastere.<sup>[[1]](#references)</sup>

### Workflow

1. **Izaberite održavan self-custody wallet.** Preuzmite ga sa zvaničnog projekta, proverite signatures/hashes kada su ponuđeni i primenite security updates.
2. **Kreirajte wallet na pouzdanom endpoint-u.** Zapišite recovery seed offline; nikada ga ne stavljajte u email, chat, screenshots ili obične cloud beleške. Testirajte recovery pre čuvanja značajne vrednosti.
3. **Držite samo operativnu vrednost hot.** Za dugoročnu vrednost koristite odgovarajući offline/hardware custody, uz recovery plan koji ne izlaže seed jednoj osetljivoj lokaciji.
4. **Generišite novu receive adresu/invoice za svaku transakciju.** Nemojte objavljivati statičnu adresu kada su mogući invoice server ili authenticated private delivery.
5. **Koristite sopstveni full node kada je moguće.** Third-party explorer/electrum server može saznati upitane adrese i IP metapodatke. Konfigurišite samo Tor/proxy ponašanje koje wallet podržava; Tor skriva mrežnu ivicu, a ne blockchain graf.
6. **Privatno označite svaki UTXO** izvorom, vlasnikom, namenom i compliance stanjem. Omogućite coin control kako nepovezani identitetski konteksti ne bi bili potrošeni zajedno.
7. **Pregledajte transakciju:** izabrane inpute, odredište kusura, iznos, fee, counterparty i da li potrošnja spaja compartment-e. Izbegavajte nepotrebnu konsolidaciju.
8. **Zakonite evidencije čuvajte odvojeno i šifrovano.** Sačuvajte osnov nabavke, fakture, autorizaciju i poreske/izveštajne podatke bez objavljivanja mapiranja.
9. **Kasniju potrošnju tretirajte kao deo iste odluke o privatnosti.** Dobro odvojen prijem može biti ponovo povezan kada se njegov output potroši zajedno sa identifikovanim sredstvima.

Bitcoin Core dokumentacija o privatnosti objašnjava da full node izbegava otkrivanje wallet upita third-party serverima, ali da emitovanje transakcija i javna istorija i dalje zahtevaju analizu.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin je saradničko plaćanje u kojem primalac dodaje input. Time se pobija pojednostavljena pretpostavka da svi inputi pripadaju pošiljaocu. BIP 78 opisuje originalni interaktivni protokol; draft BIP 77 definiše asinhroni v2 dizajn koji koristi šifrovani mailbox/OHTTP.<sup>[[3]](#references)</sup>

Bezbedna upotreba:

1. Potvrdite da oba održavana wallet-a podržavaju istu PayJoin verziju.
2. Nabavite PayJoin-capable invoice preko authenticated channel-a; zaštitite ga kao svaki payment request.
3. Proverite prvobitni iznos i odredište, a zatim dozvolite wallet-u da validira proposal/PSBT, fee contribution i zabranjene zamene.
4. Potvrdite konačni wallet summary. Nemojte ručno odobriti neočekivani output, iznos ili prekomeran fee.
5. Ako pregovaranje ne uspe, proverite da li wallet bezbedno prelazi na običnu uplatu ili zahteva novu fakturu.
6. Sačuvajte privatni receipt/evidencije potrebne za vlasništvo, računovodstvo i sporove.

PayJoin poboljšava jednu heuristiku chain-analysis-a; ne skriva plaćanje od strana, platforme za akviziciju, endpoint-a ili javnog ledger-a.

## CoinJoin: prednosti i ograničenja

CoinJoin koordinira više korisnika u jednoj transakciji kako bi mapiranje input-output bilo manje izvesno. Istraživanje specifičnih istorijskih dizajna Wasabi i Samourai pronašlo je veoma prepoznatljive transakcije i pokazalo da ponašanje pre/posle mix-a može znatno suziti anonimnost.<sup>[[4]](#references)</sup> Ovaj rezultat ne treba uopštavati na svaku implementaciju ili buduću verziju, ali pokazuje zašto broj „anonymity-set“ nije garancija.

Pre svake zakonite upotrebe:

- proverite važeći lokalni zakon, status sankcija, policy berze/custodiana i poreske/izveštajne obaveze;
- koristite održavan, non-custodial software preuzet sa zvaničnog projekta;
- razumite model coordinator-a, fee-jeve, kontrole denial-of-service-a i da li trenutni servis i dalje radi—zkSNACKs je završio svoj coordinator 2024. godine, iako drugi Wasabi coordinators mogu postojati;
- privatno sačuvajte evidencije o poreklu sredstava i transakcijama;
- nikada ne prihvatajte nepoznata sredstva u tuđe ime niti koristite custodial „mixer“ koji obećava withdrawals kojima se ne može ući u trag;
- držite outputs odvojene po izvoru/kontekstu i izbegavajte kasniju konsolidaciju koja uništava nameravanu neizvesnost.

Pravni ishodi zavise od činjenica i jurisdikcije. Priznanja krivice Samourai-ja iz 2025. odnosila su se na svesno vođenje neregistrovanog money transmitter-a koji je premeštao kriminalne prihode; ona ne utvrđuju da je svaka saradnička transakcija ili korisnik koji traži privatnost kriminalac.<sup>[[5]](#references)</sup>

## Lightning Network

Lightning-ov Sphinx onion routing dizajniran je tako da posredni hop sazna svog prethodnika i sledbenika, a ne celu rutu.<sup>[[6]](#references)</sup> To nije potpuna anonimnost: channel funding/closure je javan, node-ovi oglašavaju topologiju, counterparties znaju endpoint-e, routing/probing može otkriti stanja ili strane, a custodial wallet vidi aktivnost naloga svog korisnika.

Za bolju privatnost:

1. Preferirajte održavan non-custodial wallet ako je privatnost posrednika važna; prvo isplanirajte channel backup/recovery.
2. Koristite svež invoice ili offer za svako plaćanje. Proverite da li konkretan wallet podržava BOLT 12/route blinding umesto da to pretpostavite.
3. Izbegavajte objavljivanje nepotrebnih node alias-a, kontaktnih podataka i stabilnih mrežnih endpoint-a.
4. Povežite se preko podržane privacy mreže ako je prikladno, uz razumevanje da se obrasci dostupnosti/vremena i dalje mogu povezati.
5. Nemojte zaključiti da off-chain plaćanje nema evidencije: sender, receiver, peer-ovi, watchtower-i, liquidity provider-i i wallet servisi mogu zadržati zapažanja.

Objavljeno istraživanje pokazalo je zaključivanje pošiljaoca/primaoca i channel balance-a na osnovu javnih podataka i aktivnog probing-a, iako se napadi i mitigacije razvijaju.<sup>[[7]](#references)</sup>

## Monero

Monero koristi one-time stealth addresses za outputs, RingCT za skrivanje iznosa i ring signatures za pružanje probabilističke nejasnoće pošiljaoca; njegove aktuelne tehničke specifikacije dokumentuju ring size od 16 (15 decoys).<sup>[[8]](#references)</sup> To su jače podrazumevane zaštite on-chain poverljivosti od transparentnih ledger-a, a ne magična zaštita od grešaka na endpoint-u ili u operacijama.

### Zakoniti workflow

1. **Nabavite sredstva zakonito.** Regulisanа berza može znati za kupovinu i withdrawal čak i kada su kasniji on-chain detalji poverljivi. Čuvajte evidencije o izvoru, osnovu i izveštavanju.
2. **Instalirajte zvanični održavani wallet** i proverite preuzimanje prema uputstvima projekta. Napravite backup seed-a offline i testirajte restoration sa malim iznosom.
3. **Preferirajte lokalni node** za maksimalnu privatnost wallet upita. Ako to nije praktično, izaberite pouzdan remote node dostupan preko zvanično podržane onion/I2P konfiguracije. Remote node može beležiti IP, requests, vreme i transaction IDs; neki lightweight dizajni otkrivaju view key.
4. **Koristite novi subaddress po platiocu, kampanji ili fakturi.** Platilac može povezati ponovljenu upotrebu iste subaddress.<sup>[[9]](#references)</sup>
5. **Lokalno označite dolazne kontekste.** Izbegavajte operativno spajanje odvojenih prijema kada bi upućeni payer mogao prepoznati kasnije ponašanje.
6. **Zaštitite mrežne metapodatke.** Pratite zvaničnu konfiguraciju anonymity-network-a; prepoznajte dokumentovane leak-ove iz timestamps, intermittent synchronization, bandwidth shape i stream reuse.<sup>[[10]](#references)</sup>
7. **Podatke za compliance/audit čuvajte privatno.** View key ili dokaz transakcije otkrijte samo namerno, predviđenom auditoru/strani, i tačno razumite šta otkriva.

Istorijske studije sledljivosti uključuju bug-ove i epohe izbora decoys koje su se od tada promenile; nemojte stare procente uspeha primenjivati na aktuelne transakcije. Isto tako, FCMP++ je i dalje roadmap rad prema istraživačkom preseku iz septembra 2026. ovog poglavlja, a ne deployed protection.<sup>[[11]](#references)</sup>

## Ethereum i stablecoins

Ethereum-ov sopstveni materijal o privatnosti navodi da su on-chain radnje vidljive i da wallet/RPC infrastruktura dodaje IP i metapodatke.<sup>[[12]](#references)</sup> Token transfers, approvals, smart-contract interactions, name services i gas funding mogu povezati identitete.

Centralizovani stablecoins dodaju kontrolu emitenta. Aktuelni uslovi USDC-a i Tether-a zadržavaju ovlašćenja za blokiranje/zamrzavanje adresa ili sredstava i poštovanje zakonskih/procesnih obaveza.<sup>[[13]](#references)</sup> Mogu biti korisni payment instruments, ali su loš izbor kada je zahtev otpornost na cenzuru ili on-chain anonimnost.

## Granice compliance-a

- FATF preporuke se primenjuju kroz nacionalne zakone i menjaju se tokom vremena; njegovo ažuriranje iz 2026. naglašava VASP licenciranje/registraciju i primenu Travel Rule-a.<sup>[[14]](#references)</sup>
- U SAD, FinCEN razlikuje osobu koja koristi convertible virtual currency za sopstvenu robu/usluge od poslovanja koje je prihvata i prenosi ili razmenjuje; činjenice i kasnija pravila su važni.<sup>[[15]](#references)</sup>
- EU Regulation on Transfer of Funds zahteva podatke o pošiljaocu/primaocu kada je uključen crypto-asset service provider i dodaje pravila verifikacije za određene transfere ka/sa self-hosted adresa.<sup>[[16]](#references)</sup>
- Sankcije i poreske obaveze i dalje važe. Obavite proveru kada je potrebno, odbijte zabranjene strane i vodite evidencije; liste i pravni status mogu se brzo promeniti.<sup>[[17]](#references)</sup>

Pre raspolaganja značajnom vrednošću, prekogranične aktivnosti, koordinacije koja unapređuje privatnost ili poslovne razmene/prenosa, pribavite aktuelni stručni savet za relevantne jurisdikcije.

Za Bitcoin Silent Payments, potpuno shielded Zcash, GNU Taler, federated Chaumian e-cash i BOLT 12, nastavite na [Protokole plaćanja koji čuvaju privatnost](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Zaštitite svoju privatnost](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Funkcije privatnosti](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Jednostavan Payjoin predlog](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Usvajanje i stvarna privatnost decentralizovanih CoinJoin implementacija u Bitcoin-u (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Osnivači Samourai Wallet-a priznali krivicu (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Empirijska analiza privatnosti u Lightning Network-u](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth adrese](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) i [Tehničke specifikacije](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Mreže](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Istraživanje razvoja Monero privatnosti (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privatnost na Ethereum-u](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC uslovi](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Ciljano ažuriranje virtuelne imovine i VASP-ova za 2026.](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Primena FinCEN propisa na lica koja administriraju, razmenjuju ili koriste virtuelne valute](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Smernice za compliance sa sankcijama za industriju virtuelnih valuta](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
