# Payment protokoli koji čuvaju privatnost

Napredni payment sistemi mogu sakriti platioca od trgovca, sakriti primaoca ili iznos od javnog ledger-a, ili sprečiti mint da poveže povlačenje sa iskorišćavanjem. Ovo su različita svojstva. Nijedno ne briše zapise o nabavci, uređaju, mreži, isporuci, računovodstvu, sankcijama ili endpoint-ima.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) pruža standardizovane unose `Pros`, `Cons`, korak-po-korak `Procedure` i `Detection` za svaku payment porodicu. Ova stranica proširuje napredne protokole.

{% hint style="danger" %}
Koristite samo zakonita sredstva i counterparties. Ne koristite privacy protokole za zaobilaženje obavezne identifikacije, sankcija, poreza, provera porekla sredstava ili prijavljivanja transakcija. Ne upravljajte exchange-om, mint-om ili transmission servisom bez razumevanja obaveza u vezi sa licenciranjem, custody-jem, AML-om i zaštitom potrošača.
{% endhint %}

## Poređenje naprednih opcija

| Protokol | Šta skriva od javnosti/trgovca | Poverljiva strana ili strana koja posmatra | Zrelost/dostupnost |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Spoljni posmatrači ne mogu povezati reusable payment code sa njegovim jednokratnim output-ima | Javni Bitcoin graph ostaje; wallet/index server može videti scan-ove | Specification je završena; podrška wallet-a varira |
| Zcash fully shielded Orchard | Sender, receiver i amount su enkriptovani on-chain | Wallet backend/network i acquisition/off-ramp ostaju | Deployed; shielded podrška varira u zavisnosti od wallet-a/exchange-a |
| GNU Taler | Merchant ne mora saznati identitet platioca; prihodi merchant-a ostaju odgovorni i proverljivi | Taler exchange/bank vidi funding; merchant vidi order | Deployments su geografski ograničeni |
| Federated Chaumian e-cash | Federation ne bi trebalo da poveže izdate note sa internim transferima/redemption-om | Guardian quorum čuva rezerve; gateway-i vide aktivnosti na granicama sistema | Emerging community deployments |
| Lightning BOLT 12/route blinding | Smanjuje otkrivanje receiver/node identiteta i route-a | Endpoint-i, izabrani hop-ovi, funding chain i wallet servisi | Podrška zavisi od wallet-a |
| Virtual card/token | Merchant dobija ograničeni credential, a ne reusable PAN | Issuer/network zadržavaju podatke o platiocu i transakciji | Zrelo i široko dostupno |

## Bitcoin Silent Payments (BIP 352)

Silent Payments omogućavaju receiver-u da objavi jedan statički payment code, dok svaki sender izvodi jedinstveni Taproot output. Spoljni posmatrač chain-a ne može direktno povezati te output-e sa objavljenim code-om, a nije potreban ni interaktivni zahtev za address-om niti on-chain notification output. BIP 352 je označen kao **Complete**, ali uvodi trošak scan-ovanja i nije kompatibilan sa wallet-ima koji ga nisu implementirali.<sup>[[1]](#references)</sup>

### Workflow receiver-a

1. Izaberite održavan wallet koji izričito podržava BIP 352 receiving; proverite funkciju u aktuelnoj dokumentaciji wallet-a, a ne na osnovu tvrdnje sa društvenih mreža.
2. Napravite backup wallet seed-a i Silent Payment descriptor/key materijala koristeći dokumentovani recovery metod wallet-a. Testirajte discovery na malom testnet/mainnet iznosu pre objavljivanja code-a.
3. Generišite odvojene **labels** za kampanje, invoices ili counterparties tamo gde wallet podržava BIP 352 labels. Labels pomažu lokalnom računovodstvu bez objavljivanja adresa koje se mogu povezati.
4. Objavite statički Silent Payment code preko authenticated channel-a. Može se ponovo koristiti, ali impostor može zameniti vaš code svojim.
5. Kada je praktično, vršite scan preko lokalnog full node-a. Third-party index/scanning server može saznati vreme zahteva ili podatke filtera čak i ako ne može da troši sredstva.
6. Održavajte pronađene UTXO-e označenim i primenjujte ista coin-control pravila kao kod običnog Bitcoin-a. Njihovo trošenje ili konsolidovanje može otkriti veze vlasništva.
7. Potvrdite da recovery pronalazi payment-e bez oslanjanja na eksterni index koji nije obuhvaćen backup-om.

### Workflow sender-a

1. Potvrdite da wallet podržava slanje na address version i autentifikujte receiver-ov statički code.
2. Dozvolite wallet-u da konstruiše output; nikada nemojte ručno konvertovati ili skraćivati code.
3. Pažljivo pregledajte izabrane input-e. Silent Payments poboljšavaju privatnost recipient address-a, ali sender input-i i dalje ostaju na javnom graph-u.
4. Koristite wallet-supported fee bumping/PSBT ponašanje. BIP 352 zahteva ponovno izvođenje output-a ako se input-i promene, a neki signing mode-ovi nisu bezbedni.
5. Sačuvajte enkriptovani receipt ili proof potreban za sporove/računovodstvo.

Silent Payments rešavaju ponovno objavljivanje recipient address-a. Ne skrivaju amount, vreme transakcije, sender cluster, istoriju nabavke niti kasnije co-spending aktivnosti.

## Zcash fully shielded payments

Zcash podržava transparentne i shielded value pool-ove. Orchard shielded transakcije koriste zero-knowledge proofs kako bi node-ovi mogli da provere validnost dok su detalji transakcije enkriptovani; Unified Addresses mogu sadržati više tipova receiver-a.<sup>[[2]](#references)</sup> Privatnost zavisi od stvarne putanje koju wallet izabere, a ne od prvog karaktera prikazane adrese.

### Shielded workflow

1. Izaberite održavan wallet koji jasno navodi **shielded-by-default** ponašanje i aktuelnu Orchard podršku. Proverite download i napravite backup/test seed-a.
2. Nabavite ZEC zakonito i zabeležite osnov/poreklo. Exchange i dalje zna za acquisition i withdrawal.
3. Primite sredstva na Unified Address koju wallet podržava, a zatim proverite da li je transakcija završila u shielded pool-u. Ne pretpostavljajte automatsko shielding ponašanje bez provere wallet-a.
4. Dajte prednost **shielded-to-shielded** transferima. Transparent-to-shielded i shielded-to-transparent granična kretanja otkrivaju javne vrednosti/vreme i mogu omogućiti korelaciju iznosa; Orchard specification navodi da spending na non-Orchard address otkriva vrednost transakcije.<sup>[[3]](#references)</sup>
5. Izbegavajte karakteristične round trip-ove sa tačnim iznosima i trenutne prelaze preko granice. Ovo je privacy hygiene, a ne dozvola za prikrivanje vlasništva ili prijavljivanja.
6. Koristite network-privacy putanju koju wallet podržava. Shielded cryptography ne skriva IP/vreme od wallet servera ili peer-ova.
7. Čuvajte interne compliance zapise i koristite viewing keys samo za namerni audit/disclosure nakon razumevanja njihovog opsega.
8. Potvrdite podršku wallet-a/exchange-a primaoca pre slanja; primoravanje na transparent receiver menja privacy svojstvo.

## GNU Taler: anonymous payer, accountable merchant

GNU Taler je otvoreni electronic-payment protokol koji koristi tradicionalne valute, blind signatures i integraciju sa regulated exchange/bank sistemima. Njegov dizajn ima za cilj da zadrži anonimnost korisnika pred merchant-ima, dok merchant-i ostaju identifikovani i oporezivi.<sup>[[4]](#references)</sup> Nije cryptocurrency, a dostupnost zavisi od kompatibilnog regionalnog exchange-a, banke, wallet-a i merchant-a.

### User workflow tamo gde je deployed

1. Identifikujte aktivni Taler exchange i merchant u relevantnoj valuti/jurisdikciji; pročitajte njihove aktuelne uslove, naknade, KYC i privacy notices.
2. Instalirajte official wallet i proverite njegov izvor. Zaštitite wallet backup/recovery podatke kao gotovinu jer wallet value može biti bearer asset.
3. Povucite sredstva kroz podržani bank/exchange flow koristeći istinite podatke. Funding institution/exchange može znati za withdrawal iako blind signatures prekidaju direktnu vezu između coin-a i withdrawal-a.
4. Pregledajte merchant contract u wallet-u: identitet merchant-a, stavku/sažetak, amount, naknade, refund i delivery uslove.
5. Platite i sačuvajte receipt podatke potrebne za refund, warranty, računovodstvo ili porez.
6. Nemojte ponovo koristiti optional merchant session/account identifiers ako je potrebna unlinkability merchant-a.
7. Uključite wallet, network i delivery metadata u threat model; Taler payment cryptography ne skriva shipping address ili compromised endpoint.

Merchant i exchange ostaju odgovorni, a upravljanje bilo kojom od tih komponenti može predstavljati regulated payment-service activity.

## Federated Chaumian e-cash

Chaumian e-cash koristi blind signatures tako da mint potpisuje token bez uvida u neblinded token koji se kasnije troši. Fedimint distribuira custody rezervi i signing među guardian federation-om; njegova dokumentacija navodi da guardian-i vide aggregate reserves/outstanding notes, ali ne bi trebalo da vide pojedinačno stanje niti ko je kome platio unutar federation-a.<sup>[[5]](#references)</sup>

Ovo je **custodial bearer value**. Dovoljan guardian quorum kontroliše rezerve; failure federation-a, dishonest guardian-i, software bugs ili gubitak client state-a mogu dovesti do gubitka. Deposits, withdrawals i Lightning gateway-i su vidljivi boundary events i mogu korelisati vreme/iznos.

### Workflow sa ograničenim rizikom

1. Koristite samo mali iznos koji možete da izgubite. Tretirajte javne/nepoznate federation-e kao rizičnije od guardian-a sa stvarnom odgovornošću u realnom svetu.
2. Proverite federation invite preko authenticated channel-a i zabeležite identitete guardian-a, quorum, jurisdikciju, naknade, recovery i shutdown policy.
3. Instalirajte održavan kompatibilan wallet, proverite ga i razumejte njegov backup scheme pre deposit-a.
4. Deponujte zakonito pribavljen Bitcoin kroz dokumentovanu putanju. Zabeležite peg-in za računovodstvo i pretpostavite da su njegovo vreme/iznos javni ili poznati na granici sistema.
5. Unutar federation-a koristite fresh payment requests i izbegavajte dodavanje account/chat/delivery identifiers koji ponovo stvaraju vezu uklonjenu blind signature-om.
6. Za Lightning payments, tretirajte gateway kao dodatnog posmatrača invoices i boundary timing-a.
7. Izvršite redeem/withdrawal prema policy-ju i očekujte da se karakterističan iznos i neposredno vreme mogu korelisati sa deposit-om ili eksternim payment-om.
8. Privatno čuvajte tax/source/authorization records; nemojte tražiti od guardian-a ili gateway-a da netačno prikažu aktivnost.

Nemojte federated e-cash opisivati kao trustless, self-custodial ili garantovano anoniman.

## BOLT 12 offers i route blinding

BOLT 12 offers mogu biti reusable bez objavljivanja stabilne on-chain adrese i mogu koristiti blinded paths tako da payer ne mora saznati jasan identitet/path receiver node-a. Ovo dopunjuje, ali ne zamenjuje postojeći Lightning onion routing.

Pre korišćenja:

1. Potvrdite da sender i receiver wallet-i podržavaju iste aktuelne BOLT 12 funkcije; ne zaključujte o podršci na osnovu opšteg “Lightning” brendinga.
2. Authentifikujte offer out of band i proverite amount, issuer/description i recurrence rules.
3. Koristite fresh invoice/payment context generisan iz offer-a.
4. Svedite node aliases, javne kontakt-informacije i stabilne network endpoint-e na minimum.
5. Pretpostavite da sender/receiver, first/last hop, wallet service, channel graph i on-chain funding/closure i dalje otkrivaju delove odnosa.

## Auditability bez javnog disclosure-a

Privatnost i audit mogu koegzistirati:

- Enkriptovano čuvajte labels, invoices, authorization, cost basis i ownership mapping izvan javnog protokola.
- Odvojite **view/audit key** od spending key-a kada ga protokol pruža; prvo testirajte njegovo tačno disclosure ponašanje na sample wallet-u.
- Auditor-u dajte minimalni proof ograničenog opsega umesto seed-a ili neograničenog spending credential-a.
- U trenutku transakcije zabeležite software version, protocol/pool, transaction ID ili proof, svrhu counterparty-ja i izvor exchange rate-a.
- Definišite retention i deletion umesto akumuliranja trajnog neenkriptovanog identity graph-a.

## Checklist za izbor

- [ ] Hidden field i observer su precizno navedeni.
- [ ] Wallet/protocol podrška je proverena na datum transakcije.
- [ ] Acquisition, network, node/RPC, counterparty, delivery i later-spend veze su dokumentovane.
- [ ] Custody, recovery, liquidity, issuer/federation solvency i refund rizici su prihvaćeni.
- [ ] Obavezni identity, tax, sanctions, source i organizational records ostaju tačni.
- [ ] Mali end-to-end test, uključujući recovery i audit proof, uspešno je završen.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
