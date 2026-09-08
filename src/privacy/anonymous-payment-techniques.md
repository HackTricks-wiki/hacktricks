# Katalog tehnika anonimnog plaćanja

{{#include ../banners/hacktricks-training.md}}

Ovaj katalog obuhvata **familije** plaćanja, od običnog gotovog novca do e-novca sa slepim potpisom i obfuskacije javnih lanaca. „Anonimno“ uvek znači anonimno u odnosu na imenovanog posmatrača. Trgovac, izdavalac, mint, exchange, blockchain analitičar, mrežni provajder, poslodavac i fizički posmatrač vide različite činjenice.

Procedure u nastavku namenjene su zakonitim sredstvima, istinitim nalozima i ovlašćenoj nabavci. Tehnike čija je svrha u navedenim slučajevima bila pranje novca, izbegavanje sankcija ili prevara identiteta objašnjene su i detektuju se, ali je njihova procedura sintetička forenzička vežba, a ne uputstvo za izvršenje krivičnog dela.

## Matrica obuhvata

| Familija | Glavno svojstvo privatnosti | Glavni posmatrač/poverenje | Tretman |
|---|---|---|---|
| Gotovina i ekvivalenti gotovine | nema udaljenog zapisa platne mreže | primalac i fizičko okruženje | zakonit tok |
| Prepaid/gift/voucher vrednost | odvaja redemption od primarne kartice | prodavac, izdavalac i redemption servis | zakonit tok, zavisi od jurisdikcije |
| Virtual/tokenized kartica | skriva ponovo upotrebljivi PAN ili razdvaja trgovce | issuer/network/wallet i dalje identifikuju platioca | zakonit tok |
| Payment app/intermediary | trgovac može videti alias/intermediary | aplikacija prikuplja identitet/uređaj/transakciju | osnov za poređenje |
| Bitcoin hygiene/Silent Payments | pseudonimi i unlinkability primaoca | javni graf i granica wallet/network | deployable |
| PayJoin/CoinJoin | slabi heuristike zajedničkog vlasništva/linkage | učesnici/coordinator/network/javni graf | deployable gde je podržano; pravna provera |
| Lightning/BOLT 12 | off-chain rutiranje i smanjenje putanje do primaoca | krajnje tačke, hopovi, servisi i graf kanala | deployable gde je podržano |
| Monero/Zcash/MWEB | poverljivost na nivou protokola | acquisition, endpoint, network i granice i dalje postoje | deployable gde je zakonito/podržano |
| Ethereum ZK application | skriva određenu vezu između izjave i radnje | javni inputi, RPC, relayer i aplikacija | specifično za aplikaciju |
| Cashu/Fedimint/Taler | privatnost platioca putem slepih potpisa | mint/federation/exchange custody i granice | u razvoju/specifično za deployment |
| Stablecoins | praktično digitalno poravnanje | transparentni chain i kontrola izdavaoca | nije anonimna osnova |
| Swaps/bridges/DEX | premešta vrednost između asset/chain | oba grafa, contracti i provajderi | forenzička mehanika; samo obični zakoniti swaps |
| Mixers/peel/structuring | povećava dvosmislenost/rad nad grafom | entry/exit graf i zapisi servisa | samo sintetička vežba detekcije |
| Nominees/mules/OTC/fronts | ubacuje ljudske/poslovne posrednike | facilitatori, banke, komunikacije | samo analiza kriminalne zloupotrebe |
| Reusable/stealth payment addresses | nova adresa primaoca za svako plaćanje | javno objavljivanje/notification i wallet granice | deployable gde je podržano |
| Confidential sidechain/state channel | skriva iznos/asset ili međustanja | peers, bridge/federation i lifecycle settlement | specifično za protokol |
| Carrier/open-banking/platform billing | skriva primarnu karticu od trgovca | carrier, banka/PISP ili platforma identifikuje korisnika | obično identifikovano plaćanje |
| Mutual credit/net settlement | manje eksternih zapisa poravnanja | privatni operator ledger-a ima potpuno mapiranje | samo identifikovani učesnici |

## Gotovina

**Mehanika:** fizička bearer vrednost menja vlasnika bez online autorizacije izdavaoca ili javnog ledger-a.

**Prednosti:** trgovac ne mora saznati identitet banke/kartice; nema udaljenog transakcionog grafa; široko je razumljiva i konačna.

**Nedostaci:** samo licem u lice; krađa/gubitak; kusur/račun/serijski broj ili kontrole prijavljivanja; podizanje novca, kamere, svedoci i lokacija i dalje povezuju platioca.

**Procedura:** (1) potvrditi da je gotovina zakonita/prihvaćena i proveriti pravila o iznosu/prijavljivanju; (2) zakonito je podići ili primiti i voditi privatne računovodstvene evidencije; (3) platiti običnom trgovcu bez nepotrebnih loyalty/account identifikatora; (4) tražiti samo obavezni račun; (5) izbeći shipping/account podatke ako kupovina to ne zahteva; (6) interno zabeležiti zakonitu poslovnu svrhu.

**Detekcija:** uskladiti kasu/račun/inventar, kamere i access logove prema važećoj politici; istražiti neuobičajene cash refunding obrasce ili ponovljene iznose neposredno ispod kontrolnog praga, bez automatskog tretiranja obične upotrebe gotovine kao sumnjive.

## Money order, postal order, cashier instrument i cash on delivery

**Mehanika:** regulisani izdavalac pretvara gotovinu/sredstva sa računa u numerisani instrument plativ imenovanom primaocu; COD odlaže naplatu do dostave.

**Prednosti:** primalac možda ne dobije primarni broj bankovnog računa/kartice platioca; upotrebljivo kada gotovina ne može daljinski da se prenese; jasan račun.

**Nedostaci:** izdavalac/prodavac zadržava podatke o kupovini/identitetu prema obavezi; serijsko praćenje; adresa primaoca/dostave; gubitak/prevara i regionalna ograničenja; uglavnom nije anonimno.

**Procedura:** (1) proveriti pravila izdavaoca, limite, identifikaciju i prihvatanje primaoca; (2) kupiti istinitim podacima i zakonitim sredstvima; (3) odmah popuniti payee/iznos; (4) sačuvati serijski broj/račun; (5) koristiti praćenu dostavu primerenu vrednosti; (6) uskladiti redemption/refund.

**Detekcija:** evidencija kupovine/redemption kod izdavaoca, serijski broj instrumenta, prodavac/kamera, shipping i account primaoca; označiti izmene, duple serijske brojeve i brzo geografski neusklađeno redemption.

## Open-loop prepaid card

**Mehanika:** stored-value credential sa oznakom mreže autorizuje trošenje prepaid salda umesto primarnog kreditnog računa.

**Prednosti:** ograničava izloženost trgovca i gubitak; odvaja trgovca od glavnog PAN-a; upotrebljivo online gde je prihvaćeno.

**Nedostaci:** purchase/activation/reload/registration i device zapisi; KYC i limiti variraju; problemi sa billing address; ograničeni cash-out/refund; „bez imena“ ne znači bez zapisa izdavaoca.

**Procedura:** (1) proveriti identitet aktuelnog izdavaoca, naknade, KYC, geografiju i podršku za online/recurring plaćanja; (2) nabaviti preko ovlašćenog prodavca zakonitim sredstvima; (3) registrovati istinite obavezne podatke; (4) koristiti za jednu compartment/purpose; (5) ne strukturirati loads niti izmišljati prebivalište; (6) čuvati dokaze o kupovini/trošku i zatvoriti/odložiti prema uslovima izdavaoca.

**Detekcija:** povezati seller/activation, funding, device/IP, merchant authorization, balance checks i redemption/refund. Obrasci su važniji od prepaid oznake.

## Closed-loop gift card, voucher i transferable service credit

**Mehanika:** numerisana vrednost može se iskoristiti samo kod jednog trgovca/servisa ili u jednom ekosistemu. Airtime/game/store credits su varijante.

**Prednosti:** trgovac primalac može videti samo code/balance; ograničen blast radius; lako poklanjanje i odvajanje budžeta.

**Nedostaci:** seller i service beleže purchase/activation/redemption; account/device/delivery i dalje povezuju aktivnosti; prevare, popusti pri preprodaji i expiry/region limiti; slaba prava na refund.

**Procedura:** (1) kupovati samo ovlašćenim kanalima; (2) zabeležiti vrednost koda bez otkrivanja tajne; (3) ne vezivati nepotrebno identifying loyalty account; (4) redeem obaviti kroz odvojen zakonit merchant account/context; (5) čuvati račun dok prihvatanje ne bude potvrđeno; (6) nikad ne kupovati codes zbog neželjenog zahteva za „porez“, „podršku“ ili „otkup“.

**Detekcija:** vreme izdavanja/redemption koda, device/account convergence, bulk/threshold obrasci kupovine, jedan uređaj koji proverava mnogo salda i udaljeni brzi redemption.

## Cryptocurrency-funded card ili gift-code broker

**Mehanika:** intermediary prihvata cryptocurrency i izdaje karticu, voucher ili merchant code. To je konverzija između rail-ova: trgovac vidi običnu card/gift vrednost, dok broker povezuje on-chain deposit sa izdavanjem i dostavom.

**Prednosti:** trgovac ne dobija funding wallet; korisno za zakonite trgovce koji ne prihvataju crypto; ograničena stored value.

**Nedostaci:** nije anonimno u odnosu na brokera/izdavaoca; KYC, sanctions, exchange i card-program pravila; javni deposit graf; account/device/email i code redemption ponovo povezuju obe strane; rizik prevare/insolventnosti.

**Procedura:** (1) proveriti pravno lice, card issuer, podržanu jurisdikciju, KYC, naknade i refund policy; (2) koristiti samo zakonita dokumentovana sredstva; (3) testirati najmanju denominaciju; (4) proveriti network/merchant ograničenja pre kupovine; (5) sačuvati blockchain transakciju i broker receipt radi računovodstva; (6) nikada ne koristiti brokera koji obećava identity fraud, sanctions bypass ili „untraceable“ cash-out.

**Detekcija:** povezati broker deposit addresses, jedinstven iznos/vreme, account/device i issued-card authorization ili gift-code redemption; zapisi izdavaoca i brokera spajaju javni chain sa trgovcem.

## Virtual ili merchant-locked card

**Mehanika:** issuer povezuje generisani PAN/token sa stvarnim računom, često ograničavajući trgovca, iznos ili expiry.

**Prednosti:** sprečava otkrivanje ponovo upotrebljivog PAN-a; compartmentation po trgovcu; limiti potrošnje i laka revokacija; zrela fraud kontrola.

**Nedostaci:** issuer i dalje zna platioca, funding, merchant, device/IP i vreme; merchant vidi account/delivery; neki refunds/recurring charges ne uspevaju; nije anonimno.

**Procedura:** (1) koristiti zvaničnu funkciju regulisanog issuer-a; (2) kreirati karticu za jednog merchant/engagement; (3) postaviti najmanji koristan limit i expiry; (4) koristiti tačan billing gde je obavezan; (5) proveriti statement descriptor/refund ponašanje; (6) freeze/delete nakon konačnog settlement-a uz čuvanje audit dokaza.

**Detekcija:** issuer token-to-account mapping, merchant authorization, device i delivery. Defenders koriste merchant-specific reuse, velocity i account takeover signale.

## Mobile-wallet network token

**Mehanika:** EMV payment tokenization zamenjuje PAN ograničenim credential-om, često vezanim za uređaj, trgovca ili scenario plaćanja.<sup>[[1]](#references)</sup>

**Prednosti:** trgovac ne dobija ponovo upotrebljivi PAN; device cryptography/dynamic data smanjuju kloniranje; revokable je bez zamene kartice.

**Nedostaci:** issuer, token service, wallet platform i network zadržavaju mapping/transakcije; device/platform account i lokacija mogu identifikovati platioca.

**Procedura:** (1) registrovati legitimnu karticu u zvaničnom wallet-u; (2) zaštititi platform account/device jakom autentifikacijom; (3) proveriti device token/poslednje cifre pri kupovini; (4) isključiti nepotrebnu lokaciju/analytics gde je podržano; (5) odmah onemogućiti izgubljene devices/tokens; (6) pregledati issuer i wallet records.

**Detekcija:** token requestor/device cryptogram i issuer mapping, wallet/account telemetry, merchant terminal i fizički dokazi.

## Payment app, marketplace wallet i centralized intermediary

**Mehanika:** servis održava accounts i interne transfere ili koristi bank/card rails; trgovac može videti alias, dok servis vidi obe strane.

**Prednosti:** praktičnost, dispute/refund mehanizmi, primalac ne mora nužno videti bank/card podatke.

**Nedostaci:** centralizovani identity/social/transaction/device graf; freezes i legal process; counterparties mogu otkriti profile; upotreba podataka može prevazići potrebe plaćanja.<sup>[[2]](#references)</sup>

**Procedura:** (1) pročitati identity, privacy, retention i buyer-protection uslove; (2) svesti optional profile/contact synchronization na minimum; (3) koristiti odvojen istinit account samo kada uslovi to dozvoljavaju; (4) uključiti MFA/alerts; (5) proveriti primaoca i privatnost memo/profile podataka; (6) izvesti records i zatvoriti neiskorišćene links.

**Detekcija:** provider account, device/IP, contact graph, funding/withdrawal, memo i merchant records. Alias je pseudonymity prema counterparty-ju, a ne anonymity prema platformi.

## Bank transfer, ACH, wire i instant-account payment

**Mehanika:** regulisane institucije prenose vrednost između identifikovanih računa i razmenjuju obavezne payment podatke.

**Prednosti:** brzo, odgovorno, ograničeno reverzibilno i sa snažnim evidencijama; virtual account numbers mogu smanjiti disclosure trgovcu.

**Nedostaci:** banke/processors znaju obe strane; statements i references; nije anonimno; prekogranični i Travel Rule/AML podaci.

**Procedura:** koristiti samo kada je prihvatljiva odgovornost: nezavisno proveriti beneficiary, svesti optional memo podatke na minimum, koristiti bank-provided virtual account/reference gde postoji, uključiti alerts, sačuvati invoice i uskladiti.

**Detekcija:** deterministički bank/payment records, vlasništvo beneficiary/account, device/session i fraud controls. Ovo je baseline, a ne anonymity tehnika.

## Account i merchant compartmentation

**Mehanika:** odvojeni zakoniti identities/accounts, email aliases, cards i delivery contexts sprečavaju da nepovezani trgovci trivijalno spoje aktivnosti, dok issuer/controller zadržava mapping.

**Prednosti:** smanjuje breach i cross-merchant linkage; lako za audit; kompatibilno sa regulated payments.

**Nedostaci:** provider i dalje povezuje compartments; recovery phone/device/IP i shipping mogu ih ponovo spojiti; policy može zabraniti više accounts.

**Procedura:** (1) definisati jednu svrhu; (2) kreirati samo aliases/subaccounts usklađene sa uslovima; (3) koristiti merchant-specific token/card; (4) isključiti cross-account contact/ad personalization; (5) voditi encrypted controller ledger; (6) povući identifiers po završetku refund/retention potreba.

**Detekcija:** providers povezuju recovery, device, funding i IP; merchants povezuju delivery, browser i account behavior. Defenders treba da razlikuju legitimnu compartmentation od synthetic identity fraud.

## Controlled red-team procurement

**Mehanika:** SOC ne zna za kupovinu, dok exercise controller zadržava mapping pravnog lica, operatora i infrastrukture.

**Prednosti:** realistična vežba detekcije; nema izlaganja ličnih podataka; neposredna deconfliction i audit.

**Nedostaci:** nije anonimno prema organization/provider; governance overhead; leak ako se controller ledger-om loše rukuje.

**Procedura:** (1) dodeliti engagement-specific organization card/wallet/budget; (2) razdvojiti uloge purchaser/operator; (3) zabeležiti asset, amount, service, purpose i kill date; (4) čuvati attribution mapping uz ograničen pristup controller-a; (5) nikada ne koristiti false identity/mule/stolen funds; (6) na kraju otkriti i uskladiti indikatore i refunds.

**Detekcija:** controller mapira provider invoice i asset; SOC testira nezavisno otkrivanje kroz domain, certificate, hosting i traffic, a ne kroz cardholder podatke.

## Bitcoin address hygiene i coin control

**Mehanika:** sveže receive addresses, lokalne oznake i selektivno trošenje UTXO-a smanjuju address reuse i slučajno spajanje compartments na javnom ledger-u.

**Prednosti:** široka podrška; self-custodial; izbegava najjednostavnije javno povezivanje.

**Nedostaci:** sve transakcije/iznosi ostaju javni; common-input/change/timing i kasnija consolidation povezuju aktivnosti; acquisition/RPC/network records ostaju.

**Procedura:** (1) instalirati/proveriti održavani wallet; (2) napraviti backup i testirati seed recovery; (3) koristiti novu address za svaki invoice; (4) lokalno označiti source/purpose; (5) koristiti coin control za izbegavanje spajanja contexts; (6) preferirati local node ili privacy-aware connection; (7) pregledati change/fees i čuvati zakonito računovodstvo.<sup>[[3]](#references)</sup>

**Detekcija:** address graph, common-input/change heuristics uz neizvesnost, exact amount/time, consolidation, service deposits, node/RPC broadcast timing i off-chain records.

## Bitcoin Silent Payments

**Mehanika:** BIP 352 omogućava primaocu da objavi static code, dok senders izvode jedinstvene Taproot outputs putem ECDH; spoljašnji posmatrači ne mogu direktno povezati outputs sa code-om.<sup>[[4]](#references)</sup>

**Prednosti:** reusable public identifier bez address reuse; nema interaktivnog zahteva za address ili notification output-a; uklapa se u Taproot outputs.

**Nedostaci:** trošak scanning-a kod primaoca; wallet podrška varira; amount/sender graph i spending ostaju javni; index server može videti scans.

**Procedura:** (1) izabrati aktuelni BIP 352 wallet; (2) backup/test descriptor i scanning recovery; (3) generisati labeled code gde je podržano; (4) autentifikovati objavljeni code; (5) sender pregleda inputs i šalje mali test; (6) receiver skenira po mogućnosti preko sopstvenog node-a; (7) držati primljene UTXO-e odvojeno.

**Detekcija:** po dizajnu se ne može pouzdano prepoznati samo iz output-a; analysts koriste sender inputs, amount/time, kasnije spending, wallet/network/index i counterparty records.

## PayJoin

**Mehanika:** payer i payee doprinose inputs jednoj payment transakciji, čime se narušava pretpostavka da svi inputs pripadaju istom owner-u.<sup>[[5]](#references)</sup>

**Prednosti:** obično plaćanje sa boljom privatnošću; koristi širem grafu slabljenjem zajedničke heuristike; nije potrebna grupa equal outputs.

**Nedostaci:** interaktivnost/podrška; dostupnost receiver endpoint-a; amount i final transaction su javni; implementation i fallback metadata.

**Procedura:** (1) potvrditi da oba održavana wallet-a podržavaju istu PayJoin verziju; (2) autentifikovati invoice/endpoint; (3) početi iz wallet-ovog PayJoin-enabled payment URI-ja; (4) pregledati final amount/fee i potpisati samo očekivane inputs; (5) izbeći ručnu transaction surgery; (6) proveriti broadcast i receipt; (7) zabeležiti fallback ako negotiation ne uspe.

**Detekcija:** blockchain analysts ne smeju automatski primeniti common-input clustering; endpoint/provider može logovati negotiation; koristiti wallet/network i kasnije spending evidence, a ne samo oblik transakcije.

## CoinJoin

**Mehanika:** više učesnika zajednički kreira transakciju sa mnogo inputs/outputs, često jednakih denominacija, povećavajući nejasnoću correspondence između inputa i outputa.

**Prednosti:** veći on-chain ambiguity set; postoje self-custodial designs; merljiva struktura runde.

**Nedostaci:** coordinator/peer/network metadata; fees/liquidity; prepoznatljiv transaction shape; toxic change i kasnija consolidation uništavaju dobitke; legal/provider dostupnost varira.

**Procedura:** (1) proveriti aktuelnu dostupnost wallet/coordinator-a i zakonitost; (2) instalirati official wallet i napraviti backup; (3) koristiti samo zakonite UTXO-e; (4) razumeti denomination, fee i coordinator model; (5) označiti i odvojiti change i mixed outputs; (6) nikada ih ne konsolidovati zajedno; (7) usmeriti network traffic kako je zvanično podržano i sačuvati accounting.

**Detekcija:** identifikovati collaborative structure bez pretpostavke o krivičnom delu; izračunati moguće mappings/anonymity set, zatim pratiti change/consolidation, service boundaries i network/coordinator records.

## Lightning Network

**Mehanika:** HTLC payments prolaze kroz onion-routed channels; većina payment detalja nije objavljena on-chain, dok su funding/closing i javne channel informacije vidljive.

**Prednosti:** brzo, niske naknade; intermediaries obično vide susedne hopove; rutinski payment detalji ostaju off-chain.

**Nedostaci:** sender/receiver i first/last hop znaju više; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets identifikuju korisnike.

**Procedura:** (1) svesno izabrati self-custodial ili custodial; (2) proveriti wallet/seed/channel recovery; (3) koristiti invoice za tačno plaćanje; (4) preferirati private channels/LSP features tek nakon razumevanja tradeoff-a; (5) zaštititi node IP podržanim Tor-om gde je potrebno; (6) ne ponavljati identifying invoices; (7) voditi channel i payment accounting.<sup>[[6]](#references)</sup>

**Detekcija:** node/LSP/custodian logs, channel graph/probes, payment failure/timing i on-chain funding/closure; nepostojanje javne transakcije ne znači nepostojanje zapisa.

## BOLT 12 offers i route blinding

**Mehanika:** reusable offer proizvodi sveže invoices i može oglašavati blinded paths tako da payer ne mora saznati jasan node/path primaoca.

**Prednosti:** privatnost primaoca; reusable donation/payment endpoint bez static invoice-a; integriše se sa Lightning onion routing-om.

**Nedostaci:** wallet podrška varira; endpoints, izabrani hops i funding ostaju; javni contact ili network endpoint može ponovo identifikovati primaoca.

**Procedura:** (1) potvrditi matching BOLT 12 support; (2) autentifikovati offer; (3) zatražiti fresh invoice; (4) proveriti amount/issuer/recurrence; (5) platiti kroz wallet; (6) proveriti receipt/refund behavior; (7) svesti node alias/contact na minimum i sačuvati accounting.<sup>[[7]](#references)</sup>

**Detekcija:** wallet/LSP i first/last-hop telemetry, offer distribution account, timing/value i funding graph; route blinding namerno ograničava vidljivost payer-a.

## Monero

**Mehanika:** one-time stealth addresses skrivaju linkage primaoca, RingCT skriva iznose, a ring signatures daju nejasnoću pošiljaoca.

**Prednosti:** privatnost je podrazumevana on-chain; poverljivost sender/receiver/amount; zreo dedicated wallet/node ekosistem.

**Nedostaci:** acquisition/off-ramp i endpoint/network/counterparty records; remote node vidi queries/IP; exchange podrška i pravni tretman variraju; male operativne greške i dalje povezuju contexts.

**Procedura:** (1) zakonito pribaviti i sačuvati osnov/source; (2) instalirati/proveriti zvanični održavani wallet; (3) backup/test seed; (4) koristiti local node ili dokumentovan Tor/I2P remote-node path; (5) koristiti novu subaddress za svakog payer/invoice; (6) lokalno označiti contexts; (7) transaction proof/view access otkrivati samo namerno.<sup>[[8]](#references)</sup>

**Detekcija:** usmeriti pažnju na exchange/merchant/device/network i zaplenjeni wallet; sama upotreba protokola nije sumnjiva, a javni chain namerno otkriva manje.

## Zcash potpuno shielded Orchard

**Mehanika:** zero-knowledge proofs validiraju shielded transfers dok su sender, receiver i amount encrypted; transparent pools i pool transitions ostaju javni.

**Prednosti:** snažna shielded on-chain poverljivost; viewing keys omogućavaju ograničen audit; validnost je nametnuta protokolom.

**Nedostaci:** wallet/exchange support i stvarni izbor pool-a variraju; transparent boundary timing/value correlation; network/RPC i endpoint ostaju.

**Procedura:** (1) izabrati održavani Orchard shielded-by-default wallet; (2) proveriti/napraviti backup; (3) zakonito pribaviti ZEC; (4) primiti na podržanu Unified Address i potvrditi pool; (5) preferirati shielded-to-shielded; (6) koristiti podržanu network privacy; (7) testirati viewing-key disclosure na malom wallet-u pre audit-a.<sup>[[9]](#references)</sup>

**Detekcija:** transparent boundary i service records, wallet/network metadata i viewing keys gde su zakonito dostavljeni; ne pretpostavljati da su sva Unified Address plaćanja shielded.

## Mimblewimble i Litecoin MWEB

**Mehanika:** confidential transactions skrivaju amounts, a Mimblewimble-style aggregation uklanja uobičajenu address-rich istoriju; Litecoin implementira optional extension block uz transparent chain.

**Prednosti:** poverljivi iznosi i bolja fungibility u privatnom domenu; efikasno pruning/aggregation.

**Nedostaci:** opt-in boundary peg-in/out je javno i korelabilno; wallet/exchange support; razlike u interactive/address modelu; network i acquisition records.

**Procedura:** (1) izabrati održavani wallet sa jasnim MWEB support-om; (2) proveriti/napraviti backup i testirati mali iznos; (3) zakonito pribaviti; (4) peg-in u MWEB i proveriti balance domain; (5) transaktovati samo sa kompatibilnim receiver-om; (6) izbegavati neposredan karakteristični peg-out; (7) čuvati privatne audit records.<sup>[[10]](#references)</sup>

**Detekcija:** javni peg-in/out timing/value, exchange/wallet/node data i kasniji transparent spends; interni confidential transfer detalji su namerno smanjeni.

## Ethereum zero-knowledge privacy applications

**Mehanika:** circuit dokazuje statement—membership, valid note ownership ili authorization—bez otkrivanja secret-a; verifier contract ga proverava. Deposits, withdrawals, public inputs, events i gas i dalje mogu otkriti links.

**Prednosti:** programabilno selective disclosure; anonymous-set applications; proverljiva pravila bez otkrivanja svih podataka.

**Nedostaci:** contract/circuit bugs; mali anonymity set; javne boundaries; RPC/IP/session/analytics/gas funding; application i sanctions/legal rizik.

**Procedura:** (1) precizno definisati šta proof skriva; (2) koristiti audited maintained application gde je zakonito; (3) pregledati public inputs/events i deposit/withdraw pravila; (4) odvojiti action wallet i gas sponsorship kako protokol predviđa; (5) koristiti privacy-aware RPC/network path; (6) testirati sa malom vrednošću; (7) čuvati compliance records.<sup>[[11]](#references)</sup>

**Detekcija:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics i konačna exchange/merchant boundary. Ne tvrditi da ZK proof skriva fields označena kao public.

## Stablecoins

**Mehanika:** tokens se prenose na javnom chain-u; centralized issuers mogu freeze/blacklist ili redeem prema identifikovanim accounts.

**Prednosti:** price stability, liquidity i merchant support; brzo settlement; jednostavno računovodstvo.

**Nedostaci:** transparent address/amount/contract graph; gas funding; issuer i exchange identity/control; sanctions screening; uglavnom slaba anonymity.

**Procedura:** tretirati kao identifikovano plaćanje: koristiti fresh business address samo za compartmentation, proveriti token contract/network, testirati mali iznos, zaštititi wallet, koristiti trusted RPC/local node, sačuvati basis/source i proveriti obavezne strane.

**Detekcija:** kompletan token event graph, issuer freeze list/actions, exchange/RPC/device i gas-funding relationships.

## Cashu Chaumian e-cash

**Mehanika:** mint slepo potpisuje client-generated bearer secrets pokrivene mint-ovim Bitcoin/Lightning reserves; može sprečiti double-spend bez direktnog povezivanja issuance-a sa kasnijim redemption-om.

**Prednosti:** accountless bearer tokens; instant peer transfer; mint ne može direktno povezati blinded withdrawal sa spend-om; tokens mogu putovati kao data/QR.

**Nedostaci:** mint custody/solvency/censorship; gubitak/krađa bearer data; denomination/timing i Lightning boundaries; network metadata; rani software ecosystem.<sup>[[12]](#references)</sup>

**Procedura:** (1) prvo koristiti official test mint ili veoma malu disposable vrednost; (2) instalirati održavani wallet i testirati ograničenja backup/restore; (3) autentifikovati mint i proveriti custody/fees; (4) mint mali iznos; (5) poslati token kroz authenticated private channel/QR; (6) receiver zamenjuje token pre nego što ga smatra konačnim; (7) redeem i uskladiti. Nikada ne čuvati značajnu vrednost u nepouzdanom mint-u.

**Detekcija:** mint vidi network, issue/redeem/Lightning boundaries i spent-token set, ali blinding uklanja direktni token linkage; endpoints/messages i karakteristični amount/timing mogu obnoviti veze.

## Fedimint federated e-cash

**Mehanika:** threshold guardians drže reserves i slepo potpisuju e-cash; interni bearer transfers su privatni prema guardians, dok Lightning gateways povezuju spoljašnja plaćanja.

**Prednosti:** distribuirano custody; privatan interni transfer; community governance; nijedan guardian ne kontroliše reserve ispod threshold-a.

**Nedostaci:** guardian quorum/custody/software rizik; gateway vidi invoices/timing; deposit/withdraw boundaries; složen oporavak client state-a.

**Procedura:** (1) proveriti federation invite/guardians/quorum/jurisdiction; (2) instalirati održavani client i testirati recovery; (3) deponovati mali zakonit iznos; (4) koristiti fresh internal payment requests; (5) gateway tretirati kao posmatrača za Lightning; (6) testirati redemption; (7) source/tax records čuvati izvan javnih payment podataka.<sup>[[13]](#references)</sup>

**Detekcija:** federation vidi aggregate issuance/redemption, gateways vide external invoices, Bitcoin/Lightning prikazuju boundaries, a endpoint/communication evidence može povezati interne transfere.

## GNU Taler

**Mehanika:** bank-integrated blind-signature e-cash nastoji da payer ostane anoniman trgovcima, dok merchant i income ostaju odgovorni.

**Prednosti:** payer privacy by design; obična valuta; merchant accountability/refunds; nije potreban speculative token.

**Nedostaci:** ograničena deployment; exchange/bank vidi funding; merchant vidi order/delivery; wallet bearer/recovery rizik; regulisani operators.

**Procedura:** (1) pronaći aktuelni exchange/merchant za jurisdikciju/currency; (2) pročitati KYC/fees/privacy; (3) instalirati official wallet; (4) zakonito povući sredstva iz podržane banke/exchange-a; (5) pregledati merchant contract; (6) platiti i sačuvati receipt/refund data; (7) izbeći nepotrebne merchant session identifiers.<sup>[[14]](#references)</sup>

**Detekcija:** bank/exchange withdrawal i merchant deposit su odgovorne granice; merchant order/device/delivery i timing mogu korelisati čak i kada su coins blinded.

## Cross-chain bridge, atomic swap i decentralized exchange

**Mehanika:** contract/service zaključava/burns jedan asset i oslobađa/mintuje drugi, ili counterparties vrše atomic exchange. To prekida pogled jednog ledger-a, ali ne i ekonomsku kontinuitet.

**Prednosti:** interoperabilnost asset/network; može izbeći jednog centralized custodian-a; obična portfolio/liquidity upotreba.

**Nedostaci:** oba chain-a su javna; time/value/fees/liquidity i contracti korelišu; bridge/relayer/frontend/RPC records; smart-contract/counterparty i regulatory rizik.

**Procedura za zakonite swaps:** (1) proveriti official contract/service i legal availability; (2) pregledati custody/audit/fees/slippage; (3) koristiti mali test; (4) zabeležiti oba transaction ID-a i rate; (5) zaštititi approvals; (6) uskladiti destination asset i opozvati nepotreban approval. Ne koristiti swaps za prikrivanje porekla sredstava.

**Detekcija:** bridge deposit/withdraw events, jedinstveni amount minus fees, vremenski redosled, liquidity, relayer/RPC/frontend i kasniji service deposits.

## Centralized mixer ili tumbler

**Mehanika:** servis prima deposits u pool i kasnije vraća druge units, pokušavajući da zamagli direktno input-output mapiranje.

**Prednosti:** teoretski može povećati transaction ambiguity.

**Nedostaci:** operator može ukrasti/logovati; entry/exit timing/value analiza; sanctions/money-transmission i criminal exposure; seizure otkriva mappings; taint/rejection rizik.

**Procedura:** operativni vodič za mixing nije obezbeđen. Bezbedno reprodukovati graf proširenjem [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): kreirati synthetic deposits, pooled outputs, fees i delays; dati analitičarima nepotpune mappings; meriti koje heuristics rade; zatim otkriti ground truth.

**Detekcija:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs i downstream consolidation. Probabilistic attribution označiti kao takav.

## Peel chains, fan-out/fan-in i structuring

**Mehanika:** ponovljene transakcije odvajaju male payments od change-a, dele vrednost na mnogo addresses, ponovo spajaju collectors ili dele iznose radi izbegavanja pregleda.

**Prednosti:** povećava workload naivnog analitičara i broj adresa.

**Nedostaci:** prepoznatljiv value/cadence/transaction continuity; consolidation i service endpoints; structuring samo po sebi može biti nezakonit; fees i operativne greške.

**Procedura:** koristiti samo synthetic CSV/testnet data: generisati veliki source, ponovljene payment/change edges, parallel branches i jedan collector; dodati benigne exchange-like primere; podesiti detekciju i dokumentovati false positives.

**Detekcija:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint i off-chain records. Exchange hot wallets mogu ličiti na ove obrasce, zato je kontekst obavezan.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker i front company

**Mehanika:** drugo lice/account/company prima, konvertuje ili troši sredstva, ubacujući pravne i operativne slojeve između controller-a i transakcije.

**Prednosti za adversary-ja:** imenovani account odmah ne identifikuje controller; može povezati cash, crypto, goods i jurisdictions.

**Nedostaci:** identity fraud/money-laundering exposure; svaki participant dodaje communications, bank/company/tax/shipping records, fees, inconsistencies i witnesses; reused facilitator stvara hubs.

**Procedura:** ne emulirati sa stvarnim ljudima/accounts. Izgraditi synthetic graph sa controller, recruiter, mule, OTC, shell merchant i beneficiary; dodati device/IP/message/bank edges; tražiti od investigators da razlikuju account holder-a od controller-a i zabeleže confidence dokaza.

**Detekcija:** shared device/IP/recovery, unusual beneficiary/velocity, mnogo nepovezanih senders, neposredni onward movement, company/director/invoice inconsistency, communications i cash/commodity delivery.

## NFTs, gambling, merchant goods i refund loops

**Mehanika:** vrednost se pretvara u self-priced asset, wagering balance, resalable goods ili refunds radi stvaranja drugačije transakcione priče.

**Prednosti za adversary-ja:** menja oblik asset-a i uvodi marketplace/merchant intermediaries.

**Nedostaci:** marketplace/account/device i wash-trade graph; odds/play i refund records; delivery/resale evidence; fees/losses; fraud/laundering liability.

**Procedura:** nema workflow-a za concealment. Koristiti synthetic marketplace data sa related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument i common shipping; proveriti detekciju prema legitimnim collectors/customers.

**Detekcija:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery i proceeds reconvergence.

## Physical bearer wallet ili offline token transfer

**Mehanika:** device, paper/QR, hardware bearer instrument ili e-cash token prenosi kontrolu nad secret-om umesto broadcast-a plaćanja pri primopredaji.

**Prednosti:** nema live network event-a tokom razmene; korisno offline; custody nalik gotovini.

**Nedostaci:** copy/theft/loss i neizvesna ekskluzivnost; kasniji redemption/broadcast povezuje; fizički sastanak/shipping; counterfeit/tamper rizik.

**Procedura:** (1) koristiti samo provereni instrument/protocol; (2) privatno inicijalizovati/proveriti autentičnost; (3) učitati samo malu zakonitu vrednost; (4) preneti u dokumentovanom ovlašćenom kontekstu; (5) receiver proverava ili sweep-uje promptno kako protokol zahteva; (6) ne pretpostavljati da sender nije zadržao copy; (7) privatno zabeležiti ownership/tax evidence.

**Detekcija:** purchase/funding i konačni sweep/redemption, device serial/tamper evidence, delivery/meeting i endpoint records.

## Merchant-scoped invoice ili one-time payment request

**Mehanika:** merchant kreira single-use request sa amount, expiry i order reference. Payer ga izmiruje podržanim rail-om bez direktnog izlaganja reusable credential-a trgovcu; issuer ili payment processor i dalje mogu identifikovati obe strane.

**Prednosti:** ograničava credential reuse i accidental cross-merchant identifiers; exact amount/expiry smanjuju greške; kompatibilno sa običnim accounting i refunds.

**Nedostaci:** invoice, delivery, browser, processor i issuer i dalje povezuju order; unique amount/time može pojačati korelaciju; malicious payment links su česti.

**Procedura:** (1) nezavisno autentifikovati merchant; (2) zatražiti fresh invoice sa tačnim amount, asset/network i expiry; (3) pregledati destination i refund rules; (4) platiti iz approved engagement compartment-a; (5) proveriti da merchant potvrđuje isti invoice; (6) sačuvati receipt i transaction reference; (7) request expire, ne reuse.

**Detekcija:** merchant i processor spajaju invoice, session i settlement; unique amounts/timing i delivery identifikuju platioca. **Captured wallet/device:** invoice history otkriva counterparties i purpose; nepotrebne memo podatke svesti na minimum, device enkriptovati i authoritative accounting čuvati u controlled finance system-u.

## Prepaid service credit i capability token

**Mehanika:** service pretvara conventional payment u ograničene internal credits ili bearer capability. Naknadno API/resource korišćenje može izbeći slanje originalne kartice pri svakom zahtevu, ali servis često može povezati issuance sa redemption-om.

**Prednosti:** ograničava spend i compromise loss; odvaja svakodnevne workers od funding credential-a; podržava per-project budgets i revocation.

**Nedostaci:** obično pseudonymous, ne anonymous; service database, redemption IP i jedinstveni usage pattern povezuju aktivnosti; bearer tokens mogu biti ukradeni; refunds mogu zahtevati originalnog payer-a.

**Procedura:** (1) kupiti credits kroz organization account; (2) kreirati jedan project i budget; (3) izdati narrow token sa service, amount i expiry ograničenjima; (4) čuvati samo u approved secret manager-u ili workload identity path-u; (5) testirati odbijanje van scope-a i nakon expiry; (6) pratiti consumption; (7) revoke i uskladiti neiskorišćenu vrednost.

**Detekcija:** provider povezuje funding account, project, token issuance i usage; defenders alertuju na geographic/process changes i anomalous consumption. **Captured node:** pretpostaviti da se preostala capability može potrošiti; koristiti short expiry, low balance, audience binding i immediate server-side revocation.

## Privacy Pass ili blinded authorization token

**Mehanika:** issuer proizvodi privacy-preserving authorization token koji origin može validirati bez povezivanja redemption-a sa issuance-om. Može predstavljati plaćeno entitlement ili rate-limited access, ali nije generalna valuta. Arhitektura razdvaja client, attester, issuer i origin roles i upozorava da IP/timing ili collusion mogu poništiti unlinkability.<sup>[[18]](#references)</sup>

**Prednosti:** unlinkable redemption za podržane servise; nema reusable account cookie-ja na origin-u; cached tokens mogu vremenski odvojiti issuance i use.

**Nedostaci:** specifično za aplikaciju; issuer/attester trust i anonymity-set partitioning; IP i browser metadata ostaju; krađa tokena ili distinctive issuance timing mogu korelisati upotrebu.

**Procedura:** (1) koristiti implementation koja odgovara relevantnom Privacy Pass token type-u; (2) precizno definisati entitlement koji token dokazuje; (3) razdvojiti issuer i origin administration gde threat model to zahteva; (4) svesti challenge metadata na minimum; (5) izdati više test tokens i svaki jednom redeem-ovati na owned origins; (6) porediti logs radi forbidden stable identifiers; (7) testirati replay, expiry i revocation/abuse controls.

**Detekcija:** origins vide redemption IP/time i token validity; issuers/attesters vide issuance context; analysts testiraju timing i metadata partitions bez pretpostavke o cryptographic break-u. **Captured client:** unused bearer tokens mogu biti upotrebljivi; ograničiti njihovu vrednost, lifetime i audience, i nikada sa njima ne keširati funding credential.

## Delegated organization procurement ili fiscal sponsor

**Mehanika:** ovlašćeni procurement team, reseller ili fiscal sponsor ugovara i plaća dok operational team dobija ograničeni service. To je role separation sa istinitim records, a ne nominee ili false identity.

**Prednosti:** vendors ne moraju dobiti identitet svakog operatora ili lične payment podatke; central compliance, tax i refund handling; jasan budget i offboarding.

**Nedostaci:** sponsor zna beneficiary i purpose; contracts, approvals, delivery i accounts ostaju; dodatni delay/fees; slaba separation ako isto lice administrira sve slojeve.

**Procedura:** (1) dokumentovati business purpose, beneficiary i approving authority; (2) izabrati organization-approved intermediary; (3) ugovoriti pod istinitim podacima; (4) provision project-scoped subaccount bez ličnog billing credential-a; (5) razdvojiti finance administrators od operators; (6) uskladiti invoices i access; (7) pri zatvaranju prekinuti i service i delegated access.

**Detekcija:** procurement, identity-provider, vendor i delivery records spajaju lanac. **Captured operational device:** treba da otkrije service project, ali ne finance credentials; invoices i payer identities čuvati u finance system-u, ne na field nodes.

## Escrow ili conditional settlement

**Mehanika:** trusted escrow agent ili smart contract drži vrednost dok se dokumentovani uslovi ne ispune. Može smanjiti direktno disclosure između payer-a i payee-ja, dok escrow i underlying payment rails zadržavaju odnos.

**Prednosti:** zaštita od spora i za delivery; payer i merchant mogu izložiti manje reusable credentials jedan drugom; auditabilni release conditions.

**Nedostaci:** escrow custody/contract risk, fees i identity obligations; on-chain contracts su javni; order, shipping i dispute data ostaju; nije anonimno prema intermediary-ju.

**Procedura:** (1) proveriti legal entity, custody, fees, dispute forum i supported assets; (2) napisati tačan milestone i refund path; (3) fund iz approved organization account-a; (4) nezavisno proveriti receipt i release authorization; (5) release tek nakon dokaza; (6) sačuvati kompletan audit record; (7) zatvoriti unused permissions ili contract approvals.

**Detekcija:** escrow account/contract events, funding i release time, beneficiary i dispute records otkrivaju transakciju. **Captured device:** session tokens ili contract approvals mogu omogućiti release; zahtevati separate approver/MFA i revoke active sessions pri gubitku.

## Batched ili pooled organization settlement

**Mehanika:** mnoge odobrene obaveze agregiraju se i poravnavaju u manje bankarskih ili blockchain transakcija, uz privatni internal ledger koji dodeljuje svaki udeo. Batching može smanjiti javne detalje po kupovini, ali coordinator zadržava potpunu atribuciju.

**Prednosti:** niže fees; manje javnih graph edges; skriva pojedinačne line items od javnog posmatrača kada se iznosi agregiraju; jednostavno interno računovodstvo.

**Nedostaci:** coordinator je potpuni posmatrač i high-value target; distinctive totals/timing mogu korelisati; custody i reconciliation rizik; abuse može ličiti na structuring.

**Procedura:** (1) definisati participants i zakonite obligations u accounting system-u; (2) postaviti redovan, poslovno opravdan batch window, a ne thresholds radi izbegavanja controls; (3) zahtevati dual approval aggregate-a; (4) settle do authenticated recipients; (5) uskladiti svaki internal line sa batch-om; (6) refunds obrađivati kao linked corrections; (7) zaštititi ledger access i zadržati ga prema policy-ju.

**Detekcija:** coordinator ledger, approval i beneficiary records daju ground truth; javni analysts oprezno koriste input/output/value/time clustering. **Captured payer device:** treba da sadrži samo requisition, ne pool signing key ili participant ledger.

## Account-abstraction paymaster ili sponsored gas

**Mehanika:** relayer/bundler šalje smart-account operation, a paymaster plaća transaction fees, izbegavajući direktnu native-gas funding edge iz user wallet-a. Poboljšava jedno svojstvo grafa; operation, contract i service telemetry ostaju javni ili vidljivi.<sup>[[19]](#references)</sup>

**Prednosti:** uklanja čestu gas-funding vezu; podržava scoped sponsorship i rate limits; bolje onboarding za legitimne privacy applications.

**Nedostaci:** paymaster/bundler/RPC/front end mogu korelisati requests; contract events i public inputs ostaju; sponsorship policy fingerprint-uje cohort; malicious contracts ili approvals mogu ukrasti assets.

**Procedura:** (1) koristiti audited maintained smart account i paymaster na ispravnom network-u; (2) proveriti koji fields su public i šta sponsor loguje; (3) ograničiti sponsorship prema contract, function, amount, nonce i expiry; (4) testirati malom vrednošću; (5) slati kroz intended privacy-aware application path; (6) proveriti operation i fee payer on chain; (7) revoke allowances/session keys i sačuvati compliance records.

**Detekcija:** spojiti UserOperation, EntryPoint, paymaster, bundler/RPC i application logs; identical sponsorship policy cluster-ovati oprezno. **Captured wallet:** session keys i pending approvals mogu biti upotrebljeni i bez gas-a; usko ih ograničiti i revoke kroz account recovery policy.

## Threshold ili multisignature payment authorization

**Mehanika:** trošenje zahteva threshold nezavisnih signers. Ne skriva transakciju, ali omogućava da payment authority bude odvojena od zaplenjenog laptopa, field node-a ili jednog operatora.

**Prednosti:** snažna zaštita od compromise-a i insider-a; odgovorno odobravanje; nijedan field device nema potpunu signing authority; podržava recovery.

**Nedostaci:** coordination i availability; signer/device/account metadata mogu povezati učesnike; loš backup design uzrokuje gubitak; javni multisig patterns mogu biti prepoznatljivi.

**Procedura:** (1) definisati signers, threshold, limits i recovery pre funding-a; (2) inicijalizovati na odvojenom podržanom hardware-u/accounts; (3) nezavisno proveriti addresses i backups; (4) field workloads dati samo unsigned requisition capability; (5) zahtevati out-of-band review recipient-a, amount-a i purpose-a; (6) testirati recovery i gubitak jednog signer-a sa malom vrednošću; (7) rotirati signer nakon compromise-a.

**Detekcija:** approval system, signer device i public script/contract pružaju evidence; defenders alertuju na policy ili signer-set changes. **Captured node:** treba da izloži najviše jednu low-authority session key ili unsigned request; nikada ne keširati quorum material zajedno.

## Closed-loop community ili event currency

**Mehanika:** cooperative, conference ili private test environment izdaje credits redeemable samo među enrolled participants. Internal transfer može manje izlagati globalnim payment networks, dok operator kontroliše issuance i redemption.

**Prednosti:** ograničen ekonomski domen; može testirati offline ili privacy-preserving payment UX; ograničava external card exposure; jasne experimental controls.

**Nedostaci:** mali anonymity set; operator i merchants vide aktivnosti; ograničeno prihvatanje/redemption; licensing, consumer-protection i tax pravila mogu važiti i za lokalnu vrednost.

**Procedura:** (1) dobiti legal/compliance review i objaviti issuer terms; (2) uključiti consenting test participants; (3) ograničiti issuance i zabraniti cash-like misuse; (4) koristiti fresh payment requests i svesti public participant identifiers na minimum; (5) beležiti aggregate reserves i privatne individual receipts; (6) testirati loss/refund/redemption; (7) zatvoriti ledger i vratiti residual value kako je obećano.

**Detekcija:** issuer ledger, enrollment, merchant i redemption records rekonstruišu flows; unusual circular transfers ili rapid cash-out zahtevaju review. **Captured wallet:** local balance i counterparties mogu biti otkriveni; ograničiti vrednost, enkriptovati state i podržati issuer-side freeze/reissue sa auditabilnim zapisom.

## Bitcoin reusable payment codes i private payment instructions

**Mehanika:** BIP 47 payment codes koriste reusable public identifier i ECDH-derived one-time deposit addresses; BIP 351 definiše noviji private-payment instruction design. Smanjuju public address reuse dok omogućavaju primaocu da objavi stabilne payment instructions. Notification, wallet support, funding i kasniji coin selection i dalje utiču na privatnost.<sup>[[20]](#references)</sup>

**Prednosti:** jedna javna instruction može proizvesti različite addresses; recipient ne mora objaviti svaku invoice address; kompatibilni wallets mogu pratiti derived payments; korisno za ponovljene zakonite donors/customers.

**Nedostaci:** wallet interoperability varira; notification transactions ili objavljeni payment code povezuju relationship context; sender, recipient i javni graph i dalje vide transakcije; nemarna consolidation ili change handling poništava korist.

**Procedura:** (1) potvrditi da oba održavana wallet-a podržavaju potpuno istu specification/version; (2) backup i test recovery na low-value wallet-u; (3) out-of-band autentifikovati recipient payment code; (4) poslati mali zakonit test; (5) proveriti korišćenje fresh derived address; (6) lokalno označiti relationship i primeniti coin control; (7) testirati recovery i refund behavior pre oslanjanja na sistem.

**Detekcija:** analysts ispituju notification patterns, funding/change, later consolidation i service boundaries; public-code publication identifikuje recipient context čak i kada su deposit addresses različite. **Capture-resilient OPSEC:** spend keys držati van field devices i izložiti najviše watch-only relationship view. **Monitoring:** alert na neočekivane notification transactions, reused derived addresses, wallet gap-limit/recovery greške i neplaniranu consolidation.

## EVM stealth addresses (ERC-5564)

**Mehanika:** sender izvodi one-time stealth account iz recipient stealth meta-address i objavljuje announcement sa ephemeral public key i view tag. Recipient skenira announcements viewing key-em i izvodi odgovarajući spend key. Recipient linkage je bolji, ali sender, amount/token, gas, announcement i kasnije spending ostaju vidljivi.<sup>[[21]](#references)</sup>

**Prednosti:** non-interactive fresh receiver address; reusable meta-address; odvojene viewing i spending roles; radi preko podržanih EVM assets/applications.

**Nedostaci:** announcement scanning i spam; funding gas-a za novu address može ponovo povezati; sender zna recipient-a; public token/amount i eventualna consolidation ostaju; implementation i wallet support variraju.

**Procedura:** (1) koristiti audited maintained implementation najpre na test network-u; (2) generisati i backup-ovati odvojene viewing/spending material; (3) autentifikovati meta-address; (4) poslati low-value test i announcement; (5) skenirati i izvesti stealth account; (6) testirati podržani gas sponsorship bez ličnog funding edge-a; (7) zabeležiti public fields i sačuvati zakonito računovodstvo.

**Detekcija:** pratiti announcement caller, token/amount, timing, gas sponsor, spending i consolidation; view key može dokazati receipt bez davanja spend-a. **Capture-resilient OPSEC:** networked scanner treba da ima samo viewing role gde je podržano; spend i recovery keys držati drugde. **Monitoring:** alert na malformed/spam announcements, view-key access, unexpected spend derivation i stealth outputs moved without approval.

## Liquid Confidential Transactions

**Mehanika:** Liquid podrazumevano blinds output amounts i asset types koristeći commitments i proofs, dok transaction graph, input/output count, fee i block time ostaju vidljivi. Peg-in/peg-out i service boundaries ostaju linkable, a users mogu selektivno otkriti blinding data.<sup>[[22]](#references)</sup>

**Prednosti:** confidential amount i asset type po defaultu; brzo sidechain settlement; selective audit putem blinding keys/descriptors; skriva komercijalno osetljive vrednosti od javnih posmatrača.

**Nedostaci:** graph structure i timing ostaju; federation/bridge i exchange trust; peg boundaries i unconfidential outputs; wallet/node/network records; receiver i sender znaju svoju transakciju.

**Procedura:** (1) izabrati održavani Liquid wallet i proveriti backup model; (2) koristiti testnet ili mali zakoniti iznos; (3) primiti na confidential address i proveriti da wallet označava output kao blinded; (4) poslati test confidential transaction; (5) pregledati koja explorer fields ostaju javna; (6) izvesti samo scoped blinding proof potreban za audit; (7) dokumentovati peg/exchange boundaries i uskladiti funds.

**Detekcija:** analizirati visible graph/fee/time, peg i exchange records, network metadata i kasnije unblinding evidence; ne zaključivati skriveni amount ili asset. **Capture-resilient OPSEC:** odvojiti spend seed, blinding/view data i watch-only operations. **Monitoring:** alert na accidental unconfidential addresses, unknown peg requests, descriptor changes i unapproved unblinding-key export.

## General payment ili state channel

**Mehanika:** participants zaključavaju funds, razmenjuju signed off-chain state updates i on-chain objavljuju samo opening, closing ili disputed state. Intermediate payments nisu globalno broadcast, ali peers i routing/intermediary services vide svoj deo, a endpoints moraju čuvati latest enforceable state.<sup>[[23]](#references)</sup>

**Prednosti:** mnogo brzih low-fee interakcija privatnih prema javnom ledger-u; manje globalnih transaction detalja; bounded channel balance; korisno za metered services i ponovljene counterparties.

**Nedostaci:** channel peers znaju jedni druge i mogu čuvati updates; opening/closing/value/timing korelišu; online monitoring može biti potreban tokom challenge windows; implementation i liquidity risk; samo po sebi nije veliki anonymity set.

**Procedura:** (1) izabrati održavanu audited implementation i razumeti dispute window; (2) otvoriti low-value test channel između owned parties; (3) razmeniti signed state updates sa unique nonces; (4) backup latest enforceable state; (5) cooperatively close; (6) vežbati stale-state rejection na testnet-u; (7) čuvati accounting i channel-peer records.

**Detekcija:** public chain otkriva lifecycle/disputes; peers, watch services i application transport otkrivaju off-chain timing i parties. **Capture-resilient OPSEC:** ograničiti hot balance i latest signed state čuvati u encrypted recoverable store-u odvojenom od field nodes. **Monitoring:** stalno pratiti stale-state publication, missed backup, peer-key change i približavanje challenge deadline-a.

## Mobile carrier billing

**Mehanika:** online service naplaćuje kupovinu na mobile subscription ili prepaid balance kroz carrier billing system. Merchant može dobiti carrier authorization umesto card/bank podataka, dok carrier zna subscriber/line, device/network context, merchant, amount i time.<sup>[[24]](#references)</sup>

**Prednosti:** nema card number-a kod merchant-a; široka dostupnost telefona; korisno za digital goods male vrednosti; carrier može ograničiti i reverse charges.

**Nedostaci:** snažno identifikovano SIM/account i često device-om; mali limiti i visoke fees; merchant category restrictions; account takeover/SIM-swap risk; carrier i aggregator stvaraju kompletan transaction trail.

**Procedura:** (1) potvrditi availability, limit, fee i refund terms sa organization carrier account-om; (2) uključiti samo na dedicated organization line ako je opravdano; (3) postaviti najniži koristan spend cap; (4) kupiti benign test item; (5) proveriti merchant i carrier receipts; (6) isključiti recurring authorization; (7) uskladiti i isključiti funkciju posle assessment-a.

**Detekcija:** carrier, aggregator i merchant records povezuju line, subscriber, IP/device i charge; enterprise telecom invoices to otkrivaju. **Capture-resilient OPSEC:** ne koristiti lični broj i zahtevati carrier-account MFA van field device-a. **Monitoring:** uključiti instant charge/SIM-change alerts i zaustaviti na unexpected premium-service enrollment, forwarding ili account recovery.

## Open-banking payment initiation

**Mehanika:** uz izričitu saglasnost korisnika, regulisani payment-initiation service provider (PISP) traži od account-servicing bank da pokrene transfer. Merchant možda ne dobija card credentials, ali PISP i banks čuvaju regulisane payer, payee, consent, device i transaction records.<sup>[[25]](#references)</sup>

**Prednosti:** nema reusable card number-a na checkout-u; snažna bank authentication; tačno account-to-account settlement; consent i status APIs; jasno reconciliation.

**Nedostaci:** nije anonimno bankama/PISP-u; payee često vidi legal account details ili reference; phishing/redirect risk; jurisdiction i refund protections variraju; consent metadata dodaje posmatrača.

**Procedura:** (1) proveriti da je PISP trenutno regulisan i da je merchant callback domain autentičan; (2) početi iz merchant request-a; (3) kod banke pregledati payee, amount, reference i requested consent; (4) autorizovati samo single payment; (5) nezavisno proveriti final status; (6) revoke residual consent ako postoji; (7) sačuvati receipt i uskladiti.

**Detekcija:** bank/PISP/merchant logs i transfer references daju snažnu atribuciju. **Capture-resilient OPSEC:** banking authentication i recovery držati van operational/field devices; device treba da sadrži samo paid-service entitlement. **Monitoring:** koristiti bank transaction/consent alerts i istražiti nove PISP grants, promenjenog payee-ja ili status callbacks van očekivane sesije.

## Platform wallet, app-store balance ili in-app credit

**Mehanika:** platforma naplaćuje korisnika ili redeem-uje account credit, a zatim aplikaciji izdaje signed receipt ili entitlement. App developer možda ne dobija originalni funding instrument, dok platforma povezuje account, device, funding, product i redemption.<sup>[[26]](#references)</sup>

**Prednosti:** merchant/developer ne dobija primary PAN; fraud/refund i family/business controls; mali prepaid balance može ograničiti exposure; signed receipts olakšavaju entitlement verification.

**Nedostaci:** platform account je snažan identity i behavior hub; device i storefront geography; gift-balance purchase/redemption trail; ograničen cash-out; fraud controls mogu freeze-ovati funds; nije cross-platform money.

**Procedura:** (1) koristiti organization-managed platform account gde policy dozvoljava; (2) pregledati funding, region, refund i transferable-value rules; (3) dodati samo odobreni budget; (4) kupiti benign product kroz official store; (5) proveriti da application dobija samo očekivana receipt fields; (6) isključiti recurring purchase; (7) uskladiti i ukloniti account sa operational hardware-a.

**Detekcija:** platform receipts/server notifications, account/device login i funding records rekonstruišu purchase. **Capture-resilient OPSEC:** nikada ne prijavljivati field node u personal store account; gde je moguće proslediti samo scoped app entitlement. **Monitoring:** uključiti new-device/purchase alerts i istražiti receipt replay, family/account changes ili unexpected restore events.

## Mutual credit, clearing ili periodic net settlement

**Mehanika:** participants beleže obligations u privatnom ledger-u i periodično poravnavaju samo net position. Pojedinačni service events ne moraju stvarati zasebna javna plaćanja, ali ledger operator i counterparties zadržavaju detaljnu atribuciju.

**Prednosti:** manje external transactions i fees; javni posmatrači vide samo net settlement; radi za repeated organizations; explicit credit limits ograničavaju exposure.

**Nedostaci:** centralizovani ledger je potpuni dokaz i target za prevaru; counterparty/default risk; legal/accounting/tax duties; mali membership set; neuobičajeni net transfers i dalje mogu otkriti odnose.

**Procedura:** (1) koristiti samo identifikovane consenting organizations uz legal/accounting approval; (2) definisati unit, credit limit, settlement interval i dispute rules; (3) zabeležiti svaku obligation sa immutable approval; (4) odvojene finance roles računaju i odobravaju net positions; (5) settle kroz običan zakonit rail; (6) uskladiti individual lines sa settlement-om; (7) zatvoriti access i zadržati records prema policy-ju.

**Detekcija:** ledger, invoices, approvals i final bank/chain settlement daju ground truth; analysts ne treba da zaključuju missing gross activity samo iz net transfer-a. **Capture-resilient OPSEC:** operational devices mogu slati bounded requisitions, ali ne mogu menjati balances ili autorizovati settlement. **Monitoring:** alert na credit-limit breach, backdated entries, administrator changes, reconciliation mismatch i settlement ka novom beneficiary-ju.

## Capture/compromise exposure matrix

Ovo primenjuje seizure/loss test na svaku familiju. Cilj je ograničiti spend authority i disclosure nepovezanog identiteta uz očuvanje zakonitog računovodstva, a ne brisanje transakcija ili ometanje istrage.

| Familija tehnike | Captured wallet/device/account može otkriti | Minimalna ovlašćena kontrola |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, preostalu bearer vrednost i fizičke kontakte | nositi samo odobreni iznos; odvojeno privatno računovodstvo; odmah prijaviti gubitak; bez lažnih zapisa |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption i account/session tokens | mali saldo; jedna svrha; istinita registracija; issuer freeze/revocation gde postoji |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery i merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; bez deljenog recovery account-a |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices i project | role separation; least-privilege subaccount; finance credentials nikad na operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator ili dispute trail | single-use request; separate approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph i network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP i payment database | minimal hot balance; encrypted backup; separate node identity; close/recover po dokumentovanom planu |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC i boundary transactions | separate spend/view roles; hardware support gde postoji; bez exchange session-a na field node-u |
| Stablecoins, swaps, bridges i DEX | transparent graph, approvals, RPC/front-end state i destination assets | revoke allowances; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | mali balance; encrypted backup prema protokolu; redeem/reissue; nikad ne colocate funding credential |
| Paymaster, multisig/threshold | session key, one signer, pending operations i sponsor policy | narrow session key; independent quorum; signer rotation; field device ne sme dohvatiti threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph i participant records | bez operational use; samo synthetic/testnet emulation |
| Community/event currency | enrollment, local balance, counterparties i redemption | capped value; issuer freeze/reissue; consent i private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements i derived outputs | watch/view-only network role; offline/hardware spend role; bez personal funding session-a |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries i disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device i funding source | organization account; external MFA; low limit; bez personal account-a na field hardware-u |
| Mutual-credit clearing | members, obligations, limits, approvals i settlement ledger | samo operational requisition; separate immutable ledger i dual finance approval |

## Monitoring possible discovery ili payment compromise

Payment denial, compliance review ili wallet koji odlazi offline ne dokazuju da istraga postoji. Nadzirati samo accounts, ledgers i infrastructure koje organization ima pravo da posmatra; nikada ne sondirati providers ili counterparties radi provere da li sarađuju sa investigators.

| Obuhvaćene tehnike | Bezbedni monitoring signali | Uslov za freeze/stop |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund ili loss report | missing instrument, redemption van approved order-a, altered receipt ili custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap ili recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice i consumption | cross-project token, unknown admin, limit breach, invoice mismatch ili unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation i beneficiary change | altered amount/payee, backdated ledger, unilateral release ili unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels i consolidation | unknown spend, reused recipient output, wallet gap/recovery failure ili unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure ili coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP i chain dispute | unknown invoice payment, peer-key change, stale close ili approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor i boundary transaction | spend without approval, transparent/unconfidential downgrade, key export ili unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key i issuer action | wrong contract/public field, unknown approval/spend, paymaster change ili issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway i bearer balance | unknown redemption, mint key/terms change, restore failure ili balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate i destination | contract/route mismatch, unlimited approval, missing destination ili bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum i recovery audit | unknown proposal/signer, threshold reduction, recovery activation ili policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | samo synthetic lab ground truth i detection output | bilo koji real account, person ili value u emulation: odmah stop |

## Selection i verification workflow

1. Navesti koja strana ne sme saznati koje polje.
2. Identifikovati issuer/mint/custodian, public ledger, network/RPC, merchant i physical observers.
3. Proveriti aktuelnu podršku, zakonitost, limite, custody, recovery i refund ponašanje.
4. Koristiti mali zakonit end-to-end test.
5. Pregledati merchant receipt, provider statement, public chain i wallet/node logs.
6. Testirati backup/recovery i namerno audit disclosure.
7. Obavezne source, ownership, tax, sanctions i engagement records voditi tačno, uz kontrolisan pristup.

## References

- [1] [EMVCo — Tokenizacija plaćanja](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Zapažanja o prikupljanju podataka velikih payment platformi](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Zaštitite svoju privatnost](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Jednostavan Payjoin predlog](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Tehničke specifikacije i mrežna privatnost](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Building privacy applications with zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol i ograničenja privatnosti](https://docs.cashu.space/faq)
- [13] [Fedimint — Kako funkcioniše](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Indikatori crvenih zastavica za virtuelnu imovinu](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administratori, exchange-i i korisnici virtuelne valute](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — informacije o transferu i crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Arhitektura Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State i payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
