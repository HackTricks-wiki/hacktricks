# Katalog tehnika anonimnog plaćanja

Ovaj katalog obuhvata **familije** plaćanja, od običnog gotovog novca do e-novca sa slepim potpisom i obfuscacije javnih lanaca. „Anonimno“ uvek znači anonimno u odnosu na imenovanog posmatrača. Trgovac, izdavalac, mint, menjačnica, blockchain analitičar, mrežni provajder, poslodavac i fizički posmatrač vide različite činjenice.

Procedure u nastavku namenjene su zakonitim sredstvima, istinitim nalozima i ovlašćenoj nabavci. Tehnike čija je svrha u navedenim slučajevima bila pranje novca, izbegavanje sankcija ili krađa identiteta objašnjene su i detektuju se, ali je njihova procedura sintetička forenzička vežba, a ne uputstvo za izvršenje krivičnog dela.

## Matrica obuhvata

| Familija | Glavno svojstvo privatnosti | Glavni posmatrač/poverenje | Tretman |
|---|---|---|---|
| Gotovina i gotovinski ekvivalenti | nema udaljenog zapisa na platnoj mreži | primalac i fizičko okruženje | zakonit tok rada |
| Prepaid/gift/voucher vrednost | odvaja iskorišćavanje od primarne kartice | prodavac, izdavalac i servis za iskorišćavanje | zakonit tok rada, zavisi od jurisdikcije |
| Virtuelna/tokenizovana kartica | skriva ponovo upotrebljivi PAN ili odvaja trgovce | izdavalac/mreža/wallet i dalje identifikuju platioca | zakonit tok rada |
| Payment app/posrednik | trgovac može videti alias/posrednika | app prikuplja identitet/uređaj/transakciju | osnov za poređenje |
| Bitcoin higijena/Silent Payments | pseudonimi i nepovezivost primaoca | javni graf i granica walleta/mreže | primenljivo |
| PayJoin/CoinJoin | slabi heuristike zajedničkog vlasništva/povezivanja | učesnici/koordinator/mreža/javni graf | primenljivo gde je podržano; pravna provera |
| Lightning/BOLT 12 | off-chain rutiranje i smanjenje putanje do primaoca | krajnje tačke, hopovi, servisi i graf kanala | primenljivo gde je podržano |
| Monero/Zcash/MWEB | poverljivost na nivou protokola | akvizicija, krajnja tačka, mreža i granice i dalje postoje | primenljivo gde je zakonito/podržano |
| Ethereum ZK aplikacija | skriva određenu vezu između tvrdnje/radnje | javni ulazi, RPC, relayer i app | specifično za aplikaciju |
| Cashu/Fedimint/Taler | privatnost platioca putem slepog potpisa | mint/federacija/menjačnica i granice kastodije | u razvoju/specifično za implementaciju |
| Stablecoins | praktično digitalno poravnanje | transparentni chain i kontrola zamrzavanja izdavaoca | nije osnov za anonimnost |
| Swaps/bridges/DEX | premešta vrednost između asseta/chaina | oba grafa, contracts i provajderi | forenzička mehanika; samo zakoniti swapovi |
| Mixers/peel/structuring | povećava dvosmislenost/obim grafa | ulazni/izlazni graf i zapisi servisa | samo sintetička vežba detekcije |
| Nominees/mules/OTC/fronts | ubacuje ljudske/poslovne posrednike | pomagači, banke, komunikacije | samo analiza kriminalne zloupotrebe |
| Ponovo upotrebljive/stealth payment adrese | nova adresa primaoca za svako plaćanje | javna objava/notifikacija i granice walleta | primenljivo gde je podržano |
| Confidential sidechain/state channel | skriva iznos/asset ili međustanja | peerovi, bridge/federacija i poravnanje životnog ciklusa | specifično za protokol |
| Carrier/open-banking/platform billing | skriva primarnu karticu od trgovca | carrier, banka/PISP ili platforma identifikuje korisnika | obično identifikovano plaćanje |
| Mutual credit/net settlement | manje eksternih zapisa poravnanja | privatni operator ledger-a ima potpuno mapiranje | samo identifikovani učesnici |

## Gotovina

**Mehanika:** fizička bearer vrednost menja vlasnika bez online autorizacije izdavaoca ili javnog ledger-a.

**Prednosti:** trgovac ne mora saznati identitet banke/kartice; nema udaljenog grafa transakcija; široko razumljivo i konačno.

**Nedostaci:** samo licem u lice; krađa/gubitak; kontrola kusura/priznanica/serijskih brojeva ili prijavljivanja; podizanje, kamere, svedoci i lokacija i dalje mogu povezati platioca.

**Procedura:** (1) potvrditi da je gotovina zakonita/prihvaćena i proveriti pravilo o iznosu/prijavljivanju; (2) zakonito je podići ili primiti i voditi privatne računovodstvene zapise; (3) platiti običnom trgovcu bez nepotrebnih loyalty/account identifikatora; (4) zatražiti samo obaveznu priznanicu; (5) izbeći podatke za dostavu/nalog ako nisu potrebni; (6) interno zabeležiti legitimnu poslovnu svrhu.

**Detekcija:** uskladiti kasu/priznanice/zalihe, kamere i access logove prema primenljivoj politici; istražiti neuobičajene povraćaje gotovine ili ponovljene iznose neposredno ispod kontrolnog praga, bez automatskog smatranja uobičajene upotrebe gotovine sumnjivom.

## Money order, postal order, cashier instrument i cash on delivery

**Mehanika:** regulisani izdavalac pretvara gotovinu/sredstva sa naloga u numerisani instrument plativ imenovanom primaocu; COD odlaže naplatu do dostave.

**Prednosti:** primalac možda neće dobiti primarni broj banke/kartice platioca; upotrebljivo tamo gde gotovina ne može biti udaljeno preneta; jasna priznanica.

**Nedostaci:** izdavalac/prodavac zadržava podatke o kupovini/identitetu kada je to propisano; praćenje serijskog broja; adresa primaoca/dostave; gubitak/prevara i regionalna ograničenja; uglavnom nije anonimno.

**Procedura:** (1) proveriti pravila, limite, identifikaciju i prihvatanje primaoca; (2) kupiti istinitim podacima i zakonitim sredstvima; (3) odmah popuniti primaoca/iznos; (4) sačuvati serijski broj/priznanicu; (5) koristiti praćenu dostavu primerenu vrednosti; (6) uskladiti iskorišćavanje/povraćaj.

**Detekcija:** zapis kupovine/iskorišćavanja izdavaoca, serijski broj instrumenta, prodavac/kamera, slanje i nalog primaoca; označiti izmene, duple serijske brojeve i brzo iskorišćavanje koje je geografski nedosledno.

## Open-loop prepaid card

**Mehanika:** stored-value credential sa oznakom mreže autorizuje se prema prepaid saldu umesto prema primarnom kreditnom nalogu.

**Prednosti:** ograničava izloženost trgovca i gubitak; odvaja trgovca od glavnog PAN-a; upotrebljivo online gde je prihvaćeno.

**Nedostaci:** zapisi o kupovini/aktivaciji/reload-u/registraciji i uređaju; KYC i limiti variraju; problemi sa billing adresom; ograničenja cash-out/refund; „bez imena“ ne znači da nema zapisa izdavaoca.

**Procedura:** (1) proveriti trenutni identitet izdavaoca, naknade, KYC, geografiju i podršku za online/recurring plaćanja; (2) nabaviti preko ovlašćenog prodavca zakonitim sredstvima; (3) registrovati istinite zahtevane podatke; (4) koristiti za jednu izdvojenu svrhu; (5) ne strukturisati load-ove niti izmišljati prebivalište; (6) sačuvati dokaze o kupovini/trošku i zatvoriti/odložiti karticu prema uslovima izdavaoca.

**Detekcija:** povezati prodavca/aktivaciju, finansiranje, device/IP, autorizaciju trgovca, provere salda i redemption/refund. Obrasci su važniji od prepaid oznake.

## Closed-loop gift card, voucher i transferable service credit

**Mehanika:** numerisana vrednost može se iskoristiti samo kod jednog trgovca/servisa ili u jednom ekosistemu. Airtime/game/store credits su varijante.

**Prednosti:** trgovac primalac može videti samo kod/saldo; ograničen blast radius; lako poklanjanje i odvajanje budžeta.

**Nedostaci:** prodavac i servis beleže kupovinu/aktivaciju/iskorišćavanje; nalog/uređaj/dostava i dalje povezuju korisnika; prevare, popusti pri preprodaji i rokovi/regioni; slaba prava na refund.

**Procedura:** (1) kupovati samo preko ovlašćenih kanala; (2) zapisati vrednost koda bez otkrivanja tajne; (3) ne povezivati nepotreban loyalty nalog; (4) iskoristiti kroz odvojen legitimni merchant account/context; (5) sačuvati račun do prihvatanja; (6) nikada ne kupovati kodove za neželjeni zahtev za „porez/podršku/otkup“.

**Detekcija:** vreme izdavanja/iskorišćavanja koda, spajanje uređaja/naloga, kupovina u velikom obimu ili po pragovima, jedan uređaj koji proverava mnogo salda i brzo udaljeno iskorišćavanje.

## Cryptocurrency-funded card ili gift-code broker

**Mehanika:** posrednik prihvata cryptocurrency i izdaje karticu, voucher ili merchant code. To je konverzija između rail-ova: trgovac vidi običnu kartičnu/gift vrednost, dok broker povezuje on-chain deposit sa izdavanjem i dostavom.

**Prednosti:** trgovac ne dobija funding wallet; korisno za legitimne trgovce koji ne prihvataju crypto; ograničena stored value.

**Nedostaci:** nije anonimno prema brokeru/izdavaocu; KYC, sankcije, exchange i pravila card-programa; javni deposit graf; account/device/email i iskorišćavanje koda ponovo povezuju obe strane; rizik prevare/insolventnosti.

**Procedura:** (1) proveriti pravno lice, izdavaoca kartice, podržanu jurisdikciju, KYC, naknade i refund politiku; (2) koristiti samo zakonita dokumentovana sredstva; (3) testirati najmanju denominaciju; (4) proveriti ograničenja mreže/trgovca pre kupovine; (5) sačuvati blockchain transakciju i broker priznanicu radi računovodstva; (6) nikada ne koristiti brokera koji obećava krađu identiteta, zaobilaženje sankcija ili „nepratljiv“ cash-out.

**Detekcija:** povezati broker deposit adrese, jedinstveni iznos/vreme, nalog/uređaj i autorizaciju izdate kartice ili iskorišćavanje gift koda; zapisi izdavaoca i brokera spajaju javni chain sa trgovcem.

## Virtual ili merchant-locked card

**Mehanika:** izdavalac mapira generisani PAN/token na stvarni nalog, često ograničavajući trgovca, iznos ili rok važenja.

**Prednosti:** sprečava otkrivanje ponovo upotrebljivog PAN-a; compartmentation trgovaca; limiti potrošnje i laka opozivost; zrela kontrola prevara.

**Nedostaci:** izdavalac i dalje zna platioca, finansiranje, trgovca, uređaj/IP i vreme; trgovac vidi nalog/dostavu; neki refund/recurring charge-ovi ne uspevaju; nije anonimno.

**Procedura:** (1) koristiti zvaničnu funkciju regulisanog izdavaoca; (2) napraviti karticu za jednog trgovca/engagement; (3) postaviti najmanji koristan limit i rok; (4) koristiti tačan billing gde je potreban; (5) proveriti statement descriptor/refund ponašanje; (6) zamrznuti/obrisati nakon konačnog poravnanja uz čuvanje audit dokaza.

**Detekcija:** issuer token-to-account mapping, autorizacija trgovca, uređaj i dostava. Defenders koriste merchant-specific reuse, velocity i account-takeover signale.

## Mobile-wallet network token

**Mehanika:** EMV payment tokenization zamenjuje PAN ograničenim credential-om, često vezanim za uređaj, trgovca ili scenario plaćanja.<sup>[[1]](#references)</sup>

**Prednosti:** trgovac ne dobija ponovo upotrebljivi PAN; device cryptography/dynamic data smanjuju kloniranje; opoziv bez zamene kartice.

**Nedostaci:** izdavalac, token service, wallet platforma i mreža zadržavaju mapiranja/transakcije; device/platform account i lokacija mogu identifikovati platioca.

**Procedura:** (1) registrovati legitimnu karticu u zvaničnom walletu; (2) zaštititi platform account/device jakom autentikacijom; (3) proveriti device token/poslednje cifre pri kupovini; (4) isključiti nepotrebnu lokaciju/analitiku gde je podržano; (5) odmah ukloniti token sa izgubljenih uređaja; (6) pregledati zapise izdavaoca i walleta.

**Detekcija:** token requestor/device cryptogram i mapiranje izdavaoca, wallet/account telemetry, merchant terminal i fizički dokazi.

## Payment app, marketplace wallet i centralizovani posrednik

**Mehanika:** servis održava naloge i prenosi vrednost interno ili kroz bank/card rail-ove; trgovac može videti alias, dok servis vidi obe strane.

**Prednosti:** praktičnost, dispute/refund mehanizmi, primalac ne mora nužno videti bankarske/kartične podatke.

**Nedostaci:** centralizovani identity/social/transaction/device graf; zamrzavanja i pravni postupci; counterparties mogu otkriti profil; upotreba podataka može prevazići potrebu za plaćanjem.<sup>[[2]](#references)</sup>

**Procedura:** (1) pročitati uslove identiteta, privatnosti, čuvanja podataka i zaštite kupca; (2) smanjiti opcionu sinhronizaciju profila/kontakata; (3) koristiti poseban istinit nalog samo kada uslovi to dopuštaju; (4) uključiti MFA/alerts; (5) proveriti primaoca i privatnost memo/profila; (6) izvesti zapise i zatvoriti neiskorišćene veze.

**Detekcija:** account, device/IP, contact graph, funding/withdrawal, memo i merchant zapisi provajdera. Alias je pseudonimnost prema drugoj ugovornoj strani, a ne anonimnost prema platformi.

## Bank transfer, ACH, wire i instant-account payment

**Mehanika:** regulisane institucije prenose vrednost između identifikovanih naloga i razmenjuju zahtevane podatke o plaćanju.

**Prednosti:** brzo, odgovorno, ograničeno opozivo i sa snažnim zapisima; virtuelni account brojevi mogu smanjiti otkrivanje podataka trgovcu.

**Nedostaci:** banke/procesori znaju obe strane; izvodi i reference; nije anonimno; prekogranični i Travel Rule/AML podaci.

**Procedura:** koristiti samo kada je odgovornost prihvatljiva: nezavisno proveriti korisnika, smanjiti nepotrebne memo podatke, koristiti bankarski virtual account/reference gde je dostupno, uključiti alerts, sačuvati invoice i izvršiti reconciliation.

**Detekcija:** deterministički bankarski/payment zapisi, vlasništvo korisnika/naloga, device/session i fraud controls. Ovo je osnovna tačka, a ne tehnika anonimnosti.

## Account i merchant compartmentation

**Mehanika:** odvojeni zakoniti identiteti/nalozi, email aliasi, kartice i konteksti dostave sprečavaju da nepovezani trgovci trivijalno objedine aktivnost, dok izdavalac/controller zadržava mapiranje.

**Prednosti:** smanjuje breach i cross-merchant povezivanje; lako za audit; kompatibilno sa regulisanim plaćanjima.

**Nedostaci:** provajder i dalje mapira compartments; recovery telefon/uređaj/IP i shipping mogu ponovo uspostaviti vezu; politika može zabranjivati više naloga.

**Procedura:** (1) definisati jednu svrhu; (2) napraviti samo alias/subaccount-e usklađene sa uslovima; (3) koristiti merchant-specific token/card; (4) isključiti cross-account contact/ad personalizaciju; (5) voditi šifrovani controller ledger; (6) povući identifikatore nakon završetka refund/retention potreba.

**Detekcija:** provajderi povezuju recovery, device, funding i IP; trgovci povezuju dostavu, browser i ponašanje naloga. Defenders treba da razlikuju legitimnu compartmentation od synthetic identity fraud.

## Controlled red-team procurement

**Mehanika:** SOC nema uvid u kupovinu, dok exercise controller zadržava mapiranje pravnog lica, operatora i infrastrukture.

**Prednosti:** realistična vežba detekcije; nema izlaganja ličnih podataka; neposredna dekonflikcija i audit.

**Nedostaci:** nije anonimno prema organizaciji/provajderu; upravljački trošak; leak ako se controller ledgerom loše rukuje.

**Procedura:** (1) dodeliti engagement-specific organization card/wallet/budget; (2) odvojiti uloge purchaser/operator; (3) zabeležiti asset, iznos, servis, svrhu i kill date; (4) čuvati attribution mapping uz ograničen pristup controlleru; (5) nikada ne koristiti lažni identitet/mule/ukradena sredstva; (6) otkriti/usklađivati indikatore i refund-ove pri završetku.

**Detekcija:** controller povezuje provider invoice i asset; SOC testira nezavisno otkrivanje kroz domen, sertifikat, hosting i saobraćaj, a ne kroz podatke o vlasniku kartice.

## Bitcoin address hygiene i coin control

**Mehanika:** sveže receive adrese, lokalno označavanje i selektivno trošenje UTXO-a smanjuju ponovnu upotrebu adresa i slučajno spajanje compartment-a na javnom ledgeru.

**Prednosti:** široka podrška; self-custodial; izbegava najjednostavnije javno povezivanje.

**Nedostaci:** sve transakcije/iznosi ostaju javni; common-input/change/timing i kasnija konsolidacija povezuju aktivnost; zapisi akvizicije/RPC/mreže ostaju.

**Procedura:** (1) instalirati/proveriti održavan wallet; (2) napraviti backup i testirati seed recovery; (3) koristiti novu adresu po invoice-u; (4) lokalno označiti izvor/svrhu; (5) koristiti coin control za izbegavanje spajanja konteksta; (6) preferirati lokalni node ili privacy-aware konekciju; (7) pregledati change/fees i sačuvati zakonito računovodstvo.<sup>[[3]](#references)</sup>

**Detekcija:** address graph, common-input/change heuristike uz neizvesnost, tačan iznos/vreme, konsolidacija, service deposits, node/RPC broadcast timing i off-chain zapisi.

## Bitcoin Silent Payments

**Mehanika:** BIP 352 omogućava primaocu da objavi statički kod, dok pošiljaoci putem ECDH izvode jedinstvene Taproot outpute; spoljašnji posmatrači ne mogu direktno povezati outpute sa kodom.<sup>[[4]](#references)</sup>

**Prednosti:** ponovo upotrebljiv javni identifikator bez ponovne upotrebe adrese; nema interaktivnog zahteva za adresu ili notification outputa; uklapa se u Taproot outpute.

**Nedostaci:** trošak skeniranja primaoca; podrška walleta varira; graf iznosa/pošiljaoca i trošenje ostaju javni; index server može videti skeniranja.

**Procedura:** (1) izabrati aktuelni BIP 352 wallet; (2) napraviti/testirati descriptor i oporavak skeniranja; (3) generisati označeni kod gde je podržano; (4) autentifikovati objavljeni kod; (5) pošiljalac pregledava inpute i šalje mali test; (6) primalac skenira po mogućnosti kroz sopstveni node; (7) držati primljene UTXO-e odvojene.

**Detekcija:** po dizajnu se ne može pouzdano identifikovati samo iz outputa; analitičari koriste inpute pošiljaoca, iznos/vreme, kasnije trošenje, wallet/network/index i zapise counterparties.

## PayJoin

**Mehanika:** platioc i primalac doprinose inputima jednoj payment transakciji, čime se ruši pretpostavka da svi inputi pripadaju istom vlasniku.<sup>[[5]](#references)</sup>

**Prednosti:** obično plaćanje sa boljom privatnošću; koristi širem grafu slabljenjem uobičajene heuristike; nije potrebna grupa jednakih outputa.

**Nedostaci:** potreban interaktivni proces/podrška; dostupnost endpointa primaoca; iznos i konačna transakcija su javni; implementacioni i fallback metadata.

**Procedura:** (1) potvrditi da oba održavana walleta podržavaju istu PayJoin verziju; (2) autentifikovati invoice/endpoint; (3) započeti iz wallet PayJoin-enabled payment URI-ja; (4) pregledati konačan iznos/fee i potpisati samo očekivane inpute; (5) izbegavati ručnu obradu transakcije; (6) proveriti broadcast i prijem; (7) zabeležiti fallback ako pregovori ne uspeju.

**Detekcija:** blockchain analitičari ne smeju prisilno primenjivati common-input clustering; endpoint/provajder može logovati pregovore; koristiti wallet/network i kasnije trošenje, a ne samo oblik transakcije.

## CoinJoin

**Mehanika:** više učesnika zajednički kreira transakciju sa mnogo inputa/outputa, često jednakih denominacija, povećavajući nejasnoću korespondencije input-output.

**Prednosti:** veći on-chain skup nejasnoće; postoje self-custodial dizajni; merljiva struktura runde.

**Nedostaci:** metadata koordinatora/peerova/mreže; naknade/likvidnost; prepoznatljiv oblik transakcije; toxic change i kasnija konsolidacija uništavaju dobitke; pravna/provajderska dostupnost varira.

**Procedura:** (1) proveriti aktuelnu dostupnost walleta/koordinatora i zakonitost; (2) instalirati zvanični wallet i napraviti backup; (3) koristiti samo zakonite UTXO-e; (4) razumeti denominaciju, fee i model koordinatora; (5) označiti/odvojiti change i mixed outpute; (6) nikad ih ne konsolidovati zajedno; (7) rutirati mrežni saobraćaj kako je zvanično podržano i sačuvati računovodstvo.

**Detekcija:** identifikovati kolaborativnu strukturu bez pretpostavke krivičnog dela; izračunati moguća mapiranja/anonymity set, zatim pratiti change/consolidation, granice servisa i mrežne/koordinatorske zapise.

## Lightning Network

**Mehanika:** HTLC plaćanja prolaze kroz onion-routed kanale; većina detalja plaćanja nije objavljena on-chain, dok su funding/closing i javni podaci o kanalima dostupni.

**Prednosti:** brzo, niska naknada; posrednici obično vide susedne hopove; rutinski detalji plaćanja ostaju off-chain.

**Nedostaci:** pošiljalac/primalac i prvi/poslednji hop znaju više; probing, timing, channel graph, liquidity/wallet/LSP zapisi; custodial walleti identifikuju korisnike.

**Procedura:** (1) svesno izabrati self-custodial ili custodial model; (2) proveriti wallet/seed/channel recovery; (3) koristiti invoice za tačno plaćanje; (4) preferirati private channels/LSP funkcije tek nakon razumevanja kompromisa; (5) zaštititi node IP podržanim Tor-om gde je potrebno; (6) ne ponavljati identifikujuće invoice-e; (7) voditi channel i payment accounting.<sup>[[6]](#references)</sup>

**Detekcija:** node/LSP/custodian logovi, channel graph/probes, payment failure/timing i on-chain funding/closure; nepostojanje javne transakcije ne znači da ne postoje zapisi.

## BOLT 12 offers i route blinding

**Mehanika:** ponovljivi offer proizvodi sveže invoice-e i može oglašavati blinded paths, pa platioc ne mora saznati jasni node/path primaoca.

**Prednosti:** privatnost primaoca; ponovljiva donation/payment endpoint tačka bez statičkog invoice-a; integriše se sa Lightning onion routingom.

**Nedostaci:** podrška walleta varira; endpointi, izabrani hopovi i funding ostaju; javni kontakt ili mrežni endpoint može ponovo identifikovati primaoca.

**Procedura:** (1) potvrditi odgovarajuću BOLT 12 podršku; (2) autentifikovati offer; (3) zatražiti svež invoice; (4) proveriti iznos/izdavaoca/ponavljanje; (5) platiti kroz wallet; (6) proveriti receipt/refund ponašanje; (7) smanjiti node alias/contact i sačuvati računovodstvo.<sup>[[7]](#references)</sup>

**Detekcija:** wallet/LSP i first/last-hop telemetrija, offer distribution account, timing/value i funding graph; route blinding namerno ograničava vidljivost platioca.

## Monero

**Mehanika:** one-time stealth addresses skrivaju povezivanje primaoca, RingCT skriva iznose, a ring signatures pružaju dvosmislenost pošiljaoca.

**Prednosti:** privatnost je podrazumevana on-chain; poverljivost pošiljaoca/primaoca/iznosa; zreo ekosistem dedicated wallet/node.

**Nedostaci:** zapisi akvizicije/off-ramp-a i endpoint/network/counterparty; remote node vidi upite/IP; podrška menjačnica i pravni tretman variraju; male operativne greške i dalje povezuju kontekste.

**Procedura:** (1) zakonito nabaviti i sačuvati osnov/izvor; (2) instalirati/proveriti zvanični održavani wallet; (3) napraviti/testirati seed backup; (4) koristiti lokalni node ili dokumentovani Tor/I2P remote-node put; (5) koristiti novu subaddress po payer/invoice-u; (6) lokalno označiti kontekste; (7) transaction proof/view pristup otkrivati samo namerno.<sup>[[8]](#references)</sup>

**Detekcija:** usmeriti pažnju na exchange/merchant/device/network i zaplenjeni wallet; sama upotreba protokola nije sumnjiva, a javni chain namerno otkriva manje.

## Zcash fully shielded Orchard

**Mehanika:** zero-knowledge proofs potvrđuju shielded transfere dok su pošiljalac, primalac i iznos šifrovani; transparentni pool-ovi i prelazi između pool-ova ostaju javni.

**Prednosti:** snažna shielded on-chain poverljivost; viewing keys mogu podržati ograničeni audit; validnost nametnuta protokolom.

**Nedostaci:** podrška walleta/menjačnica i stvarni izbor pool-a variraju; korelacija vremena/vrednosti transparentne granice; mreža/RPC i endpoint ostaju.

**Procedura:** (1) izabrati održavan Orchard shielded-by-default wallet; (2) proveriti/napraviti backup; (3) zakonito nabaviti ZEC; (4) primiti na podržanu Unified Address i potvrditi pool; (5) preferirati shielded-to-shielded; (6) koristiti podržanu mrežnu privatnost; (7) pre audita testirati otkrivanje viewing key-a na malom walletu.<sup>[[9]](#references)</sup>

**Detekcija:** transparentne granice i servisni zapisi, wallet/network metadata i viewing keys gde su zakonito dostavljeni; ne pretpostavljati da su sva Unified Address plaćanja bila shielded.

## Mimblewimble i Litecoin MWEB

**Mehanika:** confidential transactions skrivaju iznose, a Mimblewimble-style aggregation uklanja konvencionalnu istoriju bogatu adresama; Litecoin implementira opcioni extension block uz transparentni chain.

**Prednosti:** poverljivi iznosi i bolja fungibilnost u privatnom domenu; efikasno pruning/aggregation.

**Nedostaci:** opt-in granica peg-in/out je javna i može se korelisati; podrška walleta/menjačnica; razlike u interaktivnom/address modelu; mrežni i acquisition zapisi.

**Procedura:** (1) izabrati održavan wallet sa jasnom MWEB podrškom; (2) proveriti/napraviti backup i testirati mali iznos; (3) zakonito nabaviti; (4) peg-in u MWEB i proveriti balance domain; (5) transakcije vršiti samo sa kompatibilnim primaocem; (6) izbeći neposredni prepoznatljiv peg-out; (7) čuvati privatne audit zapise.<sup>[[10]](#references)</sup>

**Detekcija:** javni peg-in/out timing/value, exchange/wallet/node podaci i kasnija transparentna trošenja; interni detalji poverljivih transfera namerno su smanjeni.

## Ethereum zero-knowledge privacy applications

**Mehanika:** circuit dokazuje tvrdnju — membership, valid note ownership ili authorization — bez otkrivanja tajne; verifier contract je proverava. Deposits, withdrawals, public inputs, events i gas i dalje mogu otkriti veze.

**Prednosti:** programabilno selektivno otkrivanje; aplikacije sa anonymity-setom; proverljiva pravila bez otkrivanja svih podataka.

**Nedostaci:** greške contracta/circuit-a; mali anonymity set; javne granice; RPC/IP/session/analytics/gas funding; rizik aplikacije i sankcija/prava.

**Procedura:** (1) precizno definisati šta proof skriva; (2) koristiti auditovan održavan application gde je zakonito; (3) pregledati public inputs/events i deposit/withdraw pravila; (4) odvojiti action wallet i gas sponsorship kako protokol predviđa; (5) koristiti privacy-aware RPC/network put; (6) testirati malom vrednošću; (7) sačuvati compliance zapise.<sup>[[11]](#references)</sup>

**Detekcija:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics i kasnija exchange/merchant granica. Ne tvrditi da ZK proof skriva polja deklarisana kao javna.

## Stablecoins

**Mehanika:** tokeni se prenose na javnom chainu; centralizovani izdavaoci mogu zamrznuti/blacklistovati ili otkupiti prema identifikovanim nalozima.

**Prednosti:** stabilnost cene, likvidnost i podrška trgovaca; brzo poravnanje; lako računovodstvo.

**Nedostaci:** transparentni address/amount/contract graf; gas funding; identitet/kontrola izdavaoca i menjačnice; sanctions screening; uglavnom loša anonimnost.

**Procedura:** tretirati kao identifikovano plaćanje: koristiti svežu poslovnu adresu samo za compartmentation, proveriti token contract/network, testirati mali iznos, zaštititi wallet, koristiti pouzdan RPC/lokalni node, sačuvati basis/source i proveriti obavezne strane.

**Detekcija:** kompletan token event graf, issuer freeze lista/radnje, exchange/RPC/device i gas-funding veze.

## Cashu Chaumian e-cash

**Mehanika:** mint slepo potpisuje secrets koje generiše klijent, uz podršku mint-ovih Bitcoin/Lightning reserves; može sprečiti double-spend bez direktnog povezivanja izdavanja sa kasnijim iskorišćavanjem.

**Prednosti:** accountless bearer tokens; trenutni peer transfer; mint ne može direktno povezati blinded withdrawal sa spendom; tokeni se mogu prenositi kao data/QR.

**Nedostaci:** kastodija/solventnost/censorship mint-a; gubitak/krađa bearer podataka; denomination/timing i Lightning granice; mrežni metadata; rani softverski ekosistem.<sup>[[12]](#references)</sup>

**Procedura:** (1) prvo koristiti official test mint ili veoma malu potrošnu vrednost; (2) instalirati održavan wallet i testirati ograničenja backup/restore; (3) autentifikovati mint i pregledati kastodiju/naknade; (4) mintovati mali iznos; (5) poslati token kroz autentifikovani private channel/QR; (6) primalac zamenjuje token pre nego što ga smatra konačnim; (7) redeem i reconcile. Nikada ne čuvati značajnu vrednost u nepouzdanom mintu.

**Detekcija:** mint vidi mrežu, issue/redeem/Lightning granice i skup potrošenih tokena, ali blinding uklanja direktnu vezu tokena; endpointi/poruke i prepoznatljivi iznos/timing mogu obnoviti veze.

## Fedimint federated e-cash

**Mehanika:** prag guardians drži reserves i blind-signs e-cash; interni bearer transferi su privatni prema guardians, dok Lightning gateways povezuju eksterna plaćanja.

**Prednosti:** distribuirana kastodija; privatan interni transfer; community governance; nijedan guardian ispod praga ne kontroliše reserve.

**Nedostaci:** guardian quorum/kastodija/softverski rizik; gateway vidi invoice-e/timing; deposit/withdraw granice; složen oporavak stanja klijenta.

**Procedura:** (1) proveriti federation invite/guardians/quorum/jurisdikciju; (2) instalirati održavan client i testirati recovery; (3) položiti mali zakonit iznos; (4) koristiti sveže interne payment requestove; (5) gateway tretirati kao posmatrača za Lightning; (6) testirati redemption; (7) source/tax zapise čuvati izvan javnih payment podataka.<sup>[[13]](#references)</sup>

**Detekcija:** federation vidi agregatno izdavanje/redemption, gateway-i vide eksterne invoice-e, Bitcoin/Lightning pokazuju granice, a endpoint/communication dokazi mogu povezati interne transfere.

## GNU Taler

**Mehanika:** bank-integrated blind-signature e-cash nastoji da platioc ostane anoniman trgovcu, dok trgovci i prihod ostaju odgovorni.

**Prednosti:** privatnost platioca po dizajnu; obična valuta; odgovornost trgovca/refund; nije potreban spekulativni token.

**Nedostaci:** ograničena primena; exchange/banka vide funding; trgovac vidi order/delivery; rizik bearer walleta/recovery; regulisani operatori.

**Procedura:** (1) pronaći aktuelni exchange/merchant za jurisdikciju/valutu; (2) pročitati KYC/fees/privacy; (3) instalirati zvanični wallet; (4) zakonito povući sredstva iz podržane banke/exchange-a; (5) pregledati merchant contract; (6) platiti i sačuvati receipt/refund podatke; (7) izbeći nepotrebne merchant session identifikatore.<sup>[[14]](#references)</sup>

**Detekcija:** bank/exchange withdrawal i merchant deposit su odgovorne granice; merchant order/device/delivery i timing mogu se korelisati i kada su coins blinded.

## Cross-chain bridge, atomic swap i decentralized exchange

**Mehanika:** contract/service zaključava/burn-uje jedan asset i oslobađa/mintuje drugi, ili counterparties vrše atomic exchange. To prekida pogled jednog ledger-a, ali ne i ekonomsku kontinuitet.

**Prednosti:** interoperabilnost asseta/mreže; može se izbeći jedan centralizovani custodian; uobičajena portfolio/liquidity upotreba.

**Nedostaci:** oba chaina su javna; time/value/fees/liquidity i contracts se korelišu; bridge/relayer/frontend/RPC zapisi; smart-contract/counterparty i regulatorni rizik.

**Procedura za zakonite swapove:** (1) proveriti zvanični contract/service i pravnu dostupnost; (2) pregledati custody/audit/fees/slippage; (3) koristiti mali test; (4) zapisati oba transaction ID-ja i kurs; (5) zaštititi approvals; (6) uskladiti destination asset i opozvati nepotrebne approval-e. Ne koristiti swapove za prikrivanje porekla sredstava.

**Detekcija:** bridge deposit/withdraw events, jedinstveni iznos umanjen za naknade, redosled vremena, likvidnost, relayer/RPC/frontend i kasniji service deposits.

## Centralized mixer ili tumbler

**Mehanika:** servis prima deposit-e u pool i kasnije vraća druge jedinice, pokušavajući da zamagli direktno input-output mapiranje.

**Prednosti:** teoretski može povećati transakcijsku dvosmislenost.

**Nedostaci:** operator može ukrasti/logovati; analiza vremena/vrednosti ulaza/izlaza; sanctions/money-transmission i kriminalna izloženost; zaplena otkriva mapiranja; rizik taint/rejection.

**Procedura:** operativni vodič za mixing nije obezbeđen. Bezbedno reprodukovati graf proširivanjem [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): napraviti sintetičke deposit-e, pooled outpute, fees i delays; analitičarima dati nepotpuna mapiranja; meriti koje heuristike rade; zatim otkriti ground truth.

**Detekcija:** identifikacija service wallet/contracta, entry/exit candidate sets, amount/fee/timing, reuse deposit adresa, seized/provider logovi i downstream consolidation. Probabilističku atribuciju označiti kao takvu.

## Peel chains, fan-out/fan-in i structuring

**Mehanika:** ponovljene transakcije odvajaju male uplate od kusura, dele vrednost na mnoge adrese, ponovo spajaju collectore ili dele iznose radi izbegavanja pregleda.

**Prednosti:** povećava opterećenje naivnog analitičara i broj adresa.

**Nedostaci:** prepoznatljiv value/cadence/transaction continuity; consolidation i service endpoints; structuring samo po sebi može biti nezakonit; naknade i operativne greške.

**Procedura:** koristiti samo sintetičke CSV/testnet podatke: generisati veliki source, ponovljene payment/change edge-ove, paralelne grane i jedan collector; dodati benigne exchange-like primere; podesiti detekciju i dokumentovati false positives.

**Detekcija:** graph continuity, ponovljeni change pattern, cadence, just-below-control iznosi, zajednički service endpoint i off-chain zapisi. Exchange hot walleti mogu ličiti na ove obrasce, zato je kontekst obavezan.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker i front company

**Mehanika:** drugo lice/nalog/kompanija prima, konvertuje ili troši sredstva, ubacujući pravne i operativne slojeve između controller-a i transakcije.

**Prednosti za napadača:** imenovani nalog ne identifikuje odmah controller-a; može povezati gotovinu, crypto, robu i jurisdikcije.

**Nedostaci:** izloženost krađi identiteta/pranju novca; svaki učesnik dodaje komunikacije, bank/company/tax/shipping zapise, naknade, nedoslednosti i svedoke; ponovno korišćenje pomagača stvara hubove.

**Procedura:** ne emulirati stvarnim ljudima/nalozima. Napraviti sintetički graf sa controller-om, recruiter-om, mule-om, OTC-om, shell merchant-om i beneficiary-jem; ubaciti device/IP/message/bank edge-ove; tražiti od istražitelja da razlikuju vlasnika naloga od controller-a i zabeleže pouzdanost dokaza.

**Detekcija:** zajednički device/IP/recovery, neuobičajeni beneficiary/velocity, mnogo nepovezanih pošiljalaca, neposredno dalje premeštanje, nedoslednost kompanije/direktora/fakture, komunikacije i dostava gotovine/robe.

## NFTs, gambling, merchant goods i refund loops

**Mehanika:** vrednost se pretvara u samoprocenjeni asset, wagering balance, robu za preprodaju ili refund kako bi se stvorila drugačija naracija transakcije.

**Prednosti za napadača:** menja oblik asseta i uvodi marketplace/merchant posrednike.

**Nedostaci:** marketplace/account/device i wash-trade graf; odds/play i refund zapisi; dostava/preprodaja; naknade/gubici; odgovornost za prevaru/pranje novca.

**Procedura:** bez workflow-a za prikrivanje. Koristiti sintetičke marketplace podatke sa self-trade-ovima povezanih walleta, neplauzibilnim cenama, minimalnom igrom, neusaglašenim refund instrumentom i zajedničkom dostavom; validirati detekciju prema legitimnim collector/customer primerima.

**Detekcija:** kružne/self-funded trades, zajedničko vlasništvo/finansiranje, odstupanja cena, neposredna preprodaja/refund, minimalna ekonomska aktivnost, zajednički uređaj/dostava i ponovno spajanje prihoda.

## Physical bearer wallet ili offline token transfer

**Mehanika:** uređaj, papir/QR, hardware bearer instrument ili e-cash token prenosi kontrolu tajne umesto da pri predaji emituje payment.

**Prednosti:** nema live network eventa tokom razmene; korisno offline; custody nalik gotovini.

**Nedostaci:** kopiranje/krađa/gubitak i neizvesna ekskluzivnost; kasniji redemption/broadcast povezuje; fizički sastanak/slanje; rizik falsifikovanja/tamper-a.

**Procedura:** (1) koristiti samo pregledan instrument/protokol; (2) privatno inicijalizovati/proveriti autentičnost; (3) učitati samo mali zakoniti iznos; (4) preneti u dokumentovanom ovlašćenom kontekstu; (5) primalac proverava ili promptno sweep-uje prema protokolu; (6) nikada ne pretpostavljati da pošiljalac nije zadržao kopiju; (7) privatno zabeležiti vlasništvo/tax dokaze.

**Detekcija:** kupovina/funding i konačni sweep/redemption, serijski broj uređaja/tamper dokazi, dostava/sastanak i endpoint zapisi.

## Merchant-scoped invoice ili one-time payment request

**Mehanika:** trgovac kreira jednokratni zahtev sa iznosom, rokom i order referencom. Platioc ga poravnava kroz podržani rail bez direktnog otkrivanja ponovo upotrebljivog credential-a trgovcu; izdavalac ili payment processor i dalje mogu identifikovati obe strane.

**Prednosti:** ograničava ponovno korišćenje credential-a i slučajne cross-merchant identifikatore; tačan iznos/rok smanjuju greške; kompatibilno sa običnim accounting/refund procesima.

**Nedostaci:** invoice, dostava, browser, processor i issuer i dalje povezuju order; jedinstveni iznos/vreme može pojačati korelaciju; zlonamerni payment linkovi su česti.

**Procedura:** (1) nezavisno autentifikovati trgovca; (2) zatražiti svež invoice sa tačnim iznosom, asset/network i rokom; (3) pregledati destination i refund pravila; (4) platiti iz odobrenog engagement compartment-a; (5) proveriti da trgovac potvrđuje isti invoice; (6) sačuvati receipt i transaction reference; (7) isteći zahtev umesto ponovne upotrebe.

**Detekcija:** trgovac i processor povezuju invoice, session i settlement; jedinstveni iznosi/vremena i dostava identifikuju platioca. **Captured wallet/device:** istorija invoice-a otkriva counterparties i svrhu; smanjiti nepotrebne memo podatke, šifrovati uređaj i čuvati authoritative accounting u kontrolisanom finance sistemu.

## Prepaid service credit i capability token

**Mehanika:** servis pretvara konvencionalno plaćanje u ograničene interne credits ili bearer capability. Naknadna API/resource upotreba može izbeći prezentovanje originalne kartice pri svakom zahtevu, ali servis često može mapirati izdavanje na iskorišćavanje.

**Prednosti:** ograničava potrošnju i gubitak pri kompromitaciji; odvaja svakodnevne radnike od funding credential-a; podržava per-project budžete i opoziv.

**Nedostaci:** obično pseudonimno, ne anonimno; service database, redemption IP i jedinstveni usage pattern povezuju aktivnost; bearer tokeni mogu biti ukradeni; refund može zahtevati originalnog platioca.

**Procedura:** (1) kupiti credits kroz organization account; (2) napraviti jedan projekat i budžet; (3) izdati uski token sa service/amount/expiry ograničenjima; (4) čuvati ga samo u odobrenom secret manager-u ili workload identity putanji; (5) testirati odbijanje izvan scope-a i nakon isteka; (6) nadgledati potrošnju; (7) opozvati i uskladiti neiskorišćenu vrednost.

**Detekcija:** provajder povezuje funding account, project, token issuance i usage; defenders alarmiraju geografske/procesne promene i neuobičajenu potrošnju. **Captured node:** pretpostaviti da se preostala capability može potrošiti; koristiti kratak expiry, nizak saldo, audience binding i neposredni server-side revoke.

## Privacy Pass ili blinded authorization token

**Mehanika:** izdavalac proizvodi privacy-preserving authorization token koji origin može proveriti bez povezivanja redemption-a sa issuance-om. Može predstavljati plaćeno pravo ili ograničeni pristup, ali nije opšta valuta. Arhitektura razdvaja client, attester, issuer i origin uloge i upozorava da IP/timing ili collusion mogu poništiti unlinkability.<sup>[[18]](#references)</sup>

**Prednosti:** nepoveziv redemption za podržane servise; nema ponovljivi account cookie na originu; keširani tokeni mogu vremenski odvojiti izdavanje i upotrebu.

**Nedostaci:** specifično za aplikaciju; poverenje u issuer/attester i podela anonymity-seta; IP i browser metadata ostaju; krađa tokena ili karakteristično vreme izdavanja mogu povezati upotrebu.

**Procedura:** (1) koristiti implementaciju usklađenu sa relevantnim Privacy Pass token type-om; (2) precizno definisati koje pravo token dokazuje; (3) razdvojiti issuer i origin administraciju kada model pretnje to zahteva; (4) smanjiti challenge metadata; (5) izdati više test tokena i svaki jednom iskoristiti na sopstvenim originima; (6) uporediti logove radi zabranjenih stabilnih identifikatora; (7) testirati replay, expiry i revocation/abuse kontrole.

**Detekcija:** origin vidi redemption IP/time i validnost tokena; issuer/attester vidi issuance context; analitičari testiraju timing i metadata partitions bez pretpostavke kriptografskog proboja. **Captured client:** neiskorišćeni bearer tokeni mogu biti upotrebljivi; ograničiti vrednost, trajanje i audience, a funding credential nikada ne keširati zajedno sa njima.

## Delegated organization procurement ili fiscal sponsor

**Mehanika:** ovlašćeni procurement team, reseller ili fiscal sponsor sklapa ugovor i plaća, dok operativni tim prima ograničeni servis. To je razdvajanje uloga sa istinitim zapisima, a ne nominee ili lažni identitet.

**Prednosti:** prodavci ne moraju dobiti identitet svakog operatora ili lične payment podatke; centralna compliance, poreska i refund obrada; jasan budžet i offboarding.

**Nedostaci:** sponsor zna korisnika i svrhu; ugovori, odobrenja, dostava i nalozi ostaju; dodatno vreme/naknade; slabo razdvajanje ako ista osoba upravlja svim slojevima.

**Procedura:** (1) dokumentovati poslovnu svrhu, korisnika i approving authority; (2) izabrati organization-approved intermediary; (3) ugovoriti pod istinitim podacima; (4) obezbediti project-scoped subaccount bez ličnog billing credential-a; (5) razdvojiti finance administratore od operatora; (6) uskladiti invoice-e i pristup; (7) pri završetku prekinuti servis i delegated access.

**Detekcija:** procurement, identity-provider, vendor i delivery zapisi spajaju lanac. **Captured operational device:** treba da otkrije service project, ali ne finance credential-e; invoice-e i identitete platioca čuvati u finance sistemu, ne na field node-ovima.

## Escrow ili conditional settlement

**Mehanika:** pouzdani escrow agent ili smart contract drži vrednost dok se ne ispune dokumentovani uslovi. Može smanjiti direktno otkrivanje između platioca i primaoca, dok escrow i osnovni payment rail-ovi zadržavaju odnos.

**Prednosti:** zaštita spora i dostave; platioc i trgovac mogu međusobno izložiti manje ponovo upotrebljivih credential-a; auditabilni uslovi release-a.

**Nedostaci:** escrow custody/contract rizik, naknade i identitetske obaveze; on-chain contracts su javni; order, shipping i dispute podaci ostaju; nije anonimno prema posredniku.

**Procedura:** (1) proveriti pravno lice, custody, fees, dispute forum i podržane assete; (2) napraviti precizan pisani milestone i refund path; (3) finansirati iz odobrenog organization account-a; (4) nezavisno proveriti prijem i release authorization; (5) release tek nakon dokaza; (6) sačuvati kompletan audit zapis; (7) zatvoriti neiskorišćene dozvole/contract approvals.

**Detekcija:** escrow account/contract events, funding/release time, beneficiary i dispute zapisi otkrivaju transakciju. **Captured device:** session tokeni ili contract approvals mogu omogućiti release; zahtevati odvojen approver/MFA i opozvati aktivne session-e pri gubitku.

## Batched ili pooled organization settlement

**Mehanika:** više odobrenih obaveza se agregira i poravnava u manjem broju bankarskih ili blockchain transakcija, uz privatni interni ledger koji dodeljuje udele. Batching može smanjiti javne detalje po kupovini, ali coordinator zadržava potpunu atribuciju.

**Prednosti:** niže naknade; manje javnih graf edge-ova; javni posmatrač ne vidi pojedinačne stavke kada su iznosi agregirani; jednostavno interno računovodstvo.

**Nedostaci:** coordinator je potpun posmatrač i vredna meta; karakteristični totali/timing mogu se korelisati; custody/reconciliation rizik; zloupotrebljeno može ličiti na structuring.

**Procedura:** (1) definisati učesnike i zakonite obaveze u accounting sistemu; (2) postaviti redovan, poslovno opravdan batch window umesto pragova dizajniranih za izbegavanje kontrola; (3) zahtevati dual approval agregata; (4) poravnati sa autentifikovanim primaocima; (5) uskladiti svaku internu stavku sa batch-om; (6) refund-e tretirati kao povezane korekcije; (7) zaštititi pristup ledgeru i čuvati ga prema politici.

**Detekcija:** coordinator ledger, approval i beneficiary zapisi daju ground truth; javni analitičari treba oprezno da koriste clustering inputa/outputa/vrednosti/vremena. **Captured payer device:** treba da sadrži samo svoj requisition, ne signing key pool-a ili participant ledger.

## Account-abstraction paymaster ili sponsored gas

**Mehanika:** relayer/bundler podnosi smart-account operation, a paymaster plaća transaction fees, čime se izbegava direktna native-gas funding edge veza iz user walleta. Poboljšava jedno svojstvo grafa; operation, contract i service telemetry ostaju javni ili posmatrivi.<sup>[[19]](#references)</sup>

**Prednosti:** uklanja uobičajenu gas-funding vezu; podržava scoped sponsorship i rate limits; bolje onboarding iskustvo za legitimne privacy aplikacije.

**Nedostaci:** paymaster/bundler/RPC/frontend mogu korelisati zahteve; contract events i public inputs ostaju; sponsorship policy otkriva cohort; zlonamerni contracts ili approvals mogu ukrasti assete.

**Procedura:** (1) koristiti auditovan održavan smart account i paymaster na ispravnoj mreži; (2) pregledati koja polja su javna i šta sponsor loguje; (3) ograničiti sponsorship prema contractu, funkciji, iznosu, nonce-u i expiry-ju; (4) testirati malom vrednošću; (5) slati kroz predviđeni privacy-aware path aplikacije; (6) proveriti operation i fee payer on-chain; (7) opozvati allowances/session keys i sačuvati compliance zapise.

**Detekcija:** povezati UserOperation, EntryPoint, paymaster, bundler/RPC i application logove; oprezno klasterovati identičnu sponsorship policy. **Captured wallet:** session keys i pending approvals mogu biti upotrebljivi i bez gas-a; usko ih ograničiti i opozvati kroz recovery policy naloga.

## Threshold ili multisignature payment authorization

**Mehanika:** trošenje zahteva prag nezavisnih signera. Ne skriva transakciju, ali omogućava da se payment authority odvoji od zaplenjenog laptopa, field node-a ili pojedinačnog operatora.

**Prednosti:** snažna otpornost na kompromitaciju i insidera; odgovorno odobrenje; nijedan field uređaj nema potpunu signing authority; podržava recovery.

**Nedostaci:** koordinacija i dostupnost; metadata signera/uređaja/naloga može povezati učesnike; loš backup uzrokuje gubitak; javni multisig obrasci mogu biti prepoznatljivi.

**Procedura:** (1) definisati signere, prag, limite i recovery pre funding-a; (2) inicijalizovati na odvojenom podržanom hardware-u/nalozima; (3) nezavisno proveriti adrese i backup-e; (4) field workload-ima dati samo mogućnost unsigned requisition-a; (5) zahtevati out-of-band pregled primaoca, iznosa i svrhe; (6) testirati recovery i gubitak jednog signera malom vrednošću; (7) rotirati signera nakon kompromitacije.

**Detekcija:** approval system, signer device i javni script/contract pružaju dokaze; defenders alarmiraju promene policy-ja ili signer seta. **Captured node:** treba da otkrije najviše jednu low-authority session key ili unsigned request; nikada ne keširati quorum material zajedno.

## Closed-loop community ili event currency

**Mehanika:** cooperative, conference ili privatno testno okruženje izdaje credits koji se mogu iskoristiti samo među uključenim učesnicima. Interni transfer može manje izlagati globalnim payment mrežama, dok operator kontroliše izdavanje i redemption.

**Prednosti:** ograničen ekonomski domen; može testirati offline ili privacy-preserving payment UX; ograničava eksternu card exposure; jasne eksperimentalne kontrole.

**Nedostaci:** mali anonymity set; operator i trgovci vide aktivnost; ograničena prihvaćenost/redemption; licensing, consumer-protection i tax pravila mogu važiti i za lokalnu vrednost.

**Procedura:** (1) pribaviti pravnu/compliance proveru i objaviti issuer uslove; (2) uključiti učesnike koji pristaju; (3) ograničiti izdavanje i zabraniti cash-like zloupotrebu; (4) koristiti sveže payment requestove i smanjiti javne participant identifikatore; (5) beležiti agregatne reserve i privatne individual receipts; (6) testirati gubitak/refund/redemption; (7) zatvoriti ledger i vratiti preostalu vrednost kako je obećano.

**Detekcija:** issuer ledger, enrollment, merchant i redemption zapisi rekonstruišu tokove; neuobičajeni kružni transferi ili brz cash-out zahtevaju pregled. **Captured wallet:** lokalni saldo i counterparties mogu biti izloženi; ograničiti vrednost, šifrovati state i podržati issuer-side freeze/reissue sa auditabilnim zapisom.

## Bitcoin reusable payment codes i private payment instructions

**Mehanika:** BIP 47 payment codes koriste ponovo upotrebljiv javni identifikator i ECDH-derived one-time deposit adrese; BIP 351 definiše noviji private-payment instruction dizajn. Smanjuju javno ponovno korišćenje adresa, uz stabilne payment instructions koje primalac može objaviti. Notification, podrška walleta, funding i kasniji coin selection i dalje utiču na privatnost.<sup>[[20]](#references)</sup>

**Prednosti:** jedna javna instruction može proizvesti različite adrese; primalac ne mora objaviti svaku invoice adresu; kompatibilni walleti mogu pratiti izvedena plaćanja; korisno za ponovljene zakonite donatore/klijente.

**Nedostaci:** interoperabilnost walleta varira; notification transakcije ili objavljeni payment code povezuju relationship context; pošiljalac, primalac i javni graf i dalje vide transakcije; nemarna konsolidacija ili change handling poništavaju korist.

**Procedura:** (1) potvrditi da oba održavana walleta podržavaju potpuno istu specifikaciju/verziju; (2) napraviti backup i testirati recovery na walletu male vrednosti; (3) out-of-band autentifikovati recipient payment code; (4) poslati mali zakonit test; (5) proveriti da je korišćena sveža izvedena adresa; (6) lokalno označiti odnos i primeniti coin control; (7) testirati recovery i refund ponašanje pre oslanjanja na mehanizam.

**Detekcija:** analitičari pregledaju notification obrasce, funding/change, kasniju konsolidaciju i service boundaries; objava javnog koda identifikuje recipient context i kada se deposit adrese razlikuju. **Capture-resilient OPSEC:** spend keys držati van field uređaja i izložiti najviše watch-only relationship view. **Monitoring:** alarmirati neočekivane notification transakcije, ponovo korišćene derived adrese, wallet gap-limit/recovery greške i neplaniranu konsolidaciju.

## EVM stealth addresses (ERC-5564)

**Mehanika:** pošiljalac izvodi one-time stealth account iz recipient stealth meta-address i objavljuje announcement sa ephemeral public key i view tag-om. Primalac skenira announcement-e viewing key-em i izvodi odgovarajući spend key. Povezivanje primaoca je poboljšano, ali sender, amount/token, gas, announcement i kasnije trošenje ostaju vidljivi.<sup>[[21]](#references)</sup>

**Prednosti:** sveža receiver adresa bez interakcije; ponovo upotrebljiv meta-address; odvojene viewing i spending uloge; radi sa podržanim EVM assetima/aplikacijama.

**Nedostaci:** announcement scanning i spam; funding gas-a nove adrese može ponovo uspostaviti vezu; pošiljalac zna primaoca; javni token/amount i kasnija konsolidacija ostaju; implementacija i podrška walleta variraju.

**Procedura:** (1) koristiti auditovanu održavanu implementaciju prvo na test network-u; (2) generisati i backup-ovati odvojeni viewing/spending material; (3) autentifikovati meta-address; (4) poslati test male vrednosti i announcement; (5) skenirati i izvesti stealth account; (6) testirati podržani gas sponsorship bez lične funding edge veze; (7) zabeležiti javna polja i sačuvati zakonito računovodstvo.

**Detekcija:** pratiti announcement caller, token/amount, timing, gas sponsor, spending i consolidation; view key može dokazati prijem bez odobravanja spend-a. **Capture-resilient OPSEC:** networked scanner treba da ima samo viewing ulogu gde je podržano; spend i recovery keys čuvati drugde. **Monitoring:** alarmirati malformed/spam announcement-e, view-key access, neočekivani spend derivation i stealth outpute premeštene bez odobrenja.

## Liquid Confidential Transactions

**Mehanika:** Liquid podrazumevano blinds output amounts i asset types koristeći commitments i proofs, dok transaction graph, input/output count, fee i block time ostaju vidljivi. Peg-in/peg-out i service boundaries ostaju povezivi, a korisnici mogu selektivno otkriti blinding podatke.<sup>[[22]](#references)</sup>

**Prednosti:** poverljivi iznos i asset type po defaultu; brzo sidechain poravnanje; selektivni audit putem blinding keys/descriptors; skriva komercijalno osetljive vrednosti od javnih posmatrača.

**Nedostaci:** struktura grafa i timing ostaju; poverenje u federation/bridge/exchange; peg granice i unconfidential outputs; wallet/node/network zapisi; primalac i pošiljalac znaju svoju transakciju.

**Procedura:** (1) izabrati održavan Liquid wallet i proveriti model backup-a; (2) koristiti testnet ili mali zakonit iznos; (3) primiti na confidential adresu i proveriti da wallet označava output kao blinded; (4) poslati testnu confidential transakciju; (5) pregledati koja explorer polja ostaju javna; (6) izvesti samo scoped blinding proof potreban za audit; (7) dokumentovati peg/exchange granice i uskladiti sredstva.

**Detekcija:** analizirati vidljivi graph/fee/time, peg i exchange zapise, network metadata i kasnije unblinding dokaze; ne zaključivati skriveni iznos ili asset. **Capture-resilient OPSEC:** odvojiti spend seed, blinding/view podatke i watch-only operacije. **Monitoring:** alarmirati slučajne unconfidential adrese, nepoznate peg zahteve, descriptor changes i neodobren izvoz unblinding key-a.

## General payment ili state channel

**Mehanika:** učesnici zaključavaju sredstva, razmenjuju potpisana off-chain state ažuriranja i na chain objavljuju samo otvaranje, zatvaranje ili osporeno stanje. Međupayments nisu globalno broadcastovani, ali peerovi i routing/intermediary servisi vide svoj deo, a endpointi moraju čuvati poslednje izvršivo stanje.<sup>[[23]](#references)</sup>

**Prednosti:** mnogo brzih low-fee interakcija privatnih učesnika sa javnim ledgerom; manje globalnih detalja transakcija; ograničen channel balance; korisno za metered servise i ponovljene counterparties.

**Nedostaci:** channel peerovi znaju jedni druge i mogu čuvati updates; opening/closing/value/timing se korelišu; online monitoring može biti potreban tokom challenge window-a; implementacioni i liquidity rizik; samo po sebi nije veliki anonymity set.

**Procedura:** (1) izabrati održavanu auditovanu implementaciju i razumeti dispute window; (2) otvoriti testni channel male vrednosti između sopstvenih strana; (3) razmeniti potpisana state ažuriranja sa jedinstvenim nonce-ovima; (4) backup-ovati najnovije izvršivo stanje; (5) kooperativno zatvoriti; (6) uvežbati stale-state rejection na testnetu; (7) sačuvati accounting i channel-peer zapise.

**Detekcija:** javni chain otkriva lifecycle/disputes; peerovi, watch servisi i application transport otkrivaju off-chain timing i strane. **Capture-resilient OPSEC:** ograničiti hot balance i držati poslednje potpisano stanje u šifrovanom recoverable store-u odvojenom od field node-ova. **Monitoring:** stalno pratiti stale-state publication, propušten backup, peer-key change i približavanje challenge deadline-a.

## Mobile carrier billing

**Mehanika:** online servis naplaćuje kupovinu na mobile subscription ili prepaid balance kroz carrier billing sistem. Trgovac može dobiti carrier authorization umesto card/bank podataka, dok carrier zna subscriber/line, device/network kontekst, trgovca, iznos i vreme.<sup>[[24]](#references)</sup>

**Prednosti:** nema broja kartice kod trgovca; široka dostupnost telefona; korisno za digitalnu robu male vrednosti; carrier može ograničiti i poništiti naplate.

**Nedostaci:** snažno identifikovano SIM/account-om i često uređajem; mali limiti i visoke naknade; ograničenja kategorije trgovca; account takeover/SIM-swap rizik; carrier i aggregator stvaraju kompletan trag transakcije.

**Procedura:** (1) potvrditi dostupnost, limit, naknadu i refund uslove sa organization carrier account-om; (2) uključiti samo na dedicated organization line-u ako je opravdano; (3) postaviti najniži koristan spend cap; (4) kupiti benigni test item; (5) proveriti merchant i carrier receipts; (6) isključiti recurring authorization; (7) uskladiti i isključiti funkciju nakon procene.

**Detekcija:** carrier, aggregator i merchant zapisi povezuju line, subscriber, IP/device i charge; enterprise telecom invoices to otkrivaju. **Capture-resilient OPSEC:** ne koristiti lični broj i zahtevati carrier-account MFA van field uređaja. **Monitoring:** uključiti instant charge/SIM-change alerts i zaustaviti se pri neočekivanom premium-service enrollment-u, forwarding-u ili account recovery-u.

## Open-banking payment initiation

**Mehanika:** uz izričitu saglasnost korisnika, regulisani payment-initiation service provider (PISP) traži od banke koja vodi nalog da pokrene transfer. Trgovac možda ne dobije card credentials, ali PISP i banke zadržavaju regulisane payer, payee, consent, device i transaction zapise.<sup>[[25]](#references)</sup>

**Prednosti:** nema ponovo upotrebljivog broja kartice pri checkout-u; snažna bank authentication; precizno account-to-account poravnanje; consent/status API-ji; jasna reconciliation.

**Nedostaci:** nije anonimno bankama/PISP-u; payee često vidi legal account details ili reference; phishing/redirect rizik; jurisdikcija i refund zaštite variraju; consent metadata dodaje novog posmatrača.

**Procedura:** (1) proveriti da je PISP trenutno regulisan i da je merchant callback domen autentičan; (2) početi od merchant request-a; (3) pregledati payee, iznos, reference i zahtevanu saglasnost u banci; (4) odobriti samo pojedinačno plaćanje; (5) nezavisno proveriti konačni status; (6) opozvati preostalu saglasnost ako postoji; (7) sačuvati receipt i izvršiti reconciliation.

**Detekcija:** bank/PISP/merchant logovi i transfer references pružaju snažnu atribuciju. **Capture-resilient OPSEC:** banking authentication i recovery držati van operational/field uređaja; uređaj treba da sadrži samo paid-service entitlement. **Monitoring:** koristiti bank transaction/consent alerts i istražiti nove PISP grantove, promenjenog payee-ja ili status callback-e izvan očekivane sesije.

## Platform wallet, app-store balance ili in-app credit

**Mehanika:** platforma naplaćuje korisniku ili iskorišćava account credit, zatim aplikaciji izdaje signed receipt ili entitlement. App developer možda ne dobije originalni funding instrument, dok platforma mapira account, device, funding, product i redemption.<sup>[[26]](#references)</sup>

**Prednosti:** trgovac/developer ne dobija primarni PAN; fraud/refund i family/business kontrole; mali prepaid saldo ograničava izloženost; signed receipts olakšavaju proveru entitlement-a.

**Nedostaci:** platform account je snažan identity/behavior hub; device i storefront geography; trag kupovine/iskorišćavanja gift balance-a; ograničen cash-out; fraud controls mogu zamrznuti sredstva; nije novac između platformi.

**Procedura:** (1) koristiti organization-managed platform account gde politika dopušta; (2) pregledati funding, region, refund i transferable-value pravila; (3) dodati samo odobreni budžet; (4) kupiti benigni proizvod kroz official store; (5) proveriti da aplikacija dobija samo očekivana receipt polja; (6) isključiti recurring purchase; (7) uskladiti i ukloniti nalog sa operativnog hardware-a.

**Detekcija:** platform receipts/server notifications, account/device login i funding zapisi rekonstruišu kupovinu. **Capture-resilient OPSEC:** nikada ne prijavljivati lični store account na field node; gde je moguće dati samo scoped app entitlement. **Monitoring:** uključiti new-device/purchase alerts i istražiti receipt replay, family/account changes ili neočekivane restore events.

## Mutual credit, clearing ili periodic net settlement

**Mehanika:** učesnici beleže obaveze u privatnom ledgeru i periodično poravnavaju samo net poziciju. Pojedinačni service events ne moraju stvarati posebna javna plaćanja, ali operator ledger-a i counterparties zadržavaju detaljnu atribuciju.

**Prednosti:** manje eksternih transakcija i naknada; javni posmatrači vide samo net settlement; radi za ponovljene organizacije; eksplicitni credit limits ograničavaju izloženost.

**Nedostaci:** centralizovani ledger je potpun dokaz i meta za prevaru; counterparty/default risk; pravne/računovodstvene/poreske obaveze; mali membership set; neuobičajeni net transferi i dalje mogu otkriti odnose.

**Procedura:** (1) koristiti samo identifikovane saglasne organizacije uz pravno/računovodstveno odobrenje; (2) definisati jedinicu, credit limit, settlement interval i dispute pravila; (3) beležiti svaku obavezu sa immutable approval-om; (4) odvojene finance uloge računaju i odobravaju net positions; (5) poravnati kroz običan zakonit rail; (6) uskladiti pojedinačne stavke sa settlement-om; (7) zatvoriti pristup i čuvati zapise prema politici.

**Detekcija:** ledger, invoice-i, approvals i konačni bank/chain settlement pružaju ground truth; analitičari ne treba da zaključuju nedostajuću bruto aktivnost samo iz net transfera. **Capture-resilient OPSEC:** operativni uređaji mogu slati ograničene requisitions, ali ne mogu menjati salda ili odobravati settlement. **Monitoring:** alarmirati prekoračenje credit limita, backdated entries, promene administratora, reconciliation mismatch i settlement novom beneficiary-ju.

## Matrica izloženosti pri zapleni/kompromitaciji

Ovo primenjuje seizure/loss test na svaku familiju. Cilj je ograničiti spending authority i otkrivanje nepovezanog identiteta uz očuvanje zakonitog računovodstva, a ne brisanje transakcija ili ometanje istrage.

| Familija tehnike | Zaplenjeni wallet/uređaj/nalog može otkriti | Minimalna ovlašćena kontrola |
|---|---|---|
| Gotovina, money order, COD, fizička bearer vrednost | priznanice, serijske brojeve, beleške, preostalu bearer vrednost i fizičke kontakte | nositi samo odobreni iznos; odvojeno privatno računovodstvo; odmah prijaviti gubitak; bez lažnih zapisa |
| Prepaid, gift, voucher, service credits | saldo, izdavaoca, aktivaciju, redemption i account/session tokene | mali saldo; jedna svrha; istinita registracija; issuer freeze/revocation gde je dostupno |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transakcije, recovery i istoriju trgovca | device lock; transaction alerts; merchant scope; remote issuer suspension; bez deljenog recovery naloga |
| Bank compartment, delegated procurement, red-team procurement | organizaciju, approvere, vendor, invoice-e i projekat | razdvajanje uloga; least-privilege subaccount; finance credentials nikada na operational/field node-ovima |
| Invoice, escrow, batch settlement | counterparty, svrhu, pending approval, coordinator ili dispute trag | single-use request; odvojeni approver; ograničena sesija; centralni authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, adrese, transaction graph i network configuration | hardware/offline signing; šifrovani wallet; ograničene passphrase; watch-only field view; dokumentovan recovery |
| Lightning/BOLT 12 | seed, kanale, invoice-e, peerove/LSP i payment database | minimalan hot balance; šifrovani backup; odvojeni node identity; close/recover prema dokumentovanom planu |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, lokalnu istoriju walleta, RPC i boundary transakcije | odvojene spend/view uloge; hardware podrška gde postoji; bez exchange session-a na field node-u |
| Stablecoins, swaps, bridges i DEX | transparentni graf, approvals, RPC/frontend state i destination assete | revoke allowances; provereni contracts; test male vrednosti; kompletna reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokene, mint/federation/exchange, issuance/redemption cache | mali saldo; šifrovani backup prema protokolu; redeem/reissue; nikad zajedno sa funding credential-om |
| Paymaster, multisig/threshold | session key, jednog signera, pending operations i sponsor policy | uska session key; nezavisni quorum; rotacija signera; field uređaj ne sme doseći prag |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | inkriminišući provider, komunikacije, graf i zapise učesnika | bez operativne upotrebe; samo sintetička/testnet emulacija |
| Community/event currency | enrollment, lokalni saldo, counterparties i redemption | ograničena vrednost; issuer freeze/reissue; saglasnost i privatni auditabilni ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcement-e i izvedene outpute | watch/view-only network role; offline/hardware spend role; bez personal funding session-a |
| Liquid confidential/state channels | seed, blinding data/latest state, peerove, granice i disputes | odvojeni spend/view/state backup; nizak hot balance; nezavisan dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device i funding source | organization account; external MFA; nizak limit; bez ličnog naloga na field hardware-u |
| Mutual-credit clearing | members, obligations, limits, approvals i settlement ledger | samo operational requisition; odvojeni immutable ledger i dual finance approval |

## Monitoring moguće detekcije ili kompromitacije plaćanja

Odbijanje plaćanja, compliance review ili wallet koji je offline ne dokazuju da istraga postoji. Pratiti samo naloge, ledger-e i infrastrukturu koje organizacija ima pravo da nadzire; nikada ne ispitivati provajdere ili counterparties da bi se proverilo da li sarađuju sa istražiteljima.

| Obuhvaćene tehnike | Bezbedni monitoring signali | Uslov za freeze/stop |
|---|---|---|
| Gotovina, money order/COD, prepaid/gift/voucher, fizička bearer vrednost | neslaganje inventara/priznanica, dupli serijski broj, neočekivani redemption/refund ili prijava gubitka | nedostajući instrument, redemption izvan odobrenog order-a, izmenjena priznanica ili prekid custody-ja |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, novi device/consent/payee, reuse tokena, SIM/account recovery | nepoznata autorizacija, promena payee-ja, novi recovery faktor, SIM swap ili recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice i consumption | cross-project token, nepoznati admin, prekoračenje limita, invoice mismatch ili nepodržani destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, integritet ledger-a, reconciliation i promena beneficiary-ja | izmenjen iznos/payee, backdated ledger, unilateral release ili neusaglašen batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transakcije, notification/scan state, ponovna upotreba adrese, UTXO labels i consolidation | nepoznat spend, ponovo korišćen recipient output, wallet gap/recovery failure ili neodobreno spajanje |
| PayJoin/CoinJoin | proposal inputi/outputi/fees, dostupnost koordinatora, finalna transakcija | zamenjen output, prevelika naknada, neočekivano otkrivanje inputa ili promena coordinator policy-ja |
| Lightning/BOLT12/general channels | channel backup, invoice/offer upotreba, liquidity, peer/LSP i chain dispute | nepoznato invoice plaćanje, peer-key change, stale close ili približavanje dispute deadline-a |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor i boundary transaction | spend bez odobrenja, transparent/unconfidential downgrade, key export ili nepoznata granica |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key i issuer action | pogrešan contract/public field, nepoznat approval/spend, paymaster change ili issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway i bearer balance | nepoznat redemption, promena mint key/uslova, restore failure ili neslaganje salda |
| Swaps/bridges/DEX | provereni contract, allowance, potvrde oba chaina, kurs i destination | contract/route mismatch, unlimited approval, nedostajući destination ili bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum i recovery audit | nepoznat proposal/signer, smanjen prag, recovery activation ili policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | samo sintetički lab ground truth i izlaz detekcije | bilo koji stvarni nalog, lice ili vrednost u emulaciji: odmah zaustaviti |

## Workflow izbora i verifikacije

1. Navesti koja strana ne sme saznati koje polje.
2. Identifikovati issuer/mint/custodian, javni ledger, network/RPC, trgovca i fizičke posmatrače.
3. Proveriti aktuelnu podršku, zakonitost, limite, custody, recovery i refund ponašanje.
4. Koristiti mali zakoniti end-to-end test.
5. Pregledati merchant receipt, provider statement, javni chain i wallet/node logove.
6. Testirati backup/recovery i namerno audit otkrivanje.
7. Obavezne source, ownership, tax, sanctions i engagement zapise voditi tačno, uz kontrolisan pristup.

## References

- [1] [EMVCo — Tokenizacija plaćanja](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Zapažanja o prikupljanju podataka velikih payment platformi](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Zaštitite svoju privatnost](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Jednostavan Payjoin predlog](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Tehničke specifikacije i privatnost mreže](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Izgradnja privacy aplikacija pomoću zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Ograničenja protokola i privatnosti](https://docs.cashu.space/faq)
- [13] [Fedimint — Kako funkcioniše](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler dokumentacija](https://docs.taler.net/)
- [15] [FATF — Indikatori za uzbunu kod virtual assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administratori, menjači i korisnici virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — Informacije o transferima i crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Arhitektura Privacy Pass-a](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State i payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
