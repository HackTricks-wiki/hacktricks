# Protokoli plaćanja koji čuvaju privatnost

{{#include ../banners/hacktricks-training.md}}

Napredni sistemi plaćanja mogu sakriti platioca od trgovca, sakriti primaoca ili iznos iz javnog registra ili sprečiti mint da poveže povlačenje sa otkupom. To su različita svojstva. Nijedno ne uklanja evidenciju o nabavci, uređaju, mreži, isporuci, računovodstvu, sankcijama ili krajnjoj tački.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) pruža standardizovane odeljke `Pros`, `Cons`, postupak `Procedure` korak po korak i `Detection` za svaku porodicu plaćanja. Ova stranica proširuje napredne protokole.

{% hint style="danger" %}
Koristite samo zakonita sredstva i ugovorne strane. Ne koristite protokole privatnosti za izbegavanje obavezne identifikacije, sankcija, poreza, provera porekla sredstava ili prijavljivanja transakcija. Ne upravljajte menjačnicom, mintom ili uslugom prenosa bez razumevanja obaveza u vezi sa licenciranjem, starateljstvom, AML-om i zaštitom potrošača.
{% endhint %}

## Poređenje naprednih opcija

| Protokol | Šta skriva od javnosti/trgovca | Strana od poverenja ili strana koja posmatra | Zrelost/dostupnost |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Spoljni posmatrači ne mogu povezati ponovo upotrebljiv kod plaćanja sa njegovim jednokratnim izlazima | Javni Bitcoin graf ostaje; wallet/index server može videti skeniranja | Specifikacija završena; podrška walleta varira |
| Zcash potpuno shielded Orchard | Pošiljalac, primalac i iznos su šifrovani on-chain | Wallet backend/mreža i acquisition/off-ramp ostaju vidljivi | U produkciji; shielded podrška varira po walletu/menjačnici |
| GNU Taler | Trgovac ne mora saznati identitet platioca; prihod trgovca ostaje sledljiv | Taler exchange/banka vidi finansiranje; trgovac vidi porudžbinu | Implementacije su geografski ograničene |
| Federated Chaumian e-cash | Federacija ne bi trebalo da poveže izdate novčanice sa internim transferima/otkupom | Kvorum guardian-a čuva rezerve; gateway-i vide aktivnosti na granicama | Implementacije zajednice su u nastajanju |
| Lightning BOLT 12/route blinding | Smanjuje otkrivanje primaoca/čvora i rute | Krajnje tačke, izabrani hop-ovi, lanac finansiranja i wallet usluge | Podrška zavisi od walleta |
| Virtualna kartica/token | Trgovac prima ograničenu akreditaciju, a ne PAN koji se može ponovo koristiti | Izdavalac/mreža zadržavaju podatke o platiocu i transakciji | Zrelo i široko dostupno |

## Bitcoin Silent Payments (BIP 352)

Silent Payments omogućava primaocu da objavi jedan statički kod plaćanja, dok svaki pošiljalac izvodi jedinstveni Taproot izlaz. Spoljni posmatrač lanca ne može direktno povezati te izlaze sa objavljenim kodom, a nije potreban ni interaktivni zahtev za adresu niti izlaz za on-chain obaveštenje. BIP 352 je označen kao **Complete**, ali uvodi trošak skeniranja i nije kompatibilan sa walletima koji ga nisu implementirali.<sup>[[1]](#references)</sup>

### Tok rada primaoca

1. Izaberite održavan wallet koji izričito podržava BIP 352 receiving; proverite funkciju u aktuelnoj dokumentaciji walleta, a ne na osnovu tvrdnje sa društvenih mreža.
2. Napravite rezervnu kopiju seed-a walleta i materijala Silent Payment descriptor/key koristeći dokumentovani metod oporavka walleta. Testirajte pronalaženje na malom iznosu na testnet/mainnet mreži pre objavljivanja koda.
3. Generišite zasebne **labels** za kampanje, fakture ili ugovorne strane tamo gde wallet podržava BIP 352 labels. Labels pomažu lokalnom računovodstvu bez objavljivanja adresa koje se mogu povezati.
4. Objavite statički Silent Payment kod preko autentifikovanog kanala. Može se ponovo koristiti, ali napadač može zameniti kod svojim.
5. Kada je praktično, skenirajte preko lokalnog full node-a. Server treće strane za indeksiranje/skeniranje može saznati vreme zahteva ili podatke filtera čak i ako ne može da troši sredstva.
6. Održavajte pronađene UTXO-e označenim i primenjujte ista pravila coin-control-a kao kod običnog Bitcoin-a. Njihovo trošenje ili konsolidovanje može otkriti veze vlasništva.
7. Potvrdite da oporavak pronalazi plaćanja bez oslanjanja na eksterni index koji nije obuhvaćen rezervnom kopijom.

### Tok rada pošiljaoca

1. Potvrdite da wallet podržava slanje na tu verziju adrese i autentifikujte dugački statički kod primaoca.
2. Prepustite walletu da konstruiše izlaz; nikada nemojte ručno konvertovati ili skraćivati kod.
3. Pažljivo pregledajte izabrane inpute. Silent Payments poboljšava privatnost adrese primaoca, ali inputi pošiljaoca i dalje ostaju na javnom grafu.
4. Koristite ponašanje fee bumping/PSBT koje podržava wallet. BIP 352 zahteva ponovno izvođenje izlaza ako se inputi promene, a neki režimi potpisivanja nisu bezbedni.
5. Sačuvajte šifrovanu potvrdu ili dokaz potreban za sporove/računovodstvo.

Silent Payments rešava ponovljeno objavljivanje adrese primaoca. Ne skriva iznos, vreme transakcije, klaster pošiljaoca, istoriju nabavke niti kasnije zajedničko trošenje.

## Zcash shielded plaćanja

Zcash podržava transparentne i shielded pool-ove vrednosti. Orchard shielded transakcije koriste zero-knowledge proofs tako da čvorovi mogu proveriti validnost dok su detalji transakcije šifrovani; Unified Addresses mogu sadržati više tipova primalaca.<sup>[[2]](#references)</sup> Privatnost zavisi od stvarne putanje koju je wallet izabrao, a ne od prvog karaktera prikazane adrese.

### Shielded tok rada

1. Izaberite održavan wallet koji jasno navodi ponašanje **shielded-by-default** i aktuelnu Orchard podršku. Proverite preuzimanje i napravite/testirajte rezervnu kopiju seed-a.
2. Nabavite ZEC zakonito i zabeležite osnov i izvor. Menjačnica i dalje zna za nabavku i povlačenje.
3. Primite sredstva na Unified Address koju wallet podržava, zatim proverite da li je transakcija završila u shielded pool-u. Ne pretpostavljajte automatsko shieldovanje bez potvrde ponašanja walleta.
4. Dajte prednost **shielded-to-shielded** transferima. Kretanja transparent-to-shielded i shielded-to-transparent na granici otkrivaju javne vrednosti/vreme i mogu omogućiti korelaciju iznosa; Orchard specifikacija navodi da trošenje na ne-Orchard adresu otkriva vrednost transakcije.<sup>[[3]](#references)</sup>
5. Izbegavajte karakteristične povratne transakcije sa potpuno istim iznosom i neposredne prelaske preko granice. Ovo je higijena privatnosti, a ne dozvola za prikrivanje vlasništva ili prijavljivanja.
6. Koristite mrežnu privacy putanju koju wallet podržava. Shielded kriptografija ne skriva IP/vreme od wallet servera ili peer-ova.
7. Čuvajte interne compliance evidencije i koristite viewing keys samo za namernu reviziju/otkrivanje nakon razumevanja njihovog obima.
8. Potvrdite podršku walleta/menjačnice primaoca pre slanja; obavezni transparentni primalac menja svojstvo privatnosti.

## GNU Taler: anonimni platioc, odgovorni trgovac

GNU Taler je open elektronski-payment protokol koji koristi tradicionalne valute, blind signatures i integraciju sa regulisanim exchange/bank sistemima. Njegov dizajn nastoji da korisnici ostanu anonimni trgovcima, dok trgovci ostaju identifikovani i poreski obavezni.<sup>[[4]](#references)</sup> Nije cryptocurrency, a dostupnost zavisi od kompatibilnog regionalnog exchange-a, banke, walleta i trgovca.

### Tok rada korisnika tamo gde je implementiran

1. Identifikujte aktivni Taler exchange i trgovca u relevantnoj valuti/jurisdikciji; pročitajte njihove aktuelne uslove, naknade, KYC i obaveštenja o privatnosti.
2. Instalirajte zvanični wallet i proverite njegov izvor. Zaštitite podatke za backup/recovery walleta kao gotovinu jer vrednost u walletu može biti bearer asset.
3. Povucite sredstva kroz podržani tok banke/exchange-a koristeći istinite podatke. Institucija koja finansira/exchange može znati za povlačenje iako blind signatures prekidaju direktnu vezu između coin-a i povlačenja.
4. Pregledajte ugovor sa trgovcem u walletu: identitet trgovca, stavku/sažetak, iznos, naknade, povraćaj i uslove isporuke.
5. Platite i sačuvajte podatke o potvrdi potrebne za povraćaj, garanciju, računovodstvo ili porez.
6. Nemojte ponovo koristiti opcione identifikatore sesije/računa trgovca ako je potrebna nepovezivost sa trgovcem.
7. Uključite wallet, mrežne i delivery metapodatke u threat model; Taler payment kriptografija ne skriva adresu za isporuku ili kompromitovanu krajnju tačku.

Trgovac i exchange ostaju odgovorni, a upravljanje bilo kojom od tih komponenti može predstavljati regulisanu aktivnost pružanja payment usluga.

## Federated Chaumian e-cash

Chaumian e-cash koristi blind signatures tako da mint potpisuje token bez uvida u kasnije potrošeni unblinded token. Fedimint raspodeljuje čuvanje rezervi i potpisivanje među guardian federacijom; njegova dokumentacija navodi da guardian-i vide zbirne rezerve/neizmirene novčanice, ali ne bi trebalo da vide pojedinačni saldo niti ko je kome platio unutar federacije.<sup>[[5]](#references)</sup>

Ovo je **custodial bearer value**. Dovoljan kvorum guardian-a kontroliše rezerve; otkaz federacije, nepošteni guardian-i, softverske greške ili gubitak stanja klijenta mogu dovesti do gubitka. Depoziti, povlačenja i Lightning gateway-i su vidljivi događaji na granici i mogu povezati vreme/iznos.

### Tok rada sa ograničenim rizikom

1. Koristite samo mali iznos koji možete priuštiti da izgubite. Javne/nepoznate federacije tretirajte kao rizičnije od guardian-a sa stvarnom odgovornošću.
2. Proverite pozivnicu za federaciju preko autentifikovanog kanala i zabeležite identitete guardian-a, kvorum, jurisdikciju, naknade, recovery i politiku gašenja.
3. Instalirajte održavan kompatibilni wallet, proverite ga i razumite njegovu šemu backup-a pre depozita.
4. Položite zakonito stečeni Bitcoin kroz dokumentovanu putanju. Zabeležite peg-in radi računovodstva i pretpostavite da su njegovo vreme/iznos javni ili poznati na granici.
5. Unutar federacije koristite sveže payment requests i izbegavajte dodavanje identifikatora naloga/chata/isporuke koji bi ponovo uspostavili vezu uklonjenu blind signature-om.
6. Kod Lightning plaćanja tretirajte gateway kao dodatnog posmatrača faktura i vremena aktivnosti na granici.
7. Otkupite/povucite sredstva u skladu sa pravilima i očekujte da se karakterističan iznos i neposredno vreme mogu povezati sa depozitom ili eksternim plaćanjem.
8. Privatno čuvajte poreske evidencije, evidencije porekla i ovlašćenja; ne tražite od guardian-a ili gateway-a da netačno prikažu aktivnosti.

Ne opisujte federated e-cash kao trustless, self-custodial ili garantovano anoniman.

## BOLT 12 offers i route blinding

BOLT 12 offers mogu biti ponovo upotrebljivi bez objavljivanja stabilne on-chain adrese i mogu koristiti blinded paths tako da platioc ne mora saznati jasan identitet/putanju primaočevog čvora. Ovo dopunjuje, ali ne zamenjuje postojeće onion routing mehanizme Lightning-a.

Pre upotrebe:

1. Potvrdite da wallet-i pošiljaoca i primaoca podržavaju iste aktuelne BOLT 12 funkcije; ne zaključujte o podršci na osnovu opšte oznake „Lightning“.
2. Autentifikujte offer out of band i proverite iznos, izdavaoca/opis i pravila ponavljanja.
3. Koristite svež invoice/payment kontekst generisan iz offer-a.
4. Svedite aliases čvorova, javne kontaktne podatke i stabilne mrežne krajnje tačke na minimum.
5. Pretpostavite da pošiljalac/primalac, prvi/poslednji hop, wallet servis, channel graph i on-chain finansiranje/zatvaranje i dalje otkrivaju delove odnosa.

## Mogućnost revizije bez javnog otkrivanja

Privatnost i revizija mogu postojati istovremeno:

- Čuvajte labels, fakture, ovlašćenja, nabavnu cenu i mapiranje vlasništva šifrovano izvan javnog protokola.
- Odvojite **view/audit key** od spending key-a kada ga protokol pruža; prvo testirajte njegovo tačno otkrivanje na uzorku walleta.
- Dajte revizoru dokaz minimalnog obima umesto seed-a ili neograničene spending akreditacije.
- Zabeležite verziju softvera, protocol/pool, ID transakcije ili proof, svrhu ugovorne strane i izvor kursa u trenutku transakcije.
- Definišite rok čuvanja i brisanja umesto gomilanja trajnog nešifrovanog grafa identiteta.

## Kontrolna lista za izbor

- [ ] Skriveno polje i posmatrač su precizno navedeni.
- [ ] Podrška walleta/protokola proverena je na datum transakcije.
- [ ] Veze sa nabavkom, mrežom, node/RPC-jem, ugovornom stranom, isporukom i kasnijim trošenjem su dokumentovane.
- [ ] Rizici starateljstva, oporavka, likvidnosti, solventnosti izdavaoca/federacije i povraćaja su prihvaćeni.
- [ ] Obavezne evidencije identiteta, poreza, sankcija, porekla i organizacije ostaju tačne.
- [ ] Mali end-to-end test, uključujući oporavak i dokaz revizije, uspešno je završen.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
