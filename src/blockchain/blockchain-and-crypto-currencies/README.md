# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

Ovo poglavlje obrađuje koncepte blockchaina i bezbednost na lancu. Za izložen Bitcoin peer, počnite od [enumeracije Bitcoin P2P servisa](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); za frontend u pregledaču, povezivanje novčanika ili off-chain backend, koristite [pentesting DApp aplikacija](../../pentesting-web/dapps-DecentralizedApplications.md). Za operacije privatnosti kriptovaluta i njihova ograničenja, pogledajte [poglavlje o privatnosti kriptovaluta](../../privacy/cryptocurrency-privacy.md).

## Osnovni koncepti

- **Smart Contracts** su programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi, automatizujući izvršavanje sporazuma bez posrednika.
- **Decentralized Applications (dApps)** nadovezuju se na smart contracts i sadrže korisnički prilagođen frontend i transparentan backend koji se može proveravati.
- **Tokens & Coins** razlikuju se po tome što coins služe kao digitalni novac, dok tokens predstavljaju vrednost ili vlasništvo u određenim kontekstima.
  - **Utility Tokens** omogućavaju pristup uslugama, dok **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za Decentralized Finance i nudi finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** označavaju Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

Za terminologiju koja se koristi na kripto-tržištima u vezi sa spot nalozima, futures ugovorima, leverageom i opcijama, pogledajte [Pojmove iz investiranja](investment-terms.md).

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** oslanja se na računarsku snagu za proveru transakcija.
- **Proof of Stake (PoS)** zahteva da validatori poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u odnosu na PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije obuhvataju prenos sredstava između adresa. Transakcije se validiraju digitalnim potpisima, čime se osigurava da prenos može pokrenuti samo vlasnik privatnog ključa.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **inputs** (izvora sredstava), **outputs** (odredišta), **fees** (naknada plaćena rudarima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj mu je da poboljša skalabilnost Bitcoina tako što omogućava više transakcija unutar kanala, a na blockchain objavljuje samo konačno stanje.

## Problemi sa privatnošću Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost tako što prikrivaju veze između transakcija korisnika.

## Anonimno pribavljanje bitcoina

Metode uključuju trgovinu za gotovinu, rudarenje i korišćenje mixers. **CoinJoin** meša više transakcija kako bi otežao njihovo praćenje, dok **PayJoin** prikazuje CoinJoins kao obične transakcije radi veće privatnosti.

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su razlog za zabrinutost. U nastavku je pojednostavljen pregled nekoliko uobičajenih načina na koje napadači mogu da ugroze privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Uglavnom je neuobičajeno kombinovati ulaze različitih korisnika u jednoj transakciji zbog složenosti takvog postupka. Zato se **često pretpostavlja da dve ulazne adrese u istoj transakciji pripadaju istom vlasniku**.

## **UTXO Change Address Detection**

UTXO, odnosno **Unspent Transaction Output**, mora se potrošiti u celosti u jednoj transakciji. Ako se samo deo pošalje na drugu adresu, ostatak se šalje na novu adresu za kusur. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se narušava njegova privatnost.

### Primer

Da bi se to ublažilo, mogu se koristiti servisi za mešanje ili više adresa kako bi se prikrilo vlasništvo.

## **Social Networks & Forums Exposure**

Korisnici ponekad objavljuju svoje Bitcoin adrese na internetu, zbog čega je **lako povezati adresu sa njenim vlasnikom**.

## **Transaction Graph Analysis**

Transakcije se mogu prikazati kao grafovi, otkrivajući moguće veze između korisnika na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika se zasniva na analizi transakcija sa više ulaza i izlaza kako bi se procenilo koji izlaz predstavlja kusur vraćen pošiljaocu.

### Primer

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ako dodavanje novih ulaza učini da izlaz kusura bude veći od bilo kog pojedinačnog ulaza, to može zbuniti heuristiku.

## **Prisilno ponovno korišćenje adresa**

Napadači mogu slati male iznose na adrese koje su ranije korišćene, nadajući se da će primalac te iznose spojiti sa drugim ulazima u budućim transakcijama, čime se adrese povezuju.

### Ispravno ponašanje novčanika

Novčanici bi trebalo da izbegavaju korišćenje novčića primljenih na već korišćenim, praznim adresama kako bi sprečili ovo narušavanje privatnosti.

## **Druge tehnike analize blockchaina**

- **Tačni iznosi plaćanja:** Transakcije bez kusura verovatno se odvijaju između dve adrese u vlasništvu istog korisnika.
- **Okrugli iznosi:** Okrugao iznos u transakciji nagoveštava da je reč o plaćanju, dok je izlaz sa neokruglim iznosom verovatno kusur.
- **Otisci novčanika:** Različiti novčanici imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni softver i potencijalno adresu za kusur.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može omogućiti njihovo praćenje.

## **Analiza saobraćaja**

Praćenjem mrežnog saobraćaja napadači mogu potencijalno da povežu transakcije ili blokove sa IP adresama, čime se ugrožava privatnost korisnika. To je naročito slučaj kada neki entitet upravlja velikim brojem Bitcoin čvorova, što mu omogućava da efikasnije nadzire transakcije.

## Više informacija

Sveobuhvatan spisak napada na privatnost i odbrana od njih potražite na stranici [Bitcoin Privacy na Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini anonimnog sticanja bitcoina

- **Gotovinske transakcije**: Sticanje bitcoina gotovinom.
- **Alternative gotovini**: Kupovina poklon-kartica i njihova razmena za bitcoin na internetu.
- **Rudarenje**: Najprivatniji način sticanja bitcoina je rudarenje, naročito kada se obavlja samostalno, jer rudarski poolovi mogu saznati IP adresu rudara. [Informacije o rudarskim poolovima](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: Teoretski, krađa bitcoina mogla bi biti još jedan način da se bitcoin stekne anonimno, mada je to nezakonito i ne preporučuje se.

## Usluge mešanja

Korišćenjem usluge mešanja, korisnik može **poslati bitcoine** i zauzvrat dobiti **druge bitcoine**, zbog čega je teško utvrditi ko je bio prvobitni vlasnik. Međutim, to zahteva poverenje u uslugu, da neće čuvati evidenciju i da će zaista vratiti bitcoine. Alternativne opcije mešanja uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** spaja više transakcija različitih korisnika u jednu, što otežava povezivanje ulaza sa izlazima. Uprkos efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje je potencijalno moguće pratiti.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Više informacija potražite na stranici [CoinJoin](https://coinjoin.io/en). Za Ethereum mixer zasnovan na pametnom ugovoru, koji razdvaja depozite od kasnijih isplata, pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) tako da izgleda kao obična transakcija, bez karakterističnih jednakih izlaza koji se javljaju kod CoinJoin-a. Zbog toga je izuzetno teško otkriti je, a mogla bi i da učini nevažećom heuristiku zajedničkog vlasništva nad ulazima koju koriste entiteti za nadzor transakcija.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcije poput prethodne mogu biti PayJoin, čime se poboljšava privatnost, a istovremeno ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da poremeti tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanju da se obezbedi privatnost transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Radi očuvanja privatnosti i bezbednosti, ključno je sinhronizovati novčanike sa blockchain-om. Izdvajaju se dva metoda:

- **Full node**: Preuzimanjem celog blockchain-a, full node obezbeđuje maksimalnu privatnost. Sve ikada obavljene transakcije čuvaju se lokalno, pa napadači ne mogu da utvrde koje transakcije ili adrese zanimaju korisnika.
- **Filtriranje blokova na strani klijenta**: Ovaj metod podrazumeva pravljenje filtera za svaki blok u blockchain-u, što omogućava novčanicima da prepoznaju relevantne transakcije, a da posmatračima mreže ne otkrivaju konkretna interesovanja. Laki novčanici preuzimaju ove filtere, a cele blokove preuzimaju samo kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin funkcioniše u peer-to-peer mreži, preporučuje se korišćenje Tor-a za prikrivanje IP adrese i bolju privatnost pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može narušiti privatnost povezivanjem transakcija sa istim entitetom. Savremeni novčanici svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Deljenje uplate na više transakcija može prikriti iznos transakcije i osujetiti napade na privatnost.
- **Izbegavanje kusura**: Odabir transakcija koje ne zahtevaju izlaze za kusur poboljšava privatnost jer ometa metode za otkrivanje kusura.
- **Više izlaza za kusur**: Ako izbegavanje kusura nije izvodljivo, stvaranje više izlaza za kusur i dalje može poboljšati privatnost.

# **Monero: svetionik anonimnosti**

Monero je osmišljen tako da privatnost transakcija bude prioritet.

# **Ethereum: gas i transakcije**

## **Razumevanje gas-a**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u, a njegova cena izražava se u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) ima ograničenje gasa i osnovnu naknadu, uz prioritetnu naknadu kojom se podstiču validatori da je uključe. Korisnici mogu da postave maksimalnu naknadu kako bi bili sigurni da neće platiti više nego što je potrebno; višak im se vraća.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u obuhvataju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili pametnih ugovora. Za njih je potrebna naknada i moraju biti uključene u blok. Osnovni podaci transakcije obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, ograničenje gasa i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, pa ne mora da bude navedena u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za sve koji žele da koriste kriptovalute, a da pritom daju prednost privatnosti i bezbednosti.

## Red Teaming za Web3 usmeren na vrednosti

- Popišite komponente koje upravljaju vrednostima (potpisnici, oracle-i, mostovi, automatizacija) da biste utvrdili ko može da premešta sredstva i na koji način.
- Povežite svaku komponentu sa relevantnim taktikama MITRE AADAPT kako biste otkrili putanje eskalacije privilegija.
- Uvežbajte lance napada koji uključuju flash-loan/oracle/pristupne podatke/međulančane napade da biste potvrdili uticaj i dokumentovali preduslove za eksploataciju.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje toka potpisivanja u Web3

- Manipulacijom u lancu snabdevanja korisničkih interfejsa novčanika mogu se menjati EIP-712 payload-i neposredno pre potpisivanja i pribavljati važeći potpisi za preuzimanje kontrole nad proxy-jima zasnovanim na delegatecall-u (npr. prepisivanjem slot-0 vrednosti Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Apstrakcija naloga (ERC-4337)

- Uobičajeni načini otkaza pametnih naloga uključuju zaobilaženje kontrole pristupa `EntryPoint`, nepotpisana polja gasa, validaciju sa stanjem, ERC-1271 replay i pražnjenje naknada usled revert-a nakon validacije.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost pametnih ugovora

- Testiranje mutacijama radi otkrivanja slepih tačaka u skupovima testova:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet zk dokaza / zkVM guest programa

Kada proveravalac koristi **zkVM** ili namensko dokazno kolo aplikacije da potvrdi tvrdnju, proveravalac saznaje samo da je **guest program izvršen prema svom kodu**. Ako guest sadrži **nebezbednu deserializaciju**, **nedefinisano ponašanje** ili **nedostajuća semantička ograničenja**, zlonamerni proveravalac može da generiše dokaz koji prolazi verifikaciju, iako su **javni pokazatelji ili navedena invarijanta netačni**.<sup>[[7]](#references)</sup>

### Nebezbedna deserializacija unutar proof guest programa

- Tretirajte privatne witness/circuit bajtove kao **nepoverljiv ulaz napadača**, čak i ako su skriveni dokazom.
- Izbegavajte njihovu deserializaciju pomoću neproverenih pomoćnih funkcija kao što je `rkyv::access_unchecked`, osim ako bajtovi prethodno nisu nezavisno validirani.
- Pre nego što utiču na tok kontrole ili pristup memoriji, moraju se validirati enum diskriminante, relativni pokazivači, dužine i indeksi učitani iz nepoverljivih serijalizovanih podataka.

Praktični obrazac za reviziju:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ako je polje poput `op.kind` enum i napadač može da ubaci **discriminant van opsega**, svaki nizvodni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table / UB

Ako Rust pretvori veliki `match` u **jump table**, nevažeći discriminant enuma može da izazove **nedefinisan tok kontrole**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van opsega indeksira van prve jump table i dospeva do koda povezanog sa drugom.

Rezultat: operacija se i dalje izvršava, ali se putanja obračunavanja preskače. U zkVM-u to može da omogući falsifikovanje dokaza koji prijavljuju nemoguće metrike, kao što su manji broj gate-ova, manje skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum vrednosti pod kontrolom napadača, deserijalizovane iz witness/private input-a.
- Pregledajte ponovljene `match` iskaze nad istim poljem opcode/kind.
- Tretirajte kombinaciju `unsafe` + deserijalizacija bez provera + velika opcode dispečerska logika kao visokorizičnu.
- Po potrebi obrnuto analizirajte generisani binarni fajl; raspored jump table-a može biti važniji od izvornog koda.

### Nedostajuća semantička ograničenja u reverzibilnim/specijalizovanim interpreterima

Nemojte proveravati samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba da nametne.

Za reverzibilne/instrukcijske skupove nalik kvantnim, uverite se da su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija nalik Toffoli/CCX, implementirana ovako:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

postaje nebezbedno ako gost ne odbije:

```text
op.q_control1 == op.q_control2 == op.q_target
```

U tom slučaju, prelaz se svodi na:

```text
q = q ^ (q & q) = 0
```

Ovo stvara **deterministički primitiv za resetovanje**, narušavajući pretpostavke o reverzibilnosti i omogućavajući jeftinija, nenameravana izračunavanja. U sistemima za dokazivanje koji potvrđuju upotrebu resursa, ovo napadačima može omogućiti da zadovolje funkcionalne provere, a da zaobiđu model troškova za koji verifikator veruje da se sprovodi.

### Nedovoljno ograničeni saveti dokazivača i modularna aritmetika

Vrednosti učitane sa **steka saveta/svedoka su pod kontrolom dokazivača**, čak i kada su opisane kao unapred izračunati količnici, ostaci, inverzi ili nagoveštaji. Dokaz samo potvrđuje da svedok zadovoljava implementirana ograničenja; ne potvrđuje da je izvršeno predviđeno izračunavanje ako ta ograničenja izostavljaju proveru tipa, opsega ili kanonskog oblika.<sup>[[13]](#references)</sup>

Kod pomoćne funkcije za redukciju ili euklidsko deljenje, proverite celokupnu celobrojnu relaciju, a ne samo završno oduzimanje ili množenje. Svaki limb vrednosti `q` i `r` mora biti ograničen na deklarisanu širinu, rekonstrukcija `x = q * m + r` mora važiti u predviđenom celobrojnom prikazu, a kanonska granica `0 <= r < m` mora biti nametnuta. Proverite vrednost **pre** nego što je prosledite instrukciji užeg tipa `u32`/`u64`; operacija užeg tipa ne dokazuje retroaktivno da je izvorni element polja ili višelimbna vrednost imala očekivani tip.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Neuspeh `mod_12289` u Miden-u ilustruje obrazac eksploatacije: količnik je proveren kao 64-bitna vrednost od dva limba, ali ostatak dostavljen kroz advice stigao je do `u32overflowing_sub` bez ekvivalentne provere. Zlonamerni prover mogao je da uskladi nevažeće vrednosti količnika i ostatka tako da implementirana ograničenja oduzimanja i dalje važe, a da procedura vrati matematički neispravan ostatak. Pošto se taj rezultat koristio pri Falcon verifikaciji, narušavanje soundness-a moglo je da se iskoristi za falsifikovanje potpisa za autorizaciju, umesto da samo proizvede pogrešan aritmetički rezultat.<sup>[[13]](#references)</sup>

### Revizija kriptografskih VM-ova sa implicitnim stekom

Jezici zasnovani na steku skrivaju operande, zato najpre podignite instrukcije u IR gde je svaka potrošena i proizvedena vrednost steka predstavljena izrazom sa informacijama o poreklu. Konzervativni analizni tok zatim može da:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Izgradi graf poziva i zaključi efekte procedura na ulazni i izlazni stek.
2. Simbolički izvršava podržane instrukcije i podigne tok kontrole u SSA/strukturirane izraze.
3. Propagira apstraktne činjenice kao što su `Unknown`, `ProvenU32`, `Bool`, poreklo vrednosti i lokalna inicijalizacija do fiksne tačke.
4. Označi vrednosti izvedene iz advice-a koje stižu do tipizovane aritmetike ili sink-ova koji zahtevaju vrednost različitu od nule, a da nisu sanitizovane na **svakoj** ulaznoj putanji.
5. Uporedi deklarisane i zaključene potpise i proveri da svaki izlaz čuva vrednosti steka koje pripadaju pozivaocu.

Nepoznat potpis ili nepodržanu konstrukciju tretirajte kao **analiznu prazninu**, a ne kao čist rezultat. Dinamički pozivi, petlje koje menjaju stek i grane sa različitim efektima na stek mogu onemogućiti pouzdano praćenje pozicija na steku; bezbedniji dekompajler odbacuje ili označava te slučajeve, umesto da generiše uverljiv, ali netačan pseudokod.<sup>[[10]](#references)[[13]](#references)</sup>

Na spojevima toka kontrole zadržite svojstvo samo ako važi za svakog prethodnika (na primer, `ProvenU32 join Unknown = Unknown`). Takođe razlikujte konvergenciju do fiksne tačke od dostizanja ograničenja broja iteracija: samo konvergirana, zvučno preterana aproksimacija može da opravda tretiranje izostanka dijagnostike kao dokaza da sva predstavljena izvršavanja zadovoljavaju svojstvo.<sup>[[11]](#references)</sup>

### Koristite obaveze dokazivanja da biste otkrili skrivene preduslove

Za male skupove instrukcija, prevedite procedure u izvršiv formalni VM model i dokažite i rezultat i celokupnu transformaciju steka. Teorema treba da obuhvati terminaciju, tipizovane ulaze, očekivani prefiks izlaza i očuvanje neizmenjenog steka pozivaoca. Pažljivo proverite iskaz teoreme kao i dokaz: kernel može da proveri dokaz slučajno oslabljenog tvrđenja.<sup>[[12]](#references)[[13]](#references)</sup>

Neočekivane hipoteze su korisni nalazi. Tokom Miden revizije, za dokaz 64-bitne rotacije udesno bio je potreban uslov `shift mod 32 != 0`, čime je otkriven granični slučaj koji ne radi za velike ulaze kada je pomak deljiv sa 32; drugim dokazom je utvrđeno da 256-bitni `wrapping_mul` odbacuje vrednosti steka koje pripadaju pozivaocu. Dodajte otkriveni granični slučaj u testove, pa ispravite implementaciju ili namerno pooštrite javni preduslov, umesto da neprimetno prihvatite dodatnu pretpostavku.<sup>[[12]](#references)[[13]](#references)</sup>

### Šta testirati u ZK sistemima

- Fuzz-ujte sve guest parsere sa neispravnim kodiranjima witness/private-input podataka.
- Proverite validaciju raspona enum vrednosti pre dispečovanja opkoda.
- Dodajte semantičke provere za aliasing operanada i druge nevažeće oblike instrukcija.
- Pratite svaki izvor advice/witness podataka do svakog tipizovanog aritmetičkog sink-a i zahtevajte validaciju na svakoj putanji.<sup>[[11]](#references)[[13]](#references)</sup>
- Testirajte aritmetičke pomoćne funkcije sa nek kanonskim limb-ovima, ostacima van dozvoljenog raspona i graničnim vrednostima pomaka.<sup>[[12]](#references)[[13]](#references)</sup>
- Na svakom povratku proverite visinu steka i očuvanje vrednosti ispod deklarisanih argumenata procedure.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan dokaz i dalje može da dokaže **pogrešnu tvrdnju** ako je guest program neispravan.

## Autorizacija zavisna od stanja

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacija DeFi/AMM sistema

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotrebu zaokruživanja/preciznosti, swap-ove sa flash loan-om koji prelaze prag), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za multi-asset weighted pool-ove koji keširaju virtuelna stanja i mogu biti zatrovani kada je `supply == 0`, proučite:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Javni i privatni ključ — objašnjenje - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Šta su višepotpisi transakcija? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcije | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i naknade | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privatnost - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Pobedi smo Google-ov zero-knowledge proof kvantne kriptoanalize](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zaštita kriptovaluta zasnovanih na eliptičkim krivama od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repozitorijum](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arhitektura MASM dekompajlera](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM mehanizam za statičku analizu](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean model i dokazi ispravnosti](https://github.com/trailofbits/masm-lean)
- [13] [Revizija u eri (dovoljno dobrog) AI-ja](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
