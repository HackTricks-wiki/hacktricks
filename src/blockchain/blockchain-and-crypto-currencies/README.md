# Blokčejn i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

Ovo poglavlje obrađuje koncepte blokčejna i bezbednost na lancu. Za izloženi Bitcoin peer počnite od [enumeracije Bitcoin P2P servisa](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); za frontend u pregledaču, povezivanje novčanika ili off-chain backend koristite [pentesting DApp-ova](../../pentesting-web/dapps-DecentralizedApplications.md). Za operacije privatnosti kriptovaluta i njihova ograničenja pogledajte [poglavlje o privatnosti kriptovaluta](../../privacy/cryptocurrency-privacy.md).

## Osnovni koncepti

- **Pametni ugovori** su programi koji se izvršavaju na blokčejnu kada se ispune određeni uslovi, automatizujući sprovođenje sporazuma bez posrednika.
- **Decentralizovane aplikacije (dApps)** zasnivaju se na pametnim ugovorima, uz korisnički pristupačan frontend i transparentan backend koji se može proveravati.
- **Tokeni i novčići** razlikuju se po tome što novčići služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenom kontekstu.
  - **Utility tokeni** omogućavaju pristup uslugama, a **security tokeni** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za decentralizovane finansije, koje pružaju finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAO** označavaju decentralizovane berze i decentralizovane autonomne organizacije.

Za termine koji se koriste na kripto tržištima, kao što su spot nalozi, fjučersi, leveridž i opcije, pogledajte [Investicione termine](investment-terms.md). Za zloupotrebu stope finansiranja u perpetual protokolima pogledajte [Eksploataciju stope finansiranja perpetual ugovora](perpetual-funding-rate-exploitation.md).

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blokčejnu:

- **Proof of Work (PoW)** oslanja se na računarsku snagu za proveru transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoin-a

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se proveravaju digitalnim potpisima, čime se osigurava da samo vlasnik privatnog ključa može da pokrene prenos.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature transakcije** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **ulaza** (izvor sredstava), **izlaza** (odredište), **naknada** (plaćenih rudarima) i **skripti** (pravila transakcije).

### Lightning Network

Cilj mu je da poboljša skalabilnost Bitcoin-a tako što omogućava više transakcija unutar kanala, a na blokčejn emituje samo konačno stanje.

## Problemi sa privatnošću Bitcoin-a

Napadi na privatnost, kao što su **pretpostavka o zajedničkom vlasništvu ulaza** i **otkrivanje adrese za kusur UTXO-a**, iskorišćavaju obrasce transakcija. Strategije kao što su **mikseri** i **CoinJoin** poboljšavaju anonimnost tako što prikrivaju veze između transakcija korisnika.

## Anonimno pribavljanje Bitcoin-a

Metode obuhvataju gotovinske transakcije, rudarenje i korišćenje miksera. **CoinJoin** meša više transakcija kako bi otežao njihovo praćenje, dok **PayJoin** prikazuje CoinJoin transakcije kao obične transakcije radi veće privatnosti.

# Sažetak napada na privatnost Bitcoin-a

U svetu Bitcoin-a privatnost transakcija i anonimnost korisnika često izazivaju zabrinutost. U nastavku je pojednostavljen pregled nekoliko uobičajenih metoda kojima napadači mogu da naruše privatnost Bitcoin-a.<sup>[[6]](#references)</sup>

## **Pretpostavka o zajedničkom vlasništvu ulaza**

Kombinovanje ulaza različitih korisnika u jednoj transakciji uglavnom je retko zbog složenosti. Zato se često pretpostavlja da **dve ulazne adrese u istoj transakciji pripadaju istom vlasniku**.

## **Otkrivanje adrese za kusur UTXO-a**

UTXO, odnosno **nepotrošeni izlaz transakcije**, mora se potrošiti u celosti u jednoj transakciji. Ako se samo deo pošalje na drugu adresu, ostatak se šalje na novu adresu za kusur. Posmatrači mogu pretpostaviti da ova nova adresa pripada pošiljaocu, čime se narušava privatnost.

### Primer

Da bi se to ublažilo, mogu se koristiti servisi za mešanje ili više adresa kako bi se prikrilo vlasništvo.

## **Izlaganje na društvenim mrežama i forumima**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, zbog čega je **lako povezati adresu sa njenim vlasnikom**.

## **Analiza grafa transakcija**

Transakcije se mogu prikazati kao grafovi, otkrivajući moguće veze između korisnika na osnovu toka sredstava.

## **Heuristika nepotrebnog ulaza (heuristika optimalnog kusura)**

Ova heuristika zasniva se na analizi transakcija sa više ulaza i izlaza kako bi se pogodilo koji izlaz predstavlja kusur vraćen pošiljaocu.

### Primer

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ako dodavanje većeg broja ulaza učini da je izlazna kusur-vrednost veća od bilo kog pojedinačnog ulaza, to može da zbuni heuristiku.

## **Prisilno ponovno korišćenje adresa**

Napadači mogu da pošalju male iznose na ranije korišćene adrese, nadajući se da će ih primalac kombinovati sa drugim ulazima u budućim transakcijama, čime se adrese povezuju.

### Ispravno ponašanje novčanika

Novčanici bi trebalo da izbegavaju korišćenje novčića primljenih na već korišćenim, praznim adresama kako bi sprečili ovo narušavanje privatnosti.

## **Druge tehnike analize blockchaina**

- **Tačni iznosi plaćanja:** Transakcije bez kusura verovatno se odvijaju između dve adrese u vlasništvu istog korisnika.
- **Zaokruženi iznosi:** Zaokružen iznos u transakciji nagoveštava da je reč o plaćanju, dok je izlaz sa nezaokruženim iznosom verovatno kusur.
- **Otisak novčanika:** Različiti novčanici imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da prepoznaju korišćeni softver i potencijalno adresu za kusur.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može omogućiti njihovo praćenje.

## **Analiza saobraćaja**

Praćenjem mrežnog saobraćaja, napadači mogu potencijalno da povežu transakcije ili blokove sa IP adresama, ugrožavajući privatnost korisnika. To naročito važi ako neki entitet upravlja velikim brojem Bitcoin čvorova, čime se povećava njegova mogućnost praćenja transakcija.

## Još informacija

Sveobuhvatan spisak napada na privatnost i odbrana od njih potražite na stranici [Bitcoin Privacy na Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini anonimnog pribavljanja bitcoina

- **Gotovinske transakcije**: Nabavka bitcoina gotovinom.
- **Alternative gotovini**: Kupovina poklon-kartica i njihova zamena za bitcoin na internetu.
- **Rudarenje**: Najprivatniji način zarađivanja bitcoina jeste rudarenje, naročito kada se obavlja samostalno, jer rudarski poolovi mogu da saznaju IP adresu rudara. [Informacije o rudarskim poolovima](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: Teoretski, krađa bitcoina mogla bi biti još jedan način anonimnog pribavljanja, iako je nezakonita i ne preporučuje se.

## Usluge mikсовања

Korišćenjem usluge miksovanja, korisnik može da **pošalje bitcoine** i zauzvrat primi **druge bitcoine**, zbog čega je teško ući u trag prvobitnom vlasniku. Međutim, za to je potrebno verovati da usluga neće čuvati dnevnike i da će zaista vratiti bitcoine. Alternativne opcije za miksovanje uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** objedinjuje više transakcija različitih korisnika u jednu, što otežava svakome ko pokušava da upari ulaze sa izlazima. Uprkos efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje se potencijalno mogu pratiti.

Primeri transakcija za koje je možda korišćen CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Više informacija potražite na stranici [CoinJoin](https://coinjoin.io/en). Informacije o mikseru za Ethereum pametne ugovore koji razdvaja depozite od kasnijih isplata potražite na stranici [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) tako da izgleda kao uobičajena transakcija, bez prepoznatljivih jednakih izlaza karakterističnih za CoinJoin. Zbog toga ga je izuzetno teško otkriti, a mogao bi i da učini nevažećom heuristiku zajedničkog vlasništva nad ulazima koju koriste subjekti za nadzor transakcija.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcije poput prethodne mogu biti PayJoin, čime se poboljšava privatnost, a pritom ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da oteža tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanjima da se zaštiti privatnost transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Da bi se očuvali privatnost i bezbednost, ključno je sinhronizovati novčanike sa blokčejnom. Izdvajaju se dva metoda:

- **Full node**: Preuzimanjem celog blokčejna, full node obezbeđuje maksimalnu privatnost. Sve transakcije ikada izvršene čuvaju se lokalno, pa protivnici ne mogu da utvrde koje transakcije ili adrese zanimaju korisnika.
- **Filtriranje blokova na strani klijenta**: Ovaj metod podrazumeva pravljenje filtera za svaki blok u blokčejnu, što novčanicima omogućava da prepoznaju relevantne transakcije, a da posmatračima mreže ne otkriju konkretna interesovanja. Laki novčanici preuzimaju te filtere i preuzimaju cele blokove samo kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin funkcioniše na peer-to-peer mreži, preporučuje se korišćenje Tor-a za prikrivanje IP adrese, čime se povećava privatnost pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Da biste zaštitili privatnost, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može da ugrozi privatnost povezivanjem transakcija sa istim entitetom. Savremeni novčanici su osmišljeni tako da obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Podela uplate na više transakcija može da prikrije iznos transakcije i osujeti napade na privatnost.
- **Izbegavanje kusura**: Odabir transakcija koje ne zahtevaju izlaze za kusur poboljšava privatnost tako što ometa metode za otkrivanje kusura.
- **Više izlaza za kusur**: Ako izbegavanje kusura nije izvodljivo, generisanje više izlaza za kusur i dalje može da poboljša privatnost.

# **Monero: svetionik anonimnosti**

Monero je osmišljen tako da daje prednost privatnosti transakcija.

# **Ethereum: Gas i transakcije**

## **Razumevanje Gas-a**

Gas meri količinu računarskog rada potrebnog za izvršavanje operacija na Ethereum-u, a cena mu se izražava u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) podrazumeva ograničenje za gas i osnovnu naknadu, uz prioritetnu naknadu kojom se podstiče validator da uključi transakciju. Korisnici mogu da postave maksimalnu naknadu kako bi izbegli preplaćivanje, a višak im se vraća.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili pametnih ugovora. Za njih je potrebna naknada i moraju biti uključene u blok. Osnovni podaci transakcije obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, ograničenje za gas i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, pa nema potrebe da bude navedena u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za svakoga ko želi da koristi kriptovalute, a pritom daje prednost privatnosti i bezbednosti.

## Red Teaming za Web3 usmeren na vrednost

- Popišite komponente koje upravljaju vrednošću (signeri, orakli, mostovi, automatizacija) da biste utvrdili ko može da premešta sredstva i na koji način.
- Povežite svaku komponentu sa relevantnim MITRE AADAPT taktikama kako biste otkrili putanje eskalacije privilegija.
- Uvežbajte lance napada koji uključuju flash loan, oracle, akreditive i cross-chain kako biste potvrdili uticaj i dokumentovali preduslove za iskorišćavanje.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje Web3 procesa potpisivanja

- Neovlašćene izmene u lancu snabdevanja wallet UI-ja mogu da izmene EIP-712 payload neposredno pre potpisivanja i prikupe važeće potpise za preuzimanje kontrole nad proxy-jem zasnovano na delegatecall-u (npr. prepisivanje slot-0 vrednosti Safe masterCopy-ja).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Apstrakcija naloga (ERC-4337)

- Uobičajeni načini otkaza smart account-a uključuju zaobilaženje kontrole pristupa `EntryPoint`-a, nepotpisana gas polja, validaciju sa stanjem, ERC-1271 replay i pražnjenje naknada putem revert-a nakon validacije.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost pametnih ugovora

- Mutation testing za otkrivanje slepih tačaka u skupovima testova:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet ZK dokaza / zkVM guest-a

Kada proveravač koristi **zkVM** ili aplikaciono specifično dokazno kolo da potvrdi tvrdnju, verifikator saznaje samo da je **guest program izvršen kako je napisan**. Ako guest sadrži **nebezbednu deserijalizaciju**, **nedefinisano ponašanje** ili **nedostajuća semantička ograničenja**, zlonamerni proveravač može da generiše dokaz koji prolazi verifikaciju, iako su **javni pokazatelji ili tvrđena invarijanta netačni**.<sup>[[7]](#references)</sup>

### Nebezbedna deserijalizacija unutar proof guest-a

- Tretirajte privatne witness/circuit bajtove kao **neproverene ulazne podatke napadača**, čak i ako su sakriveni dokazom.
- Izbegavajte njihovu deserijalizaciju pomoću neproverenih pomoćnih funkcija poput `rkyv::access_unchecked`, osim ako bajtovi nisu već provereni izvan ovog procesa.
- Enumeracione diskriminante, relativni pokazivači, dužine i indeksi učitani iz neproverenih serijalizovanih podataka moraju se proveriti pre nego što utiču na tok izvršavanja ili pristup memoriji.

Praktičan obrazac za audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ako je polje kao što je `op.kind` enum i napadač može da ubaci **discriminant van dozvoljenog opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table/UB-a

Ako Rust prevede veliki `match` u **jump table**, nevažeći enum discriminant može da dovede do **nedefinisanog toka kontrole**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van dozvoljenog opsega indeksira izvan prve jump table i izvršavanje nastavlja u kodu povezanom sa drugom.

Rezultat: operacija se ipak izvrši, ali se putanja za obračun preskače. U zkVM-u to može da omogući falsifikovanje dokaza koji prikazuju nemoguće metrike, kao što su manji broj gate-ova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum-e pod kontrolom napadača koji se deserijalizuju iz witness/private input-a.
- Pregledajte ponovljene `match` iskaze nad istim poljem opcode/kind.
- Tretirajte kombinaciju `unsafe` + deserijalizacija bez provera + velika opcode dispatch logika kao visokorizičnu.
- Po potrebi izvršite reverse engineering generisanog binarnog fajla; raspored jump table-a može da bude važniji od izvornog koda.

### Nedостајуća semantička ograničenja u reverzibilnim/specijalizovanim interpreter-ima

Nemojte proveravati samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba da sprovodi.

Kod reverzibilnih instrukcijskih skupova nalik kvantnim, uverite se da su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija nalik Toffoli/CCX implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>

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

Ovo stvara **deterministički primitiv za resetovanje**, narušava pretpostavke o reverzibilnosti i omogućava jeftinije, nenameravane proračune. U sistemima dokaza koji potvrđuju korišćenje resursa, ovo može omogućiti napadačima da prođu funkcionalne provere, a da zaobiđu model troškova za koji verifikator veruje da se sprovodi.

### Nedovoljno ograničeni saveti za dokazivača i modularna aritmetika

Vrednosti učitane sa steka za advice/witness pod kontrolom su dokazivača, čak i kada su opisane kao unapred izračunati količnici, ostaci, inverzi ili nagoveštaji. Dokaz samo potvrđuje da witness zadovoljava implementirana ograničenja; on ne potvrđuje da je izvršeno predviđeno izračunavanje ako ta ograničenja ne uključuju proveru tipa, opsega ili kanonskog oblika.<sup>[[13]](#references)</sup>

Kod pomoćne funkcije za redukciju ili deljenje sa ostatkom po Euklidovom algoritmu, proverite ceo celobrojni odnos, a ne samo završno oduzimanje ili množenje. Svaka cifra vrednosti `q` i `r` mora biti ograničena na svoju deklarisanu širinu, rekonstrukcija `x = q * m + r` mora da važi u predviđenoj celobrojnoj reprezentaciji, a kanonska granica `0 <= r < m` mora da se sprovodi. Proverite vrednost **pre** nego što je prosledite instrukciji užeg tipa `u32`/`u64`; operacija užeg tipa ne dokazuje retroaktivno da je originalni element polja ili vrednost sa više cifara imao očekivani tip.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

The `mod_12289` greška u Miden-u ilustruje obrazac eksploatacije: količnik je proveren kao 64-bitna vrednost od dva limb-a, ali ostatak dostavljen putem advice-a stigao je do `u32overflowing_sub` bez ekvivalentne validacije. Zlonamerni prover mogao je da uskladi nevažeće vrednosti količnika i ostatka tako da implementirana ograničenja oduzimanja i dalje važe, dok procedura vraća matematički neispravan ostatak. Pošto je ovaj rezultat korišćen u Falcon verifikaciji, greška u ispravnosti mogla je da se iskoristi za falsifikovanje potpisa za autorizaciju, umesto da samo proizvede pogrešan aritmetički rezultat.<sup>[[13]](#references)</sup>

### Revizija kriptografskih VM-ova sa implicitnim stekom

Jezici zasnovani na steku skrivaju operande, pa prvo podignite instrukcije u IR u kojem je svaka vrednost sa steka koja se troši ili proizvodi izraz sa poreklom. Konzervativni proces analize zatim može da:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Izgradi graf poziva i zaključi efekte procedura na ulazni i izlazni stek.
2. Simbolički izvršava podržane instrukcije i podigne tok kontrole u SSA/strukturirane izraze.
3. Propagira apstraktne činjenice kao što su `Unknown`, `ProvenU32`, `Bool`, poreklo vrednosti i lokalna inicijalizacija do fiksne tačke.
4. Označi vrednosti izvedene iz advice-a koje stižu do tipizovane aritmetike ili odredišta koja zahtevaju vrednost različitu od nule, a da prethodno nisu sanitizovane na **svakoj** dolaznoj putanji.
5. Uporedi deklarisane i izvedene potpise i proveri da li svaki izlaz čuva vrednosti na steku koje pripadaju pozivaocu.

Nepoznat potpis ili nepodržanu konstrukciju tretirajte kao **analitičku prazninu**, a ne kao čist rezultat. Dinamički pozivi, petlje koje ne čuvaju stek i grane sa različitim efektima na stek mogu onemogućiti pouzdano praćenje pozicija na steku; bezbedniji dekompajler odbacuje ili označava ove slučajeve umesto da emituje uverljiv, ali netačan pseudokod.<sup>[[10]](#references)[[13]](#references)</sup>

Na spojevima tokova kontrole zadržite svojstvo samo ako važi na svim prethodnim putanjama (na primer, `ProvenU32 join Unknown = Unknown`). Takođe razlikujte konvergenciju do fiksne tačke od dostizanja ograničenja broja iteracija: samo konvergirana, ispravna nadaproksimacija može da opravda tretiranje odsustva dijagnostičke poruke kao dokaza da sva predstavljena izvršavanja zadovoljavaju svojstvo.<sup>[[11]](#references)</sup>

### Koristite dokazne obaveze da biste otkrili skrivene preduslove

Za male skupove instrukcija prevedite procedure u izvršiv formalni VM model i dokažite i rezultat i kompletnu transformaciju steka. Teorema treba da obuhvati terminaciju, tipizovane ulaze, očekivani prefiks izlaza i očuvanje neizmenjenog steka pozivaoca. Pažljivo proverite iskaz teoreme jednako kao i dokaz: kernel može da validira dokaz tvrdnje koja je slučajno oslabljena.<sup>[[12]](#references)[[13]](#references)</sup>

Neočekivane pretpostavke su korisni nalazi. U Miden reviziji, dokaz za 64-bitnu rotaciju udesno zahtevao je `shift mod 32 != 0`, čime je otkriven slučaj greške za velike ulaze kada je pomeraj bio umnožak broja 32; drugi dokaz je otkrio da je 256-bitni `wrapping_mul` odbacivao vrednosti na steku koje pripadaju pozivaocu. Dodajte otkriveni granični slučaj u testove, a zatim ispravite implementaciju ili namerno pooštrite javni preduslov, umesto da neprimetno prihvatite dodatnu pretpostavku.<sup>[[12]](#references)[[13]](#references)</sup>

### Šta testirati u ZK sistemima

- Fuzz-ujte sve guest parsere neispravnim kodiranjima witness/private-input podataka.
- Proverite validaciju opsega enum vrednosti pre dispečovanja opcode-a.
- Dodajte semantičke provere za aliasing operanada i druge nevažeće oblike instrukcija.
- Pratite svaki izvor advice/witness podataka do svakog tipizovanog aritmetičkog odredišta i zahtevajte validaciju na svakoj putanji.<sup>[[11]](#references)[[13]](#references)</sup>
- Testirajte aritmetičke pomoćne funkcije sa nek kanonskim limb-ovima, ostacima van opsega i graničnim vrednostima pomeraja.<sup>[[12]](#references)[[13]](#references)</sup>
- Proverite visinu steka i očuvanje vrednosti ispod deklarisanih argumenata procedure pri svakom povratku.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan dokaz i dalje može dokazivati **pogrešnu tvrdnju** ako je guest program neispravan.

## Autorizacija zavisna od stanja

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacija DeFi/AMM sistema

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotrebu zaokruživanja/preciznosti, swap-ove koji prelaze prag uz pojačanje flash loan-om), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za pool-ove sa ponderisanim višestrukim sredstvima koji keširaju virtuelne bilanse i mogu biti zatrovani kada je `supply == 0`, proučite:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Dokaz o udelu - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Objašnjenje javnog i privatnog ključa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Šta su transakcije sa više potpisa? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcije | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i naknade | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privatnost - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Nadmašili smo Google-ov dokaz nultog znanja za kvantnu kriptoanalizu](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zaštita kriptovaluta zasnovanih na eliptičkim krivama od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits repozitorijum sa proof-of-concept kodom](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arhitektura MASM dekompajlera](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM mehanizam za statičku analizu](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean model i dokazi ispravnosti](https://github.com/trailofbits/masm-lean)
- [13] [Revizija u doba (dovoljno dobrog) AI-ja](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
