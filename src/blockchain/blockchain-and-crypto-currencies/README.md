# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Pametni ugovori** su programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi i automatizuju izvršavanje sporazuma bez posrednika.
- **Decentralizovane aplikacije (dApps)** zasnivaju se na pametnim ugovorima i imaju korisnički prilagođen front-end i transparentan, proverljiv back-end.
- **Tokeni i novčići** razlikuju se po tome što novčići služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenom kontekstu.
  - **Utility tokeni** omogućavaju pristup uslugama, a **security tokeni** predstavljaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za decentralizovane finansije i obuhvata finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAO** označavaju platforme za decentralizovanu razmenu i decentralizovane autonomne organizacije.

Za terminologiju koja se koristi na kripto tržištima za spot naloge, fjučerse, polugu i opcije, pogledajte [Investment Terms](investment-terms.md).

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** se oslanja na računarsku snagu za proveru transakcija.
- **Proof of Stake (PoS)** zahteva da validatori poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije obuhvataju prenos sredstava između adresa. Transakcije se proveravaju digitalnim potpisima, čime se obezbeđuje da prenos može da pokrene samo vlasnik privatnog ključa.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Transakcije sa više potpisa** zahtevaju više potpisa za odobrenje transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **ulaza** (izvor sredstava), **izlaza** (odredište), **naknada** (plaćenih rudarima) i **skripti** (pravila transakcije).

### Lightning Network

Cilj mu je da poboljša skalabilnost Bitcoina tako što omogućava više transakcija unutar kanala, a na blockchain objavljuje samo konačno stanje.

## Problemi sa privatnošću Bitcoina

Napadi na privatnost, kao što su **pretpostavka o zajedničkom vlasništvu nad ulazima** i **otkrivanje adrese za kusur UTXO-a**, iskorišćavaju obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost tako što prikrivaju veze između transakcija korisnika.

## Anonimno sticanje Bitcoina

Metode obuhvataju trgovinu za gotovinu, rudarenje i korišćenje miksera. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikazuje CoinJoin transakcije kao obične transakcije radi veće privatnosti.

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmet zabrinutosti. Sledi pojednostavljen pregled nekoliko uobičajenih metoda pomoću kojih napadači mogu da naruše privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Pretpostavka o zajedničkom vlasništvu nad ulazima**

Kombinovanje ulaza različitih korisnika u jednoj transakciji uglavnom je retko zbog složenosti postupka. Zato se često pretpostavlja da **dve ulazne adrese u istoj transakciji pripadaju istom vlasniku**.

## **Otkrivanje adrese za kusur UTXO-a**

UTXO, odnosno **nepotrošeni izlaz transakcije**, mora se potrošiti u celosti u jednoj transakciji. Ako se samo deo pošalje na drugu adresu, ostatak se šalje na novu adresu za kusur. Posmatrači mogu da pretpostave da ta nova adresa pripada pošiljaocu, čime se narušava njegova privatnost.

### Primer

Da bi se to ublažilo, mogu se koristiti usluge mešanja ili više adresa radi prikrivanja vlasništva.

## **Izlaganje na društvenim mrežama i forumima**

Korisnici ponekad objavljuju svoje Bitcoin adrese na internetu, zbog čega je **lako povezati adresu sa njenim vlasnikom**.

## **Analiza grafa transakcija**

Transakcije se mogu prikazati kao grafovi, čime se otkrivaju moguće veze između korisnika na osnovu toka sredstava.

## **Heuristika nepotrebnog ulaza (heuristika optimalnog kusura)**

Ova heuristika se zasniva na analizi transakcija sa više ulaza i izlaza kako bi se pogodilo koji izlaz predstavlja kusur koji se vraća pošiljaocu.

### Primer

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ako dodavanje većeg broja ulaza učini izlaz za kusur većim od bilo kog pojedinačnog ulaza, to može zbuniti heuristiku.

## **Prisilna ponovna upotreba adresa**

Napadači mogu slati male iznose na ranije korišćene adrese, nadajući se da će primalac u budućim transakcijama kombinovati te iznose sa drugim ulazima i tako povezati adrese.

### Ispravno ponašanje novčanika

Novčanici bi trebalo da izbegavaju korišćenje novčića primljenih na već korišćene, prazne adrese kako bi sprečili ovaj leak privatnosti.

## **Druge tehnike analize blockchain-a**

- **Tačni iznosi plaćanja:** Transakcije bez kusura verovatno se odvijaju između dve adrese u vlasništvu istog korisnika.
- **Zaokruženi iznosi:** Zaokružen iznos u transakciji ukazuje na to da je reč o plaćanju, dok je izlaz sa nezaokruženim iznosom verovatno kusur.
- **Otisci novčanika:** Različiti novčanici imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da utvrde koji je softver korišćen i potencijalno prepoznaju adresu za kusur.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može omogućiti njihovo praćenje.

## **Analiza saobraćaja**

Praćenjem mrežnog saobraćaja napadači potencijalno mogu da povežu transakcije ili blokove sa IP adresama, čime ugrožavaju privatnost korisnika. To naročito važi ako neki entitet upravlja velikim brojem Bitcoin čvorova, što mu omogućava da efikasnije prati transakcije.

## Više informacija

Sveobuhvatan spisak napada na privatnost i odbrana od njih potražite na stranici [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini anonimnog dobijanja bitcoina

- **Gotovinske transakcije**: Dobijanje bitcoina gotovinom.
- **Alternative za gotovinu**: Kupovina poklon-kartica i njihova zamena za bitcoin na mreži.
- **Rudarenje**: Najprivatniji način zarade bitcoina jeste rudarenje, naročito ako se obavlja samostalno, jer rudarski pulovi mogu saznati IP adresu rudara. [Informacije o rudarskim pulovima](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: Teoretski, krađa bitcoina mogla bi biti još jedan način da se on anonimno pribavi, ali je to nezakonito i ne preporučuje se.

## Usluge mešanja

Korišćenjem usluge mešanja, korisnik može da **pošalje bitcoine** i zauzvrat dobije **druge bitcoine**, zbog čega je teško pratiti prvobitnog vlasnika. Međutim, to zahteva poverenje u uslugu — da neće čuvati logove i da će zaista vratiti bitcoine. Alternativne opcije za mešanje uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** objedinjuje više transakcija različitih korisnika u jednu, što otežava povezivanje ulaza sa izlazima. Uprkos efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje se potencijalno mogu pratiti.

Primeri transakcija za koje je možda korišćen CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Više informacija potražite na stranici [CoinJoin](https://coinjoin.io/en). Za Ethereum mikser zasnovan na pametnim ugovorima, koji razdvaja depozite od kasnijih isplata, pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) tako da izgleda kao obična transakcija, bez karakterističnih izlaza jednakih iznosa koji se javljaju kod CoinJoin-a. Zbog toga ju je izuzetno teško otkriti, a mogla bi da učini nevažećom heuristiku zajedničkog vlasništva nad ulazima koju koriste akteri za nadzor transakcija.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcije poput prethodne mogle bi biti PayJoin, čime se poboljšava privatnost, a transakcije ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da omete tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u težnji ka privatnosti transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Da bi se očuvali privatnost i bezbednost, ključno je sinhronizovati novčanike sa blokčejnom. Izdvajaju se dva načina:

- **Full node**: Preuzimanjem celog blokčejna, full node obezbeđuje maksimalnu privatnost. Sve ikada obavljene transakcije čuvaju se lokalno, pa protivnici ne mogu da utvrde koje transakcije ili adrese korisnika zanimaju.
- **Filtriranje blokova na strani klijenta**: Ovaj način podrazumeva kreiranje filtera za svaki blok u blokčejnu, što novčanicima omogućava da prepoznaju relevantne transakcije bez otkrivanja konkretnih interesovanja posmatračima mreže. Laki novčanici preuzimaju ove filtere i preuzimaju cele blokove samo kada se pronađe poklapanje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Budući da Bitcoin funkcioniše na peer-to-peer mreži, preporučuje se korišćenje Tor-a za maskiranje IP adrese, čime se poboljšava privatnost pri povezivanju sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Da bi se zaštitila privatnost, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može da ugrozi privatnost povezivanjem transakcija sa istim entitetom. Savremeni novčanici svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Podela uplate na nekoliko transakcija može da prikrije iznos transakcije i osujeti napade na privatnost.
- **Izbegavanje kusura**: Izbor transakcija kojima nisu potrebni izlazi za kusur poboljšava privatnost tako što ometa metode za otkrivanje kusura.
- **Više izlaza za kusur**: Ako izbegavanje kusura nije izvodljivo, kreiranje više izlaza za kusur i dalje može da poboljša privatnost.

# **Monero: svetionik anonimnosti**

Monero je osmišljen tako da daje prioritet privatnosti transakcija.

# **Ethereum: gas i transakcije**

## **Razumevanje gasa**

Gas meri računarski rad potreban za izvršavanje operacija na Ethereum-u, a cena mu se izražava u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje ograničenje gasa i osnovnu naknadu, uz prioritetnu naknadu kojom se podstiče validator da je uključi. Korisnici mogu da podese maksimalnu naknadu kako bi izbegli preplaćivanje, a višak se vraća.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u obuhvataju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili pametnih ugovora. Za njih je potrebna naknada i moraju biti uključene u blok. Osnovni podaci transakcije obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, ograničenje gasa i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, pa nema potrebe da se navodi u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za sve koji žele da koriste kriptovalute uz davanje prioriteta privatnosti i bezbednosti.

## Web3 Red Teaming usmeren na vrednost

- Napravite popis komponenti koje raspolažu vrednošću (potpisnici, oracles, mostovi, automatizacija) da biste razumeli ko može da premešta sredstva i kako.
- Povežite svaku komponentu sa relevantnim MITRE AADAPT taktikama da biste otkrili putanje eskalacije privilegija.
- Uvežbavajte lance napada koji uključuju flash-loan/oracle/credential/cross-chain kako biste proverili uticaj i dokumentovali preduslove za eksploataciju.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje Web3 potpisnog toka rada

- Manipulisanje lancem snabdevanja korisničkih interfejsa novčanika može da izmeni EIP-712 payload-e neposredno pre potpisivanja i pribavi važeće potpise za preuzimanje proxy-ja zasnovano na delegatecall-u (npr. prepisivanje slot-0 polja Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Apstrakcija naloga (ERC-4337)

- Uobičajeni načini otkaza pametnih naloga obuhvataju zaobilaženje kontrole pristupa `EntryPoint`, nepotpisana gas polja, stateful validaciju, ERC-1271 replay i iscrpljivanje naknada putem revert-a nakon validacije.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost pametnih ugovora

- Mutation testing za pronalaženje slepih tačaka u testnim paketima:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet ZK dokaza / zkVM guest-a

Kada proverivač koristi **zkVM** ili aplikaciono specifično kolo za dokazivanje tvrdnje, on saznaje samo da je **guest program izvršen kako je napisan**. Ako guest sadrži **nebezbednu deserijalizaciju**, **nedefinisano ponašanje** ili **nedostajuća semantička ograničenja**, zlonamerni proverivač može da generiše dokaz koji prolazi proveru, iako su **javni pokazatelji ili navedena invarijanta netačni**.<sup>[[7]](#references)</sup>

### Nebezbedna deserijalizacija unutar proof guest-ova

- Tretirajte bajtove privatnog witness-a/kola kao **nepoverljiv ulaz napadača**, čak i ako ih dokaz skriva.
- Izbegavajte njihovu deserijalizaciju pomoću neproverenih pomoćnih funkcija kao što je `rkyv::access_unchecked`, osim ako su bajtovi prethodno validirani drugim putem.
- Diskriminante enum-a, relativni pokazivači, dužine i indeksi učitani iz nepoverljivih serijalizovanih podataka moraju se validirati pre nego što utiču na tok izvršavanja ili pristup memoriji.

Praktični obrazac za reviziju:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ako je polje poput `op.kind` enum i napadač može da ubaci **discriminant van dozvoljenog opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table / UB

Ako Rust prevede veliki `match` u **jump table**, nevažeći enum discriminant može da dovede do **nedefinisanog toka kontrole**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van dozvoljenog opsega indeksira memoriju iza prve jump table i dospeva u kod povezan sa drugom.

Rezultat: operacija se i dalje izvršava, ali se putanja za obračun preskače. U zkVM-u to može da omogući falsifikovanje dokaza koji prikazuju nemoguće metrike, kao što su manji broj gate-ova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum vrednosti pod kontrolom napadača koje se deserijalizuju iz witness/privatnog ulaza.
- Pregledajte ponovljene `match` iskaze nad istim poljem opcode/kind.
- Tretirajte kombinaciju `unsafe` + deserijalizacije bez provera + velike opcode dispečerske logike kao visokorizičnu.
- Po potrebi izvršite reverzni inženjering generisanog binarnog fajla; raspored jump table-a može biti važniji od izvornog koda.

### Nedostajuća semantička ograničenja u reverzibilnim/specijalizovanim interpreterima

Ne proveravajte samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba да спроведе.

Kod reverzibilnih/instrukcijskih skupova nalik kvantnim, proverite da li su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija nalik Toffoli/CCX implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>

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

Ovo stvara **deterministički primitiv za resetovanje**, narušavajući pretpostavke o reverzibilnosti i omogućavajući jeftinija, nenameravana izračunavanja. U sistemima za dokazivanje koji potvrđuju potrošnju resursa, napadači mogu time da zadovolje funkcionalne provere, a da zaobiđu model troškova za koji verifikator veruje da se primenjuje.

### Nedovoljno ograničeni saveti dokazivača i modularna aritmetika

Vrednosti učitane sa steka saveta/svedoka su **pod kontrolom dokazivača**, čak i kada su opisane kao unapred izračunati količnici, ostaci, inverzi ili nagoveštaji. Dokaz samo potvrđuje da svedok zadovoljava implementirana ograničenja; ne potvrđuje da je izvršeno predviđeno izračunavanje ako ta ograničenja ne obuhvataju proveru tipa, opsega ili kanonskog oblika.<sup>[[13]](#references)</sup>

Prilikom revizije pomoćne funkcije za redukciju ili Euklidsko deljenje, proverite celokupnu celobrojnu relaciju, a ne samo završno oduzimanje ili množenje. Svaki limb vrednosti `q` i `r` mora biti ograničen na deklarisanu širinu, rekonstrukcija `x = q * m + r` mora da važi u predviđenoj celobrojnoj reprezentaciji, a kanonska granica `0 <= r < m` mora biti nametnuta. Proverite vrednost **pre** prosleđivanja instrukciji užeg tipa `u32`/`u64`; operacija užeg tipa ne dokazuje naknadno da je prvobitni element polja ili višelimbska vrednost imala očekivani tip.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Neuspeh `mod_12289` u Miden-u ilustruje obrazac eksploatacije: količnik je proveren kao 64-bitna vrednost od dva limb-a, ali ostatak dostavljen kroz advice prosleđen je funkciji `u32overflowing_sub` bez ekvivalentne validacije. Zlonamerni proverivač mogao je da uskladi neispravne vrednosti količnika i ostatka tako da implementirana ograničenja oduzimanja i dalje važe, dok procedura vraća matematički neispravan ostatak. Pošto se ovaj rezultat koristio u Falcon verifikaciji, propust u soundness-u mogao je da se eskalira u falsifikovane potpise za autorizaciju, umesto da samo proizvede pogrešan aritmetički rezultat.<sup>[[13]](#references)</sup>

### Revizija implicitnih stek kriptografskih VM-ova

Stek jezici skrivaju operande, zato najpre podignite instrukcije u IR u kojem je svaka potrošena i proizvedena vrednost steka izraz sa poreklom. Konzervativni proces analize zatim može da:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Napravi graf poziva i zaključi efekte procedura na ulazni i izlazni stek.
2. Simbolički izvršava podržane instrukcije i podiže kontrolni tok u SSA/strukturirane izraze.
3. Prenosi apstraktne činjenice, kao što su `Unknown`, `ProvenU32`, `Bool`, poreklo vrednosti i lokalna inicijalizacija, sve do dostizanja fiksne tačke.
4. Označi vrednosti izvedene iz advice-a koje dospeju do tipizovane aritmetike ili odredišta koje zahteva vrednost različitu od nule, a da pritom nisu sanirane na **svakoj** ulaznoj putanji.
5. Uporedi deklarisane i izvedene potpise i proveri da li svaki izlaz čuva vrednosti steka koje pripadaju pozivaocu.

Nepoznat potpis ili nepodržanu konstrukciju tretirajte kao **prazninu u analizi**, a ne kao čist rezultat. Dinamički pozivi, petlje koje ne čuvaju stek i grananja sa različitim efektima na stek mogu onemogućiti pouzdano praćenje stek slotova; bezbedniji dekompajler odbacuje ili označava ove slučajeve umesto da emituje uverljiv, ali netačan pseudokod.<sup>[[10]](#references)[[13]](#references)</sup>

Na spojevima kontrolnog toka zadržite svojstvo samo ako važi za svakog prethodnika (na primer, `ProvenU32 join Unknown = Unknown`). Takođe razlikujte konvergenciju do fiksne tačke od dostizanja ograničenja broja iteracija: samo konvergirana, zvučno preterana aproksimacija može opravdati da se odsustvo dijagnostičke poruke tretira kao dokaz da sva predstavljena izvršavanja zadovoljavaju svojstvo.<sup>[[11]](#references)</sup>

### Koristite obaveze dokazivanja da biste otkrili skrivene preduslove

Za male skupove instrukcija prevedite procedure u izvršiv formalni VM model i dokažite i rezultat i kompletnu transformaciju steka. Teorema treba da obuhvati terminaciju, tipizovane ulaze, očekivani prefiks izlaza i očuvanje neizmenjenog steka pozivaoca. Pažljivo proverite iskaz teoreme koliko i sam dokaz: kernel može da validira dokaz slučajno oslabljene tvrdnje.<sup>[[12]](#references)[[13]](#references)</sup>

Neočekivane hipoteze su korisna otkrića. U Miden reviziji, dokaz rotacije udesno za 64-bitnu vrednost zahtevao je `shift mod 32 != 0`, čime je otkriven neispravan granični slučaj za velike ulaze kada je pomeraj bio umnožak broja 32; drugi dokaz je otkrio da `wrapping_mul` za 256-bitne vrednosti odbacuje vrednosti steka koje pripadaju pozivaocu. Dodajte otkriveni granični slučaj u testove, a zatim ispravite implementaciju ili namerno pooštrite javni preduslov, umesto da neprimetno prihvatite dodatnu pretpostavku.<sup>[[12]](#references)[[13]](#references)</sup>

### Šta testirati u ZK sistemima

- Fuzz-ujte sve guest parser-e neispravnim kodiranjima witness-a/privatnih ulaza.
- Proverite validaciju opsega enum-a pre dispečovanja opcode-a.
- Dodajte semantičke provere za aliasing operanada i druge neispravne oblike instrukcija.
- Pratite svaki izvor advice/witness vrednosti do svakog tipizovanog aritmetičkog odredišta i zahtevajte validaciju na svakoj putanji.<sup>[[11]](#references)[[13]](#references)</sup>
- Testirajte aritmetičke pomoćne funkcije sa nekanonskim limb-ovima, ostacima van opsega i graničnim vrednostima pomeraja.<sup>[[12]](#references)[[13]](#references)</sup>
- Proverite visinu steka i očuvanje vrednosti ispod deklarisanih argumenata procedure pri svakom povratku.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan dokaz i dalje može da dokaže **pogrešnu tvrdnju** ako je guest program neispravan.

## Autorizacija zavisna od stanja

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM eksploatacija

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotrebu zaokruživanja/preciznosti, swap-ove sa pozajmicom flash loan koji pojačavaju prelazak praga), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za ponderisane pulove sa više sredstava koji keširaju virtuelna stanja i mogu biti zatrovani kada je `supply == 0`, proučite:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Dokaz udela - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Objašnjenje javnog i privatnog ključa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Šta su transakcije sa više potpisa? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcije | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i naknade | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privatnost - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Pobijedili smo Google-ov dokaz kvantne kriptoanalize sa nultim znanjem](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zaštita kriptovaluta zasnovanih na eliptičkim krivama od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits repozitorijum sa proof-of-concept kodom](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arhitektura MASM dekompajlera](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM mehanizam za statičku analizu](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean model i dokazi ispravnosti](https://github.com/trailofbits/masm-lean)
- [13] [Revizija u dobu (dovoljno dobre) veštačke inteligencije](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
