# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Pametni ugovori** su programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi, automatizujući izvršavanje sporazuma bez posrednika.
- **Decentralizovane aplikacije (dApps)** nadograđuju se na pametne ugovore i imaju korisnički prilagođen front-end i transparentan, proverljiv back-end.
- **Tokeni i novčići** razlikuju se po tome što novčići služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenim kontekstima.
  - **Utility tokeni** omogućavaju pristup uslugama, a **security tokeni** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za decentralizovane finansije koje nude finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAO** označavaju platforme za decentralizovanu razmenu i decentralizovane autonomne organizacije.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** oslanja se na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju digitalnim potpisima, čime se obezbeđuje da prenos može da pokrene samo vlasnik privatnog ključa.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature transakcije** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **ulaza** (izvor sredstava), **izlaza** (odredište), **naknada** (plaćenih rudarima) i **skripti** (pravila transakcije).

### Lightning Network

Cilj mu je da poboljša skalabilnost Bitcoina tako što omogućava više transakcija unutar kanala, a na blockchain emituje samo konačno stanje.

## Problemi sa privatnošću Bitcoina

Napadi na privatnost, kao što su **zajedničko vlasništvo nad ulazima** i **otkrivanje adrese za kusur UTXO-a**, iskorišćavaju obrasce transakcija. Strategije kao što su **mikseri** i **CoinJoin** poboljšavaju anonimnost tako što prikrivaju veze između transakcija korisnika.

## Anonimno sticanje bitcoina

Metode uključuju kupovinu i prodaju za gotovinu, rudarenje i korišćenje miksera. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikazuje CoinJoin transakcije kao obične transakcije radi veće privatnosti.

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često izazivaju zabrinutost. Sledi pojednostavljen pregled nekoliko uobičajenih metoda kojima napadači mogu da ugroze privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Pretpostavka o zajedničkom vlasništvu nad ulazima**

Uglavnom je neuobičajeno da se ulazi različitih korisnika kombinuju u jednoj transakciji zbog složenosti takvog postupka. Zbog toga se **često pretpostavlja da dve ulazne adrese u istoj transakciji pripadaju istom vlasniku**.

## **Otkrivanje adrese za kusur UTXO-a**

UTXO, odnosno **nepotrošeni izlaz transakcije**, mora se potrošiti u celosti u jednoj transakciji. Ako se samo deo pošalje na drugu adresu, ostatak se šalje na novu adresu za kusur. Posmatrači mogu pretpostaviti da ova nova adresa pripada pošiljaocu, čime se ugrožava privatnost.

### Primer

Da bi se to ublažilo, mogu se koristiti usluge mešanja ili više adresa kako bi se prikrilo vlasništvo.

## **Izlaganje na društvenim mrežama i forumima**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, zbog čega je **lako povezati adresu sa njenim vlasnikom**.

## **Analiza grafa transakcija**

Transakcije se mogu prikazati kao grafovi, otkrivajući moguće veze između korisnika na osnovu toka sredstava.

## **Heuristika nepotrebnog ulaza (heuristika optimalnog kusura)**

Ova heuristika zasniva se na analizi transakcija sa više ulaza i izlaza kako bi se procenilo koji izlaz predstavlja kusur vraćen pošiljaocu.

### Primer

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ako dodavanje novih ulaza učini izlaz kusura većim od bilo kog pojedinačnog ulaza, to može zbuniti heuristiku.

## **Prinudno ponovno korišćenje adresa**

Napadači mogu slati male iznose na ranije korišćene adrese, nadajući se da će ih primalac kombinovati sa drugim ulazima u budućim transakcijama i tako povezati adrese.

### Ispravno ponašanje novčanika

Novčanici treba da izbegavaju korišćenje novčića primljenih na već korišćene, prazne adrese kako bi sprečili ovo narušavanje privatnosti.

## **Druge tehnike analize blockchaina**

- **Tačni iznosi plaćanja:** Transakcije bez kusura verovatno se odvijaju između dve adrese koje pripadaju istom korisniku.
- **Zaokruženi iznosi:** Zaokružen iznos u transakciji ukazuje na to da je reč o plaćanju, dok je izlaz sa nezaokruženim iznosom verovatno kusur.
- **Otisci novčanika:** Različiti novčanici imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da prepoznaju korišćeni softver i potencijalno utvrde adresu za kusur.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može omogućiti njihovo praćenje.

## **Analiza saobraćaja**

Praćenjem mrežnog saobraćaja napadači mogu potencijalno da povežu transakcije ili blokove sa IP adresama, čime se ugrožava privatnost korisnika. To naročito važi ako neki entitet upravlja velikim brojem Bitcoin čvorova, što mu omogućava da efikasnije nadgleda transakcije.

## Još informacija

Sveobuhvatan spisak napada na privatnost i odbrana potražite na stranici [Privatnost Bitcoina na Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini za anonimno dobijanje bitcoina

- **Gotovinske transakcije**: Nabavka bitcoina gotovinom.
- **Alternative gotovini**: Kupovina poklon-kartica i njihova zamena za bitcoin na internetu.
- **Rudarenje**: Najprivatniji način za zaradu bitcoina jeste rudarenje, naročito ako se obavlja samostalno, jer rudarski pulovi mogu znati IP adresu rudara. [Informacije o rudarskim pulovima](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: Teoretski, krađa bitcoina može biti još jedan način anonimnog pribavljanja bitcoina, ali je nezakonita i ne preporučuje se.

## Servisi za mešanje

Korišćenjem servisa za mešanje, korisnik može **poslati bitcoine** i zauzvrat dobiti **druge bitcoine**, što otežava praćenje prvobitnog vlasnika. Ipak, to zahteva poverenje da servis ne čuva evidenciju i da će zaista vratiti bitcoine. Alternativne opcije za mešanje obuhvataju Bitcoin kazina.

## CoinJoin

**CoinJoin** objedinjuje više transakcija različitih korisnika u jednu, otežavajući svakome ko pokušava da poveže ulaze sa izlazima. Uprkos efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje se potencijalno mogu pratiti.

Primeri transakcija koje su možda koristile CoinJoin su `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Više informacija potražite na stranici [CoinJoin](https://coinjoin.io/en). Za Ethereum mikser zasnovan na pametnim ugovorima, koji razdvaja depozite od kasnijih isplata, pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) tako da izgleda kao obična transakcija, bez karakterističnih jednakih izlaza koje koristi CoinJoin. Zbog toga ju je izuzetno teško otkriti, a mogla bi i da učini nevažećom heuristiku zajedničkog vlasništva nad ulazima koju koriste subjekti za nadzor transakcija.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcije poput prethodno navedene mogu biti PayJoin, čime se poboljšava privatnost, a one i dalje ostaju nerazlučive od standardnih Bitcoin transakcija.

**Korišćenje PayJoin-a može značajno da omete tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanju da se postigne privatnost transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Da bi se očuvali privatnost i bezbednost, ključno je sinhronizovati novčanike sa blockchain-om. Izdvajaju se dve metode:

- **Full node**: Preuzimanjem celog blockchain-a, full node obezbeđuje maksimalnu privatnost. Sve transakcije koje su ikada obavljene čuvaju se lokalno, pa protivnici ne mogu da utvrde koje transakcije ili adrese zanimaju korisnika.
- **Filtriranje blokova na strani klijenta**: Ova metoda podrazumeva kreiranje filtera za svaki blok u blockchain-u, što novčanicima omogućava da prepoznaju relevantne transakcije bez otkrivanja konkretnih interesovanja posmatračima mreže. Laki novčanici preuzimaju ove filtere i preuzimaju cele blokove samo kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin funkcioniše preko peer-to-peer mreže, preporučuje se korišćenje Tor-a za prikrivanje IP adrese, čime se poboljšava privatnost pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može da ugrozi privatnost tako što povezuje transakcije sa istim entitetom. Savremeni novčanici svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Podela plaćanja na nekoliko transakcija može da zamagli iznos transakcije i osujeti napade na privatnost.
- **Izbegavanje kusura**: Izbor transakcija koje ne zahtevaju izlaze za kusur poboljšava privatnost tako što remeti metode za otkrivanje kusura.
- **Više izlaza za kusur**: Ako izbegavanje kusura nije izvodljivo, kreiranje više izlaza za kusur i dalje može da poboljša privatnost.

# **Monero: Svetionik anonimnosti**

Monero je osmišljen tako da privatnost transakcija bude na prvom mestu.

# **Ethereum: Gas i transakcije**

## **Razumevanje gas-a**

Gas meri količinu računarskog rada potrebnu za izvršavanje operacija na Ethereum-u, a cena mu se izražava u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) podrazumeva gas limit i osnovnu naknadu, uz prioritetnu naknadu koja podstiče validatora da uključi transakciju. Korisnici mogu da postave maksimalnu naknadu kako bi osigurali da ne plate previše, a višak se vraća.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili pametnih ugovora. Za njih je potrebna naknada i moraju biti uključene u blok. Osnovni podaci transakcije obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, gas limit i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, pa je nije potrebno uključiti u podatke transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za sve koji žele da koriste kriptovalute, a da pritom daju prednost privatnosti i bezbednosti.

## Red Teaming Web3 sistema usmeren na vrednost

- Napravite popis komponenti koje sadrže vrednost (potpisnici, orakuli, mostovi, automatizacija) da biste razumeli ko može da premešta sredstva i na koji način.
- Povežite svaku komponentu sa relevantnim MITRE AADAPT taktikama kako biste otkrili puteve eskalacije privilegija.
- Uvežbajte lance napada koji uključuju flash-loan/oracle/credential/cross-chain kako biste potvrdili uticaj i dokumentovali preduslove za eksploataciju.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje procesa potpisivanja u Web3

- Neovlašćene izmene u lancu snabdevanja novčanika mogu da izmenе EIP-712 payload-e neposredno pre potpisivanja i pribave važeće potpise za preuzimanje kontrole nad proxy-jem zasnovano na delegatecall-u (npr. prepisivanje slot-0 vrednosti Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Apstrakcija naloga (ERC-4337)

- Uobičajeni načini otkaza pametnih naloga obuhvataju zaobilaženje kontrole pristupa `EntryPoint`, nepotpisana gas polja, validaciju sa stanjem, ERC-1271 replay i iscrpljivanje naknada usled revert-a nakon validacije.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost pametnih ugovora

- Mutaciono testiranje radi pronalaženja slepih tačaka u skupovima testova:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet ZK dokaza / zkVM guest programa

Kada proveravalac koristi **zkVM** ili namenski dokazni sklop aplikacije da potvrdi neku tvrdnju, saznaje samo da je **guest program izvršen onako kako je napisan**. Ako guest sadrži **nebezbednu deserializaciju**, **nedefinisano ponašanje** ili **nedostajuća semantička ograničenja**, zlonamerni dokazivač može da generiše dokaz koji prolazi proveru, iako su **javno prikazane metrike ili navedena invarijanta netačne**.<sup>[[7]](#references)</sup>

### Nebezbedna deserializacija unutar proof guest programa

- Tretirajte privatne witness/circuit bajtove kao **neproverene ulazne podatke napadača**, čak i ako su skriveni dokazom.
- Izbegavajte njihovu deserializaciju neproverenim pomoćnim funkcijama kao što je `rkyv::access_unchecked`, osim ako bajtovi već nisu validirani van ovog postupka.
- Enumeracione diskriminante, relativne pokazivače, dužine i indekse učitane iz neproverenih serijalizovanih podataka treba validirati pre nego što utiču na tok kontrole ili pristup memoriji.

Praktični obrazac za audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ako je polje kao što je `op.kind` enum i napadač može da ubaci **discriminant van dozvoljenog opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table-a / UB-a

Ako Rust prevede veliki `match` u **jump table**, nevažeći enum discriminant može da dovede do **nedefinisanog toka kontrole**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van dozvoljenog opsega indeksira izvan prve jump table i stiže do koda povezanog sa drugom.

Rezultat: operacija se i dalje izvršava, ali se putanja obračunavanja preskače. U zkVM-u to može da omogući falsifikovanje dokaza koji prikazuju nemoguće metrike, kao što su manji broj gate-ova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum vrednosti pod kontrolom napadača koje se deserijalizuju iz witness/private input-a.
- Pregledajte ponovljene `match` iskaze nad istim poljem opcode/kind.
- Tretirajte kombinaciju `unsafe` + neproverena deserializacija + velika opcode dispatch logika kao visokorizičnu.
- Po potrebi izvršite reverzni inženjering generisanog binarnog fajla; raspored jump table-a može biti važniji od izvornog koda.

### Nedostajuća semantička ograničenja u reverzibilnim/specijalizovanim interpreterima

Nemojte proveravati samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba da nametne.

Kod reverzibilnih/skupu kvantnih instrukcija sličnih instrukcija, proverite da li su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija slična Toffoli/CCX, implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

postaje nebezbedno ako gost ne odbije:

```text
op.q_control1 == op.q_control2 == op.q_target
```

U tom slučaju, tranzicija se svodi na:

```text
q = q ^ (q & q) = 0
```

Ovo stvara **deterministički primitiv za resetovanje**, narušava pretpostavke o reverzibilnosti i omogućava jeftinija, nenameravana izračunavanja. U sistemima za dokazivanje koji potvrđuju korišćenje resursa, ovo napadačima može omogućiti da prođu funkcionalne provere, a da zaobiđu model troškova za koji verifikator veruje da se primenjuje.

### Šta testirati u ZK sistemima

- Fuzz-ujte sve guest parsere neispravno formatiranim kodiranjima witness/private-input podataka.
- Proverite validaciju opsega enum-a pre opcode dispatch-a.
- Dodajte semantičke provere za aliasing operanada i druge nevažeće oblike instrukcija.
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan dokaz i dalje može dokazivati **pogrešnu tvrdnju** ako je guest program neispravan.

## Autorizacija zavisna od stanja

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacija DeFi/AMM sistema

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotrebu zaokruživanja/preciznosti, swapove sa pragom koji se prelazi uz pomoć flash-loana), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za ponderisane pool-ove sa više sredstava koji keširaju virtuelne salde i mogu biti zatrovani kada je `supply == 0`, proučite:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Dokaz o udelu - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Javni i privatni ključ — objašnjenje - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Šta su transakcije sa više potpisa? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcije | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i naknade | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privatnost - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Nadmašili smo Google-ov dokaz kvantne kriptoanalize sa nultim znanjem](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zaštita kriptovaluta zasnovanih na eliptičkim krivama od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits repozitorijum sa proof-of-concept kodom](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
