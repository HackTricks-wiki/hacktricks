# Blockchain i kriptovalute

## Osnovni koncepti

- **Pametni ugovori** su definisani kao programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi, automatizujući izvršavanje sporazuma bez posrednika.
- **Decentralizovane aplikacije (dApps)** nadograđuju se na pametne ugovore i imaju korisnički prijemčiv front-end i transparentan back-end koji se može proveriti.
- **Tokeni i novčići** razlikuju se po tome što novčići služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenim kontekstima.
- **Utility Tokeni** omogućavaju pristup uslugama, dok **Security Tokeni** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za Decentralizovane finansije i pruža finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAO** označavaju decentralizovane platforme za razmenu i decentralizovane autonomne organizacije.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** oslanja se na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju putem digitalnih potpisa, čime se obezbeđuje da samo vlasnik privatnog ključa može da pokrene transfere.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **ulaza** (izvor sredstava), **izlaza** (odredište), **naknada** (isplaćenih minerima) i **skripti** (pravila transakcije).

### Lightning Network

Cilj je poboljšanje skalabilnosti Bitcoina omogućavanjem više transakcija unutar kanala, pri čemu se blockchainu emituje samo konačno stanje.

## Problemi privatnosti Bitcoina

Privacy napadi, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost prikrivanjem veza između transakcija korisnika.

## Anonimno pribavljanje Bitcoina

Metode obuhvataju trgovinu za gotovinu, mining i korišćenje mixers. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikriva CoinJoin transakcije kao obične transakcije radi veće privatnosti.

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često predstavljaju razlog za zabrinutost. U nastavku je pojednostavljen pregled nekoliko uobičajenih metoda pomoću kojih napadači mogu da ugroze privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Uopšteno govoreći, retko se dešava da se ulazi različitih korisnika kombinuju u jednoj transakciji zbog složenosti takvog postupka. Zato se **dve ulazne adrese u istoj transakciji često smatraju adresama istog vlasnika**.

## **UTXO Change Address Detection**

UTXO, odnosno **Unspent Transaction Output**, mora u potpunosti da se potroši u transakciji. Ako se samo njegov deo pošalje na drugu adresu, ostatak se prosleđuje na novu change adresu. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se ugrožava privatnost.

### Primer

Da bi se ovo ublažilo, mixing servisi ili korišćenje više adresa mogu pomoći u prikrivanju vlasništva.

## **Social Networks & Forums Exposure**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, zbog čega je **lako povezati adresu sa njenim vlasnikom**.

## **Transaction Graph Analysis**

Transakcije se mogu vizuelizovati kao grafovi, otkrivajući potencijalne veze između korisnika na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika zasniva se na analizi transakcija sa više ulaza i izlaza kako bi se pretpostavilo koji izlaz predstavlja change koji se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje većeg broja inputa učini da change output bude veći od bilo kog pojedinačnog inputa, to može zbuniti heuristiku.

## **Forced Address Reuse**

Napadači mogu slati male iznose na prethodno korišćene adrese, nadajući se da će primalac u budućim transakcijama kombinovati te iznose sa drugim inputima i time povezati adrese.

### Ispravno ponašanje walleta

Walleti treba da izbegavaju korišćenje coinova primljenih na već korišćene, prazne adrese kako bi sprečili ovaj privacy leak.

## **Other Blockchain Analysis Techniques**

- **Tačni iznosi plaćanja:** Transakcije bez change-a verovatno se odvijaju između dve adrese u vlasništvu istog korisnika.
- **Zaokruženi brojevi:** Zaokružen iznos u transakciji ukazuje na to da je reč o plaćanju, dok je output koji nije zaokružen verovatno change.
- **Wallet Fingerprinting:** Različiti walleti imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni software i potencijalno change adresu.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije sledljivim.

## **Traffic Analysis**

Praćenjem mrežnog saobraćaja napadači potencijalno mogu povezati transakcije ili blokove sa IP adresama, čime ugrožavaju privacy korisnika. Ovo je naročito tačno ako entitet upravlja velikim brojem Bitcoin nodova, što poboljšava njegovu sposobnost praćenja transakcija.

## Više

Za sveobuhvatan spisak privacy napada i odbrana posetite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini za anonimno dobijanje Bitcoin-a

- **Cash transakcije**: Nabavka bitcoina korišćenjem gotovine.
- **Alternative za gotovinu**: Kupovina gift kartica i njihova online razmena za bitcoin.
- **Mining**: Najprivatniji način zarade bitcoina jeste mining, naročito kada se obavlja samostalno, jer mining pool-ovi mogu znati IP adresu minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: Teorijski, krađa bitcoina mogla bi biti još jedan način anonimnog sticanja bitcoina, iako je nezakonita i ne preporučuje se.

## Mixing Services

Korišćenjem mixing service-a korisnik može **poslati bitcoine** i zauzvrat primiti **drugačije bitcoine**, što otežava praćenje prvobitnog vlasnika. Ipak, ovo zahteva poverenje u service da neće čuvati logove i da će zaista vratiti bitcoine. Alternativne opcije za mixing uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** objedinjuje više transakcija različitih korisnika u jednu, čime komplikuje proces svima koji pokušavaju da povežu inpute sa outputima. Uprkos njegovoj efikasnosti, transakcije sa jedinstvenim veličinama inputa i outputa i dalje potencijalno mogu biti praćene.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija posetite [CoinJoin](https://coinjoin.io/en). Za Ethereum smart-contract mixer koji razdvaja depozite od kasnijih povlačenja pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) kao regularnu transakciju, bez karakterističnih jednakih outputa koji se javljaju kod CoinJoin-a. Zbog toga ga je izuzetno teško detektovati, a mogao bi učiniti nevažećom heuristiku vlasništva nad zajedničkim inputima koju koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije poput navedene mogle bi biti PayJoin, čime se poboljšava privatnost, a istovremeno ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da poremeti tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanju da se postigne privatnost transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije wallet-a**

Radi očuvanja privatnosti i bezbednosti, sinhronizacija wallet-a sa blockchain-om je ključna. Izdvajaju se dva metoda:

- **Full node**: Preuzimanjem celog blockchain-a, full node obezbeđuje maksimalnu privatnost. Sve ikada izvršene transakcije čuvaju se lokalno, zbog čega adversaries ne mogu da utvrde za koje transakcije ili adrese je korisnik zainteresovan.
- **Client-side block filtering**: Ovaj metod podrazumeva kreiranje filtera za svaki blok u blockchain-u, što wallet-ima omogućava da identifikuju relevantne transakcije bez otkrivanja konkretnih interesovanja posmatračima mreže. Lightweight wallet-i preuzimaju ove filtere i preuzimaju cele blokove samo kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin funkcioniše na peer-to-peer mreži, preporučuje se korišćenje Tor-a za maskiranje IP adrese, čime se poboljšava privatnost pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti, od ključne je važnosti koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Moderni wallet-i svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Multiple transactions**: Deljenje plaćanja na više transakcija može da prikrije iznos transakcije i osujeti privacy attacks.
- **Change avoidance**: Odabir transakcija koje ne zahtevaju change output poboljšava privatnost ometanjem metoda za detekciju change-a.
- **Multiple change outputs**: Ako izbegavanje change-a nije moguće, kreiranje više change output-a i dalje može poboljšati privatnost.

# **Monero: Svetionik anonimnosti**

Monero je dizajniran tako da daje prioritet privatnosti transakcija.

# **Ethereum: Gas i transakcije**

## **Razumevanje gas-a**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u i izražava se u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje gas limit i osnovnu naknadu, uz priority fee koji podstiče validator-e da je uključe. Korisnici mogu podesiti maksimalnu naknadu kako bi bili sigurni da neće platiti više nego što je potrebno, pri čemu se višak refundira.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract-a. One zahtevaju naknadu i moraju biti uključene u blok. Osnovne informacije u transakciji obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, gas limit i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, zbog čega nije potrebno navoditi je u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za svakoga ko želi da koristi kriptovalute uz davanje prioriteta privatnosti i bezbednosti.

## Red Teaming Web3-a usmeren na vrednost

- Napravite inventar komponenti koje sadrže vrednost (signers, oracles, bridges, automation) kako biste razumeli ko može da pomera sredstva i na koji način.
- Mapirajte svaku komponentu na relevantne MITRE AADAPT tactics kako biste otkrili puteve za privilege escalation.
- Uvežbajte flash-loan/oracle/credential/cross-chain attack chains kako biste potvrdili uticaj i dokumentovali preconditions koje je moguće iskoristiti.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje Web3 Signing Workflow-a

- Supply-chain tampering wallet UI-jeva može da izmeni EIP-712 payloads neposredno pre potpisivanja i prikuplja validne potpise za preuzimanja proxy-ja zasnovana na delegatecall-u (npr. prepisivanje slot-0 vrednosti Safe masterCopy-ja).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Uobičajeni načini otkaza smart account-a obuhvataju zaobilaženje kontrole pristupa `EntryPoint`-u, nepotpisana gas polja, stateful validation, ERC-1271 replay i fee-drain putem revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing za pronalaženje slepih tačaka u test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Kada proveravač koristi **zkVM** ili proof circuit specifičan za aplikaciju kako bi potvrdio neku tvrdnju, verifier saznaje samo da je **guest program izvršen onako kako je napisan**. Ako guest sadrži **unsafe deserialization**, **undefined behavior** ili **missing semantic constraints**, zlonamerni proveravač može generisati proof koji prolazi verifikaciju, dok su **javne metrike ili navedeni invariant netačni**.<sup>[[7]](#references)</sup>

### Unsafe deserialization unutar proof guest-ova

- Tretirajte private witness/circuit bytes kao **untrusted attacker input**, čak i ako su sakriveni proof-om.
- Izbegavajte njihovu deserializaciju pomoću unchecked helper-a kao što je `rkyv::access_unchecked`, osim ako bajtovi prethodno nisu validirani out-of-band.
- Enum discriminants, relative pointers, lengths i indexes učitani iz untrusted serialized data moraju biti validirani pre nego što utiču na control flow ili memory access.

Praktičan obrazac za audit:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Ako je polje kao što je `op.kind` enum i napadač može da ubaci **out-of-range discriminant**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Jump-table / UB counter bypass

Ako Rust prevede veliki `match` u **jump table**, nevažeći enum discriminant može izazvati **undefined control flow**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **security-critical counters/constraints**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Out-of-range discriminant indeksira memoriju iza prve jump table i izvršavanje se nastavlja u kodu povezanom sa drugom.

Rezultat: operacija se i dalje izvršava, ali se accounting putanja preskače. U zkVM-u ovo može omogućiti falsifikovanje proof-ova koji prijavljuju nemoguće metrike, kao što su manji broj gates, manji broj expensive operations ili drugi falsifikovani bounded resources.

Kontrolna lista za pregled:

- Potražite enum vrednosti pod kontrolom napadača koje se deserijalizuju iz witness/private input podataka.
- Proverite ponovljene `match` naredbe nad istim opcode/kind poljem.
- Tretirajte kombinaciju `unsafe` + unchecked deserialization + large opcode dispatch kao kombinaciju visokog rizika.
- Po potrebi izvršite reverse engineering emitovanog binary-ja; raspored jump table-a može biti važniji od izvornog koda.

### Missing semantic constraints in reversible/specialized interpreters

Nemojte proveravati samo memory safety; proverite i **semantic rules** koje proof treba da nametne.

Kod reversible/quantum-like instruction set-ova, proverite da li su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Toffoli/CCX-like operacija implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>
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
Ovo kreira **deterministic reset primitive**, čime se narušavaju pretpostavke reverzibilnosti i omogućavaju jeftinija nenameravana izračunavanja. U proof systems koji potvrđuju korišćenje resursa, ovo napadačima može omogućiti da ispune funkcionalne provere, zaobilazeći cost model za koji verifier veruje da se primenjuje.

### Šta testirati u ZK systems

- Fuzz sve guest parser-e sa neispravnim encoding-ima witness/private-input podataka.
- Potvrditi validaciju opsega enum vrednosti pre opcode dispatch-a.
- Dodati semantic provere za operand aliasing i druge nevažeće forme instrukcija.
- Uporediti prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da valid proof i dalje može dokazati **pogrešnu tvrdnju** ako je guest program neispravan.

## DeFi/AMM eksploatacija

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotreba zaokruživanja/preciznosti, flash-loan amplified threshold-crossing swaps), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za multi-asset weighted pools koji keširaju virtual balances i mogu biti poisoned kada je `supply == 0`, proučite:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Objašnjenje javnog i privatnog ključa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Šta su multi-signature transakcije? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcije | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i naknade | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privatnost - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Pobijedili smo Google-ov zero-knowledge proof kvantne kriptanalize](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Obezbeđivanje zaštite elliptic curve cryptocurrencies od kvantnih ranjivosti: procene resursa i mitigacije (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
