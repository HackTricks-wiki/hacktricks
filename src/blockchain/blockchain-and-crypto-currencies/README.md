# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni koncepti

- **Smart Contracts** su definisani kao programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi, automatizujući izvršavanje sporazuma bez posrednika.
- **Decentralized Applications (dApps)** se zasnivaju na smart contracts, sa korisnički prijemčivim front-endom i transparentnim back-endom koji se može auditovati.
- **Tokens & Coins** razlikuju se po tome što coins služe kao digitalni novac, dok tokens predstavljaju vrednost ili vlasništvo u određenim kontekstima.
- **Utility Tokens** omogućavaju pristup uslugama, dok **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za Decentralized Finance i pruža finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** označavaju Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju sigurne i usaglašene validacije transakcija na blockchainu:

- **Proof of Work (PoW)** oslanja se na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju putem digitalnih potpisa, čime se obezbeđuje da samo vlasnik privatnog ključa može da pokrene transfere.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (odredište), **fees** (naknade plaćene minerima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj mu je poboljšanje skalabilnosti Bitcoina omogućavanjem više transakcija unutar kanala, pri čemu se blockchainu emituje samo konačno stanje.

## Problemi privatnosti Bitcoina

Privacy attacks, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije kao što su **Mixers** i **CoinJoin** poboljšavaju anonimnost prikrivanjem veza između transakcija korisnika.

## Anonimno pribavljanje Bitcoina

Metode obuhvataju trgovinu za gotovinu, mining i korišćenje mixers. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikriva CoinJoins kao obične transakcije radi veće privatnosti.

# Sažetak privacy attacks na Bitcoin

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmet zabrinutosti. U nastavku je pojednostavljen pregled nekoliko uobičajenih metoda kojima attackers mogu ugroziti privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Uopšteno, retko se dešava da se inputs različitih korisnika kombinuju u jednoj transakciji zbog složenosti takvog postupka. Zbog toga se **dve input adrese u istoj transakciji često smatraju adresama istog vlasnika**.

## **UTXO Change Address Detection**

UTXO, odnosno **Unspent Transaction Output**, mora biti u potpunosti potrošen u transakciji. Ako se samo njegov deo pošalje na drugu adresu, ostatak odlazi na novu change adresu. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se ugrožava privatnost.

### Primer

Da bi se ovo ublažilo, mixing services ili korišćenje više adresa mogu pomoći u prikrivanju vlasništva.

## **Social Networks & Forums Exposure**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, zbog čega ih je **lako povezati sa njihovim vlasnikom**.

## **Transaction Graph Analysis**

Transakcije se mogu vizuelizovati kao grafovi, otkrivajući moguće veze između korisnika na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika se zasniva na analizi transakcija sa više inputs i outputs kako bi se pogodilo koji output predstavlja change koji se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje većeg broja inputa učini da output promene bude veći od bilo kog pojedinačnog inputa, to može zbuniti heuristic.

## **Forced Address Reuse**

Napadači mogu slati male iznose na prethodno korišćene adrese, nadajući se da će ih primalac u budućim transakcijama kombinovati sa drugim inputima i tako povezati adrese.

### Ispravno ponašanje walleta

Walleti treba da izbegavaju korišćenje coin-a primljenih na već korišćenim, praznim adresama kako bi sprečili ovaj privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcije bez kusura verovatno su između dve adrese u vlasništvu istog korisnika.
- **Round Numbers:** Zaokružen iznos u transakciji ukazuje na to da je reč o uplati, dok je output koji nije zaokružen verovatno kusur.
- **Wallet Fingerprinting:** Različiti walleti imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni software i potencijalno adresu za kusur.
- **Amount & Timing Correlations:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije sledljivim.

## **Traffic Analysis**

Nadgledanjem mrežnog saobraćaja, napadači potencijalno mogu povezati transakcije ili blokove sa IP adresama, čime se ugrožava privacy korisnika. Ovo je naročito tačno ako entitet upravlja velikim brojem Bitcoin node-ova, čime se poboljšava njegova sposobnost nadgledanja transakcija.

## Više

Za sveobuhvatan spisak privacy napada i odbrana posetite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Načini za anonimno pribavljanje Bitcoin-a

- **Cash Transactions**: Nabavka bitcoin-a putem gotovine.
- **Cash Alternatives**: Kupovina gift card-ova i njihova online razmena za bitcoin.
- **Mining**: Najprivatniji način zarade bitcoin-a jeste mining, naročito kada se obavlja samostalno, jer mining pool-ovi mogu znati IP adresu miner-a. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretski, krađa bitcoin-a mogla bi biti još jedan način za njegovu anonimnu nabavku, iako je nezakonita i ne preporučuje se.

## Mixing Services

Korišćenjem mixing service-a, korisnik može **slati bitcoin-e** i zauzvrat primiti **druge bitcoin-e**, što otežava praćenje prvobitnog vlasnika. Ipak, ovo zahteva poverenje u service da neće čuvati logove i da će zaista vratiti bitcoin-e. Alternativne opcije za mixing uključuju Bitcoin casinos.

## CoinJoin

**CoinJoin** spaja više transakcija različitih korisnika u jednu, otežavajući proces svima koji pokušavaju da povežu inpute sa outputima. Uprkos njegovoj efikasnosti, transakcije sa jedinstvenim veličinama inputa i outputa i dalje se potencijalno mogu pratiti.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija posetite [CoinJoin](https://coinjoin.io/en). Za Ethereum smart-contract mixer koji razdvaja depozite od kasnijih povlačenja pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) kao regularnu transakciju, bez karakterističnih jednakih outputa koji odlikuju CoinJoin. Zbog toga ga je izuzetno teško otkriti, a mogao bi učiniti nevažećim common-input-ownership heuristic koji koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije poput navedene mogle bi biti PayJoin, čime se poboljšava privatnost, a da pritom ostanu nerazlikovane od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da naruši tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanju da se očuva privatnost transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Za očuvanje privatnosti i bezbednosti, sinhronizacija novčanika sa blockchainom je ključna. Izdvajaju se dve metode:

- **Full node**: Preuzimanjem celog blockchaina, full node obezbeđuje maksimalnu privatnost. Sve ikada izvršene transakcije čuvaju se lokalno, zbog čega napadači ne mogu da utvrde za koje transakcije ili adrese je korisnik zainteresovan.
- **Client-side block filtering**: Ova metoda podrazumeva kreiranje filtera za svaki blok u blockchainu, što novčanicima omogućava da identifikuju relevantne transakcije bez otkrivanja konkretnih interesovanja posmatračima mreže. Lightweight novčanici preuzimaju ove filtere i preuzimaju cele blokove samo kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin funkcioniše na peer-to-peer mreži, preporučuje se korišćenje Tor-a za skrivanje IP adrese, čime se poboljšava privatnost tokom interakcije sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti, od ključnog je značaja koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Moderni novčanici svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Multiple transactions**: Deljenje plaćanja na više transakcija može zamagliti iznos transakcije i onemogućiti privacy napade.
- **Change avoidance**: Biranje transakcija koje ne zahtevaju change output-e poboljšava privatnost ometanjem metoda za detekciju change output-a.
- **Multiple change outputs**: Ako izbegavanje change output-a nije moguće, kreiranje više change output-a i dalje može poboljšati privatnost.

# **Monero: Svetionik anonimnosti**

Monero je osmišljen tako da daje prioritet privatnosti transakcija.

# **Ethereum: Gas i transakcije**

## **Razumevanje gas-a**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u i obračunava se u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje gas limit i osnovnu naknadu, uz priority fee koji podstiče validator da je uključi. Korisnici mogu podesiti maksimalnu naknadu kako bi osigurali da ne plate više nego što je potrebno, pri čemu se višak refundira.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract-a. One zahtevaju naknadu i moraju biti uključene u blok. Osnovne informacije u transakciji obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, gas limit i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, pa nije neophodna u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za svakoga ko želi da koristi kriptovalute, uz davanje prioriteta privatnosti i bezbednosti.

## Red Teaming Web3 sistema usmeren na vrednost

- Popišite komponente koje sadrže vrednost (signers, oracles, bridges, automation) da biste razumeli ko može da pomera sredstva i na koji način.
- Mapirajte svaku komponentu na relevantne MITRE AADAPT taktike kako biste otkrili putanje za eskalaciju privilegija.
- Uvežbajte flash-loan/oracle/credential/cross-chain attack chains da biste potvrdili uticaj i dokumentovali uslove koji omogućavaju exploit.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje Web3 procesa potpisivanja

- Supply-chain tampering wallet UI-jeva može da izmeni EIP-712 payload-e neposredno pre potpisivanja i preuzme validne potpise za delegatecall-based proxy takeovers (npr. slot-0 overwrite Safe masterCopy-ja).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Uobičajeni načini otkaza smart account-a obuhvataju zaobilaženje kontrole pristupa `EntryPoint`-a, unsigned gas fields, stateful validation, ERC-1271 replay i fee-drain putem revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost smart contract-a

- Mutation testing za pronalaženje slepih tačaka u testnim paketima:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet ZK dokaza / zkVM guest-a

Kada proveravač koristi **zkVM** ili proof circuit specifičan za aplikaciju da potvrdi tvrdnju, on saznaje samo da je **guest program izvršen onako kako je napisan**. Ako guest sadrži **unsafe deserialization**, **undefined behavior** ili **missing semantic constraints**, zlonamerni proveravač može generisati dokaz koji prolazi proveru, dok su **javne metrike ili navedeni invariant netačni**.<sup>[[7]](#references)</sup>

### Unsafe deserialization unutar proof guest-ova

- Tretirajte private witness/circuit bytes kao **untrusted attacker input**, čak i ako su skriveni proof-om.
- Izbegavajte njihovu deserializaciju pomoću neproverenih helper-a kao što je `rkyv::access_unchecked`, osim ako su bajtovi prethodno validirani out-of-band.
- Enum discriminants, relative pointers, lengths i indexes učitani iz nepouzdanih serijalizovanih podataka moraju biti validirani pre nego što utiču na tok izvršavanja ili pristup memoriji.

Praktični obrazac za audit:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Ako je polje kao što je `op.kind` enum i napadač može da ubaci **discriminant van dozvoljenog opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table / UB

Ako Rust prevede veliki `match` u **jump table**, nevažeći enum discriminant može dovesti do **nedefinisanog toka izvršavanja**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van dozvoljenog opsega indeksira memoriju iza prve jump table i skače na kod povezan sa drugom.

Rezultat: operacija se i dalje izvršava, ali se putanja za obračun preskače. U zkVM-u se na taj način mogu falsifikovati dokazi koji prijavljuju nemoguće metrike, kao što su manji broj gate-ova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum vrednosti pod kontrolom napadača koje se deserijalizuju iz witness/private input-a.
- Proverite ponovljene `match` iskaze nad istim opcode/kind poljem.
- Kombinaciju `unsafe` + deserijalizaciju bez provera + veliki opcode dispatch tretirajte kao kombinaciju visokog rizika.
- Po potrebi izvršite reverse engineering emitovanog binary-ja; raspored jump table-a može biti važniji od izvornog koda.

### Nedostajuća semantička ograničenja u reverzibilnim/specijalizovanim interpreterima

Nemojte proveravati samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba da nametne.

Kod reverzibilnih/kvantno-sličnih skupova instrukcija, uverite se da su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija nalik Toffoli/CCX, implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
postaje nebezbedno ako guest ne odbije:
```text
op.q_control1 == op.q_control2 == op.q_target
```
U tom slučaju tranzicija se svodi na:
```text
q = q ^ (q & q) = 0
```
Ovo stvara **deterministički primitiv za resetovanje**, narušava pretpostavke o reverzibilnosti i omogućava jeftinija nenameravana izračunavanja. U proof sistemima koji potvrđuju korišćenje resursa, ovo napadačima može omogućiti da zadovolje funkcionalne provere, a da zaobiđu model troškova za koji verifier veruje da se primenjuje.

### Šta testirati u ZK sistemima

- Fuzz-ujte sve guest parsere neispravnim enkodiranjima witness/private-input podataka.
- Potvrdite validaciju opsega enum vrednosti pre opcode dispatch-a.
- Dodajte semantičke provere za aliasing operanada i druge nevažeće oblike instrukcija.
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan proof i dalje može dokazivati **pogrešnu tvrdnju** ako je guest program neispravan.

## Eksploatacija DeFi/AMM sistema

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotreba zaokruživanja/preciznosti, swap-ovi sa pojačanim flash loan-om koji prelaze prag), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za multi-asset weighted pool-ove koji keširaju virtuelne balanse i mogu biti otrovani kada je `supply == 0`, proučite:

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
- [7] [Trail of Bits - Pobijedili smo Google-ov zero-knowledge proof kvantne kriptoanalize](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zaštita elliptic curve kriptovaluta od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repozitorijum](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
