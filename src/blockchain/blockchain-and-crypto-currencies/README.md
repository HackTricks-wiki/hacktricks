# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni koncepti

- **Smart Contracts** su definisani kao programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi, automatizujući izvršavanje sporazuma bez posrednika.
- **Decentralized Applications (dApps)** se zasnivaju na smart contracts, sa korisnički prilagođenim front-endom i transparentnim backendom koji se može proveriti.
- **Tokens & Coins** se razlikuju po tome što coins služe kao digitalni novac, dok tokens predstavljaju vrednost ili vlasništvo u određenim kontekstima.
- **Utility Tokens** omogućavaju pristup uslugama, dok **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za Decentralized Finance i pruža finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** označavaju Decentralized Exchange Platforms i Decentralized Autonomous Organizations.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** se oslanja na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju putem digitalnih potpisa, čime se obezbeđuje da samo vlasnik privatnog ključa može da pokrene transfere.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (odredište), **fees** (naknada plaćena minerima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj mu je da poboljša skalabilnost Bitcoina omogućavanjem više transakcija unutar kanala, pri čemu se blockchainu emituje samo konačno stanje.

## Problemi privatnosti Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost prikrivanjem veza između transakcija korisnika.

## Anonimno pribavljanje Bitcoina

Metode obuhvataju trgovinu za gotovinu, mining i korišćenje mixers. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikazuje CoinJoins kao obične transakcije radi veće privatnosti.

# Napadi na privatnost Bitcoina

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često predstavljaju razlog za zabrinutost. U nastavku je pojednostavljen pregled nekoliko uobičajenih metoda kojima napadači mogu ugroziti privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Pretpostavka o vlasništvu nad ulazima**

Kombinovanje inputs različitih korisnika u jednoj transakciji uglavnom je retko zbog složenosti takvog postupka. Zato se često pretpostavlja da **dve ulazne adrese u istoj transakciji pripadaju istom vlasniku**.

## **Detekcija UTXO Change Address**

UTXO, odnosno **Unspent Transaction Output**, mora biti u potpunosti potrošen u transakciji. Ako se samo njegov deo pošalje na drugu adresu, ostatak odlazi na novu change adresu. Posmatrači mogu pretpostaviti da ova nova adresa pripada pošiljaocu, čime se ugrožava privatnost.

### Primer

Da bi se ovo ublažilo, mixing services ili korišćenje više adresa mogu pomoći u prikrivanju vlasništva.

## **Izloženost na društvenim mrežama i forumima**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, zbog čega ih je **lako povezati sa njihovim vlasnikom**.

## **Analiza grafa transakcija**

Transakcije se mogu vizuelizovati kao grafovi, otkrivajući moguće veze između korisnika na osnovu toka sredstava.

## **Heuristika nepotrebnog ulaza (heuristika optimalne kusur adrese)**

Ova heuristika se zasniva na analizi transakcija sa više inputs i outputs kako bi se pretpostavilo koji output predstavlja kusur koji se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje većeg broja inputa učini da izlaz kusura bude veći od bilo kog pojedinačnog inputa, to može zbuniti heuristiku.

## **Forced Address Reuse**

Napadači mogu slati male iznose na prethodno korišćene adrese, nadajući se da će ih primalac u budućim transakcijama kombinovati sa drugim inputima, čime se adrese međusobno povezuju.

### Ispravno ponašanje walleta

Walleti treba da izbegavaju korišćenje coina primljenih na već korišćene, prazne adrese kako bi sprečili ovaj privacy leak.

## **Druge tehnike analize blockchaina**

- **Tačni iznosi plaćanja:** Transakcije bez kusura verovatno se odvijaju između dve adrese u vlasništvu istog korisnika.
- **Zaokruženi brojevi:** Zaokružen broj u transakciji ukazuje na to da je reč o plaćanju, dok je izlaz koji nije zaokružen verovatno kusur.
- **Fingerprinting walleta:** Različiti walleti imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni software i potencijalno adresu za kusur.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije sledljivim.

## **Analiza saobraćaja**

Praćenjem mrežnog saobraćaja napadači potencijalno mogu povezati transakcije ili blokove sa IP adresama, čime ugrožavaju privacy korisnika. Ovo je naročito izraženo ako entitet upravlja velikim brojem Bitcoin nodeova, što povećava njegovu sposobnost praćenja transakcija.

## Više

Za sveobuhvatan spisak privacy napada i odbrana posetite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Načini za anonimno pribavljanje Bitcoina

- **Gotovinske transakcije:** Nabavljanje Bitcoina korišćenjem gotovine.
- **Alternative gotovini:** Kupovina gift kartica i njihova online zamena za Bitcoin.
- **Mining:** Najprivatniji način zarade Bitcoina jeste mining, naročito kada se obavlja samostalno, jer mining poolovi mogu znati IP adresu minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa:** Teoretski, krađa Bitcoina mogla bi biti još jedan način anonimnog pribavljanja, iako je nezakonita i ne preporučuje se.

## Mixing Services

Korišćenjem mixing servicea korisnik može **slati Bitcoine** i zauzvrat primiti **druge Bitcoine**, što otežava praćenje prvobitnog vlasnika. Ipak, ovo zahteva poverenje u service da neće čuvati logove i da će zaista vratiti Bitcoine. Alternativne opcije za mixing uključuju Bitcoin casina.

## CoinJoin

**CoinJoin** spaja više transakcija različitih korisnika u jednu, čime se komplikuje proces svakome ko pokušava da poveže inpute sa izlazima. Uprkos efikasnosti, transakcije sa jedinstvenim veličinama inputa i izlaza i dalje potencijalno mogu biti praćene.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija posetite [CoinJoin](https://coinjoin.io/en). Za sličan service na Ethereumu pogledajte [Tornado Cash](https://tornado.cash), koji anonymizuje transakcije koristeći sredstva od minera.

## PayJoin

Varijanta CoinJoina, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) tako da izgleda kao regularna transakcija, bez karakterističnih jednakih izlaza CoinJoina. Zbog toga je izuzetno teško detektovati je, a mogla bi i da učini nevažećom heuristiku zajedničkog vlasništva inputa koju koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije poput prethodno navedene mogle bi biti PayJoin, čime se poboljšava privatnost, a istovremeno ostaju nerazlikovljive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da poremeti tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanju da se postigne privatnost transakcija.

# Najbolje prakse za privatnost kriptovaluta

## **Tehnike sinhronizacije wallet-a**

Radi očuvanja privatnosti i bezbednosti, sinhronizacija wallet-a sa blockchain-om je ključna. Izdvajaju se dve metode:

- **Full node**: Preuzimanjem celokupnog blockchain-a, full node obezbeđuje maksimalnu privatnost. Sve ikada izvršene transakcije čuvaju se lokalno, zbog čega adversaries ne mogu da utvrde za koje transakcije ili adrese je korisnik zainteresovan.
- **Client-side block filtering**: Ovaj metod podrazumeva kreiranje filtera za svaki block u blockchain-u, čime wallet-i mogu da identifikuju relevantne transakcije bez otkrivanja konkretnih interesovanja network observer-ima. Lightweight wallet-i preuzimaju ove filtere i preuzimaju cele block-ove samo kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin funkcioniše na peer-to-peer network-u, preporučuje se korišćenje Tor-a za maskiranje IP adrese, čime se poboljšava privatnost pri interakciji sa network-om.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti, od ključnog je značaja koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Moderni wallet-i svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Multiple transactions**: Deljenje uplate na više transakcija može prikriti iznos transakcije i osujetiti privacy attacks.
- **Change avoidance**: Odabir transakcija koje ne zahtevaju change output-e poboljšava privatnost ometanjem metoda za detekciju change-a.
- **Multiple change outputs**: Ako izbegavanje change-a nije izvodljivo, generisanje više change output-a i dalje može poboljšati privatnost.

# **Monero: Svetionik anonimnosti**

Monero rešava potrebu za potpunom anonimnošću u digitalnim transakcijama i postavlja visok standard privatnosti.

# **Ethereum: Gas i transakcije**

## **Razumevanje gas-a**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u i izražava se u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje gas limit i osnovnu naknadu, uz tip kojim se miners podstiču. Korisnici mogu postaviti maksimalnu naknadu kako bi osigurali da ne plate više nego što je potrebno, pri čemu se višak refundira.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract-a. One zahtevaju naknadu i moraju biti minovane. Osnovne informacije u transakciji obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, gas limit i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, čime se uklanja potreba da ona bude navedena u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za svakoga ko želi da koristi kriptovalute uz davanje prioriteta privatnosti i bezbednosti.

## Value-Centric Web3 Red Teaming

- Napravite inventar komponenti koje sadrže vrednost (signers, oracles, bridges, automation) kako biste razumeli ko može da pomera sredstva i na koji način.
- Mapirajte svaku komponentu prema relevantnim MITRE AADAPT taktikama kako biste otkrili puteve za privilege escalation.
- Uvežbajte flash-loan/oracle/credential/cross-chain attack chain-ove da biste potvrdili uticaj i dokumentovali preuslove koji omogućavaju exploitation.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje Web3 Signing Workflow-a

- Supply-chain tampering wallet UI-jeva može da izmeni EIP-712 payload-e neposredno pre potpisivanja i preuzme validne potpise za delegatecall-based proxy takeover-e (npr. prepisivanje slot-0 vrednosti za preuzimanje Safe masterCopy-ja).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Uobičajeni smart-account failure mode-ovi obuhvataju zaobilaženje `EntryPoint` access control-a, nepotpisana gas polja, stateful validation, ERC-1271 replay i fee-drain putem revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost smart contract-a

- Mutation testing za pronalaženje slepih tačaka u test suite-ovima:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / integritet zkVM Guest-a

Kada proveravač koristi **zkVM** ili application-specific proof circuit za potvrđivanje neke tvrdnje, on saznaje samo da je **guest program izvršen onako kako je napisan**. Ako guest sadrži **unsafe deserialization**, **undefined behavior** ili **missing semantic constraints**, zlonamerni proveravač može generisati proof koji prolazi verifikaciju, dok su **javne metrike ili navedeni invariant netačni**.<sup>[[7]](#references)</sup>

### Unsafe deserialization unutar proof guest-ova

- Tretirajte private witness/circuit bytes kao **untrusted attacker input**, čak i kada su sakriveni proof-om.
- Izbegavajte njihovu deserializaciju pomoću unchecked helper-a kao što je `rkyv::access_unchecked`, osim ako su bytes već validirani out-of-band.
- Enum discriminant-i, relative pointer-i, length vrednosti i index-i učitani iz nepouzdanih serializovanih podataka moraju biti validirani pre nego što utiču na control flow ili memory access.

Praktičan audit obrazac:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Ako je polje kao što je `op.kind` enum i napadač može da ubaci **discriminant van opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table / UB

Ako Rust prevede veliki `match` u **jump table**, nevažeći enum discriminant može izazvati **undefined control flow**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **security-critical brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van opsega indeksira memoriju iza prve jump table i dospeva u kod povezan sa drugom.

Rezultat: operacija se i dalje izvršava, ali se accounting putanja preskače. U zkVM-u to može omogućiti falsifikovanje dokaza koji prijavljuju nemoguće metrike, kao što su manji broj gejtova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum vrednosti pod kontrolom napadača koje se deserijalizuju iz witness/private input-a.
- Pregledajte ponovljene `match` naredbe nad istim opcode/kind poljem.
- Kombinaciju `unsafe` + unchecked deserialization + veliki opcode dispatch tretirajte kao visokorizičnu.
- Po potrebi izvršite reverse engineering emitovanog binary-ja; raspored jump table-a može biti važniji od izvornog koda.

### Nedostajuća semantička ograničenja u reverzibilnim/specijalizovanim interpreterima

Nemojte proveravati samo memory safety; proverite i **semantička pravila** koja dokaz treba da nametne.

Kod reverzibilnih/kvantno-sličnih skupova instrukcija proverite da li su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija nalik Toffoli/CCX, implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
postaje nebezbedno ako guest ne odbije:
```text
op.q_control1 == op.q_control2 == op.q_target
```
U tom slučaju prelaz se svodi na:
```text
q = q ^ (q & q) = 0
```
Ovo stvara **deterministički primitiv za resetovanje**, narušava pretpostavke reverzibilnosti i omogućava jeftinija nenameravana izračunavanja. U proof sistemima koji potvrđuju utrošak resursa, ovo napadačima može omogućiti da ispune funkcionalne provere, a da zaobiđu model troškova za koji verifier veruje da se sprovodi.

### Šta testirati u ZK sistemima

- Fuzz-ujte sve guest parsere neispravnim encoding-om witness/private-input podataka.
- Proverite opseg enum vrednosti pre dispatch-a opcode-a.
- Dodajte semantičke provere za aliasing operanada i druge nevažeće oblike instrukcija.
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan proof i dalje može dokazivati **pogrešnu tvrdnju** ako guest program sadrži grešku.

## Eksploatacija DeFi/AMM sistema

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotreba zaokruživanja/preciznosti, flash-loan pojačane swap-ove koji prelaze prag), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za weighted pool-ove sa više asset-a koji keširaju virtuelne balanse i mogu biti otrovani kada je `supply == 0`, proučite:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## Reference

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key Explained - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [What are multi-signature transactions? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas and fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
