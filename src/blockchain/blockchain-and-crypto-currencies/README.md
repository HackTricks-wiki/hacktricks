# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni koncepti

- **Pametni ugovori** su definisani kao programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi, automatizujući izvršavanje sporazuma bez posrednika.
- **Decentralizovane aplikacije (dApps)** zasnivaju se na pametnim ugovorima i imaju korisnički prijemčiv front-end i transparentan backend koji se može proveriti.
- **Tokeni i novčići** razlikuju se po tome što novčići služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenim kontekstima.
- **Utility Tokens** omogućavaju pristup uslugama, dok **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za Decentralized Finance i pruža finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** označavaju Decentralized Exchange Platforms, odnosno Decentralized Autonomous Organizations.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju sigurnu i usaglašenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** oslanja se na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva da validatori poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju pomoću digitalnih potpisa, čime se obezbeđuje da samo vlasnik privatnog ključa može da pokrene prenose.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **ulaza** (izvor sredstava), **izlaza** (odredište), **naknada** (koje se plaćaju minerima) i **skripti** (pravila transakcije).

### Lightning Network

Cilj je poboljšanje skalabilnosti Bitcoina omogućavanjem više transakcija unutar kanala, pri čemu se na blockchain emituje samo konačno stanje.

## Problemi privatnosti Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije kao što su **Mixers** i **CoinJoin** poboljšavaju anonimnost prikrivanjem veza između transakcija korisnika.

## Anonimno pribavljanje Bitcoina

Metode obuhvataju trgovinu za gotovinu, mining i korišćenje mixers servisa. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikriva CoinJoins kao obične transakcije radi veće privatnosti.

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često predstavljaju razlog za zabrinutost. U nastavku je pojednostavljen pregled nekoliko uobičajenih metoda pomoću kojih napadači mogu ugroziti privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Uopšteno govoreći, retko se dešava da se ulazi različitih korisnika kombinuju u jednoj transakciji zbog složenosti takvog postupka. Zbog toga se **dve ulazne adrese u istoj transakciji često smatraju adresama istog vlasnika**.

## **UTXO Change Address Detection**

UTXO, odnosno **Unspent Transaction Output**, mora biti u potpunosti potrošen u okviru transakcije. Ako se samo njegov deo pošalje na drugu adresu, ostatak se šalje na novu adresu za kusur. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se ugrožava privatnost.

### Primer

Da bi se ovo ublažilo, mixing servisi ili korišćenje više adresa mogu pomoći u prikrivanju vlasništva.

## **Social Networks & Forums Exposure**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, čime postaje **lako povezati adresu sa njenim vlasnikom**.

## **Transaction Graph Analysis**

Transakcije se mogu vizuelizovati kao grafovi, otkrivajući potencijalne veze između korisnika na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika zasniva se na analizi transakcija sa više ulaza i izlaza kako bi se pretpostavilo koji izlaz predstavlja kusur koji se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje većeg broja inputa učini da je change output veći od bilo kog pojedinačnog inputa, to može zbuniti heuristic.

## **Forced Address Reuse**

Napadači mogu slati male iznose na prethodno korišćene adrese, nadajući se da će ih primalac u budućim transakcijama kombinovati sa drugim inputima, čime se adrese međusobno povezuju.

### Ispravno ponašanje walleta

Walleti bi trebalo da izbegavaju korišćenje coins primljenih na već korišćenim, praznim adresama kako bi sprečili ovaj privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcije bez change-a verovatno se odvijaju između dve adrese u vlasništvu istog korisnika.
- **Round Numbers:** Okrugao broj u transakciji ukazuje na to da je reč o uplati, dok je output koji nije okrugao verovatno change.
- **Wallet Fingerprinting:** Različiti walleti imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni software i potencijalno change adresu.
- **Amount & Timing Correlations:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije sledljivim.

## **Traffic Analysis**

Praćenjem mrežnog saobraćaja, napadači potencijalno mogu povezati transakcije ili blokove sa IP adresama, čime ugrožavaju privatnost korisnika. Ovo je naročito izraženo ako entitet upravlja velikim brojem Bitcoin nodova, čime povećava sposobnost praćenja transakcija.

## More

Za sveobuhvatan spisak privacy napada i odbrana posetite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Nabavljanje bitcoina putem gotovine.
- **Cash Alternatives**: Kupovina gift kartica i njihova online razmena za bitcoin.
- **Mining**: Najprivatniji način zarade bitcoina jeste mining, naročito kada se obavlja samostalno, jer mining pool-ovi mogu znati IP adresu minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorijski, krađa bitcoina mogla bi biti još jedan način anonimnog pribavljanja, iako je nezakonita i ne preporučuje se.

## Mixing Services

Korišćenjem mixing service-a, korisnik može **slati bitcoine** i zauzvrat primiti **druge bitcoine**, što otežava praćenje prvobitnog vlasnika. Ipak, ovo zahteva poverenje u service da neće čuvati logove i da će zaista vratiti bitcoine. Alternativne mixing opcije uključuju Bitcoin casinos.

## CoinJoin

**CoinJoin** spaja više transakcija različitih korisnika u jednu, čime komplikuje proces svakome ko pokušava da poveže inpute sa outputima. Uprkos svojoj efikasnosti, transakcije sa jedinstvenim veličinama inputa i outputa i dalje se potencijalno mogu pratiti.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija posetite [CoinJoin](https://coinjoin.io/en). Za Ethereum smart-contract mixer koji razdvaja depozite od kasnijih povlačenja pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikazuje transakciju između dve strane (npr. kupca i trgovca) kao običnu transakciju, bez karakterističnih jednakih outputa koji se povezuju sa CoinJoin-om. Zbog toga ga je izuzetno teško otkriti, a mogao bi i učiniti nevažećim heuristic o vlasništvu nad zajedničkim inputima koji koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije poput navedene mogle bi biti PayJoin, čime se poboljšava privatnost, a istovremeno ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da poremeti tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u težnji ka privatnosti transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije wallet-a**

Radi očuvanja privatnosti i bezbednosti, sinhronizacija wallet-a sa blockchain-om je ključna. Izdvajaju se dva metoda:

- **Full node**: Preuzimanjem celog blockchain-a, full node obezbeđuje maksimalnu privatnost. Sve ikada obavljene transakcije čuvaju se lokalno, zbog čega adversarima postaje nemoguće da utvrde za koje transakcije ili adrese je korisnik zainteresovan.
- **Client-side block filtering**: Ovaj metod podrazumeva kreiranje filtera za svaki blok u blockchain-u, što wallet-ima omogućava da identifikuju relevantne transakcije bez otkrivanja konkretnih interesovanja posmatračima mreže. Lightweight wallet-i preuzimaju ove filtere i preuzimaju cele blokove samo kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin funkcioniše na peer-to-peer mreži, preporučuje se korišćenje Tor-a za prikrivanje IP adrese, čime se poboljšava privatnost prilikom interakcije sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti, od ključnog je značaja koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Moderni wallet-i svojim dizajnom odvraćaju od ponovne upotrebe adresa.

## **Strategije za privatnost transakcija**

- **Multiple transactions**: Podela plaćanja na više transakcija može prikriti iznos transakcije i sprečiti privacy napade.
- **Change avoidance**: Opredeljivanje za transakcije koje ne zahtevaju change output-e poboljšava privatnost ometanjem metoda za detekciju change-a.
- **Multiple change outputs**: Ako izbegavanje change-a nije izvodljivo, generisanje više change output-a i dalje može poboljšati privatnost.

# **Monero: Svetionik anonimnosti**

Monero je dizajniran tako da daje prednost privatnosti transakcija.

# **Ethereum: Gas i transakcije**

## **Razumevanje gas-a**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u i izražava se u **gwei**. Na primer, transakcija čiji je trošak 2,310,000 gwei (ili 0.00231 ETH) obuhvata gas limit i osnovnu naknadu, uz priority fee koji podstiče validator-a da je uključi. Korisnici mogu da postave maksimalnu naknadu kako bi osigurali da ne plate više nego što je potrebno, pri čemu se višak refundira.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract-a. One zahtevaju naknadu i moraju biti uključene u blok. Osnovne informacije u transakciji obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, gas limit i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, zbog čega nije potrebno da bude navedena u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za svakoga ko želi da koristi kriptovalute, uz davanje prioriteta privatnosti i bezbednosti.

## Red Teaming Web3 sistema usmeren na vrednost

- Napravite inventar komponenti koje sadrže vrednost (signeri, oracle-i, bridge-ovi, automation) da biste razumeli ko može da pomera sredstva i na koji način.
- Mapirajte svaku komponentu na relevantne MITRE AADAPT taktike kako biste otkrili puteve eskalacije privilegija.
- Uvežbajte flash-loan/oracle/credential/cross-chain attack chain-ove da biste potvrdili uticaj i dokumentovali preuslove koji omogućavaju eksploataciju.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje Web3 procesa potpisivanja

- Tampering u supply chain-u wallet UI-jeva može da izmeni EIP-712 payload-e neposredno pre potpisivanja i da preuzme validne potpise za delegatecall-based proxy takeover-e (npr. prepisivanje slot-0 vrednosti masterCopy-ja na Safe-u).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Apstrakcija naloga (ERC-4337)

- Uobičajeni načini otkaza smart account-a obuhvataju zaobilaženje kontrole pristupa `EntryPoint`-u, nepotpisana gas polja, stateful validaciju, ERC-1271 replay i iscrpljivanje naknada putem revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost smart contract-a

- Mutation testing za pronalaženje slepih tačaka u test suite-ovima:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet ZK Proof / zkVM Guest-a

Kada proveravač koristi **zkVM** ili proof circuit specifičan za aplikaciju da potvrdi neku tvrdnju, on saznaje samo da je **guest program izvršen onako kako je napisan**. Ako guest sadrži **unsafe deserialization**, **undefined behavior** ili **missing semantic constraints**, maliciozni proveravač može da generiše proof koji prolazi verifikaciju, dok su **javne metrike ili navedeni invariant netačni**.<sup>[[7]](#references)</sup>

### Unsafe deserialization unutar proof guest-ova

- Tretirajte private witness/circuit bytes kao **untrusted attacker input**, čak i ako su skriveni proof-om.
- Izbegavajte njihovu deserializaciju pomoću unchecked helper-a kao što je `rkyv::access_unchecked`, osim ako bajtovi prethodno nisu validirani out-of-band.
- Enum discriminant-i, relativni pokazivači, dužine i indeksi učitani iz nepouzdanih serijalizovanih podataka moraju biti validirani pre nego što utiču na kontrolni tok ili pristup memoriji.

Praktični obrazac za audit:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Ako je polje poput `op.kind` enum i napadač može da ubaci **discriminant van dozvoljenog opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača preko jump table / UB

Ako Rust prevede veliki `match` u **jump table**, nevažeći enum discriminant može izazvati **nedefinisan tok kontrole**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van dozvoljenog opsega indeksira memoriju iza prve jump table i skače u kod povezan sa drugom.

Rezultat: operacija se i dalje izvršava, ali se putanja za obračun preskače. U zkVM-u to može omogućiti falsifikovanje dokaza koji prijavljuju nemoguće metrike, kao što su manji broj gate-ova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum-e pod kontrolom napadača koji se deserijalizuju iz witness/private input podataka.
- Pregledajte ponovljene `match` naredbe nad istim opcode/kind poljem.
- Kombinaciju `unsafe` + deserijalizacija bez provera + velika opcode dispatch logika tretirajte kao kombinaciju visokog rizika.
- Po potrebi izvršite reverse engineering emitovanog binarnog fajla; raspored jump table-a može biti važniji od izvornog koda.

### Nedostajuća semantička ograničenja u reverzibilnim/specijalizovanim interpreterima

Nemojte proveravati samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba da nametne.

Kod reverzibilnih/kvantno-sličnih skupova instrukcija, uverite se da su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija nalik Toffoli/CCX implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
postaje nebezbedno ako gost ne odbije:
```text
op.q_control1 == op.q_control2 == op.q_target
```
U tom slučaju prelaz se svodi na:
```text
q = q ^ (q & q) = 0
```
Ovo stvara **deterministički primitiv za resetovanje**, narušavajući pretpostavke reverzibilnosti i omogućavajući jeftinija nenamerna izračunavanja. U proof sistemima koji potvrđuju korišćenje resursa, ovo napadačima može omogućiti da ispune funkcionalne provere, a da zaobiđu model troškova za koji verifier veruje da se primenjuje.

### Šta testirati u ZK sistemima

- Fuzz-ujte sve guest parsere neispravnim witness/private-input enkodinzima.
- Proverite opseg enum vrednosti pre opcode dispatch-a.
- Dodajte semantičke provere za aliasing operanada i druge nevažeće forme instrukcija.
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan proof i dalje može dokazivati **pogrešnu tvrdnju** ako guest program sadrži grešku.

## Autorizacija zavisna od stanja

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacija DeFi/AMM sistema

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotreba zaokruživanja/preciznosti, swap-ovi za prelazak praga pojačani flash loan-ovima), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za multi-asset weighted pool-ove koji keširaju virtuelne bilanse i mogu biti zatrovani kada je `supply == 0`, proučite:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Dokaz o udelu - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Javni ključ i privatni ključ - objašnjenje - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Šta su multi-signature transakcije? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transakcije | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas i naknade | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privatnost - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Nadmašili smo Google-ov zero-knowledge proof kvantne kriptoanalize](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zaštita kriptovaluta zasnovanih na eliptičkim krivama od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repozitorijum](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
