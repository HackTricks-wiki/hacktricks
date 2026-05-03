# Blockchain i Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Smart Contracts** su definisani kao programi koji se izvršavaju na blockchain-u kada su ispunjeni određeni uslovi, automatizujući izvršavanje sporazuma bez posrednika.
- **Decentralized Applications (dApps)** nadograđuju se na smart contracts, sa korisniku prijatnim front-end-om i transparentnim, proverljivim back-end-om.
- **Tokens & Coins** razlikuju se po tome što coins služe kao digitalni novac, dok tokens predstavljaju vrednost ili vlasništvo u specifičnim kontekstima.
- **Utility Tokens** daju pristup servisima, a **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** znači Decentralized Finance, i nudi finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** označavaju Decentralized Exchange Platforms i Decentralized Autonomous Organizations, redom.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blockchain-u:

- **Proof of Work (PoW)** se oslanja na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da drže određenu količinu tokena, smanjujući potrošnju energije u poređenju sa PoW.

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju pomoću digitalnih potpisa, čime se obezbeđuje da samo vlasnik privatnog ključa može da pokrene prenose.

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za odobravanje transakcije.
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (odredište), **fees** (plaćaju se minerima) i **scripts** (pravila transakcije).

### Lightning Network

Cilja da poboljša skalabilnost Bitcoina tako što omogućava više transakcija unutar kanala, a na blockchain se šalje samo konačno stanje.

## Problemi sa privatnošću Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, koriste obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost prikrivanjem veza između transakcija korisnika.

## Anonimno sticanje Bitcoina

Metode uključuju gotovinske trgovine, mining i korišćenje mixera. **CoinJoin** meša više transakcija da bi otežao praćenje, dok **PayJoin** prikriva CoinJoins kao obične transakcije radi veće privatnosti.

# Bitcoin Privacy Atacks

# Sažetak Bitcoin Privacy Atacks

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmet zabrinutosti. Evo pojednostavljenog pregleda nekoliko uobičajenih metoda pomoću kojih napadači mogu da kompromituju privatnost Bitcoina.

## **Common Input Ownership Assumption**

Generalno je retko da se inputi različitih korisnika kombinuju u jednoj transakciji zbog složenosti koja je uključena. Stoga se **pretpostavlja da dva input adresa u istoj transakciji često pripadaju istom vlasniku**.

## **UTXO Change Address Detection**

UTXO, ili **Unspent Transaction Output**, mora biti u potpunosti potrošen u transakciji. Ako se samo jedan deo pošalje na drugu adresu, ostatak ide na novu change adresu. Posmatrači mogu da pretpostave da ova nova adresa pripada pošiljaocu, čime se ugrožava privatnost.

### Primer

Da bi se to ublažilo, mogu pomoći usluge mixinga ili korišćenje više adresa kako bi se prikrilo vlasništvo.

## **Social Networks & Forums Exposure**

Korisnici ponekad dele svoje Bitcoin adrese online, što olakšava **povezivanje adrese sa njenim vlasnikom**.

## **Transaction Graph Analysis**

Transakcije se mogu vizuelizovati kao grafovi, otkrivajući potencijalne veze između korisnika na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika se zasniva na analizi transakcija sa više inputa i outputa kako bi se pogodilo koji je output change koji se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje više inputa čini change output veći od bilo kog pojedinačnog inputa, to može zbuniti heuristic.

## **Forced Address Reuse**

Napadači mogu slati male iznose na prethodno korišćene adrese, nadajući se da će primalac to kombinovati sa drugim inputima u budućim transakcijama, čime se adrese povezuju.

### Correct Wallet Behavior

Wallets bi trebalo da izbegavaju korišćenje coina primljenih na već korišćene, prazne adrese kako bi sprečili ovaj privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcije bez change-a su verovatno između dve adrese u vlasništvu istog korisnika.
- **Round Numbers:** Okrugao broj u transakciji ukazuje da je to plaćanje, a neokrugli output je verovatno change.
- **Wallet Fingerprinting:** Različiti walleti imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni software i potencijalno change adresu.
- **Amount & Timing Correlations:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije pratljivim.

## **Traffic Analysis**

Praćenjem network traffic-a, napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama, kompromitujući privacy korisnika. Ovo je posebno tačno ako neka entity operiše veliki broj Bitcoin nodova, što povećava njihovu sposobnost da prate transakcije.

## More

Za sveobuhvatan spisak privacy napada i odbrana, posetite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Sticanje bitcoina putem keša.
- **Cash Alternatives**: Kupovina gift kartica i njihova razmena online za bitcoin.
- **Mining**: Najprivatniji način da se zarade bitcoini je mining, naročito kada se radi solo, jer mining poolovi mogu znati minerovu IP adresu. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretski, krađa bitcoina bi mogla biti još jedan način da se do njih dođe anonimno, iako je to ilegalno i ne preporučuje se.

## Mixing Services

Korišćenjem mixing service-a, korisnik može **poslati bitcoine** i dobiti **druge bitcoine zauzvrat**, što otežava praćenje prvobitnog vlasnika. Ipak, ovo zahteva poverenje da service neće čuvati logs i da će zaista vratiti bitcoine. Alternativne mixing opcije uključuju Bitcoin kasina.

## CoinJoin

**CoinJoin** spaja više transakcija različitih korisnika u jednu, otežavajući proces svakome ko pokušava da uskladi inpute sa outputima. Uprkos svojoj efikasnosti, transakcije sa jedinstvenim veličinama inputa i outputa i dalje se potencijalno mogu pratiti.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija, posetite [CoinJoin](https://coinjoin.io/en). Za sličan service na Ethereum-u, pogledajte [Tornado Cash](https://tornado.cash), koji anonymizes transakcije sredstvima od miner-a.

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) kao običnu transakciju, bez karakterističnih jednakih outputa tipičnih za CoinJoin. To ga čini izuzetno teškim za otkrivanje i može poništiti common-input-ownership heuristic koji koriste entity za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije kao gore navedene mogle bi biti PayJoin, poboljšavajući privatnost dok ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno poremetiti tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u težnji ka privatnosti transakcija.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Da bi se održali privatnost i bezbednost, sinhronizacija wallet-a sa blockchain-om je ključna. Izdvajaju se dve metode:

- **Full node**: Preuzimanjem celog blockchain-a, full node obezbeđuje maksimalnu privatnost. Sve transakcije ikada napravljene čuvaju se lokalno, što onemogućava protivnicima da identifikuju koje su transakcije ili adrese korisniku zanimljive.
- **Client-side block filtering**: Ova metoda podrazumeva kreiranje filtera za svaki block u blockchain-u, omogućavajući wallet-ima da identifikuju relevantne transakcije bez otkrivanja specifičnih interesovanja mrežnim posmatračima. Lagani wallet-i preuzimaju ove filtere i pune block-ove preuzimaju tek kada se pronađe poklapanje sa korisnikovim adresama.

## **Utilizing Tor for Anonymity**

Pošto Bitcoin funkcioniše na peer-to-peer mreži, preporučuje se korišćenje Tor-a kako bi se prikrila vaša IP adresa i poboljšala privatnost pri interakciji sa mrežom.

## **Preventing Address Reuse**

Da bi se zaštitila privatnost, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Moderni wallet-i obeshrabruju ponovnu upotrebu adresa svojim dizajnom.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Deljenje plaćanja na nekoliko transakcija može prikriti iznos transakcije i osujetiti napade na privatnost.
- **Change avoidance**: Biranje transakcija koje ne zahtevaju change output-e poboljšava privatnost tako što remeti metode otkrivanja change-a.
- **Multiple change outputs**: Ako je izbegavanje change-a neizvodljivo, generisanje više change output-a i dalje može poboljšati privatnost.

# **Monero: A Beacon of Anonymity**

Monero odgovara na potrebu za potpunom anonimnošću u digitalnim transakcijama, postavljajući visok standard za privatnost.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u, a cena mu je izražena u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje gas limit i base fee, uz tip kao podsticaj za miners. Korisnici mogu da postave max fee kako bi bili sigurni da neće preplatiti, a višak se refundira.

## **Executing Transactions**

Transakcije u Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract-a. Zahtevaju fee i moraju biti mined. Ključne informacije u transakciji uključuju primaoca, potpis pošiljaoca, vrednost, opcionalne podatke, gas limit i fee-jeve. Značajno je da se adresa pošiljaoca izvodi iz potpisa, pa nije potrebno navoditi je u podacima transakcije.

Ove prakse i mehanizmi su osnovni za svakoga ko želi da koristi cryptocurrencies uz prioritet privatnosti i bezbednosti.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UI-jevima can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Kada prover koristi **zkVM** ili aplikaciono-specifičan proof circuit da potvrdi tvrdnju, verifier saznaje samo da je **guest program izvršen onako kako je napisan**. Ako guest sadrži **unsafe deserialization**, **undefined behavior** ili **missing semantic constraints**, zlonamerni prover može generisati proof koji prolazi proveru, dok su **javni metrika ili tvrđeni invariant netačni**.

### Unsafe deserialization inside proof guests

- Tretirajte private witness/circuit bajtove kao **nepouzdani attacker input** čak i ako su skriveni proof-om.
- Izbegavajte njihovo deserializovanje pomoću neproverenih helper-a kao što je `rkyv::access_unchecked` osim ako su bajtovi već prethodno validirani van toka.
- Enum discriminants, relative pointers, lengths i indexes učitani iz nepouzdanih serialized podataka moraju biti validirani pre nego što utiču na control flow ili memory access.

Praktični pattern za audit:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Ako je polje kao što je `op.kind` enum i napadač može da ubaci **discriminant van opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Jump-table / UB counter bypass

Ako Rust veliki `match` prevede u **jump table**, neispravan enum discriminant može da dovede do **undefined control flow**. Opasan obrazac je:

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van opsega indeksira iza prve jump table i završava u kodu povezanom sa drugom.

Rezultat: operacija se i dalje izvršava, ali se accounting putanja preskače. U zkVM-u ovo može da falsifikuje dokaze koji prijavljuju nemoguće metrike kao što su manji broj gate-ova, manje skupih operacija ili drugi falsifikovani ograničeni resursi.

Checklist za review:

- Potražite enum-e pod kontrolom napadača koji se deserializuju iz witness/private input.
- Pregledajte ponovljene `match` izraze nad istim opcode/kind poljem.
- Smatrajte kombinaciju `unsafe` + neproverene deserializacije + velikog opcode dispatch-a visokorizičnom.
- Po potrebi reverzno inženjerujte emitovani binary; raspored jump-table može biti važniji od source koda.

### Missing semantic constraints in reversible/specialized interpreters

Ne validirajte samo memory safety; validirajte i **semantička pravila** koja dokaz treba da enforce-uje.

Za reversible/quantum-like instruction sets, obezbedite da su operandi koji moraju biti različiti zaista constrained da budu različiti. Toffoli/CCX-like operacija implementirana kao:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
postaje nesigurno ako gost ne odbije:
```text
op.q_control1 == op.q_control2 == op.q_target
```
U tom slučaju tranzicija se svodi na:
```text
q = q ^ (q & q) = 0
```
Ovo stvara **deterministic reset primitive**, narušava pretpostavke o reverzibilnosti i omogućava jeftinije neintended computation. U proof systems koji potvrđuju potrošnju resursa, ovo može napadačima da prođu functional checks dok zaobilaze cost model za koji verifier misli da se sprovodi.

### Šta testirati u ZK systems

- Fuzzuj sve guest parsers sa malformed witness/private-input encodings.
- Potvrdi enum range validation pre opcode dispatch-a.
- Dodaj semantic checks za operand aliasing i druge invalid instruction forms.
- Uporedi prijavljene/public counters sa nezavisnom reference implementation.
- Zapamti da valid proof i dalje može dokazivati **pogrešnu tvrdnju** ako je guest program buggy.

## DeFi/AMM Exploitation

Ako istražuješ praktičnu exploitation DEXes i AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), pogledaj:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za multi-asset weighted pools koji cache-uju virtual balances i mogu biti poisoned kada `supply == 0`, prouči:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
