# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni koncepti

- **Smart Contracts** su programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi i automatizuju izvršavanje ugovora bez posrednika.
- **Decentralized Applications (dApps)** zasnivaju se na smart contracts i sadrže korisnički prilagođen front-end i transparentan back-end koji se može revidirati.
- **Tokens & Coins** razlikuju se po tome što coin-i služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenom kontekstu.
  - **Utility Tokens** omogućavaju pristup uslugama, a **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica od Decentralized Finance i pruža finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** označavaju platforme za decentralizovanu razmenu i decentralizovane autonomne organizacije.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** oslanja se na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju digitalnim potpisima, čime se obezbeđuje da prenos može da pokrene samo vlasnik privatnog ključa.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (odredište), **fees** (naknade koje se plaćaju rudarima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj mu je da poboljša skalabilnost Bitcoina tako što omogućava više transakcija unutar kanala, a na blockchain emituje samo konačno stanje.

## Pitanja privatnosti Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije kao što su **Mixers** i **CoinJoin** poboljšavaju anonimnost tako što prikrivaju veze između transakcija korisnika.

## Anonimno pribavljanje bitcoina

Metode obuhvataju trgovinu za gotovinu, rudarenje i korišćenje mixers. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikriva CoinJoins kao obične transakcije radi veće privatnosti.

# Pregled napada na privatnost Bitcoina

U svetu Bitcoina privatnost transakcija i anonimnost korisnika često izazivaju zabrinutost. U nastavku je pojednostavljen pregled nekoliko čestih metoda kojima napadači mogu da ugroze privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Pretpostavka o zajedničkom vlasništvu nad ulazima**

Uglavnom je retko da se ulazi različitih korisnika objedine u jednoj transakciji zbog složenosti takvog postupka. Zato se **često pretpostavlja da dve ulazne adrese u istoj transakciji pripadaju istom vlasniku**.

## **Otkrivanje UTXO adrese za kusur**

UTXO, odnosno **Unspent Transaction Output**, mora se potrošiti u celosti u jednoj transakciji. Ako se samo deo pošalje na drugu adresu, ostatak se šalje na novu adresu za kusur. Posmatrači mogu da pretpostave da ova nova adresa pripada pošiljaocu, čime se ugrožava privatnost.

### Primer

Da bi se ovo ublažilo, mogu se koristiti usluge mešanja ili više adresa kako bi se prikrilo vlasništvo.

## **Izlaganje na društvenim mrežama i forumima**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, pa je **lako povezati adresu sa njenim vlasnikom**.

## **Analiza grafa transakcija**

Transakcije mogu da se prikažu kao grafovi, otkrivajući moguće veze između korisnika na osnovu toka sredstava.

## **Heuristika nepotrebnog ulaza (heuristika optimalnog kusura)**

Ova heuristika se zasniva na analizi transakcija sa više ulaza i izlaza kako bi se pogodilo koji izlaz predstavlja kusur koji se vraća pošiljaocu.

### Primer

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ako dodavanje novih ulaza učini izlaz za kusur većim od bilo kog pojedinačnog ulaza, to može zbuniti heuristiku.

## **Prinudna ponovna upotreba adresa**

Napadači mogu slati male iznose na ranije korišćene adrese, nadajući se da će ih primalac spojiti sa drugim ulazima u budućim transakcijama i tako povezati adrese.

### Ispravno ponašanje novčanika

Novčanici bi trebalo da izbegavaju korišćenje novčića primljenih na već korišćenim, praznim adresama kako bi sprečili ovaj privacy leak.

## **Druge tehnike analize blockchaina**

- **Tačni iznosi plaćanja:** Transakcije bez kusura verovatno se odvijaju između dve adrese koje pripadaju istom korisniku.
- **Zaokruženi iznosi:** Zaokružen iznos u transakciji ukazuje na to da je reč o plaćanju, dok je izlaz sa nezaokruženim iznosom verovatno kusur.
- **Otisci novčanika:** Različiti novčanici imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni softver i potencijalno adresu za kusur.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može omogućiti njihovo praćenje.

## **Analiza saobraćaja**

Praćenjem mrežnog saobraćaja napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama, čime se ugrožava privatnost korisnika. To naročito važi ako neki entitet upravlja velikim brojem Bitcoin čvorova, čime se povećava njegova mogućnost praćenja transakcija.

## Više

Sveobuhvatan spisak napada na privatnost i mera odbrane potražite na stranici [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini za anonimno pribavljanje bitcoina

- **Gotovinske transakcije**: Pribavljanje bitcoina gotovinom.
- **Alternative gotovini**: Kupovina poklon-kartica i njihova zamena za bitcoin na internetu.
- **Rudarenje**: Najprivatniji način zarade bitcoina jeste rudarenje, naročito ako se obavlja samostalno, jer rudarski pulovi mogu saznati IP adresu rudara. [Informacije o rudarskim pulovima](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: Teoretski, krađa bitcoina mogla bi biti još jedan način anonimnog pribavljanja, mada je nezakonita i ne preporučuje se.

## Usluge mešanja

Korišćenjem usluge mešanja korisnik može **poslati bitcoine** i zauzvrat dobiti **druge bitcoine**, što otežava praćenje prvobitnog vlasnika. Ipak, za to je potrebno verovati da usluga neće čuvati evidenciju i da će zaista vratiti bitcoine. Alternativne opcije mešanja uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** spaja više transakcija različitih korisnika u jednu, što otežava uparivanje ulaza i izlaza. Uprkos svojoj efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje se potencijalno mogu pratiti.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Više informacija potražite na stranici [CoinJoin](https://coinjoin.io/en). Za Ethereum mikser zasnovan na pametnim ugovorima, koji razdvaja depozite od kasnijih isplata, pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) tako da izgleda kao obična transakcija, bez karakterističnih jednakih izlaza koji se javljaju kod CoinJoin-a. Zbog toga ju je izuzetno teško otkriti, a mogla bi i da obori heuristiku zajedničkog vlasništva nad ulazima koju koriste subjekti za nadzor transakcija.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcije poput one iznad mogu biti PayJoin, čime se povećava privatnost, a istovremeno ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da omete tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanju da se obezbedi privatnost transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Radi očuvanja privatnosti i bezbednosti, ključno je sinhronizovati novčanike sa blockchain-om. Izdvajaju se dva metoda:

- **Pun čvor**: Preuzimanjem celog blockchain-a, pun čvor obezbeđuje maksimalnu privatnost. Sve ikada obavljene transakcije čuvaju se lokalno, pa protivnici ne mogu da utvrde koje transakcije ili adrese zanimaju korisnika.
- **Filtriranje blokova na klijentskoj strani**: Ovaj metod podrazumeva kreiranje filtera za svaki blok u blockchain-u, što novčanicima omogućava da pronađu relevantne transakcije bez otkrivanja konkretnih interesovanja posmatračima mreže. Laki novčanici preuzimaju ove filtere i pune blokove preuzimaju samo kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin funkcioniše preko peer-to-peer mreže, preporučuje se korišćenje Tor-a radi prikrivanja IP adrese i poboljšanja privatnosti pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može da ugrozi privatnost povezivanjem transakcija sa istim entitetom. Savremeni novčanici svojim dizajnom odvraćaju od ponovne upotrebe adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Podela uplate na nekoliko transakcija može da prikrije iznos transakcije i osujeti napade na privatnost.
- **Izbegavanje kusura**: Odabir transakcija koje ne zahtevaju izlaze kusura poboljšava privatnost ometanjem metoda za otkrivanje kusura.
- **Više izlaza kusura**: Ako izbegavanje kusura nije izvodljivo, generisanje više izlaza kusura i dalje može da poboljša privatnost.

# **Monero: Svetionik anonimnosti**

Monero je osmišljen tako da daje prednost privatnosti transakcija.

# **Ethereum: Gas i transakcije**

## **Razumevanje gas-a**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u i izražava se u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) ima ograničenje gasa i osnovnu naknadu, uz prioritetnu naknadu kojom se podstiče validator da je uključi. Korisnici mogu da postave maksimalnu naknadu kako bi izbegli preplaćivanje, a višak im se vraća.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili pametnih ugovora. Za njih je potrebna naknada i moraju biti uključene u blok. Osnovni podaci transakcije obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, ograničenje gasa i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, pa nema potrebe da bude navedena u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za svakoga ko želi da koristi kriptovalute, a pritom daje prednost privatnosti i bezbednosti.

## Red Teaming Web3 sistema usmeren na vrednost

- Napravite inventar komponenti koje čuvaju vrednost (potpisivači, orakli, mostovi, automatizacija) da biste razumeli ko može da premešta sredstva i na koji način.
- Povežite svaku komponentu sa relevantnim MITRE AADAPT taktikama da biste otkrili putanje eskalacije privilegija.
- Uvežbajte lance napada flash-loan/oracle/credential/cross-chain kako biste proverili uticaj i dokumentovali preduslove za eksploataciju.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje Web3 procesa potpisivanja

- Manipulacija lancem snabdevanja korisničkih interfejsa novčanika može da izmeni EIP-712 payload-e neposredno pre potpisivanja i da prikupi važeće potpise za preuzimanje kontrole nad proxy ugovorima zasnovano na delegatecall-u (npr. prepisivanje slot-0 vrednosti Safe masterCopy-ja).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Apstrakcija naloga (ERC-4337)

- Uobičajeni načini otkaza pametnih naloga obuhvataju zaobilaženje kontrole pristupa `EntryPoint`, nepotpisana gas polja, validaciju sa promenom stanja, ERC-1271 replay napade i pražnjenje naknada usled revert-a nakon validacije.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost pametnih ugovora

- Mutation testing radi otkrivanja slepih tačaka u testnim paketima:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet ZK dokaza / zkVM gosta

Kada proverivač koristi **zkVM** ili dokazno kolo specifično za aplikaciju da bi potvrdio neku tvrdnju, saznaje samo da je **guest program izvršen onako kako je napisan**. Ako guest sadrži **nebezbednu deserijalizaciju**, **nedefinisano ponašanje** ili **nedostajuća semantička ograničenja**, zlonamerni proverivač može da generiše dokaz koji prolazi proveru iako su **javni pokazatelji ili navedena invarijanta netačni**.<sup>[[7]](#references)</sup>

### Nebezbedna deserijalizacija unutar proof guest-ova

- Tretirajte privatni witness/circuit sadržaj kao **nepouzdan unos napadača**, čak i kada je skriven dokazom.
- Izbegavajte deserijalizaciju pomoću provera koje ne obavljaju validaciju, kao što je `rkyv::access_unchecked`, osim ako su bajtovi već validirani izvan tog procesa.
- Diskriminante enum-a, relativni pokazivači, dužine i indeksi učitani iz nepouzdanih serijalizovanih podataka moraju biti validirani pre nego što utiču na tok izvršavanja ili pristup memoriji.

Praktičan obrazac za audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ako je polje kao što je `op.kind` enum, a napadač može da ubaci **discriminant van dozvoljenog opsega**, svaki nizvodni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table / UB

Ako Rust prevede veliki `match` u **jump table**, nevažeći enum discriminant može da dovede do **nedefinisanog toka kontrole**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van dozvoljenog opsega indeksira izvan prve jump table i stiže do koda povezanog sa drugom.

Rezultat: operacija se ipak izvršava, ali se putanja obračunavanja preskače. U zkVM-u, ovo može da omogući falsifikovanje dokaza koji prikazuju nemoguće metrike, kao što su manji broj gate-ova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum vrednosti pod kontrolom napadača koje se deserijalizuju iz witness/private input.
- Pregledajte ponovljene `match` iskaze nad istim opcode/kind poljem.
- Smatrajte kombinaciju `unsafe` + neproverena deserijalizacija + velika opcode dispečerska logika visokorizičnom.
- Po potrebi izvršite reverzni inženjering generisanog binarnog fajla; raspored jump table može biti važniji od izvornog koda.

### Nedostajuća semantička ograničenja u reverzibilnim/specijalizovanim interpreterima

Nemojte proveravati samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba da nametne.

Kod reverzibilnih/skupu instrukcija sličnih kvantnim, proverite da li su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija nalik Toffoli/CCX implementirana kao: <sup>[[7]](#references)[[8]](#references)</sup>

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

Ovo stvara **deterministički primitiv za resetovanje**, narušavajući pretpostavke o reverzibilnosti i omogućavajući jeftinije, nenameravane proračune. U sistemima dokaza koji potvrđuju potrošnju resursa, napadači tako mogu da zadovolje funkcionalne provere, a da zaobiđu model troškova za koji verifikator veruje da se primenjuje.

### Šta testirati u ZK sistemima

- Fuzz-ujte sve guest parsere neispravnim kodiranjima witness/private-input podataka.
- Proverite validaciju opsega enum vrednosti pre slanja instrukcije na opcode dispatch.
- Dodajte semantičke provere za aliasing operanada i druge nevažeće oblike instrukcija.
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan dokaz i dalje može da dokaže **pogrešnu tvrdnju** ako je guest program neispravan.

## Autorizacija zavisna od stanja

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacija DeFi/AMM

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotreba zaokruživanja/preciznosti, swapovi sa pragom koji se prelazi uz pojačavanje flash‑loan-om), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za multi-asset weighted pool-ove koji keširaju virtuelna stanja i mogu da budu zatrovani kada je `supply == 0`, pogledajte:

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
- [7] [Trail of Bits - Srušili smo Google-ov dokaz bez znanja za kvantnu kriptoanalizu](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zaštita kriptovaluta zasnovanih na eliptičkim krivama od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits repozitorijum sa proof-of-concept primerom](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
