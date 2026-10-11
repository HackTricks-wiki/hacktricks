# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Pametni ugovori** su programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi i automatizuju izvršavanje sporazuma bez posrednika.
- **Decentralizovane aplikacije (dApps)** nadograđuju se na pametne ugovore i imaju korisnički pristupačan front-end i transparentan back-end koji se može revidirati.
- **Tokeni i novčići** razlikuju se po tome što novčići služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenom kontekstu.
  - **Utility tokeni** omogućavaju pristup uslugama, a **security tokeni** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za decentralizovane finansije koje nude finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAO** označavaju platforme za decentralizovanu razmenu i decentralizovane autonomne organizacije.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju sigurnu i usaglašenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** se oslanja na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da poseduju određenu količinu tokena i troši manje energije nego PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju digitalnim potpisima, čime se osigurava da prenose može da pokrene samo vlasnik privatnog ključa.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature transakcije** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **ulaza** (izvor sredstava), **izlaza** (odredište), **naknada** (plaćenih rudarima) i **skripti** (pravila transakcije).

### Lightning Network

Cilj mu je da poboljša skalabilnost Bitcoina tako što omogućava više transakcija unutar kanala, a na blockchain se emituje samo konačno stanje.

## Problemi s privatnošću Bitcoina

Napadi na privatnost, kao što su **pretpostavka zajedničkog vlasništva nad ulazima** i **otkrivanje adrese za kusur UTXO-a**, iskorišćavaju obrasce transakcija. Strategije kao što su **mikseri** i **CoinJoin** poboljšavaju anonimnost tako što prikrivaju veze između transakcija korisnika.

## Anonimno pribavljanje Bitcoina

Metode obuhvataju trgovinu gotovinom, rudarenje i korišćenje miksera. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikazuje CoinJoin transakcije kao obične transakcije radi veće privatnosti.

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su razlog za zabrinutost. Evo pojednostavljenog pregleda nekoliko uobičajenih metoda pomoću kojih napadači mogu da ugroze privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Pretpostavka zajedničkog vlasništva nad ulazima**

Kombinovanje ulaza različitih korisnika u jednoj transakciji uglavnom je retko zbog složenosti takvog postupka. Zato se **često pretpostavlja da dve ulazne adrese u istoj transakciji pripadaju istom vlasniku**.

## **Otkrivanje adrese za kusur UTXO-a**

UTXO, odnosno **nepotrošeni izlaz transakcije**, mora se potrošiti u celosti u jednoj transakciji. Ako se samo deo pošalje na drugu adresu, ostatak se šalje na novu adresu za kusur. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se ugrožava privatnost.

### Primer

Da bi se to ublažilo, servisi za mešanje ili korišćenje više adresa mogu pomoći u prikrivanju vlasništva.

## **Izlaganje na društvenim mrežama i forumima**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, zbog čega je **lako povezati adresu s njenim vlasnikom**.

## **Analiza grafa transakcija**

Transakcije se mogu prikazati kao grafovi koji otkrivaju moguće veze između korisnika na osnovu toka sredstava.

## **Heuristika nepotrebnog ulaza (heuristika optimalnog kusura)**

Ova heuristika se zasniva na analizi transakcija sa više ulaza i izlaza kako bi se pogodilo koji izlaz predstavlja kusur vraćen pošiljaocu.

### Primer

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ako dodavanje novih ulaza učini izlaz za kusur većim od bilo kog pojedinačnog ulaza, to može zbuniti heuristiku.

## **Namerno ponovno korišćenje adresa**

Napadači mogu slati male iznose na ranije korišćene adrese, nadajući se da će ih primalac kombinovati sa drugim ulazima u budućim transakcijama, čime se adrese povezuju.

### Ispravno ponašanje novčanika

Novčanici bi trebalo da izbegavaju korišćenje novčića primljenih na već korišćene, prazne adrese, kako bi sprečili ovaj privacy leak.

## **Druge tehnike analize blockchain-a**

- **Tačni iznosi plaćanja:** Transakcije bez kusura verovatno se odvijaju između dve adrese u vlasništvu istog korisnika.
- **Zaokruženi iznosi:** Zaokružen iznos u transakciji sugeriše da je reč o plaćanju, dok je izlaz sa nezaokruženim iznosom verovatno kusur.
- **Otisci novčanika:** Različiti novčanici imaju jedinstvene obrasce za kreiranje transakcija, što analitičarima omogućava da prepoznaju korišćeni softver i potencijalno utvrde adresu za kusur.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može omogućiti njihovo praćenje.

## **Analiza saobraćaja**

Praćenjem mrežnog saobraćaja, napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama, ugrožavajući privatnost korisnika. Ovo naročito važi ako neki entitet upravlja velikim brojem Bitcoin čvorova, čime se povećava njegova mogućnost praćenja transakcija.

## Još

Sveobuhvatan spisak napada na privatnost i odbrana potražite na stranici [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini anonimnog pribavljanja bitcoina

- **Gotovinske transakcije**: Nabavljanje bitcoina putem gotovine.
- **Alternative gotovini**: Kupovina poklon-kartica i njihova onlajn zamena za bitcoin.
- **Rudarenje**: Najprivatniji način zarade bitcoina jeste rudarenje, naročito ako se obavlja samostalno, jer rudarski pulovi mogu saznati IP adresu rudara. [Informacije o rudarskim pulovima](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: U teoriji, krađa bitcoina mogla bi biti još jedan način anonimnog pribavljanja, ali je nezakonita i ne preporučuje se.

## Servisi za mešanje

Korišćenjem servisa za mešanje, korisnik može **da pošalje bitcoine** i zauzvrat dobije **druge bitcoine**, što otežava praćenje prvobitnog vlasnika. Međutim, za to je potrebno verovati servisu da neće čuvati logove i da će zaista vratiti bitcoine. Alternativne opcije za mešanje uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** objedinjuje više transakcija različitih korisnika u jednu, čime komplikuje pokušaje povezivanja ulaza sa izlazima. Uprkos svojoj efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje se potencijalno mogu pratiti.

Primeri transakcija u kojima je možda korišćen CoinJoin su `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Više informacija potražite na stranici [CoinJoin](https://coinjoin.io/en). Za Ethereum mikser zasnovan na pametnim ugovorima, koji razdvaja depozite od kasnijih isplata, pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) tako da izgleda kao obična transakcija, bez karakterističnih jednakih izlaza koje ima CoinJoin. Zbog toga ga je izuzetno teško otkriti, a mogao bi i da učini nevažećom heuristiku zajedničkog vlasništva nad ulazima koju koriste subjekti za nadzor transakcija.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcije poput gore navedene mogle bi biti PayJoin, čime se povećava privatnost, a istovremeno ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da oteža tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanjima da se obezbedi privatnost transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Da bi se očuvali privatnost i bezbednost, važno je sinhronizovati novčanike sa blockchain-om. Izdvajaju se dve metode:

- **Pun čvor**: Preuzimanjem celog blockchain-a, pun čvor obezbeđuje maksimalnu privatnost. Sve ikada obavljene transakcije čuvaju se lokalno, pa protivnici ne mogu da utvrde koje transakcije ili adrese interesuju korisnika.
- **Filtriranje blokova na strani klijenta**: Ova metoda podrazumeva pravljenje filtera za svaki blok u blockchain-u, što novčanicima omogućava da prepoznaju relevantne transakcije bez otkrivanja konkretnih interesovanja posmatračima mreže. Laki novčanici preuzimaju ove filtere, a cele blokove preuzimaju samo kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tor-a radi anonimnosti**

Pošto Bitcoin funkcioniše na peer-to-peer mreži, preporučuje se korišćenje Tor-a za prikrivanje IP adrese i povećanje privatnosti pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Savremeni novčanici svojim dizajnom odvraćaju od ponovne upotrebe adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Deljenjem uplate na nekoliko transakcija može se prikriti iznos transakcije i osujetiti napadi na privatnost.
- **Izbegavanje kusura**: Izbor transakcija kojima nisu potrebni izlazi za kusur povećava privatnost ometanjem metoda za otkrivanje kusura.
- **Više izlaza za kusur**: Ako izbegavanje kusura nije izvodljivo, pravljenje više izlaza za kusur i dalje može poboljšati privatnost.

# **Monero: svetionik anonimnosti**

Monero je osmišljen tako da privatnost transakcija bude prioritet.

# **Ethereum: gas i transakcije**

## **Razumevanje gas-a**

Gas meri računarski rad potreban za izvršavanje operacija na Ethereum-u, a cena mu se izražava u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) ima ograničenje gasa i osnovnu naknadu, uz prioritetnu naknadu koja podstiče validatore da je uključe. Korisnici mogu da podese maksimalnu naknadu kako ne bi platili previše, a višak im se vraća.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili pametnih ugovora. Za njih je potrebna naknada i moraju biti uključene u blok. Osnovni podaci transakcije obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, ograničenje gasa i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, pa nema potrebe da bude navedena u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za sve koji žele da koriste kriptovalute, a da pritom daju prednost privatnosti i bezbednosti.

## Crveno-timsko testiranje Web3 sistema usmereno na vrednost

- Napravite popis komponenti koje drže vrednost (potpisnici, orakuli, mostovi, automatizacija) da biste razumeli ko može da premešta sredstva i na koji način.
- Povežite svaku komponentu sa relevantnim taktikama MITRE AADAPT-a kako biste otkrili putanje eskalacije privilegija.
- Uvežbajte lance napada koji uključuju flash loan-ove, orakule, akreditive i napade između lanaca da biste potvrdili uticaj i dokumentovali preduslove za eksploataciju.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje procesa potpisivanja u Web3 sistemima

- Manipulacija komponentama lanca nabavke korisničkih interfejsa novčanika može da izmeni EIP-712 payload-e neposredno pre potpisivanja, čime se prikupljaju važeći potpisi za preuzimanje proxy-ja zasnovanih na delegatecall-u (npr. prepisivanje slot-0 vrednosti Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Apstrakcija naloga (ERC-4337)

- Uobičajeni načini otkaza pametnih naloga obuhvataju zaobilaženje kontrole pristupa `EntryPoint`, nepotpisana polja za gas, validaciju sa izmenama stanja, ERC-1271 replay napade i pražnjenje sredstava putem revert-a nakon validacije.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost pametnih ugovora

- Mutaciono testiranje radi pronalaženja slepih tačaka u testnim skupovima:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet ZK dokaza / zkVM guest-a

Kada proverivač koristi **zkVM** ili namenski dokazni sklop aplikacije da potvrdi tvrdnju, proverivač saznaje samo da je **guest program izvršen onako kako je napisan**. Ako guest sadrži **nebezbednu deserializaciju**, **nedefinisano ponašanje** ili **nedostajuća semantička ograničenja**, zlonamerni proverivač može da generiše dokaz koji prolazi verifikaciju, iako su **javni metrički podaci ili tvrđena invarijanta netačni**.<sup>[[7]](#references)</sup>

### Nebezbedna deserializacija unutar proof guest-ova

- Tretirajte privatni witness/circuit sadržaj bajtova kao **nepouzdan ulaz napadača**, čak i kada je sakriven dokazom.
- Izbegavajte njihovu deserializaciju pomoću neproverenih pomoćnih funkcija kao što je `rkyv::access_unchecked`, osim ako bajtovi već nisu nezavisno provereni.
- Diskriminante enum-a, relativni pokazivači, dužine i indeksi učitani iz nepouzdanih serijalizovanih podataka moraju se proveriti pre nego što utiču na tok kontrole ili pristup memoriji.

Praktični obrazac za reviziju:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ako je polje poput `op.kind` enum i napadač može da ubaci **discriminantu van opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table-a / UB-a

Ako Rust kompajlira veliki `match` u **jump table**, nevažeća discriminanta enum-a može da izazove **nedefinisani tok kontrole**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminanta van opsega indeksira izvan prve jump table i dospeva do koda povezanog sa drugom.

Rezultat: operacija se ipak izvršava, ali se putanja obračunavanja preskače. U zkVM-u, to može da omogući falsifikovanje dokaza koji prikazuju nemoguće metrike, kao što su manji broj gejtova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum-e pod kontrolom napadača koji se deserijalizuju iz witness/private input-a.
- Pregledajte ponovljene `match` iskaze nad istim poljem opcode/kind.
- Kombinaciju `unsafe` + neproverene deserijalizacije + velike opcode-dispatch logike smatrajte visokorizičnom.
- Po potrebi, izvršite reverse engineering emitovanog binarnog fajla; raspored jump table-a može biti važniji od izvornog koda.

### Nedostaju semantička ograničenja u reverzibilnim/specijalizovanim interpreterima

Nemojte proveravati samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba da nametne.

Kod reverzibilnih/skupu kvantnih instrukcija sličnih, proverite da li su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija slična Toffoli/CCX-u implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>

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

Ovo stvara **deterministički primitiv za resetovanje**, narušavajući pretpostavke o reverzibilnosti i omogućavajući jeftinija, nenameravana izračunavanja. U sistemima za dokazivanje koji potvrđuju korišćenje resursa, ovo može omogućiti napadačima da zadovolje funkcionalne provere, a da zaobiđu model troškova za koji verifikator veruje da se sprovodi.

### Šta testirati u ZK sistemima

- Fuzzujte sve guest parsere neispravnim enkodiranjima witness/private-input podataka.
- Potvrdite da se opseg enum vrednosti proverava pre dispečovanja opcode-a.
- Dodajte semantičke provere za aliasing operanada i druge nevažeće oblike instrukcija.
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan dokaz i dalje može da dokaže **pogrešnu tvrdnju** ako je guest program neispravan.

## Autorizacija zavisna od stanja

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacija DeFi/AMM sistema

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotreba zaokruživanja/preciznosti, swapovi sa pragom pojačani flash loan-ovima), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za pool-ove ponderisane prema više sredstava, koji keširaju virtuelna stanja i mogu biti zatrovani kada je `supply == 0`, proučite:

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
- [7] [Trail of Bits - Pobijedili smo Google-ov dokaz kvantne kriptoanalize sa nultim znanjem](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Obezbeđivanje kriptovaluta zasnovanih na eliptičnim krivama od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits repozitorijum sa dokazom koncepta](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
