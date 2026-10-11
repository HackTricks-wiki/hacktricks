# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Smart Contracts** su programi koji se izvršavaju na blockchainu kada se ispune određeni uslovi, automatizujući sprovođenje dogovora bez posrednika.
- **Decentralized Applications (dApps)** zasnivaju se na smart contracts i sadrže korisnički pristupačan front-end i transparentan, proverljiv back-end.
- **Tokens & Coins** razlikuju se po tome što coins služe kao digitalni novac, dok tokens predstavljaju vrednost ili vlasništvo u određenim kontekstima.
  - **Utility Tokens** omogućavaju pristup uslugama, a **Security Tokens** predstavljaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za Decentralized Finance, odnosno finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** označavaju platforme za decentralizovanu razmenu i decentralizovane autonomne organizacije.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** oslanja se na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da poseduju određenu količinu tokens, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju digitalnim potpisima, čime se osigurava da prenos može da pokrene samo vlasnik privatnog ključa.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (odredište), **fees** (naknade isplaćene rudarima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj mu je da poboljša skalabilnost Bitcoina tako što omogućava više transakcija unutar kanala, a na blockchain objavljuje samo konačno stanje.

## Zabrinutost u vezi sa privatnošću Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost prikrivanjem veza između transakcija korisnika.

## Anonimno sticanje Bitcoina

Metode obuhvataju trgovinu za gotovinu, rudarenje i korišćenje miksera. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikazuje CoinJoins kao uobičajene transakcije radi veće privatnosti.

# Pregled napada na privatnost Bitcoina

U svetu Bitcoina privatnost transakcija i anonimnost korisnika često su razlog za zabrinutost. Sledi pojednostavljen pregled nekoliko uobičajenih metoda kojima napadači mogu da naruše privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Pretpostavka o zajedničkom vlasništvu ulaza**

Kombinovanje ulaza različitih korisnika u jednoj transakciji uglavnom je retko zbog složenosti. Zato se **često pretpostavlja da dve adrese ulaza u istoj transakciji pripadaju istom vlasniku**.

## **Otkrivanje adrese za kusur UTXO-a**

UTXO, odnosno **Unspent Transaction Output**, mora se potrošiti u celosti u jednoj transakciji. Ako se samo deo pošalje na drugu adresu, ostatak odlazi na novu adresu za kusur. Posmatrači mogu da pretpostave da ta nova adresa pripada pošiljaocu, čime se narušava privatnost.

### Primer

Da bi se to ublažilo, mogu se koristiti usluge mešanja ili više adresa radi prikrivanja vlasništva.

## **Izlaganje na društvenim mrežama i forumima**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, zbog čega je **lako povezati adresu sa njenim vlasnikom**.

## **Analiza grafa transakcija**

Transakcije se mogu prikazati kao grafovi koji otkrivaju moguće veze između korisnika na osnovu kretanja sredstava.

## **Heuristika nepotrebnog ulaza (heuristika optimalnog kusura)**

Ova heuristika se zasniva na analizi transakcija sa više ulaza i izlaza kako bi se pogodilo koji izlaz predstavlja kusur koji se vraća pošiljaocu.

### Primer

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ako dodavanje novih ulaza učini izlaznu kusur-transakciju većom od bilo kog pojedinačnog ulaza, to može zbuniti heuristiku.

## **Nametnuta ponovna upotreba adresa**

Napadači mogu slati male iznose na ranije korišćene adrese, nadajući se da će primalac te iznose kombinovati sa drugim ulazima u budućim transakcijama i tako povezati adrese.

### Ispravno ponašanje novčanika

Novčanici bi trebalo da izbegavaju upotrebu novčića primljenih na već korišćenim, praznim adresama kako bi sprečili ovo narušavanje privatnosti.

## **Druge tehnike blockchain analize**

- **Tačni iznosi plaćanja:** Transakcije bez kusura verovatno se odvijaju između dve adrese koje pripadaju istom korisniku.
- **Zaokruženi iznosi:** Zaokružen iznos u transakciji sugeriše da je reč o plaćanju, dok je izlaz sa nezaokruženim iznosom verovatno kusur.
- **Otisci novčanika:** Različiti novčanici imaju jedinstvene obrasce za kreiranje transakcija, što analitičarima omogućava da prepoznaju korišćeni softver i potencijalno utvrde koja je adresa za kusur.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može omogućiti njihovo praćenje.

## **Analiza saobraćaja**

Praćenjem mrežnog saobraćaja napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama, čime ugrožavaju privatnost korisnika. To naročito važi ako neki entitet upravlja velikim brojem Bitcoin čvorova, što mu omogućava da bolje prati transakcije.

## Više informacija

Sveobuhvatan spisak napada na privatnost i odbrana potražite na stranici [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini anonimnog pribavljanja bitcoina

- **Gotovinske transakcije**: Nabavljanje bitcoina za gotovinu.
- **Alternative gotovini**: Kupovina poklon-kartica i njihova onlajn zamena za bitcoin.
- **Rudarenje**: Najprivatniji način sticanja bitcoina jeste rudarenje, naročito kada se obavlja samostalno, jer rudarski bazeni mogu znati IP adresu rudara. [Informacije o rudarskim bazenima](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: Teoretski, krađa bitcoina mogla bi biti još jedan način anonimnog pribavljanja, ali je nezakonita i ne preporučuje se.

## Usluge mešanja

Korišćenjem usluge mešanja korisnik može da **pošalje bitcoine** i zauzvrat dobije **druge bitcoine**, što otežava praćenje prvobitnog vlasnika. Međutim, za to je potrebno verovati da usluga neće čuvati evidenciju i da će zaista vratiti bitcoine. Alternativne mogućnosti mešanja uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** spaja više transakcija različitih korisnika u jednu, otežavajući svakome ko pokušava da poveže ulaze sa izlazima. Iako je efikasan, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje je potencijalno moguće pratiti.

Primeri transakcija za koje je možda korišćen CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Više informacija potražite na stranici [CoinJoin](https://coinjoin.io/en). Za Ethereum mikser zasnovan na pametnom ugovoru, koji odvaja depozite od kasnijih povlačenja, pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) tako da izgleda kao obična transakcija, bez karakterističnih jednakih izlaza kakve ima CoinJoin. Zbog toga ju je izuzetno teško otkriti, a mogla bi i da obori heuristiku zajedničkog vlasništva nad ulazima koju koriste subjekti za nadzor transakcija.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcije poput gornje mogle bi biti PayJoin, čime se poboljšava privatnost, a transakcije ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi znatno da naruši tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanju da se obezbedi privatnost transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Za očuvanje privatnosti i bezbednosti ključno je sinhronizovati novčanike sa blockchain-om. Izdvajaju se dva metoda:

- **Full node**: Preuzimanjem celog blockchain-a, full node obezbeđuje maksimalnu privatnost. Sve ikada obavljene transakcije čuvaju se lokalno, pa protivnici ne mogu da utvrde koje transakcije ili adrese zanimaju korisnika.
- **Filtriranje blokova na strani klijenta**: Ovaj metod podrazumeva kreiranje filtera za svaki blok u blockchain-u, što novčanicima omogućava da pronađu relevantne transakcije, a da posmatračima mreže ne otkriju šta korisnika zanima. Laki novčanici preuzimaju ove filtere, a cele blokove pribavljaju samo kada pronađu podudaranje sa korisnikovim adresama.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin funkcioniše u peer-to-peer mreži, preporučuje se korišćenje Tor-a za prikrivanje IP adrese i povećanje privatnosti pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može da naruši privatnost povezivanjem transakcija sa istim entitetom. Savremeni novčanici svojim dizajnom odvraćaju od ponovne upotrebe adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Podelom uplate na nekoliko transakcija može se prikriti iznos transakcije i osujetiti napadi na privatnost.
- **Izbegavanje kusura**: Izbor transakcija kojima nisu potrebni izlazi za kusur poboljšava privatnost tako što ometa metode za otkrivanje kusura.
- **Više izlaza za kusur**: Ako kusur nije moguće izbeći, kreiranje više izlaza za kusur i dalje može da poboljša privatnost.

# **Monero: svetionik anonimnosti**

Monero je osmišljen tako da daje prednost privatnosti transakcija.

# **Ethereum: gas i transakcije**

## **Razumevanje gasa**

Gas meri računarski rad potreban za izvršavanje operacija na Ethereum-u i izražava se u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) ima ograničenje gasa i osnovnu naknadu, uz prioritetnu naknadu koja podstiče validatora da je uključi. Korisnici mogu da postave maksimalnu naknadu kako bi izbegli preplaćivanje, a višak im se vraća.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u obuhvataju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili pametnih ugovora. Za njih je potrebna naknada i moraju biti uključene u blok. Osnovni podaci transakcije obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, ograničenje gasa i naknade. Važno je da se adresa pošiljaoca izvodi iz potpisa, pa nema potrebe da bude navedena u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju osnovu za svakoga ko želi da koristi kriptovalute, a pritom daje prednost privatnosti i bezbednosti.

## Red Teaming za Web3 usmeren na vrednost

- Napravite popis komponenti koje drže ili prenose vrednost (potpisnici, oracles, bridges, automatizacija) da biste utvrdili ko može da premešta sredstva i na koji način.
- Povežite svaku komponentu sa relevantnim taktikama MITRE AADAPT-a da biste otkrili puteve eskalacije privilegija.
- Uvežbajte lance napada koji uključuju flash-loan/oracle/credential/cross-chain kako biste proverili uticaj i dokumentovali uslove koji omogućavaju eksploataciju.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje toka potpisivanja u Web3

- Manipulacija interfejsima wallet-a u lancu snabdevanja može da izmeni EIP-712 podatke neposredno pre potpisivanja i pribavi važeće potpise za preuzimanje kontrole nad proxy-jem zasnovanim na delegatecall-u (npr. prepisivanje slot-0 vrednosti Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Apstrakcija naloga (ERC-4337)

- Uobičajeni načini otkaza pametnih naloga obuhvataju zaobilaženje kontrole pristupa `EntryPoint`-a, nepotpisana polja za gas, validaciju sa promenljivim stanjem, ERC-1271 replay i iscrpljivanje sredstava za naknade putem revert-a nakon validacije.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost pametnih ugovora

- Mutation testing za otkrivanje slepih tačaka u testnim paketima:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet ZK dokaza / gostujućeg programa zkVM-a

Kada proverivač koristi **zkVM** ili aplikaciono specifično dokazno kolo za potvrdu tvrdnje, on saznaje samo da je **gostujući program izvršen onako kako je napisan**. Ako gostujući program sadrži **nebezbednu deserializaciju**, **nedefinisano ponašanje** ili **nedostajuća semantička ograničenja**, zlonamerni dokazivač može da generiše dokaz koji prolazi proveru, iako su **javne metrike ili navedena invarijanta netačne**.<sup>[[7]](#references)</sup>

### Nebezbedna deserializacija unutar gostujućih programa dokaza

- Tretirajte privatni witness/circuit sadržaj kao **nepouzdan ulaz napadača**, čak i kada je sakriven dokazom.
- Izbegavajte deserializaciju pomoću neproverenih pomoćnih funkcija kao što je `rkyv::access_unchecked`, osim ako su podaci već validirani van tog procesa.
- Enum diskriminante, relativne pokazivače, dužine i indekse učitane iz nepouzdanih serijalizovanih podataka treba validirati pre nego što utiču na tok izvršavanja ili pristup memoriji.

Praktičan obrazac za audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ako je polje kao što je `op.kind` enum, a napadač može da ubaci **diskriminantu van dozvoljenog opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table / UB

Ako Rust prevede veliki `match` u **jump table**, nevažeća diskriminanta enuma može da dovede do **nedefinisanog toka kontrole**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Diskriminanta van dozvoljenog opsega indeksira izvan prve jump table i stiže do koda povezanog sa drugom.

Rezultat: operacija se i dalje izvršava, ali se putanja za obračun preskače. U zkVM-u to može da omogući falsifikovanje dokaza koji prikazuju nemoguće metrike, kao što su manji broj gate-ova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum vrednosti pod kontrolom napadača koje se deserijalizuju iz witness/private input-a.
- Pregledajte ponovljene `match` naredbe nad istim poljem opcode/kind.
- Tretirajte kombinaciju `unsafe` + deserijalizacije bez provera + velike opcode dispečerske logike kao visokorizičnu.
- Po potrebi izvršite reverse engineering generisanog binarnog fajla; raspored jump table može biti važniji od izvornog koda.

### Nedostajuća semantička ograničenja u reverzibilnim/specijalizovanim interpreter-ima

Nemojte proveravati samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba da sprovodi.

Kod reverzibilnih/skupova instrukcija nalik kvantnim, uverite se da su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija nalik Toffoli/CCX implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

postaje nebezbedno ako gost ne odbije:

```text
op.q_control1 == op.q_control2 == op.q_target
```

U tom slučaju se prelaz svodi na:

```text
q = q ^ (q & q) = 0
```

Ovo stvara **deterministički primitiv za resetovanje**, narušavajući pretpostavke o reverzibilnosti i omogućavajući jeftinije nenameravane proračune. U sistemima dokaza koji potvrđuju upotrebu resursa, ovo može omogućiti napadačima da zadovolje funkcionalne provere, a da pritom zaobiđu model troškova za koji verifikator veruje da se sprovodi.

### Nedovoljno ograničeni saveti proverača i modularna aritmetika

Vrednostima učitanim sa **stek-a saveta/svedoka upravlja proverač**, čak i kada su opisane kao unapred izračunati količnici, ostaci, inverzi ili nagoveštaji. Dokaz samo potvrđuje da svedok zadovoljava implementirana ograničenja; on ne potvrđuje da je izvršen željeni proračun ako ta ograničenja ne uključuju proveru tipa, opsega ili kanonskog oblika.<sup>[[13]](#references)</sup>

Kod pomoćne funkcije za redukciju ili Euklidsko deljenje, proverite celokupnu celobrojnu relaciju, a ne samo završno oduzimanje ili množenje. Svaka reč `q` i `r` mora biti ograničena na deklarisanu širinu, mora važiti rekonstrukcija `x = q * m + r` u predviđenoj celobrojnoj reprezentaciji, a kanonska granica `0 <= r < m` mora biti nametnuta. Proverite vrednost **pre** nego što je prosledite užoj instrukciji `u32`/`u64`; uska operacija ne dokazuje naknadno da su prvobitni element polja ili višerečni broj imali očekivani tip.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Greška `mod_12289` u Miden-u pokazuje obrazac eksploatacije: količnik je proveren kao 64-bitna vrednost od dva sloga, ali ostatak dobijen iz advice-a prosleđen je funkciji `u32overflowing_sub` bez ekvivalentne provere. Zlonamerni dokazivač mogao je da uskladi nevažeće vrednosti količnika i ostatka tako da implementirana ograničenja oduzimanja i dalje važe, dok procedura vraća matematički neispravan ostatak. Pošto je ovaj rezultat korišćen u Falcon verifikaciji, propust u bezbednosti dokazivanja mogao je da se iskoristi za falsifikovanje potpisa za autorizaciju, umesto da se samo dobije pogrešan aritmetički rezultat.<sup>[[13]](#references)</sup>

### Revizija kriptografskih VM-ova sa implicitnim stekom

Jezici zasnovani na steku skrivaju operande, pa najpre podignite instrukcije u IR u kojem je svaka potrošena i proizvedena vrednost steka predstavljena izrazom sa poreklom. Konzervativni tok analize zatim može da:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Izgradi graf poziva i zaključi ulazne/izlazne efekte steka procedura.
2. Simbolički izvrši podržane instrukcije i podigne tok kontrole u SSA/strukturirane izraze.
3. Propagira apstraktne činjenice, kao što su `Unknown`, `ProvenU32`, `Bool`, poreklo vrednosti i lokalna inicijalizacija, do dostizanja fiksne tačke.
4. Označi vrednosti izvedene iz advice-a koje dospeju do tipizirane aritmetike ili odredišta koja zahtevaju vrednost različitu od nule, a da nisu validirane na **svakoj** ulaznoj putanji.
5. Uporedi deklarisane i izvedene potpise i proveri da li svaki izlaz čuva vrednosti steka koje pripadaju pozivaocu.

Nepoznat potpis ili nepodržanu konstrukciju tretirajte kao **prazninu u analizi**, a ne kao čist rezultat. Dinamički pozivi, petlje koje ne čuvaju strukturu steka i grane sa različitim efektima steka mogu onemogućiti pouzdano praćenje pozicija na steku; bezbedniji dekompajler odbacuje ili označava ove slučajeve umesto da emituje uverljiv, ali netačan pseudokod.<sup>[[10]](#references)[[13]](#references)</sup>

Na mestima spajanja tokova kontrole zadržite svojstvo samo ako važi za svakog prethodnika (na primer, `ProvenU32 join Unknown = Unknown`). Takođe razlikujte dostizanje fiksne tačke od prekoračenja ograničenja broja iteracija: samo konvergirana, zvučna nadaproksimacija može opravdati tretiranje odsustva dijagnostičke poruke kao dokaza da sve predstavljene izvršne putanje zadovoljavaju svojstvo.<sup>[[11]](#references)</sup>

### Koristite obaveze dokazivanja da biste otkrili skrivene preduslove

Za male skupove instrukcija prevedite procedure u izvršiv formalni VM model i dokažite i rezultat i celokupnu transformaciju steka. Teorema treba da obuhvati terminaciju, tipizirane ulaze, očekivani prefiks izlaza i očuvanje netaknutog steka pozivaoca. Pažljivo proverite iskaz teoreme kao i dokaz: kernel može da potvrdi dokaz slučajno oslabljene tvrdnje.<sup>[[12]](#references)[[13]](#references)</sup>

Neočekivane hipoteze su korisni nalazi. U Miden-ovoj reviziji, dokaz za 64-bitnu rotaciju udesno zahtevao je `shift mod 32 != 0`, čime je otkriven rubni slučaj koji ne radi za velike ulaze kada je pomeraj višekratnik broja 32; drugi dokaz je pokazao da je 256-bitni `wrapping_mul` odbacivao vrednosti steka koje pripadaju pozivaocu. Dodajte otkriveni rubni slučaj u testove, a zatim ispravite implementaciju ili namerno pooštrite javni preduslov, umesto da prećutno prihvatite dodatnu pretpostavku.<sup>[[12]](#references)[[13]](#references)</sup>

### Šta testirati u ZK sistemima

- Fuzz-ujte sve guest parser-e sa neispravno formatiranim kodiranjima witness/private-input podataka.
- Proverite validaciju opsega enum vrednosti pre dispečovanja opcode-a.
- Dodajte semantičke provere za preklapanje operanada i druge nevažeće oblike instrukcija.
- Pratite svaki izvor advice/witness podataka do svakog tipiziranog aritmetičkog odredišta i zahtevajte validaciju na svakoj putanji.<sup>[[11]](#references)[[13]](#references)</sup>
- Testirajte aritmetičke pomoćne funkcije sa nekanonskim slogovima, ostacima van dozvoljenog opsega i graničnim vrednostima pomeraja.<sup>[[12]](#references)[[13]](#references)</sup>
- Proverite visinu steka i očuvanje vrednosti ispod deklarisanih argumenata procedure pri svakom povratku.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan dokaz i dalje može dokazivati **pogrešnu tvrdnju** ako je guest program neispravan.

## Autorizacija zavisna od stanja

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacija DeFi/AMM sistema

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotrebu zaokruživanja/preciznosti, swap-ove sa flash loan-om koji pojačavaju prelazak praga), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za pool-ove sa ponderisanim višestrukim sredstvima koji keširaju virtuelna stanja i mogu biti zatrovani kada je `supply == 0`, proučite:

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
- [8] [Zaštita kriptovaluta zasnovanih na eliptičkim krivama od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits repozitorijum sa proof-of-concept kodom](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arhitektura MASM dekompajlera](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM mehanizam za statičku analizu](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean model i dokazi ispravnosti](https://github.com/trailofbits/masm-lean)
- [13] [Revizija u dobu (dovoljno dobrog) AI-ja](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
