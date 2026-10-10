# Blokčejn i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni koncepti

- **Pametni ugovori** su programi koji se izvršavaju na blokčejnu kada se ispune određeni uslovi i automatizuju izvršavanje sporazuma bez posrednika.
- **Decentralizovane aplikacije (dApps)** zasnivaju se na pametnim ugovorima i imaju korisnički prilagođen front-end i transparentan back-end koji se može proveriti.
- **Tokeni i novčići** se razlikuju po tome što novčići služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenom kontekstu.
  - **Utility tokeni** omogućavaju pristup uslugama, a **Security tokeni** označavaju vlasništvo nad imovinom.
- **DeFi** je skraćenica za Decentralized Finance i nudi finansijske usluge bez centralnih organa.
- **DEX** i **DAO** označavaju decentralizovane platforme za razmenu i decentralizovane autonomne organizacije.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju bezbednu i usaglašenu validaciju transakcija na blokčejnu:

- **Proof of Work (PoW)** koristi računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva da validatori poseduju određenu količinu tokena, čime se smanjuje potrošnja energije u poređenju sa PoW.<sup>[[1]](#references)</sup>

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju digitalnim potpisima, čime se osigurava da prenos može da pokrene samo vlasnik privatnog ključa.<sup>[[2]](#references)</sup>

#### Ključne komponente:

- **Multisignature transakcije** zahtevaju više potpisa za autorizaciju transakcije.<sup>[[3]](#references)</sup>
- Transakcije se sastoje od **ulaza** (izvor sredstava), **izlaza** (odredište), **naknada** (plaćenih rudarima) i **skripti** (pravila transakcije).

### Lightning Network

Cilj je da se poveća skalabilnost Bitcoina tako što se omogućava više transakcija unutar kanala, dok se na blokčejnu objavljuje samo konačno stanje.

## Problemi sa privatnošću Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost prikrivanjem veza između transakcija korisnika.

## Anonimno sticanje Bitcoina

Metode obuhvataju kupovinu i prodaju za gotovinu, rudarenje i korišćenje miksera. **CoinJoin** kombinuje više transakcija kako bi otežao njihovo praćenje, dok **PayJoin** prikazuje CoinJoin transakcije kao obične transakcije radi veće privatnosti.

# Pregled napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su razlog za zabrinutost. U nastavku je pojednostavljen pregled nekoliko uobičajenih načina na koje napadači mogu da ugroze privatnost Bitcoina.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Uglavnom je retko da se ulazi različitih korisnika kombinuju u jednoj transakciji zbog složenosti takvog postupka. Zato se često pretpostavlja da **dve ulazne adrese u istoj transakciji pripadaju istom vlasniku**.

## **UTXO Change Address Detection**

UTXO, odnosno **Unspent Transaction Output**, mora se u potpunosti potrošiti u transakciji. Ako se samo deo pošalje na drugu adresu, ostatak se šalje na novu adresu za kusur. Posmatrači mogu da pretpostave da ta nova adresa pripada pošiljaocu, čime se narušava privatnost.

### Primer

Da bi se to ublažilo, mogu se koristiti servisi za mešanje ili više adresa kako bi se prikrilo vlasništvo.

## **Izlaganje na društvenim mrežama i forumima**

Korisnici ponekad dele svoje Bitcoin adrese na internetu, zbog čega je **lako povezati adresu sa njenim vlasnikom**.

## **Analiza grafa transakcija**

Transakcije se mogu prikazati kao grafovi koji otkrivaju moguće veze između korisnika na osnovu kretanja sredstava.

## **Heuristika nepotrebnog ulaza (heuristika optimalnog kusura)**

Ova heuristika se zasniva na analizi transakcija sa više ulaza i izlaza kako bi se procenilo koji izlaz predstavlja kusur vraćen pošiljaocu.

### Primer

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ako dodavanje još ulaza učini da izlazna kusurina bude veća od bilo kog pojedinačnog ulaza, to može zbuniti heuristiku.

## **Prisilna ponovna upotreba adresa**

Napadači mogu slati male iznose na ranije korišćene adrese, nadajući se da će primalac te iznose spojiti sa drugim ulazima u budućim transakcijama i tako povezati adrese.

### Ispravno ponašanje novčanika

Novčanici bi trebalo da izbegavaju korišćenje novčića primljenih na već korišćenim, praznim adresama kako bi sprečili ovo narušavanje privatnosti.

## **Druge tehnike analize blockchain-a**

- **Tačni iznosi plaćanja:** Transakcije bez kusurine verovatno se odvijaju između dve adrese koje pripadaju istom korisniku.
- **Zaokruženi iznosi:** Zaokružen iznos u transakciji ukazuje na to da je reč o plaćanju, dok je izlaz sa nezaokruženim iznosom verovatno kusurina.
- **Otiskivanje novčanika:** Različiti novčanici imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da prepoznaju korišćeni softver i potencijalno adresu za kusurinu.
- **Korelacije iznosa i vremena:** Otkrivanje vremena ili iznosa transakcija može omogućiti njihovo praćenje.

## **Analiza saobraćaja**

Praćenjem mrežnog saobraćaja napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama i tako ugroziti privatnost korisnika. Ovo naročito važi ako neki entitet upravlja velikim brojem Bitcoin čvorova, čime povećava svoju mogućnost nadgledanja transakcija.

## Više informacija

Sveobuhvatan spisak napada na privatnost i odbrana potražite na stranici [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini anonimnog pribavljanja bitcoina

- **Gotovinske transakcije**: Pribavljanje bitcoina gotovinom.
- **Alternative gotovini**: Kupovina poklon-kartica i njihova onlajn zamena za bitcoin.
- **Rudarenje**: Najprivatniji način zarade bitcoina jeste rudarenje, naročito ako se obavlja samostalno, jer rudarski pulovi mogu znati IP adresu rudara. [Informacije o rudarskim pulovima](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: U teoriji, krađa bitcoina mogla bi biti još jedan način anonimnog pribavljanja, ali je nezakonita i ne preporučuje se.

## Usluge mešanja

Korišćenjem usluge mešanja, korisnik može da **pošalje bitcoine** i zauzvrat dobije **druge bitcoine**, što otežava praćenje prvobitnog vlasnika. Međutim, za to je potrebno verovati usluzi da neće čuvati evidenciju i da će zaista vratiti bitcoine. Alternativne opcije za mešanje uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** objedinjuje više transakcija različitih korisnika u jednu, čime se otežava uparivanje ulaza sa izlazima. Uprkos svojoj efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje se potencijalno mogu pratiti.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Više informacija potražite na stranici [CoinJoin](https://coinjoin.io/en). Za Ethereum mikser zasnovan na pametnom ugovoru koji razdvaja depozite od kasnijih isplata, pogledajte [Tornado Cash](https://tornado.cash).

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) tako da izgleda kao obična transakcija, bez karakterističnih jednakih izlaza koji se javljaju kod CoinJoin-a. Zbog toga ju je izuzetno teško otkriti, a mogla bi da učini nevažećom heuristiku zajedničkog vlasništva nad ulazima koju koriste subjekti za nadzor transakcija.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transakcije poput gornje mogu biti PayJoin, čime se poboljšava privatnost, a istovremeno ostaju nerazlučive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da poremeti tradicionalne metode nadzora**, što ga čini obećavajućim razvojem u nastojanjima da se obezbedi privatnost transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Radi očuvanja privatnosti i bezbednosti, ključno je sinhronizovati novčanike sa blockchain-om. Izdvajaju se dve metode:

- **Full node**: Preuzimanjem celog blockchain-a, full node obezbeđuje maksimalnu privatnost. Sve ikada izvršene transakcije čuvaju se lokalno, pa protivnici ne mogu da utvrde koje transakcije ili adrese zanimaju korisnika.
- **Filtriranje blokova na strani klijenta**: Ova metoda podrazumeva kreiranje filtera za svaki blok u blockchain-u, što novčanicima omogućava da pronađu relevantne transakcije bez otkrivanja konkretnih interesovanja posmatračima mreže. Laki novčanici preuzimaju te filtere, a cele blokove preuzimaju samo kada se pronađe podudaranje sa korisnikovim adresama.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin radi preko peer-to-peer mreže, preporučuje se korišćenje Tor-a za prikrivanje IP adrese i veću privatnost pri povezivanju sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Radi zaštite privatnosti važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Savremeni novčanici su dizajnirani tako da obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Deljenje plaćanja na nekoliko transakcija može da prikrije iznos transakcije i osujeti napade na privatnost.
- **Izbegavanje kusura**: Odabir transakcija koje ne zahtevaju izlaze za kusur poboljšava privatnost tako što ometa metode za otkrivanje kusura.
- **Više izlaza za kusur**: Ako izbegavanje kusura nije izvodljivo, kreiranje više izlaza za kusur i dalje može da poboljša privatnost.

# **Monero: svetionik anonimnosti**

Monero je osmišljen tako da privatnost transakcija bude prioritet.

# **Ethereum: gas i transakcije**

## **Razumevanje gasa**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u, a cena mu se izražava u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje ograničenje gasa i osnovnu naknadu, uz prioritetnu naknadu kojom se podstiču validatori da je uključe. Korisnici mogu da postave maksimalnu naknadu kako bi izbegli preplaćivanje, a višak im se vraća.<sup>[[5]](#references)</sup>

## **Izvršavanje transakcija**

Transakcije na Ethereum-u obuhvataju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili pametnih ugovora. Za njih je potrebna naknada i moraju biti uključene u blok. Osnovni podaci transakcije obuhvataju primaoca, potpis pošiljaoca, vrednost, opcione podatke, ograničenje gasa i naknade. Važno je napomenuti da se adresa pošiljaoca izvodi iz potpisa, pa nije potrebno navoditi je u podacima transakcije.<sup>[[4]](#references)</sup>

Ove prakse i mehanizmi predstavljaju temelj za sve koji žele da koriste kriptovalute, uz davanje prioriteta privatnosti i bezbednosti.

## Red Teaming u Web3 usmeren na vrednost

- Napravite inventar komponenti koje upravljaju vrednostima (signeri, oracle-i, bridge-ovi, automatizacija) da biste utvrdili ko može da premešta sredstva i na koji način.
- Povežite svaku komponentu sa relevantnim taktikama MITRE AADAPT-a kako biste otkrili puteve eskalacije privilegija.
- Uvežbajte lance napada koji uključuju flash-loan/oracle/credential/cross-chain kako biste potvrdili uticaj i dokumentovali preduslove za eksploataciju.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromitovanje toka potpisivanja u Web3

- Manipulacija u lancu snabdevanja korisničkim interfejsima novčanika može da izmeni EIP-712 podatke neposredno pre potpisivanja i prikupi važeće potpise za preuzimanje proxy-ja zasnovano na delegatecall-u (npr. prepisivanjem slot-0 vrednosti Safe masterCopy-ja).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Apstrakcija naloga (ERC-4337)

- Uobičajeni načini otkazivanja pametnih naloga obuhvataju zaobilaženje kontrole pristupa `EntryPoint`-u, nepotpisana gas polja, validaciju sa stanjem, ERC-1271 replay i iscrpljivanje naknada usled revert-a nakon validacije.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Bezbednost pametnih ugovora

- Korišćenje mutation testing-a za pronalaženje slepih tačaka u testnim paketima:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integritet ZK dokaza / zkVM guest-a

Kada proverilac dokaza koristi **zkVM** ili dokazno kolo specifično za aplikaciju da potvrdi tvrdnju, verifikator saznaje samo da je **guest program izvršen onako kako je napisan**. Ako guest sadrži **nesigurnu deserijalizaciju**, **nedefinisano ponašanje** ili **nedostajuća semantička ograničenja**, zlonamerni proverilac može da generiše dokaz koji prolazi proveru iako su **javni metrički podaci ili navedena invarijanta netačni**.<sup>[[7]](#references)</sup>

### Nesigurna deserijalizacija unutar proof guest-ova

- Tretirajte privatne witness/circuit bajtove kao **nepouzdan korisnički ulaz koji može biti zlonameran**, čak i ako ih dokaz skriva.
- Izbegavajte njihovu deserijalizaciju pomoću neproverenih pomoćnih funkcija kao što je `rkyv::access_unchecked`, osim ako bajtovi nisu prethodno provereni na drugi način.
- Vrednosti enum diskriminanata, relativni pokazivači, dužine i indeksi učitani iz nepouzdanih serijalizovanih podataka moraju biti provereni pre nego što utiču na tok izvršavanja ili pristup memoriji.

Praktični obrazac za audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ako je polje poput `op.kind` enum i napadač može da ubaci **discriminant van dozvoljenog opsega**, svaki naredni `match` nad tom vrednošću postaje sumnjiv.

### Zaobilaženje brojača pomoću jump table / UB

Ako Rust prevede veliki `match` u **jump table**, nevažeći discriminant enuma može dovesti do **nedefinisanog toka izvršavanja**. Opasan obrazac je:<sup>[[7]](#references)[[9]](#references)</sup>

1. Jedan `match` ažurira **bezbednosno kritične brojače/ograničenja**.
2. Drugi `match` izvršava **stvarnu semantiku instrukcije**.
3. Discriminant van dozvoljenog opsega indeksira izvan prve jump table i prelazi na kod povezan sa drugom.

Rezultat: operacija se i dalje izvršava, ali se putanja za obračun preskače. U zkVM-u to može da omogući falsifikovanje dokaza koji prijavljuju nemoguće metrike, kao što su manji broj gate-ova, manji broj skupih operacija ili drugi falsifikovani ograničeni resursi.

Kontrolna lista za pregled:

- Potražite enum-e pod kontrolom napadača koji se deserijalizuju iz witness/private input-a.
- Pregledajte ponovljene `match` naredbe nad istim poljem opcode/kind.
- Tretirajte kombinaciju `unsafe` + deserijalizacija bez provera + velika opcode dispečerska logika kao visokorizičnu.
- Po potrebi izvršite obrnuti inženjering emitovanog binarnog fajla; raspored jump table može biti važniji od izvornog koda.

### Nedostajuća semantička ograničenja u reverzibilnim/specijalizovanim interpreterima

Nemojte proveravati samo bezbednost memorije; proverite i **semantička pravila** koja dokaz treba da nametne.

Kod reverzibilnih/skupova instrukcija nalik kvantnim, uverite se da su operandi koji moraju biti različiti zaista ograničeni tako da budu različiti. Operacija nalik Toffoli/CCX, implementirana kao:<sup>[[7]](#references)[[8]](#references)</sup>

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

This stvara **determinističku primitivu resetovanja**, narušavajući pretpostavke o reverzibilnosti i omogućavajući jeftinije nenameravane proračune. U sistemima za dokazivanje koji potvrđuju utrošak resursa, ovo može omogućiti napadačima da prođu funkcionalne provere, a da zaobiđu model troškova za koji verifier veruje da se primenjuje.

### Šta testirati u ZK sistemima

- Fuzzujte sve guest parsere neispravnim kodiranjima witness/private-input podataka.
- Proverite validaciju opsega enum vrednosti pre dispatch-a opcode-a.
- Dodajte semantičke provere aliasovanja operanada i drugih neispravnih oblika instrukcija.
- Uporedite prijavljene/javne brojače sa nezavisnom referentnom implementacijom.
- Imajte na umu da validan dokaz i dalje može dokazivati **pogrešnu tvrdnju** ako je guest program neispravan.

## Autorizacija zavisna od stanja

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Eksploatacija DeFi/AMM

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, zloupotreba zaokruživanja/preciznosti, swapovi sa pojačanim pragovima pomoću flash-loan-ova), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za ponderisane pool-ove sa više sredstava koji keširaju virtuelna stanja i mogu biti zatrovani kada je `supply == 0`, proučite:

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
- [7] [Trail of Bits - Srušili smo Google-ov dokaz o kvantnoj kriptoanalizi sa nultim znanjem](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Zaštita kriptovaluta zasnovanih na eliptičnim krivama od kvantnih ranjivosti: procene resursa i mere ublažavanja (zakrpljena verzija)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repozitorijum za proof-of-concept kompanije Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
