# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** se definišu kao programi koji se izvršavaju na blockchain-u kada su ispunjeni određeni uslovi, automatizujući izvršenje sporazuma bez posrednika.
- **Decentralized Applications (dApps)** nadograđuju Smart Contracts, sa korisnički prijatnim front-end-om i transparentnim, audibilnim back-end-om.
- **Tokens & Coins** prave razliku gde coins služe kao digitalni novac, dok tokens predstavljaju vrednost ili vlasništvo u specifičnim kontekstima.
- **Utility Tokens** omogućavaju pristup uslugama, a **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** označava Decentralized Finance, pružajući finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** se odnose na Decentralized Exchange Platforms i Decentralized Autonomous Organizations, respektivno.

## Consensus Mechanisms

Mehanizmi konsenzusa obezbeđuju sigurnu i dogovorenu verifikaciju transakcija na blockchain-u:

- **Proof of Work (PoW)** se oslanja na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da drže određenu količinu tokena, smanjujući potrošnju energije u odnosu na PoW.

## Bitcoin Essentials

### Transactions

Bitcoin transakcije uključuju prenos sredstava između adresa. Transakcije se verifikuju digitalnim potpisima, osiguravajući da samo vlasnik privatnog ključa može inicirati transfer.

#### Key Components:

- **Multisignature Transactions** zahtevaju više potpisa da bi autorizovali transakciju.
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (destinacija), **fees** (plaćaju se minerima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj je poboljšanje skalabilnosti Bitcoina omogućavanjem više transakcija unutar kanala, pri čemu se samo konačno stanje emituje na blockchain.

## Bitcoin Privacy Concerns

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, eksploatišu obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost zamagljivanjem veza između transakcija i korisnika.

## Acquiring Bitcoins Anonymously

Metode uključuju trgovinu za gotovinu, mining, i korišćenje mixers. **CoinJoin** meša više transakcija kako bi otežao trasabilnost, dok **PayJoin** prikriva CoinJoins kao obične transakcije za poboljšanu privatnost.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmet zabrinutosti. Evo pojednostavljenog pregleda nekoliko uobičajenih metoda putem kojih napadači mogu kompromitovati Bitcoin privatnost.

## **Common Input Ownership Assumption**

Generalno je retko da se inputi iz različitih korisnika kombinuju u jednoj transakciji zbog složenosti koja je uključena. Dakle, **dve input adrese u istoj transakciji se često smatraju da pripadaju istom vlasniku**.

## **UTXO Change Address Detection**

UTXO, ili **Unspent Transaction Output**, mora biti u potpunosti potrošen u transakciji. Ako je samo deo poslat na drugu adresu, ostatak ide na novu change adresu. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se narušava privatnost.

### Example

Da bi se to ublažilo, mixing servisi ili korišćenje više adresa mogu pomoći da se prikrije vlasništvo.

## **Social Networks & Forums Exposure**

Korisnici ponekad dele svoje Bitcoin adrese online, što olakšava **povezivanje adrese sa njenim vlasnikom**.

## **Transaction Graph Analysis**

Transakcije se mogu vizualizovati kao grafovi, otkrivajući potencijalne veze između korisnika na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika se zasniva na analizi transakcija sa više inputa i outputa kako bi se pogodilo koji output je change koji se vraća pošiljaocu.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If dodavanje više inputa učini change output većim od bilo kog pojedinačnog inputa, to može da zbuni heuristiku.

## **Forced Address Reuse**

Napadači mogu poslati male iznose na ranije korišćene adrese, nadajući se da će primalac kombinovati te iznose sa drugim ulazima u budućim transakcijama, čime će povezati adrese.

### Correct Wallet Behavior

Novčanici bi trebalo da izbegavaju korišćenje coins primljenih na već korišćene, prazne adrese kako bi sprečili ovaj privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcije bez izlaza za kusur verovatno su između dve adrese koje pripadaju istom korisniku.
- **Round Numbers:** Okrugli iznos u transakciji sugeriše da je u pitanju plaćanje, pri čemu je neokrugli izlaz verovatno izlaz za kusur.
- **Wallet Fingerprinting:** Različiti wallets imaju jedinstvene obrasce kreiranja transakcija, što analitičarima može omogućiti identifikaciju softvera koji je korišćen i potencijalno adresu za kusur.
- **Amount & Timing Correlations:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije pratljivim.

## **Traffic Analysis**

Praćenjem mrežnog saobraćaja, napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama, ugrožavajući privatnost korisnika. Ovo je posebno tačno ako entitet upravlja mnogim Bitcoin čvorovima, čime povećava svoju sposobnost praćenja transakcija.

## More

Za sveobuhvatan spisak napada na privatnost i odbrana posetite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Načini za anonimno dobijanje bitcoina

- **Cash Transactions**: Nabavka bitcoina gotovinom.
- **Cash Alternatives**: Kupovina poklon kartica i njihova zamena na internetu za bitcoin.
- **Mining**: Najprivatniji metod za sticanje bitcoina je kroz mining, posebno kada se radi solo, jer mining pool-ovi mogu znati IP adresu minera. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretski, krađa bitcoina mogla bi biti još jedan metod za anonimno sticanje, iako je to protivzakonito i ne preporučuje se.

## Mixing Services

Korišćenjem mixing service-a, korisnik može poslati bitcoins i dobiti različite bitcoins zauzvrat, što otežava praćenje originalnog vlasnika. Ipak, to zahteva poverenje u servis da ne vodi logove i da zaista vrati bitcoine. Alternativne opcije za mešanje uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** spaja više transakcija od različitih korisnika u jednu, komplikujući proces svakome ko pokušava da upari input-e sa output-ima. Uprkos svojoj efikasnosti, transakcije sa jedinstvenim veličinama input-a i output-a i dalje mogu biti potencijalno praćene.

Primeri transakcija koje su mogle koristiti CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija posetite [CoinJoin](https://coinjoin.io/en). Za sličnu uslugu na Ethereum-u, pogledajte [Tornado Cash](https://tornado.cash), koji anonimizuje transakcije koristeći sredstva od minera.

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), maskira transakciju između dve strane (npr. kupac i trgovac) kao običnu transakciju, bez karakterističnih jednakih output-a koji su tipični za CoinJoin. To je izuzetno teško detektovati i može poništiti common-input-ownership heuristic koju koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije poput prikazane mogu biti PayJoin — povećavaju privatnost, a istovremeno izgledaju kao standardne bitcoin transakcije.

**Korišćenje PayJoin-a moglo bi značajno poremetiti tradicionalne metode nadzora**, čineći ga perspektivnim razvojem u potrazi za privatnošću transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Da bi se održala privatnost i bezbednost, sinhronizacija novčanika sa blockchain-om je od suštinskog značaja. Ističu se dve metode:

- **Full node**: Preuzimanjem cele blockchain mreže, Full node obezbeđuje maksimalnu privatnost. Sve transakcije ikada izvršene čuvaju se lokalno, što otežava napadačima da identifikuju koje transakcije ili adrese zanimaju korisnika.
- **Client-side block filtering**: Ova metoda uključuje kreiranje filtera za svaki blok u blockchain-u, omogućavajući novčanicima da identifikuju relevantne transakcije bez otkrivanja specifičnih interesovanja posmatračima mreže. Lagani novčanici preuzimaju te filtere i kompletne blokove samo kada se pronađe poklapanje sa adresama korisnika.

## **Korišćenje Tor-a za anonimizaciju**

S obzirom da Bitcoin radi na peer-to-peer mreži, preporučuje se korišćenje Tor-a da biste sakrili svoju IP adresu, povećavajući privatnost pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Da bi se zaštitila privatnost, ključno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može kompromitovati privatnost povezivanjem transakcija sa istim subjektom. Moderni novčanici kroz svoj dizajn obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Multiple transactions**: Podela uplate na više transakcija može zamagliti iznos transakcije i onemogućiti napade na privatnost.
- **Change avoidance**: Izbor transakcija koje ne zahtevaju izlaze za kusur poboljšava privatnost jer remeti metode detekcije kusura.
- **Multiple change outputs**: Ako izbegavanje kusura nije izvodljivo, generisanje više izlaza za kusur i dalje može poboljšati privatnost.

# **Monero: svetionik anonimnosti**

Monero zadovoljava potrebu za apsolutnom anonimnošću u digitalnim transakcijama, postavljajući visok standard za privatnost.

# **Ethereum: Gas i transakcije**

## **Razumevanje gasa**

Gas meri računski napor potreban za izvršavanje operacija na Ethereum-u, a cena se izražava u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje gas limit i osnovnu naknadu, uz napojnicu koja podstiče rudare. Korisnici mogu postaviti maksimalnu naknadu kako ne bi platili previše; višak se vraća.

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract-a. One zahtevaju naknadu i moraju biti ubačene u blok. Suštinske informacije u transakciji uključuju primaoca, potpis pošiljaoca, vrednost, opciona data, gas limit i naknade. Značajno je da se adresa pošiljaoca izvodi iz potpisa, pa nije neophodno da bude uključena u podatke transakcije.

Ove prakse i mehanizmi su osnov za svakoga ko želi da se bavi kriptovalutama uz prioritet na privatnost i bezbednost.

## Sigurnost smart contract-a

- Mutation testing za pronalaženje slepih tačaka u testnim setovima:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## Eksploatacija DeFi/AMM

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za multi-asset weighted pools koje keširaju virtualne bilanse i mogu biti zatrovane kada je `supply == 0`, proučite:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
