# Blockchain i kripto-valute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Smart Contracts** se definišu kao programi koji se izvršavaju na blockchain-u kada su ispunjeni određeni uslovi, automatizujući izvršenje ugovora bez posrednika.
- **Decentralized Applications (dApps)** nadograđuju se na Smart Contracts, imajući user-friendly front-end i transparentan, auditable back-end.
- **Tokens & Coins** prave razliku gde coins služe kao digitalni novac, dok tokens predstavljaju vrednost ili vlasništvo u specifičnim kontekstima.
- **Utility Tokens** omogućavaju pristup servisima, a **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** predstavlja decentralizovane finansije, nudeći finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** odnose se na Decentralized Exchange Platforms i Decentralized Autonomous Organizations, respektivno.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju sigurnu i dogovorenu validaciju transakcija na blockchain-u:

- **Proof of Work (PoW)** se oslanja na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da drže određenu količinu tokena, smanjujući potrošnju energije u odnosu na PoW.

## Osnovno o Bitcoinu

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se validiraju putem digitalnih potpisa, obezbeđujući da samo vlasnik privatnog ključa može inicirati prijenos.

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa da bi se autorizovala transakcija.
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (odredište), **fees** (plaćeno minersima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj je unaprediti skalabilnost Bitcoina dozvoljavajući više transakcija unutar kanala, pri čemu se samo krajnje stanje emituje na blockchain.

## Problemi privatnosti Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce u transakcijama. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost tako što zamagljuju veze između transakcija i korisnika.

## Kako anonimno pribaviti Bitcoine

Metode uključuju gotovinske razmene, mining i korišćenje mixers. **CoinJoin** meša više transakcija da oteža tragačnost, dok **PayJoin** prerušava CoinJoin transakcije u regularne transakcije radi povećane privatnosti.

# Napadi na privatnost Bitcoina

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmet zabrinutosti. Ovde je pojednostavljen pregled nekoliko uobičajenih metoda kojima napadači mogu ugroziti privatnost Bitcoina.

## **Common Input Ownership Assumption**

Obično je retko da se inputi od različitih korisnika kombinuju u jednoj transakciji zbog uključenih kompleksnosti. Dakle, **dve input adrese u istoj transakciji se često pretpostavljaju da pripadaju istom vlasniku**.

## **UTXO Change Address Detection**

UTXO, ili **Unspent Transaction Output**, mora biti u potpunosti potrošen u transakciji. Ako se samo deo prenese na drugu adresu, ostatak ide na novu change adresu. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se kompromituje privatnost.

### Primer

Da bi se ovo ublažilo, servisi za mešanje (Mixers) ili korišćenje više adresa mogu pomoći da se zamagli vlasništvo.

## **Social Networks & Forums Exposure**

Korisnici ponekad dele svoje Bitcoin adrese online, što olakšava **povezivanje adrese sa njenim vlasnikom**.

## **Transaction Graph Analysis**

Transakcije se mogu vizualizovati kao grafovi, otkrivajući potencijalne veze između korisnika na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika se zasniva na analiziranju transakcija sa više inputa i outputa kako bi se pogodilo koji output predstavlja change koji se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje više inputa učini kusurni izlaz većim od bilo kog pojedinačnog inputa, to može zbuniti heuristiku.

## **Forced Address Reuse**

Napadači mogu poslati male iznose na ranije korišćene adrese, nadajući se da primalac kombinuje te iznose sa drugim inputima u budućim transakcijama, čime se adrese povezuju.

### Correct Wallet Behavior

Wallets bi trebalo da izbegavaju korišćenje sredstava primljenih na već korišćene, prazne adrese kako bi sprečili ovu privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcije bez kusura verovatno su između dve adrese u vlasništvu istog korisnika.
- **Round Numbers:** Zaokrugljeni iznos u transakciji sugeriše da je u pitanju plaćanje, pri čemu je nezaokrugljeni izlaz verovatno kusur.
- **Wallet Fingerprinting:** Različiti wallets imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni softver i potencijalno adresu za kusur.
- **Amount & Timing Correlations:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije pratljivim.

## **Traffic Analysis**

Praćenjem mrežnog saobraćaja, napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama, kompromitujući privatnost korisnika. Ovo je naročito tačno ako neka entiteta upravlja mnogim Bitcoin čvorovima, što povećava njihovu sposobnost da nadgledaju transakcije.

## More

Za sveobuhvatan spisak napada na privatnost i odbrana, posetite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin transakcije

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Sticanje bitcoina gotovinom.
- **Cash Alternatives**: Kupovina poklon kartica i njihova zamena online za bitcoin.
- **Mining**: Najprivatniji način da se zarade bitcoini je rudarenje, posebno ako se radi solo, jer mining poolovi mogu znati IP adresu rudara. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretski, krađa bitcoina mogla bi biti još jedan metod da se anonimno dođe do njih, iako je to ilegalno i nepreporučljivo.

## Mixing Services

Korišćenjem mixing servisa, korisnik može **poslati bitcoine** i dobiti **drugačije bitcoine zauzvrat**, što otežava praćenje originalnog vlasnika. Ipak, ovo zahteva poverenje u servis da ne čuva logove i da zaista vrati bitcoine. Alternativne opcije za mešanje uključuju Bitcoin kazina.

## CoinJoin

**CoinJoin** spaja više transakcija od različitih korisnika u jednu, otežavajući proces za svakoga ko pokuša da podudari ulaze sa izlazima. Uprkos svojoj efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje se potencijalno mogu pratiti.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija posetite [CoinJoin](https://coinjoin.io/en). Za sličnu uslugu na Ethereum-u pogledajte [Tornado Cash](https://tornado.cash), koji anonimizuje transakcije sredstvima rudara.

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), maskira transakciju između dve strane (npr. kupca i trgovca) kao običnu transakciju, bez karakterističnih jednakih izlaza tipičnih za CoinJoin. To je izuzetno teško detektovati i može poništiti common-input-ownership heuristic koju koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije kao gore navedene mogle bi biti PayJoin, poboljšavajući privatnost dok ostaju neprepoznatljive u odnosu na standardne bitcoin transakcije.

**Upotreba PayJoin-a može značajno poremetiti tradicionalne metode nadzora**, čineći ga perspektivnim razvojem u potrazi za transakcionom privatnošću.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Da bi se održala privatnost i bezbednost, sinhronizacija novčanika sa blockchain-om je ključna. Ističu se dve metode:

- **Puni čvor**: Preuzimanjem celog blockchain-a, puni čvor obezbeđuje maksimalnu privatnost. Sve ikada izvršene transakcije se čuvaju lokalno, čineći nemogućim za protivnike da identifikuju koje transakcije ili adrese interesuju korisnika.
- **Filtriranje blokova na strani klijenta**: Ova metoda podrazumeva kreiranje filtera za svaki blok u blockchain-u, omogućavajući novčanicima da identifikuju relevantne transakcije bez izlaganja specifičnih interesovanja posmatračima mreže. Lightweight novčanici preuzimaju ove filtere i samo povlače pune blokove kada postoji poklapanje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

Pošto Bitcoin radi na peer-to-peer mreži, preporučuje se korišćenje Tor-a za maskiranje vaše IP adrese, čime se poboljšava privatnost prilikom interakcije sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Za zaštitu privatnosti važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Moderni novčanici svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Podela uplate na više transakcija može zamagliti iznos transakcije, onemogućavajući napade na privatnost.
- **Izbegavanje kusura**: Biranje transakcija koje ne zahtevaju change outputs poboljšava privatnost tako što remeti metode detekcije change-a.
- **Više change output-a**: Ako izbegavanje change-a nije izvodljivo, generisanje više change output-a i dalje može poboljšati privatnost.

# **Monero: Svetionik anonimnosti**

Monero odgovara na potrebu za apsolutnom anonimnošću u digitalnim transakcijama, postavljajući visok standard privatnosti.

# **Ethereum: Gas i transakcije**

## **Razumevanje gasa**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u, cenjen u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje gas limit i osnovnu naknadu, sa napojnicom za stimulisanje rudara. Korisnici mogu postaviti maksimalnu naknadu kako bi izbegli preplaćivanje, a višak se refundira.

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract-a. One zahtevaju naknadu i moraju biti uključene u blok (mined). Suštinske informacije u transakciji uključuju primaoca, pošiljačev potpis, vrednost, opcionalne podatke, gas limit i naknade. Bitno je da se adresa pošiljaoca izvodi iz potpisa, čime se eliminiše potreba za njom u podacima transakcije.

Ove prakse i mehanizmi su temelj za svakoga ko želi da se bavi kriptovalutama uz prioritetizovanje privatnosti i bezbednosti.

## Value-Centric Web3 Red Teaming

- Inventarizujte komponente koje nose vrednost (signers, oracles, bridges, automation) kako biste razumeli ko može pomerati sredstva i na koji način.
- Mapirajte svaku komponentu na relevantne MITRE AADAPT taktike da biste otkrili puteve eskalacije privilegija.
- Vežbajte flash-loan/oracle/credential/cross-chain attack chain-ove da biste validirali uticaj i dokumentovali eksploatabilne preduslove.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Sabotaža u lancu snabdevanja na UI-ima novčanika može izmeniti EIP-712 payload-e neposredno pre potpisivanja, prikupljajući validne potpise za delegatecall-based proxy takeovers (npr. slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Uobičajeni načini otkaza smart-account-a uključuju zaobilaženje kontrole pristupa `EntryPoint`, nepotpisana polja gasa, stateful validation, ERC-1271 replay i fee-drain putem revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing za pronalaženje slepih tačaka u test-suit-ovima:

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

## DeFi/AMM Eksploatacija

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Za multi-asset weighted pool-ove koji keširaju virtuelna stanja i mogu biti zatrovani kada je `supply == 0`, proučite:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
