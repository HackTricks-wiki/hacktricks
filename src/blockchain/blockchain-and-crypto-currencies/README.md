# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Smart Contracts** su definisani kao programi koji se izvršavaju na blockchainu kada su ispunjeni određeni uslovi, automatizujući izvršavanje sporazuma bez posrednika.
- **Decentralized Applications (dApps)** se zasnivaju na smart contract-ima, sa korisničkim front-end-om i transparentnim, podložnim reviziji back-end-om.
- **Tokens & Coins** se razlikuju: coins služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenim kontekstima.
- **Utility Tokens** omogućavaju pristup uslugama, a **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** označava decentralizovane finansije, koje nude finansijske usluge bez centralnih vlasti.
- **DEX** i **DAOs** odnose se na platforme za decentralizovanu razmenu (Decentralized Exchange Platforms) i decentralizovane autonomne organizacije (Decentralized Autonomous Organizations).

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju sigurnu i zajednički prihvaćenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** se oslanja na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da drže određenu količinu tokena, smanjujući potrošnju energije u poređenju sa PoW.

## Osnovni pojmovi vezani za Bitcoin

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se potvrđuju digitalnim potpisima, čime se osigurava da samo vlasnik privatnog ključa može inicirati transfere.

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (odredište), **fees** (naknade, plaćene rudarima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj je poboljšati skalabilnost Bitcoina omogućavajući više transakcija unutar kanala, pri čemu se na blockchain objavljuje samo konačno stanje.

## Zabrinutosti za privatnost u Bitcoinu

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost zamagljujući veze između transakcija korisnika.

## Kako anonimno nabaviti Bitcoine

Metode uključuju kupovinu za gotovinu, rudarenje i korišćenje mixers-a. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** maskira CoinJoin transakcije kao obične transfere radi dodatne privatnosti.

# Napadi na privatnost Bitcoina

# Pregled napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmet zabrinutosti. Evo pojednostavljenog pregleda nekoliko uobičajenih metoda kojima napadači mogu ugroziti privatnost Bitcoina.

## **Common Input Ownership Assumption**

Retko je da se inputi od različitih korisnika kombinuju u jednoj transakciji zbog složenosti, pa se zato **dve input adrese u istoj transakciji često smatraju da pripadaju istom vlasniku**.

## **UTXO Change Address Detection**

UTXO, ili **Unspent Transaction Output** (neiskorišćeni izlaz transakcije), mora biti u potpunosti potrošen u transakciji. Ako se samo deo pošalje na drugu adresu, ostatak ide na novu change adresu. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se ugrožava privatnost.

### Primer

Da bi se to ublažilo, mixing servisi ili korišćenje više adresa može pomoći u zamućivanju vlasništva.

## **Social Networks & Forums Exposure**

Korisnici ponekad dele svoje Bitcoin adrese online, što olakšava **povezivanje adrese sa njenim vlasnikom**.

## **Transaction Graph Analysis**

Transakcije se mogu vizuelizovati kao grafovi, otkrivajući potencijalne veze među korisnicima na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika se zasniva na analizi transakcija sa više inputa i outputa kako bi se pogodilo koji output je change koji se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje više ulaza učini izlaz za kusur većim od bilo kog pojedinačnog ulaza, to može zbuniti heuristiku.

## **Forced Address Reuse**

Napadači mogu poslati male sume na ranije upotrebljene adrese, nadajući se da će primalac ove iznose kombinovati sa drugim ulazima u budućim transakcijama, čime bi povezao adrese.

### Ispravno ponašanje novčanika

Novčanici bi trebalo da izbegavaju korišćenje sredstava primljenih na već upotrebljene, prazne adrese kako bi se sprečio ovaj privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcije bez izlaza za kusur verovatno su između dve adrese koje pripadaju istom korisniku.
- **Round Numbers:** Zaokružen iznos u transakciji sugeriše da je u pitanju uplata, dok je ne-zaokruženi izlaz verovatno kusur.
- **Wallet Fingerprinting:** Različiti walleti imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju softver koji je korišćen i potencijalno adresu za kusur.
- **Amount & Timing Correlations:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije pratljivim.

## **Traffic Analysis**

Praćenjem mrežnog saobraćaja, napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama, ugrožavajući privatnost korisnika. Ovo je naročito tačno ako neka organizacija upravlja mnogim Bitcoin čvorovima, čime poboljšava svoju sposobnost nadzora transakcija.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Nabavka bitcoina gotovinom.
- **Cash Alternatives**: Kupovina poklon kartica i njihovo menjanje online za bitcoin.
- **Mining**: Najprivatniji način za zaradu bitcoina je rudarenje, naročito kada se radi samostalno, jer rudarski poolovi mogu znati IP adresu rudara. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretski, krađa bitcoina mogla bi biti još jedan način da se stekne anonimno, mada je to protivzakonito i ne preporučuje se.

## Mixing Services

Korišćenjem servisa za mešanje, korisnik može **poslati bitcoine** i primiti **drugačije bitcoine zauzvrat**, što otežava praćenje originalnog vlasnika. Ipak, to zahteva poverenje u servis da ne čuva logove i da stvarno vrati bitcoine. Alternativne opcije mešanja uključuju Bitcoin kazino.

## CoinJoin

CoinJoin spaja više transakcija od različitih korisnika u jednu, otežavajući pokušaje da se uparuju ulazi sa izlazima. Uprkos efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje se mogu pratiti.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija posetite [CoinJoin](https://coinjoin.io/en). Za sličan servis na Ethereumu, pogledajte [Tornado Cash](https://tornado.cash), koji anonimizuje transakcije pomoću sredstava od rudara.

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), maskira transakciju između dve strane (npr. kupca i prodavca) kao običnu transakciju, bez karakterističnih jednakih izlaza koji su tipični za CoinJoin. To je čini izuzetno teškom za detektovanje i može poništiti common-input-ownership heuristic koju koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije poput prethodne mogu biti PayJoin, poboljšavajući privatnost dok su neprepoznatljive u odnosu na standardne bitcoin transakcije.

**Korišćenje PayJoin-a moglo bi značajno poremetiti tradicionalne metode nadzora**, čineći ga obećavajućim razvojem u težnji za privatnošću transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Wallet Synchronization Techniques**

Da bi se održala privatnost i bezbednost, sinhronizacija novčanika sa blockchain-om je od ključne važnosti. Dve metode se izdvajaju:

- **Full node**: Preuzimanjem celog blockchain-a, full node obezbeđuje maksimalnu privatnost. Sve transakcije koje su ikada napravljene se čuvaju lokalno, što onemogućava protivnicima da identifikuju koje transakcije ili adrese zanimaju korisnika.
- **Client-side block filtering**: Ova metoda podrazumeva kreiranje filtera za svaki blok u blockchain-u, omogućavajući novčanicima da identifikuju relevantne transakcije bez izlaganja specifičnih interesa posmatračima mreže. Lagani novčanici preuzimaju ove filtere i pune blokove preuzimaju samo kada se nađe poklapanje sa adresama korisnika.

## **Utilizing Tor for Anonymity**

S obzirom da Bitcoin radi na peer-to-peer mreži, preporučuje se korišćenje Tor-a za maskiranje vaše IP adrese, čime se povećava privatnost prilikom interakcije sa mrežom.

## **Preventing Address Reuse**

Da biste zaštitili privatnost, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Moderni novčanici svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategies for Transaction Privacy**

- **Više transakcija**: Podela uplate na više transakcija može zamagliti iznos transakcije i osujetiti napade na privatnost.
- **Izbegavanje change izlaza**: Opcija koja izbaci potrebu za change izlazima poboljšava privatnost jer remeti metode detekcije change izlaza.
- **Više change izlaza**: Ako izbegavanje change izlaza nije moguće, generisanje više change izlaza može ipak poboljšati privatnost.

# **Monero: Svetionik anonimnosti**

Monero odgovara na potrebu za apsolutnom anonimnošću u digitalnim transakcijama, postavljajući visok standard za privatnost.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u, a cena se izražava u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje gas limit i osnovnu naknadu, uz napojnicu za motivisanje miners-a. Korisnici mogu postaviti max fee kako bi osigurali da ne preplaćuju, a višak se vraća.

## **Executing Transactions**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract adrese. One zahtevaju naknadu i moraju biti mined. Suštinske informacije u transakciji uključuju primaoca, pošiljačev potpis, vrednost, opcionu data, gas limit i naknade. Napomena: adresa pošiljaoca se izvodi iz potpisa, pa nije potrebna u podacima transakcije.

Ove prakse i mehanizmi su osnov za svakoga ko želi da učestvuje u radu sa kriptovalutama, uz prioritet na privatnost i bezbednost.

## Value-Centric Web3 Red Teaming

- Inventarizujte komponente koje nose vrednost (signers, oracles, bridges, automation) da biste razumeli ko može pomerati sredstva i kako.
- Mapirajte svaku komponentu na relevantne MITRE AADAPT taktike kako biste otkrili puteve za eskalaciju privilegija.
- Režirajte flash-loan/oracle/credential/cross-chain attack chain-ove da biste validirali uticaj i dokumentovali iskorišćive preuslove.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

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

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
