# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Smart Contracts** su definisani kao programi koji se izvršavaju na blockchainu kada su ispunjeni određeni uslovi, automatizujući sprovođenje ugovora bez posrednika.
- **Decentralized Applications (dApps)** se oslanjaju na smart contracts, imajući korisnički pristupačan front-end i transparentan i podložan reviziji back-end.
- **Tokens & Coins** razlikuju se tako što coini služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenim kontekstima.
- **Utility Tokens** omogućavaju pristup uslugama, a **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** označava Decentralized Finance, koji nudi finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** se odnose na Decentralized Exchange Platforms i Decentralized Autonomous Organizations, redom.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju sigurnu i zajednički prihvaćenu validaciju transakcija na blockchainu:

- **Proof of Work (PoW)** se oslanja na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva da validatori drže određenu količinu tokena, smanjujući potrošnju energije u odnosu na PoW.

## Osnovno o Bitcoinu

### Transakcije

Bitcoin transakcije uključuju prenos sredstava između adresa. Transakcije se validiraju digitalnim potpisima, što osigurava da samo vlasnik privatnog ključa može inicirati prenose.

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (odredište), **fees** (plaćanja minerima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj je poboljšanje skalabilnosti Bitcoina omogućavanjem više transakcija unutar kanala, pri čemu se na blockchain emituje samo konačno stanje.

## Problemi privatnosti Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, koriste obrasce transakcija. Strategije poput **Mixers** i **CoinJoin** poboljšavaju anonimnost zamagljivanjem veza između transakcija korisnika.

## Nabavka Bitcoina anonimno

Metode uključuju trgovinu za keš, mining i korišćenje Mixers. **CoinJoin** meša više transakcija kako bi se zakomplikovala tragabilnost, dok **PayJoin** maskira CoinJoin-ove kao obične transakcije za poboljšanu privatnost.

# Napadi na privatnost Bitcoina

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmet zabrinutosti. Evo pojednostavljenog pregleda nekoliko uobičajenih metoda kojima napadači mogu narušiti privatnost Bitcoina.

## **Common Input Ownership Assumption**

Generalno je retko da se inputs od različitih korisnika kombinuju u jednoj transakciji zbog uključenih komplikacija. Stoga se često pretpostavlja da **dve input adrese u istoj transakciji pripadaju istom vlasniku**.

## **UTXO Change Address Detection**

UTXO, odnosno **Unspent Transaction Output**, mora biti u potpunosti potrošen u transakciji. Ako se samo deo pošalje na drugu adresu, ostatak ide na novu change adresu. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se narušava privatnost.

### Primer

Da bi se to ublažilo, servisi za mešanje ili korišćenje više adresa mogu pomoći da se zamaskira vlasništvo.

## **Social Networks & Forums Exposure**

Korisnici ponekad dele svoje Bitcoin adrese online, što olakšava **povezivanje adrese sa njenim vlasnikom**.

## **Transaction Graph Analysis**

Transakcije se mogu vizualizovati kao grafovi, otkrivajući potencijalne veze između korisnika na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika se zasniva na analizi transakcija sa višestrukim inputs i outputs kako bi se pogodilo koji output predstavlja change koji se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje više inputa učini da change output bude veći od bilo kog pojedinačnog inputa, to može zbuniti heuristiku.

## **Forced Address Reuse**

Napadači mogu poslati male iznose na prethodno korišćene adrese, nadajući se da će primalac ubuduće kombinovati ove sa drugim inputima u budućim transakcijama, čime se adrese dovode u vezu.

### Correct Wallet Behavior

Novčanici bi trebalo da izbegavaju korišćenje kovanica primljenih na već korišćene, prazne adrese kako bi sprečili ovaj privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcije bez change verovatno su između dve adrese koje pripadaju istom korisniku.
- **Round Numbers:** Zaokružen iznos u transakciji sugeriše da je u pitanju plaćanje, pri čemu je ne-zaokruženi izlaz verovatno change.
- **Wallet Fingerprinting:** Različiti novčanici imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju softver koji je korišćen i potencijalno change address.
- **Amount & Timing Correlations:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije pratljivim.

## **Traffic Analysis**

Praćenjem mrežnog saobraćaja, napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama, ugrožavajući privatnost korisnika. Ovo je naročito tačno ako neko upravlja velikim brojem Bitcoin čvorova, čime se povećava njihova sposobnost nadgledanja transakcija.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Nabavka Bitcoina gotovinom.
- **Cash Alternatives**: Kupovina poklon kartica i zamena na internetu za Bitcoin.
- **Mining**: Najprivatniji način da se zaradi Bitcoin je rudarenje, naročito kada se radi solo jer mining pools mogu znati IP adresu rudara. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretski, krađa Bitcoina bi mogla biti još jedan metod da se stekne anonimno, iako je to nezakonito i nije preporučljivo.

## Mixing Services

Korišćenjem mixing service-a, korisnik može poslati bitcoine i dobiti druge bitcoine zauzvrat, što otežava praćenje originalnog vlasnika. Ipak, ovo zahteva poverenje u servis da neće voditi logove i da će zaista vratiti bitcoine. Alternativne opcije za mixanje uključuju Bitcoin kazina.

## CoinJoin

CoinJoin spaja više transakcija od različitih korisnika u jednu, otežavajući povezivanje inputa sa outputima. Uprkos efikasnosti, transakcije sa jedinstvenim veličinama inputa i outputa i dalje se mogu pratiti.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Varijanta CoinJoin-a, PayJoin (ili P2EP), maskira transakciju između dve strane (npr. kupca i trgovca) kao običnu transakciju, bez karakterističnih jednakih outputs koji su tipični za CoinJoin. To je čini izuzetno teškom za detekciju i može obesmišljiti common-input-ownership heuristic koju koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije poput gornje mogu biti PayJoin, čime se poboljšava privatnost, a istovremeno ostaju neprepoznatljive u odnosu na standardne bitcoin transakcije.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, čineći ga perspektivnim razvojem u nastojanju ka privatnosti transakcija.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Da bi se očuvale privatnost i bezbednost, sinhronizacija novčanika sa blockchainom je ključna. Dve metode se ističu:

- **Full node**: Preuzimanjem celog blockchaina, Full node obezbeđuje maksimalnu privatnost. Sve ikada izvršene transakcije skladište se lokalno, čineći nemogućim za protivnike da identifikuju koje transakcije ili adrese zanimaju korisnika.
- **Client-side block filtering**: Ova metoda podrazumeva kreiranje filtera za svaki blok u blockchainu, što omogućava novčanicima da identifikuju relevantne transakcije bez otkrivanja specifičnih interesovanja posmatračima mreže. Lightweight wallets preuzimaju ove filtere i dohvaćaju pune blokove samo kada se pronađe podudaranje sa adresama korisnika.

## **Utilizing Tor for Anonymity**

S obzirom da Bitcoin funkcioniše na peer-to-peer mreži, preporučuje se korišćenje Tor-a za prikrivanje vaše IP adrese, čime se poboljšava privatnost pri interakciji sa mrežom.

## **Preventing Address Reuse**

Za očuvanje privatnosti, važno je koristiti novu adresu za svaku transakciju. Ponovno korišćenje adresa može kompromitovati privatnost povezivanjem transakcija sa istim entitetom. Moderni novčanici svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Razdvajanje uplate na više transakcija može zamagliti iznos plaćanja i otežati napade na privatnost.
- **Change avoidance**: Odabir transakcija koje ne zahtevaju change outputs povećava privatnost tako što narušava metode detekcije promena.
- **Multiple change outputs**: Ako izbegavanje change outputs nije moguće, generisanje više change outputs i dalje može poboljšati privatnost.

# **Monero: A Beacon of Anonymity**

Monero odgovara na potrebu za apsolutnom anonimnošću u digitalnim transakcijama, postavljajući visok standard privatnosti.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u, cenjen u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje gas limit i osnovnu naknadu, uz napojnicu koja podstiče rudare. Korisnici mogu postaviti maksimalnu naknadu da ne bi preplatili, pri čemu se višak vraća.

## **Executing Transactions**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract-a. Za njih je potrebna naknada i moraju biti potvrđene rudarenjem. Bitne informacije u transakciji uključuju primaoca, potpis pošiljaoca, vrednost, opciona polja, gas limit i naknade. Važno je da se adresa pošiljaoca izvodi iz potpisa, što eliminiše potrebu da bude eksplicitno uključena u podatke transakcije.

Ove prakse i mehanizmi predstavljaju osnovu za svakog ko želi da se bavi kriptovalutama, a prioritet mu je privatnost i bezbednost.

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

{{#include ../../banners/hacktricks-training.md}}
