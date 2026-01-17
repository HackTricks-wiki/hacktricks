# Blokčejn i kripto-valute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Pametni ugovori (Smart Contracts)** su definisani kao programi koji se izvršavaju na blokčejnu kada su ispunjeni određeni uslovi, automatizujući izvršenje sporazuma bez posrednika.
- **Decentralizovane aplikacije (dApps)** se oslanjaju na pametne ugovore i imaju korisnički prijatan front-end i transparentan, revizibilan back-end.
- **Tokeni i coini (Tokens & Coins)** prave razliku: coini služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u određenim kontekstima.
- **Utility tokeni** omogućavaju pristup uslugama, a **security tokeni** označavaju vlasništvo nad imovinom.
- **Decentralizovane finansije (DeFi)** nude finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** se odnose na decentralizovane berze (Decentralized Exchange Platforms) i decentralizovane autonomne organizacije (Decentralized Autonomous Organizations).

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju sigurnu i dogovorenu verifikaciju transakcija na blokčejnu:

- **Proof of Work (PoW)** se oslanja na računsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da drže određenu količinu tokena, smanjujući potrošnju energije u poređenju sa PoW.

## Osnovi Bitcoina

### Transakcije

Bitcoin transakcije podrazumevaju prenos sredstava između adresa. Transakcije se potvrđuju kroz digitalne potpise, osiguravajući da samo vlasnik privatnog ključa može inicirati prenos.

#### Ključne komponente:

- **Multisignature transakcije** zahtevaju više potpisa za autorizaciju transakcije.
- Transakcije se sastoje iz **inputa** (izvor sredstava), **outputa** (odredište), **naknada** (plaćene minerima) i **skripti** (pravila transakcije).

### Lightning Network

Cilj mu je da poboljša skalabilnost Bitcoina omogućavajući više transakcija unutar kanala, pri čemu se samo završno stanje emituje na blokčejn.

## Zabrinutosti oko privatnosti Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce transakcija. Strategije poput **mixera** i **CoinJoin** poboljšavaju anonimnost time što zamagljuju veze između transakcija i korisnika.

## Anonimno sticanje Bitcoina

Metode uključuju trgovinu za keš, rudarenje i korišćenje mixera. **CoinJoin** meša više transakcija da bi otežao praćenje, dok **PayJoin** prikriva CoinJoin kao obične transakcije radi povećane privatnosti.

# Napadi na privatnost Bitcoina

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmet zabrinutosti. Evo pojednostavljenog pregleda nekoliko uobičajenih metoda kojima napadači mogu ugroziti privatnost Bitcoina.

## **Pretpostavka zajedničkog vlasništva inputa (Common Input Ownership Assumption)**

Retko se dešava da se inputi od različitih korisnika kombinuju u jednoj transakciji zbog složenosti. Dakle, **dve ulazne adrese u istoj transakciji se često pretpostavljaju kao adrese istog vlasnika**.

## **Otkrivanje adrese za povratnu vrednost UTXO-a (UTXO Change Address Detection)**

UTXO, ili nepotrošeni izlaz transakcije, mora biti u potpunosti potrošen u transakciji. Ako se samo njegov deo pošalje na drugu adresu, ostatak se salje na novu adresu za povratnu vrednost (change address). Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se narušava privatnost.

### Primer

Da bi se to ublažilo, korišćenje mixing servisa ili više adresa može pomoći da se zamagli vlasništvo.

## **Izlaganje na društvenim mrežama i forumima**

Korisnici ponekad dele svoje Bitcoin adrese online, što olakšava **povezivanje adrese sa njenim vlasnikom**.

## **Analiza grafova transakcija**

Transakcije se mogu vizualizovati kao grafovi, otkrivajući potencijalne veze između korisnika na osnovu toka sredstava.

## **Heuristika nepotrebnog inputa (Optimal Change Heuristic)**

Ova heuristika se zasniva na analizi transakcija sa više inputa i outputa kako bi se pogodilo koji output predstavlja povratnu vrednost koja se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje više inputs učini change output većim od bilo kojeg pojedinačnog inputa, to može zbuniti heuristiku.

## **Forced Address Reuse**

Napadači mogu poslati male iznose na prethodno korišćene adrese, nadajući se da će primalac kombinovati ove sa drugim inputs u budućim transakcijama, čime će povezati adrese.

### Correct Wallet Behavior

Novčanici bi trebalo da izbegavaju upotrebu coins primljenih na već korišćene, prazne adrese kako bi sprečili ovaj privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcije bez change-a verovatno su između dve adrese koje pripadaju istom korisniku.
- **Round Numbers:** Zaokružen iznos u transakciji sugeriše da je to uplata, dok je ne-zaokruženi output verovatno change.
- **Wallet Fingerprinting:** Različiti wallet-i imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni softver i potencijalno change adresu.
- **Amount & Timing Correlations:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije moguće za praćenje.

## **Traffic Analysis**

Praćenjem mrežnog saobraćaja, napadači potencijalno mogu povezati transakcije ili blokove sa IP adresama, ugrožavajući privatnost korisnika. Ovo je posebno tačno ako neka entiteta upravlja mnogim Bitcoin node-ovima, što poboljšava njihovu sposobnost nadgledanja transakcija.

## More

Za sveobuhvatan spisak napada na privatnost i odbrana, posetite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Nabavka bitcoin-a gotovinom.
- **Cash Alternatives**: Kupovina poklon kartica i zamena online za bitcoin.
- **Mining**: Najprivatniji način za zarađivanje bitcoina je mining, naročito kada se radi samostalno jer mining pools mogu znati IP adresu rudara. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretski, krađa bitcoina mogla bi biti još jedan metod da se dobije anonimno, iako je ilegalno i nije preporučljivo.

## Mixing Services

Korišćenjem mixing servisa, korisnik može **poslati bitcoins** i primiti **različite bitcoins zauzvrat**, što otežava praćenje originalnog vlasnika. Ipak, to zahteva poverenje u servis da ne čuva logove i da zaista vrati bitcoins. Alternativne opcije za mešanje uključuju Bitcoin casina.

## CoinJoin

CoinJoin spaja više transakcija od različitih korisnika u jednu, otežavajući proces onima koji pokušavaju da poklope inputs sa outputs. Uprkos svojoj efikasnosti, transakcije sa jedinstvenim veličinama inputa i outputa i dalje mogu biti potencijalno praćene.

Primer transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), kamuflira transakciju između dve strane (npr. kupac i trgovac) kao običnu transakciju, bez karakterističnih jednakih outputs koji su tipični za CoinJoin. To je čini izuzetno teškom za detekciju i može poništiti common-input-ownership heuristic koju koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije poput prethodne mogu biti PayJoin, poboljšavajući privatnost dok ostaju neprepoznatljive u odnosu na standardne bitcoin transakcije.

**Korišćenje PayJoin-a može značajno poremetiti tradicionalne metode nadzora**, čineći ga obećavajućim razvojem u težnji ka privatnosti transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Da biste održali privatnost i bezbednost, sinhronizacija novčanika sa blockchain-om je ključna. Dve metode se izdvajaju:

- **Full node**: Preuzimanjem cele blockchain mreže, Full node obezbeđuje maksimalnu privatnost. Sve transakcije ikada izvršene se čuvaju lokalno, što otežava protivnicima da identifikuju koje transakcije ili adrese interesuju korisnika.
- **Client-side block filtering**: Ova metoda podrazumeva kreiranje filtera za svaki blok u blockchain-u, omogućavajući novčanicima da identifikuju relevantne transakcije bez izlaganja specifičnih interesovanja posmatračima mreže. Lagani novčanici preuzimaju ove filtere i povlače pune blokove samo kada se pronađe poklapanje sa adresama korisnika.

## **Korišćenje Tor-a radi anonimiteta**

S obzirom da Bitcoin radi na peer-to-peer mreži, preporučuje se korišćenje Tor-a za maskiranje vaše IP adrese, čime se poboljšava privatnost pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Da biste zaštitili privatnost, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može kompromitovati privatnost povezivanjem transakcija sa istim entitetom. Savremeni novčanici svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Više transakcija**: Podela uplate na više transakcija može zamagliti iznos plaćanja, onemogućavajući napade na privatnost.
- **Izbegavanje change izlaza**: Odabir transakcija koje ne zahtevaju change izlaze poboljšava privatnost remeteći metode detekcije kusura.
- **Više change izlaza**: Ako izbegavanje change-a nije izvodljivo, kreiranje više change izlaza može i dalje poboljšati privatnost.

# **Monero: A Beacon of Anonymity**

Monero odgovara na potrebu za apsolutnom anonimnošću u digitalnim transakcijama, postavljajući visoke standarde privatnosti.

# **Ethereum: Gas and Transactions**

## **Razumevanje gasa**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u, a cena se izražava u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) obuhvata gas limit i base fee, uz napojnicu (tip) za motivisanje miner-a. Korisnici mogu postaviti max fee kako ne bi platili previše; višak se refundira.

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract adrese. One zahtevaju naknadu i moraju biti mined. Osnovne informacije u transakciji uključuju primaoca, pošiljačev potpis, iznos, opciona data, gas limit i naknade. Značajno je da se adresa pošiljaoca izvodi iz potpisa, što eliminiše potrebu za njenim eksplicitnim navođenjem u podacima transakcije.

Ove prakse i mehanizmi predstavljaju osnov za svakoga ko želi da koristi kriptovalute uz prioritet na privatnost i bezbednost.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
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
