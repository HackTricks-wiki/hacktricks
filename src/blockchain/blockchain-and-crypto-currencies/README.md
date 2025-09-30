# Blockchain i kriptovalute

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pojmovi

- **Smart Contracts** su definisani kao programi koji se izvršavaju na blockchain-u kada su ispunjeni određeni uslovi, automatizujući izvršavanje sporazuma bez posrednika.
- **Decentralizovane aplikacije (dApps)** nadograđuju se na smart contracts, imajući korisnički prihvatljiv front-end i transparentan, auditabilan back-end.
- **Tokeni & Coinsi** razlikuju se tako što coinsi služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u specifičnim kontekstima.
- **Utility Tokens** daju pristup uslugama, a **Security Tokens** označavaju vlasništvo nad imovinom.
- **DeFi** označava Decentralizovane finansije, koje nude finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** odnose se na Decentralizovane berze i Decentralizovane autonomne organizacije.

## Mehanizmi konsenzusa

Mehanizmi konsenzusa obezbeđuju sigurnu i dogovorenu validaciju transakcija na blockchain-u:

- **Proof of Work (PoW)** oslanja se na računarsku snagu za verifikaciju transakcija.
- **Proof of Stake (PoS)** zahteva od validatora da drže određenu količinu tokena, smanjujući potrošnju energije u odnosu na PoW.

## Osnove Bitcoina

### Transakcije

Bitcoin transakcije uključuju prenos sredstava između adresa. Transakcije se validiraju digitalnim potpisima, što osigurava da samo vlasnik privatnog ključa može inicirati transfer.

#### Ključne komponente:

- **Multisignature Transactions** zahtevaju više potpisa za autorizaciju transakcije.
- Transakcije se sastoje od **inputs** (izvor sredstava), **outputs** (odredište), **fees** (plaćeni rudarima) i **scripts** (pravila transakcije).

### Lightning Network

Cilj mu je poboljšanje skalabilnosti Bitcoina omogućavajući više transakcija unutar kanala, pri čemu se samo konačno stanje objavljuje na blockchain-u.

## Problemi privatnosti Bitcoina

Napadi na privatnost, kao što su **Common Input Ownership** i **UTXO Change Address Detection**, iskorišćavaju obrasce u transakcijama. Strategije kao što su **Mixers** i **CoinJoin** poboljšavaju anonimnost time što zamagljuju veze transakcija između korisnika.

## Anonimno sticanje Bitcoina

Metode uključuju trgovinu za keš, mining i korišćenje mixera. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikriva CoinJoin kao obične transakcije za veću privatnost.

# Bitcoin Privacy Atacks

# Sažetak napada na privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmet brige. Evo pojednostavljenog pregleda nekoliko uobičajenih metoda kojima napadači mogu ugroziti privatnost Bitcoina.

## **Common Input Ownership Assumption**

Generalno je retko da se inputi različitih korisnika kombinuju u jednoj transakciji zbog složenosti koja je u tome uključena. Zato se **dve input adrese u istoj transakciji često pretpostavljaju da pripadaju istom vlasniku**.

## **UTXO Change Address Detection**

UTXO, odnosno **Unspent Transaction Output**, mora biti u potpunosti potrošen u transakciji. Ako se samo deo šalje na drugu adresu, ostatak ide na novu change address. Posmatrači mogu pretpostaviti da ta nova adresa pripada pošiljaocu, čime se narušava privatnost.

### Primer

Da bi se to ublažilo, mixing servisi ili korišćenje više adresa mogu pomoći da se zamagli vlasništvo.

## **Izlaganje preko društvenih mreža i foruma**

Korisnici ponekad dele svoje Bitcoin adrese online, što olakšava **povezivanje adrese sa njenim vlasnikom**.

## **Analiza grafova transakcija**

Transakcije se mogu vizualizovati kao grafovi, otkrivajući potencijalne veze između korisnika na osnovu toka sredstava.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Ova heuristika se zasniva na analizi transakcija sa više inputa i outputa kako bi se pogodilo koji output predstavlja change koji se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ako dodavanje više inputa učini da change output bude veći od bilo kojeg pojedinačnog inputa, to može zbuniti heuristiku.

## **Forced Address Reuse**

Napadači mogu poslati male iznose na prethodno korišćene adrese, nadajući se da će primalac u budućim transakcijama kombinovati te iznose sa drugim inputima, čime bi adrese bile povezane.

### Correct Wallet Behavior

Novčanici bi trebalo da izbegavaju korišćenje coina primljenih na već korišćene, prazne adrese kako bi sprečili ovaj privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transakcije bez change-a verovatno su između dve adrese koje pripadaju istom korisniku.
- **Round Numbers:** Zaokružen broj u transakciji ukazuje na to da je reč o uplati, dok je ne-zaokruženi output verovatno change.
- **Wallet Fingerprinting:** Različiti novčanici imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni softver i potencijalno change address.
- **Amount & Timing Correlations:** Otkrivanje vremena ili iznosa transakcija može učiniti transakcije sledljivim.

## **Traffic Analysis**

Praćenjem mrežnog saobraćaja, napadači potencijalno mogu povezati transakcije ili blokove sa IP adresama, ugrožavajući privatnost korisnika. Ovo je naročito tačno ako neka organizacija upravlja velikim brojem Bitcoin nodova, čime povećava svoju sposobnost nadgledanja transakcija.

## More

Za sveobuhvatan spisak napada na privatnost i odbrana, posetite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonimne Bitcoin Transakcije

## Načini za anonimno dobijanje Bitcoina

- **Cash Transactions**: Nabavka bitcoina gotovinom.
- **Cash Alternatives**: Kupovina poklon kartica i njihova zamena na internetu za bitcoin.
- **Mining**: Najprivatniji metod za zarađivanje bitcoina je mining, posebno kada se radi samostalno, jer mining poolovi mogu znati IP adresu rudara. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoretski, krađa bitcoina mogla bi biti još jedan metod za njegovo anonimno sticanje, iako je to protivzakonito i ne preporučuje se.

## Mixing Services

Korišćenjem mixing servisa, korisnik može poslati bitcoine i primiti drugačije bitcoine zauzvrat, što otežava praćenje izvornog vlasnika. Ipak, to zahteva poverenje u servis da neće čuvati logove i da će zaista vratiti bitcoine. Alternativa mixing servisima su Bitcoin kazina.

## CoinJoin

CoinJoin spaja više transakcija od različitih korisnika u jednu, otežavajući povezivanje inputa i outputa. Uprkos efikasnosti, transakcije sa jedinstvenim veličinama inputa i outputa i dalje se mogu pratiti.

Primer transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija, posetite [CoinJoin](https://coinjoin.io/en). Za sličan servis na Ethereum-u, pogledajte [Tornado Cash](https://tornado.cash), koji anonimizuje transakcije koristeći sredstva od miner-a.

## PayJoin

Varijanta CoinJoin-a, PayJoin (ili P2EP), maskira transakciju između dve strane (npr. kupac i trgovac) kao običnu transakciju, bez karakterističnih jednakih outputa tipičnih za CoinJoin. To je izuzetno teško detektovati i može poništiti common-input-ownership heuristic koju koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije kao gore navedene mogu biti PayJoin, poboljšavajući privatnost dok ostaju neodvojive od standardnih bitcoin transakcija.

**Korišćenje PayJoin-a moglo bi značajno da poremeti tradicionalne metode nadzora**, čineći ga perspektivnim razvojem u potrazi za privatnošću transakcija.

# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Za očuvanje privatnosti i bezbednosti, sinhronizacija novčanika sa blockchain-om je ključna. Ističu se dve metode:

- **Full node**: Preuzimanjem celog blockchain-a, Full node obezbeđuje maksimalnu privatnost. Sve transakcije ikada izvršene se čuvaju lokalno, čime je onemogućeno da protivnici identifikuju koje transakcije ili adrese korisnika su relevantne.
- **Client-side block filtering**: Ova metoda podrazumeva kreiranje filtera za svaki blok u blockchain-u, omogućavajući novčanicima da identifikuju relevantne transakcije bez otkrivanja specifičnih interesovanja posmatračima mreže. Lightweight wallets preuzimaju ove filtere i dohvataju pune blokove samo kad se pronađe poklapanje sa adresama korisnika.

## **Korišćenje Tor-a za anonimnost**

S obzirom da Bitcoin radi na peer-to-peer mreži, preporučuje se korišćenje Tor-a za maskiranje IP adrese, čime se povećava privatnost pri interakciji sa mrežom.

## **Sprečavanje ponovne upotrebe adresa**

Za zaštitu privatnosti važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Moderni novčanici svojim dizajnom obeshrabruju ponovnu upotrebu adresa.

## **Strategije za privatnost transakcija**

- **Multiple transactions**: Razdvajanje uplate na više transakcija može zamagliti iznos transakcije i otežati napade na privatnost.
- **Change avoidance**: Odabir transakcija koje ne zahtevaju change outputs povećava privatnost jer remeti metode detekcije change-a.
- **Multiple change outputs**: Ako izbegavanje change-a nije moguće, generisanje više change outputs može i dalje poboljšati privatnost.

# **Monero: Svetionik anonimnosti**

Monero odgovara na potrebu za apsolutnom anonimnošću u digitalnim transakcijama, postavljajući visok standard privatnosti.

# **Ethereum: Gas i transakcije**

## **Razumevanje gasa**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereum-u, cenjen u **gwei**. Na primer, transakcija koja košta 2,310,000 gwei (ili 0.00231 ETH) uključuje gas limit i baznu naknadu, kao i napojnicu za podsticanje rudara. Korisnici mogu postaviti maksimalnu naknadu kako ne bi preplatili, a višak se refundira.

## **Izvršavanje transakcija**

Transakcije na Ethereum-u uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili smart contract-a. One zahtevaju naknadu i moraju biti mined. Osnovne informacije u transakciji uključuju primaoca, potpis pošiljaoca, vrednost, opcionu data, gas limit i naknade. Značajno je da se adresa pošiljaoca izvodi iz potpisa, što eliminiše potrebu da bude eksplicitno uključena u podacima transakcije.

Ove prakse i mehanizmi su temeljni za svakoga ko želi da se bavi kriptovalutama, a prioritet mu je privatnost i bezbednost.

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

Ako istražujete praktičnu eksploataciju DEX-ova i AMM-ova (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), pogledajte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
