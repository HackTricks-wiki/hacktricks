# Blockchain e Criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di base

- **Smart Contracts** sono definiti come programmi che vengono eseguiti su una blockchain quando sono soddisfatte determinate condizioni, automatizzando l'esecuzione di accordi senza intermediari.
- **Decentralized Applications (dApps)** si basano su smart contract, presentando un front-end con interfaccia utente intuitiva e un back-end trasparente e verificabile.
- **Tokens & Coins** differenziano: le coin fungono da moneta digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- **Utility Tokens** danno accesso a servizi, e i **Security Tokens** indicano la proprietà di un asset.
- **DeFi** sta per Decentralized Finance, offrendo servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** si riferiscono rispettivamente a Decentralized Exchange Platforms e Decentralized Autonomous Organizations.

## Meccanismi di consenso

I meccanismi di consenso assicurano la validazione sicura e concordata delle transazioni sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza computazionale per la verifica delle transazioni.
- **Proof of Stake (PoS)** richiede che i validator detengano una certa quantità di token, riducendo il consumo energetico rispetto al PoW.

## Nozioni essenziali su Bitcoin

### Transazioni

Le transazioni Bitcoin coinvolgono il trasferimento di fondi tra indirizzi. Le transazioni sono validate tramite firme digitali, garantendo che solo il proprietario della chiave privata possa iniziare i trasferimenti.

#### Componenti chiave:

- **Multisignature Transactions** richiedono più firme per autorizzare una transazione.
- Le transazioni sono composte da **inputs** (fonte dei fondi), **outputs** (destinazione), **fees** (pagate ai miner) e **scripts** (regole della transazione).

### Lightning Network

Punta a migliorare la scalabilità di Bitcoin permettendo molteplici transazioni all'interno di un canale, trasmettendo alla blockchain solo lo stato finale.

## Preoccupazioni sulla privacy di Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i modelli di transazione. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti tra le transazioni degli utenti.

## Acquisire Bitcoin in modo anonimo

I metodi includono scambi in contanti, mining e l'uso di mixers. **CoinJoin** mescola più transazioni per rendere più complicata la tracciabilità, mentre **PayJoin** camuffa i CoinJoin come transazioni normali per una maggiore privacy.

# Bitcoin Privacy Atacks

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di diversi metodi comuni con cui gli attaccanti possono compromettere la privacy su Bitcoin.

## **Common Input Ownership Assumption**

È generalmente raro che inputs provenienti da utenti diversi vengano combinati in un'unica transazione a causa della complessità implicata. Pertanto, **due indirizzi di input nella stessa transazione sono spesso considerati appartenenti allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, deve essere speso interamente in una transazione. Se solo una parte viene inviata a un altro indirizzo, il resto va a un nuovo change address. Gli osservatori possono presumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio

Per mitigare questo, i servizi di mixing o l'uso di più indirizzi possono aiutare a oscurare la proprietà.

## **Esposizione su social network e forum**

Gli utenti a volte condividono i loro indirizzi Bitcoin online, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Transaction Graph Analysis**

Le transazioni possono essere visualizzate come grafi, rivelando potenziali connessioni tra utenti basate sul flusso di fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Questa euristica si basa sull'analisi di transazioni con multipli input e output per indovinare quale output sia il change che ritorna al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se aggiungere più input fa sì che l'output di resto sia più grande di qualsiasi singolo input, può confondere l'euristica.

## **Forced Address Reuse**

Gli attaccanti possono inviare piccole quantità a indirizzi già usati, sperando che il destinatario le combini con altri input in transazioni future, collegando così gli indirizzi tra loro.

### Correct Wallet Behavior

I wallet dovrebbero evitare di usare monete ricevute su indirizzi vuoti già usati per prevenire questo privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Le transazioni senza resto sono probabilmente tra due indirizzi appartenenti allo stesso utente.
- **Round Numbers:** Un numero tondo in una transazione suggerisce che si tratta di un pagamento, con l'output non tondo probabilmente costituito dal resto.
- **Wallet Fingerprinting:** Diversi wallet hanno modelli unici di creazione delle transazioni, permettendo agli analisti di identificare il software usato e potenzialmente l'indirizzo di resto.
- **Amount & Timing Correlations:** Rivelare orari o importi delle transazioni può renderle tracciabili.

## **Traffic Analysis**

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy degli utenti. Questo è particolarmente vero se un'entità gestisce molti nodi Bitcoin, migliorando la sua capacità di monitorare le transazioni.

## More

Per un elenco completo di attacchi alla privacy e contromisure, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Ottenere bitcoin tramite contanti.
- **Cash Alternatives**: Acquistare gift card e scambiarle online per bitcoin.
- **Mining**: Il metodo più privato per guadagnare bitcoin è il mining, specialmente se fatto in solitaria, perché i mining pool possono conoscere l'indirizzo IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, rubare bitcoin potrebbe essere un altro metodo per acquisirli in modo anonimo, anche se è illegale e non consigliato.

## Mixing Services

Usando un mixing service, un utente può **send bitcoins** e **receive different bitcoins in return**, rendendo difficile tracciare il proprietario originale. Tuttavia, questo richiede fiducia nel servizio affinché non tenga log e che restituisca effettivamente i bitcoin. Opzioni alternative di mixing includono i casinò Bitcoin.

## CoinJoin

**CoinJoin** fonde più transazioni provenienti da utenti diversi in una sola, complicando il processo per chiunque cerchi di associare input e output. Nonostante la sua efficacia, le transazioni con dimensioni uniche di input e output possono comunque essere potenzialmente tracciate.

Esempi di transazioni che potrebbero aver usato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, vedi [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi provenienti dai miner.

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera la transazione tra due parti (es. un cliente e un commerciante) come una normale transazione, senza gli output uguali distintivi tipici di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare l'euristica common-input-ownership usata dalle entità di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy pur rimanendo indistinguibili dalle transazioni bitcoin standard.

**L'utilizzo di PayJoin potrebbe interrompere significativamente i metodi tradizionali di sorveglianza**, rendendolo uno sviluppo promettente nella ricerca della privacy transazionale.

# Pratiche consigliate per la privacy nelle criptovalute

## **Tecniche di sincronizzazione del wallet**

Per mantenere privacy e sicurezza, sincronizzare i wallet con la blockchain è fondamentale. Due metodi si distinguono:

- **Full node**: Scaricando l'intera blockchain, un nodo completo garantisce la massima privacy. Tutte le transazioni effettuate sono memorizzate localmente, rendendo impossibile per gli avversari identificare quali transazioni o indirizzi interessano all'utente.
- **Client-side block filtering**: Questo metodo prevede la creazione di filtri per ogni blocco della blockchain, permettendo ai wallet di identificare le transazioni rilevanti senza esporre interessi specifici agli osservatori di rete. I wallet leggeri scaricano questi filtri, recuperando i blocchi completi solo quando c'è una corrispondenza con gli indirizzi dell'utente.

## **Utilizzo di Tor per l'anonimato**

Poiché Bitcoin opera su una rete peer-to-peer, si raccomanda l'uso di Tor per mascherare il proprio indirizzo IP, migliorando la privacy durante l'interazione con la rete.

## **Evitare il riutilizzo degli indirizzi**

Per proteggere la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Il riutilizzo degli indirizzi può compromettere la privacy collegando transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategie per la privacy delle transazioni**

- **Più transazioni**: Suddividere un pagamento in diverse transazioni può oscurare l'importo trasferito, contrastando attacchi alla privacy.
- **Evitare output di resto**: Scegliere transazioni che non richiedono output di resto aumenta la privacy interrompendo i metodi di rilevamento del change.
- **Più output di resto**: Se evitare il resto non è fattibile, generare più output di resto può comunque migliorare la privacy.

# **Monero: Un faro di anonimato**

Monero risponde alla necessità di anonimato assoluto nelle transazioni digitali, fissando uno standard elevato per la privacy.

# **Ethereum: Gas e transazioni**

## **Comprendere il Gas**

Il gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, prezzato in **gwei**. Ad esempio, una transazione che costa 2.310.000 gwei (o 0.00231 ETH) coinvolge un gas limit e una base fee, con una tip per incentivare i miner. Gli utenti possono impostare una max fee per assicurarsi di non pagare troppo; l'eccesso viene rimborsato.

## **Esecuzione delle transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi utente o smart contract. Richiedono una fee e devono essere minate. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, eventuali dati opzionali, il gas limit e le fee. Nota che l'indirizzo del mittente è dedotto dalla firma, eliminando la necessità di includerlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque desideri interagire con le criptovalute dando priorità a privacy e sicurezza.

## Riferimenti

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
