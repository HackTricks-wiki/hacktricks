# Blockchain e Criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di base

- **Smart Contracts** sono definiti come programmi che vengono eseguiti su una blockchain quando vengono soddisfatte certe condizioni, automatizzando l'esecuzione di accordi senza intermediari.
- **Decentralized Applications (dApps)** si basano sui smart contract, presentando un front-end user-friendly e un back-end trasparente e verificabile.
- **Tokens & Coins** differenziano dove le coin fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- **Utility Tokens** concedono accesso a servizi, e **Security Tokens** segnalano la proprietà di asset.
- **DeFi** sta per Decentralized Finance, offrendo servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** si riferiscono rispettivamente a Decentralized Exchange Platforms e Decentralized Autonomous Organizations.

## Meccanismi di consenso

I meccanismi di consenso garantiscono la validazione sicura e concordata delle transazioni sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza computazionale per la verifica delle transazioni.
- **Proof of Stake (PoS)** richiede che i validator detengano una certa quantità di token, riducendo il consumo energetico rispetto al PoW.

## Fondamenti di Bitcoin

### Transazioni

Le transazioni Bitcoin implicano il trasferimento di fondi tra indirizzi. Le transazioni sono validate tramite firme digitali, assicurando che solo il proprietario della chiave privata possa iniziare trasferimenti.

#### Componenti chiave:

- **Multisignature Transactions** richiedono più firme per autorizzare una transazione.
- Le transazioni sono composte da **inputs** (origine dei fondi), **outputs** (destinazione), **fees** (pagate ai miner) e **scripts** (regole della transazione).

### Lightning Network

Ha lo scopo di migliorare la scalabilità di Bitcoin permettendo molteplici transazioni all'interno di un canale, trasmettendo alla blockchain solo lo stato finale.

## Problemi di privacy di Bitcoin

Attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i pattern delle transazioni. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti tra transazioni e utenti.

## Acquisire Bitcoin in modo anonimo

I metodi includono scambi in contanti, mining e l'uso di mixer. **CoinJoin** mescola più transazioni per complicarne la tracciabilità, mentre **PayJoin** camuffa i CoinJoin come transazioni normali per una privacy migliorata.

# Attacchi alla privacy di Bitcoin

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di diversi metodi comuni attraverso cui un attaccante può compromettere la privacy di Bitcoin.

## **Common Input Ownership Assumption**

È generalmente raro che input provenienti da utenti diversi vengano combinati in una singola transazione a causa della complessità coinvolta. Di conseguenza, **due indirizzi input nella stessa transazione sono spesso presi per appartenere allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, deve essere speso interamente in una transazione. Se solo una parte viene inviata a un altro indirizzo, il resto viene inviato a un nuovo change address. Gli osservatori possono presumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio

Per mitigare questo rischio, i servizi di mixing o l'uso di più indirizzi possono aiutare a oscurare la proprietà.

## **Social Networks & Forums Exposure**

Gli utenti talvolta condividono i loro indirizzi Bitcoin online, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Transaction Graph Analysis**

Le transazioni possono essere visualizzate come grafi, rivelando potenziali connessioni tra gli utenti basate sul flusso di fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Quuristica basata sull'analisi di transazioni con input e output multipli per indovinare quale output sia il change che ritorna al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se l'aggiunta di più input fa sì che il change output sia più grande di qualsiasi singolo input, può confondere l'euristica.

## **Forced Address Reuse**

Gli attaccanti possono inviare piccole somme a indirizzi già usati, nella speranza che il destinatario combini questi importi con altri input in transazioni future, collegando così gli indirizzi.

### Comportamento corretto del wallet

I wallet dovrebbero evitare di usare coin ricevute su indirizzi già utilizzati e vuoti per prevenire questo privacy leak.

## **Other Blockchain Analysis Techniques**

- **Importi di pagamento esatti:** Le transazioni senza change sono probabilmente tra due indirizzi appartenenti allo stesso utente.
- **Numeri tondi:** Un numero tondo in una transazione suggerisce che si tratta di un pagamento, con l'output non-tondo probabilmente rappresentante il change.
- **Fingerprinting del wallet:** Wallet diversi hanno pattern unici di creazione delle transazioni, permettendo agli analisti di identificare il software usato e potenzialmente l'indirizzo di change.
- **Correlazioni tra importo e tempistica:** Rivelare tempi o importi delle transazioni può renderle tracciabili.

## Traffic Analysis

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi ad indirizzi IP, compromettendo la privacy degli utenti. Questo è particolarmente vero se un'entità gestisce molti nodi Bitcoin, aumentando la sua capacità di monitorare le transazioni.

## More

Per un elenco completo di attacchi alla privacy e delle contromisure, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquisire Bitcoin tramite contanti.
- **Cash Alternatives**: Acquistare gift card e scambiarle online per Bitcoin.
- **Mining**: Il metodo più privato per guadagnare Bitcoin è tramite mining, specialmente se eseguito da solo, poiché i mining pools possono conoscere l'indirizzo IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, il furto di bitcoin potrebbe essere un altro metodo per acquisirli in modo anonimo, anche se è illegale e non raccomandato.

## Mixing Services

Usando un mixing service, un utente può **send bitcoins** and receive **different bitcoins in return**, il che rende difficile rintracciare il proprietario originale. Tuttavia, ciò richiede fiducia nel servizio che non tenga log e che restituisca effettivamente i bitcoin. Opzioni alternative di mixing includono i Bitcoin casinos.

## CoinJoin

**CoinJoin** unisce più transazioni da diversi utenti in una sola, complicando il processo per chiunque cerchi di associare input a output. Nonostante la sua efficacia, le transazioni con dimensioni uniche di input e output possono comunque essere potenzialmente tracciate.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, dai un'occhiata a [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi provenienti dai miner.

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), camuffa la transazione tra due parti (es. cliente e commerciante) come una transazione normale, senza i tipici output uguali caratteristici di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare la common-input-ownership heuristic usata dalle entità di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy pur rimanendo indistinguibili dalle normali transazioni bitcoin.

**L'utilizzo di PayJoin potrebbe interrompere significativamente i metodi tradizionali di sorveglianza**, rendendolo un promettente sviluppo nella ricerca della privacy transazionale.

# Migliori pratiche per la privacy nelle criptovalute

## **Tecniche di sincronizzazione dei wallet**

Per mantenere privacy e sicurezza, sincronizzare i wallet con la blockchain è cruciale. Due metodi si distinguono:

- **Full node**: Scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate sono memorizzate localmente, rendendo impossibile agli avversari identificare quali transazioni o indirizzi interessano l'utente.
- **Client-side block filtering**: Questo metodo implica la creazione di filtri per ogni blocco della blockchain, permettendo ai wallet di identificare le transazioni rilevanti senza esporre interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri, recuperando i blocchi completi solo quando viene trovata una corrispondenza con gli indirizzi dell'utente.

## **Utilizzare Tor per l'anonimato**

Dato che Bitcoin opera su una rete peer-to-peer, si raccomanda di usare Tor per mascherare l'indirizzo IP, migliorando la privacy durante le interazioni con la rete.

## **Evitare il riutilizzo degli indirizzi**

Per proteggere la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Il riutilizzo degli indirizzi può compromettere la privacy collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategie per la privacy delle transazioni**

- **Più transazioni**: Suddividere un pagamento in più transazioni può oscurare l'importo della transazione, ostacolando attacchi alla privacy.
- **Evitare il change**: Preferire transazioni che non richiedono output di change migliora la privacy interrompendo i metodi di rilevamento del change.
- **Più output di change**: Se evitare il change non è fattibile, generare più output di change può comunque migliorare la privacy.

# **Monero: Un faro di anonimato**

Monero risponde alla necessità di anonimato assoluto nelle transazioni digitali, stabilendo uno standard elevato per la privacy.

# **Ethereum: Gas e transazioni**

## **Comprendere il Gas**

Il gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, prezzato in **gwei**. Ad esempio, una transazione che costa 2,310,000 gwei (o 0.00231 ETH) coinvolge un gas limit e una base fee, con una tip per incentivare i miner. Gli utenti possono impostare una max fee per assicurarsi di non pagare troppo, con l'eccesso rimborsato.

## **Esecuzione delle transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi di utente o smart contract. Richiedono una fee e devono essere minate. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, dati opzionali, gas limit e le fee. È importante notare che l'indirizzo del mittente è dedotto dalla firma, eliminando la necessità di includerlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque voglia interagire con le criptovalute dando priorità a privacy e sicurezza.

## Smart Contract Security

- Mutation testing per trovare punti ciechi nelle suite di test:

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

Se stai ricercando lo sfruttamento pratico di DEXes e AMM (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per multi-asset weighted pools che cacheano bilanci virtuali e possono essere avvelenati quando `supply == 0`, studia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
