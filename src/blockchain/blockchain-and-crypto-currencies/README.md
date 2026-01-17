# Blockchain e Criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di base

- **Smart Contracts** sono definiti come programmi che vengono eseguiti su una blockchain quando si verificano determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- **Decentralized Applications (dApps)** si basano sui smart contracts, presentando un front-end user-friendly e un back-end trasparente e verificabile.
- **Tokens & Coins** distinguono dove le coin fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- **Utility Tokens** concedono accesso a servizi, e **Security Tokens** indicano la proprietà di un asset.
- **DeFi** sta per Decentralized Finance, offrendo servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** si riferiscono rispettivamente a Decentralized Exchange Platforms e Decentralized Autonomous Organizations.

## Meccanismi di consenso

I meccanismi di consenso garantiscono validazioni delle transazioni sicure e concordate sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza di calcolo per la verifica delle transazioni.
- **Proof of Stake (PoS)** richiede che i validator detengano una certa quantità di token, riducendo il consumo energetico rispetto al PoW.

## Fondamenti di Bitcoin

### Transactions

Le transactions di Bitcoin implicano il trasferimento di fondi tra indirizzi. Le transactions sono validate tramite firme digitali, assicurando che solo il proprietario della private key possa avviare trasferimenti.

#### Componenti chiave:

- **Multisignature Transactions** richiedono più firme per autorizzare una transaction.
- Le transactions sono composte da **inputs** (fonte dei fondi), **outputs** (destinazione), **fees** (pagate ai miners) e **scripts** (regole della transaction).

### Lightning Network

Ha lo scopo di migliorare la scalabilità di Bitcoin permettendo multiple transactions all'interno di un channel, pubblicando sulla blockchain solo lo stato finale.

## Problematiche di privacy di Bitcoin

Attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i pattern delle transactions. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato rendendo meno evidenti i legami tra le transactions degli utenti.

## Acquisire Bitcoins in modo anonimo

I metodi includono trade in contanti, mining e l'uso di mixers. **CoinJoin** miscela multiple transactions per complicare la tracciabilità, mentre **PayJoin** maschera i CoinJoin come transactions normali per una privacy maggiore.

# Attacchi alla privacy di Bitcoin

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transactions e l'anonimato degli utenti sono spesso oggetto di preoccupazione. Ecco una panoramica semplificata di alcuni metodi comuni con cui un attaccante può compromettere la privacy di Bitcoin.

## **Common Input Ownership Assumption**

È generalmente raro che inputs provenienti da utenti differenti vengano combinati in una singola transaction a causa della complessità coinvolta. Quindi, **due indirizzi di input nella stessa transaction sono spesso assunti appartenere allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, deve essere speso interamente in una transaction. Se ne viene inviato solo un parte ad un altro indirizzo, il resto viene inviato a un nuovo change address. Gli osservatori possono assumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio

Per mitigare questo, servizi di mixing o l'uso di multiple addresses possono aiutare a offuscare la proprietà.

## **Esposizione tramite social network & forum**

Gli utenti a volte condividono i loro Bitcoin addresses online, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Analisi del grafo delle transactions**

Le transactions possono essere visualizzate come grafi, rivelando potenziali connessioni tra utenti basate sul flusso dei fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Quell'euristica si basa sull'analisi di transactions con multiple inputs e outputs per indovinare quale output sia il change che ritorna al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se l'aggiunta di più input rende l'output di resto più grande di qualsiasi singolo input, può confondere l'euristica.

## **Forced Address Reuse**

Gli aggressori possono inviare piccole somme ad indirizzi già utilizzati in precedenza, sperando che il destinatario combini questi importi con altri input in transazioni future, collegando così gli indirizzi tra loro.

### Correct Wallet Behavior

I wallet dovrebbero evitare di usare monete ricevute su indirizzi vuoti già usati per prevenire questo privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Le transazioni senza resto sono probabilmente tra due indirizzi appartenenti allo stesso utente.
- **Round Numbers:** Un importo tondo in una transazione suggerisce che si tratti di un pagamento, mentre l'output non tondo sarà probabilmente il resto.
- **Wallet Fingerprinting:** Diversi wallet hanno pattern unici nella creazione delle transazioni, permettendo agli analisti di identificare il software usato e, potenzialmente, l'indirizzo di resto.
- **Amount & Timing Correlations:** Rendere noti tempi o importi delle transazioni può renderle tracciabili.

## **Traffic Analysis**

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy degli utenti. Questo è particolarmente vero se un'entità gestisce molti nodi Bitcoin, aumentando la sua capacità di monitorare le transazioni.

## More

Per un elenco completo di attacchi alla privacy e delle difese, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquisire bitcoin tramite contanti.
- **Cash Alternatives**: Acquistare gift card e cambiarle online per ottenere bitcoin.
- **Mining**: Il metodo più privato per ottenere Bitcoin è il mining, specialmente se fatto da soli, perché le mining pools possono conoscere l'IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, rubare bitcoin potrebbe essere un altro modo per ottenerli in modo anonimo, anche se è illegale e non raccomandato.

## Mixing Services

Usando un servizio di mixing, un utente può inviare bitcoin e ricevere bitcoin differenti in cambio, rendendo difficile tracciare il proprietario originale. Tuttavia, questo richiede fiducia nel servizio affinché non mantenga log e che effettivamente restituisca i bitcoin. Opzioni alternative di mixing includono i casinò Bitcoin.

## CoinJoin

CoinJoin unisce più transazioni da diversi utenti in una sola, complicando il processo per chi tenta di associare input e output. Nonostante la sua efficacia, transazioni con input e output di dimensioni uniche possono comunque essere potenzialmente tracciate.

Esempi di transazioni che potrebbero aver usato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, dai un'occhiata a [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi provenienti dai miner.

## PayJoin

Una variante di CoinJoin, PayJoin (o P2EP), maschera la transazione tra due parti (es. un cliente e un commerciante) come una transazione normale, senza i distintivi output uguali caratteristici di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare la common-input-ownership heuristic usata dalle entità di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Le transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy pur rimanendo indistinguibili dalle transazioni bitcoin standard.

**L'utilizzo di PayJoin potrebbe compromettere in modo significativo i metodi di sorveglianza tradizionali**, rendendolo un promettente sviluppo nella ricerca della privacy delle transazioni.

# Buone pratiche per la privacy nelle criptovalute

## **Tecniche di sincronizzazione dei wallet**

Per mantenere privacy e sicurezza, sincronizzare i wallet con la blockchain è cruciale. Due metodi si distinguono:

- **Full node**: Scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate sono memorizzate localmente, rendendo impossibile per gli avversari identificare quali transazioni o indirizzi interessino l'utente.
- **Client-side block filtering**: Questo metodo implica la creazione di filtri per ogni blocco nella blockchain, permettendo ai wallet di identificare le transazioni rilevanti senza esporre interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri, recuperando i blocchi completi solo quando si trova una corrispondenza con gli indirizzi dell'utente.

## **Utilizzare Tor per l'anonimato**

Dato che Bitcoin opera su una rete peer-to-peer, si raccomanda l'uso di Tor per mascherare il proprio indirizzo IP, migliorando la privacy durante l'interazione con la rete.

## **Evitare il riutilizzo degli indirizzi**

Per proteggere la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Il riutilizzo degli indirizzi può compromettere la privacy collegando transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi attraverso il loro design.

## **Strategie per la privacy delle transazioni**

- **Multiple transactions**: Dividere un pagamento in più transazioni può offuscare l'importo della transazione, ostacolando attacchi alla privacy.
- **Change avoidance**: Scegliere transazioni che non richiedono output di resto aumenta la privacy, ostacolando i metodi di individuazione del resto.
- **Multiple change outputs**: Se evitare il resto non è fattibile, generare più output di resto può comunque migliorare la privacy.

# **Monero: Un faro di anonimato**

Monero risponde alla necessità di anonimato assoluto nelle transazioni digitali, fissando un elevato standard per la privacy.

# **Ethereum: Gas e transazioni**

## **Comprendere il Gas**

Gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, prezzo espresso in **gwei**. Per esempio, una transazione che costa 2,310,000 gwei (o 0.00231 ETH) coinvolge un gas limit e una base fee, con una tip per incentivare i miner. Gli utenti possono impostare una max fee per assicurarsi di non pagare troppo; l'eccesso viene rimborsato.

## **Esecuzione delle transazioni**

Le transazioni in Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi utente o smart contract. Richiedono una fee e devono essere mined. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, eventuali dati, il gas limit e le fee. È importante notare che l'indirizzo del mittente è ricavato dalla firma, eliminando la necessità di includerlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque voglia operare con le criptovalute dando priorità a privacy e sicurezza.

## Red Teaming Web3 orientato al valore

- Inventariare i componenti che detengono valore (signers, oracles, bridges, automation) per capire chi può spostare fondi e come.
- Mappare ogni componente alle tattiche MITRE AADAPT rilevanti per esporre percorsi di escalation dei privilegi.
- Eseguire simulazioni di catene di attacco flash-loan/oracle/credential/cross-chain per validare l'impatto e documentare le precondizioni sfruttabili.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromissione del workflow di firma Web3

- La manomissione della supply chain delle UI dei wallet può mutare i payload EIP-712 immediatamente prima della firma, raccogliendo firme valide per takeover di proxy basati su delegatecall (es. sovrascrittura di slot-0 del Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Sicurezza dei smart contract

- Mutation testing per trovare punti ciechi nelle suite di test:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Riferimenti

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## Sfruttamento DeFi/AMM

Se stai ricercando lo sfruttamento pratico di DEXes e AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per pool ponderati multi-asset che memorizzano in cache saldi virtuali e possono essere avvelenati quando `supply == 0`, studia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
