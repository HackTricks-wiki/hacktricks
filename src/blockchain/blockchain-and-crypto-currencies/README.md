# Blockchain e Criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di base

- **Smart Contracts** sono definiti come programmi che vengono eseguiti su una blockchain quando vengono soddisfatte determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- **Decentralized Applications (dApps)** si basano sui smart contracts e presentano un front-end intuitivo per l'utente e un back-end trasparente e verificabile.
- **Tokens & Coins** si distinguono per il fatto che le coins fungono da denaro digitale, mentre i tokens rappresentano valore o proprietà in contesti specifici.
- **Utility Tokens** concedono accesso a servizi, e **Security Tokens** indicano la proprietà di asset.
- **DeFi** sta per Decentralized Finance, offrendo servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** si riferiscono rispettivamente a Decentralized Exchange Platforms e Decentralized Autonomous Organizations.

## Meccanismi di consenso

I meccanismi di consenso garantiscono la validazione sicura e concordata delle transazioni sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza computazionale per la verifica delle transazioni.
- **Proof of Stake (PoS)** richiede che i validator detengano una certa quantità di token, riducendo il consumo energetico rispetto al PoW.

## Fondamentali di Bitcoin

### Transazioni

Le transazioni Bitcoin implicano il trasferimento di fondi tra indirizzi. Le transazioni sono validate tramite firme digitali, assicurando che solo il proprietario della chiave privata possa iniziare trasferimenti.

#### Componenti chiave:

- **Multisignature Transactions** richiedono più firme per autorizzare una transazione.
- Le transazioni sono composte da **inputs** (sorgente dei fondi), **outputs** (destinazione), **fees** (pagate ai miners) e **scripts** (regole della transazione).

### Lightning Network

Punta a migliorare la scalabilità di Bitcoin permettendo multiple transazioni all'interno di un canale, pubblicando sulla blockchain solo lo stato finale.

## Questioni di privacy di Bitcoin

Attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i pattern delle transazioni. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti delle transazioni tra gli utenti.

## Acquisire Bitcoin in modo anonimo

I metodi includono scambi in contanti, mining e l'uso di mixers. **CoinJoin** mescola più transazioni per complicare la tracciabilità, mentre **PayJoin** camuffa i CoinJoin come transazioni normali per una privacy maggiore.

# Attacchi alla privacy di Bitcoin

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di diversi metodi comuni attraverso i quali gli attaccanti possono compromettere la privacy su Bitcoin.

## **Common Input Ownership Assumption**

È generalmente raro che input provenienti da utenti diversi vengano combinati in una singola transazione a causa della complessità coinvolta. Quindi, **due indirizzi input nella stessa transazione sono spesso assunti appartenere allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, deve essere speso interamente in una transazione. Se ne viene inviato solo una parte a un altro indirizzo, il resto va a un nuovo change address. Gli osservatori possono assumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio

Per mitigare ciò, i servizi di mixing o l'uso di indirizzi multipli possono aiutare a oscurare la proprietà.

## **Social Networks & Forums Exposure**

Gli utenti talvolta condividono i loro indirizzi Bitcoin online, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Transaction Graph Analysis**

Le transazioni possono essere visualizzate come grafi, rivelando potenziali connessioni tra utenti basate sul flusso di fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Questa euristica si basa sull'analisi di transazioni con più input e output per indovinare quale output sia il change che ritorna al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se l'aggiunta di più input fa sì che il change output sia più grande di qualsiasi singolo input, può confondere l'euristica.

## **Riutilizzo forzato degli indirizzi**

Gli aggressori possono inviare piccole somme a indirizzi già usati, sperando che il destinatario combini questi importi con altri input in future transazioni, collegando così gli indirizzi tra loro.

### Comportamento corretto del wallet

I wallet dovrebbero evitare di usare monete ricevute su indirizzi già usati e vuoti per prevenire questa privacy leak.

## **Altre tecniche di analisi della blockchain**

- **Exact Payment Amounts:** Le transazioni senza change sono probabilmente tra due indirizzi di proprietà dello stesso utente.
- **Round Numbers:** Un numero tondo in una transazione suggerisce che sia un pagamento, con l'output non tondo che probabilmente è il change.
- **Wallet Fingerprinting:** Diversi wallet hanno pattern unici nella creazione delle transazioni, permettendo agli analisti di identificare il software usato e potenzialmente il change address.
- **Amount & Timing Correlations:** La divulgazione degli orari o degli importi delle transazioni può renderle tracciabili.

## **Analisi del traffico**

Monitorando il traffico di rete, gli aggressori possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy degli utenti. Questo è particolarmente vero se un'entità gestisce molti nodi Bitcoin, migliorando la loro capacità di monitorare le transazioni.

## Altro

Per un elenco completo di attacchi alla privacy e contromisure, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transazioni Bitcoin anonime

## Modi per ottenere Bitcoin in modo anonimo

- **Transazioni in contanti**: Acquistare bitcoin in contanti.
- **Alternative al contante**: Acquisto di carte regalo e scambio online per bitcoin.
- **Mining**: Il metodo più privato per guadagnare bitcoin è il mining, specialmente se fatto da soli, perché i mining pools possono conoscere l'indirizzo IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, rubare bitcoin potrebbe essere un altro metodo per ottenerli in modo anonimo, anche se è illegale e non raccomandato.

## Servizi di mixing

Usando un servizio di mixing, un utente può **send bitcoins** e ricevere **different bitcoins in return**, rendendo difficile rintracciare il proprietario originale. Tuttavia, ciò richiede fiducia nel servizio affinché non tenga log e per restituire effettivamente i bitcoin. Opzioni alternative di mixing includono i Bitcoin casinos.

## CoinJoin

**CoinJoin** unisce più transazioni da utenti diversi in una sola, complicando il processo per chi tenta di abbinare input con output. Nonostante la sua efficacia, le transazioni con dimensioni uniche di input e output possono comunque essere tracciate.

Esempi di transazioni che potrebbero aver usato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, controlla [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi provenienti dai miner.

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera la transazione tra due parti (ad esempio, un cliente e un commerciante) come una transazione normale, senza i distintivi output uguali tipici di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare la common-input-ownership heuristic usata dalle entità di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transazioni come quelle sopra potrebbero essere PayJoin, migliorando la privacy pur rimanendo indistinguibili dalle normali transazioni bitcoin.

**L'utilizzo di PayJoin potrebbe compromettere significativamente i metodi di sorveglianza tradizionali**, rendendolo un sviluppo promettente nella ricerca della privacy transazionale.

# Migliori pratiche per la privacy nelle criptovalute

## **Tecniche di sincronizzazione dei wallet**

Per mantenere privacy e sicurezza, sincronizzare i wallet con la blockchain è cruciale. Due metodi si distinguono:

- **Full node**: Scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate sono memorizzate localmente, rendendo impossibile per gli avversari identificare quali transazioni o indirizzi interessano all'utente.
- **Client-side block filtering**: Questo metodo prevede la creazione di filtri per ogni blocco della blockchain, permettendo ai wallet di identificare le transazioni rilevanti senza esporre interessi specifici agli osservatori di rete. I wallet lightweight scaricano questi filtri, recuperando i blocchi completi solo quando viene trovato un match con gli indirizzi dell'utente.

## **Utilizzo di Tor per l'anonimato**

Dato che Bitcoin opera su una rete peer-to-peer, è consigliabile usare Tor per mascherare il proprio indirizzo IP, migliorando la privacy durante l'interazione con la rete.

## **Evitare il riutilizzo degli indirizzi**

Per proteggere la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Il riutilizzo degli indirizzi può compromettere la privacy collegando transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategie per la privacy delle transazioni**

- **Multiple transactions**: Suddividere un pagamento in più transazioni può offuscare l'importo della transazione, ostacolando gli attacchi alla privacy.
- **Change avoidance**: Optare per transazioni che non richiedono change outputs migliora la privacy interrompendo i metodi di rilevamento del change.
- **Multiple change outputs**: Se evitare il change non è fattibile, generare più change outputs può comunque migliorare la privacy.

# **Monero: Un faro di anonimato**

Monero risponde alla necessità di anonimato assoluto nelle transazioni digitali, fissando un alto standard per la privacy.

# **Ethereum: Gas e transazioni**

## **Comprendere il Gas**

Il Gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, prezzato in **gwei**. Per esempio, una transazione che costa 2,310,000 gwei (o 0.00231 ETH) implica un gas limit e una base fee, con una tip per incentivare i miner. Gli utenti possono impostare una max fee per assicurarsi di non pagare eccessivamente, con l'eccedenza rimborsata.

## **Esecuzione delle transazioni**

Le transazioni in Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi utente o smart contract. Richiedono una fee e devono essere minate. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, dati opzionali, il gas limit e le fee. Nota che l'indirizzo del mittente viene ricavato dalla firma, eliminando la necessità di includerlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque voglia interagire con le criptovalute ponendo priorità alla privacy e alla sicurezza.

## Value-Centric Web3 Red Teaming

- Inventariare i componenti portatori di valore (signers, oracles, bridges, automation) per capire chi può muovere fondi e come.
- Mappare ogni componente alle tattiche MITRE AADAPT rilevanti per esporre percorsi di escalation dei privilegi.
- Provare catene di attacco flash-loan/oracle/credential/cross-chain per validare l'impatto e documentare le precondizioni sfruttabili.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- La manomissione della supply-chain delle UI dei wallet può mutare i payload EIP-712 immediatamente prima della firma, raccogliendo firme valide per takeover di proxy basati su delegatecall (es., sovrascrittura di slot-0 del masterCopy di Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- I comuni failure mode degli smart-account includono il bypass del controllo di accesso di `EntryPoint`, campi gas non firmati, validazione stateful, replay ERC-1271 e drenaggio delle fee tramite revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

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

Se stai ricercando lo sfruttamento pratico di DEXes e AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per pool ponderati multi-asset che cacheano bilanci virtuali e possono essere avvelenati quando `supply == 0`, studia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
