# Blockchain e Criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di base

- **Smart Contracts** sono definiti come programmi che vengono eseguiti su una blockchain quando vengono soddisfatte determinate condizioni, automatizzando l'esecuzione di accordi senza intermediari.
- **Decentralized Applications (dApps)** si basano sui smart contracts, con un front-end facile da usare e un back-end trasparente e verificabile.
- **Tokens & Coins** differenziano: le coin fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- **Utility Tokens** concedono accesso a servizi, e i **Security Tokens** indicano la proprietà di un asset.
- **DeFi** sta per Decentralized Finance, offrendo servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** si riferiscono rispettivamente a piattaforme di scambio decentralizzate e organizzazioni autonome decentralizzate.

## Meccanismi di consenso

I meccanismi di consenso garantiscono la convalida sicura e concordata delle transazioni sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza computazionale per la verifica delle transazioni.
- **Proof of Stake (PoS)** richiede che i validator detengano una certa quantità di token, riducendo il consumo energetico rispetto al PoW.

## Fondamenti di Bitcoin

### Transazioni

Le transazioni Bitcoin implicano il trasferimento di fondi tra indirizzi. Le transazioni sono validate tramite firme digitali, garantendo che solo il proprietario della chiave privata possa iniziare i trasferimenti.

#### Componenti chiave:

- **Multisignature Transactions** richiedono più firme per autorizzare una transazione.
- Le transazioni sono composte da **inputs** (sorgente dei fondi), **outputs** (destinazione), **fees** (pagate ai miners) e **scripts** (regole della transazione).

### Lightning Network

Ha lo scopo di migliorare la scalabilità di Bitcoin permettendo più transazioni all'interno di un canale, trasmettendo alla blockchain solo lo stato finale.

## Problemi di privacy in Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i modelli delle transazioni. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i legami delle transazioni tra gli utenti.

## Acquisire Bitcoin in modo anonimo

I metodi includono scambi in contanti, mining e l'uso di mixers. **CoinJoin** mescola più transazioni per complicare la tracciabilità, mentre **PayJoin** camuffa i CoinJoin come transazioni normali per aumentare la privacy.

# Attacchi alla privacy di Bitcoin

# Riepilogo degli attacchi alla privacy in Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di alcuni metodi comuni con cui un attaccante può compromettere la privacy su Bitcoin.

## **Common Input Ownership Assumption**

È generalmente raro che inputs provenienti da utenti diversi siano combinati in una singola transazione a causa della complessità. Di conseguenza, **due indirizzi di input nella stessa transazione sono spesso assunti come appartenenti allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, ovvero **Unspent Transaction Output**, deve essere speso completamente in una transazione. Se ne viene inviato solo una parte a un altro indirizzo, il resto va a un nuovo indirizzo di cambio (change address). Gli osservatori possono assumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio

Per mitigare questo, servizi di mixing o l'uso di più indirizzi possono aiutare a oscurare la proprietà.

## **Social Networks & Forums Exposure**

Gli utenti a volte condividono i loro indirizzi Bitcoin online, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Transaction Graph Analysis**

Le transazioni possono essere visualizzate come grafi, rivelando potenziali connessioni tra utenti in base al flusso di fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Questa euristica si basa sull'analisi di transazioni con più inputs e outputs per indovinare quale output è il resto che torna al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se l'aggiunta di più inputs fa sì che l'output di change sia più grande di qualsiasi singolo input, può confondere l'euristica.

## **Forced Address Reuse**

Gli attaccanti possono inviare piccole somme ad indirizzi già usati, sperando che il destinatario combini questi con altri input in transazioni future, collegando così gli indirizzi tra loro.

### Correct Wallet Behavior

I wallet dovrebbero evitare di usare i coin ricevuti su indirizzi già usati e vuoti per prevenire questa privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Le transazioni senza change sono probabilmente tra due indirizzi appartenenti allo stesso utente.
- **Round Numbers:** Un numero tondo in una transazione suggerisce che si tratta di un pagamento, con l'output non tondo probabilmente il change.
- **Wallet Fingerprinting:** Wallet diversi hanno schemi unici nella creazione delle transazioni, permettendo agli analisti di identificare il software usato e potenzialmente l'indirizzo di change.
- **Amount & Timing Correlations:** La divulgazione di orari o importi delle transazioni può renderle tracciabili.

## **Traffic Analysis**

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy degli utenti. Questo è particolarmente vero se un'entità gestisce molti Bitcoin nodes, migliorando la sua capacità di monitorare le transazioni.

## More

Per un elenco completo di attacchi alla privacy e difese, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquisire bitcoin tramite contanti.
- **Cash Alternatives**: Acquistare gift card e scambiarle online per bitcoin.
- **Mining**: Il metodo più privato per ottenere bitcoin è il mining, specialmente se fatto in solitaria perché i mining pools possono conoscere l'IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, rubare bitcoin potrebbe essere un altro metodo per ottenerli anonimamente, anche se è illegale e non raccomandato.

## Mixing Services

Usando un mixing service, un utente può **inviare bitcoins** e ricevere **bitcoins diversi in cambio**, rendendo difficile tracciare il proprietario originale. Tuttavia, questo richiede fiducia nel servizio affinché non tenga log e che effettivamente restituisca i bitcoins. Opzioni alternative di mixing includono i Bitcoin casinos.

## CoinJoin

**CoinJoin** unisce più transazioni da utenti diversi in una sola, complicando il compito di chi cerca di abbinare input e output. Nonostante la sua efficacia, le transazioni con dimensioni uniche di input e output possono ancora essere potenzialmente tracciate.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, dai un'occhiata a [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi provenienti dai miners.

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera la transazione tra due parti (ad es. un cliente e un commerciante) come una transazione normale, senza i distintivi output uguali tipici di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare l'heuristic common-input-ownership usata dagli enti di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**L'utilizzo di PayJoin potrebbe sconvolgere significativamente i metodi tradizionali di sorveglianza**, rendendolo un progresso promettente nella ricerca della privacy nelle transazioni.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Per mantenere privacy e sicurezza, è cruciale sincronizzare i wallet con la blockchain. Due metodi si distinguono:

- **Full node**: Scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni effettuate vengono archiviate localmente, rendendo impossibile per gli avversari identificare quali transazioni o indirizzi interessano l'utente.
- **Client-side block filtering**: Questo metodo prevede la creazione di filtri per ogni blocco della blockchain, permettendo ai wallet di identificare le transazioni rilevanti senza esporre interessi specifici agli osservatori di rete. I wallet leggeri scaricano questi filtri, recuperando i blocchi completi solo quando si trova una corrispondenza con gli indirizzi dell'utente.

## **Utilizing Tor for Anonymity**

Dato che Bitcoin opera su una rete peer-to-peer, è consigliabile utilizzare Tor per mascherare il proprio indirizzo IP, migliorando la privacy durante l'interazione con la rete.

## **Preventing Address Reuse**

Per salvaguardare la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Il riuso degli indirizzi può compromettere la riservatezza collegando più transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Suddividere un pagamento in più transazioni può oscurare l'importo della transazione, ostacolando gli attacchi sulla privacy.
- **Change avoidance**: Preferire transazioni che non richiedono output di change aumenta la privacy interrompendo i metodi di rilevamento del change.
- **Multiple change outputs**: Se evitare il change non è fattibile, generare più output di change può comunque migliorare la privacy.

# **Monero: A Beacon of Anonymity**

Monero affronta la necessità di anonimato assoluto nelle transazioni digitali, stabilendo un elevato standard per la privacy.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, prezzato in **gwei**. Per esempio, una transazione che costa 2,310,000 gwei (o 0.00231 ETH) coinvolge un gas limit e una base fee, con un tip per incentivare i miner. Gli utenti possono impostare un max fee per evitare di pagare troppo, con l'eccedenza rimborsata.

## **Executing Transactions**

Le transazioni in Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi utente o smart contract. Richiedono una fee e devono essere minate. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, i dati opzionali, il gas limit e le fee. Da notare che l'indirizzo del mittente è dedotto dalla firma, eliminando la necessità di includerlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque voglia operare con le criptovalute dando priorità a privacy e sicurezza.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

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
