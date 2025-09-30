# Blockchain e Criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di Base

- **Smart Contracts** sono definiti come programmi che vengono eseguiti su una blockchain quando vengono soddisfatte certe condizioni, automatizzando l'esecuzione di accordi senza intermediari.
- **Decentralized Applications (dApps)** si basano sugli smart contract, presentando un front-end user-friendly e un back-end trasparente e verificabile.
- **Tokens & Coins** si distinguono nel fatto che le coin fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- **Utility Tokens** concedono accesso a servizi, e **Security Tokens** indicano la proprietà di un asset.
- **DeFi** sta per Decentralized Finance, offrendo servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** si riferiscono rispettivamente a Decentralized Exchange Platforms e Decentralized Autonomous Organizations.

## Meccanismi di Consenso

I meccanismi di consenso garantiscono validazioni di transazione sicure e concordate sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza di calcolo per la verifica delle transazioni.
- **Proof of Stake (PoS)** richiede che i validator detengano una certa quantità di token, riducendo il consumo energetico rispetto al PoW.

## Nozioni Essenziali su Bitcoin

### Transazioni

Le transazioni Bitcoin implicano il trasferimento di fondi tra indirizzi. Le transazioni sono validate tramite firme digitali, assicurando che solo il proprietario della chiave privata possa avviare trasferimenti.

#### Componenti Chiave:

- **Multisignature Transactions** richiedono più firme per autorizzare una transazione.
- Le transazioni consistono di **inputs** (origine dei fondi), **outputs** (destinazione), **fees** (pagate ai miner) e **scripts** (regole della transazione).

### Lightning Network

Ha lo scopo di migliorare la scalabilità di Bitcoin permettendo molteplici transazioni all'interno di un canale, pubblicando sulla blockchain solo lo stato finale.

## Problemi di Privacy in Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano pattern nelle transazioni. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti tra le transazioni degli utenti.

## Come Acquisire Bitcoin in Modo Anonimo

I metodi includono scambi in contanti, mining e l'uso di mixers. **CoinJoin** miscela più transazioni per complicare la tracciabilità, mentre **PayJoin** camuffa i CoinJoin come transazioni ordinarie per una privacy maggiore.

# Attacchi alla Privacy di Bitcoin

# Sommario degli Attacchi alla Privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di alcuni metodi comuni tramite i quali un attaccante può compromettere la privacy su Bitcoin.

## **Common Input Ownership Assumption**

È generalmente raro che input di utenti differenti siano combinati in una singola transazione a causa della complessità coinvolta. Quindi, **due indirizzi input nella stessa transazione sono spesso assunti appartenere allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, deve essere speso interamente in una transazione. Se ne viene inviato solo in parte a un altro indirizzo, il resto va a un nuovo change address. Gli osservatori possono assumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio

Per mitigare questo problema, servizi di mixing o l'uso di più indirizzi possono aiutare a oscurare la proprietà.

## **Esposizione tramite Social Network & Forum**

Gli utenti a volte condividono i loro indirizzi Bitcoin online, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Transaction Graph Analysis**

Le transazioni possono essere visualizzate come grafi, rivelando possibili connessioni tra utenti basate sul flusso di fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Questa euristica si basa sull'analisi di transazioni con multiple input e output per indovinare quale output sia il change che ritorna al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se l'aggiunta di più input fa sì che il change output sia più grande di qualunque singolo input, può confondere l'euristica.

## **Forced Address Reuse**

Gli aggressori possono inviare piccole somme a indirizzi già usati, sperando che il destinatario combini questi importi con altri input in transazioni future, collegando così insieme gli indirizzi.

### Correct Wallet Behavior

I wallet dovrebbero evitare di usare monete ricevute su indirizzi già utilizzati e vuoti per prevenire questa privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Le transazioni senza change sono probabilmente tra due indirizzi posseduti dallo stesso utente.
- **Round Numbers:** Un numero tondo in una transazione suggerisce che sia un pagamento, con l'output non-tondo probabilmente il change.
- **Wallet Fingerprinting:** Different wallets have unique transaction creation patterns, allowing analysts to identify the software used and potentially the change address.
- **Amount & Timing Correlations:** Divulgare gli orari o gli importi delle transazioni può renderle tracciabili.

## **Traffic Analysis**

Monitorando il traffico di rete, gli aggressori possono potenzialmente collegare transazioni o blocchi ad indirizzi IP, compromettendo la privacy degli utenti. Questo è particolarmente vero se un'entità gestisce molti nodi Bitcoin, aumentando la sua capacità di monitorare le transazioni.

## More

Per un elenco completo di attacchi alla privacy e contromisure, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquisire bitcoin in contanti.
- **Cash Alternatives**: Acquistare carte regalo e cambiarle online per bitcoin.
- **Mining**: Il metodo più privato per guadagnare bitcoin è il mining, specialmente se fatto da soli, perché i mining pool possono conoscere l'IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, rubare bitcoin potrebbe essere un altro metodo per ottenerli in modo anonimo, sebbene sia illegale e non consigliato.

## Mixing Services

Usando un servizio di mixing, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, il che rende difficile rintracciare il proprietario originale. Tuttavia, questo richiede fiducia nel servizio a non conservare log e a restituire effettivamente i bitcoin. Opzioni alternative di mixing includono casinò Bitcoin.

## CoinJoin

CoinJoin unisce più transazioni di diversi utenti in una sola, complicando il lavoro di chi cerca di abbinare input a output. Nonostante la sua efficacia, transazioni con dimensioni uniche di input e output possono comunque essere tracciate.

Esempi di transazioni che potrebbero aver usato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, vedi [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi dai miner.

## PayJoin

Una variante di CoinJoin, PayJoin (o P2EP), camuffa la transazione tra due parti (es. cliente e commerciante) come una normale transazione, senza i distintivi output uguali caratteristici di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare la common-input-ownership heuristic usata dalle entità di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transazioni come quelle sopra potrebbero essere PayJoin, migliorando la privacy pur rimanendo indistinguibili dalle transazioni standard di bitcoin.

**L'utilizzo di PayJoin potrebbe mettere a dura prova i metodi di sorveglianza tradizionali**, rendendolo uno sviluppo promettente nella ricerca della privacy nelle transazioni.

# Best Practices per la privacy nelle criptovalute

## **Tecniche di sincronizzazione del wallet**

Per mantenere privacy e sicurezza, sincronizzare i wallet con la blockchain è cruciale. Risaltano due metodi:

- **Full node**: Scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate sono memorizzate localmente, rendendo impossibile per gli avversari identificare quali transazioni o indirizzi interessano l'utente.
- **Client-side block filtering**: Questo metodo prevede la creazione di filtri per ogni blocco della blockchain, permettendo ai wallet di identificare le transazioni rilevanti senza esporre interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri, recuperando i blocchi completi solo quando viene trovata una corrispondenza con gli indirizzi dell'utente.

## **Utilizzare Tor per l'anonimato**

Dato che Bitcoin opera su una rete peer-to-peer, è consigliato usare Tor per mascherare il proprio indirizzo IP, migliorando la privacy durante l'interazione con la rete.

## **Evitare il riutilizzo degli indirizzi**

Per tutelare la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Il riutilizzo degli indirizzi può compromettere la privacy collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategie per la privacy delle transazioni**

- **Transazioni multiple**: Suddividere un pagamento in più transazioni può oscurare l'importo, contrastando gli attacchi alla privacy.
- **Evitare gli output di resto**: Scegliere transazioni che non richiedono output di resto aumenta la privacy interrompendo i metodi di rilevamento del resto.
- **Molteplici output di resto**: Se evitare il resto non è possibile, generare molteplici output di resto può comunque migliorare la privacy.

# **Monero: Un faro di anonimato**

Monero risponde alla necessità di anonimato assoluto nelle transazioni digitali, fissando uno standard elevato per la privacy.

# **Ethereum: Gas e transazioni**

## **Comprendere il Gas**

Il gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, prezzato in **gwei**. Ad esempio, una transazione che costa 2,310,000 gwei (o 0.00231 ETH) comporta un gas limit e una base fee, con una tip per incentivare i minatori. Gli utenti possono impostare una max fee per assicurarsi di non pagare troppo, con l'eccesso rimborsato.

## **Esecuzione delle transazioni**

Le transazioni in Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi utente o smart contract. Richiedono una fee e devono essere minate. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, dati opzionali, gas limit e fee. Notare che l'indirizzo del mittente viene dedotto dalla firma, eliminando la necessità di includerlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque voglia interagire con le criptovalute dando priorità alla privacy e alla sicurezza.

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

Se stai ricercando lo sfruttamento pratico di DEXes e AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
