{{#include ../../banners/hacktricks-training.md}}

## Concetti di Base

- **Smart Contracts** sono definiti come programmi che vengono eseguiti su una blockchain quando vengono soddisfatte determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- **Decentralized Applications (dApps)** si basano su smart contracts, presentando un'interfaccia utente intuitiva e un back-end trasparente e verificabile.
- **Tokens & Coins** differenziano dove le monete servono come denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- **Utility Tokens** concedono accesso ai servizi, e **Security Tokens** significano proprietà di asset.
- **DeFi** sta per Finanza Decentralizzata, offrendo servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** si riferiscono a Piattaforme di Scambio Decentralizzate e Organizzazioni Autonome Decentralizzate, rispettivamente.

## Meccanismi di Consenso

I meccanismi di consenso garantiscono validazioni di transazione sicure e concordate sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza computazionale per la verifica delle transazioni.
- **Proof of Stake (PoS)** richiede ai validatori di detenere una certa quantità di token, riducendo il consumo energetico rispetto al PoW.

## Fondamentali di Bitcoin

### Transazioni

Le transazioni Bitcoin comportano il trasferimento di fondi tra indirizzi. Le transazioni vengono validate tramite firme digitali, garantendo che solo il proprietario della chiave privata possa avviare i trasferimenti.

#### Componenti Chiave:

- **Transazioni Multisignature** richiedono più firme per autorizzare una transazione.
- Le transazioni consistono in **input** (fonte di fondi), **output** (destinazione), **commissioni** (pagate ai miner) e **script** (regole della transazione).

### Lightning Network

Punta a migliorare la scalabilità di Bitcoin consentendo più transazioni all'interno di un canale, trasmettendo solo lo stato finale alla blockchain.

## Preoccupazioni sulla Privacy di Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i modelli di transazione. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti delle transazioni tra gli utenti.

## Acquisire Bitcoin in Modo Anonimo

I metodi includono scambi in contante, mining e utilizzo di mixer. **CoinJoin** mescola più transazioni per complicare la tracciabilità, mentre **PayJoin** maschera i CoinJoin come transazioni normali per una maggiore privacy.

# Attacchi alla Privacy di Bitcoin

# Riepilogo degli Attacchi alla Privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso oggetto di preoccupazione. Ecco una panoramica semplificata di diversi metodi comuni attraverso i quali gli attaccanti possono compromettere la privacy di Bitcoin.

## **Assunzione di Proprietà di Input Comuni**

È generalmente raro che input di diversi utenti vengano combinati in una singola transazione a causa della complessità coinvolta. Pertanto, **due indirizzi di input nella stessa transazione sono spesso assunti appartenere allo stesso proprietario**.

## **Rilevamento dell'Indirizzo di Cambio UTXO**

Un UTXO, o **Unspent Transaction Output**, deve essere completamente speso in una transazione. Se solo una parte di esso viene inviata a un altro indirizzo, il resto va a un nuovo indirizzo di cambio. Gli osservatori possono assumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio

Per mitigare questo, i servizi di mixing o l'uso di più indirizzi possono aiutare a oscurare la proprietà.

## **Esposizione su Reti Sociali e Forum**

Gli utenti a volte condividono i loro indirizzi Bitcoin online, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Analisi del Grafo delle Transazioni**

Le transazioni possono essere visualizzate come grafi, rivelando potenziali collegamenti tra gli utenti in base al flusso di fondi.

## **Euristica di Input Non Necessari (Euristica di Cambio Ottimale)**

Questa euristica si basa sull'analisi delle transazioni con più input e output per indovinare quale output è il cambio che ritorna al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se l'aggiunta di più input rende l'output del cambiamento più grande di qualsiasi singolo input, può confondere l'euristica.

## **Riutilizzo Forzato degli Indirizzi**

Gli attaccanti possono inviare piccole somme a indirizzi già utilizzati, sperando che il destinatario le combini con altri input in future transazioni, collegando così gli indirizzi tra loro.

### Comportamento Corretto del Wallet

I wallet dovrebbero evitare di utilizzare monete ricevute su indirizzi già utilizzati e vuoti per prevenire questa perdita di privacy.

## **Altre Tecniche di Analisi della Blockchain**

- **Importi di Pagamento Esatti:** Le transazioni senza resto sono probabilmente tra due indirizzi di proprietà dello stesso utente.
- **Numeri Rotondi:** Un numero tondo in una transazione suggerisce che si tratta di un pagamento, con l'output non tondo che probabilmente è il resto.
- **Fingerprinting del Wallet:** I diversi wallet hanno schemi unici di creazione delle transazioni, consentendo agli analisti di identificare il software utilizzato e potenzialmente l'indirizzo di resto.
- **Correlazioni tra Importo e Tempistiche:** La divulgazione dei tempi o degli importi delle transazioni può rendere le transazioni tracciabili.

## **Analisi del Traffico**

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy degli utenti. Questo è particolarmente vero se un'entità gestisce molti nodi Bitcoin, migliorando la propria capacità di monitorare le transazioni.

## Altro

Per un elenco completo di attacchi alla privacy e difese, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transazioni Bitcoin Anonime

## Modi per Ottenere Bitcoin Anonimamente

- **Transazioni in Contante**: Acquisire bitcoin tramite contante.
- **Alternative al Contante**: Acquistare carte regalo e scambiarle online per bitcoin.
- **Mining**: Il metodo più privato per guadagnare bitcoin è attraverso il mining, specialmente se fatto da solo, poiché i pool di mining possono conoscere l'indirizzo IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Furto**: Teoricamente, rubare bitcoin potrebbe essere un altro metodo per acquisirlo in modo anonimo, anche se è illegale e non raccomandato.

## Servizi di Mixing

Utilizzando un servizio di mixing, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, il che rende difficile rintracciare il proprietario originale. Tuttavia, ciò richiede fiducia nel servizio affinché non tenga registri e restituisca effettivamente i bitcoin. Opzioni di mixing alternative includono i casinò Bitcoin.

## CoinJoin

**CoinJoin** unisce più transazioni da diversi utenti in una sola, complicando il processo per chiunque cerchi di abbinare input e output. Nonostante la sua efficacia, le transazioni con dimensioni di input e output uniche possono comunque essere potenzialmente tracciate.

Esempi di transazioni che potrebbero aver utilizzato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per ulteriori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, dai un'occhiata a [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi provenienti dai miner.

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera la transazione tra due parti (ad esempio, un cliente e un commerciante) come una transazione normale, senza le caratteristiche distintive degli output uguali tipiche di CoinJoin. Questo rende estremamente difficile da rilevare e potrebbe invalidare l'euristica di proprietà degli input comuni utilizzata dalle entità di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Le transazioni come quelle sopra potrebbero essere PayJoin, migliorando la privacy rimanendo indistinguibili dalle transazioni bitcoin standard.

**L'utilizzo di PayJoin potrebbe interrompere significativamente i metodi di sorveglianza tradizionali**, rendendolo uno sviluppo promettente nella ricerca della privacy transazionale.

# Migliori Pratiche per la Privacy nelle Criptovalute

## **Tecniche di Sincronizzazione dei Wallet**

Per mantenere la privacy e la sicurezza, è cruciale sincronizzare i wallet con la blockchain. Due metodi si distinguono:

- **Full node**: Scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate sono memorizzate localmente, rendendo impossibile per gli avversari identificare quali transazioni o indirizzi interessano l'utente.
- **Filtraggio dei blocchi lato client**: Questo metodo prevede la creazione di filtri per ogni blocco nella blockchain, consentendo ai wallet di identificare transazioni rilevanti senza esporre interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri, recuperando solo blocchi completi quando viene trovata una corrispondenza con gli indirizzi dell'utente.

## **Utilizzo di Tor per l'Anonymity**

Dato che Bitcoin opera su una rete peer-to-peer, si consiglia di utilizzare Tor per mascherare il proprio indirizzo IP, migliorando la privacy durante l'interazione con la rete.

## **Prevenire il Riutilizzo degli Indirizzi**

Per proteggere la privacy, è fondamentale utilizzare un nuovo indirizzo per ogni transazione. Riutilizzare indirizzi può compromettere la privacy collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi attraverso il loro design.

## **Strategie per la Privacy delle Transazioni**

- **Transazioni multiple**: Suddividere un pagamento in più transazioni può offuscare l'importo della transazione, ostacolando gli attacchi alla privacy.
- **Evitare il resto**: Optare per transazioni che non richiedono output di resto migliora la privacy interrompendo i metodi di rilevamento del resto.
- **Molteplici output di resto**: Se evitare il resto non è fattibile, generare molteplici output di resto può comunque migliorare la privacy.

# **Monero: Un Faro di Anonimato**

Monero risponde alla necessità di anonimato assoluto nelle transazioni digitali, stabilendo un elevato standard per la privacy.

# **Ethereum: Gas e Transazioni**

## **Comprendere il Gas**

Il gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, con un prezzo in **gwei**. Ad esempio, una transazione che costa 2.310.000 gwei (o 0.00231 ETH) comporta un limite di gas e una tariffa base, con una mancia per incentivare i miner. Gli utenti possono impostare una tariffa massima per garantire di non pagare troppo, con l'eccedenza rimborsata.

## **Esecuzione delle Transazioni**

Le transazioni in Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi di utenti o smart contract. Richiedono una tariffa e devono essere minate. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, dati opzionali, limite di gas e tariffe. Notabilmente, l'indirizzo del mittente è dedotto dalla firma, eliminando la necessità di includerlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque desideri interagire con le criptovalute dando priorità alla privacy e alla sicurezza.

## Riferimenti

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

{{#include ../../banners/hacktricks-training.md}}
