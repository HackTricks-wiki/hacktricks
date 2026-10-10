# Blockchain e criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di base

- Gli **Smart Contracts** sono programmi che vengono eseguiti su una blockchain al verificarsi di determinate condizioni, automatizzando l’esecuzione degli accordi senza intermediari.
- Le **Decentralized Applications (dApps)** si basano sugli smart contract e includono un’interfaccia front-end intuitiva e un back-end trasparente e verificabile.
- **Token e coin** si distinguono perché le coin fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
  - Gli **Utility Token** consentono l’accesso ai servizi, mentre i **Security Token** rappresentano la proprietà di un asset.
- **DeFi** sta per Decentralized Finance e offre servizi finanziari senza autorità centrali.
- **DEX** e **DAO** indicano rispettivamente le piattaforme di scambio decentralizzate e le organizzazioni autonome decentralizzate.

## Meccanismi di consenso

I meccanismi di consenso garantiscono che le transazioni sulla blockchain vengano validate in modo sicuro e concordato:

- **Proof of Work (PoW)** si basa sulla potenza di calcolo per verificare le transazioni.
- **Proof of Stake (PoS)** richiede ai validatori di possedere una determinata quantità di token, riducendo il consumo energetico rispetto al PoW.<sup>[[1]](#references)</sup>

## Concetti essenziali di Bitcoin

### Transazioni

Le transazioni Bitcoin comportano il trasferimento di fondi tra indirizzi. Vengono convalidate tramite firme digitali, che garantiscono che solo il proprietario della chiave privata possa avviare i trasferimenti.<sup>[[2]](#references)</sup>

#### Componenti principali:

- Le **transazioni multisignature** richiedono più firme per autorizzare una transazione.<sup>[[3]](#references)</sup>
- Le transazioni sono composte da **input** (fonte dei fondi), **output** (destinazione), **commissioni** (pagate ai miner) e **script** (regole della transazione).

### Lightning Network

Mira a migliorare la scalabilità di Bitcoin consentendo più transazioni all’interno di un canale e pubblicando sulla blockchain solo lo stato finale.

## Problemi di privacy di Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano gli schemi delle transazioni. Strategie come i **Mixer** e **CoinJoin** migliorano l’anonimato oscurando i collegamenti tra le transazioni degli utenti.

## Ottenere Bitcoin in modo anonimo

I metodi includono gli scambi in contanti, il mining e l’uso di mixer. **CoinJoin** mescola più transazioni per complicarne la tracciabilità, mentre **PayJoin** maschera le transazioni CoinJoin facendole sembrare transazioni normali, per garantire maggiore privacy.

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l’anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di alcuni metodi comuni con cui gli aggressori possono compromettere la privacy di Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

In genere è raro che gli input di utenti diversi vengano combinati in un’unica transazione, data la complessità dell’operazione. Perciò, **si presume spesso che due indirizzi di input della stessa transazione appartengano allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, ovvero un **Unspent Transaction Output**, deve essere speso interamente in una transazione. Se ne viene inviata solo una parte a un altro indirizzo, il resto viene inviato a un nuovo indirizzo di resto. Gli osservatori possono presumere che questo nuovo indirizzo appartenga al mittente, compromettendone la privacy.

### Esempio

Per mitigare questo problema, è possibile usare servizi di mixing o più indirizzi per rendere meno evidente la titolarità.

## **Esposizione sui social network e sui forum**

A volte gli utenti condividono online i propri indirizzi Bitcoin, rendendo **facile collegare l’indirizzo al suo proprietario**.

## **Analisi del grafo delle transazioni**

Le transazioni possono essere rappresentate come grafi, rivelando potenziali collegamenti tra utenti in base al flusso dei fondi.

## **Euristica degli input non necessari (euristica del resto ottimale)**

Questa euristica si basa sull’analisi delle transazioni con più input e output per ipotizzare quale output rappresenti il resto restituito al mittente.

### Esempio

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se l'aggiunta di altri input rende l'output di resto più grande di qualsiasi singolo input, può confondere l'euristica.

## **Riutilizzo forzato degli indirizzi**

Gli aggressori possono inviare piccoli importi a indirizzi già utilizzati, nella speranza che il destinatario li combini con altri input in transazioni future, collegando così gli indirizzi tra loro.

### Comportamento corretto del wallet

I wallet dovrebbero evitare di usare monete ricevute su indirizzi già utilizzati e vuoti per prevenire questa fuga di privacy.

## **Altre tecniche di analisi della blockchain**

- **Importi esatti dei pagamenti:** Le transazioni senza resto probabilmente avvengono tra due indirizzi posseduti dallo stesso utente.
- **Numeri tondi:** Un numero tondo in una transazione suggerisce che si tratti di un pagamento, mentre l'output non tondo probabilmente è il resto.
- **Fingerprinting del wallet:** Wallet diversi hanno schemi di creazione delle transazioni unici, che permettono agli analisti di identificare il software utilizzato e potenzialmente l'indirizzo del resto.
- **Correlazioni tra importi e orari:** Divulgare gli orari o gli importi delle transazioni può renderle tracciabili.

## **Analisi del traffico**

Monitorando il traffico di rete, gli aggressori possono potenzialmente collegare transazioni o blocchi agli indirizzi IP, compromettendo la privacy degli utenti. Ciò è particolarmente vero se un'entità gestisce molti nodi Bitcoin, aumentando la sua capacità di monitorare le transazioni.

## Altro

Per un elenco completo degli attacchi alla privacy e delle relative difese, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transazioni Bitcoin anonime

## Modi per ottenere Bitcoin in modo anonimo

- **Transazioni in contanti**: Ottenere bitcoin in contanti.
- **Alternative al contante**: Acquistare carte regalo e scambiarle online con bitcoin.
- **Mining**: Il metodo più privato per guadagnare bitcoin è fare mining, specialmente da soli, perché le mining pool potrebbero conoscere l'indirizzo IP del miner. [Informazioni sulle mining pool](https://en.bitcoin.it/wiki/Pooled_mining)
- **Furto**: In teoria, rubare bitcoin potrebbe essere un altro modo per ottenerli anonimamente, anche se è illegale e sconsigliato.

## Servizi di mixing

Usando un servizio di mixing, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, rendendo difficile risalire al proprietario originale. Tuttavia, ciò richiede di fidarsi del servizio, affinché non conservi i log e restituisca effettivamente i bitcoin. Tra le alternative per il mixing ci sono i casinò Bitcoin.

## CoinJoin

**CoinJoin** unisce più transazioni di utenti diversi in una sola, complicando il processo per chiunque cerchi di associare gli input agli output. Nonostante la sua efficacia, le transazioni con importi unici per input e output possono comunque essere tracciate.

Esempi di transazioni che potrebbero aver utilizzato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un mixer basato su smart contract di Ethereum che separa i depositi dai prelievi successivi, consulta [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera la transazione tra due parti (ad esempio, un cliente e un commerciante) facendola sembrare una transazione normale, senza gli output uguali distintivi di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare l'euristica della proprietà comune degli input usata dagli enti che sorvegliano le transazioni.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy pur restando indistinguibili dalle transazioni bitcoin standard.

**L'utilizzo di PayJoin potrebbe compromettere significativamente i metodi di sorveglianza tradizionali**, rappresentando uno sviluppo promettente nella ricerca della privacy delle transazioni.

# Buone pratiche per la privacy nelle criptovalute

## **Tecniche di sincronizzazione dei wallet**

Per mantenere privacy e sicurezza, è fondamentale sincronizzare i wallet con la blockchain. Due metodi si distinguono:

- **Nodo completo**: scaricando l'intera blockchain, un nodo completo garantisce la massima privacy. Tutte le transazioni mai effettuate vengono archiviate localmente, rendendo impossibile agli avversari identificare le transazioni o gli indirizzi a cui l'utente è interessato.
- **Filtraggio dei blocchi lato client**: questo metodo consiste nel creare filtri per ogni blocco della blockchain, consentendo ai wallet di individuare le transazioni pertinenti senza rivelare interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri e recuperano i blocchi completi solo quando viene trovata una corrispondenza con gli indirizzi dell'utente.

## **Utilizzare Tor per l'anonimato**

Poiché Bitcoin opera su una rete peer-to-peer, si consiglia di usare Tor per mascherare il proprio indirizzo IP e migliorare la privacy durante l'interazione con la rete.

## **Evitare il riutilizzo degli indirizzi**

Per tutelare la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Riutilizzare gli indirizzi può compromettere la privacy, collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi attraverso la loro progettazione.

## **Strategie per la privacy delle transazioni**

- **Transazioni multiple**: suddividere un pagamento in più transazioni può rendere meno evidente l'importo, ostacolando gli attacchi alla privacy.
- **Evitare il resto**: scegliere transazioni che non richiedono output di resto migliora la privacy, ostacolando i metodi di rilevamento del resto.
- **Output di resto multipli**: se non è possibile evitare il resto, generarne più output può comunque migliorare la privacy.

# **Monero: un faro di anonimato**

Monero è progettato per dare priorità alla privacy delle transazioni.

# **Ethereum: gas e transazioni**

## **Comprendere il gas**

Il gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum e ha un prezzo espresso in **gwei**. Per esempio, una transazione che costa 2,310,000 gwei (o 0.00231 ETH) prevede un limite di gas e una commissione di base, oltre a una commissione di priorità per incentivare l'inclusione da parte di un validatore. Gli utenti possono impostare una commissione massima per evitare di pagare troppo; l'importo in eccesso viene rimborsato.<sup>[[5]](#references)</sup>

## **Eseguire transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi di utenti o di smart contract. Richiedono una commissione e devono essere incluse in un blocco. Le informazioni essenziali di una transazione includono il destinatario, la firma del mittente, il valore, eventuali dati, il limite di gas e le commissioni. In particolare, l'indirizzo del mittente viene dedotto dalla firma, quindi non è necessario includerlo nei dati della transazione.<sup>[[4]](#references)</sup>

Queste pratiche e questi meccanismi sono fondamentali per chiunque desideri utilizzare le criptovalute dando priorità a privacy e sicurezza.

## Red Teaming Web3 orientato al valore

- Inventariare i componenti che detengono valore (firmatari, oracoli, bridge, automazione) per comprendere chi può spostare fondi e in che modo.
- Mappare ogni componente alle tattiche MITRE AADAPT pertinenti per individuare i percorsi di escalation dei privilegi.
- Simulare catene di attacco basate su flash loan/oracoli/credenziali/cross-chain per convalidarne l'impatto e documentare i prerequisiti sfruttabili.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromissione del flusso di firma Web3

- La manomissione della supply chain delle interfacce dei wallet può modificare i payload EIP-712 subito prima della firma, raccogliendo firme valide per takeover di proxy basati su delegatecall (ad es. sovrascrittura dello slot 0 di `masterCopy` di Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Astrazione degli account (ERC-4337)

- Tra i comuni punti deboli degli smart account rientrano l'elusione dei controlli di accesso di `EntryPoint`, i campi gas non firmati, la validazione con stato, i replay di ERC-1271 e il drenaggio delle commissioni tramite revert dopo la validazione.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sicurezza degli smart contract

- Utilizzare il mutation testing per individuare punti ciechi nelle suite di test:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrità dei guest delle prove ZK / zkVM

Quando un prover usa una **zkVM** o un circuito di prova specifico dell'applicazione per attestare un'affermazione, il verifier apprende soltanto che il **guest program è stato eseguito come scritto**. Se il guest contiene **deserializzazione non sicura**, **comportamento indefinito** o **vincoli semantici mancanti**, un prover malevolo può generare una prova che viene verificata anche se le **metriche pubbliche o l'invariante dichiarato sono falsi**.<sup>[[7]](#references)</sup>

### Deserializzazione non sicura nei guest delle prove

- Considerare i byte del witness/circuito privato come **input non attendibile controllato dall'attaccante**, anche se sono nascosti dalla prova.
- Evitare di deserializzarli con funzioni helper non verificate come `rkyv::access_unchecked`, a meno che i byte non siano già stati convalidati separatamente.
- I discriminanti degli enum, i puntatori relativi, le lunghezze e gli indici caricati da dati serializzati non attendibili devono essere convalidati prima di influire sul flusso di controllo o sull'accesso alla memoria.

Schema pratico di audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se un campo come `op.kind` è un enum e un attacker può iniettare un **discriminante fuori intervallo**, ogni `match` successivo su quel valore diventa sospetto.

### Bypass dei contatori tramite jump table / UB

Se Rust traduce un `match` esteso in una **jump table**, un discriminante enum non valido può causare **flusso di controllo indefinito**. Un pattern pericoloso è:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` aggiorna **contatori/vincoli critici per la sicurezza**.
2. Un secondo `match` esegue la **semantica effettiva dell'istruzione**.
3. Un discriminante fuori intervallo indicizza oltre la prima jump table e finisce nel codice associato alla seconda.

Risultato: l'operazione viene comunque eseguita, ma il percorso di contabilizzazione viene saltato. In una zkVM questo può consentire di falsificare prove che riportano metriche impossibili, come un numero inferiore di gate, meno operazioni costose o altre risorse limitate falsificate.

Checklist di revisione:

- Cerca enum controllati dall'attacker e deserializzati da witness/input privato.
- Esamina le istruzioni `match` ripetute sullo stesso campo opcode/kind.
- Considera `unsafe` + deserializzazione senza controlli + dispatch di opcode esteso una combinazione ad alto rischio.
- Se necessario, esegui il reverse engineering del binario generato: la disposizione della jump table può essere più importante del sorgente.

### Vincoli semantici mancanti negli interpreti reversibili/specializzati

Non limitarti a convalidare la sicurezza della memoria: convalida anche le **regole semantiche** che la prova dovrebbe far rispettare.

Per set di istruzioni reversibili/simili a quelle quantistiche, assicurati che gli operandi che devono essere distinti siano effettivamente vincolati a essere distinti. Un'operazione simile a Toffoli/CCX implementata come:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

diventa insicuro se il guest non rifiuta:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In tal caso, la transizione si riduce a:

```text
q = q ^ (q & q) = 0
```

Questo crea una **primitiva di reset deterministica**, violando le ipotesi di reversibilità e consentendo calcoli non previsti a costi inferiori. Nei sistemi di prova che attestano l'utilizzo delle risorse, ciò può consentire agli attaccanti di superare i controlli funzionali aggirando al contempo il modello dei costi che il verificatore ritiene di applicare.

### Cosa testare nei sistemi ZK

- Eseguire fuzzing su tutti i parser guest con codifiche malformate di witness/input privati.
- Verificare l'intervallo degli enum prima dell'invio delle istruzioni all'opcode.
- Aggiungere controlli semantici per l'aliasing degli operandi e altre forme di istruzione non valide.
- Confrontare i contatori dichiarati/pubblici con un'implementazione di riferimento indipendente.
- Ricorda che una prova valida può comunque dimostrare l'**affermazione sbagliata** se il programma guest contiene bug.

## Autorizzazione dipendente dallo stato

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Sfruttamento di DeFi/AMM

Se stai studiando lo sfruttamento pratico di DEX e AMM (hook di Uniswap v4, abuso di arrotondamenti/precisione, swap che superano soglie amplificati da flash loan), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per i pool multi-asset ponderati che memorizzano nella cache i saldi virtuali e possono essere avvelenati quando `supply == 0`, consulta:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key Explained - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [What are multi-signature transactions? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas and fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
