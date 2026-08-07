# Blockchain e criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di base

- Gli **Smart Contracts** sono definiti come programmi che vengono eseguiti su una blockchain quando vengono soddisfatte determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- Le **Decentralized Applications (dApps)** si basano sugli smart contract e includono un front-end intuitivo e un back-end trasparente e verificabile.
- **Tokens & Coins** si distinguono perché le coin fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- Gli **Utility Tokens** garantiscono l'accesso ai servizi, mentre gli **Security Tokens** rappresentano la proprietà di un asset.
- **DeFi** sta per Decentralized Finance e offre servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** indicano rispettivamente le Decentralized Exchange Platforms e le Decentralized Autonomous Organizations.

## Meccanismi di consenso

I meccanismi di consenso garantiscono convalide delle transazioni sicure e condivise sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza di calcolo per verificare le transazioni.
- **Proof of Stake (PoS)** richiede ai validator di possedere una determinata quantità di token, riducendo il consumo energetico rispetto al PoW.<sup>[[1]](#references)</sup>

## Elementi essenziali di Bitcoin

### Transazioni

Le transazioni Bitcoin comportano il trasferimento di fondi tra indirizzi. Le transazioni vengono convalidate tramite firme digitali, assicurando che solo il proprietario della private key possa avviare i trasferimenti.<sup>[[2]](#references)</sup>

#### Componenti principali:

- Le **Multisignature Transactions** richiedono più firme per autorizzare una transazione.<sup>[[3]](#references)</sup>
- Le transazioni sono costituite da **inputs** (fonte dei fondi), **outputs** (destinazione), **fees** (corrisposte ai miner) e **scripts** (regole della transazione).

### Lightning Network

Mira a migliorare la scalabilità di Bitcoin consentendo più transazioni all'interno di un canale e trasmettendo alla blockchain solo lo stato finale.

## Problemi di privacy di Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i pattern delle transazioni. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti tra le transazioni degli utenti.

## Acquisire Bitcoin in modo anonimo

I metodi includono scambi in contanti, mining e l'utilizzo di mixer. **CoinJoin** combina più transazioni per rendere più complessa la tracciabilità, mentre **PayJoin** maschera i CoinJoin da transazioni normali per aumentare la privacy.

# Attacchi alla privacy di Bitcoin

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Di seguito è riportata una panoramica semplificata di alcuni metodi comuni attraverso i quali gli attacker possono compromettere la privacy di Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

In genere è raro che gli input di utenti diversi vengano combinati in una singola transazione a causa della complessità coinvolta. Pertanto, **si presume spesso che due indirizzi di input nella stessa transazione appartengano allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, ovvero un **Unspent Transaction Output**, deve essere speso interamente in una transazione. Se solo una parte viene inviata a un altro indirizzo, il resto viene inviato a un nuovo change address. Gli osservatori possono presumere che questo nuovo indirizzo appartenga al mittente, compromettendo la privacy.

### Esempio

Per mitigare questo problema, i servizi di mixing o l'utilizzo di più indirizzi possono contribuire a nascondere la proprietà.

## **Social Networks & Forums Exposure**

Gli utenti a volte condividono online i propri indirizzi Bitcoin, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Transaction Graph Analysis**

Le transazioni possono essere visualizzate come grafi, rivelando potenziali collegamenti tra gli utenti in base al flusso dei fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Questa euristica si basa sull'analisi delle transazioni con più input e output per cercare di individuare quale output rappresenti il resto restituito al mittente.

### Esempio
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se l'aggiunta di ulteriori input rende l'output del resto più grande di qualsiasi singolo input, può confondere l'euristica.

## **Forced Address Reuse**

Gli aggressori possono inviare piccole somme a indirizzi utilizzati in precedenza, sperando che il destinatario li combini con altri input in transazioni future, collegando così gli indirizzi tra loro.

### Comportamento corretto del wallet

I wallet dovrebbero evitare di utilizzare le coin ricevute su indirizzi già utilizzati e vuoti, per prevenire questo privacy leak.

## **Altre tecniche di analisi della blockchain**

- **Importi di pagamento esatti:** Le transazioni senza resto probabilmente avvengono tra due indirizzi appartenenti allo stesso utente.
- **Numeri tondi:** Un numero tondo in una transazione suggerisce che si tratti di un pagamento, mentre l'output non tondo è probabilmente il resto.
- **Fingerprinting del wallet:** Wallet diversi presentano pattern unici nella creazione delle transazioni, consentendo agli analisti di identificare il software utilizzato e potenzialmente l'indirizzo del resto.
- **Correlazioni tra importo e tempistica:** La divulgazione degli orari o degli importi delle transazioni può rendere le transazioni tracciabili.

## **Traffic Analysis**

Monitorando il traffico di rete, gli aggressori possono potenzialmente collegare transazioni o blocchi agli indirizzi IP, compromettendo la privacy degli utenti. Ciò è particolarmente vero se un'entità gestisce molti nodi Bitcoin, aumentando la propria capacità di monitorare le transazioni.

## Altro

Per un elenco completo degli attacchi alla privacy e delle difese, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transazioni Bitcoin anonime

## Modi per ottenere Bitcoin in modo anonimo

- **Transazioni in contanti:** Ottenere bitcoin tramite contanti.
- **Alternative al contante:** Acquistare gift card e scambiarle online con bitcoin.
- **Mining:** Il metodo più privato per guadagnare bitcoin è fare mining, soprattutto quando viene eseguito individualmente, perché le mining pool possono conoscere l'indirizzo IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Furto:** In teoria, rubare bitcoin potrebbe essere un altro metodo per acquisirli in modo anonimo, sebbene sia illegale e sconsigliato.

## Mixing Services

Utilizzando un mixing service, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, rendendo difficile tracciare il proprietario originale. Tuttavia, ciò richiede fiducia nel fatto che il servizio non conservi log e restituisca effettivamente i bitcoin. Tra le alternative per il mixing ci sono i casinò Bitcoin.

## CoinJoin

**CoinJoin** unisce più transazioni di utenti diversi in una sola, complicando il processo per chiunque tenti di associare gli input agli output. Nonostante la sua efficacia, le transazioni con quantità uniche di input e output possono comunque essere potenzialmente tracciate.

Esempi di transazioni che potrebbero aver utilizzato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per ulteriori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, consulta [Tornado Cash](https://tornado.cash), che rende anonime le transazioni utilizzando fondi provenienti dai miner.

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera la transazione tra due parti (ad esempio, un cliente e un commerciante) facendola apparire come una transazione normale, senza la caratteristica distintiva degli output uguali di CoinJoin. Ciò la rende estremamente difficile da rilevare e potrebbe invalidare l'euristica della proprietà comune degli input utilizzata dalle entità di sorveglianza delle transazioni.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy pur rimanendo indistinguibili dalle transazioni bitcoin standard.

**L'utilizzo di PayJoin potrebbe compromettere significativamente i metodi tradizionali di sorveglianza**, rendendolo uno sviluppo promettente nella ricerca della privacy delle transazioni.

# Best Practice per la privacy nelle criptovalute

## **Tecniche di sincronizzazione dei wallet**

Per mantenere privacy e sicurezza, è fondamentale sincronizzare i wallet con la blockchain. Due metodi si distinguono:

- **Full node**: scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate vengono archiviate localmente, rendendo impossibile per gli avversari identificare quali transazioni o indirizzi interessano all'utente.
- **Filtraggio dei blocchi lato client**: questo metodo consiste nel creare filtri per ogni blocco della blockchain, consentendo ai wallet di identificare le transazioni pertinenti senza esporre interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri e recuperano i blocchi completi solo quando viene trovata una corrispondenza con gli indirizzi dell'utente.

## **Utilizzo di Tor per l'anonimato**

Poiché Bitcoin opera su una rete peer-to-peer, si consiglia di utilizzare Tor per mascherare l'indirizzo IP, migliorando la privacy durante l'interazione con la rete.

## **Prevenzione del riutilizzo degli indirizzi**

Per proteggere la privacy, è fondamentale utilizzare un nuovo indirizzo per ogni transazione. Il riutilizzo degli indirizzi può compromettere la privacy collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategie per la privacy delle transazioni**

- **Transazioni multiple**: suddividere un pagamento in diverse transazioni può oscurare l'importo della transazione, contrastando gli attacchi alla privacy.
- **Evitare il resto**: optare per transazioni che non richiedono output di resto migliora la privacy interrompendo i metodi di rilevamento del resto.
- **Output di resto multipli**: se evitare il resto non è possibile, generare più output di resto può comunque migliorare la privacy.

# **Monero: un faro dell'anonimato**

Monero risponde alla necessità di anonimato assoluto nelle transazioni digitali, stabilendo uno standard elevato per la privacy.

# **Ethereum: gas e transazioni**

## **Comprendere il gas**

Il gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum e ha un prezzo espresso in **gwei**. Ad esempio, una transazione dal costo di 2.310.000 gwei (o 0,00231 ETH) prevede un limite di gas e una fee di base, con una mancia per incentivare i miner. Gli utenti possono impostare una fee massima per assicurarsi di non pagare troppo; l'eccedenza viene rimborsata.<sup>[[5]](#references)</sup>

## **Esecuzione delle transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi di utenti o di smart contract. Richiedono una fee e devono essere sottoposte a mining. Le informazioni essenziali in una transazione includono il destinatario, la firma del mittente, il valore, i dati opzionali, il limite di gas e le fee. In particolare, l'indirizzo del mittente viene dedotto dalla firma, eliminando la necessità di includerlo nei dati della transazione.<sup>[[4]](#references)</sup>

Queste pratiche e questi meccanismi sono fondamentali per chiunque desideri utilizzare le criptovalute dando priorità a privacy e sicurezza.

## Red Teaming di Web3 incentrato sul valore

- Inventariare i componenti che detengono valore (signer, oracoli, bridge, automazione) per comprendere chi può trasferire i fondi e in che modo.
- Mappare ogni componente alle tattiche MITRE AADAPT pertinenti per esporre i percorsi di privilege escalation.
- Esercitare catene di attacco flash-loan/oracolo/credenziali/cross-chain per convalidare l'impatto e documentare le precondizioni sfruttabili.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromissione del workflow di signing Web3

- La manomissione della supply chain delle UI dei wallet può alterare i payload EIP-712 subito prima del signing, raccogliendo firme valide per takeover di proxy basati su delegatecall (ad esempio, la sovrascrittura dello slot 0 del masterCopy di Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Tra i comuni failure mode degli smart account figurano l'elusione dell'access control di `EntryPoint`, i campi gas non firmati, la validazione stateful, il replay di ERC-1271 e il drenaggio delle fee tramite revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sicurezza degli smart contract

- Mutation testing per individuare i punti ciechi nelle test suite:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrità dei proof guest ZK / zkVM

Quando un prover utilizza una **zkVM** o un circuito di proof specifico per l'applicazione per attestare un'asserzione, il verifier apprende soltanto che il **guest program è stato eseguito come scritto**. Se il guest contiene **unsafe deserialization**, **undefined behavior** o **vincoli semantici mancanti**, un prover malevolo può generare una proof che viene verificata mentre le **metriche pubbliche o l'invariante dichiarato sono falsi**.<sup>[[7]](#references)</sup>

### Unsafe deserialization all'interno dei proof guest

- Considerare i byte del witness/circuito privato come **input non attendibile controllato dall'attaccante**, anche se sono nascosti dalla proof.
- Evitare di deserializzarli con helper non verificati come `rkyv::access_unchecked`, a meno che i byte non siano già stati validati out-of-band.
- Discriminanti degli enum, puntatori relativi, lunghezze e indici caricati da dati serializzati non attendibili devono essere validati prima di influenzare il flusso di controllo o l'accesso alla memoria.

Pattern pratico di audit:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Se un campo come `op.kind` è un enum e un attacker può iniettare un **discriminante fuori intervallo**, ogni `match` successivo su quel valore diventa sospetto.

### Bypass dei contatori tramite jump-table / UB

Se Rust converte un `match` di grandi dimensioni in una **jump table**, un discriminante enum non valido può produrre un **flusso di controllo indefinito**. Un pattern pericoloso è:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un primo `match` aggiorna **contatori/vincoli critici per la sicurezza**.
2. Un secondo `match` esegue la **semantica effettiva dell'istruzione**.
3. Un discriminante fuori intervallo indicizza oltre la prima jump table e atterra nel codice associato alla seconda.

Risultato: l'operazione viene comunque eseguita, ma il percorso di contabilizzazione viene saltato. In una zkVM ciò può consentire di forgiare proof che riportano metriche impossibili, come un numero inferiore di gate, un numero inferiore di operazioni costose o altre risorse con limiti falsificati.

Checklist per la revisione:

- Cerca enum controllati dall'attacker e deserializzati da witness/private input.
- Analizza le istruzioni `match` ripetute sullo stesso campo opcode/kind.
- Considera la combinazione `unsafe` + deserializzazione senza controlli + dispatch di opcode di grandi dimensioni come ad alto rischio.
- Esegui il reverse engineering del binary generato quando necessario; il layout della jump table può essere più importante del codice sorgente.

### Vincoli semantici mancanti negli interpreti reversibili/specializzati

Non limitarti a validare la memory safety; valida anche le **regole semantiche** che la proof deve applicare.

Per gli instruction set reversibili/simili a quelli quantistici, assicurati che gli operandi che devono essere distinti siano effettivamente vincolati a essere distinti. Un'operazione simile a Toffoli/CCX implementata come:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
diventa non sicuro se il guest non rifiuta:
```text
op.q_control1 == op.q_control2 == op.q_target
```
In tal caso la transizione si riduce a:
```text
q = q ^ (q & q) = 0
```
Questo crea un **primitivo di reset deterministico**, violando le ipotesi di reversibilità e consentendo calcoli non intenzionali a costi inferiori. Nei proof system che attestano l'utilizzo delle risorse, ciò può permettere agli attacker di soddisfare i controlli funzionali bypassando il modello dei costi che il verifier ritiene di applicare.

### Cosa testare nei sistemi ZK

- Eseguire il fuzzing di tutti i parser guest con codifiche witness/private-input malformate.
- Verificare l'intervallo degli enum prima del dispatch degli opcode.
- Aggiungere controlli semantici per l'aliasing degli operandi e altre forme di istruzioni non valide.
- Confrontare i contatori riportati/pubblici con un'implementazione di riferimento indipendente.
- Ricordare che una proof valida può comunque dimostrare la **statement sbagliata** se il guest program contiene bug.

## Sfruttamento di DeFi/AMM

Se stai studiando lo sfruttamento pratico di DEX e AMM (hook di Uniswap v4, abuso di arrotondamenti/precisione, swap amplificati da flash loan che attraversano soglie), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per i weighted pool multi-asset che memorizzano nella cache i saldi virtuali e possono essere avvelenati quando `supply == 0`, studia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## Riferimenti

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Chiavi pubbliche e chiavi private spiegate - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Cosa sono le transazioni multi-signature? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transazioni | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas e commissioni | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Abbiamo battuto la zero-knowledge proof di Google sulla crittoanalisi quantistica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Proteggere le criptovalute basate su curve ellittiche dalle vulnerabilità quantistiche: stime delle risorse e mitigazioni (versione corretta)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repository proof-of-concept di Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
