# Blockchain e Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Concetti di Base

- **Smart Contracts** sono definiti come programmi che eseguono su una blockchain quando vengono soddisfatte determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- **Decentralized Applications (dApps)** si basano su smart contracts, con un front-end user-friendly e un back-end trasparente e verificabile.
- **Tokens & Coins** distinguono dove le coins fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
- **Utility Tokens** concedono accesso ai servizi, e i **Security Tokens** indicano la proprietà di un asset.
- **DeFi** sta per Decentralized Finance, e offre servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** si riferiscono rispettivamente a Decentralized Exchange Platforms e Decentralized Autonomous Organizations.

## Meccanismi di Consenso

I meccanismi di consenso garantiscono validazioni delle transazioni sicure e concordate sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza di calcolo per la verifica delle transazioni.
- **Proof of Stake (PoS)** richiede che i validator detengano una certa quantità di token, riducendo il consumo energetico rispetto a PoW.

## Fondamentali di Bitcoin

### Transazioni

Le transazioni Bitcoin comportano il trasferimento di fondi tra indirizzi. Le transazioni vengono validate tramite firme digitali, garantendo che solo il proprietario della private key possa avviare i trasferimenti.

#### Componenti Chiave:

- Le **Multisignature Transactions** richiedono più firme per autorizzare una transazione.
- Le transazioni sono composte da **inputs** (fonte dei fondi), **outputs** (destinazione), **fees** (pagate ai miner) e **scripts** (regole della transazione).

### Lightning Network

Mira a migliorare la scalabilità di Bitcoin consentendo più transazioni all'interno di un canale, trasmettendo alla blockchain solo lo stato finale.

## Preoccupazioni sulla Privacy di Bitcoin

Attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i pattern delle transazioni. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti tra le transazioni degli utenti.

## Acquisire Bitcoin in Modo Anonimo

I metodi includono scambi in contanti, mining e uso di mixers. **CoinJoin** mescola più transazioni per complicare la tracciabilità, mentre **PayJoin** maschera i CoinJoin come transazioni normali per una privacy maggiore.

# Bitcoin Privacy Atacks

# Riepilogo degli Attacchi alla Privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di diversi metodi comuni attraverso cui gli attacker possono compromettere la privacy di Bitcoin.

## **Common Input Ownership Assumption**

In genere è raro che input di utenti diversi vengano combinati in una singola transazione a causa della complessità coinvolta. Pertanto, **due indirizzi di input nella stessa transazione vengono spesso considerati appartenere allo stesso owner**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, deve essere speso interamente in una transazione. Se solo una parte viene inviata a un altro indirizzo, il resto va a un nuovo change address. Gli osservatori possono assumere che questo nuovo indirizzo appartenga al sender, compromettendo la privacy.

### Example

Per mitigare questo, servizi di mixing o l'uso di più indirizzi possono aiutare a oscurare la proprietà.

## **Esposizione tramite Social Networks & Forums**

Gli utenti a volte condividono i propri indirizzi Bitcoin online, rendendo **facile collegare l'indirizzo al suo owner**.

## **Analisi del Transaction Graph**

Le transazioni possono essere visualizzate come graph, rivelando potenziali connessioni tra utenti in base al flusso dei fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Questa heuristic si basa sull'analisi di transazioni con più input e output per indovinare quale output sia il change che torna al sender.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se aggiungere più input rende l'output di change più grande di qualsiasi singolo input, può confondere l'euristica.

## **Forced Address Reuse**

Gli attacker possono inviare piccole quantità a indirizzi già usati, sperando che il destinatario le combini con altri input in future transazioni, collegando così gli indirizzi tra loro.

### Correct Wallet Behavior

I wallet dovrebbero evitare di usare coin ricevute su indirizzi vuoti già usati per prevenire questo leak di privacy.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Le transazioni senza change probabilmente avvengono tra due indirizzi posseduti dallo stesso user.
- **Round Numbers:** Un numero tondo in una transazione suggerisce che sia un pagamento, mentre l'output non tondo è probabilmente il change.
- **Wallet Fingerprinting:** Wallet diversi hanno pattern unici di creazione delle transazioni, permettendo agli analyst di identificare il software usato e potenzialmente l'indirizzo di change.
- **Amount & Timing Correlations:** Rivelare i tempi o gli importi delle transazioni può renderle tracciabili.

## **Traffic Analysis**

Monitorando il network traffic, gli attacker possono potenzialmente collegare transazioni o blocchi agli indirizzi IP, compromettendo la privacy degli user. Questo è particolarmente vero se un'entità gestisce molti nodi Bitcoin, aumentando la sua capacità di monitorare le transazioni.

## More

Per un elenco completo di privacy attack e defense, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquisire bitcoin tramite cash.
- **Cash Alternatives**: Acquistare gift cards e scambiarle online per bitcoin.
- **Mining**: Il metodo più private per guadagnare bitcoin è il mining, specialmente se fatto da soli perché i mining pool possono conoscere l'indirizzo IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: In teoria, rubare bitcoin potrebbe essere un altro metodo per acquisirli anonymous, anche se è illegale e non raccomandato.

## Mixing Services

Usando un mixing service, un user può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, rendendo difficile tracciare il proprietario originale. Tuttavia, ciò richiede fiducia nel servizio perché non conservi log e restituisca davvero i bitcoin. Opzioni alternative di mixing includono i Bitcoin casino.

## CoinJoin

**CoinJoin** unisce più transazioni di utenti diversi in una sola, complicando il processo per chiunque cerchi di abbinare input e output. Nonostante la sua efficacia, le transazioni con dimensioni uniche di input e output possono ancora essere potenzialmente tracciate.

Esempi di transazioni che potrebbero aver usato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un servizio simile su Ethereum, dai un'occhiata a [Tornado Cash](https://tornado.cash), che anonimizza le transazioni con fondi dei miner.

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), camuffa la transazione tra due parti (ad es. un customer e un merchant) come una normale transazione, senza i distintivi output uguali caratteristici di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare la common-input-ownership heuristic usata dalle entità di transaction surveillance.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**L'utilizzo di PayJoin potrebbe sconvolgere significativamente i metodi di sorveglianza tradizionali**, rendendolo uno sviluppo promettente nella ricerca della privacy transazionale.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Per mantenere privacy e sicurezza, sincronizzare i wallet con la blockchain è cruciale. Si distinguono due metodi:

- **Full node**: Scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate sono memorizzate localmente, rendendo impossibile per gli avversari identificare quali transazioni o indirizzi interessino l'utente.
- **Client-side block filtering**: Questo metodo consiste nel creare filtri per ogni blocco nella blockchain, consentendo ai wallet di identificare le transazioni rilevanti senza esporre interessi specifici agli osservatori di rete. I wallet leggeri scaricano questi filtri, recuperando i full blocks solo quando viene trovato un match con gli indirizzi dell'utente.

## **Utilizing Tor for Anonymity**

Dato che Bitcoin opera su una rete peer-to-peer, è consigliato usare Tor per mascherare il tuo indirizzo IP, migliorando la privacy quando interagisci con la rete.

## **Preventing Address Reuse**

Per proteggere la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Il riutilizzo degli indirizzi può compromettere la privacy collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Suddividere un pagamento in più transazioni può oscurare l'importo della transazione, ostacolando gli attacchi alla privacy.
- **Change avoidance**: Optare per transazioni che non richiedono output di change migliora la privacy interrompendo i metodi di rilevamento del change.
- **Multiple change outputs**: Se evitare il change non è fattibile, generare più output di change può comunque migliorare la privacy.

# **Monero: A Beacon of Anonymity**

Monero risponde alla necessità di anonimato assoluto nelle transazioni digitali, stabilendo un alto standard per la privacy.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum, prezzato in **gwei**. Per esempio, una transazione che costa 2,310,000 gwei (o 0.00231 ETH) comporta un gas limit e una base fee, con una tip per incentivare i miners. Gli utenti possono impostare una max fee per assicurarsi di non pagare troppo, con l'eccesso rimborsato.

## **Executing Transactions**

Le transazioni in Ethereum coinvolgono un sender e un recipient, che possono essere indirizzi di utenti o di smart contract. Richiedono una fee e devono essere mined. Le informazioni essenziali in una transazione includono il recipient, la signature del sender, il value, dati opzionali, gas limit e fees. In particolare, l'indirizzo del sender viene dedotto dalla signature, eliminando la necessità di inserirlo nei dati della transazione.

Queste pratiche e meccanismi sono fondamentali per chiunque voglia interagire con le cryptocurrencies dando priorità a privacy e sicurezza.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

When a prover uses a **zkVM** or an application-specific proof circuit to attest a claim, the verifier is only learning that the **guest program executed as written**. If the guest contains **unsafe deserialization**, **undefined behavior**, or **missing semantic constraints**, a malicious prover may generate a proof that verifies while the **public metrics or claimed invariant are false**.

### Unsafe deserialization inside proof guests

- Treat private witness/circuit bytes as **untrusted attacker input** even if they are hidden by the proof.
- Avoid deserializing them with unchecked helpers such as `rkyv::access_unchecked` unless the bytes were already validated out-of-band.
- Enum discriminants, relative pointers, lengths, and indexes loaded from untrusted serialized data must be validated before they influence control flow or memory access.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Se un campo come `op.kind` è un enum e un attaccante può iniettare un **discriminant fuori intervallo**, ogni `match` downstream su quel valore diventa sospetto.

### Bypass jump-table / UB counter

Se Rust trasforma un `match` grande in una **jump table**, un discriminant enum non valido può produrre **undefined control flow**. Un pattern pericoloso è:

1. Un primo `match` aggiorna **contatori/vincoli di sicurezza critici**.
2. Un secondo `match` esegue la **vera semantica dell'istruzione**.
3. Un discriminant fuori intervallo indicizza oltre la prima jump table e finisce nel codice associato alla seconda.

Risultato: l'operazione viene comunque eseguita, ma il percorso di accounting viene saltato. In uno zkVM questo può falsificare proof che riportano metriche impossibili come meno gate, meno operazioni costose o altre risorse limitate falsificate.

Checklist di revisione:

- Cerca enum controllati dall'attaccante deserializzati da witness/private input.
- Ispeziona `match` ripetuti sullo stesso campo opcode/kind.
- Considera `unsafe` + deserializzazione non verificata + dispatch di opcode grande come combinazione ad alto rischio.
- Reverse engineer del binario emesso quando serve; il layout della jump table può contare più del sorgente.

### Vincoli semantici mancanti in interpreter reversibili/specializzati

Non limitarti a validare la sicurezza della memoria; valida anche le **regole semantiche** che la proof deve imporre.

Per set di istruzioni reversibili/quantum-like, assicurati che gli operand che devono essere distinti siano effettivamente vincolati a essere distinti. Un'operazione tipo Toffoli/CCX implementata come:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
diventa insicuro se il guest non rifiuta:
```text
op.q_control1 == op.q_control2 == op.q_target
```
In quel caso la transizione collassa in:
```text
q = q ^ (q & q) = 0
```
Questo crea un **primitivo di reset deterministico**, rompendo le assunzioni di reversibilità e abilitando computazioni non intenzionali più economiche. Nei proof systems che attestano l’uso di risorse, questo può consentire agli attacker di soddisfare i controlli funzionali eludendo il modello di costo che il verifier ritiene applicato.

### Cosa testare nei sistemi ZK

- Fuzzare tutti i parser del guest con encoding di witness/private-input malformati.
- Aggiungere assert sulla validazione del range degli enum prima del dispatch delle opcode.
- Aggiungere controlli semantici per l’aliasing degli operandi e altre forme non valide di istruzioni.
- Confrontare i contatori riportati/pubblici con un’implementazione di riferimento indipendente.
- Ricorda che una proof valida può comunque provare la **stessa affermazione sbagliata** se il programma guest è bugged.

## Exploitation DeFi/AMM

Se stai ricercando exploitation pratica di DEXes e AMMs (hook di Uniswap v4, abuso di rounding/precision, swap che attraversano soglie amplificati da flash‑loan), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per pool multi-asset pesati che cachano bilanci virtuali e possono essere poisoned quando `supply == 0`, studia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
