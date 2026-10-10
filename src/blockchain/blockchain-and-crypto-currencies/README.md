# Blockchain e criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di base

- Gli **Smart Contracts** sono programmi che vengono eseguiti su una blockchain al verificarsi di determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- Le **Decentralized Applications (dApps)** si basano sugli smart contract e offrono un'interfaccia front-end intuitiva e un back-end trasparente e verificabile.
- **Tokens & Coins** si distinguono perché i coin fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
  - Gli **Utility Tokens** danno accesso ai servizi, mentre i **Security Tokens** rappresentano la proprietà di un asset.
- **DeFi** sta per Decentralized Finance e offre servizi finanziari senza autorità centrali.
- **DEX** e **DAOs** indicano rispettivamente le piattaforme di scambio decentralizzate e le organizzazioni autonome decentralizzate.

## Meccanismi di consenso

I meccanismi di consenso garantiscono che le transazioni sulla blockchain vengano convalidate in modo sicuro e concordato:

- **Proof of Work (PoW)** si basa sulla potenza di calcolo per verificare le transazioni.
- **Proof of Stake (PoS)** richiede ai validatori di detenere una certa quantità di token, riducendo il consumo energetico rispetto al PoW.<sup>[[1]](#references)</sup>

## Nozioni fondamentali su Bitcoin

### Transazioni

Le transazioni Bitcoin comportano il trasferimento di fondi tra indirizzi. Vengono convalidate tramite firme digitali, che garantiscono che solo il proprietario della chiave privata possa avviare i trasferimenti.<sup>[[2]](#references)</sup>

#### Componenti principali:

- Le **Multisignature Transactions** richiedono più firme per autorizzare una transazione.<sup>[[3]](#references)</sup>
- Le transazioni comprendono **inputs** (fonte dei fondi), **outputs** (destinazione), **fees** (pagate ai miner) e **scripts** (regole della transazione).

### Lightning Network

Mira a migliorare la scalabilità di Bitcoin consentendo più transazioni all'interno di un canale e trasmettendo alla blockchain solo lo stato finale.

## Problemi di privacy di Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano i pattern delle transazioni. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti tra le transazioni degli utenti.

## Acquisire Bitcoin in modo anonimo

I metodi includono scambi in contanti, mining e uso di mixer. **CoinJoin** combina più transazioni per rendere più difficile tracciarle, mentre **PayJoin** camuffa le transazioni CoinJoin facendole sembrare transazioni normali, per garantire maggiore privacy.

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di alcuni metodi comuni con cui gli attaccanti possono compromettere la privacy di Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

In genere, è raro che gli input di utenti diversi vengano combinati in un'unica transazione, data la complessità dell'operazione. Perciò, **si presume spesso che due indirizzi di input della stessa transazione appartengano allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, ovvero un **Unspent Transaction Output**, deve essere speso interamente in una transazione. Se ne viene inviata solo una parte a un altro indirizzo, il resto viene trasferito a un nuovo indirizzo di resto. Gli osservatori possono presumere che questo nuovo indirizzo appartenga al mittente, compromettendone la privacy.

### Esempio

Per mitigare questo rischio, si possono usare servizi di mixing o più indirizzi per rendere meno chiara la titolarità.

## **Esposizione sui social network e nei forum**

A volte gli utenti condividono online i propri indirizzi Bitcoin, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Analisi del grafo delle transazioni**

Le transazioni possono essere rappresentate come grafi, rivelando potenziali collegamenti tra gli utenti in base al flusso dei fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Questa euristica si basa sull'analisi delle transazioni con più input e output per ipotizzare quale output rappresenti il resto restituito al mittente.

### Esempio

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se l'aggiunta di altri input rende l'output di resto più grande di qualsiasi singolo input, può confondere l'euristica.

## **Forced Address Reuse**

Gli attaccanti possono inviare piccole somme a indirizzi già usati, sperando che il destinatario li combini con altri input in transazioni future, collegando così gli indirizzi tra loro.

### Comportamento corretto del wallet

I wallet dovrebbero evitare di usare coin ricevuti su indirizzi vuoti già utilizzati, per prevenire questo leak di privacy.

## **Altre tecniche di analisi della blockchain**

- **Importi di pagamento esatti:** Le transazioni senza resto probabilmente coinvolgono due indirizzi appartenenti allo stesso utente.
- **Numeri tondi:** Un numero tondo in una transazione suggerisce che si tratti di un pagamento; è probabile che l'output con un importo non tondo sia il resto.
- **Fingerprinting del wallet:** Wallet diversi hanno schemi di creazione delle transazioni unici, che consentono agli analisti di identificare il software usato e, potenzialmente, l'indirizzo di resto.
- **Correlazioni tra importi e tempistiche:** La divulgazione degli orari o degli importi delle transazioni può renderle tracciabili.

## **Analisi del traffico**

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy degli utenti. Ciò è particolarmente vero se un'entità gestisce molti nodi Bitcoin, aumentando la sua capacità di monitorare le transazioni.

## Altro

Per un elenco completo degli attacchi alla privacy e delle relative difese, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transazioni Bitcoin anonime

## Modi per ottenere Bitcoin in modo anonimo

- **Transazioni in contanti**: Acquistare bitcoin in contanti.
- **Alternative al contante**: Acquistare gift card e scambiarle online con bitcoin.
- **Mining**: Il metodo più riservato per guadagnare bitcoin è il mining, soprattutto se svolto individualmente, perché le mining pool potrebbero conoscere l'indirizzo IP del miner. [Informazioni sulle mining pool](https://en.bitcoin.it/wiki/Pooled_mining)
- **Furto**: In teoria, rubare bitcoin potrebbe essere un altro modo per ottenerli in modo anonimo, anche se è illegale e sconsigliato.

## Servizi di mixing

Usando un servizio di mixing, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, rendendo difficile risalire al proprietario originale. Tuttavia, è necessario fidarsi che il servizio non conservi i log e restituisca effettivamente i bitcoin. Tra le alternative per il mixing ci sono i casinò Bitcoin.

## CoinJoin

**CoinJoin** unisce più transazioni di utenti diversi in una sola, complicando il tentativo di associare gli input agli output. Nonostante la sua efficacia, le transazioni con dimensioni uniche degli input e degli output possono comunque essere tracciate.

Esempi di transazioni che potrebbero aver usato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un mixer basato su smart contract di Ethereum che separa i depositi dai prelievi successivi, consulta [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera una transazione tra due parti (ad esempio, un cliente e un commerciante) facendola apparire come una transazione normale, senza gli output uguali caratteristici di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare l'euristica della proprietà comune degli input usata dalle entità che sorvegliano le transazioni.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy e rimanendo indistinguibili dalle transazioni Bitcoin standard.

**L'utilizzo di PayJoin potrebbe compromettere significativamente i metodi di sorveglianza tradizionali**, rappresentando uno sviluppo promettente nella ricerca della privacy delle transazioni.

# Best practice per la privacy nelle criptovalute

## **Tecniche di sincronizzazione del wallet**

Per mantenere privacy e sicurezza, è fondamentale sincronizzare i wallet con la blockchain. Si distinguono due metodi:

- **Full node**: scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate vengono archiviate localmente, rendendo impossibile agli avversari identificare le transazioni o gli indirizzi a cui l'utente è interessato.
- **Filtraggio dei blocchi lato client**: questo metodo prevede la creazione di filtri per ogni blocco della blockchain, consentendo ai wallet di individuare le transazioni pertinenti senza rivelare interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri e recuperano i blocchi completi solo quando viene trovata una corrispondenza con gli indirizzi dell'utente.

## **Utilizzo di Tor per l'anonimato**

Dato che Bitcoin opera su una rete peer-to-peer, si consiglia di usare Tor per mascherare il proprio indirizzo IP e migliorare la privacy quando si interagisce con la rete.

## **Prevenire il riutilizzo degli indirizzi**

Per proteggere la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Riutilizzare gli indirizzi può compromettere la privacy collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategie per la privacy delle transazioni**

- **Transazioni multiple**: suddividere un pagamento in più transazioni può nascondere l'importo della transazione, contrastando gli attacchi alla privacy.
- **Evitare il resto**: scegliere transazioni che non richiedono output di resto migliora la privacy interrompendo i metodi di rilevamento del resto.
- **Output di resto multipli**: se non è possibile evitare il resto, generare più output di resto può comunque migliorare la privacy.

# **Monero: un baluardo dell'anonimato**

Monero è progettato per dare priorità alla privacy delle transazioni.

# **Ethereum: gas e transazioni**

## **Comprendere il gas**

Il gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum ed è prezzato in **gwei**. Ad esempio, una transazione che costa 2.310.000 gwei (o 0,00231 ETH) comporta un limite di gas e una commissione base, oltre a una commissione di priorità che incentiva l'inclusione da parte di un validatore. Gli utenti possono impostare una commissione massima per assicurarsi di non pagare troppo; l'eccedenza viene rimborsata.<sup>[[5]](#references)</sup>

## **Esecuzione delle transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi di utenti o di smart contract. Richiedono una commissione e devono essere incluse in un blocco. Le informazioni essenziali di una transazione includono il destinatario, la firma del mittente, il valore, dati facoltativi, il limite di gas e le commissioni. È importante notare che l'indirizzo del mittente viene dedotto dalla firma, quindi non è necessario includerlo nei dati della transazione.<sup>[[4]](#references)</sup>

Queste pratiche e questi meccanismi sono fondamentali per chiunque voglia usare le criptovalute dando priorità a privacy e sicurezza.

## Red teaming Web3 incentrato sul valore

- Inventariare i componenti che detengono valore (firmatari, oracoli, bridge, automazione) per capire chi può spostare i fondi e in che modo.
- Mappare ogni componente alle tattiche MITRE AADAPT pertinenti per individuare i percorsi di escalation dei privilegi.
- Simulare catene di attacco basate su flash loan, oracoli, credenziali e attacchi cross-chain per convalidare l'impatto e documentare i prerequisiti sfruttabili.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromissione del flusso di firma Web3

- La manomissione della supply chain delle interfacce dei wallet può modificare i payload EIP-712 subito prima della firma, raccogliendo firme valide per takeover di proxy basati su delegatecall (ad es. sovrascrittura dello slot 0 di Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Astrazione degli account (ERC-4337)

- Tra i comuni modi di guasto degli smart account figurano l'aggiramento dei controlli di accesso di `EntryPoint`, campi gas non firmati, convalida con stato, replay ERC-1271 e drenaggio delle commissioni tramite revert dopo la convalida.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sicurezza degli smart contract

- Mutation testing per individuare punti ciechi nelle suite di test:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrità delle prove ZK / degli guest zkVM

Quando un prover usa una **zkVM** o un circuito di prova specifico per un'applicazione per attestare un'affermazione, il verifier apprende soltanto che il **programma guest è stato eseguito come scritto**. Se il guest contiene **deserializzazione non sicura**, **comportamento indefinito** o **vincoli semantici mancanti**, un prover malevolo può generare una prova che risulta valida anche se le **metriche pubbliche o l'invariante dichiarata sono false**.<sup>[[7]](#references)</sup>

### Deserializzazione non sicura all'interno dei guest delle prove

- Trattare i byte del witness privato/del circuito come **input dell'attaccante non attendibile**, anche se sono nascosti dalla prova.
- Evitare di deserializzarli con helper non sicuri come `rkyv::access_unchecked`, a meno che i byte non siano già stati convalidati fuori banda.
- I discriminanti degli enum, i puntatori relativi, le lunghezze e gli indici caricati da dati serializzati non attendibili devono essere convalidati prima di influenzare il flusso di controllo o l'accesso alla memoria.

Schema pratico di audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se un campo come `op.kind` è un enum e un attaccante può iniettare un **discriminante fuori intervallo**, ogni `match` a valle su quel valore diventa sospetto.

### Bypass tramite jump table / UB

Se Rust trasforma un `match` esteso in una **jump table**, un discriminante enum non valido può produrre un **flusso di controllo indefinito**. Un pattern pericoloso è:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` aggiorna **contatori/vincoli critici per la sicurezza**.
2. Un secondo `match` esegue la **semantica effettiva dell’istruzione**.
3. Un discriminante fuori intervallo supera i limiti della prima jump table e atterra nel codice associato alla seconda.

Risultato: l’operazione viene comunque eseguita, ma il percorso di contabilizzazione viene saltato. In una zkVM questo può consentire di falsificare prove che riportano metriche impossibili, come un numero inferiore di gate, di operazioni costose o di altre risorse limitate falsificate.

Checklist di revisione:

- Cerca enum controllati dall’attaccante e deserializzati da input witness/privati.
- Esamina le istruzioni `match` ripetute sullo stesso campo opcode/kind.
- Considera `unsafe` + deserializzazione senza controlli + dispatch di opcode esteso una combinazione ad alto rischio.
- Se necessario, fai reverse engineering del binario generato: la disposizione della jump table può essere più importante del sorgente.

### Vincoli semantici mancanti negli interpreti reversibili/specializzati

Non limitarti a convalidare la sicurezza della memoria; convalida anche le **regole semantiche** che la prova dovrebbe far rispettare.

Per insiemi di istruzioni reversibili/simili a quelli quantistici, verifica che gli operandi che devono essere distinti siano effettivamente vincolati a esserlo. Un’operazione simile a Toffoli/CCX implementata come:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

diventa non sicuro se il guest non rifiuta:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In tal caso, la transizione collassa in:

```text
q = q ^ (q & q) = 0
```

Questo crea una **primitiva di reset deterministica**, che viola le ipotesi di reversibilità e consente calcoli non previsti a costi inferiori. Nei sistemi di proof che attestano l’uso delle risorse, questo può consentire agli attacker di superare i controlli funzionali aggirando il modello dei costi che il verifier ritiene di applicare.

### Cosa testare nei sistemi ZK

- Eseguire fuzzing su tutti i parser guest con codifiche witness/input privati malformate.
- Verificare la validità dell’intervallo degli enum prima del dispatch degli opcode.
- Aggiungere controlli semantici per l’aliasing degli operandi e altre forme di istruzione non valide.
- Confrontare i contatori riportati/pubblici con un’implementazione di riferimento indipendente.
- Ricorda che una proof valida può comunque dimostrare l’**enunciato sbagliato** se il programma guest contiene bug.

## Autorizzazione dipendente dallo stato

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation di DeFi/AMM

Se stai studiando l’exploitation pratica di DEX e AMM (hook di Uniswap v4, abuso di arrotondamento/precisione, swap amplificati da flash loan che superano soglie), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per i pool ponderati multi-asset che memorizzano nella cache i saldi virtuali e possono essere avvelenati quando `supply == 0`, approfondisci:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Chiave pubblica e chiave privata spiegate - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Cosa sono le transazioni multi-firma? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transazioni | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas e commissioni | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Abbiamo battuto la proof a conoscenza zero di Google sulla crittoanalisi quantistica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protezione delle criptovalute basate su curve ellittiche dalle vulnerabilità quantistiche: stime delle risorse e contromisure (versione corretta)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repository proof-of-concept di Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
