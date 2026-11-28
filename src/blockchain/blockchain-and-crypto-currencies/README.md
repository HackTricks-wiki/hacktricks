# Blockchain e criptovalute

{{#include ../../banners/hacktricks-training.md}}

Questo capitolo tratta i concetti di blockchain e la sicurezza on-chain. Per un peer Bitcoin esposto, inizia con [Enumerazione del servizio Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); per un frontend browser, la connessione a un wallet o un backend off-chain, consulta [DApp pentesting](../../pentesting-web/dapps-DecentralizedApplications.md). Per le operazioni di privacy sulle criptovalute e i loro limiti, consulta il [capitolo sulla privacy delle criptovalute](../../privacy/cryptocurrency-privacy.md).

## Concetti di base

- Gli **Smart Contract** sono programmi che vengono eseguiti su una blockchain al verificarsi di determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- Le **Decentralized Applications (dApp)** si basano sugli smart contract e offrono un front-end intuitivo e un back-end trasparente e verificabile.
- **Token e coin** si distinguono perché le coin fungono da moneta digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
  - Gli **Utility Token** consentono l'accesso ai servizi, mentre i **Security Token** rappresentano la proprietà di un asset.
- **DeFi** è l'acronimo di Decentralized Finance e offre servizi finanziari senza autorità centrali.
- **DEX** e **DAO** indicano rispettivamente le piattaforme di exchange decentralizzate e le organizzazioni autonome decentralizzate.

Per la terminologia relativa a ordini spot, futures, leva finanziaria e opzioni nei mercati crypto, consulta [Termini di investimento](investment-terms.md). Per gli abusi dei funding rate nei protocolli perpetui, consulta [Sfruttamento dei funding rate nei perpetual](perpetual-funding-rate-exploitation.md).

## Meccanismi di consenso

I meccanismi di consenso garantiscono che le transazioni sulla blockchain siano validate in modo sicuro e concordato:

- **Proof of Work (PoW)** si basa sulla potenza di calcolo per verificare le transazioni.
- **Proof of Stake (PoS)** richiede ai validator di detenere una certa quantità di token, riducendo il consumo energetico rispetto al PoW.<sup>[[1]](#references)</sup>

## Elementi essenziali di Bitcoin

### Transazioni

Le transazioni Bitcoin prevedono il trasferimento di fondi tra indirizzi. Sono validate tramite firme digitali, che garantiscono che solo il proprietario della chiave privata possa avviare i trasferimenti.<sup>[[2]](#references)</sup>

#### Componenti principali:

- Le **transazioni multisignature** richiedono più firme per autorizzare una transazione.<sup>[[3]](#references)</sup>
- Le transazioni sono composte da **input** (fonte dei fondi), **output** (destinazione), **commissioni** (pagate ai miner) e **script** (regole della transazione).

### Lightning Network

Mira a migliorare la scalabilità di Bitcoin consentendo più transazioni all'interno di un canale e trasmettendo alla blockchain solo lo stato finale.

## Problemi di privacy di Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano gli schemi delle transazioni. Strategie come **Mixers** e **CoinJoin** migliorano l'anonimato nascondendo i collegamenti tra le transazioni degli utenti.

## Acquisire Bitcoin in modo anonimo

I metodi includono scambi in contanti, mining e uso di mixer. **CoinJoin** combina più transazioni per rendere più difficile tracciarle, mentre **PayJoin** maschera i CoinJoin facendoli apparire come transazioni normali, per una maggiore privacy.

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di alcuni metodi comuni con cui gli attaccanti possono compromettere la privacy di Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

In genere, è raro che input appartenenti a utenti diversi vengano combinati in un'unica transazione, data la complessità dell'operazione. Pertanto, spesso si presume che **due indirizzi di input nella stessa transazione appartengano allo stesso proprietario**.

## **UTXO Change Address Detection**

Un UTXO, ovvero un **Unspent Transaction Output**, deve essere speso interamente in una transazione. Se ne viene inviato solo una parte a un altro indirizzo, il resto viene trasferito a un nuovo indirizzo di resto. Gli osservatori possono presumere che questo nuovo indirizzo appartenga al mittente, compromettendone la privacy.

### Esempio

Per mitigare questo rischio, si possono usare servizi di mixing o più indirizzi per nascondere la proprietà.

## **Esposizione sui social network e sui forum**

A volte gli utenti condividono online i propri indirizzi Bitcoin, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Analisi del grafo delle transazioni**

Le transazioni possono essere rappresentate come grafi, rivelando possibili collegamenti tra gli utenti in base al flusso dei fondi.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Questa euristica si basa sull'analisi delle transazioni con più input e output per individuare quale output rappresenti il resto restituito al mittente.

### Esempio

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se aggiungere altri input rende l’output di resto più grande di qualsiasi singolo input, può confondere l’euristica.

## **Forced Address Reuse**

Gli attacker possono inviare piccole somme a indirizzi usati in precedenza, nella speranza che il destinatario li combini con altri input in transazioni future, collegando così gli indirizzi.

### Comportamento corretto del wallet

I wallet dovrebbero evitare di usare coin ricevute su indirizzi vuoti già utilizzati, per prevenire questa perdita di privacy.

## **Altre tecniche di analisi della blockchain**

- **Importi di pagamento esatti:** le transazioni senza resto probabilmente avvengono tra due indirizzi appartenenti allo stesso utente.
- **Importi tondi:** un importo tondo in una transazione suggerisce che si tratti di un pagamento; è probabile che l’output non tondo sia il resto.
- **Wallet fingerprinting:** wallet diversi hanno schemi univoci di creazione delle transazioni, che permettono agli analyst di identificare il software usato e, potenzialmente, l’indirizzo di resto.
- **Correlazioni tra importo e orario:** divulgare gli orari o gli importi delle transazioni può renderle tracciabili.

## **Analisi del traffico**

Monitorando il traffico di rete, gli attacker possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy degli utenti. Ciò è particolarmente vero se un’entità gestisce molti nodi Bitcoin, aumentando la propria capacità di monitorare le transazioni.

## Altro

Per un elenco completo degli attacchi alla privacy e delle difese, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transazioni Bitcoin anonime

## Modi per ottenere Bitcoin in modo anonimo

- **Transazioni in contanti**: ottenere bitcoin pagando in contanti.
- **Alternative al contante**: acquistare gift card e scambiarle online con bitcoin.
- **Mining**: il metodo più privato per guadagnare bitcoin è fare mining, soprattutto in solitaria, perché le mining pool potrebbero conoscere l’indirizzo IP del miner. [Informazioni sulle mining pool](https://en.bitcoin.it/wiki/Pooled_mining)
- **Furto**: in teoria, rubare bitcoin potrebbe essere un altro modo per ottenerli in forma anonima, anche se è illegale e sconsigliato.

## Servizi di mixing

Usando un servizio di mixing, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, rendendo difficile risalire al proprietario originale. Tuttavia, è necessario fidarsi del servizio, affinché non conservi i log e restituisca effettivamente i bitcoin. Tra le alternative per il mixing ci sono i casinò Bitcoin.

## CoinJoin

**CoinJoin** unisce più transazioni di utenti diversi in una sola, complicando il processo per chiunque cerchi di associare gli input agli output. Nonostante la sua efficacia, le transazioni con importi unici di input e output possono comunque essere tracciate.

Esempi di transazioni che potrebbero aver usato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per ulteriori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un mixer basato su smart contract di Ethereum che separa i depositi dai prelievi successivi, vedi [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera una transazione tra due parti (ad esempio, un cliente e un commerciante) facendola sembrare una transazione normale, senza i caratteristici output di pari importo di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare l’euristica della proprietà comune degli input usata dagli enti che sorvegliano le transazioni.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy e restando indistinguibili dalle transazioni bitcoin standard.

**L'utilizzo di PayJoin potrebbe compromettere significativamente i metodi di sorveglianza tradizionali**, rappresentando uno sviluppo promettente nella ricerca della privacy nelle transazioni.

# Best practice per la privacy nelle criptovalute

## **Tecniche di sincronizzazione del wallet**

Per mantenere la privacy e la sicurezza, è fondamentale sincronizzare i wallet con la blockchain. Spiccano due metodi:

- **Full node**: scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate vengono archiviate localmente, rendendo impossibile per gli avversari identificare le transazioni o gli indirizzi a cui l'utente è interessato.
- **Filtraggio dei blocchi lato client**: questo metodo prevede la creazione di filtri per ogni blocco della blockchain, consentendo ai wallet di identificare le transazioni pertinenti senza esporre interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri e recuperano i blocchi completi solo quando viene trovata una corrispondenza con gli indirizzi dell'utente.

## **Utilizzo di Tor per l'anonimato**

Poiché Bitcoin opera su una rete peer-to-peer, si consiglia di usare Tor per mascherare il proprio indirizzo IP e migliorare la privacy quando si interagisce con la rete.

## **Prevenire il riutilizzo degli indirizzi**

Per proteggere la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Riutilizzare gli indirizzi può compromettere la privacy, collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite la loro progettazione.

## **Strategie per la privacy delle transazioni**

- **Transazioni multiple**: suddividere un pagamento in più transazioni può nascondere l'importo della transazione e contrastare gli attacchi alla privacy.
- **Evitare il resto**: scegliere transazioni che non richiedono output di resto migliora la privacy, ostacolando i metodi di rilevamento del resto.
- **Output di resto multipli**: se non è possibile evitare il resto, generare più output di resto può comunque migliorare la privacy.

# **Monero: un faro di anonimato**

Monero è progettato per dare priorità alla privacy delle transazioni.

# **Ethereum: gas e transazioni**

## **Capire il gas**

Il gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum e ha un prezzo espresso in **gwei**. Per esempio, una transazione che costa 2.310.000 gwei (o 0,00231 ETH) prevede un limite di gas e una commissione base, oltre a una commissione prioritaria per incentivare i validator a includerla. Gli utenti possono impostare una commissione massima per assicurarsi di non pagare troppo; l'importo eccedente viene rimborsato.<sup>[[5]](#references)</sup>

## **Eseguire transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi di utenti o di smart contract. Richiedono una commissione e devono essere incluse in un blocco. Le informazioni essenziali di una transazione includono il destinatario, la firma del mittente, il valore, i dati facoltativi, il limite di gas e le commissioni. In particolare, l'indirizzo del mittente viene dedotto dalla firma, quindi non è necessario includerlo nei dati della transazione.<sup>[[4]](#references)</sup>

Queste pratiche e questi meccanismi sono fondamentali per chiunque voglia utilizzare le criptovalute dando priorità alla privacy e alla sicurezza.

## Red Teaming Web3 centrato sul valore

- Inventariare i componenti che custodiscono valore (signer, oracoli, bridge, automazioni) per capire chi può spostare fondi e in che modo.
- Mappare ogni componente alle tattiche MITRE AADAPT pertinenti per individuare i percorsi di escalation dei privilegi.
- Simulare catene di attacco con flash loan, oracoli, credenziali e attacchi cross-chain per convalidarne l'impatto e documentare le precondizioni sfruttabili.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromissione del workflow di firma Web3

- La manomissione della supply chain delle interfacce wallet può modificare i payload EIP-712 subito prima della firma, raccogliendo firme valide per takeover di proxy basati su delegatecall (ad es., sovrascrittura dello slot 0 di masterCopy di Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Tra i comuni modi di guasto degli smart account figurano l'aggiramento dei controlli di accesso di `EntryPoint`, campi gas non firmati, validazione con stato, replay ERC-1271 e drenaggio delle commissioni tramite revert dopo la validazione.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sicurezza degli smart contract

- Mutation testing per individuare i punti ciechi nelle suite di test:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrità dei guest ZK Proof / zkVM

Quando un prover usa una **zkVM** o un circuito di proof specifico per un'applicazione per attestare un'affermazione, il verifier apprende soltanto che il **programma guest è stato eseguito come scritto**. Se il guest contiene **deserializzazione non sicura**, **comportamento indefinito** o **vincoli semantici mancanti**, un prover malintenzionato potrebbe generare una proof che viene verificata anche se le **metriche pubbliche o l'invariante dichiarata sono false**.<sup>[[7]](#references)</sup>

### Deserializzazione non sicura nei guest delle proof

- Considerare i byte del witness/del circuito privati come **input non attendibile controllato dall'attaccante**, anche se sono nascosti dalla proof.
- Evitare di deserializzarli con helper non sicuri come `rkyv::access_unchecked`, a meno che i byte non siano già stati convalidati fuori banda.
- I discriminanti degli enum, i puntatori relativi, le lunghezze e gli indici caricati da dati serializzati non attendibili devono essere convalidati prima di influenzare il flusso di controllo o l'accesso alla memoria.

Procedura pratica di audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se un campo come `op.kind` è un enum e un attaccante può iniettare un **discriminante fuori intervallo**, ogni `match` a valle su quel valore diventa sospetto.

### Bypass dei contatori tramite jump table / UB

Se Rust converte un `match` ampio in una **jump table**, un discriminante enum non valido può generare **flusso di controllo non definito**. Un pattern pericoloso è:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` aggiorna **contatori/vincoli critici per la sicurezza**.
2. Un secondo `match` esegue la **semantica effettiva dell'istruzione**.
3. Un discriminante fuori intervallo accede a una posizione oltre la prima jump table e finisce nel codice associato alla seconda.

Risultato: l'operazione viene comunque eseguita, ma il percorso di contabilizzazione viene saltato. In una zkVM, questo può consentire di falsificare prove che riportano metriche impossibili, come un numero minore di gate, di operazioni costose o di altre risorse limitate.

Checklist di revisione:

- Cerca enum controllati dall'attaccante e deserializzati da input witness/private.
- Esamina le istruzioni `match` ripetute sullo stesso campo opcode/kind.
- Considera `unsafe` + deserializzazione senza controlli + dispatch di opcode ampio una combinazione ad alto rischio.
- Se necessario, fai reverse engineering del binario generato; la disposizione delle jump table può essere più importante del codice sorgente.

### Vincoli semantici mancanti negli interpreti reversibili/specializzati

Non limitarti a convalidare la sicurezza della memoria; convalida anche le **regole semantiche** che la prova deve far rispettare.

Per set di istruzioni reversibili/simili a quelle quantistiche, assicurati che gli operandi che devono essere distinti siano effettivamente vincolati a esserlo. Un'operazione simile a Toffoli/CCX implementata come:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

diventa non sicuro se il guest non rifiuta:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In tal caso, la transizione si riduce a:

```text
q = q ^ (q & q) = 0
```

Questo crea una **primitiva di reset deterministica**, che infrange le ipotesi di reversibilità e consente calcoli non previsti a costo inferiore. Nei sistemi di proof che attestano l'uso delle risorse, ciò può permettere agli attacker di superare i controlli funzionali aggirando al contempo il modello dei costi che il verifier ritiene di far rispettare.

### Advice del prover insufficientemente vincolati e aritmetica modulare

I valori caricati da uno **stack advice/witness sono controllati dal prover**, anche quando vengono descritti come quozienti, resti, inversi o hint precalcolati. Una proof stabilisce solo che il witness soddisfa i vincoli implementati; non dimostra che sia stato eseguito il calcolo previsto se tali vincoli omettono un controllo del tipo, dell'intervallo o della forma canonica.<sup>[[13]](#references)</sup>

Per un helper di riduzione o divisione euclidea, verifica l'intera relazione tra numeri interi, non solo la sottrazione o la moltiplicazione finale. Ogni limb di `q` e `r` deve essere vincolato alla larghezza dichiarata, la ricostruzione `x = q * m + r` deve essere valida nella rappresentazione intera prevista e deve essere applicato il limite canonico `0 <= r < m`. Valida un valore **prima** di passarlo a un'istruzione `u32`/`u64` più stretta; un'operazione su un tipo più stretto non dimostra retroattivamente che l'elemento di campo originale o il valore multi-limb avesse il tipo previsto.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Il failure `mod_12289` in Miden illustra il pattern di exploit: il quoziente veniva verificato come valore a due limb da 64 bit, ma il resto fornito tramite advice raggiungeva `u32overflowing_sub` senza una convalida equivalente. Un prover malevolo poteva coordinare valori non validi di quoziente e resto, in modo che i vincoli di sottrazione implementati fossero comunque rispettati, mentre la procedura restituiva un resto non matematico. Poiché questo risultato alimentava la verifica Falcon, il failure di soundness poteva essere trasformato in firme di autorizzazione contraffatte, anziché limitarsi a produrre un risultato aritmetico errato.<sup>[[13]](#references)</sup>

### Analisi di VM crittografiche con stack implicito

I linguaggi stack nascondono gli operandi, quindi per prima cosa converti le istruzioni in un IR in cui ogni valore consumato e prodotto sullo stack sia un'espressione con provenienza. Una pipeline di analisi conservativa può quindi:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Costruire il grafo delle chiamate e dedurre gli effetti delle procedure sullo stack in input e output.
2. Eseguire simbolicamente le istruzioni supportate e convertire il flusso di controllo in espressioni SSA/strutturate.
3. Propagare fatti astratti come `Unknown`, `ProvenU32`, `Bool`, la provenienza dei valori e l'inizializzazione locale, fino a raggiungere un punto fisso.
4. Segnalare i valori derivati da advice che raggiungono operazioni aritmetiche tipizzate o sink non-zero senza un sanitizer su **ogni** percorso in ingresso.
5. Confrontare le signature dichiarate e dedotte e verificare che ogni uscita preservi i valori dello stack appartenenti al chiamante.

Considera una signature sconosciuta o un costrutto non supportato come una **lacuna dell'analisi**, non come un risultato pulito. Le chiamate dinamiche, i loop che non preservano lo stack e i branch con effetti diversi sullo stack possono rendere impossibile tracciare in modo affidabile gli slot dello stack; un decompiler più sicuro rifiuta o contrassegna questi casi, anziché generare pseudocodice plausibile ma errato.<sup>[[10]](#references)[[13]](#references)</sup>

Nei punti di unione del flusso di controllo, conserva una proprietà solo se vale per ogni predecessore (per esempio, `ProvenU32 join Unknown = Unknown`). Distingui inoltre la convergenza al punto fisso dal raggiungimento del limite di iterazioni: solo un'approssimazione superiore convergente e sound può giustificare l'interpretazione dell'assenza di una segnalazione come prova che tutte le esecuzioni rappresentate soddisfano la proprietà.<sup>[[11]](#references)</sup>

### Usa gli obblighi di prova per far emergere precondizioni nascoste

Per insiemi di istruzioni ridotti, traduci le procedure in un modello VM formale eseguibile e dimostra sia il risultato sia la trasformazione completa dello stack. Il teorema deve coprire la terminazione, gli input tipizzati, il prefisso di output previsto e la preservazione dello stack del chiamante non modificato. Esamina l'enunciato del teorema con la stessa attenzione riservata alla prova: il kernel può convalidare la prova di un'affermazione indebolita accidentalmente.<sup>[[12]](#references)[[13]](#references)</sup>

Le ipotesi inattese sono risultati utili. Nella revisione di Miden, una prova della rotazione a destra a 64 bit richiedeva `shift mod 32 != 0`, rivelando un caso limite non gestito per input grandi quando lo shift era un multiplo di 32; un'altra prova ha rilevato che `wrapping_mul` a 256 bit scartava valori dello stack appartenenti al chiamante. Aggiungi il caso limite individuato ai test, poi correggi l'implementazione o rafforza deliberatamente la precondizione pubblica, invece di accettare tacitamente l'ipotesi aggiuntiva.<sup>[[12]](#references)[[13]](#references)</sup>

### Cosa testare nei sistemi ZK

- Fuzzare tutti i parser guest con codifiche malformate di witness/input privati.
- Verificare la convalida dell'intervallo degli enum prima del dispatch degli opcode.
- Aggiungere controlli semantici per l'aliasing degli operandi e altre forme di istruzioni non valide.
- Tracciare ogni sorgente di advice/witness fino a ciascun sink aritmetico tipizzato e richiedere la convalida su ogni percorso.<sup>[[11]](#references)[[13]](#references)</sup>
- Testare gli helper aritmetici con limb non canonici, resti fuori intervallo e valori limite degli shift.<sup>[[12]](#references)[[13]](#references)</sup>
- Verificare l'altezza dello stack e la preservazione dei valori al di sotto degli argomenti dichiarati della procedura a ogni ritorno.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Confrontare i contatori riportati/pubblici con un'implementazione di riferimento indipendente.
- Ricorda che una prova valida può comunque dimostrare l'**affermazione sbagliata** se il programma guest contiene bug.

## Autorizzazione dipendente dallo stato

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation di DeFi/AMM

Se stai studiando l'exploitation pratica di DEX e AMM (hook di Uniswap v4, abuso di arrotondamenti/precisione, swap amplificati da flash loan che superano soglie), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per i pool multi-asset ponderati che memorizzano nella cache i saldi virtuali e possono essere avvelenati quando `supply == 0`, consulta:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Chiave pubblica e chiave privata: spiegazione - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Cosa sono le transazioni multi-firma? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transazioni | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas e commissioni | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Abbiamo battuto la prova a conoscenza zero di Google contro la crittoanalisi quantistica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Proteggere le criptovalute basate su curve ellittiche dalle vulnerabilità quantistiche: stime delle risorse e mitigazioni (versione corretta)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repository proof-of-concept di Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Architettura del decompiler MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Motore di analisi statica MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modello MASM-to-Lean e prove di correttezza](https://github.com/trailofbits/masm-lean)
- [13] [Audit nell'era dell'IA (abbastanza buona)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
