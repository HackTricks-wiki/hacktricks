# Blockchain e criptovalute

{{#include ../../banners/hacktricks-training.md}}

Questo capitolo tratta i concetti di blockchain e la sicurezza on-chain. Per un peer Bitcoin esposto, inizia con [l'enumerazione del servizio Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); per un frontend browser, la connessione a un wallet o un backend off-chain, usa [il pentesting delle DApp](../../pentesting-web/dapps-DecentralizedApplications.md). Per le operazioni di privacy sulle criptovalute e i loro limiti, consulta il [capitolo sulla privacy delle criptovalute](../../privacy/cryptocurrency-privacy.md).

## Concetti di base

- **Smart Contract** sono definiti come programmi che vengono eseguiti su una blockchain quando si verificano determinate condizioni, automatizzando l'esecuzione degli accordi senza intermediari.
- Le **applicazioni decentralizzate (dApp)** si basano sugli smart contract e sono dotate di un frontend intuitivo e di un backend trasparente e verificabile.
- **Token e coin** si distinguono perché le coin fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
  - I **token di utilità** consentono l'accesso ai servizi, mentre i **security token** attestano la proprietà di asset.
- **DeFi** sta per finanza decentralizzata e offre servizi finanziari senza autorità centrali.
- **DEX** e **DAO** indicano rispettivamente piattaforme di exchange decentralizzate e organizzazioni autonome decentralizzate.

Per la terminologia relativa agli ordini spot, ai futures, alla leva finanziaria e alle opzioni usata nei mercati crypto, consulta [Termini di investimento](investment-terms.md).

## Meccanismi di consenso

I meccanismi di consenso garantiscono che le transazioni sulla blockchain siano convalidate in modo sicuro e condiviso:

- **Proof of Work (PoW)** si basa sulla potenza di calcolo per verificare le transazioni.
- **Proof of Stake (PoS)** richiede ai validatori di detenere una certa quantità di token, riducendo il consumo energetico rispetto al PoW.<sup>[[1]](#references)</sup>

## Nozioni essenziali su Bitcoin

### Transazioni

Le transazioni Bitcoin comportano il trasferimento di fondi tra indirizzi. Vengono convalidate tramite firme digitali, garantendo che solo il proprietario della chiave privata possa avviare i trasferimenti.<sup>[[2]](#references)</sup>

#### Componenti principali:

- Le **transazioni multisig** richiedono più firme per autorizzare una transazione.<sup>[[3]](#references)</sup>
- Le transazioni sono composte da **input** (fonte dei fondi), **output** (destinazione), **commissioni** (pagate ai miner) e **script** (regole della transazione).

### Lightning Network

Mira a migliorare la scalabilità di Bitcoin consentendo più transazioni all'interno di un canale e registrando sulla blockchain solo lo stato finale.

## Problemi di privacy di Bitcoin

Gli attacchi alla privacy, come **Common Input Ownership** e **UTXO Change Address Detection**, sfruttano gli schemi delle transazioni. Strategie come **mixer** e **CoinJoin** migliorano l'anonimato oscurando i collegamenti tra le transazioni degli utenti.

## Acquisire bitcoin in modo anonimo

I metodi includono gli scambi in contanti, il mining e l'uso di mixer. **CoinJoin** combina più transazioni per complicarne la tracciabilità, mentre **PayJoin** maschera i CoinJoin da transazioni normali per aumentare la privacy.

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l'anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di alcuni metodi comuni con cui gli attaccanti possono compromettere la privacy di Bitcoin.<sup>[[6]](#references)</sup>

## **Ipotesi di proprietà comune degli input**

In genere è raro che input di utenti diversi vengano combinati in un'unica transazione, a causa della complessità dell'operazione. Perciò, **si presume spesso che due indirizzi di input nella stessa transazione appartengano allo stesso proprietario**.

## **Rilevamento dell'indirizzo di resto UTXO**

Un UTXO, o **output di transazione non speso**, deve essere speso interamente in una transazione. Se ne viene inviata solo una parte a un altro indirizzo, il resto viene inviato a un nuovo indirizzo di resto. Gli osservatori possono presumere che questo nuovo indirizzo appartenga al mittente, compromettendone la privacy.

### Esempio

Per mitigare questo rischio, i servizi di mixing o l'uso di più indirizzi possono aiutare a nascondere la titolarità.

## **Esposizione sui social network e nei forum**

A volte gli utenti condividono online i propri indirizzi Bitcoin, rendendo **facile collegare l'indirizzo al suo proprietario**.

## **Analisi del grafo delle transazioni**

Le transazioni possono essere rappresentate come grafi, rivelando possibili connessioni tra gli utenti in base al flusso dei fondi.

## **Euristica degli input non necessari (euristica del resto ottimale)**

Questa euristica si basa sull'analisi delle transazioni con più input e output per indovinare quale output rappresenta il resto restituito al mittente.

### Esempio

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se l'aggiunta di altri input fa sì che l'output del resto sia maggiore di qualsiasi singolo input, può confondere l'euristica.

## **Riutilizzo forzato degli indirizzi**

Gli attaccanti possono inviare piccoli importi a indirizzi già usati, nella speranza che in futuro il destinatario li combini con altri input in nuove transazioni, collegando così gli indirizzi tra loro.

### Comportamento corretto del wallet

I wallet dovrebbero evitare di usare monete ricevute su indirizzi già usati e vuoti, per prevenire questa perdita di privacy.

## **Altre tecniche di analisi della blockchain**

- **Importi esatti:** È probabile che le transazioni senza resto avvengano tra due indirizzi appartenenti allo stesso utente.
- **Importi tondi:** Un importo tondo in una transazione suggerisce che si tratti di un pagamento, mentre l'output non tondo è probabilmente il resto.
- **Fingerprinting del wallet:** Wallet diversi hanno schemi di creazione delle transazioni unici, che consentono agli analisti di identificare il software usato e, potenzialmente, l'indirizzo del resto.
- **Correlazioni tra importo e orario:** Divulgare gli orari o gli importi delle transazioni può renderle tracciabili.

## Analisi del traffico

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy degli utenti. Questo vale soprattutto se un'entità gestisce molti nodi Bitcoin, aumentando la propria capacità di monitorare le transazioni.

## Altro

Per un elenco completo degli attacchi alla privacy e delle relative difese, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transazioni Bitcoin anonime

## Modi per ottenere Bitcoin in modo anonimo

- **Transazioni in contanti**: Acquistare bitcoin in contanti.
- **Alternative al contante**: Acquistare gift card e scambiarle online con bitcoin.
- **Mining**: Il metodo più privato per guadagnare bitcoin è il mining, soprattutto se svolto da soli, perché le mining pool potrebbero conoscere l'indirizzo IP del miner. [Informazioni sulle mining pool](https://en.bitcoin.it/wiki/Pooled_mining)
- **Furto**: In teoria, rubare bitcoin potrebbe essere un altro modo per ottenerli in forma anonima, anche se è illegale e sconsigliato.

## Servizi di mixing

Usando un servizio di mixing, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, rendendo difficile rintracciare il proprietario originale. Tuttavia, ciò richiede di fidarsi del servizio, che non deve conservare i log e deve effettivamente restituire i bitcoin. Tra le alternative per il mixing ci sono i casinò Bitcoin.

## CoinJoin

**CoinJoin** combina più transazioni di utenti diversi in una sola, complicando il tentativo di associare gli input agli output. Nonostante la sua efficacia, le transazioni con importi unici per gli input e gli output possono comunque essere tracciate.

Esempi di transazioni che potrebbero aver usato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per maggiori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un mixer basato su smart contract Ethereum che separa i depositi dai prelievi successivi, vedi [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera una transazione tra due parti (ad esempio, un cliente e un commerciante) facendola apparire come una transazione normale, senza i caratteristici output di pari importo di CoinJoin. Questo la rende estremamente difficile da rilevare e potrebbe invalidare l'euristica della proprietà comune degli input usata dagli enti di sorveglianza delle transazioni.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy pur restando indistinguibili dalle transazioni Bitcoin standard.

**L'utilizzo di PayJoin potrebbe compromettere significativamente i metodi di sorveglianza tradizionali**, rappresentando uno sviluppo promettente per la tutela della privacy delle transazioni.

# Best practice per la privacy nelle criptovalute

## **Tecniche di sincronizzazione del wallet**

Per tutelare la privacy e la sicurezza, è fondamentale sincronizzare i wallet con la blockchain. Due metodi si distinguono:

- **Full node**: scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni mai effettuate vengono archiviate localmente, rendendo impossibile agli avversari identificare le transazioni o gli indirizzi a cui l'utente è interessato.
- **Filtraggio dei blocchi lato client**: questo metodo consiste nel creare filtri per ogni blocco della blockchain, consentendo ai wallet di individuare le transazioni pertinenti senza rivelare interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri e recuperano i blocchi completi solo quando trovano una corrispondenza con gli indirizzi dell'utente.

## **Utilizzo di Tor per l'anonimato**

Dato che Bitcoin opera su una rete peer-to-peer, si consiglia di usare Tor per mascherare il proprio indirizzo IP e aumentare la privacy quando si interagisce con la rete.

## **Prevenire il riutilizzo degli indirizzi**

Per tutelare la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Riutilizzare gli indirizzi può compromettere la privacy collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategie per la privacy delle transazioni**

- **Più transazioni**: suddividere un pagamento in più transazioni può rendere meno evidente l'importo, ostacolando gli attacchi alla privacy.
- **Evitare il resto**: scegliere transazioni che non richiedano output di resto migliora la privacy, contrastando i metodi di rilevamento del resto.
- **Più output di resto**: se non è possibile evitare il resto, generare più output di resto può comunque migliorare la privacy.

# **Monero: un faro di anonimato**

Monero è progettato per dare priorità alla privacy delle transazioni.

# **Ethereum: gas e transazioni**

## **Comprendere il gas**

Il gas misura il lavoro computazionale necessario per eseguire operazioni su Ethereum ed è prezzato in **gwei**. Per esempio, una transazione che costa 2.310.000 gwei (o 0,00231 ETH) prevede un limite di gas e una commissione base, oltre a una commissione di priorità che incentiva l'inclusione da parte dei validatori. Gli utenti possono impostare una commissione massima per evitare di pagare troppo; l'eccedenza viene rimborsata.<sup>[[5]](#references)</sup>

## **Eseguire transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi utente o di smart contract. Richiedono una commissione e devono essere incluse in un blocco. Le informazioni essenziali di una transazione includono il destinatario, la firma del mittente, il valore, i dati facoltativi, il limite di gas e le commissioni. In particolare, l'indirizzo del mittente viene dedotto dalla firma, quindi non è necessario includerlo nei dati della transazione.<sup>[[4]](#references)</sup>

Queste pratiche e questi meccanismi sono fondamentali per chiunque desideri usare le criptovalute dando priorità alla privacy e alla sicurezza.

## Red Teaming Web3 incentrato sul valore

- Inventaria i componenti che custodiscono valore (firmatari, oracoli, bridge, automazioni) per capire chi può spostare fondi e in che modo.
- Mappa ogni componente alle tattiche MITRE AADAPT pertinenti per individuare i percorsi di escalation dei privilegi.
- Simula catene di attacco con flash loan/oracoli/credenziali/cross-chain per convalidarne l'impatto e documentare i prerequisiti sfruttabili.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromissione del flusso di firma Web3

- La manomissione della supply chain delle interfacce utente dei wallet può modificare i payload EIP-712 subito prima della firma, raccogliendo firme valide per takeover di proxy basati su delegatecall (ad es., sovrascrittura dello slot 0 di masterCopy di Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Tra i comuni punti deboli degli smart account figurano l'elusione dei controlli di accesso di `EntryPoint`, campi gas non firmati, validazione con effetti di stato, replay ERC-1271 e drenaggio delle commissioni tramite revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sicurezza degli smart contract

- Usa il mutation testing per individuare punti ciechi nelle suite di test:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrità dei guest ZK Proof / zkVM

Quando un prover utilizza una **zkVM** o un circuito di proof specifico per un'applicazione per attestare un'affermazione, il verifier apprende soltanto che il **programma guest è stato eseguito come scritto**. Se il guest contiene **deserializzazione non sicura**, **comportamento indefinito** o **vincoli semantici mancanti**, un prover malevolo può generare una proof valida anche se le **metriche pubbliche o l'invariante dichiarato sono falsi**.<sup>[[7]](#references)</sup>

### Deserializzazione non sicura nei guest delle proof

- Considera i byte del witness/circuito privato come **input non attendibile controllato dall'attaccante**, anche se sono nascosti dalla proof.
- Evita di deserializzarli con helper non verificati come `rkyv::access_unchecked`, a meno che i byte non siano già stati convalidati al di fuori del sistema.
- I discriminanti delle enum, i puntatori relativi, le lunghezze e gli indici caricati da dati serializzati non attendibili devono essere convalidati prima di influenzare il flusso di controllo o l'accesso alla memoria.

Schema pratico di audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se un campo come `op.kind` è un enum e un attaccante può iniettare un **discriminante fuori intervallo**, ogni `match` successivo su quel valore diventa sospetto.

### Bypass dei contatori tramite jump table / UB

Se Rust compila un `match` di grandi dimensioni in una **jump table**, un discriminante enum non valido può generare un **flusso di controllo indefinito**. Un pattern pericoloso è:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` aggiorna **contatori/vincoli critici per la sicurezza**.
2. Un secondo `match` esegue la **semantica effettiva dell’istruzione**.
3. Un discriminante fuori intervallo supera l’indice della prima jump table e finisce nel codice associato alla seconda.

Risultato: l’operazione viene comunque eseguita, ma il percorso di contabilizzazione viene saltato. In una zkVM, ciò può consentire di falsificare prove che riportano metriche impossibili, come un numero inferiore di gate, di operazioni costose o di altre risorse limitate falsificate.

Checklist di revisione:

- Cerca enum controllati dall’attaccante deserializzati da input witness/privati.
- Esamina le istruzioni `match` ripetute sullo stesso campo opcode/kind.
- Considera una combinazione di `unsafe`, deserializzazione senza controlli e dispatch di opcode di grandi dimensioni come una situazione ad alto rischio.
- Se necessario, esegui il reverse engineering del binario prodotto: la disposizione della jump table può essere più importante del sorgente.

### Vincoli semantici mancanti negli interpreti reversibili/specializzati

Non limitarti a convalidare la sicurezza della memoria: convalida anche le **regole semantiche** che la prova deve imporre.

Per set di istruzioni reversibili/simili a quelle quantistiche, assicurati che gli operandi che devono essere distinti siano effettivamente vincolati a essere distinti. Un’operazione simile a Toffoli/CCX implementata come:<sup>[[7]](#references)[[8]](#references)</sup>

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

Questo crea una **primitiva di reset deterministica**, violando le ipotesi di reversibilità e consentendo calcoli non previsti a costi inferiori. Nei sistemi di proof che attestano l'uso delle risorse, ciò può permettere agli attacker di soddisfare i controlli funzionali aggirando il modello di costo che il verifier crede di imporre.

### Advice del prover non sufficientemente vincolati e aritmetica modulare

I valori caricati da uno **stack advice/witness sono controllati dal prover**, anche quando sono descritti come quozienti, resti, inversi o hint precalcolati. Una proof stabilisce solo che il witness soddisfa i vincoli implementati; non stabilisce che il calcolo previsto sia stato eseguito se tali vincoli non includono un controllo del tipo, dell'intervallo o della forma canonica.<sup>[[13]](#references)</sup>

Per una funzione helper di riduzione o divisione euclidea, verifica la relazione intera completa anziché solo la sottrazione o moltiplicazione finale. Ogni limb di `q` e `r` deve essere vincolato alla larghezza dichiarata, la ricostruzione `x = q * m + r` deve essere valida nella rappresentazione intera prevista e deve essere imposto il limite canonico `0 <= r < m`. Convalida un valore **prima** di passarlo a un'istruzione `u32`/`u64` più stretta; un'operazione a larghezza ridotta non dimostra retroattivamente che l'elemento di campo originale o il valore multi-limb avesse il tipo previsto.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Il fallimento di `mod_12289` in Miden illustra il pattern di exploit: il quoziente veniva verificato come valore a due limb da 64 bit, ma il resto fornito tramite advice raggiungeva `u32overflowing_sub` senza una convalida equivalente. Un prover malevolo poteva coordinare valori non validi di quoziente e resto in modo che i vincoli di sottrazione implementati continuassero a essere soddisfatti, mentre la procedura restituiva un resto non matematico. Poiché questo risultato veniva usato nella verifica Falcon, il problema di soundness poteva essere sfruttato per ottenere firme di autorizzazione contraffatte, invece di limitarsi a produrre un risultato aritmetico errato.<sup>[[13]](#references)</sup>

### Verifica di VM crittografiche con stack implicito

I linguaggi basati su stack nascondono gli operandi, quindi per prima cosa converti le istruzioni in un IR in cui ogni valore consumato e prodotto dallo stack è un'espressione con provenienza. Una pipeline di analisi conservativa può quindi:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Costruire il grafo delle chiamate e dedurre gli effetti delle procedure su input e output dello stack.
2. Eseguire simbolicamente le istruzioni supportate e convertire il flusso di controllo in espressioni SSA/strutturate.
3. Propagare fatti astratti come `Unknown`, `ProvenU32`, `Bool`, la provenienza dei valori e l'inizializzazione locale fino a raggiungere un punto fisso.
4. Segnalare i valori derivati da advice che raggiungono operazioni aritmetiche tipizzate o sink che richiedono un valore non nullo senza un sanitizer su **ogni** percorso in ingresso.
5. Confrontare le firme dichiarate e dedotte e verificare che ogni uscita preservi i valori dello stack appartenenti al chiamante.

Considera una firma sconosciuta o un costrutto non supportato come una **lacuna nell'analisi**, non come un risultato pulito. Le chiamate dinamiche, i cicli che non preservano lo stack e i branch con effetti diversi sullo stack possono rendere impossibile tracciare in modo affidabile le posizioni dello stack; un decompiler più sicuro rifiuta o contrassegna questi casi invece di generare pseudocodice plausibile ma errato.<sup>[[10]](#references)[[13]](#references)</sup>

Nei punti di unione del flusso di controllo, mantieni una proprietà solo se vale per ogni predecessore (ad esempio, `ProvenU32 join Unknown = Unknown`). Distingui inoltre la convergenza del punto fisso dal raggiungimento del limite di iterazioni: solo un'approssimazione conservativa convergente e sound può giustificare l'assenza di una segnalazione come prova che tutte le esecuzioni rappresentate soddisfano la proprietà.<sup>[[11]](#references)</sup>

### Usa gli obblighi di dimostrazione per individuare precondizioni nascoste

Per insiemi di istruzioni ridotti, traduci le procedure in un modello eseguibile di VM formale e dimostra sia il risultato sia la trasformazione completa dello stack. Il teorema dovrebbe coprire la terminazione, gli input tipizzati, il prefisso di output previsto e la preservazione dello stack del chiamante non modificato. Esamina l'enunciato del teorema con la stessa attenzione della dimostrazione: il kernel può convalidare una prova di un'affermazione indebolita per errore.<sup>[[12]](#references)[[13]](#references)</sup>

Le ipotesi inattese sono risultati utili. Nella revisione di Miden, una dimostrazione della rotazione a destra di 64 bit richiedeva `shift mod 32 != 0`, rivelando un caso limite problematico per input grandi quando lo shift era multiplo di 32; un'altra dimostrazione ha rilevato che `wrapping_mul` a 256 bit eliminava valori dello stack appartenenti al chiamante. Aggiungi il caso limite scoperto ai test, quindi correggi l'implementazione o rafforza deliberatamente la precondizione pubblica, invece di accettare silenziosamente l'ipotesi aggiuntiva.<sup>[[12]](#references)[[13]](#references)</sup>

### Cosa testare nei sistemi ZK

- Fuzzare tutti i parser guest con codifiche malformate di witness/input privati.
- Verificare la convalida dell'intervallo degli enum prima del dispatch degli opcode.
- Aggiungere controlli semantici per l'aliasing degli operandi e altre forme di istruzioni non valide.
- Tracciare ogni origine di advice/witness fino a ciascun sink aritmetico tipizzato e richiedere la convalida su ogni percorso.<sup>[[11]](#references)[[13]](#references)</sup>
- Testare gli helper aritmetici con limb non canonici, resti fuori intervallo e conteggi di shift limite.<sup>[[12]](#references)[[13]](#references)</sup>
- Verificare l'altezza dello stack e la preservazione dei valori al di sotto degli argomenti dichiarati della procedura a ogni ritorno.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Confrontare i contatori riportati/pubblici con un'implementazione di riferimento indipendente.
- Ricorda che una prova valida può dimostrare l'**enunciato sbagliato** se il programma guest contiene bug.

## Autorizzazione dipendente dallo stato

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation di DeFi/AMM

Se stai studiando lo sfruttamento pratico di DEX e AMM (hook di Uniswap v4, abusi di arrotondamento/precisione, swap con flash loan che superano soglie), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per i pool ponderati multi-asset che memorizzano in cache i saldi virtuali e possono essere avvelenati quando `supply == 0`, consulta:

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
- [7] [Trail of Bits - Abbiamo battuto la prova a conoscenza zero di Google sulla crittoanalisi quantistica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Proteggere le criptovalute a curva ellittica dalle vulnerabilità quantistiche: stime delle risorse e contromisure (versione corretta)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repository proof-of-concept di Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Architettura del decompiler MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Motore di analisi statica MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modello MASM-to-Lean e dimostrazioni di correttezza](https://github.com/trailofbits/masm-lean)
- [13] [Fare audit nell'era dell'IA (abbastanza buona)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
