# Blockchain e criptovalute

{{#include ../../banners/hacktricks-training.md}}

## Concetti di base

- I **contratti intelligenti** sono programmi che vengono eseguiti su una blockchain quando si verificano determinate condizioni, automatizzando l’esecuzione degli accordi senza intermediari.
- Le **applicazioni decentralizzate (dApp)** si basano sui contratti intelligenti e offrono un’interfaccia utente intuitiva e un back-end trasparente e verificabile.
- **Token e coin** si distinguono perché le coin fungono da denaro digitale, mentre i token rappresentano valore o proprietà in contesti specifici.
  - I **token di utilità** consentono l’accesso ai servizi, mentre i **security token** rappresentano la proprietà di un asset.
- **DeFi** sta per finanza decentralizzata e offre servizi finanziari senza autorità centrali.
- **DEX** e **DAO** indicano rispettivamente piattaforme di scambio decentralizzate e organizzazioni autonome decentralizzate.

## Meccanismi di consenso

I meccanismi di consenso garantiscono la convalida sicura e condivisa delle transazioni sulla blockchain:

- **Proof of Work (PoW)** si basa sulla potenza di calcolo per verificare le transazioni.
- **Proof of Stake (PoS)** richiede ai validatori di detenere una certa quantità di token e riduce il consumo energetico rispetto al PoW.<sup>[[1]](#references)</sup>

## Nozioni essenziali su Bitcoin

### Transazioni

Le transazioni Bitcoin trasferiscono fondi tra indirizzi. Vengono convalidate tramite firme digitali, che garantiscono che solo il proprietario della chiave privata possa avviare i trasferimenti.<sup>[[2]](#references)</sup>

#### Componenti principali:

- Le **transazioni multisignature** richiedono più firme per autorizzare una transazione.<sup>[[3]](#references)</sup>
- Le transazioni sono composte da **input** (origine dei fondi), **output** (destinazione), **commissioni** (pagate ai miner) e **script** (regole della transazione).

### Lightning Network

Mira a migliorare la scalabilità di Bitcoin consentendo più transazioni all’interno di un canale e pubblicando sulla blockchain solo lo stato finale.

## Problemi di privacy di Bitcoin

Attacchi alla privacy, come l’**associazione degli input a un proprietario comune** e il **rilevamento dell’indirizzo di resto UTXO**, sfruttano gli schemi delle transazioni. Strategie come i **mixer** e **CoinJoin** migliorano l’anonimato nascondendo i collegamenti tra le transazioni degli utenti.

## Acquisire Bitcoin in modo anonimo

I metodi includono gli scambi in contanti, il mining e l’uso dei mixer. **CoinJoin** combina più transazioni per rendere più difficile tracciarle, mentre **PayJoin** maschera le transazioni CoinJoin facendole apparire come transazioni normali, per garantire maggiore privacy.

# Riepilogo degli attacchi alla privacy di Bitcoin

Nel mondo di Bitcoin, la privacy delle transazioni e l’anonimato degli utenti sono spesso motivo di preoccupazione. Ecco una panoramica semplificata di alcuni metodi comuni con cui gli aggressori possono compromettere la privacy di Bitcoin.<sup>[[6]](#references)</sup>

## **Assunzione di proprietà comune degli input**

In genere, è raro che input appartenenti a utenti diversi vengano combinati in una singola transazione, data la complessità dell’operazione. Pertanto, **si presume spesso che due indirizzi di input nella stessa transazione appartengano allo stesso proprietario**.

## **Rilevamento dell’indirizzo di resto UTXO**

Un UTXO, ovvero un **output di transazione non speso**, deve essere speso interamente in una transazione. Se ne viene inviato solo una parte a un altro indirizzo, il resto viene trasferito a un nuovo indirizzo di resto. Gli osservatori possono presumere che questo nuovo indirizzo appartenga al mittente, compromettendone la privacy.

### Esempio

Per mitigare questo problema, è possibile ricorrere a servizi di mixing o usare più indirizzi per nascondere la proprietà.

## **Esposizione su social network e forum**

A volte gli utenti condividono online i propri indirizzi Bitcoin, rendendo **facile collegare l’indirizzo al suo proprietario**.

## **Analisi del grafo delle transazioni**

Le transazioni possono essere rappresentate come grafi, rivelando potenziali collegamenti tra gli utenti in base al flusso dei fondi.

## **Euristica dell’input non necessario (euristica del resto ottimale)**

Questa euristica si basa sull’analisi delle transazioni con più input e output per ipotizzare quale output rappresenti il resto restituito al mittente.

### Esempio

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se l'aggiunta di altri input rende l'output del resto più grande di qualsiasi singolo input, può confondere l'euristica.

## **Forced Address Reuse**

Gli attaccanti possono inviare piccole quantità a indirizzi già usati, sperando che il destinatario li combini con altri input in transazioni future, collegando così gli indirizzi tra loro.

### Comportamento corretto del wallet

I wallet dovrebbero evitare di usare monete ricevute su indirizzi già usati e vuoti, per prevenire questa leak della privacy.

## **Altre tecniche di analisi della blockchain**

- **Importi esatti:** È probabile che le transazioni senza resto siano tra due indirizzi posseduti dallo stesso utente.
- **Numeri tondi:** Un numero tondo in una transazione suggerisce che si tratti di un pagamento; è probabile che l'output non tondo sia il resto.
- **Fingerprinting del wallet:** Wallet diversi hanno schemi unici di creazione delle transazioni, che consentono agli analisti di identificare il software usato e, potenzialmente, l'indirizzo del resto.
- **Correlazioni tra importi e tempi:** Divulgare gli orari o gli importi delle transazioni può renderle tracciabili.

## **Analisi del traffico**

Monitorando il traffico di rete, gli attaccanti possono potenzialmente collegare transazioni o blocchi a indirizzi IP, compromettendo la privacy degli utenti. Ciò vale soprattutto se un'entità gestisce molti nodi Bitcoin, aumentando la propria capacità di monitorare le transazioni.

## Altro

Per un elenco completo degli attacchi alla privacy e delle relative difese, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transazioni Bitcoin anonime

## Modi per ottenere bitcoin in modo anonimo

- **Transazioni in contanti**: Ottenere bitcoin tramite contanti.
- **Alternative al contante**: Acquistare gift card e scambiarle online con bitcoin.
- **Mining**: Il metodo più privato per guadagnare bitcoin è il mining, soprattutto se effettuato in solitaria, perché le mining pool potrebbero conoscere l'indirizzo IP del miner. [Informazioni sulle mining pool](https://en.bitcoin.it/wiki/Pooled_mining)
- **Furto**: In teoria, rubare bitcoin potrebbe essere un altro modo per ottenerli in forma anonima, anche se è illegale e sconsigliato.

## Servizi di mixing

Usando un servizio di mixing, un utente può **inviare bitcoin** e ricevere **bitcoin diversi in cambio**, rendendo difficile risalire al proprietario originale. Tuttavia, ciò richiede di fidarsi del servizio, che non deve conservare i log e deve restituire effettivamente i bitcoin. Tra le opzioni alternative di mixing ci sono i casinò Bitcoin.

## CoinJoin

**CoinJoin** unisce più transazioni di utenti diversi in una sola, complicando il processo per chiunque tenti di associare gli input agli output. Nonostante la sua efficacia, le transazioni con input e output di dimensioni uniche possono comunque essere tracciate.

Esempi di transazioni che potrebbero aver usato CoinJoin includono `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Per ulteriori informazioni, visita [CoinJoin](https://coinjoin.io/en). Per un mixer basato su smart contract Ethereum che separa i depositi dai prelievi successivi, consulta [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante di CoinJoin, **PayJoin** (o P2EP), maschera la transazione tra due parti (ad esempio, un cliente e un commerciante) facendola sembrare una transazione normale, senza gli output uguali caratteristici di CoinJoin. Ciò la rende estremamente difficile da rilevare e potrebbe invalidare l'euristica della proprietà comune degli input usata dagli enti di sorveglianza delle transazioni.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transazioni come quella sopra potrebbero essere PayJoin, migliorando la privacy pur restando indistinguibili dalle transazioni bitcoin standard.

**L'utilizzo di PayJoin potrebbe compromettere significativamente i metodi di sorveglianza tradizionali**, rappresentando uno sviluppo promettente nella ricerca della privacy delle transazioni.

# Best practice per la privacy nelle criptovalute

## **Tecniche di sincronizzazione dei wallet**

Per mantenere privacy e sicurezza, è fondamentale sincronizzare i wallet con la blockchain. Si distinguono due metodi:

- **Full node**: scaricando l'intera blockchain, un full node garantisce la massima privacy. Tutte le transazioni effettuate vengono archiviate localmente, rendendo impossibile per gli avversari identificare le transazioni o gli indirizzi a cui l'utente è interessato.
- **Filtraggio dei blocchi lato client**: questo metodo prevede la creazione di filtri per ogni blocco della blockchain, consentendo ai wallet di individuare le transazioni pertinenti senza rivelare interessi specifici agli osservatori della rete. I wallet leggeri scaricano questi filtri e recuperano i blocchi completi solo quando trovano una corrispondenza con gli indirizzi dell'utente.

## **Utilizzare Tor per l'anonimato**

Poiché Bitcoin opera su una rete peer-to-peer, si consiglia di usare Tor per mascherare il proprio indirizzo IP e aumentare la privacy quando si interagisce con la rete.

## **Evitare il riutilizzo degli indirizzi**

Per proteggere la privacy, è fondamentale usare un nuovo indirizzo per ogni transazione. Riutilizzare gli indirizzi può compromettere la privacy, collegando le transazioni alla stessa entità. I wallet moderni scoraggiano il riutilizzo degli indirizzi tramite il loro design.

## **Strategie per la privacy delle transazioni**

- **Transazioni multiple**: suddividere un pagamento in più transazioni può nascondere l'importo, ostacolando gli attacchi alla privacy.
- **Evitare il resto**: scegliere transazioni che non richiedono output di resto aumenta la privacy, ostacolando i metodi di rilevamento del resto.
- **Output di resto multipli**: se non è possibile evitare il resto, generare più output di resto può comunque migliorare la privacy.

# **Monero: un baluardo dell'anonimato**

Monero è progettato per dare priorità alla privacy delle transazioni.

# **Ethereum: gas e transazioni**

## **Capire il gas**

Il gas misura lo sforzo computazionale necessario per eseguire operazioni su Ethereum ed è prezzato in **gwei**. Ad esempio, una transazione che costa 2.310.000 gwei (o 0,00231 ETH) prevede un limite di gas e una commissione base, oltre a una commissione di priorità che incentiva l'inclusione da parte del validatore. Gli utenti possono impostare una commissione massima per assicurarsi di non pagare troppo; l'importo in eccesso viene rimborsato.<sup>[[5]](#references)</sup>

## **Eseguire transazioni**

Le transazioni su Ethereum coinvolgono un mittente e un destinatario, che possono essere indirizzi di utenti o di smart contract. Richiedono una commissione e devono essere incluse in un blocco. Le informazioni essenziali di una transazione includono il destinatario, la firma del mittente, il valore, i dati opzionali, il limite di gas e le commissioni. È importante notare che l'indirizzo del mittente viene dedotto dalla firma, quindi non è necessario includerlo nei dati della transazione.<sup>[[4]](#references)</sup>

Queste pratiche e questi meccanismi sono fondamentali per chiunque voglia usare le criptovalute dando priorità a privacy e sicurezza.

## Red Teaming Web3 incentrato sul valore

- Inventariare i componenti che custodiscono o movimentano valore (firmatari, oracoli, bridge, automazione) per capire chi può spostare i fondi e come.
- Mappare ogni componente alle tattiche MITRE AADAPT pertinenti per individuare percorsi di escalation dei privilegi.
- Simulare catene di attacco basate su flash loan/oracoli/credenziali/cross-chain per convalidarne l'impatto e documentare i prerequisiti sfruttabili.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromissione del workflow di firma Web3

- La manomissione della supply chain delle UI dei wallet può modificare i payload EIP-712 subito prima della firma, raccogliendo firme valide per takeover di proxy basati su delegatecall (ad es. sovrascrittura dello slot 0 di `masterCopy` di Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Tra i comuni modi di malfunzionamento degli smart account figurano l'elusione dei controlli di accesso di `EntryPoint`, campi gas non firmati, validazione con stato, replay ERC-1271 e drenaggio delle commissioni tramite revert dopo la validazione.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sicurezza degli smart contract

- Mutation testing per individuare punti ciechi nelle suite di test:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrità dei guest ZK proof / zkVM

Quando un prover usa una **zkVM** o un circuito di proof specifico per l'applicazione per attestare un'affermazione, il verifier apprende soltanto che il **guest program è stato eseguito come scritto**. Se il guest contiene **deserializzazione non sicura**, **comportamento indefinito** o **vincoli semantici mancanti**, un prover malevolo potrebbe generare una proof valida anche se le **metriche pubbliche o l'invariante dichiarata sono false**.<sup>[[7]](#references)</sup>

### Deserializzazione non sicura nei guest delle proof

- Considerare i byte di witness/circuito privati come **input non attendibile controllato dall'attaccante**, anche se sono nascosti dalla proof.
- Evitare di deserializzarli con helper non verificati come `rkyv::access_unchecked`, a meno che i byte non siano già stati convalidati separatamente.
- I discriminanti degli enum, i puntatori relativi, le lunghezze e gli indici caricati da dati serializzati non attendibili devono essere convalidati prima di influenzare il flusso di controllo o l'accesso alla memoria.

Schema pratico di audit:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se un campo come `op.kind` è un enum e un attaccante può iniettare un **discriminante fuori intervallo**, ogni `match` successivo su quel valore diventa sospetto.

### Bypass dei contatori tramite jump table / UB

Se Rust traduce un `match` ampio in una **jump table**, un discriminante enum non valido può causare **flusso di controllo undefined**. Un pattern pericoloso è:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` aggiorna **contatori/vincoli critici per la sicurezza**.
2. Un secondo `match` esegue la **semantica effettiva dell'istruzione**.
3. Un discriminante fuori intervallo indicizza oltre la prima jump table e raggiunge codice associato alla seconda.

Risultato: l'operazione viene comunque eseguita, ma il percorso di contabilizzazione viene saltato. In una zkVM, questo può consentire di falsificare prove che riportano metriche impossibili, ad esempio un numero inferiore di gate, meno operazioni costose o altre risorse limitate falsificate.

Checklist di revisione:

- Cerca enum controllati dall'attaccante e deserializzati da input witness/privati.
- Esamina le istruzioni `match` ripetute sullo stesso campo opcode/kind.
- Considera `unsafe` + deserializzazione senza controlli + dispatch di opcode ampio una combinazione ad alto rischio.
- Effettua il reverse engineering del binario generato quando necessario; la disposizione delle jump table può essere più importante del sorgente.

### Vincoli semantici mancanti negli interpreti reversibili/specializzati

Non limitarti a convalidare la sicurezza della memoria; convalida anche le **regole semantiche** che la prova deve imporre.

Per set di istruzioni reversibili/di tipo quantistico, verifica che gli operandi che devono essere distinti siano effettivamente vincolati a esserlo. Un'operazione di tipo Toffoli/CCX implementata come:<sup>[[7]](#references)[[8]](#references)</sup>

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

Questo crea una **primitiva di reset deterministica**, infrangendo le ipotesi di reversibilità e consentendo calcoli non previsti a costi inferiori. Nei sistemi di proof che attestano l’uso delle risorse, ciò può permettere agli attacker di superare i controlli funzionali aggirando il modello dei costi che il verifier ritiene di imporre.

### Cosa testare nei sistemi ZK

- Esegui il fuzzing di tutti i parser guest con codifiche malformate di witness/private input.
- Verifica la validazione dell’intervallo degli enum prima del dispatch degli opcode.
- Aggiungi controlli semantici per l’aliasing degli operandi e altre forme di istruzione non valide.
- Confronta i contatori dichiarati/pubblici con un’implementazione di riferimento indipendente.
- Ricorda che una proof valida può comunque dimostrare l’**enunciato sbagliato** se il programma guest contiene bug.

## Autorizzazione dipendente dallo stato

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Sfruttamento di DeFi/AMM

Se stai studiando lo sfruttamento pratico di DEX e AMM (hook di Uniswap v4, abusi di arrotondamento/precisione, swap con soglie superate grazie a flash loan), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Per i pool ponderati multi-asset che memorizzano nella cache i saldi virtuali e possono essere avvelenati quando `supply == 0`, consulta:

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
- [7] [Trail of Bits - Abbiamo battuto la proof zero-knowledge di Google sulla crittoanalisi quantistica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Proteggere le criptovalute basate su curve ellittiche dalle vulnerabilità quantistiche: stime delle risorse e mitigazioni (versione corretta)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repository proof-of-concept di Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
