# Esecuzione di payload virtualizzati ed evasione con VM personalizzate

{{#include ../banners/hacktricks-training.md}}

La virtualizzazione dei payload compila la logica offensiva in un instruction set guest e la esegue con un interprete nativo. A differenza di un packer, che prima o poi deve esporre in memoria le istruzioni native originali, un payload virtualizzato può mantenere la logica protetta sotto forma di bytecode per tutta la sua durata. Questo elimina quella specifica finestra di unpacking, ma **non** nasconde i comportamenti visibili sull'host, come le syscall, l'attività di rete o il confine tra VM e chiamate native.<sup>[[2]](#references)[[3]](#references)</sup>

## Re-hosting WebAssembly per eludere l'analisi statica

Invece di modificare uno strumento Go fortemente basato su signature, lo si può compilare come guest `wasip1` e incorporare in un loader nativo separato. Il guest viene compilato usando un GOROOT modificato, in cui le operazioni non supportate come `net.Dial`, `net.Listen`, `os/exec` e `os.Pipe` vengono delegate tramite `//go:wasmimport`; un modulo host Wazero implementa quindi socket, operazioni sui processi, chiamate Win32 e chiamate ai framework macOS. In questo modo, l'uso delle API Go del progetto originale rimane invariato, mentre la maggior parte della logica viene trasferita in un modulo WASM cifrato che gli strumenti statici per PE potrebbero non comprendere.<sup>[[4]](#references)</sup>

### Collegare la memoria lineare alle API native

Un puntatore guest è un offset a 32 bit nella memoria lineare WASM, non un indirizzo virtuale dell'host. Prima di una chiamata nativa, il bridge può tradurre un argomento solo se è contrassegnato come puntatore locale e rientra nell'intervallo `0x10000 <= value < wasmMemorySize`, ottenendo `wasmMemoryBase + value`. Il limite inferiore evita di riscrivere handle, flag e `nil` di piccole dimensioni; le maschere per API generate da `win32metadata` distinguono i puntatori reali da handle, dimensioni e indirizzi di processi remoti, con override per i metadati imprecisi o ambigui.<sup>[[4]](#references)</sup>

Le API native possono anche restituire puntatori host tramite buffer di output guest. Una tabella mirror può assegnare rappresentazioni in memoria guest a questi oggetti e conservare una mappatura inversa all'indirizzo host originale. COM richiede il mirroring sia dell'interfaccia sia della relativa vtable: i puntatori ai dati possono essere seguiti e sottoposti a mirroring, mentre i puntatori eseguibili nelle regioni `MEM_IMAGE` devono rimanere token opachi, perché WASM non può eseguire istruzioni native. Questo modello non supporta direttamente API di callback da host a guest, come `EnumWindows` o `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### Polimorfismo della VM WASM per ogni build

Il runtime e il payload possono essere trasformati insieme a ogni build: si mescola la tabella di corrispondenza tra opcode e handler, si riscrive ogni opcode guest secondo la nuova mappatura, si randomizzano gli identificatori delle sezioni, si sostituisce la magic standard `\0asm` con un marker specifico della build e si cambia la magic della cache del runtime. Lo stesso sorgente produce così moduli diversi a livello di byte, e i normali strumenti WASM non possono analizzare il payload finché l'analista non recupera dal loader host la mappatura e il framing personalizzati.<sup>[[4]](#references)</sup>

Per il reverse engineering, partire dall'host nativo anziché cercare solo `\0asm`: identificare il marker compilato, il percorso di decrittazione del modulo, la tabella di dispatch degli opcode e le registrazioni delle host function `env`, quindi ricostruire un modulo standard o strumentare il confine degli import. Il bridge rimane un utile punto di controllo comportamentale, perché le chiamate per rete, creazione di processi, accesso al registro, caricamento dinamico e dispatch Win32 generico lo attraversano anche quando il bytecode incorporato cambia da una build all'altra.<sup>[[4]](#references)</sup>

### Camuffare l'eseguibile Go esterno

Modificare solo il guest lascia comunque un loader riconoscibile. Le trasformazioni dimostrate inseriscono in `gopclntab` profili di simboli densi prelevati da progetti Go legittimi, alternano un piccolo insieme plausibile di import DLL e variano le stringhe `VERSIONINFO` e di identità Authenticode del PE. Queste trasformazioni prendono di mira le caratteristiche statiche e di machine learning del container; non rimuovono il comportamento del runtime esposto dagli shim host.<sup>[[4]](#references)</sup>

## Modello di esecuzione

Un loader virtualizzato compatto può suddividere l'esecuzione nei seguenti livelli.<sup>[[3]](#references)</sup>

1. Compilare codice C freestanding, sorgenti BOF o librerie runtime tramite LLVM in un ISA bytecode personalizzato.
2. Avviare un piccolo interprete nativo e inizializzare una mappatura degli opcode specifica della build.
3. Eseguire il PE linker-loader stesso come bytecode: analizzare gli header, mappare le sezioni, applicare le rilocazioni, risolvere gli import e popolare la IAT.
4. Mantenere le chiamate da guest a guest all'interno dell'interprete. Instradare i target esterni alla regione bytecode, come le funzioni delle DLL importate, tramite un thunk di chiamata host nativo.
5. Spostare le funzionalità di supporto, come il framing HTTP, TLS e parti del runtime C, oltre lo stesso confine di interpretazione.

Questo modello evita di allocare una regione di codice nativo separata per ogni plugin e impedisce che il payload originale appaia come uno stream di istruzioni x86-64 riconoscibile. Rimane comunque un confine di evasione/offuscamento, non un confine di sicurezza: l'interprete nativo e ogni effetto esterno restano osservabili.<sup>[[2]](#references)[[3]](#references)</sup>

## Bridge host a memoria condivisa

Una VM isolata rappresenta i puntatori come offset in un buffer guest, quindi ogni attraversamento verso un'API host richiede la traduzione dei puntatori e una gestione specifica dei parametri di output. Una VM a memoria condivisa, invece, rende gli indirizzi guest validi come indirizzi del processo host. Le letture e le scritture possono quindi usare operazioni simili a `memcpy`, e un puntatore restituito da un'ECALL di allocazione nativa può essere dereferenziato direttamente dal bytecode. RISC-Y Business ha dimostrato che questo design può ridurre il bridge al recupero del PEB e all'esecuzione di chiamate host arbitrarie.<sup>[[1]](#references)</sup>

Per Windows x64, il file di registri virtuali può rispecchiare l'ABI: inserire i primi quattro argomenti interi o puntatore in `RCX`, `RDX`, `R8` e `R9`, con gli argomenti successivi e lo spazio shadow nello stack. Quando una `CALL` virtuale risolve un indirizzo esterno all'intervallo bytecode, un thunk universale prepara lo stato per una chiamata nativa e copia il valore restituito nella VM. Questo consente chiamate IAT, allocazione heap e operazioni socket senza correzioni dei puntatori.<sup>[[2]](#references)[[3]](#references)</sup>

Il compromesso è la perdita completa dell'isolamento. La corruzione della memoria guest può influire direttamente sull'host, i callee nativi possono conservare o modificare i puntatori guest e l'interprete deve considerare il bytecode completamente attendibile. Anche le callback da nativo a VM richiedono un bridge inverso; una VM che supporta solo le chiamate in uscita non può soddisfare direttamente API basate su callback come `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfismo ISA per ogni build

Un ISA personalizzato a larghezza fissa semplifica decodifica, dispatch, rilocazione e mappatura dei registri virtuali. Centurion usa un formato di istruzioni di 18 byte ispirato a x86-64, che sacrifica la densità del codice in favore di un parsing prevedibile e offre anche un possibile percorso per tradurre artefatti x86-64 esistenti in bytecode.<sup>[[3]](#references)</sup>

Randomizzare la mappatura tra opcode e handler a ogni build fa sì che la stessa logica guest produca sequenze di byte diverse. Cifrare la tabella di mappatura e recuperarla solo a runtime elimina ulteriormente un dizionario stabile degli opcode su disco. Questo ostacola le signature fisse e le regole di disassembly riutilizzabili, ma non rende automaticamente polimorfi il dispatcher nativo, la routine di decrittazione della tabella o il confine delle chiamate host.<sup>[[3]](#references)</sup>

## Portare l'ambiente di esecuzione nella VM

Il processo host può essere ridotto alle primitive di memoria, syscall e socket, mentre le librerie freestanding forniscono servizi di livello superiore all'interno della VM. Per esempio, FreeRTOS coreHTTP può gestire il framing HTTP e mbedTLS può gestire TLS senza ricorrere a WinHTTP o a un'API TLS del sistema operativo. I socket raw tramite `afd.sys` o un'interfaccia simile diventano quindi il ristretto confine nativo di rete.<sup>[[3]](#references)</sup>

Questo design **Bring Your Own Execution Environment (BYOEE)** può anche collocare il caricamento PE, il supporto runtime e un filesystem in memoria dietro l'interprete. Riduce le implementazioni native riconoscibili, ma non elimina la telemetria: le operazioni sui socket raw restano visibili e gli ambienti che richiedono proxy espliciti o l'intercettazione TLS possono impedire il funzionamento del design di rete.<sup>[[3]](#references)</sup>

## Accelerazione nativa selettiva

Interpretare ogni istruzione è particolarmente costoso nella crittografia a chiave pubblica. Una suddivisione pratica usa gli hook `MBEDTLS_ALT` di mbedTLS come interfaccia per un coprocessore software: mantiene in bytecode lo stato TLS, il parsing dei certificati, la negoziazione, l'allocazione e il codice bignum di alto livello, ma esegue i kernel aritmetici più intensivi di `bignum_core.c` tramite ECALL native. Nel prototipo Centurion, `bignum.c`, `bignum_mod.c` e `bignum_mod_raw.c` sono rimasti virtualizzati, mentre i loop interni venivano eseguiti nativamente, riducendo un handshake ECDHE da minuti a secondi.<sup>[[3]](#references)</sup>

Rendere gli acceleratori opzionali, così che i payload che non necessitano di TLS omettano i punti di ingresso nativi aggiuntivi. Questo schema si applica a qualsiasi workload dell'interprete: prima profilare, poi esporre la più piccola primitiva nativa possibile invece di spostare un intero sottosistema fuori dalla VM.<sup>[[3]](#references)</sup>

Centurion ha convalidato l'intera catena con una bind shell TLS 1.2: il loader bytecode ha mappato il PE, le chiamate socket hanno attraversato il thunk universale, mbedTLS ha gestito il protocollo all'interno della VM e le ECALL native hanno accelerato l'aritmetica ECDHE. L'interprete nativo di circa 18 KB ha quindi supportato un canale di comando cifrato senza materializzare il payload come codice x86-64 nativo.<sup>[[3]](#references)</sup>

## Punti di riferimento per reverse engineering e rilevamento

I seguenti sono punti di riferimento pratici per l'analisi dedotti dall'architettura; la virtualizzazione cambia dove gli analisti osservano il comportamento, ma non elimina il comportamento stesso.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identificare il loop di fetch/decode/dispatch, il program counter virtuale, il file di registri e l'avanzamento ripetuto a passi di istruzioni a larghezza fissa.
- Scaricare la tabella degli opcode dopo la decrittazione a runtime e ricondurre gli indirizzi degli handler alle operazioni semantiche, invece di cercare nel bytecode cifrato su disco.
- Impostare un breakpoint sul thunk universale o sul dispatcher ECALL per registrare il target nativo, i registri virtuali degli argomenti, gli argomenti sullo stack e il valore restituito.
- Tracciare l'accesso al PEB, la risoluzione degli export, il parsing degli header PE, le scritture di rilocazione e il popolamento della IAT anche quando l'implementazione del loader è essa stessa bytecode.
- Correlare la creazione di socket e il traffico `afd.sys` con l'assenza delle attese chiamate WinHTTP o TLS native; l'assenza di import di alto livello è un indizio, non una prova di comportamento benigno.
- Considerare gli acceleratori aritmetici nativi come punti di controllo semantici: i chiamanti possono rivelare attività di scambio delle chiavi e convalida dei certificati, mentre la macchina a stati TLS circostante rimane virtualizzata.

Per i flussi di lavoro di analisi che partono dal dispatcher invece che dal grafo originale del flusso di controllo, vedere la [guida di malware analysis per la virtualizzazione dei packer](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Vincoli operativi

La virtualizzazione impone un overhead di interpretazione, aumenta la complessità della toolchain e dell'ABI e non risolve il rilevamento comportamentale. La memoria condivisa è insicura per progettazione, il networking tramite socket raw può non funzionare dietro proxy obbligatori e le API Win32 che fanno ampio uso di callback richiedono trampoline da nativo a VM. Anche l'interprete, il bridge syscall e gli eventuali acceleratori nativi rimangono una normale impronta nativa che i difensori possono sottoporre a signature o strumentare.<sup>[[2]](#references)[[3]](#references)</sup>

## Pagine correlate

Per l'analisi del packing VMProtect 3.x, vedere [unpacking emulato e riparazione degli import](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Creare una macchina virtuale RISC-V per l'offuscamento dei payload](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red teaming nell'era EDR — Evasione tramite virtualizzazione del malware](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Porta il tuo ambiente di esecuzione](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Entra in WasmForge: compilare Sliver in WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
