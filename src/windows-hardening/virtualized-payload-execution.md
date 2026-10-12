# Esecuzione di payload virtualizzati ed evasione tramite VM personalizzate

{{#include ../banners/hacktricks-training.md}}

La virtualizzazione dei payload compila la logica offensiva in un set di istruzioni guest e la esegue tramite un interprete nativo. A differenza di un packer, che prima o poi deve esporre in memoria le istruzioni native originali, un payload virtualizzato può mantenere la logica protetta in bytecode per tutta la sua durata. Questo elimina quella specifica finestra di unpacking, ma **non** nasconde i comportamenti visibili all'host, come le syscall, l'attività di rete o il confine tra VM e chiamate native.<sup>[[2]](#references)[[3]](#references)</sup>

## Modello di esecuzione

Un loader virtualizzato compatto può suddividere l'esecuzione nei seguenti livelli.<sup>[[3]](#references)</sup>

1. Compilare codice C freestanding, codice sorgente BOF o librerie runtime tramite LLVM in una ISA bytecode personalizzata.
2. Avviare un piccolo interprete nativo e inizializzare una mappatura degli opcode specifica per la build.
3. Eseguire il linker-loader PE stesso come bytecode: analizzare gli header, mappare le sezioni, applicare le rilocazioni, risolvere gli import e popolare la IAT.
4. Mantenere le chiamate guest-to-guest all'interno dell'interprete. Instradare verso un thunk host nativo i target esterni alla regione bytecode, come le funzioni delle DLL importate.
5. Spostare le funzionalità di supporto, come l'incapsulamento HTTP, TLS e parti del runtime C, dietro lo stesso confine di interpretazione.

Questo modello evita di allocare una regione di codice nativo separata per ogni plugin e impedisce che il payload originale appaia come un flusso di istruzioni x86-64 riconoscibile. È comunque un confine di evasione/offuscamento, non un confine di sicurezza: l'interprete nativo e ogni effetto esterno restano osservabili.<sup>[[2]](#references)[[3]](#references)</sup>

## Bridge host a memoria condivisa

Una VM isolata rappresenta i puntatori come offset all'interno di un buffer guest, quindi ogni attraversamento delle API host richiede la traduzione dei puntatori e una gestione speciale dei parametri di output. Una VM a memoria condivisa rende invece gli indirizzi guest validi anche come indirizzi del processo host. Le letture e le scritture possono quindi usare operazioni simili a `memcpy`, e un puntatore restituito da una ECALL di allocazione nativa può essere dereferenziato direttamente dal bytecode. RISC-Y Business ha dimostrato che questo design può ridurre il bridge all'ottenimento del PEB e all'esecuzione di chiamate host arbitrarie.<sup>[[1]](#references)</sup>

Per Windows x64, il file dei registri virtuali può rispecchiare l'ABI: i primi quattro argomenti interi o puntatori vanno in `RCX`, `RDX`, `R8` e `R9`, mentre gli argomenti successivi e lo shadow space vanno sullo stack. Quando una `CALL` virtuale ha come destinazione un indirizzo esterno all'intervallo bytecode, un thunk universale organizza lo stato per una chiamata nativa e copia il valore restituito nella VM. Questo consente di effettuare chiamate IAT, allocazioni heap e operazioni socket senza correzioni dei puntatori.<sup>[[2]](#references)[[3]](#references)</sup>

Il compromesso è la perdita completa dell'isolamento. La corruzione della memoria guest può influire direttamente sull'host, i callee nativi possono conservare o modificare i puntatori guest e l'interprete deve considerare il bytecode completamente attendibile. Anche le callback da nativo a VM richiedono un bridge inverso: una VM che supporta solo le chiamate in uscita non può soddisfare direttamente API basate su callback come `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfismo ISA per build

Un'ISA personalizzata a larghezza fissa semplifica la decodifica, il dispatch, le rilocazioni e la mappatura dei registri virtuali. Centurion usa un formato di istruzioni di 18 byte, ispirato a x86-64, che sacrifica la densità del codice in cambio di un parsing prevedibile e lascia anche aperta la possibilità di tradurre in bytecode artefatti x86-64 esistenti.<sup>[[3]](#references)</sup>

Randomizzare la mappatura opcode-handler a ogni build fa sì che la stessa logica guest produca sequenze di byte diverse. Cifrare la tabella di mappatura e recuperarla solo a runtime elimina ulteriormente un dizionario opcode stabile su disco. Questo ostacola le firme statiche e le regole di disassemblaggio riutilizzabili, ma non rende automaticamente polimorfi il dispatcher nativo, la routine di decifratura della tabella o il confine delle chiamate host.<sup>[[3]](#references)</sup>

## Portare l'ambiente di esecuzione nella VM

È possibile ridurre il processo host ai primitivi di memoria, syscall e socket, mentre le librerie freestanding forniscono servizi di livello superiore all'interno della VM. Per esempio, FreeRTOS coreHTTP può gestire l'incapsulamento HTTP e mbedTLS può gestire TLS senza chiamare WinHTTP o un'API TLS del sistema operativo. I socket grezzi tramite `afd.sys` o un'interfaccia simile diventano così il ristretto confine nativo di rete.<sup>[[3]](#references)</sup>

Questo design **Bring Your Own Execution Environment (BYOEE)** può anche collocare il caricamento PE, il supporto runtime e un filesystem in memoria dietro l'interprete. Riduce le implementazioni native riconoscibili, ma non elimina la telemetria: le operazioni socket grezze restano visibili e gli ambienti che richiedono proxy espliciti o l'intercettazione TLS possono impedire il funzionamento del design di rete.<sup>[[3]](#references)</sup>

## Accelerazione nativa selettiva

Interpretare ogni istruzione è particolarmente costoso nella crittografia a chiave pubblica. Una suddivisione pratica usa gli hook `MBEDTLS_ALT` di mbedTLS come interfaccia per un coprocessore software: mantiene lo stato TLS, il parsing dei certificati, la negoziazione, l'allocazione e il codice bignum di alto livello in bytecode, ma esegue i kernel aritmetici più intensivi di `bignum_core.c` tramite ECALL native. Nel prototipo Centurion, `bignum.c`, `bignum_mod.c` e `bignum_mod_raw.c` sono rimasti virtualizzati, mentre i cicli interni sono stati eseguiti nativamente, riducendo un handshake ECDHE da minuti a secondi.<sup>[[3]](#references)</sup>

Rendi gli acceleratori opzionali, così i payload che non necessitano di TLS possono omettere gli entry point nativi aggiuntivi. Questo approccio si applica a qualsiasi carico di lavoro dell'interprete: prima esegui il profiling, poi esponi il primitivo nativo più piccolo possibile invece di spostare un intero sottosistema fuori dalla VM.<sup>[[3]](#references)</sup>

Centurion ha convalidato l'intera catena con una bind shell TLS 1.2: il loader bytecode ha mappato il PE, le chiamate socket hanno attraversato il thunk universale, mbedTLS ha gestito il protocollo all'interno della VM e le ECALL native hanno accelerato l'aritmetica ECDHE. L'interprete nativo, di circa 18 KB, ha quindi supportato un canale di comando cifrato senza materializzare il payload come codice x86-64 nativo.<sup>[[3]](#references)</sup>

## Indicatori utili per il reverse engineering e il rilevamento

I seguenti sono indicatori pratici per l'analisi, dedotti dall'architettura: la virtualizzazione cambia il punto in cui gli analisti osservano il comportamento, ma non elimina il comportamento stesso.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identificare il ciclo di fetch/decode/dispatch, il program counter virtuale, il file dei registri e l'avanzamento ripetuto a passi di larghezza fissa nelle istruzioni.
- Estrarre la tabella opcode dopo la decifratura a runtime e associare gli indirizzi degli handler alle operazioni semantiche, invece di cercare corrispondenze nel bytecode cifrato su disco.
- Impostare un breakpoint sul thunk universale o sul dispatcher ECALL per registrare il target nativo, i registri virtuali degli argomenti, gli argomenti sullo stack e il valore restituito.
- Tracciare l'accesso al PEB, la risoluzione degli export, il parsing degli header PE, le scritture delle rilocazioni e il popolamento della IAT, anche quando l'implementazione del loader è bytecode.
- Correlare la creazione dei socket e il traffico `afd.sys` con l'assenza delle chiamate WinHTTP o TLS native previste; la mancanza degli import di alto livello è un indizio, non una prova di comportamento benigno.
- Considerare gli acceleratori aritmetici nativi come punti di controllo semantici: i loro chiamanti possono rivelare attività di scambio delle chiavi e convalida dei certificati, mentre la macchina a stati TLS circostante resta virtualizzata.

Per i flussi di analisi che partono dal dispatcher anziché dal grafo di flusso di controllo originale, consulta la [guida all'analisi malware per la virtualizzazione dei packer](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Vincoli operativi

La virtualizzazione introduce un overhead di interpretazione, aumenta la complessità della toolchain e dell'ABI e non risolve il rilevamento basato sul comportamento. La memoria condivisa è insicura per progettazione, la rete tramite socket grezzi può non funzionare dietro proxy obbligatori e le API Win32 con molte callback richiedono trampoline da nativo a VM. Anche l'interprete, il bridge syscall e gli eventuali acceleratori nativi mantengono un'impronta nativa convenzionale che i difensori possono rilevare tramite firme o strumentazione.<sup>[[2]](#references)[[3]](#references)</sup>

## Pagine correlate

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: creazione di una macchina virtuale RISC-V per l'offuscamento dei payload](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red teaming nell'era dell'EDR — evasione tramite virtualizzazione del malware](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — porta il tuo ambiente di esecuzione](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
