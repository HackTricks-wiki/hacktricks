# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Perché l'unwinding guidato dai metadati può essere contraffatto

Alcuni strumenti di sicurezza di macOS delegano la raccolta dello stack dei thread a `/usr/sbin/spindump` o si affidano comunque a un unwinder convenzionale guidato dai metadati. Un implant può sfruttare questo confine di fiducia inserendo nel proprio stack record sintetici conformi all'ABI, così che sembri che una API sensibile sia stata raggiunta passando per funzioni selezionate dall'attaccante in dyld e nei framework Apple caricati, anziché da codice dell'implant non supportato. Si tratta di un inganno della telemetria, non di una modifica all'eseguibile o ai suoi metadati di unwinding.<sup>[[1]](#references)</sup>

Vedi [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) per il contesto relativo alla raccolta.

Un unwinder non dimostra che un record sia stato creato da un prologo generato dal compilatore. Usa ripetutamente il `PC` corrente per selezionare una ricetta Mach-O, applica tale ricetta a `SP`, `x29`, `x30`, alla memoria dello stack e a qualsiasi registro non volatile dichiarato, quindi usa il `PC` del chiamante recuperato per selezionare la ricetta successiva. Se la memoria controllata dall'attaccante soddisfa ogni ricetta selezionata, la catena risultante può essere strutturalmente valida e associabile a simboli, anche se quelle chiamate non sono mai avvenute.<sup>[[1]](#references)</sup>

## Stato del frame ARM64

La [panoramica sull'assembly ARM64](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) descrive i ruoli dei registri e la convenzione di chiamata. Per un frame convenzionale creato con `stp x29, x30, [sp, #-16]!` seguito da `mov x29, sp`, il Canonical Frame Address (CFA), che rappresenta lo `SP` del chiamante all'ingresso, è `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

I record di frame formano una lista concatenata tramite `[FP]`, ma seguirla alla cieca non basta: le funzioni foglia possono non avere frame, le tail call possono rimuovere transizioni logiche e i layout insoliti usano DWARF CFI. La regola determinata dall'indirizzo corrente stabilisce se l'unwinder legge o meno la catena FP.<sup>[[1]](#references)[[4]](#references)</sup>

## Selezione di una regola di unwind Mach-O

Le immagini collegate finali memorizzano i dati compact unwind in `__TEXT,__unwind_info`. L'header della sezione punta a un indice di funzioni di primo livello; ogni intervallo dell'indice punta a una pagina di secondo livello regolare (`kind=2`) o compressa (`kind=3`). I layout che il compact unwind non è in grado di descrivere usano un FDE e le istruzioni call-frame in `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Per ogni PC runtime candidato:<sup>[[1]](#references)[[2]](#references)</sup>

1. Rimuovi o normalizza i bit PAC di ARM64e solo per la ricerca.
2. Trova il Mach-O caricato il cui intervallo eseguibile `__TEXT` contiene l'indirizzo.
3. Calcola `functionOffset = normalizedPC - loadedImageBase` e rifiuta i risultati negativi o superiori a `UINT32_MAX`.
4. Seleziona l'intervallo di primo livello che soddisfa `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Analizza la pagina di secondo livello referenziata, scegli la voce più vicina il cui inizio non supera l'offset e verifica che l'indirizzo sia inferiore alla voce successiva o alla fine dell'intervallo di primo livello.
6. Decodifica la voce e costruisci lo stato esatto che descrive.

Quando un indirizzo proviene da un LR salvato, la ricerca può usare `PC-1`, così che un indirizzo subito dopo una call rimanga nell'intervallo coperto dal caller. Questo modifica la selezione della regola, non gli offset dello stack.<sup>[[1]](#references)</sup>

Un parser deve controllare i limiti di ogni header e array, richiedere la versione di sezione `1`, tenere conto del sentinel finale di primo livello, rifiutare un offset di pagina di secondo livello pari a zero e distinguere le pagine regolari da quelle compresse. In una pagina regolare, `entryPageOffset` è relativo all'inizio della pagina, mentre l'offset della pagina di primo livello è relativo all'inizio di `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

La modalità generale è `encoding & 0x0F000000`. Le definizioni LLVM attuali includono le seguenti modalità; un parser non dovrebbe trattare ogni valore diverso da DWARF come un frame classico:<sup>[[1]](#references)[[2]](#references)</sup>

| Modalità | Valore | Recupero del caller |
| --- | --- | --- |
| Nessuna regola compact | `0x00000000` | Interrompi o usa un fallback indipendente. |
| Senza frame | `0x02000000` | Aggiungi la dimensione dello stack codificata allo `SP` corrente; il PC del caller è l'LR live. |
| DWARF | `0x03000000` | Esegui l'FDE/CFI identificato dai 24 bit meno significativi. |
| Con frame | `0x04000000` | Leggi il record di frame convenzionale `x29`. |
| Frame arm64e con intervallo LR autenticato | `0x05000000` | Gestisci `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`; il campo offset individua `pacibsppc` nell'intervallo coperto. |

Per la modalità senza frame, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. Per la modalità con frame, i cinque bit meno significativi indicano coppie contigue di GPR salvati, da `x19/x20` a `x27/x28`; i bit `0x100-0x800` indicano analogamente le coppie `d8-d15`. Questi registri salvati potrebbero non essere necessari per trovare il PC successivo, ma uno stato virtuale plausibile del caller deve soddisfare tutti i campi ricostruiti dal consumer.<sup>[[1]](#references)[[2]](#references)</sup>

## Costruzione di record sintetici in modalità frame

Il processo di costruzione inverte il funzionamento dell'unwinder, invece di cercare nello stack valori che sembrano indirizzi:<sup>[[1]](#references)</sup>

1. Scegli un PC eseguibile reale in un'immagine attualmente caricata.
2. Decodifica la regola che copre quel PC preciso o l'indirizzo del call site.
3. Alloca un record sintetico con l'allineamento richiesto e la relazione CFA corretta.
4. Memorizza il successivo FP sintetico in `[FP]`, il PC del caller salvato da quel frame in `[FP+8]` e ogni salvataggio GPR/FPR dichiarato dalla codifica al di sotto di FP.
5. Collega più record e inserisci il primo record in `x29` live.
6. Organizza l'LR live e il percorso di ritorno dell'API in modo che l'unwinding entri nella catena scelta, consentendo al contempo di ripristinare l'esecuzione in sicurezza.

Ad esempio, `0x04000001` indica la modalità con frame più la coppia `x19/x20`. La trasformazione di stato corrispondente e la memoria richiesta sono:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Un indirizzo dall'aspetto legittimo non è quindi sufficiente. Ogni PC recuperato diventa la chiave per la ricerca successiva, quindi un singolo indirizzo la cui codifica non corrisponde al layout contraffatto interrompe la catena o fa sì che il consumer ricostruisca uno stato dei registri incoerente.<sup>[[1]](#references)</sup>

## Requisiti PAC di ARM64e

PAC memorizza un valore di integrità con chiave nei bit altrimenti inutilizzati del puntatore; non cifra l'indirizzo. Lo schema degli indirizzi di ritorno arm64e di Clang usa la chiave di istruzioni B e lo stack pointer all'ingresso della funzione come discriminante. In un frame convenzionale, tale `SP` d'ingresso è il CFA, quindi il LR salvato in `[FP+8]` è associato a `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Ogni LR sintetico deve essere firmato in modo indipendente, perché spostare un LR già firmato in un frame con un CFA diverso modifica il discriminatore e fa fallire l’autenticazione. `ptrauth_strip()` è adatto alla normalizzazione degli indirizzi e alla ricerca dei simboli, ma **non** ne garantisce l’autenticità; qualsiasi ritorno effettivo o branch indiretto autenticato deve usare la chiave e il modificatore previsti per quella precisa transizione.<sup>[[1]](#references)[[3]](#references)</sup>

Una tipica funzione arm64e non-leaf firma LR prima di salvarlo e lo autentica dopo aver ripristinato lo SP d’ingresso:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline e restore bridge

I record sintetici devono solo soddisfare l’unwinder; non contengono un contesto di esecuzione completo. Il ritorno diretto dalla API sensibile ai chiamanti fabbricati causerebbe normalmente un crash. Il design pratico colloca quindi un frame gadget immediatamente sotto la API: la API ritorna a codice eseguibile in un framework caricato e il gadget esegue un branch, tramite un registro controllato preservato dal chiamato, verso un restore bridge nell’implant.<sup>[[1]](#references)</sup>

Un gadget utile preserva LR e trasferisce il controllo tramite un registro controllato, per esempio usando una sequenza `br`, `braa` o `brab` appropriata. Il restore bridge deve ripristinare i valori originali di `x19-x30` e `SP` prima di riprendere l’esecuzione dell’implant. Su arm64e, ogni ritorno o branch autenticato nei percorsi API-gadget, gadget-bridge e bridge-implant richiede un puntatore firmato con la chiave e il discriminatore usati da quell’istruzione.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

Il risultato rappresenta una grave violazione del confine di fiducia per i rilevamenti basati sullo stack: una catena può contenere solo PC di framework Apple mappati e associabili a simboli, senza per questo rappresentare il flusso di controllo effettivo. L’output dell’unwinding dovrebbe quindi essere corroborato da prove indipendenti sulla provenienza della memoria eseguibile del thread e sulle transizioni reali attorno all’API sensibile, anziché essere trattato come una traccia di esecuzione.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Internals dello stack ARM64 e offuscamento su Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Definizioni della codifica compact unwind di Mach-O](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Autenticazione dei puntatori](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Standard per le chiamate di procedura per l’architettura Arm a 64 bit](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
