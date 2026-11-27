# Flusso di controllo guidato dalle eccezioni di Windows e anti-debugging

{{#include ../banners/hacktricks-training.md}}

Un programma Windows protetto può usare un’eccezione intenzionale come diramazione: l’istruzione che genera l’eccezione è solo il punto d’ingresso a un gestore che seleziona l’indirizzo successivo del codice utente. Questo nasconde i collegamenti nel disassemblaggio lineare e sposta il passaggio successivo nella gestione delle eccezioni.<sup>[[1]](#references)</sup>

## L’importanza della gestione delle eccezioni

Un debugger collegato al processo riceve un’eccezione **first-chance** prima dei gestori dell’applicazione. Se la segnala come non gestita, Windows cerca i gestori del processo; se non esiste alcun gestore, l’eccezione torna al debugger come **last-chance**. Un debugger che intercetta un evento breakpoint o single-step può quindi modificare l’esecuzione del gestore del programma.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registra un VEH a livello di processo all’inizio dell’elenco vectored. Viene eseguito prima del SEH basato sui frame, ma una registrazione successiva con priorità massima può spostare un altro gestore davanti a esso. Restituire `EXCEPTION_CONTINUE_SEARCH` lascia l’eccezione agli altri gestori; `EXCEPTION_CONTINUE_EXECUTION` riprende dall’elemento `CONTEXT` salvato, incluse eventuali modifiche ai registri apportate dal gestore.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Il SEH classico x86 usa registrazioni collegate nello stack, che `!exchain` può esaminare. Il codice nativo x64 usa voci `RUNTIME_FUNCTION` in `.pdata` con dati di unwind in `.xdata`, non la catena x86. Non applicare il [workflow di sovrascrittura SEH x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) a un processo nativo x64.<sup>[[5]](#references)[[6]](#references)</sup>

## Trasformare un errore in un collegamento del flusso di controllo

Per esempio, un divisore pari a zero può generare intenzionalmente `EXCEPTION_INT_DIVIDE_BY_ZERO` anziché rappresentare un bug. Il gestore deve riconoscere l’eccezione e l’indirizzo dell’istruzione che l’ha generata, quindi impostare `ContextRecord->Rip` (o `Eip` su x86) su un punto di continuazione valido prima di restituire `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Il core dell'handler qui sotto presuppone che `fault_site` e `continuation` siano indirizzi noti nello stesso contesto di control-flow. Un'implementazione reale deve preservare lo stack e i registri previsti e non deve riprendere dalla stessa istruzione che ha generato l'eccezione, altrimenti si verificherà di nuovo l'errore.<sup>[[7]](#references)</sup>

```c
if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO &&
    e->ExceptionRecord->ExceptionAddress == fault_site) {
#ifdef _M_X64
    e->ContextRecord->Rip = (DWORD64)continuation;
#else
    e->ContextRecord->Eip = (DWORD)continuation;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
return EXCEPTION_CONTINUE_SEARCH;
```

Lo stesso meccanismo può intercettare un `INT3`/`__debugbreak()` intenzionale (`EXCEPTION_BREAKPOINT`) e reindirizzare l’esecuzione. **Non** incrementare alla cieca `Rip` per "saltare il breakpoint": l’indirizzo salvato e l’aggiustamento necessario dipendono dal trap, dalla codifica dell’istruzione e dal comportamento del debugger. Confronta `ExceptionRecord->ExceptionAddress` con il puntatore all’istruzione salvato e disassembla i byte prima di scegliere la continuazione.<sup>[[8]](#references)</sup> Il [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) è un esempio separato di hardware-breakpoint che modifica lo stato di ritorno di una syscall del loader.

## Materializzazione delle pagine guidata dai fault

Un VEH può trasformare un page fault in un **lazy loader**, non solo in un salto. Riserva un intervallo di immagine privato lasciando le pagine non committed, oppure usa pagine mappate con guardia, se supportate. Prima di eseguire l’immagine, indicizza i punti di rilocazione e le thunk IAT in base alla pagina di destinazione. In caso di fault all’interno di quell’intervallo, l’handler esegue il commit della pagina interessata o la rende scrivibile, copia i byte della sezione, applica le rilocazioni e gli import di quella pagina, imposta la protezione finale e restituisce `EXCEPTION_CONTINUE_EXECUTION`. L’istruzione originale viene ritentata: **non** avanzare `Rip` come in un handler che salta il fault. Le pagine mai toccate non devono necessariamente contenere il payload in memoria.<sup>[[11]](#references)</sup>

In caso di access violation, `ExceptionRecord->ExceptionAddress` identifica l’**istruzione** che ha generato il fault, mentre `ExceptionInformation[1]` identifica l’indirizzo a cui si è tentato di accedere.<sup>[[10]](#references)</sup> Controlla il codice dell’eccezione, il numero di parametri e l’intervallo dell’indirizzo a cui si è tentato di accedere prima di materializzare una pagina; altrimenti, un fault non correlato potrebbe essere scambiato per una richiesta del loader.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` genera `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) al primo accesso e Windows azzera automaticamente il bit di guardia, quindi riattivarla è un’operazione separata, non un hook continuo.<sup>[[12]](#references)</sup> Mantieni il VEH e tutti i metadati necessari accessibili durante la gestione dell’eccezione.<sup>[[11]](#references)</sup> Su x64, i dati di unwind potrebbero dover essere disponibili prima del primo fault; il loader citato materializza eager le pagine prima di invocare `DllMain` per evitare race durante l’inizializzazione.<sup>[[11]](#references)</sup> Svuota la cache delle istruzioni dopo aver scritto il codice e prima di eseguirlo.<sup>[[13]](#references)</sup>

Per ricostruire questo flusso durante il reversing, imposta un breakpoint sulle guard-page violation e access violation first-chance, esamina il record dell’eccezione, quindi passa l’evento all’handler dell’applicazione con `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Usa `!vprot` sull’indirizzo a cui si è tentato di accedere per esaminare la protezione corrente della pagina.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Dopo che l'handler materializza la pagina, scaricane i byte e confrontali con l'immagine del file.<sup>[[11]](#references)</sup> Un `!vprot` eseguito dopo il fault non può dimostrare che la pagina fosse protetta da guard prima, perché lo stato di guard è monouso.<sup>[[11]](#references)[[12]](#references)</sup> Restringi i filtri delle eccezioni o i breakpoint dell'handler una volta individuato l'intervallo rilevante dell'immagine, per evitare fault non correlati.<sup>[[16]](#references)</sup> Consulta [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) per configurare i filtri.<sup>[[16]](#references)</sup>

## Trap Flag come gate dipendente dal debugger

Il bit `0x100` in `EFLAGS`/`RFLAGS` è il Trap Flag (TF). Impostandolo, al confine dell'istruzione successiva viene generato `STATUS_SINGLE_STEP` (`0x80000004`). Un ramo VEH o SEH può distinguere un evento single-step passato all'applicazione da uno gestito da un debugger, ma si tratta di un'**euristica controllata dalla policy di gestione delle eccezioni del debugger**, non di una prova affidabile dell'esistenza di un debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Se l'handler vuole un solo step, azzera `0x100` in `EFlags` del contesto ripristinato prima di continuare. Distingui inoltre gli step causati da TF dagli eventi di hardware breakpoint controllando l'indirizzo che li ha generati e lo stato di debug: entrambi possono apparire come `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Per le impostazioni di first-/second-chance di `sxe`, `sxd` e `sxi` di WinDbg, consulta [Automazione delle eccezioni di WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: eccezioni](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Gestione delle eccezioni del debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Gestione vettoriale delle eccezioni](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Gestione delle eccezioni x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Uso di un gestore vettoriale delle eccezioni](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: istruzioni assembly](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Architettura x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Caricamento di immagini basato su fault](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Creazione di pagine guard](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Visualizza il record dell'eccezione)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - Filtri delle eccezioni sx](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Continua con eccezione non gestita)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
