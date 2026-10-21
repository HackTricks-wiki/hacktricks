# Flusso di controllo basato sulle eccezioni in Windows e Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Un programma Windows protetto può usare un'eccezione intenzionale come diramazione: l'istruzione che genera l'eccezione è solo l'ingresso a un handler che seleziona il successivo indirizzo del codice utente. Questo nasconde gli archi alla disassemblazione lineare e sposta il passo successivo nel dispatch delle eccezioni.<sup>[[1]](#references)</sup>

## Il dispatch è importante

Un debugger collegato al processo riceve un'eccezione **first-chance** prima degli handler dell'applicazione. Se la segnala come non gestita, Windows cerca gli handler del processo; un'eccezione senza handler torna al debugger come **last-chance**. Un debugger che intercetta un evento di breakpoint o single-step può quindi modificare l'esecuzione dell'handler del programma.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registra un VEH a livello di processo in testa alla lista vectored. Viene eseguito prima del SEH basato sui frame, ma una registrazione successiva con priorità massima può collocare un altro handler davanti a esso. Restituire `EXCEPTION_CONTINUE_SEARCH` lascia l'eccezione agli altri handler; `EXCEPTION_CONTINUE_EXECUTION` riprende l'esecuzione dal `CONTEXT` salvato, incluse eventuali modifiche ai registri effettuate dall'handler.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Il SEH classico x86 usa registrazioni collegate allo stack, ispezionabili con `!exchain`. Lo x64 nativo usa voci `RUNTIME_FUNCTION` in `.pdata` con dati di unwind in `.xdata`, non quella catena x86. Non applicare il [workflow di overwrite del SEH x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) a un processo x64 nativo.<sup>[[5]](#references)[[6]](#references)</sup>

## Trasformare un'eccezione in un arco del flusso di controllo

Per esempio, un divisore zero può generare intenzionalmente `EXCEPTION_INT_DIVIDE_BY_ZERO`, invece di rappresentare un bug. L'handler deve riconoscere l'eccezione e l'indirizzo dell'istruzione che l'ha generata, quindi impostare `ContextRecord->Rip` (o `Eip` su x86) su una continuazione valida prima di restituire `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Il nucleo del gestore riportato di seguito presuppone che `fault_site` e `continuation` siano indirizzi noti nello stesso contesto del flusso di controllo. Un’implementazione reale deve preservare lo stack e i registri previsti e non deve riprendere dalla stessa istruzione che ha generato l’errore, altrimenti l’errore si verificherà di nuovo.<sup>[[7]](#references)</sup>

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

Lo stesso meccanismo può intercettare un `INT3`/`__debugbreak()` intenzionale (`EXCEPTION_BREAKPOINT`) e reindirizzare l'esecuzione. **Non** incrementare `Rip` alla cieca per «saltare il breakpoint»: l'indirizzo salvato e la correzione necessaria dipendono dal trap, dalla codifica dell'istruzione e dal comportamento del debugger. Confronta `ExceptionRecord->ExceptionAddress` con il puntatore all'istruzione salvato e disassembla i byte prima di scegliere la continuazione.<sup>[[8]](#references)</sup> Il [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) è un esempio distinto di hardware-breakpoint che modifica lo stato di ritorno di una syscall del loader.

## Trap Flag come gate dipendente dal debugger

Il bit `0x100` in `EFLAGS`/`RFLAGS` è il Trap Flag (TF). Impostandolo, il confine dell'istruzione successiva genera `STATUS_SINGLE_STEP` (`0x80000004`). Un ramo VEH o SEH può distinguere un evento single-step passato all'applicazione da uno intercettato da un debugger, ma si tratta di una **euristica controllata dai criteri di gestione delle eccezioni del debugger**, non di una prova affidabile della presenza di un debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Se l'handler vuole un solo step, azzera `0x100` in `EFlags` del context ripristinato prima di continuare. Distingui inoltre gli step attivati da TF dagli eventi di hardware breakpoint controllando l'indirizzo che li ha attivati e lo stato di debug; entrambi possono apparire come `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Per le impostazioni di first-/second-chance di `sxe`, `sxd` e `sxi` di WinDbg, consulta [Automazione delle eccezioni in WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-debug: eccezioni](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Gestione delle eccezioni del debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Gestione delle eccezioni vectored](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Gestione delle eccezioni x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Uso di un vectored exception handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-debug: istruzioni assembly](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Architettura x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
