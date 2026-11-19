# Windows Process Injection tramite nomi dei thread e thread in attesa

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) trasferisce byte in un processo in esecuzione senza `WriteProcessMemory`; Waiting Thread Hijacking (WTH) li esegue su un thread esistente senza `SetThreadContext` né la creazione di un thread remoto.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Si tratta di **primitive di process injection, non di vulnerabilità di privilege escalation**: l'injector deve comunque poter accedere al processo e al thread target. Le API per le descrizioni dei thread richiedono Windows 10 versione 1607 o successiva.<sup>[[1]](#references)[[3]](#references)</sup> Vedi [Antivirus (AV) Bypass](av-bypass.md) per altri approcci di injection ed evasione.

## Thread Name-Calling: copia del payload lato target

`NtSetInformationThread(ThreadNameInformation)` copia una `UNICODE_STRING` fornita nell'area di memoria riservata al nome del thread. Chiamando `GetThreadDescription` **all'interno del target** viene quindi creata una copia del nome nell'heap in user mode. In questo modo il trasferimento del payload è separato dalla copia finale in memoria: l'injector può leggere il **puntatore** heap restituito, mentre un APC che esegue `RtlMoveMemory` all'interno del target copia i byte alla destinazione.<sup>[[1]](#references)</sup> La tecnica originale supporta anche gli special user APC; l'implementazione WhisperHijack usa invece `NtQueueApcThread` ordinario su un thread in attesa.<sup>[[1]](#references)[[3]](#references)</sup>

Per ogni blocco di al massimo `0xFFFE` byte, il PoC segue questo ordine. Un evento auto-reset duplicato segnala il completamento solo dopo che il target ha riempito lo slot scratch; l'injector attende il segnale prima di leggere il puntatore. L'evento conferma la ricezione dell'APC del puntatore heap, non della successiva APC di copia. Il PoC invia un alert allo stesso thread dopo aver accodato la copia e si affida all'ordine degli APC invece di usare un secondo segnale di completamento.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

L'indirizzo scratch deve essere scrivibile nel target e noto all'injector senza doverlo prima scrivere. Il PoC originale usa `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack offre anche `PEB.PostProcessInitRoutine` e usa per impostazione predefinita `TEB.TlsSlots[63]` (individuato con `NtQueryInformationThread(ThreadBasicInformation)`). Non è garantito che lo slot TLS sia inutilizzato in ogni target: sovrascrivere uno slot in uso può compromettere quel thread. Abilita esattamente un'opzione in `Main.c`. I controlli in fase di compilazione rifiutano selezioni PEB/TEB mancanti o in conflitto.<sup>[[4]](#references)</sup>

Una normale chiamata a `RtlInitUnicodeString` si interromperebbe in corrispondenza di un null wide incorporato. Per trasportare dati binari, inizializza la lunghezza di `UNICODE_STRING` usando un buffer di padding non-null della stessa dimensione, sostituisci i byte di `Buffer` con il chunk reale, quindi passalo a `NtSetInformationThread`. Questo trasferimento basato sulla lunghezza è distinto dal passaggio dello shellcode direttamente a `SetThreadDescription` come stringa terminata.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: ritorno da un'attesa di coda

Enumera i thread con `NtQuerySystemInformation(SystemProcessInformation)` e cerca `ThreadState == Waiting` con `WaitReason == WrQueue`. Un thread bloccato in un wrapper di syscall come `NtWaitForWorkViaWorkerFactory` ha l'indirizzo di ritorno del chiamante salvato in `[Rsp]`. Sostituendo quello slot dello stack si reindirizza il `ret` del wrapper a uno stub, senza modificare `Rip` tramite `SetThreadContext`. Lo stub deve salvare flags e registri, **chiamare** un payload che ritorna, ripristinare lo stato e poi saltare all'indirizzo di ritorno originale salvato.<sup>[[2]](#references)[[3]](#references)</sup>

Nel PoC x64, lo stub ha uno slot di 8 byte per il return salvato a `+0x00`, istruzioni a `+0x08` e il payload a `+0x45`. Lo slot dello stack riceve `allocation_base + 0x08`, non l'indirizzo dello slot dati. `WrQueue` da solo **non prova** che si tratti di un'attesa di worker factory: la ricerca originale identifica anche `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` come percorso di attesa di coda. Verifica lo stack effettivo di attesa/chiamata e che `[Rsp]` sia lo slot di ritorno previsto prima di fare affidamento su questo layout.<sup>[[2]](#references)[[3]](#references)</sup>

## Combinare TNC e WTH senza scritture tra processi

WhisperHijack mostra il workflow combinato contro un processo nativo x64 esistente. Il suo Writer seleziona un processo/thread candidato, mentre un processo figlio Flipper eredita gli handle necessari per il passaggio finale. L'handle del processo richiede `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **non** `PROCESS_VM_WRITE`; il PoC attuale apre comunque il thread con `THREAD_ALL_ACCESS`. Restano applicabili i controlli di accesso e le mitigazioni del processo.<sup>[[3]](#references)[[4]](#references)</sup>

Il PoC combinato usa questa sequenza; le APC di copia della memoria vengono eseguite nel target, invece di usare un handle con diritti di scrittura remota.<sup>[[4]](#references)</sup>

1. Riserva blocchi liberi allineati a 64 KB nel target, quindi esegui il commit delle relative pagine da 4 KB come `PAGE_READWRITE`. Il PoC prova indirizzi candidati fissi con `NtQueryVirtualMemory`; questi indirizzi sono scelte implementative, non un requisito di TNC o WTH.
2. Assembla `[stub WTH da 0x45 byte][payload x64 con ritorno][puntatore di 8 byte all'ingresso dello stub]`, dove il puntatore finale è `allocation_base + 0x08`. Trasferisci questo buffer con il ciclo di chunk TNC.
3. Nel Flipper, ottieni `Rsp` del thread in attesa con `NtGetContextThread(CONTEXT_CONTROL)`. Accoda un'APC `RtlMoveMemory` nel target per copiare il valore originale di 8 byte in `[Rsp]` nello slot dati dello stub.
4. Rendi eseguibile la regione preparata con `NtProtectVirtualMemory`. Questo PoC sceglie `PAGE_EXECUTE_READWRITE` perché il suo payload polimorfico si decodifica da sé; WTH non richiede di per sé un payload automodificante.
5. Accoda un'altra APC `RtlMoveMemory` nel target per copiare il **puntatore finale preparato in precedenza** in `[Rsp]`, quindi chiama `NtAlertThread`. L'ordine FIFO delle APC salva il return originale prima di sostituirlo; il ritorno del wrapper entra nello stub e, dopo il ritorno del payload, riprende il chiamante originale.

L'assenza di `NtWriteVirtualMemory` **non** significa che non avvengano scritture nel target: `GetThreadDescription` e `RtlMoveMemory` le eseguono all'interno del target.<sup>[[1]](#references)[[3]](#references)</sup> Anche la consegna di normali APC user-mode dipende dal fatto che il thread selezionato elabori la propria coda APC; uno snapshot `WrQueue` e un alert non garantiscono in generale un'esecuzione immediata.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> L'esempio evita la creazione di remote thread, la sospensione e la sostituzione diretta del context, ma resta osservabile tramite le APC e la transizione delle protezioni.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – PoC e README di WhisperHijack](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – Implementazione di WhisperHijack in Main.c](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
