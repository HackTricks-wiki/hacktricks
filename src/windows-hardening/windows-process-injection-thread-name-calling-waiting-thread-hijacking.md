# Windows Process Injection über Thread Names und Waiting Threads

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) überträgt Bytes in einen laufenden Prozess, ohne `WriteProcessMemory` zu verwenden; Waiting Thread Hijacking (WTH) führt sie auf einem vorhandenen Thread aus, ohne `SetThreadContext` aufzurufen oder einen Remote-Thread zu erstellen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Dabei handelt es sich um **Process-Injection-Primitiven, nicht um Privilege-Escalation-Schwachstellen**: Der Injektor benötigt weiterhin Zugriff auf den Zielprozess und den Thread. Die Thread-Description-APIs erfordern Windows 10 Version 1607 oder höher.<sup>[[1]](#references)[[3]](#references)</sup> Weitere Ansätze für Injection und Evasion findest du unter [Antivirus (AV) Bypass](av-bypass.md).

## Thread Name-Calling: Payload-Kopieren auf der Zielseite

`NtSetInformationThread(ThreadNameInformation)` kopiert eine übergebene `UNICODE_STRING` in den Thread-Namensspeicher. Ein Aufruf von `GetThreadDescription` **innerhalb des Ziels** erstellt dann eine Heap-Kopie dieses Namens im User Mode. Dadurch werden die Payload-Übertragung und das abschließende Kopieren in den Speicher getrennt: Der Injektor kann den zurückgegebenen Heap-**Pointer** auslesen, während ein APC, der `RtlMoveMemory` innerhalb des Ziels ausführt, die Bytes an ihr Ziel kopiert.<sup>[[1]](#references)</sup> Die ursprüngliche Technik unterstützt außerdem spezielle User APCs; die WhisperHijack-Implementierung verwendet stattdessen ein gewöhnliches `NtQueueApcThread` auf einem wartenden Thread.<sup>[[1]](#references)[[3]](#references)</sup>

Für jeden Chunk mit höchstens `0xFFFE` Bytes verwendet der PoC die folgende Reihenfolge. Ein dupliziertes Auto-Reset-Event signalisiert den Abschluss erst, nachdem das Ziel den Scratch-Slot gefüllt hat; der Injektor wartet auf dieses Signal, bevor er den Pointer ausliest. Das Event bestätigt den Heap-Pointer-APC, nicht den anschließenden Copy-APC. Der PoC alarmiert denselben Thread, nachdem er den Copy-APC in die Warteschlange gestellt hat, und verlässt sich statt auf ein zweites Abschlusssignal auf die APC-Reihenfolge.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Die Scratch-Adresse muss im Ziel beschreibbar und dem Injector bekannt sein, ohne dass sie zuvor beschrieben wird. Das ursprüngliche PoC verwendet `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack bietet außerdem `PEB.PostProcessInitRoutine` und verwendet standardmäßig `TEB.TlsSlots[63]` (ermittelt mit `NtQueryInformationThread(ThreadBasicInformation)`). Der TLS-Slot ist **nicht garantiert** in jedem Ziel unbenutzt; das Überschreiben eines aktiven Slots kann den Thread beeinträchtigen. Aktiviere genau eine Option in `Main.c`. Die Compile-Time-Prüfungen weisen fehlende oder widersprüchliche PEB/TEB-Auswahlen zurück.<sup>[[4]](#references)</sup>

Ein normaler Aufruf von `RtlInitUnicodeString` würde bei einem eingebetteten Wide-Nullzeichen abbrechen. Um Binärdaten zu übertragen, initialisiere die Länge von `UNICODE_STRING` mithilfe eines gleich großen, nicht-nullterminierten Padding-Puffers, ersetze die Bytes von `Buffer` durch den tatsächlichen Chunk und übergib die Struktur anschließend an `NtSetInformationThread`. Diese längenbasierte Übertragung unterscheidet sich davon, den Shellcode direkt als nullterminierten String an `SetThreadDescription` zu übergeben.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: Rückkehr aus einem Queue-Wait

Enumeriere Threads mit `NtQuerySystemInformation(SystemProcessInformation)` und suche nach `ThreadState == Waiting` mit `WaitReason == WrQueue`. Ein Thread, der in einem Syscall-Wrapper wie `NtWaitForWorkViaWorkerFactory` blockiert ist, hat an `[Rsp]` eine gespeicherte Rücksprungadresse des Aufrufers. Durch Ersetzen dieses Stack-Slots wird der `ret` des Wrappers zu einem Stub umgeleitet, ohne `Rip` über `SetThreadContext` zu ändern. Der Stub muss Flags und Register sichern, eine Payload **aufrufen**, die zurückkehrt, den Zustand wiederherstellen und dann über die gespeicherte ursprüngliche Rücksprungadresse springen.<sup>[[2]](#references)[[3]](#references)</sup>

Im x64-PoC hat der Stub einen 8-Byte-Slot für die gespeicherte Rücksprungadresse bei `+0x00`, Anweisungen bei `+0x08` und die Payload bei `+0x45`. Der Stack-Slot erhält `allocation_base + 0x08`, nicht die Adresse des Datenslots. `WrQueue` allein ist **kein Beleg** für einen Wait in einer Worker Factory: Die ursprüngliche Recherche identifiziert auch `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` als Pfad für Queue-Waits. Prüfe den tatsächlichen Wait-/Call-Stack und vergewissere dich, dass `[Rsp]` der vorgesehene Rücksprung-Slot ist, bevor du dich auf dieses Layout verlässt.<sup>[[2]](#references)[[3]](#references)</sup>

## TNC und WTH ohne prozessübergreifende Schreibzugriffe kombinieren

WhisperHijack demonstriert den kombinierten Ablauf anhand eines bestehenden nativen x64-Prozesses. Sein Writer wählt einen infrage kommenden Prozess/Thread aus, während ein Flipper-Kindprozess die für die abschließende Übergabe benötigten Handles erbt. Das Prozess-Handle fordert `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE` an, **nicht** `PROCESS_VM_WRITE`; das aktuelle PoC öffnet den Thread dennoch mit `THREAD_ALL_ACCESS`. Zugriffskontrollen und Prozess-Mitigationen gelten weiterhin.<sup>[[3]](#references)[[4]](#references)</sup>

Das kombinierte PoC verwendet die folgende Abfolge; die Memory-Copy-APCs werden im Ziel ausgeführt und nicht über ein Handle mit Remote-Write-Rechten.<sup>[[4]](#references)</sup>

1. Reserviere im Ziel freie, an 64 KB ausgerichtete Speicherblöcke und committe anschließend deren 4-KB-Seiten als `PAGE_READWRITE`. Das PoC prüft feste Kandidatenadressen mit `NtQueryVirtualMemory`; diese Adressen sind Implementierungsentscheidungen und keine Voraussetzung für TNC oder WTH.
2. Stelle `[0x45-Byte-WTH-Stub][zurückkehrende x64-Payload][8-Byte-Stub-Einstiegszeiger]` zusammen, wobei der letzte Zeiger `allocation_base + 0x08` ist. Übertrage diesen Puffer mithilfe der TNC-Chunk-Schleife.
3. Ermittle im Flipper mit `NtGetContextThread(CONTEXT_CONTROL)` den `Rsp` des wartenden Threads. Stelle eine In-Target-`RtlMoveMemory`-APC in die Warteschlange, um den ursprünglichen 8-Byte-Wert bei `[Rsp]` in den Datenslot des Stubs zu kopieren.
4. Ändere den bereitgestellten Speicherbereich mit `NtProtectVirtualMemory` auf ausführbar. Dieses PoC wählt `PAGE_EXECUTE_READWRITE`, weil sich seine polymorphe Payload selbst dekodiert; WTH erfordert an sich keine selbstmodifizierende Payload.
5. Stelle eine weitere In-Target-`RtlMoveMemory`-APC in die Warteschlange, um den **zuvor bereitgestellten Tail-Zeiger** nach `[Rsp]` zu kopieren, und rufe dann `NtAlertThread` auf. Die FIFO-Reihenfolge der APCs sichert die ursprüngliche Rücksprungadresse, bevor sie ersetzt wird; die Rückkehr des Wrappers führt in den Stub und setzt nach Rückkehr der Payload die Ausführung beim ursprünglichen Aufrufer fort.

Das Fehlen von `NtWriteVirtualMemory` **bedeutet nicht**, dass keine Schreibzugriffe im Ziel stattfinden: `GetThreadDescription` und `RtlMoveMemory` führen sie innerhalb des Ziels aus.<sup>[[1]](#references)[[3]](#references)</sup> Die Zustellung gewöhnlicher User-APCs hängt außerdem davon ab, dass der ausgewählte Thread seine APC-Warteschlange verarbeitet; ein `WrQueue`-Snapshot und ein Alert garantieren keine sofortige Ausführung.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Das Beispiel vermeidet das Erstellen eines Remote-Threads, das Suspendieren und das direkte Ersetzen des Kontexts, bleibt aber durch seine APCs und den Wechsel der Speicherschutzrechte beobachtbar.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack-PoC und README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – WhisperHijack-Main.c-Implementierung](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
