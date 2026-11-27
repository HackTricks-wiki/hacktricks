# Windows-Ausnahmegesteuerter Kontrollfluss und Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Ein geschütztes Windows-Programm kann eine absichtliche Ausnahme als Verzweigung verwenden: Die fehlerauslösende Instruktion ist lediglich der Einstiegspunkt zu einem handler, der die nächste Adresse im User-Code auswählt. Dadurch werden Kanten vor der linearen Disassemblierung verborgen und der nächste Schritt in die Ausnahmeverarbeitung verlagert.<sup>[[1]](#references)</sup>

## Die Ausnahmeverarbeitung ist entscheidend

Ein an den Prozess angehängter Debugger empfängt eine **first-chance**-Ausnahme, bevor die Anwendungs-handler aufgerufen werden. Gibt er das Ereignis als unbehandelt weiter, durchsucht Windows die handler des Prozesses; eine Ausnahme ohne handler wird als **last-chance** an den Debugger zurückgegeben. Ein Debugger, der ein Breakpoint- oder Single-Step-Ereignis abfängt, kann daher beeinflussen, ob der handler des Programms ausgeführt wird.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registriert einen prozessweiten VEH am Anfang der Vectored-Liste. Er wird vor frame-basiertem SEH ausgeführt, aber eine spätere Registrierung mit erster Priorität kann einen anderen handler davor platzieren. Die Rückgabe von `EXCEPTION_CONTINUE_SEARCH` überlässt die Ausnahme anderen handlern; `EXCEPTION_CONTINUE_EXECUTION` setzt die Ausführung mit dem gespeicherten `CONTEXT` fort, einschließlich aller vom handler vorgenommenen Registeränderungen.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klassisches x86-SEH verwendet stack-verknüpfte Registrierungen, die sich mit `!exchain` untersuchen lassen. Natives x64 verwendet `RUNTIME_FUNCTION`-Einträge in `.pdata` mit Unwind-Daten in `.xdata` und nicht diese x86-Kette. Wende den [x86-SEH-Overwrite-Workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md) nicht auf einen nativen x64-Prozess an.<sup>[[5]](#references)[[6]](#references)</sup>

## Einen Fehler in eine Kontrollflusskante umwandeln

Ein Divisor von null kann beispielsweise absichtlich `EXCEPTION_INT_DIVIDE_BY_ZERO` auslösen, anstatt einen Fehler darzustellen. Der handler muss die Ausnahme und die Fehleradresse erkennen und dann `ContextRecord->Rip` (oder auf x86 `Eip`) auf eine gültige Fortsetzungsadresse setzen, bevor er `EXCEPTION_CONTINUE_EXECUTION` zurückgibt.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Der folgende Handler-Kern setzt voraus, dass `fault_site` und `continuation` bekannte Adressen im selben Kontrollflusskontext sind. Eine echte Implementierung muss den erwarteten Stack und die Register erhalten und darf nicht bei derselben fehlerauslösenden Instruktion fortfahren, da sonst erneut ein Fehler auftritt.<sup>[[7]](#references)</sup>

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

Derselbe Mechanismus kann ein absichtlich ausgelöstes `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) abfangen und die Ausführung umleiten. Erhöhe `Rip` **nicht** blind, um den Breakpoint zu „überspringen“: Die gespeicherte Adresse und die erforderliche Anpassung hängen vom Trap, der Instruktionskodierung und dem Verhalten des Debuggers ab. Vergleiche `ExceptionRecord->ExceptionAddress` mit dem gespeicherten Instruction Pointer und disassembliere die Bytes, bevor du die Fortsetzung auswählst.<sup>[[8]](#references)</sup> Der [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) ist ein separates Hardware-Breakpoint-Beispiel, das den Rückgabestatus eines Loader-Syscalls ändert.

## Seitenmaterialisierung bei einem Fehler

Ein VEH kann einen Seitenfehler in einen **lazy loader** verwandeln, nicht nur in einen Sprung. Reserviere einen privaten Image-Bereich mit nicht committeten Seiten oder, sofern unterstützt, mit Guard-Seiten. Indiziere vor dem Ausführen des Images die Relocation-Sites und IAT-Thunks anhand ihrer Zielseite. Bei einem Fehler innerhalb dieses Bereichs committet der Handler die betroffene Seite oder setzt sie auf beschreibbar, kopiert ihre Section-Bytes, wendet die Relocations und Imports dieser Seite an, setzt ihren endgültigen Schutz und gibt `EXCEPTION_CONTINUE_EXECUTION` zurück. Die ursprüngliche Instruktion wird erneut ausgeführt; erhöhe `Rip` **nicht** wie bei einem Handler, der den Fehler überspringt. Seiten, auf die nie zugegriffen wird, müssen die Payload nicht im Speicher enthalten.<sup>[[11]](#references)</sup>

Bei einer Access Violation identifiziert `ExceptionRecord->ExceptionAddress` die **Instruktion**, die den Fehler ausgelöst hat, während `ExceptionInformation[1]` die adressierte Speicherstelle angibt.<sup>[[10]](#references)</sup> Prüfe den Exception-Code, die Anzahl der Parameter und den Bereich der adressierten Speicherstelle, bevor du eine Seite materialisierst; andernfalls kann ein nicht zugehöriger Fehler fälschlich als Loader-Anfrage interpretiert werden.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` löst beim ersten Zugriff `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) aus, und Windows löscht das Guard-Bit automatisch. Das erneute Setzen ist daher ein separater Schritt und kein kontinuierlicher Hook.<sup>[[12]](#references)</sup> Stelle sicher, dass der VEH und alle von ihm benötigten Metadaten während der Ausführung des Handlers zugänglich sind.<sup>[[11]](#references)</sup> Unter x64 müssen Unwind-Daten möglicherweise bereits vor dem ersten Fehler verfügbar sein; der zitierte Loader materialisiert Seiten vor dem Aufruf von `DllMain` vollständig, um Initialisierungsrennen zu vermeiden.<sup>[[11]](#references)</sup> Leere nach dem Schreiben von Code und vor dessen Ausführung den Instruction Cache.<sup>[[13]](#references)</sup>

Um diesen Ablauf beim Reversing nachzuvollziehen, setze Breakpoints auf First-Chance-Guard-Page-Verletzungen und Access Violations, untersuche den Exception-Record und übergib das Ereignis dann mit `gn` an den Handler der Anwendung.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Verwende `!vprot` auf der adressierten Speicherstelle, um den aktuellen Seitenschutz zu untersuchen.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Nachdem der Handler die Seite materialisiert hat, dumpen Sie ihre Bytes und vergleichen Sie sie mit dem Dateiabbild.<sup>[[11]](#references)</sup> Ein `!vprot` nach dem Fault kann nicht beweisen, dass die Seite zuvor guarded war, da der Guard-Status nur einmal gilt.<sup>[[11]](#references)[[12]](#references)</sup> Grenzen Sie die Exception-Filter oder Handler-Breakpoints ein, sobald der relevante Image-Bereich bekannt ist, um nicht zusammenhängende Faults zu vermeiden.<sup>[[16]](#references)</sup> Informationen zum Einrichten von Filtern finden Sie unter [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).<sup>[[16]](#references)</sup>

## Trap Flag als debuggerabhängiges Gate

Bit `0x100` in `EFLAGS`/`RFLAGS` ist das Trap Flag (TF). Wenn es gesetzt ist, löst die nächste Instruktionsgrenze `STATUS_SINGLE_STEP` (`0x80000004`) aus. Ein VEH- oder SEH-Zweig kann unterscheiden, ob ein an die Anwendung weitergeleitetes Single-Step-Ereignis vorliegt oder eines, das vom Debugger abgefangen wurde. Dies ist jedoch eine **durch die Exception-Richtlinie des Debuggers gesteuerte Heuristik** und kein zuverlässiger Beweis dafür, dass ein Debugger vorhanden ist.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Wenn der Handler nur einen Schritt ausführen soll, lösche `0x100` im `EFlags` des fortgesetzten Kontexts, bevor du fortfährst. Unterscheide außerdem TF-gesteuerte Schritte von Hardware-Breakpoint-Ereignissen, indem du die auslösende Adresse und den Debug-Status prüfst; beide können als `EXCEPTION_SINGLE_STEP` auftreten.<sup>[[8]](#references)[[9]](#references)</sup> Informationen zu den First-/Second-Chance-Einstellungen `sxe`, `sxd` und `sxi` in WinDbg findest du unter [WinDbg-Ausnahmeautomatisierung](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Ausnahmen](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Ausnahmebehandlung im Debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Vectored Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64-Ausnahmebehandlung](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Verwenden eines Vectored Exception Handlers](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Assembly-Instruktionen](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86-Architektur](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Fehlergesteuertes Laden von Images](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Erstellen von Guard Pages](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Ausnahmedatensatz anzeigen)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - sx-Ausnahmefilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Fortfahren, wenn die Ausnahme nicht behandelt wurde)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
