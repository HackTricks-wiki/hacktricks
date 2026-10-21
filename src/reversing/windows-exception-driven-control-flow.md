# Windows Exception-Driven Control Flow und Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Ein geschütztes Windows-Programm kann eine absichtliche Ausnahme als Verzweigung verwenden: Die fehlerauslösende Anweisung ist lediglich der Einstiegspunkt für einen Handler, der die nächste Adresse im Benutzercode auswählt. Dadurch werden Kanten vor der linearen Disassemblierung verborgen und der nächste Schritt in die Ausnahmebehandlung verlagert.<sup>[[1]](#references)</sup>

## Die Ausnahmebehandlung ist entscheidend

Ein an den Prozess angehängter Debugger erhält eine Ausnahme als **first-chance**, bevor die Anwendungs-Handler aufgerufen werden. Gibt er das Ereignis als unbehandelt weiter, durchsucht Windows die Handler des Prozesses; gibt es keinen Handler für die Ausnahme, wird sie als **last-chance** an den Debugger zurückgegeben. Ein Debugger, der ein Breakpoint- oder Single-Step-Ereignis abfängt, kann daher beeinflussen, ob der Handler des Programms ausgeführt wird.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registriert einen prozessweiten VEH am Anfang der Vectored-Liste. Er wird vor framebasiertem SEH ausgeführt, aber eine spätere Registrierung mit gleicher Priorität kann einen anderen Handler vor ihn verschieben. Die Rückgabe von `EXCEPTION_CONTINUE_SEARCH` überlässt die Ausnahme weiteren Handlern; `EXCEPTION_CONTINUE_EXECUTION` setzt die Ausführung mit dem gespeicherten `CONTEXT` fort, einschließlich aller vom Handler vorgenommenen Registeränderungen.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klassisches x86-SEH verwendet stackverknüpfte Registrierungen, die sich mit `!exchain` untersuchen lassen. Native x64-Systeme verwenden `RUNTIME_FUNCTION`-Einträge in `.pdata` mit Unwind-Daten in `.xdata` und nicht diese x86-Kette. Wende den [x86-SEH-Overwrite-Workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md) nicht auf einen nativen x64-Prozess an.<sup>[[5]](#references)[[6]](#references)</sup>

## Einen Fehler in eine Kontrollflusskante umwandeln

Zum Beispiel kann eine Division durch null absichtlich `EXCEPTION_INT_DIVIDE_BY_ZERO` auslösen, anstatt einen Fehler darzustellen. Der Handler muss die Ausnahme und die Fehleradresse erkennen und dann `ContextRecord->Rip` (oder auf x86 `Eip`) auf eine gültige Fortsetzungsadresse setzen, bevor er `EXCEPTION_CONTINUE_EXECUTION` zurückgibt.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Der folgende Handler-Kern setzt voraus, dass `fault_site` und `continuation` bekannte Adressen im selben Kontrollflusskontext sind. Eine reale Implementierung muss den erwarteten Stack und die Register erhalten und darf nicht bei derselben fehlerauslösenden Instruktion fortfahren, da sonst erneut ein Fehler auftritt.<sup>[[7]](#references)</sup>

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

Derselbe Mechanismus kann ein absichtliches `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) abfangen und die Ausführung umleiten. Erhöhe `Rip` **nicht** blind, um den „Breakpoint zu überspringen“: Die gespeicherte Adresse und die erforderliche Anpassung hängen vom Trap, der Instruktionskodierung und dem Verhalten des Debuggers ab. Vergleiche `ExceptionRecord->ExceptionAddress` mit dem gespeicherten Instruktionszeiger und disassembliere die Bytes, bevor du die Fortsetzung festlegst.<sup>[[8]](#references)</sup> Der [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) ist ein separates Beispiel für Hardware-Breakpoints, das den Rückgabestatus eines Loader-Systemaufrufs ändert.

## Trap Flag als debuggerabhängige Schranke

Bit `0x100` in `EFLAGS`/`RFLAGS` ist das Trap Flag (TF). Wenn es gesetzt ist, löst die nächste Instruktionsgrenze `STATUS_SINGLE_STEP` (`0x80000004`) aus. Ein VEH- oder SEH-Zweig kann unterscheiden, ob ein an die Anwendung weitergegebenes Single-Step-Ereignis vom Debugger abgefangen wurde; dies ist jedoch eine **Heuristik, die von der Exception-Richtlinie des Debuggers abhängt, und kein zuverlässiger Beweis dafür, dass ein Debugger existiert**.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Wenn der Handler nur einen Schritt ausführen soll, lösche `0x100` im `EFlags` des fortgesetzten Kontexts, bevor du fortfährst. Unterscheide außerdem TF-gesteuerte Schritte von Hardware-Breakpoint-Ereignissen, indem du die auslösende Adresse und den Debug-Status prüfst; beide können als `EXCEPTION_SINGLE_STEP` auftreten.<sup>[[8]](#references)[[9]](#references)</sup> Informationen zu den First-/Second-Chance-Einstellungen von WinDbg mit `sxe`, `sxd` und `sxi` findest du unter [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Ausnahmen](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Debugger-Ausnahmebehandlung](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Vectored Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64-Ausnahmebehandlung](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Verwenden eines Vectored Exception Handlers](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Assembly-Anweisungen](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86-Architektur](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
