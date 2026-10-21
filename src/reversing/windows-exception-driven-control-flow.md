# Windows Exception-Driven Control Flow and Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Chroniony program Windows może używać celowego wyjątku jako rozgałęzienia: instrukcja powodująca błąd jest jedynie wejściem do procedury obsługi, która wybiera kolejny adres kodu użytkownika. Ukrywa to krawędzie przed liniową dezasemblacją i przenosi wybór kolejnego kroku do mechanizmu obsługi wyjątków.<sup>[[1]](#references)</sup>

## Znaczenie mechanizmu obsługi

Debugger podłączony do procesu otrzymuje wyjątek **pierwszej szansy** przed procedurami obsługi aplikacji. Jeśli przekaże zdarzenie jako nieobsłużone, Windows przeszukuje procedury obsługi procesu; wyjątek, dla którego nie ma procedury obsługi, wraca do debuggera jako wyjątek **ostatniej szansy**. Debugger, który przechwytuje zdarzenie punktu przerwania lub pojedynczego kroku, może więc zmienić to, czy uruchomi się procedura obsługi programu.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` rejestruje ogólnoprocesową procedurę VEH na początku listy procedur wektorowych. Jest ona uruchamiana przed procedurami SEH opartymi na ramkach, ale późniejsza rejestracja z najwyższym priorytetem może umieścić inną procedurę przed nią. Zwrócenie `EXCEPTION_CONTINUE_SEARCH` pozostawia wyjątek do obsługi przez inne procedury; `EXCEPTION_CONTINUE_EXECUTION` wznawia wykonanie z zapisanego `CONTEXT`, uwzględniając zmiany rejestrów wprowadzone przez procedurę obsługi.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klasyczny x86 SEH używa powiązanych ze stosem wpisów rejestracyjnych, które można sprawdzić za pomocą `!exchain`. Natywny x64 używa wpisów `RUNTIME_FUNCTION` w `.pdata` z danymi unwind w `.xdata`, a nie tego łańcucha x86. Nie stosuj [procedury nadpisywania x86 SEH](../binary-exploitation/stack-overflow/windows-seh-overflow.md) do natywnego procesu x64.<sup>[[5]](#references)[[6]](#references)</sup>

## Zamień błąd w krawędź przepływu sterowania

Na przykład dzielnik równy zero może celowo wywołać `EXCEPTION_INT_DIVIDE_BY_ZERO`, zamiast oznaczać błąd. Procedura obsługi musi rozpoznać wyjątek i adres instrukcji powodującej błąd, a następnie ustawić `ContextRecord->Rip` (lub `Eip` w x86) na prawidłowy adres kontynuacji przed zwróceniem `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Poniższy rdzeń procedury obsługi zakłada, że `fault_site` i `continuation` są znanymi adresami w tym samym kontekście przepływu sterowania. Rzeczywista implementacja musi zachować oczekiwane wartości na stacku i w rejestrach oraz nie może wznawiać wykonania od tej samej instrukcji powodującej błąd, bo błąd wystąpi ponownie.<sup>[[7]](#references)</sup>

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

Ten sam mechanizm może obsłużyć celowe `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) i przekierować wykonanie. **Nie** zwiększaj bezrefleksyjnie `Rip`, aby „pominąć breakpoint”: zapisany adres i wymagane przesunięcie zależą od pułapki, kodowania instrukcji i zachowania debuggera. Przed wybraniem miejsca wznowienia porównaj `ExceptionRecord->ExceptionAddress` z zapisanym wskaźnikiem instrukcji i zdeasembluj bajty.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) to osobny przykład wykorzystania hardware breakpoint, który zmienia stan powrotu syscalla loadera.

## Trap Flag jako bramka zależna od debuggera

Bit `0x100` w `EFLAGS`/`RFLAGS` to Trap Flag (TF). Jego ustawienie powoduje zgłoszenie `STATUS_SINGLE_STEP` (`0x80000004`) na granicy następnej instrukcji. Gałąź VEH lub SEH może rozróżnić zdarzenie single-step przekazane aplikacji od zdarzenia przechwyconego przez debugger, ale jest to **heurystyka zależna od polityki obsługi wyjątków debuggera**, a nie wiarygodny dowód na obecność debuggera.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Jeśli handler potrzebuje tylko jednego kroku, przed kontynuowaniem wyczyść `0x100` w `EFlags` wznowionego kontekstu. Rozróżniaj też kroki wywołane przez TF od zdarzeń sprzętowego breakpointu, sprawdzając adres wyzwalający i stan debugowania; oba mogą wystąpić jako `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Informacje o ustawieniach `sxe`, `sxd` i `sxi` w WinDbg dla wyjątków pierwszej i drugiej szansy znajdziesz w [automatyzacji obsługi wyjątków w WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: wyjątki](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Obsługa wyjątków przez debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Obsługa wyjątków wektorowych](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Obsługa wyjątków x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Korzystanie z vectored exception handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: instrukcje asemblera](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Architektura x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
