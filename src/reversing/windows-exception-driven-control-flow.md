# Sterowanie przepływem sterowane wyjątkami w Windows i anti-debugging

{{#include ../banners/hacktricks-training.md}}

Chroniony program Windows może używać celowo wywołanego wyjątku jako rozgałęzienia: instrukcja powodująca błąd jest jedynie wejściem do handlera, który wybiera następny adres kodu użytkownika. Ukrywa to krawędzie przepływu przed deasemblacją liniową i przenosi wybór kolejnego kroku do obsługi wyjątków.<sup>[[1]](#references)</sup>

## Znaczenie obsługi wyjątków

Debugger podłączony do procesu otrzymuje wyjątek **first-chance** przed handlerami aplikacji. Jeśli przekaże zdarzenie jako nieobsłużone, Windows przeszukuje handlery procesu; wyjątek bez handlera wraca do debuggera jako **last-chance**. Debugger, który przechwytuje zdarzenie breakpointa lub single-step, może więc zmienić to, czy handler programu zostanie uruchomiony.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` rejestruje VEH dla całego procesu na początku listy wektorowej. Jest on uruchamiany przed SEH opartym na ramkach, ale późniejsza rejestracja z priorytetem pierwszeństwa może przesunąć inny handler przed niego. Zwrócenie `EXCEPTION_CONTINUE_SEARCH` pozostawia wyjątek do obsługi przez inne handlery; `EXCEPTION_CONTINUE_EXECUTION` wznawia wykonywanie na podstawie zapisanego `CONTEXT`, w tym zmian rejestrów wprowadzonych przez handler.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Klasyczny x86 SEH używa powiązanych ze stosem rejestracji, które można sprawdzić poleceniem `!exchain`. Natywne x64 używa wpisów `RUNTIME_FUNCTION` w `.pdata` z danymi unwind w `.xdata`, a nie łańcucha x86. Nie stosuj [procedury nadpisywania x86 SEH](../binary-exploitation/stack-overflow/windows-seh-overflow.md) do natywnego procesu x64.<sup>[[5]](#references)[[6]](#references)</sup>

## Zmień błąd w krawędź przepływu sterowania

Na przykład dzielenie przez zero może celowo wywołać `EXCEPTION_INT_DIVIDE_BY_ZERO`, zamiast być błędem. Handler musi rozpoznać wyjątek i adres instrukcji powodującej błąd, a następnie ustawić `ContextRecord->Rip` (lub `Eip` na x86) na prawidłowy adres kontynuacji przed zwróceniem `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Poniższy rdzeń procedury obsługi zakłada, że `fault_site` i `continuation` są znanymi adresami w tym samym kontekście przepływu sterowania. Rzeczywista implementacja musi zachować oczekiwany stos i rejestry oraz nie może wznawiać wykonania od tej samej instrukcji powodującej błąd, bo błąd wystąpi ponownie.<sup>[[7]](#references)</sup>

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

Ten sam mechanizm może przechwycić celowe `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) i przekierować wykonanie. **Nie** zwiększaj bezrefleksyjnie `Rip`, aby „pominąć breakpoint”: zapisany adres i wymagane przesunięcie zależą od pułapki, kodowania instrukcji i zachowania debuggera. Przed wyborem miejsca kontynuacji porównaj `ExceptionRecord->ExceptionAddress` z zapisanym wskaźnikiem instrukcji i zdeasembluj bajty.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) to osobny przykład wykorzystania hardware-breakpointu do zmiany stanu powrotu z syscalla loadera.

## Materializacja stron sterowana błędami

VEH może zmienić page fault w **lazy loader**, a nie tylko skok. Zarezerwuj prywatny zakres obrazu z niezatwierdzonymi stronami albo, jeśli to obsługiwane, użyj guard pages. Przed uruchomieniem obrazu zindeksuj miejsca relokacji i thunki IAT według stron docelowych. Gdy wystąpi błąd w tym zakresie, handler zatwierdza dotkniętą stronę lub ustawia ją jako zapisywalną, kopiuje bajty jej sekcji, stosuje relokacje i importy tej strony, ustawia jej końcowe uprawnienia i zwraca `EXCEPTION_CONTINUE_EXECUTION`. Pierwotna instrukcja zostaje ponowiona; **nie** zwiększaj `Rip`, jak w handlerze pomijającym błąd. Strony, do których nigdy nie uzyskano dostępu, nie muszą zawierać payloadu w pamięci.<sup>[[11]](#references)</sup>

W przypadku access violation `ExceptionRecord->ExceptionAddress` wskazuje **instrukcję**, która spowodowała błąd, natomiast `ExceptionInformation[1]` wskazuje adres, do którego uzyskano dostęp.<sup>[[10]](#references)</sup> Przed materializacją strony sprawdź kod wyjątku, liczbę parametrów i zakres adresu, do którego uzyskano dostęp; w przeciwnym razie niezwiązany błąd może zostać pomylony z żądaniem loadera.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` przy pierwszym dostępie zgłasza `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`), a Windows automatycznie czyści bit guard, więc ponowne jego ustawienie jest osobnym krokiem, a nie ciągłym hookiem.<sup>[[12]](#references)</sup> Zapewnij dostępność VEH i potrzebnych mu metadanych podczas obsługi wyjątku.<sup>[[11]](#references)</sup> Na x64 dane unwind mogą być potrzebne przed pierwszym błędem; cytowany loader materializuje strony z wyprzedzeniem, przed wywołaniem `DllMain`, aby uniknąć wyścigów podczas inicjalizacji.<sup>[[11]](#references)</sup> Po zapisaniu kodu, a przed jego wykonaniem, opróżnij cache instrukcji.<sup>[[13]](#references)</sup>

Aby odtworzyć ten przepływ podczas reverse engineeringu, ustaw breakpointy na wyjątki guard page i access violation zgłaszane przy pierwszej szansie, sprawdź rekord wyjątku, a następnie przekaż zdarzenie handlerowi aplikacji za pomocą `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Użyj `!vprot` na adresie, do którego uzyskano dostęp, aby sprawdzić bieżące uprawnienia strony.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Po zmaterializowaniu strony przez handler zrzucić jej bajty i porównać je z obrazem pliku.<sup>[[11]](#references)</sup> `!vprot` wykonane po błędzie nie może dowieść, że strona była wcześniej oznaczona jako guard, ponieważ ten status jest jednorazowy.<sup>[[11]](#references)[[12]](#references)</sup> Po ustaleniu odpowiedniego zakresu obrazu zawęzić filtry wyjątków lub punkty przerwania handlera, aby uniknąć niepowiązanych błędów.<sup>[[16]](#references)</sup> Zobacz [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception), aby skonfigurować filtry.<sup>[[16]](#references)</sup>

## Trap Flag jako bramka zależna od debuggera

Bit `0x100` w `EFLAGS`/`RFLAGS` to Trap Flag (TF). Jego ustawienie powoduje zgłoszenie `STATUS_SINGLE_STEP` (`0x80000004`) na granicy następnej instrukcji. Gałąź VEH lub SEH może rozróżnić zdarzenie single-step przekazane aplikacji od zdarzenia obsłużonego przez debugger, ale jest to **heurystyka zależna od polityki obsługi wyjątków debuggera**, a nie wiarygodny dowód na jego obecność.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Jeśli handler potrzebuje tylko jednego kroku, wyczyść `0x100` w polu `EFlags` wznowionego kontekstu przed kontynuowaniem. Odróżnij też kroki wywołane przez TF od zdarzeń sprzętowych punktów przerwania, sprawdzając adres wyzwalający i stan debugowania; oba mogą być zgłaszane jako `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Informacje o ustawieniach first-/second-chance w `sxe`, `sxd` i `sxi` WinDbg znajdziesz w sekcji [Automatyzacja wyjątków w WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-debugowanie: wyjątki](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Obsługa wyjątków przez debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Obsługa wyjątków wektorowych](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Obsługa wyjątków x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Korzystanie z handlera wyjątków wektorowych](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-debugowanie: instrukcje asemblera](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Architektura x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Ładowanie obrazu sterowane błędami](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Tworzenie stron Guard](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (wyświetlanie rekordu wyjątku)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - Filtry wyjątków sx](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (kontynuuj po nieobsłużonym wyjątku)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
