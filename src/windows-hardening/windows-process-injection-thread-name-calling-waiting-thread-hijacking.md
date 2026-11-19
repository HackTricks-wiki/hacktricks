# Windows Process Injection za pomocą nazw wątków i wątków oczekujących

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) przesyła bajty do działającego procesu bez użycia `WriteProcessMemory`; Waiting Thread Hijacking (WTH) uruchamia je w istniejącym wątku bez użycia `SetThreadContext` ani tworzenia zdalnego wątku.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Są to **prymitywy process injection, a nie podatności umożliwiające eskalację uprawnień**: injector nadal potrzebuje dostępu do procesu docelowego i jego wątku. Interfejsy API opisujące wątki wymagają systemu Windows 10 w wersji 1607 lub nowszej.<sup>[[1]](#references)[[3]](#references)</sup> Inne metody injection i unikania wykrycia opisano w sekcji [Antivirus (AV) Bypass](av-bypass.md).

## Thread Name-Calling: kopiowanie payloadu po stronie procesu docelowego

`NtSetInformationThread(ThreadNameInformation)` kopiuje podany `UNICODE_STRING` do pamięci przechowującej nazwę wątku. Wywołanie `GetThreadDescription` **wewnątrz procesu docelowego** tworzy następnie kopię tej nazwy na stercie w trybie użytkownika. Dzięki temu przesyłanie payloadu jest oddzielone od końcowego kopiowania pamięci: injector może odczytać zwrócony **wskaźnik** do sterty, a APC uruchamiający `RtlMoveMemory` wewnątrz procesu docelowego kopiuje bajty pod wskazany adres.<sup>[[1]](#references)</sup> Oryginalna technika obsługuje również specjalne APC użytkownika; implementacja WhisperHijack używa natomiast zwykłego `NtQueueApcThread` w oczekującym wątku.<sup>[[1]](#references)[[3]](#references)</sup>

Dla każdego fragmentu o rozmiarze nie większym niż `0xFFFE` bajtów PoC stosuje następującą kolejność. Zduplikowane zdarzenie z automatycznym resetowaniem sygnalizuje zakończenie dopiero po wypełnieniu przez proces docelowy tymczasowego slotu; injector czeka na ten sygnał, zanim odczyta wskaźnik. Zdarzenie potwierdza wykonanie APC zwracającego wskaźnik do sterty, a nie późniejszego APC kopiującego dane. Po umieszczeniu APC kopiującego w kolejce PoC wybudza ten sam wątek i polega na kolejności APC zamiast na drugim sygnale zakończenia.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Adres scratch musi być zapisywalny w procesie target i znany injectorowi bez wcześniejszego zapisywania go. Oryginalny PoC używa `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack udostępnia również `PEB.PostProcessInitRoutine`, a domyślnie używa `TEB.TlsSlots[63]` (lokalizowanego za pomocą `NtQueryInformationThread(ThreadBasicInformation)`). Nie ma gwarancji, że slot TLS jest nieużywany w każdym procesie target; nadpisanie aktywnego slotu może uszkodzić działanie wątku. Włącz dokładnie jedną opcję w `Main.c`. Kontrole czasu kompilacji odrzucają brakujące lub sprzeczne wybory PEB/TEB.<sup>[[4]](#references)</sup>

Zwykłe wywołanie `RtlInitUnicodeString` zakończyłoby działanie na osadzonym szerokim znaku null. Aby przenieść dane binarne, zainicjuj długość `UNICODE_STRING`, używając bufora wypełniającego o tej samej wielkości, który nie zawiera znaków null, zastąp bajty `Buffer` właściwym fragmentem, a następnie przekaż go do `NtSetInformationThread`. Ten transfer oparty na długości różni się od przekazania shellcode bezpośrednio do `SetThreadDescription` jako zakończonego znakiem null ciągu.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: powrót z oczekiwania na kolejkę

Wylicz wątki za pomocą `NtQuerySystemInformation(SystemProcessInformation)` i szukaj `ThreadState == Waiting` oraz `WaitReason == WrQueue`. Wątek zablokowany w wrapperze syscalla, takim jak `NtWaitForWorkViaWorkerFactory`, ma zapisany adres powrotu wywołującego pod `[Rsp]`. Zastąpienie tego slotu na stosie przekierowuje `ret` wrappera do stubu bez zmiany `Rip` przez `SetThreadContext`. Stub musi zapisać flagi i rejestry, **wywołać** payload, który powraca, odtworzyć stan, a następnie wykonać skok pod zapisany oryginalny adres powrotu.<sup>[[2]](#references)[[3]](#references)</sup>

W PoC x64 stub ma 8-bajtowy slot zapisanego adresu powrotu pod `+0x00`, instrukcje pod `+0x08`, a payload pod `+0x45`. Slot na stosie otrzymuje `allocation_base + 0x08`, a nie adres slotu danych. Samo `WrQueue` **nie dowodzi**, że wątek czeka na worker factory: oryginalne badania wskazują również `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` jako ścieżkę oczekiwania na kolejkę. Przed poleganiem na tym układzie sprawdź rzeczywisty stos oczekiwania/wywołań oraz to, czy `[Rsp]` jest właściwym slotem adresu powrotu.<sup>[[2]](#references)[[3]](#references)</sup>

## Łączenie TNC i WTH bez zapisów między procesami

WhisperHijack demonstruje połączony workflow na istniejącym natywnym procesie x64. Jego Writer wybiera kandydujący proces/wątek, a proces potomny Flipper dziedziczy uchwyty potrzebne do końcowego przekazania. Uchwyt procesu żąda `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **a nie** `PROCESS_VM_WRITE`; bieżący PoC otwiera jednak wątek z `THREAD_ALL_ACCESS`. Nadal obowiązują kontrole dostępu i zabezpieczenia procesu.<sup>[[3]](#references)[[4]](#references)</sup>

Połączony PoC stosuje poniższą sekwencję; APC kopiujące pamięć są wykonywane w procesie target, a nie za pośrednictwem uchwytu z prawami do zdalnego zapisu.<sup>[[4]](#references)</sup>

1. Zarezerwuj w procesie target wolne bloki wyrównane do 64 KB, a następnie zatwierdź ich strony 4-KB jako `PAGE_READWRITE`. PoC sprawdza stałe adresy kandydackie za pomocą `NtQueryVirtualMemory`; adresy te są wyborem implementacyjnym, a nie wymogiem TNC ani WTH.
2. Złóż `[stub WTH o rozmiarze 0x45 bajta][payload x64 powracający do wywołującego][8-bajtowy wskaźnik wejścia do stubu]`, gdzie ostatni wskaźnik to `allocation_base + 0x08`. Przekaż ten bufor za pomocą pętli fragmentów TNC.
3. W Flipper pobierz `Rsp` oczekującego wątku za pomocą `NtGetContextThread(CONTEXT_CONTROL)`. Umieść w kolejce APC wywołujące `RtlMoveMemory` w procesie target, aby skopiować oryginalną 8-bajtową wartość spod `[Rsp]` do slotu danych stubu.
4. Zmień region etapowany na wykonywalny za pomocą `NtProtectVirtualMemory`. Ten PoC wybiera `PAGE_EXECUTE_READWRITE`, ponieważ jego polimorficzny payload sam się dekoduje; WTH nie wymaga payloadu samomodyfikującego się.
5. Umieść w kolejce kolejne APC wywołujące `RtlMoveMemory` w procesie target, aby skopiować **wcześniej przygotowany wskaźnik końcowy** do `[Rsp]`, a następnie wywołaj `NtAlertThread`. Kolejność FIFO APC zapisuje oryginalny adres powrotu przed jego zastąpieniem; powrót z wrappera przechodzi do stubu, a po powrocie payloadu wznawia działanie oryginalnego kodu wywołującego.

Brak `NtWriteVirtualMemory` **nie** oznacza, że w procesie target nie są wykonywane żadne zapisy: wykonują je tam `GetThreadDescription` i `RtlMoveMemory`.<sup>[[1]](#references)[[3]](#references)</sup> Dostarczenie zwykłego APC użytkownika zależy również od tego, czy wybrany wątek obsługuje swoją kolejkę APC; migawka `WrQueue` i alert nie gwarantują natychmiastowego wykonania w każdej sytuacji.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Przykład unika tworzenia zdalnego wątku, zawieszania go i bezpośredniej podmiany kontekstu, ale nadal jest widoczny przez APC i zmianę ochrony pamięci.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC i plik README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – implementacja WhisperHijack w Main.c](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
