# Debugowanie jądra Windows za pomocą KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt to debugger dla Windows x64 przeznaczony do kontrolowanych laboratoriów inżynierii wstecznej. Interfejs WPF po stronie hosta lub `KfConsole.exe` wysyła polecenia do `KfRelay.exe` na testowej maszynie wirtualnej Windows z włączonymi testowymi podpisami. Relay przekształca je w żądania `DeviceIoControl` dla `KernelFlirt.sys`, który udostępnia operacje na pamięci, rejestrach i breakpointach, sterowanie wykonaniem oraz operacje na modułach jądra. Sterownik modyfikuje także ścieżkę debugowania jądra za pomocą inline hooka `KdpStub`/`KdTrap`, dlatego używaj go wyłącznie na jednorazowej maszynie wirtualnej.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

Relay to uprzywilejowana granica debugowania, a nie zwykła usługa zdalna. Port TCP `31337` utrzymuj w odizolowanej sieci host-only i nigdy nie udostępniaj sterownika podpisanego testowym certyfikatem ani relay w niezaufanej sieci.<sup>[[1]](#references)</sup>

Powiązane techniki Windows exploitation:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Konfiguracja laboratorium i pierwszy przystanek

Do kompilacji wymagane są Windows 10/11 x64, Visual Studio 2022 z C++, WDK 10.0.26100.0 lub nowszy oraz .NET 9. Załaduj sterownik i relay wewnątrz VM, a następnie połącz się z hosta. Interfejs może otwierać zdalne pliki EXE lub SYS, a widok **Kernel Modules** umożliwia ustawianie breakpointów w już załadowanych sterownikach.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Po zakończeniu laboratorium użyj `KfLoader.exe unload`. Konsola obsługuje niepołączony REPL, bezpośredni dostęp do urządzenia lokalnego i dostęp przez relay; tylko tryb relay obsługuje opisany poniżej deterministyczny przepływ pracy `open`.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Minimalny przepływ pracy w konsoli to:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Adresy są wyrażeniami. Same liczby są interpretowane jako szesnastkowe, a wyrażenia mogą używać rejestrów, działań arytmetycznych, dereferencji, takich jak `[rsp]`, oraz symboli, takich jak `ntdll!NtCreateFile`. Breakpointy symboliczne należy dodawać dopiero po tym, jak `open` lub `attach` wyliczy moduły i załaduje ich pliki PDB.<sup>[[2]](#references)</sup>

## Deterministyczne przechwytywanie punktu wejścia za pomocą `EB FE`

`open` po stronie relay tworzy proces docelowy w stanie wstrzymania, zapisuje pierwsze bajty jego punktu wejścia, zapisuje tam `EB FE`, wznawia wątek wejściowy i sprawdza w pętli, aż jego wskaźnik instrukcji osiągnie ten adres. `EB FE` to dwubajtowy krótki skok do samego siebie, który zatrzymuje wykonanie bez polegania na dostarczeniu wyjątku debugowania w trybie użytkownika. Następnie relay przywraca oryginalne bajty i pozostawia proces docelowy zatrzymany w punkcie wejścia.<sup>[[2]](#references)</sup>

Ten wzorzec jest również przydatny, gdy trzeba zaobserwować wczesną ścieżkę loadera, zanim zakończy się standardowa konfiguracja debuggera.<sup>[[2]](#references)</sup>

1. Utwórz proces w stanie wstrzymania i ustal jego rzeczywisty punkt wejścia po zmapowaniu obrazu.
2. Zapisz oryginalne bajty punktu wejścia i zastąp je dwubajtową pętlą skoku do samej siebie.
3. Wznów wątek wejściowy i sprawdzaj w pętli jego wskaźnik instrukcji, aż osiągnie załatany adres.
4. Wstrzymaj proces docelowy i przywróć dokładnie oryginalne bajty przed wznowieniem analizy.

Ta technika celowo ingeruje w działanie procesu. Jeśli debugger lub relay zakończy działanie przed przywróceniem bajtów, proces docelowy może pozostać w pętli. Lokalny tryb KernelFlirt nie obsługuje załatanych punktów wejścia po stronie relay; uruchom proces ręcznie i użyj `attach <pid>`.<sup>[[2]](#references)</sup>

## Wybór mechanizmu breakpointów

KernelFlirt udostępnia kilka mechanizmów breakpointów, które mają różne skutki uboczne. Poniższe polecenia pozwalają analitykowi przełączać mechanizmy, gdy spakowany kod sam się przepisuje, strony wykonywalne są tylko do odczytu lub bajty programowych breakpointów są sprawdzane pod kątem integralności.<sup>[[1]](#references)[[2]](#references)</sup>

| Mechanizm | Polecenie | Działanie i zastosowanie |
| --- | --- | --- |
| Programowy | `bp <expr>` | `INT3` oparty na MDL; umożliwia instrumentację stron RX `.text` |
| Warunkowy programowy | `bp <expr> if <condition>` | Sprawdza warunek przy każdym trafieniu i wznawia wykonanie bez komunikatu, gdy warunek jest fałszywy |
| Sprzętowy — wykonanie | `ba e1 <expr>` | Używa jednego z DR0-DR3 bez zmieniania bajtów kodu |
| Sprzętowy — dane | `ba w4 <expr>` / `ba r8 <expr>` | Obserwuje zapisy albo odczyty/zapisy 1, 2, 4 lub 8 bajtów |
| Strona ochronna | `bm <expr> [size]` | Używa `PAGE_GUARD` do ustawienia breakpointu dla zakresu pamięci |
| Tymczasowy | `g <expr>`, `p` lub `o` | Pomocniczy breakpoint: uruchomienie do adresu, Step Over i Step Out |

Użyj `bl`, aby rozróżnić wpisy programowe, sprzętowe, pamięciowe i tymczasowe, a `bc <address|handle|all>`, aby je usunąć. Liczba slotów sprzętowych jest ograniczona, a ich działanie opiera się na stanie rejestrów debugowania. Strony ochronne obejmują większy zakres, ale wyzwalają się przy niezwiązanych z analizą dostępach do tej samej strony.

## Krokowanie natywne x64 a WoW64

Natywne krokowanie pojedynczymi instrukcjami w x64 ustawia flagę pułapki procesora za pomocą `IOCTL_KF_SINGLE_STEP`. Step Over dekoduje bieżącą instrukcję i umieszcza tymczasowe breakpointy pod możliwymi adresami następnych instrukcji. Step Out odczytuje adres powrotu ze szczytu bieżącego stosu. W prologu funkcji założenie dotyczące stosu może być błędne, dlatego lepiej użyć znanego wewnętrznego breakpointu.<sup>[[2]](#references)</sup>

Hook `KdTrap` nie przechwytuje wyjątków 32-bitowych w ten sam sposób. W przypadku procesów WoW64 debugger dekoduje instrukcję za pomocą Iced, zapisuje `EB FE` pod obliczonym następnym `EIP` i sprawdza w pętli wskaźniki instrukcji wątków. W rezultacie `g <address>` nie jest dostępne dla WoW64, a zwykłe `g` blokuje konsolę do chwili osiągnięcia breakpointu. Najpierw ustaw osiągalny breakpoint i unikaj nieograniczonego czasowo uruchomienia, ponieważ `Ctrl+C` kończy działanie konsoli zamiast anulować sprawdzanie w pętli.<sup>[[2]](#references)</sup>

## Analiza wspomagana pamięcią, rejestrami i symbolami

Konsola pozwala połączyć zatrzymanie na symbolu z inspekcją pamięci i kontrolowaną modyfikacją. Wyszukiwanie obsługuje symbole wieloznaczne bajtów, ASCII lub UTF-16; jest ograniczone do 4 MB i zwraca maksymalnie 256 dopasowań. Polecenia alokacji i ochrony pamięci wywołują sterownikowe IOCTL-e alokacji, zwalniania i zmiany ochrony.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

Ładowanie PDB odczytuje katalog debugowania PE każdego modułu zdalnego, wyodrębnia jego identyfikator RSDS, wyszukuje pasujący PDB za pomocą DbgHelp/SymSrv i sprawdza, czy został załadowany jako PDB. Umieść prywatne pliki PDB obok targetu na maszynie przekaźnikowej lub dodaj ich katalog do `_NT_SYMBOL_PATH` na hoście.<sup>[[2]](#references)</sup>

## Zmiany stanu anti-debug obsługiwane przez Kernel

Dostęp do kernela pozwala debuggerowi usuwać wskaźniki, które debugger działający w user-mode nie potrafi niezawodnie ukryć. Wprowadzaj po jednej zmianie naraz, sprawdzaj odpowiednią kontrolę targetu i przywróć powiązany hook przed zakończeniem sesji.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` clears `EPROCESS.DebugPort`.
- `clr_thread_hide` removes `HideFromDebugger` from target threads.
- `ntqsi on` spoofs `NtQuerySystemInformation` class `0x23` (`SystemKernelDebuggerInformation`).
- `spoof on` sprawia, że odczyty `KUSER_SHARED_DATA.KdDebuggerEnabled` w trybie użytkownika zwracają false, podczas gdy stan jądra wymagany przez mechanizm pułapek pozostaje zachowany.
- `stats` sprawdza liczniki hooków oraz zarejestrowany stan `KiDebugRoutine`, `KdpStub` i `KdTrap`.

Te operacje zmieniają stan procesu i jądra. Awaria, nieaktualny inline hook, nieprawidłowy offset struktury lub nieukończone przywracanie patcha mogą destabilizować VM, dlatego migawki i odizolowane środowisko z wymuszonym podpisywaniem sterowników są obowiązkowe.<sup>[[1]](#references)</sup>

## References

- [1] [Repozytorium KernelFlirt i główna dokumentacja](https://github.com/AkaTorich/KernelFlirt)
- [2] [Dokumentacja konsoli KernelFlirt](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
