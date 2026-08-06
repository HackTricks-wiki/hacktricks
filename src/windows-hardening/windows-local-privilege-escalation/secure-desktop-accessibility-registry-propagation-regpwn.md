# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Funkcje ułatwień dostępu systemu Windows przechowują konfigurację użytkownika w HKCU i propagują ją do lokalizacji HKLM właściwych dla danej sesji. Podczas przejścia do **Secure Desktop** (ekran blokady lub monit UAC) komponenty działające jako **SYSTEM** ponownie kopiują te wartości. Jeśli **klucz HKLM właściwy dla sesji jest zapisywalny przez użytkownika**, staje się uprzywilejowanym punktem zapisu, który można przekierować za pomocą **symbolicznych dowiązań rejestru**, uzyskując **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

Technika RegPwn wykorzystuje ten łańcuch propagacji za pomocą niewielkiego okna wyścigu, stabilizowanego przez **opportunistic lock (oplock)** na pliku używanym przez `osk.exe`.<sup>[[1]](#references)</sup>

## Łańcuch propagacji rejestru (Accessibility -> Secure Desktop)

Przykładowa funkcja: **On-Screen Keyboard** (`osk`). Odpowiednie lokalizacje to:

- **Systemowa lista funkcji**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Konfiguracja użytkownika (zapisywalna przez użytkownika)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Konfiguracja HKLM właściwa dla sesji (tworzona przez `winlogon.exe`, zapisywalna przez użytkownika)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (kontekst SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagacja podczas przejścia do secure desktop (uproszczona):

1. **Użytkownik `atbroker.exe`** kopiuje `HKCU\...\ATConfig\osk` do `HKLM\...\Session<session id>\ATConfig\osk`.
2. **`atbroker.exe` działający jako SYSTEM** kopiuje `HKLM\...\Session<session id>\ATConfig\osk` do `HKU\.DEFAULT\...\ATConfig\osk`.
3. **`osk.exe` działający jako SYSTEM** kopiuje `HKU\.DEFAULT\...\ATConfig\osk` z powrotem do `HKLM\...\Session<session id>\ATConfig\osk`.

Jeśli poddrzewo HKLM sesji jest zapisywalne przez użytkownika, kroki 2/3 zapewniają zapis wykonywany jako SYSTEM za pośrednictwem lokalizacji, którą użytkownik może zastąpić.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Zastąp zapisywalny przez użytkownika klucz właściwy dla sesji **symbolicznym dowiązaniem rejestru**, które wskazuje na wybrane przez attackera miejsce docelowe. Gdy nastąpi kopiowanie wykonywane jako SYSTEM, dowiązanie zostanie użyte, a kontrolowane przez attackera wartości zostaną zapisane w dowolnym docelowym kluczu.

Najważniejsza idea:

- Cel zapisu ofiary (zapisywalny przez użytkownika):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker zastępuje ten klucz **registry link** wskazującym na dowolny inny klucz.
- SYSTEM wykonuje kopiowanie i zapisuje dane w wybranym przez attackera kluczu z uprawnieniami SYSTEM.

Zapewnia to primitive **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

## Wygrywanie okna wyścigu za pomocą Oplocks

Pomiędzy uruchomieniem **`osk.exe` działającym jako SYSTEM** a zapisem klucza właściwego dla sesji występuje krótkie okno czasowe. Aby exploit działał niezawodnie, umieszcza **oplock** na:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Gdy uruchamia się oplock, attacker zamienia klucz HKLM dla danej sesji na registry link, pozwala, aby zapis wykonany przez SYSTEM został zrealizowany, a następnie usuwa link.<sup>[[1]](#references)</sup>

## Przykładowy przebieg exploitation (zarys)

1. Pobierz bieżący **session ID** z access token.
2. Uruchom ukrytą instancję `osk.exe` i odczekaj krótko (aby upewnić się, że oplock się uruchomi).
3. Zapisz wartości kontrolowane przez attackera do:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Ustaw **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Uruchom **Secure Desktop** (`LockWorkstation()`), co spowoduje uruchomienie `atbroker.exe` / `osk.exe` przez SYSTEM.
6. Po uruchomieniu oplock zamień `HKLM\...\Session<session id>\ATConfig\osk` na **registry link** wskazujący dowolny cel.
7. Odczekaj krótko na zakończenie kopiowania przez SYSTEM, a następnie usuń link.<sup>[[1]](#references)</sup>

## Konwersja primitive do wykonania kodu jako SYSTEM

Jednym z prostych chainów jest nadpisanie wartości **service configuration** (np. `ImagePath`), a następnie uruchomienie usługi. RegPwn PoC nadpisuje `ImagePath` usługi **`msiserver`** i uruchamia ją przez utworzenie instancji **MSI COM object**, co prowadzi do wykonania kodu jako **SYSTEM**.<sup>[[1]](#references)[[2]](#references)</sup>

## Powiązane

Inne zachowania Secure Desktop / UIAccess opisano tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Referencje

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
