# LPE przez propagację wpisów rejestru ułatwień dostępu Secure Desktop (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Omówienie

Funkcje ułatwień dostępu systemu Windows przechowują konfigurację użytkownika w HKCU i propagują ją do lokalizacji HKLM dla poszczególnych sesji. Podczas przejścia do **Secure Desktop** (ekran blokady lub monit UAC) komponenty działające jako **SYSTEM** ponownie kopiują te wartości. Jeśli **klucz HKLM dla danej sesji jest zapisywalny przez użytkownika**, staje się uprzywilejowanym punktem zapisu, który można przekierować za pomocą **symbolicznych dowiązań rejestru**, uzyskując **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

Technika RegPwn wykorzystuje ten łańcuch propagacji wraz z niewielkim oknem czasowym, stabilizowanym za pomocą **opportunistic lock (oplock)** na pliku używanym przez `osk.exe`.<sup>[[1]](#references)</sup>

## Łańcuch propagacji rejestru (Accessibility -> Secure Desktop)

Przykładowa funkcja: **On-Screen Keyboard** (`osk`). Istotne lokalizacje:

- **Lista funkcji obejmująca cały system**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Konfiguracja dla użytkownika (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Konfiguracja HKLM dla danej sesji (tworzona przez `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (kontekst SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagacja podczas przejścia do secure desktop (w uproszczeniu):

1. **User `atbroker.exe`** kopiuje `HKCU\...\ATConfig\osk` do `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** kopiuje `HKLM\...\Session<session id>\ATConfig\osk` do `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** kopiuje `HKU\.DEFAULT\...\ATConfig\osk` z powrotem do `HKLM\...\Session<session id>\ATConfig\osk`.

Jeśli poddrzewo HKLM sesji jest zapisywalne przez użytkownika, kroki 2/3 zapewniają zapis jako SYSTEM za pośrednictwem lokalizacji, którą użytkownik może zastąpić.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write przez Registry Links

Zastąp zapisywalny przez użytkownika klucz dla danej sesji **symbolicznym dowiązaniem rejestru**, które wskazuje na wybraną przez atakującego lokalizację docelową. Gdy nastąpi kopiowanie przez SYSTEM, dowiązanie zostanie użyte, a wartości kontrolowane przez atakującego zostaną zapisane w dowolnym docelowym kluczu.

Najważniejsza idea:

- Cel zapisu ofiary (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Atakujący zastępuje ten klucz **registry link** wskazującym dowolny inny klucz.
- SYSTEM wykonuje kopiowanie i zapisuje dane w wybranym przez atakującego kluczu z uprawnieniami SYSTEM.

Zapewnia to primitive **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

## Wygrywanie Race Window za pomocą Oplocks

Pomiędzy uruchomieniem **SYSTEM `osk.exe`** a zapisem klucza dla danej sesji istnieje krótkie okno czasowe. Aby zapewnić niezawodność, exploit zakłada **oplock** na:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Gdy uruchamia się oplock, attacker zamienia klucz HKLM dla danej sesji na registry link, pozwala na zapis SYSTEM, a następnie usuwa link.<sup>[[1]](#references)</sup>

## Przykładowy przebieg exploitation (ogólny)

1. Pobierz bieżący **session ID** z access token.
2. Uruchom ukrytą instancję `osk.exe` i odczekaj chwilę (aby zapewnić uruchomienie oplock).
3. Zapisz wartości kontrolowane przez attackera w:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Ustaw **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Uruchom **Secure Desktop** (`LockWorkstation()`), powodując uruchomienie `atbroker.exe` / `osk.exe` przez SYSTEM.
6. Po uruchomieniu oplock zastąp `HKLM\...\Session<session id>\ATConfig\osk` przez **registry link** wskazujący dowolny target.
7. Odczekaj chwilę na zakończenie kopiowania przez SYSTEM, a następnie usuń link.<sup>[[1]](#references)</sup>

## Konwersja primitive do wykonania kodu jako SYSTEM

Jednym z prostych chainów jest nadpisanie wartości **service configuration** (np. `ImagePath`), a następnie uruchomienie usługi. RegPwn PoC nadpisuje `ImagePath` usługi **`msiserver`** i uruchamia ją przez utworzenie instancji **obiektu COM MSI**, co skutkuje wykonaniem kodu jako **SYSTEM**.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Powiązane

Informacje o innych zachowaniach Secure Desktop / UIAccess znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
