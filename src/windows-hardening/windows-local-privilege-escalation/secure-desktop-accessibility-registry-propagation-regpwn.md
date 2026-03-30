# Secure Desktop Propagacja rejestru Ułatwień dostępu LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Funkcje Accessibility w Windows zapisują konfigurację użytkownika pod HKCU i propagują ją do lokalizacji HKLM przypisanych do sesji. Podczas przejścia na **Secure Desktop** (ekran blokady lub monit UAC) komponenty działające jako **SYSTEM** ponownie kopiują te wartości. Jeśli **klucz HKLM specyficzny dla sesji jest zapisywalny przez użytkownika**, staje się punktem węzłowym zapisu z uprzywilejowaniami, który można przekierować za pomocą **symbolicznych linków rejestru**, co daje możliwość **dowolnego zapisu rejestru jako SYSTEM**.

Technika RegPwn wykorzystuje ów łańcuch propagacji z niewielkim oknem wyścigu, stabilizowanym przez **opportunistic lock (oplock)** na pliku używanym przez `osk.exe`.

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Przykładowa funkcja: **On-Screen Keyboard** (`osk`). Istotne lokacje to:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagacja podczas przejścia na secure desktop (uproszczone):

1. **Proces `atbroker.exe` uruchomiony przez użytkownika** kopiuje `HKCU\...\ATConfig\osk` do `HKLM\...\Session<session id>\ATConfig\osk`.
2. **Proces `atbroker.exe` działający jako SYSTEM** kopiuje `HKLM\...\Session<session id>\ATConfig\osk` do `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** kopiuje `HKU\.DEFAULT\...\ATConfig\osk` z powrotem do `HKLM\...\Session<session id>\ATConfig\osk`.

Jeśli poddrzewo HKLM dla sesji jest zapisywalne przez użytkownika, kroki 2/3 dostarczają zapisu jako SYSTEM przez lokalizację, którą użytkownik może zastąpić.

## Prymityw: Dowolny zapis rejestru jako SYSTEM za pomocą linków rejestru

Zastąp klucz per-session zapisywalny przez użytkownika **symbolicznym linkiem rejestru**, który wskazuje na cel wybrany przez atakującego. Gdy kopiowanie wykonywane przez SYSTEM nastąpi, podąży ono za linkiem i zapisze wartości kontrolowane przez atakującego w dowolnym docelowym kluczu.

Kluczowa idea:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker replaces that key with a **registry link** to any other key.
- SYSTEM performs the copy and writes into the attacker-chosen key with SYSTEM permissions.

To daje prymityw umożliwiający **dowolny zapis rejestru jako SYSTEM**.

## Wygranie okna wyścigu za pomocą oplocków

Istnieje krótkie okno czasowe między uruchomieniem **SYSTEM `osk.exe`** a zapisem klucza per-session. Aby to uczynić niezawodnym, exploit umieszcza **oplock** na:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Gdy oplock zostanie wyzwolony, atakujący podmienia przypisany do sesji klucz HKLM na registry link, pozwala SYSTEMowi zapisać dane, a następnie usuwa link.

## Przykładowy przebieg eksploitacji (wysoki poziom)

1. Pobierz bieżące **session ID** z access tokena.
2. Uruchom ukrytą instancję `osk.exe` i krótko poczekaj (upewnij się, że oplock zostanie wyzwolony).
3. Zapisz wartości kontrolowane przez atakującego do:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Ustaw **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Wywołaj **Secure Desktop** (`LockWorkstation()`), powodując uruchomienie SYSTEM `atbroker.exe` / `osk.exe`.
6. Gdy oplock zostanie wyzwolony, zastąp `HKLM\...\Session<session id>\ATConfig\osk` **registry link** wskazujący na dowolny cel.
7. Poczekaj krótko, aż kopia wykonana przez SYSTEM się zakończy, a następnie usuń link.

## Zamiana prymitywu na wykonanie jako SYSTEM

Jednym prostym łańcuchem jest nadpisanie wartości **service configuration** (np. `ImagePath`), a następnie uruchomienie usługi. RegPwn PoC nadpisuje `ImagePath` **`msiserver`** i wywołuje ją przez instancjonowanie **MSI COM object**, skutkując wykonaniem kodu jako **SYSTEM**.

## Powiązane

Aby zobaczyć inne zachowania Secure Desktop / UIAccess, zobacz:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
