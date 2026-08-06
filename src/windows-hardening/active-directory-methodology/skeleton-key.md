# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** to technika, która pozwala atakującym **ominąć uwierzytelnianie Active Directory** poprzez **wstrzyknięcie hasła głównego** do procesu LSASS każdego kontrolera domeny. Po wstrzyknięciu hasło główne (domyślnie **`mimikatz`**) może służyć do uwierzytelniania jako **dowolny użytkownik domeny**, podczas gdy ich rzeczywiste hasła nadal działają.<sup>[[1]](#references)[[2]](#references)</sup>

Najważniejsze fakty:

- Wymaga uprawnień **Domain Admin/SYSTEM + SeDebugPrivilege** na każdym DC i musi zostać **zastosowane ponownie po każdym ponownym uruchomieniu**.<sup>[[2]](#references)</sup>
- Modyfikuje ścieżki walidacji **NTLM** i **Kerberos RC4 (etype 0x17)**; realm lub konta używające wyłącznie AES albo wymuszające AES **nie zaakceptują skeleton key**.<sup>[[2]](#references)</sup>
- Może powodować konflikty z zewnętrznymi pakietami uwierzytelniania LSA lub dodatkowymi dostawcami uwierzytelniania za pomocą kart inteligentnych / MFA.<sup>[[2]](#references)</sup>
- Moduł Mimikatz akceptuje opcjonalny przełącznik `/letaes`, aby uniknąć modyfikowania hooków Kerberos/AES w przypadku problemów ze zgodnością.<sup>[[3]](#references)</sup>

### Execution

Klasyczny LSASS chroniony bez PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Jeśli **LSASS działa jako PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), przed patchowaniem LSASS wymagany jest sterownik jądra:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Po injection authenticate with any domain account but use password `mimikatz` (or the value set by the operator). Remember to repeat on **all DCs** in multi‑DC environments.

## Środki zaradcze

- **Monitorowanie logów**
- Systemowy **Event ID 7045** (instalacja usługi/sterownika) dla niepodpisanych sterowników, takich jak `mimidrv.sys`.
- **Sysmon**: Event ID 7 (ładowanie sterownika) dla `mimidrv.sys`; Event ID 10 dla podejrzanego dostępu do `lsass.exe` z procesów niesystemowych.
- Security **Event ID 4673/4611** w przypadku użycia wrażliwych uprawnień lub anomalii związanych z rejestracją pakietu uwierzytelniania LSA; skoreluj je z nieoczekiwanymi logowaniami 4624 przy użyciu RC4 (etype 0x17) z DCs.
- **Hardening LSASS**
- Utrzymuj włączone **RunAsPPL/Credential Guard/Secure LSASS** na DCs, aby zmusić attackerów do wdrażania sterowników w trybie kernel-mode (więcej telemetry, trudniejsze exploitation).
- Wyłącz starsze **RC4**, jeśli to możliwe; bilety Kerberos ograniczone do AES uniemożliwiają użycie ścieżki hooka RC4 wykorzystywanej przez skeleton key.<sup>[[2]](#references)</sup>
- Szybkie wyszukiwania PowerShell:
- Wykrywanie instalacji niepodpisanych sterowników kernel-mode: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Wyszukiwanie sterownika Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Weryfikacja, czy PPL jest wymuszane po restarcie: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Dodatkowe wskazówki dotyczące hardeningu poświadczeń znajdziesz w [ochronie poświadczeń Windows](../stealing-credentials/credentials-protections.md).

## Referencje

- [1] [Netwrix – atak Skeleton Key w Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – moduł Mimikatz misc::skeleton](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
