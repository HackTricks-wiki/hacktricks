# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key napad** je sofisticirana tehnika koja omogućava napadačima da **obiđu Active Directory autentifikaciju** tako što **ubacuju glavnu lozinku** u kontroler domena. Ovo omogućava napadaču da **autentifikuje kao bilo koji korisnik** bez njihove lozinke, efektivno **dajući im neograničen pristup** domenu.

Može se izvesti korišćenjem [Mimikatz](https://github.com/gentilkiwi/mimikatz). Da bi se izveo ovaj napad, **prava Domain Admin su preduslov**, a napadač mora ciljati svaki kontroler domena kako bi osigurao sveobuhvatan proboj. Međutim, efekat napada je privremen, jer **ponovno pokretanje kontrolera domena eliminiše malver**, što zahteva ponovnu implementaciju za trajni pristup.

**Izvršavanje napada** zahteva jednu komandu: `misc::skeleton`.

## Mitigations

Strategije ublažavanja protiv ovakvih napada uključuju praćenje specifičnih ID-eva događaja koji ukazuju na instalaciju usluga ili korišćenje osetljivih privilegija. Konkretno, praćenje System Event ID 7045 ili Security Event ID 4673 može otkriti sumnjive aktivnosti. Pored toga, pokretanje `lsass.exe` kao zaštićenog procesa može značajno otežati napadačima, jer to zahteva korišćenje drajvera u kernel modu, povećavajući složenost napada.

Evo PowerShell komandi za poboljšanje bezbednosnih mera:

- Da biste otkrili instalaciju sumnjivih usluga, koristite: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Konkretno, da biste otkrili Mimikatz-ov drajver, može se koristiti sledeća komanda: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Da biste ojačali `lsass.exe`, preporučuje se da ga omogućite kao zaštićen proces: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Verifikacija nakon ponovnog pokretanja sistema je ključna kako bi se osiguralo da su zaštitne mere uspešno primenjene. Ovo se može postići kroz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References

- [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{{#include ../../banners/hacktricks-training.md}}
