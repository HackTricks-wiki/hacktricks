# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Aanval

Die **Skeleton Key aanval** is 'n gesofistikeerde tegniek wat aanvallers in staat stel om **Active Directory-outeentifikasie te omseil** deur 'n **meesterwagwoord** in die domeinbeheerder in te spuit. Dit stel die aanvaller in staat om **as enige gebruiker te autentiseer** sonder hul wagwoord, wat effektief **onbeperkte toegang** tot die domein verleen.

Dit kan uitgevoer word met [Mimikatz](https://github.com/gentilkiwi/mimikatz). Om hierdie aanval uit te voer, is **Domein Admin-regte 'n voorvereiste**, en die aanvaller moet elke domeinbeheerder teiken om 'n omvattende oortreding te verseker. Die effek van die aanval is egter tydelik, aangesien **herbegin van die domeinbeheerder die malware uitwis**, wat 'n herimplementering vir volgehoue toegang vereis.

**Die aanval uitvoer** vereis 'n enkele opdrag: `misc::skeleton`.

## Versagtings

Versagtingsstrategieë teen sulke aanvalle sluit in om spesifieke gebeurtenis-ID's te monitor wat die installasie van dienste of die gebruik van sensitiewe voorregte aandui. Spesifiek, om te kyk vir Stelsels Gebeurtenis ID 7045 of Sekuriteit Gebeurtenis ID 4673 kan verdagte aktiwiteite onthul. Boonop kan die uitvoering van `lsass.exe` as 'n beskermde proses die aanvallers se pogings aansienlik bemoeilik, aangesien dit vereis dat hulle 'n kernmodus bestuurder gebruik, wat die kompleksiteit van die aanval verhoog.

Hier is die PowerShell-opdragte om sekuriteitsmaatreëls te verbeter:

- Om die installasie van verdagte dienste te detecteer, gebruik: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Spesifiek, om Mimikatz se bestuurder te detecteer, kan die volgende opdrag gebruik word: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Om `lsass.exe` te versterk, word dit aanbeveel om dit as 'n beskermde proses in te stel: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Verifikasie na 'n stelsels herbegin is van kardinale belang om te verseker dat die beskermende maatreëls suksesvol toegepas is. Dit kan bereik word deur: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Verwysings

- [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{{#include ../../banners/hacktricks-training.md}}
