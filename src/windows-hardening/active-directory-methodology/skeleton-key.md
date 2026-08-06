# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

Die **Skeleton Key-aanval** is 'n tegniek waarmee aanvallers **Active Directory-verifikasie kan omseil** deur 'n **meesterwagwoord** in die LSASS-proses van elke domeinbeheerder **te inject**. Ná injection kan die meesterwagwoord (verstek **`mimikatz`**) gebruik word om as **enige domeingebruiker** te authenticateer, terwyl hul werklike wagwoorde steeds werk.<sup>[[1]](#references)[[2]](#references)</sup>

Sleutelfeite:

- Vereis **Domain Admin/SYSTEM + SeDebugPrivilege** op elke DC en moet **ná elke herlaai weer toegepas word**.<sup>[[2]](#references)</sup>
- Patch **NTLM**- en **Kerberos RC4 (etype 0x17)**-validasiepaadjies; AES-only realms of rekeninge wat AES afdwing, sal **nie die skeleton key aanvaar nie**.<sup>[[2]](#references)</sup>
- Kan konflik veroorsaak met derdeparty-LSA-authentication packages of addisionele smart-card- / MFA-providers.<sup>[[2]](#references)</sup>
- Die Mimikatz-module aanvaar die opsionele skakelaar `/letaes` om te voorkom dat daar aan Kerberos/AES-hooks geraak word in geval van compatibility-probleme.<sup>[[3]](#references)</sup>

### Uitvoering

Klassieke LSASS wat nie deur PPL beskerm word nie:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Indien **LSASS as PPL** loop (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), is ’n kernel driver nodig om beskerming te verwyder voordat LSASS gepatch word:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Na injection, autentiseer met enige domeinrekening, maar gebruik die wagwoord `mimikatz` (of die waarde wat deur die operator gestel is). Onthou om dit in multi-DC-omgewings op **alle DCs** te herhaal.

## Versagtingsmaatreëls

- **Logmonitering**
- System **Event ID 7045** (diens-/drywerinstallasie) vir ongetekende drywers soos `mimidrv.sys`.
- **Sysmon**: Event ID 7 (drywerlaai) vir `mimidrv.sys`; Event ID 10 vir verdagte toegang tot `lsass.exe` vanaf nie-stelselprosesse.
- Security **Event ID 4673/4611** vir sensitiewe voorreggebruik of anomalieë met LSA-authentication package-registrasie; korreleer dit met onverwagte 4624-logons wat RC4 (etype 0x17) vanaf DCs gebruik.
- **Verharding van LSASS**
- Hou **RunAsPPL/Credential Guard/Secure LSASS** op DCs geaktiveer om attackers te dwing om kernel-mode driver deployment te gebruik (meer telemetrie, moeiliker exploitation).
- Deaktiveer legacy **RC4** waar moontlik; Kerberos-tickets wat tot AES beperk is, voorkom die RC4-hook path wat deur die skeleton key gebruik word.<sup>[[2]](#references)</sup>
- Vinnige PowerShell-hunts:
- Bespeur installasies van ongetekende kernel-drivers: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Soek na Mimikatz-driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Bevestig dat PPL ná herlaai afgedwing word: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Vir bykomende leiding oor credential-hardening, kyk na [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## Verwysings

- [1] [Netwrix – Skeleton Key-aanval in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton-module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
