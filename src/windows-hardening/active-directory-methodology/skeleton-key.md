# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

Die **Skeleton Key-aanval** is ’n tegniek waarmee aanvallers **Active Directory-verifikasie kan omseil** deur ’n **hoofwagwoord** in die LSASS-proses van elke domeinbeheerder te **inject**. Ná die injectie kan die hoofwagwoord (verstek **`mimikatz`**) gebruik word om as **enige domeingebruiker** te verifieer, terwyl hul werklike wagwoorde steeds werk.<sup>[[1]](#references)[[2]](#references)</sup>

Belangrike feite:

- Vereis **Domain Admin/SYSTEM + SeDebugPrivilege** op elke DC en moet **ná elke herlaai weer toegepas word**.<sup>[[2]](#references)</sup>
- Die klassieke Mimikatz-implementering patch **NTLM**- en **Kerberos RC4 (etype 0x17)**-validasiepaaie; AES-only-verifikasie aanvaar nie daardie skeleton-wagwoord deur die RC4-hook nie.<sup>[[2]](#references)</sup>
- Kan konflik veroorsaak met derdeparty-LSA-verifikasiepakkette of bykomende slimkaart-/MFA-verskaffers.<sup>[[2]](#references)</sup>
- Die Mimikatz-module aanvaar die opsionele skakelaar `/letaes` om te voorkom dat Kerberos/AES-hooks geraak word indien daar versoenbaarheidskwessies is.<sup>[[3]](#references)</sup>

### Uitvoering

Klassieke LSASS wat nie deur PPL beskerm word nie:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
As **LSASS as ’n protected process light (PPL)** loop, word user-mode debug access geblokkeer. Die historiese Mimikatz-prosedure hieronder laai sy kernel driver en verwyder beskerming voordat dit LSASS patch. Credential Guard is ’n afsonderlike isolasiebeheer en moet nie as ’n sinoniem vir PPL gebruik word nie.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Na inspuiting, authentiseer met enige domeinrekening, maar gebruik die wagwoord `mimikatz` (of die waarde wat deur die operator gestel is). Onthou om dit op **alle DCs** in multi-DC-omgewings te herhaal.

## Versagtings

- **Logmonitering**
- Stelsel-**Event ID 7045** (diens-/drywerinstallasie) vir ongetekende drywers soos `mimidrv.sys`.
- **Sysmon**: Event ID 7 (drywerlaai) vir `mimidrv.sys`; Event ID 10 vir verdagte toegang tot `lsass.exe` vanaf nie-stelselprosesse.
- Sekuriteit-**Event ID 4673/4611** vir die gebruik van sensitiewe regte of afwykings in die registrasie van LSA-verifikasiepakkette; korreleer dit met onverwagte 4624-aanmeldings wat RC4 (etype 0x17) vanaf DCs gebruik.
- **Versterking van LSASS**
- Hou **RunAsPPL** en **Credential Guard** geaktiveer waar dit ondersteun word. Hulle bied verskillende beskermings, en verhoog saam die koste en telemetrie van pogings om LSASS-geheime te wysig of te onttrek.<sup>[[4]](#references)</sup>
- Deaktiveer verouderde **RC4** waar moontlik; Kerberos-tickets wat tot AES beperk is, voorkom die RC4-hook-pad wat deur die skeleton key gebruik word.<sup>[[2]](#references)</sup>
- Vinnige PowerShell-soektogte:
- Bespeur ongetekende kernel-drywerinstallasies: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Soek na Mimikatz-drywer: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Bevestig dat PPL ná herlaai afgedwing word: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Vir bykomende leiding oor credential-hardening, raadpleeg [Windows-beskerming van credentials](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Skeleton Key-aanval in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton-module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Stel bykomende LSA-beskerming op](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
