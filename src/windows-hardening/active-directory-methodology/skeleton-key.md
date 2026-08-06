# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** ni technique inayowawezesha attackers **kupita authentication ya Active Directory** kwa **kuingiza master password** kwenye process ya LSASS ya kila domain controller. Baada ya kuingizwa, master password (default **`mimikatz`**) inaweza kutumika ku-authenticate kama **mtumiaji yeyote wa domain**, huku passwords zao halisi zikiendelea kufanya kazi.<sup>[[1]](#references)[[2]](#references)</sup>

Mambo muhimu:

- Inahitaji **Domain Admin/SYSTEM + SeDebugPrivilege** kwenye kila DC na lazima **itekelezwe tena baada ya kila reboot**.<sup>[[2]](#references)</sup>
- Hupatch njia za validation za **NTLM** na **Kerberos RC4 (etype 0x17)**; realms za AES pekee au accounts zinazolazimisha AES **hazitakubali skeleton key**.<sup>[[2]](#references)</sup>
- Inaweza kugongana na third-party LSA authentication packages au providers wa ziada wa smart-card / MFA.<sup>[[2]](#references)</sup>
- Mimikatz module inakubali switch ya hiari `/letaes` ili kuepuka kugusa Kerberos/AES hooks iwapo kuna matatizo ya compatibility.<sup>[[3]](#references)</sup>

### Utekelezaji

Classic, LSASS isiyolindwa na PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Ikiwa **LSASS inaendeshwa kama PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), kernel driver inahitajika kuondoa protection kabla ya kupatch LSASS:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Baada ya injection, authenticate kwa kutumia account yoyote ya domain lakini tumia password `mimikatz` (au value iliyowekwa na operator). Kumbuka kurudia kwenye **DCs zote** katika mazingira yenye DC nyingi.

## Hatua za kupunguza athari

- **Ufuatiliaji wa logs**
- **Event ID 7045** ya System (service/driver install) kwa drivers ambazo hazijasainiwa kama `mimidrv.sys`.
- **Sysmon**: Event ID 7 (driver load) kwa `mimidrv.sys`; Event ID 10 kwa access ya kutiliwa shaka kwenye `lsass.exe` kutoka kwa processes zisizo za system.
- **Event ID 4673/4611** ya Security kwa matumizi ya sensitive privileges au anomalies za usajili wa LSA authentication package; correlate na logons za 4624 zisizotarajiwa zinazotumia RC4 (etype 0x17) kutoka kwa DCs.
- **Kuimarisha LSASS**
- Weka **RunAsPPL/Credential Guard/Secure LSASS** ikiwa enabled kwenye DCs ili kuwalazimisha attackers kutumia kernel-mode driver deployment (telemetry zaidi, exploitation ngumu zaidi).
- Disable legacy **RC4** inapowezekana; Kerberos tickets zinazotumia AES pekee huzuia RC4 hook path inayotumiwa na skeleton key.<sup>[[2]](#references)</sup>
- PowerShell hunts za haraka:
- Detect installs za unsigned kernel drivers: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Hunt kwa Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Validate kwamba PPL inatekelezwa baada ya reboot: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Kwa mwongozo wa ziada kuhusu credential-hardening, angalia [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## Marejeo

- [1] [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
