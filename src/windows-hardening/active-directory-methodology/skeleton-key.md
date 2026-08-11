# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** ni mbinu inayowaruhusu washambuliaji **kukwepa uthibitishaji wa Active Directory** kwa **kuingiza nenosiri kuu** kwenye mchakato wa LSASS wa kila domain controller. Baada ya kuingizwa, nenosiri kuu (chaguo-msingi **`mimikatz`**) linaweza kutumiwa kuthibitisha utambulisho kama **mtumiaji yeyote wa domain**, huku manenosiri yao halisi yakiendelea kufanya kazi.<sup>[[1]](#references)[[2]](#references)</sup>

Mambo muhimu:

- Inahitaji **Domain Admin/SYSTEM + SeDebugPrivilege** kwenye kila DC na lazima **itekelezwe tena baada ya kila kuwasha upya**.<sup>[[2]](#references)</sup>
- Utekelezaji wa kawaida wa Mimikatz hubadilisha njia za uthibitishaji za **NTLM** na **Kerberos RC4 (etype 0x17)**; uthibitishaji wa AES pekee **haukubali nenosiri hilo la skeleton kupitia RC4 hook**.<sup>[[2]](#references)</sup>
- Inaweza kukinzana na third‑party LSA authentication packages au watoa huduma wa ziada wa smart‑card / MFA.<sup>[[2]](#references)</sup>
- Moduli ya Mimikatz inakubali switch ya hiari `/letaes` ili kuepuka kugusa Kerberos/AES hooks endapo kutakuwa na matatizo ya uoanifu.<sup>[[3]](#references)</sup>

### Execution

LSASS ya kawaida, isiyolindwa na PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Ikiwa **LSASS inaendeshwa kama protected process light (PPL)**, user-mode debug access huzuiwa. Utaratibu wa kihistoria wa Mimikatz ulio hapa chini hupakia kernel driver yake na kuondoa protection kabla ya kufanya patch LSASS. Credential Guard ni isolation control tofauti na haipaswi kutumiwa kama kisawe cha PPL.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Baada ya injection, authenticate kwa kutumia akaunti yoyote ya domain lakini tumia password `mimikatz` (au thamani iliyowekwa na operator). Kumbuka kurudia kwenye **DCs zote** katika mazingira yenye DC nyingi.

## Mitigations

- **Ufuatiliaji wa log**
- **Event ID 7045** ya System (usakinishaji wa service/driver) kwa drivers zisizosainiwa kama `mimidrv.sys`.
- **Sysmon**: Event ID 7 (upakiaji wa driver) kwa `mimidrv.sys`; Event ID 10 kwa access yenye mashaka kwa `lsass.exe` kutoka kwa processes zisizo za system.
- **Event ID 4673/4611** ya Security kwa matumizi ya privilege nyeti au anomalies za usajili wa LSA authentication package; correlate na logons za 4624 zisizotarajiwa zinazotumia RC4 (etype 0x17) kutoka kwa DCs.
- **Kufanya LSASS iwe hardened**
- Weka **RunAsPPL** na **Credential Guard** zikiwa enabled pale zinapoungwa mkono. Zinatoa protections tofauti, na kwa pamoja huongeza gharama na telemetry ya majaribio ya kurekebisha au kutoa secrets za LSASS.<sup>[[4]](#references)</sup>
- Disable **RC4** ya zamani inapowezekana; Kerberos tickets zinazotumia AES pekee huzuia RC4 hook path inayotumiwa na skeleton key.<sup>[[2]](#references)</sup>
- PowerShell hunts za haraka:
- Detect usakinishaji wa unsigned kernel driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Hunt kwa Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Thibitisha kuwa PPL inatekelezwa baada ya reboot: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Kwa mwongozo wa ziada wa credential-hardening, angalia [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Skeleton Key attack katika Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
