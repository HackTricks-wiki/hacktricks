# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** ni mbinu inayomruhusu mshambuliaji **kupitisha uthibitishaji wa Active Directory** kwa **kuingiza nenosiri kuu** ndani ya mchakato wa LSASS wa kila domain controller. Baada ya kuingizwa, nenosiri kuu (chaguo‑msingi **`mimikatz`**) unaweza kutumika kujiuthibitisha kama **mtumiaji wa domain yeyote** huku nywila zao halisi zikibaki kufanya kazi.

Key facts:

- Inahitaji **Domain Admin/SYSTEM + SeDebugPrivilege** kwenye kila DC na lazima **iwekwe tena baada ya kila kuanzishwa upya**.
- Inarekebisha njia za uthibitishaji za **NTLM** na **Kerberos RC4 (etype 0x17)**; realms zinazotumia **AES** pekee au akaunti zinazolazimisha AES **hazitakubali skeleton key**.
- Inaweza kuleta mgongano na vifurushi vya uthibitishaji vya **LSA** vya wahusika wa tatu au watoa huduma wa **smart‑card / MFA** za ziada.
- Moduli ya **Mimikatz** inakubali switch hiari `/letaes` ili kuepuka kugusa Kerberos/AES hooks iwapo kuna masuala ya muendano.

### Execution

Kawaida, LSASS isiyo na ulinzi wa PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Ikiwa **LSASS inafanya kazi kama PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), inahitaji dereva ya kernel ili kuondoa ulinzi kabla ya kuifanyia patch LSASS:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Baada ya injection, thibitisha kwa akaunti yoyote ya domain lakini tumia nenosiri `mimikatz` (au thamani iliyowekwa na msimamizi). Kumbuka kurudia kwenye **DC zote** katika mazingira yenye DC nyingi.

## Uzuiaji

- **Ufuatiliaji wa logi**
- System **Event ID 7045** (installation ya service/driver) kwa drivers zisizotiwa saini kama `mimidrv.sys`.
- **Sysmon**: Event ID 7 (driver load) kwa `mimidrv.sys`; Event ID 10 kwa ufikiaji wa kushukiwa wa `lsass.exe` kutoka kwa michakato isiyo ya system.
- Security **Event ID 4673/4611** kwa matumizi ya vibali nyeti au kasoro katika usajili wa kifurushi cha uthibitishaji wa LSA; linganisha na logons 4624 zisizotarajiwa zinazotumia RC4 (etype 0x17) kutoka kwa DCs.
- **Kuimarisha LSASS**
- Weka **RunAsPPL/Credential Guard/Secure LSASS** zikiwezeshwa kwenye DCs ili kulazimisha wadukuzi kutumia deployment ya driver ya kernel‑mode (telemetry zaidi, matumizi mabaya magumu zaidi).
- Zima legacy **RC4** inapowezekana; tikiti za Kerberos kufungwa kwa AES kunazuia njia ya hook ya RC4 inayotumiwa na skeleton key.
- Uchunguzi wa PowerShell wa haraka:
- Gundua usakinishaji wa driver za kernel zisizotiwa saini: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Tafuta driver ya Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Thibitisha PPL inatekelezwa baada ya kuanzisha upya: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Kwa mwongozo zaidi wa kuimarisha credentials angalia [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
