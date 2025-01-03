# Windows Credentials Protections

## Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Protokali ya [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), iliyoanzishwa na Windows XP, imeundwa kwa ajili ya uthibitishaji kupitia Protokali ya HTTP na **imewezeshwa kwa default kwenye Windows XP hadi Windows 8.0 na Windows Server 2003 hadi Windows Server 2012**. Mpangilio huu wa default unapelekea **hifadhi ya nywila katika maandiko ya wazi katika LSASS** (Local Security Authority Subsystem Service). Mshambuliaji anaweza kutumia Mimikatz ili **kuchota hizi akidi** kwa kutekeleza:
```bash
sekurlsa::wdigest
```
Ili **kuwasha au kuzima kipengele hiki**, funguo za rejista _**UseLogonCredential**_ na _**Negotiate**_ ndani ya _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ lazima ziwe zimewekwa kuwa "1". Ikiwa funguo hizi **hazipo au zimewekwa kuwa "0"**, WDigest ime **zimwa**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection

Kuanzia na **Windows 8.1**, Microsoft iliboresha usalama wa LSA ili **kuzuia usomaji wa kumbukumbu zisizoidhinishwa au uingizaji wa msimbo na michakato isiyoaminika**. Uboreshaji huu unakwamisha utendaji wa kawaida wa amri kama `mimikatz.exe sekurlsa:logonpasswords`. Ili **kuwezesha ulinzi huu ulioimarishwa**, thamani ya _**RunAsPPL**_ katika _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ inapaswa kubadilishwa kuwa 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Inawezekana kupita ulinzi huu kwa kutumia Mimikatz driver mimidrv.sys:

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**, kipengele ambacho ni cha kipekee kwa **Windows 10 (Enterprise na Education editions)**, kinaongeza usalama wa akiba za mashine kwa kutumia **Virtual Secure Mode (VSM)** na **Virtualization Based Security (VBS)**. Kinatumia nyongeza za virtualisasi za CPU ili kutenga michakato muhimu ndani ya nafasi ya kumbukumbu iliyo salama, mbali na ufikiaji wa mfumo wa uendeshaji mkuu. Kutengwa huku kunahakikisha kwamba hata kernel haiwezi kufikia kumbukumbu katika VSM, kwa ufanisi ikilinda akiba za mashine dhidi ya mashambulizi kama **pass-the-hash**. **Local Security Authority (LSA)** inafanya kazi ndani ya mazingira haya salama kama trustlet, wakati mchakato wa **LSASS** katika mfumo wa uendeshaji mkuu unafanya kazi kama mwasiliani tu na LSA ya VSM.

Kwa kawaida, **Credential Guard** haifanyi kazi na inahitaji kuanzishwa kwa mikono ndani ya shirika. Ni muhimu kwa kuongeza usalama dhidi ya zana kama **Mimikatz**, ambazo zinakabiliwa na uwezo wao wa kutoa akiba za mashine. Hata hivyo, udhaifu bado unaweza kutumika kupitia kuongeza **Security Support Providers (SSP)** za kawaida ili kukamata akiba za mashine katika maandiko wazi wakati wa majaribio ya kuingia.

Ili kuthibitisha hali ya kuanzishwa kwa **Credential Guard**, funguo ya rejista _**LsaCfgFlags**_ chini ya _**HKLM\System\CurrentControlSet\Control\LSA**_ inaweza kukaguliwa. Thamani ya "**1**" inaonyesha kuanzishwa kwa **UEFI lock**, "**2**" bila lock, na "**0**" inaashiria haijaanzishwa. Ukaguzi huu wa rejista, ingawa ni kiashiria kizuri, si hatua pekee ya kuanzisha Credential Guard. Mwongozo wa kina na skripti ya PowerShell ya kuanzisha kipengele hiki zinapatikana mtandaoni.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Kwa ufahamu wa kina na maelekezo juu ya kuwezesha **Credential Guard** katika Windows 10 na uanzishaji wake wa kiotomatiki katika mifumo inayofaa ya **Windows 11 Enterprise na Education (toleo 22H2)**, tembelea [dokumentasiyo ya Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Maelezo zaidi juu ya kutekeleza SSPs za kawaida kwa ajili ya kukamata akidi yanapatikana katika [hiki kiongozi](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 na Windows Server 2012 R2** zilileta vipengele vingi vipya vya usalama, ikiwa ni pamoja na _**Restricted Admin mode kwa RDP**_. Hali hii ilipangwa kuboresha usalama kwa kupunguza hatari zinazohusiana na [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) mashambulizi.

Kawaida, unapounganisha na kompyuta ya mbali kupitia RDP, akidi zako zinahifadhiwa kwenye mashine lengwa. Hii inatoa hatari kubwa ya usalama, hasa unapokuwa ukitumia akaunti zenye mamlaka ya juu. Hata hivyo, kwa kuanzishwa kwa _**Restricted Admin mode**_, hatari hii inapungua kwa kiasi kikubwa.

Wakati wa kuanzisha muunganisho wa RDP kwa kutumia amri **mstsc.exe /RestrictedAdmin**, uthibitishaji wa kompyuta ya mbali unafanywa bila kuhifadhi akidi zako kwenye hiyo. Njia hii inahakikisha kwamba, katika tukio la maambukizi ya programu hasidi au ikiwa mtumiaji mbaya atapata ufikiaji wa seva ya mbali, akidi zako hazitakuwa hatarini, kwani hazihifadhiwi kwenye seva.

Ni muhimu kutambua kwamba katika **Restricted Admin mode**, juhudi za kufikia rasilimali za mtandao kutoka kwenye kikao cha RDP hazitatumia akidi zako binafsi; badala yake, **utambulisho wa mashine** unatumika.

Kipengele hiki kinatoa hatua muhimu mbele katika kulinda muunganisho wa desktop ya mbali na kulinda taarifa nyeti zisifichuliwe katika tukio la uvunjaji wa usalama.

![](../../images/RAM.png)

Kwa maelezo zaidi tembelea [hiki kiungo](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows inalinda **akidi za kikoa** kupitia **Local Security Authority (LSA)**, ikisaidia michakato ya kuingia kwa kutumia itifaki za usalama kama **Kerberos** na **NTLM**. Kipengele muhimu cha Windows ni uwezo wake wa kuhifadhi **kuingia kwa kikoa kumi za mwisho** ili kuhakikisha watumiaji wanaweza bado kufikia kompyuta zao hata kama **kikundi cha kudhibiti kikoa kiko offline**—faida kwa watumiaji wa laptop ambao mara nyingi wako mbali na mtandao wa kampuni yao.

Idadi ya kuingia zilizohifadhiwa inaweza kubadilishwa kupitia **funguo maalum za rejista au sera ya kikundi**. Ili kuona au kubadilisha mipangilio hii, amri ifuatayo inatumika:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Upatikanaji wa hizi akiba za sifa umewekwa kwa udhibiti mkali, ambapo ni akaunti ya **SYSTEM** pekee yenye ruhusa zinazohitajika kuziangalia. Wasimamizi wanaohitaji kufikia taarifa hii lazima wafanye hivyo kwa ruhusa za mtumiaji wa SYSTEM. Sifa zinahifadhiwa katika: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** inaweza kutumika kutoa hizi akiba za sifa kwa kutumia amri `lsadump::cache`.

Kwa maelezo zaidi, chanzo cha asili [source](http://juggernaut.wikidot.com/cached-credentials) kinatoa taarifa kamili.

## Watumiaji Waliohifadhiwa

Uanachama katika **kikundi cha Watumiaji Waliohifadhiwa** unaleta maboresho kadhaa ya usalama kwa watumiaji, kuhakikisha viwango vya juu vya ulinzi dhidi ya wizi wa sifa na matumizi mabaya:

- **Delegation ya Sifa (CredSSP)**: Hata kama mipangilio ya Kundi la Sera kwa **Ruhusu kuhamasisha sifa za kawaida** imewezeshwa, sifa za maandiko wazi za Watumiaji Waliohifadhiwa hazitahifadhiwa.
- **Windows Digest**: Kuanzia **Windows 8.1 na Windows Server 2012 R2**, mfumo hautahifadhi sifa za maandiko wazi za Watumiaji Waliohifadhiwa, bila kujali hali ya Windows Digest.
- **NTLM**: Mfumo hautahifadhi sifa za maandiko wazi za Watumiaji Waliohifadhiwa au kazi za NT moja kwa moja (NTOWF).
- **Kerberos**: Kwa Watumiaji Waliohifadhiwa, uthibitishaji wa Kerberos hautazalisha **DES** au **RC4 keys**, wala hautahifadhi sifa za maandiko wazi au funguo za muda mrefu zaidi ya upatikanaji wa Tiketi ya Kutoa Tiketi (TGT) ya awali.
- **Kuingia Bila Mtandao**: Watumiaji Waliohifadhiwa hawatakuwa na mthibitishaji wa akiba aliyeundwa wakati wa kuingia au kufungua, ikimaanisha kuwa kuingia bila mtandao hakusaidiwi kwa akaunti hizi.

Ulinzi huu unawashwa mara tu mtumiaji, ambaye ni mwanachama wa **kikundi cha Watumiaji Waliohifadhiwa**, anapoingia kwenye kifaa. Hii inahakikisha kuwa hatua muhimu za usalama zipo ili kulinda dhidi ya mbinu mbalimbali za kuathiri sifa.

Kwa maelezo zaidi, angalia [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Jedwali kutoka** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

{{#include ../../banners/hacktricks-training.md}}
