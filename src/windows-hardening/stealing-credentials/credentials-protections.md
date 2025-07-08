# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Protokali ya [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), iliyozinduliwa na Windows XP, imeundwa kwa ajili ya uthibitishaji kupitia Protokali ya HTTP na **imewezeshwa kwa default kwenye Windows XP hadi Windows 8.0 na Windows Server 2003 hadi Windows Server 2012**. Mpangilio huu wa default unapelekea **hifadhi ya nywila za maandiko wazi katika LSASS** (Local Security Authority Subsystem Service). Mshambuliaji anaweza kutumia Mimikatz ili **kuchota hizi akidi** kwa kutekeleza:
```bash
sekurlsa::wdigest
```
Ili **kuwasha au kuzima kipengele hiki**, funguo za rejista _**UseLogonCredential**_ na _**Negotiate**_ ndani ya _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ lazima ziwe zimewekwa kuwa "1". Ikiwa funguo hizi **hazipo au zimewekwa kuwa "0"**, WDigest ime **zimwa**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

**Protected Process (PP)** na **Protected Process Light (PPL)** ni **ulinzi wa kiwango cha kernel cha Windows** ulioanzishwa ili kuzuia ufikiaji usioidhinishwa kwa michakato nyeti kama **LSASS**. Ilianzishwa katika **Windows Vista**, **mfano wa PP** awali ulitengenezwa kwa ajili ya utekelezaji wa **DRM** na iliruhusu tu binaries zilizotiwa saini na **cheti maalum cha media** kulindwa. Mchakato ulioashiriwa kama **PP** unaweza kufikiwa tu na michakato mingine ambayo ni **pia PP** na ina **kiwango sawa au cha juu cha ulinzi**, na hata hivyo, **tu kwa haki za ufikiaji zilizopunguzwa** isipokuwa zimeruhusiwa kwa mahsusi.

**PPL**, iliyoanzishwa katika **Windows 8.1**, ni toleo lenye kubadilika zaidi la PP. Inaruhusu **matumizi mapana** (mfano, LSASS, Defender) kwa kuanzisha **"viwango vya ulinzi"** kulingana na **sehemu ya EKU (Enhanced Key Usage)** ya saini ya kidijitali. Kiwango cha ulinzi kinahifadhiwa katika uwanja wa `EPROCESS.Protection`, ambao ni muundo wa `PS_PROTECTION` wenye:
- **Aina** (`Protected` au `ProtectedLight`)
- **Msigner** (mfano, `WinTcb`, `Lsa`, `Antimalware`, n.k.)

Muundo huu umefungwa katika byte moja na unamua **nani anaweza kufikia nani**:
- **Thamani za msigner za juu zinaweza kufikia za chini**
- **PPLs haziwezi kufikia PPs**
- **Michakato isiyo na ulinzi haiwezi kufikia PPL/PP yoyote**

### Unachohitaji kujua kutoka kwa mtazamo wa mashambulizi

- Wakati **LSASS inafanya kazi kama PPL**, juhudi za kuifungua kwa kutumia `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` kutoka kwa muktadha wa kawaida wa admin **zinashindwa na `0x5 (Access Denied)`**, hata kama `SeDebugPrivilege` imewezeshwa.
- Unaweza **kuangalia kiwango cha ulinzi cha LSASS** kwa kutumia zana kama Process Hacker au kwa njia ya programu kwa kusoma thamani ya `EPROCESS.Protection`.
- LSASS kwa kawaida itakuwa na `PsProtectedSignerLsa-Light` (`0x41`), ambayo inaweza kufikiwa **tu na michakato iliyotiwa saini na msigner wa kiwango cha juu**, kama `WinTcb` (`0x61` au `0x62`).
- PPL ni **kizuizi cha Userland pekee**; **kanuni za kiwango cha kernel zinaweza kuzikwepa kabisa**.
- LSASS kuwa PPL haina **zuia dumping ya akidi ikiwa unaweza kutekeleza shellcode ya kernel** au **kutumia mchakato wa haki za juu wenye ufikiaji sahihi**.
- **Kuweka au kuondoa PPL** kunahitaji kuanzisha upya au **mipangilio ya Secure Boot/UEFI**, ambayo inaweza kudumisha mipangilio ya PPL hata baada ya mabadiliko ya rejista kurudishwa nyuma.

**Chaguzi za kuondoa ulinzi wa PPL:**

Ikiwa unataka kudondoa LSASS licha ya PPL, una chaguzi 3 kuu:
1. **Tumia dereva wa kernel ulio saini (mfano, Mimikatz + mimidrv.sys)** ili **kuondoa bendera ya ulinzi ya LSASS**:

![](../../images/mimidrv.png)

2. **Leta Dereva Yako ya Hatari (BYOVD)** ili kuendesha kanuni maalum ya kernel na kuondoa ulinzi. Zana kama **PPLKiller**, **gdrv-loader**, au **kdmapper** zinafanya hii iwezekane.
3. **Pora kushughulikia LSASS iliyopo** kutoka kwa mchakato mwingine ambao una wazi (mfano, mchakato wa AV), kisha **iga** ndani ya mchakato wako. Hii ndiyo msingi wa mbinu ya `pypykatz live lsa --method handledup`.
4. **Tumia mchakato fulani wa haki** ambao utaruhusu kupakia kanuni yoyote ndani ya nafasi yake ya anwani au ndani ya mchakato mwingine wa haki, kwa ufanisi ukipita vizuizi vya PPL. Unaweza kuangalia mfano wa hii katika [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) au [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Angalia hali ya sasa ya ulinzi wa LSA (PPL/PP) kwa LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- Kwa maelezo zaidi kuhusu hili angalia [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, kipengele ambacho ni maalum kwa **Windows 10 (Enterprise na Education editions)**, kinaongeza usalama wa akiba za mashine kwa kutumia **Virtual Secure Mode (VSM)** na **Virtualization Based Security (VBS)**. Kinatumia nyongeza za virtualisasi za CPU kutenga michakato muhimu ndani ya nafasi ya kumbukumbu iliyo salama, mbali na ufikiaji wa mfumo wa uendeshaji mkuu. Kutengwa huku kunahakikisha kwamba hata kernel haiwezi kufikia kumbukumbu katika VSM, kwa ufanisi ikilinda akiba dhidi ya mashambulizi kama **pass-the-hash**. **Local Security Authority (LSA)** inafanya kazi ndani ya mazingira haya salama kama trustlet, wakati mchakato wa **LSASS** katika OS kuu unafanya kazi kama mwasiliani tu na LSA ya VSM.

Kwa kawaida, **Credential Guard** haifanyi kazi na inahitaji kuamshwa kwa mikono ndani ya shirika. Ni muhimu kwa kuongeza usalama dhidi ya zana kama **Mimikatz**, ambazo zinakabiliwa na uwezo wao wa kutoa akiba. Hata hivyo, udhaifu bado unaweza kutumika kupitia kuongeza **Security Support Providers (SSP)** za kawaida ili kukamata akiba katika maandiko wazi wakati wa majaribio ya kuingia.

Ili kuthibitisha hali ya kuamshwa ya **Credential Guard**, funguo ya rejista _**LsaCfgFlags**_ chini ya _**HKLM\System\CurrentControlSet\Control\LSA**_ inaweza kukaguliwa. Thamani ya "**1**" inaonyesha kuamshwa kwa **UEFI lock**, "**2**" bila lock, na "**0**" inaashiria haijawashwa. Ukaguzi huu wa rejista, ingawa ni kiashiria kizuri, si hatua pekee ya kuamsha Credential Guard. Mwongozo wa kina na skripti ya PowerShell ya kuamsha kipengele hiki zinapatikana mtandaoni.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Kwa ufahamu wa kina na maelekezo juu ya kuwezesha **Credential Guard** katika Windows 10 na uanzishaji wake wa kiotomatiki katika mifumo inayofaa ya **Windows 11 Enterprise na Education (toleo 22H2)**, tembelea [dokumentasiyo ya Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Maelezo zaidi juu ya kutekeleza SSPs za kawaida kwa ajili ya kukamata akidi yanapatikana katika [hiki kiongozi](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 na Windows Server 2012 R2** zilileta vipengele vingi vipya vya usalama, ikiwa ni pamoja na _**Restricted Admin mode kwa RDP**_. Hali hii ilipangwa kuboresha usalama kwa kupunguza hatari zinazohusiana na [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) mashambulizi.

Kawaida, unapounganisha na kompyuta ya mbali kupitia RDP, akidi zako zinahifadhiwa kwenye mashine lengwa. Hii inatoa hatari kubwa ya usalama, hasa unapokuwa ukitumia akaunti zenye mamlaka ya juu. Hata hivyo, kwa kuanzishwa kwa _**Restricted Admin mode**_, hatari hii inapunguzwa kwa kiasi kikubwa.

Wakati wa kuanzisha muunganisho wa RDP kwa kutumia amri **mstsc.exe /RestrictedAdmin**, uthibitishaji wa kompyuta ya mbali unafanywa bila kuhifadhi akidi zako kwenye hiyo. Njia hii inahakikisha kwamba, katika tukio la maambukizi ya programu hasidi au ikiwa mtumiaji mbaya atapata ufikiaji wa seva ya mbali, akidi zako hazitakuwa hatarini, kwani hazihifadhiwa kwenye seva.

Ni muhimu kutambua kwamba katika **Restricted Admin mode**, juhudi za kufikia rasilimali za mtandao kutoka kwenye kikao cha RDP hazitatumia akidi zako binafsi; badala yake, **utambulisho wa mashine** unatumika.

Kipengele hiki kinatoa hatua muhimu mbele katika kulinda muunganisho wa desktop ya mbali na kulinda taarifa nyeti zisifichuliwe katika tukio la uvunjaji wa usalama.

![](../../images/RAM.png)

Kwa maelezo zaidi tembelea [rasilimali hii](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows inalinda **akidi za kikoa** kupitia **Local Security Authority (LSA)**, ikisaidia michakato ya kuingia kwa kutumia itifaki za usalama kama **Kerberos** na **NTLM**. Kipengele muhimu cha Windows ni uwezo wake wa kuhifadhi **kuingia kumi za mwisho za kikoa** ili kuhakikisha watumiaji wanaweza kuendelea kufikia kompyuta zao hata kama **kikundi cha kudhibiti kikoa kiko offline**—faida kwa watumiaji wa laptop ambao mara nyingi wako mbali na mtandao wa kampuni yao.

Idadi ya kuingia zilizohifadhiwa inaweza kubadilishwa kupitia **funguo maalum za rejista au sera ya kikundi**. Ili kuona au kubadilisha mipangilio hii, amri ifuatayo inatumika:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Access to these cached credentials is tightly controlled, with only the **SYSTEM** account having the necessary permissions to view them. Administrators needing to access this information must do so with SYSTEM user privileges. The credentials are stored at: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** can be employed to extract these cached credentials using the command `lsadump::cache`.

For further details, the original [source](http://juggernaut.wikidot.com/cached-credentials) provides comprehensive information.

## Watumiaji Waliohifadhiwa

Uanachama katika **kikundi cha Watumiaji Waliohifadhiwa** unaleta maboresho kadhaa ya usalama kwa watumiaji, kuhakikisha viwango vya juu vya ulinzi dhidi ya wizi na matumizi mabaya ya akidi:

- **Delegation ya Akidi (CredSSP)**: Hata kama mipangilio ya Kundi la Sera ya **Ruhusu kuhamasisha akidi za kawaida** imewezeshwa, akidi za maandiko wazi za Watumiaji Waliohifadhiwa hazitahifadhiwa.
- **Windows Digest**: Kuanzia **Windows 8.1 na Windows Server 2012 R2**, mfumo hautahifadhi akidi za maandiko wazi za Watumiaji Waliohifadhiwa, bila kujali hali ya Windows Digest.
- **NTLM**: Mfumo hautahifadhi akidi za maandiko wazi za Watumiaji Waliohifadhiwa au kazi za NT moja kwa moja (NTOWF).
- **Kerberos**: Kwa Watumiaji Waliohifadhiwa, uthibitishaji wa Kerberos hautazalisha **DES** au **RC4 keys**, wala hautahifadhi akidi za maandiko wazi au funguo za muda mrefu zaidi ya upatikanaji wa Tiketi ya Kutoa Tiketi (TGT) ya awali.
- **Kuingia Bila Mtandao**: Watumiaji Waliohifadhiwa hawatakuwa na mthibitishaji aliyehifadhiwa anayeundwa wakati wa kuingia au kufungua, ikimaanisha kuingia bila mtandao hakusaidiwi kwa akaunti hizi.

Ulinzi huu unawashwa mara tu mtumiaji, ambaye ni mwanachama wa **kikundi cha Watumiaji Waliohifadhiwa**, anapoingia kwenye kifaa. Hii inahakikisha kuwa hatua muhimu za usalama zipo ili kulinda dhidi ya mbinu mbalimbali za kuathiri akidi.

Kwa maelezo zaidi, angalia [nyaraka rasmi](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Jedwali kutoka** [**nyaraka**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
