# Ulinzi wa Vifikisho vya Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Protocol ya [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), iliyoanzishwa na Windows XP, imeundwa kwa ajili ya uthibitishaji kupitia HTTP Protocol na **imewezeshwa kwa chaguo-msingi kwenye Windows XP hadi Windows 8.0 na Windows Server 2003 hadi Windows Server 2012**. Mpangilio huu wa chaguo-msingi husababisha **plain-text password storage in LSASS** (Local Security Authority Subsystem Service). Mshambulizi anaweza kutumia Mimikatz ili **kutoa vifikisho hivi** kwa kukimbiza:
```bash
sekurlsa::wdigest
```
Ili **kuzima au kuwasha kipengele hiki**, vifunguo vya rejista _**UseLogonCredential**_ na _**Negotiate**_ ndani ya _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ lazima viwe vimewekwa kuwa "1". Ikiwa vifunguo hivi **havipo au vimewekwa kuwa "0"**, WDigest **imezimwa**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Ulinzi (PP & PPL protected processes)

**Protected Process (PP)** na **Protected Process Light (PPL)** ni **ulinzi za ngazi ya kernel za Windows** zilizoundwa kuzuia ufikiaji usioidhinishwa kwa michakato nyeti kama **LSASS**. Imetangazwa katika **Windows Vista**, **mfumo wa PP** awali uliundwa kwa ajili ya utekelezaji wa **DRM** na uliruhusu tu binaries zilizotiwa saini na **cheti maalumu cha media** kuwalindwa. Mchakato uliotajwa kama **PP** unaweza kufikiwa tu na michakato mingine ambayo **pia ni PP** na ina **ngazi sawa au ya juu ya ulinzi**, na hata hivyo, **kwa haki za kufikia zilizo na mipaka tu** isipokuwa ruhusiwe maalumu.

**PPL**, iliyoanzishwa katika **Windows 8.1**, ni toleo lenye urekebishaji zaidi la PP. Inaruhusu **matumizi mapana zaidi** (mfano, LSASS, Defender) kwa kuanzisha **"protection levels"** kulingana na uwanja wa **EKU (Enhanced Key Usage)** wa saini ya kidijitali. Ngazi ya ulinzi huhifadhiwa katika uwanja wa `EPROCESS.Protection`, ambao ni muundo wa `PS_PROTECTION` wenye:
- **Type** (`Protected` au `ProtectedLight`)
- **Signer** (mfano, `WinTcb`, `Lsa`, `Antimalware`, n.k.)

Muundo huu umepakwa ndani ya bait moja na unaamua **nani anaweza kumfikia nani**:
- **Thamani za signer za juu zinaweza kumfikia wale wa chini**
- **PPLs hawawezi kufikia PPs**
- **Michakato isiyolindwa haiwezi kufikia PPL/PP yoyote**

### Unachohitaji kujua kwa mtazamo wa mashambulizi

- Wakati **LSASS** inapoendesha kama **PPL**, majaribio ya kuifungua kwa kutumia `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` kutoka muktadha wa kawaida wa admin **huishia kwa `0x5 (Access Denied)`**, hata kama `SeDebugPrivilege` iko imewezeshwa.
- Unaweza **kuangalia ngazi ya ulinzi ya LSASS** kwa kutumia zana kama Process Hacker au kwa njia ya programu kwa kusoma thamani ya `EPROCESS.Protection`.
- Kwa kawaida LSASS itakuwa na `PsProtectedSignerLsa-Light` (`0x41`), ambayo inaweza kufikiwa **tu na michakato iliyotiwa saini na signer wa kiwango cha juu**, kama `WinTcb` (`0x61` au `0x62`).
- PPL ni **kizuizi tu cha Userland**; **msimbo wa kernel unaweza kukivuka kikamilifu**.
- LSASS kuwa PPL **haitazuia credential dumping** ikiwa unaweza kutekeleza **kernel shellcode** au kutumia mchakato mwenye ruhusa za juu na ufikiaji unaofaa.
- Kuweka au kuondoa PPL kunahitaji kuanzisha upya au mipangilio ya **Secure Boot/UEFI**, ambayo inaweza kudumu kuweka PPL hata baada ya mabadiliko ya registry kurudishwa.

### Tengeneza mchakato wa PPL wakati wa kuanzisha (documented API)

Windows inatoa njia iliyoandikwa ya kuomba ngazi ya Protected Process Light kwa mchakato mtoto wakati wa uundaji kwa kutumia extended startup attribute list. Hii haivunji mahitaji ya saini — image lengwa lazima iwe imetiwa saini kwa daraja la signer linalohitajika.

Mtiririko mdogo katika C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Vidokezo na vikwazo:
- Tumia `STARTUPINFOEX` pamoja na `InitializeProcThreadAttributeList` na `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, kisha pasha `EXTENDED_STARTUPINFO_PRESENT` kwa `CreateProcess*`.
- DWORD ya ulinzi inaweza kuwekwa kwa vigezo kama `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, au `PROTECTION_LEVEL_LSA_LIGHT`.
- Child hupanuka kama PPL tu ikiwa image yake imesainiwa kwa signer class hiyo; vinginevyo uundaji wa process unashindwa, kawaida kwa `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Hii si bypass — ni API inayounga mkono iliyokusudiwa kwa images zilizosainiwa ipasavyo. Inafaa kuimarisha tools au kuthibitisha mipangilio iliyo chini ya ulinzi wa PPL.

Mfano wa CLI ukitumia loader ndogo:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Bypass PPL protections options:**

Ikiwa unataka dump LSASS licha ya PPL, una chaguzi kuu 3:
1. **Use a signed kernel driver (e.g., Mimikatz + mimidrv.sys)** ili **kuondoa bendera ya ulinzi ya LSASS**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** ili kuendesha custom kernel code na kuzima ulinzi. Tools kama **PPLKiller**, **gdrv-loader**, au **kdmapper** hufanya hili liwezekane.
3. **Steal an existing LSASS handle** kutoka kwa process nyingine ambayo imeifungua (mfano, process ya AV), kisha **duplicate** ndani ya process yako. Hii ni msingi wa mbinu ya `pypykatz live lsa --method handledup`.
4. **Abuse some privileged process** ambayo itakuwezesha kupakia code yoyote ndani ya address space yake au ndani ya process nyingine yenye privilégè, effectively bypassing the PPL restrictions. Unaweza kuona mfano ya hili katika [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) au [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Check current status of LSA protection (PPL/PP) for LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` because of this.

- For more information about this check [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, kipengele kinachopatikana tu kwenye **Windows 10 (Enterprise and Education editions)**, kinaimarisha usalama wa nywila za mashine kwa kutumia **Virtual Secure Mode (VSM)** na **Virtualization Based Security (VBS)**. Inatumia ugani wa virtualization wa CPU kutenganisha michakato muhimu ndani ya eneo la kumbukumbu lililolindwa, mbali na ufikivu wa mfumo mkuu wa uendeshaji. Kutengwa hili kunahakikisha hata kernel hawezi kufikia kumbukumbu ndani ya VSM, hivyo kulinda nywila dhidi ya mashambulizi kama **pass-the-hash**. Local Security Authority (LSA) inafanya kazi ndani ya mazingira haya salama kama trustlet, wakati mchakato wa **LSASS** kwenye OS kuu unatumika tu kama mwasilishaji kwa LSA ya VSM.

Kwa kawaida, **Credential Guard** haizimwi kwa default na inahitaji uanzishaji kwa mkono ndani ya shirika. Ni muhimu kwa kuimarisha usalama dhidi ya zana kama **Mimikatz**, ambazo zinapata ugumu katika uwezo wao wa kutoa nywila. Hata hivyo, udhaifu bado unaweza kutumika kwa kuongeza custom **Security Support Providers (SSP)** ili kunasa nywila kwa maandishi wazi wakati wa jaribio la kuingia.

Ili kuthibitisha hali ya uanzishaji ya **Credential Guard**, funguo la rejista _**LsaCfgFlags**_ chini ya _**HKLM\System\CurrentControlSet\Control\LSA**_ linaweza kutazamwa. Thamani ya "**1**" inaonyesha uanzishaji na **UEFI lock**, "**2**" bila lock, na "**0**" inaonyesha haijawezeshwa. Ukaguzi huu wa rejista, ingawa ni dalili thabiti, si hatua pekee ya kuwezesha Credential Guard. Mwongozo wa kina na script ya **PowerShell** ya kuwezesha kipengele hiki yanapatikana mtandaoni.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Kwa uelewa kamili na maagizo ya kuwawezesha **Credential Guard** katika Windows 10 na uanzishaji wake wa moja kwa moja katika mifumo inayofaa ya **Windows 11 Enterprise and Education (version 22H2)**, tembelea [nyaraka za Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Maelezo zaidi kuhusu kutekeleza custom SSPs kwa ajili ya credential capture yameelezwa katika [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** ziliweka vipengele vingi vipya vya usalama, ikiwemo _**Restricted Admin mode for RDP**_. Mode hii ilibuniwa kuboresha usalama kwa kupunguza hatari zinazohusiana na mashambulizi ya [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Kawaida, unaponunganishwa kwenye kompyuta ya mbali kupitia RDP, credentials zako zinahifadhiwa kwenye mashine lengwa. Hii inasababisha hatari kubwa ya usalama, hasa unapoitumia akaunti zenye ruhusa za juu. Hata hivyo, kwa kuanzishwa kwa _**Restricted Admin mode**_, hatari hii inapunguzwa kwa kiasi kikubwa.

Unapoanzisha muunganisho wa RDP kwa kutumia amri **mstsc.exe /RestrictedAdmin**, uthibitishaji kwa kompyuta ya mbali hufanyika bila kuhifadhi credentials zako juu yake. Mbinu hii inahakikisha kwamba, endapo kutatokea maambukizi ya malware au mtumiaji mbaya atapata ufikiaji kwenye server ya mbali, credentials zako hazitavamiwa, kwa kuwa hazijahifadhiwa kwenye server.

Ni muhimu kutambua kwamba katika **Restricted Admin mode**, jaribio la kufikia rasilimali za mtandao kutoka kwa kikao cha RDP halitatumia credentials zako za kibinafsi; badala yake, **machine's identity** inatumika.

Kipengele hiki ni hatua muhimu katika kuimarisha usalama wa remote desktop connections na kulinda taarifa nyeti kuonyeshwa endapo kutatokea uvunjaji wa usalama.

![](../../images/RAM.png)

Kwa maelezo ya kina zaidi tembelea [chanzo hiki](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows inalinda **domain credentials** kupitia **Local Security Authority (LSA)**, ikisaidia michakato ya kuingia kwa itifaki za usalama kama **Kerberos** na **NTLM**. Kipengele muhimu cha Windows ni uwezo wake wa kuhifadhi (cache) **last ten domain logins** ili kuhakikisha watumiaji bado wanaweza kufikia kompyuta zao hata pale **domain controller** iko offline — jambo lenye faida kwa watumiaji wa laptop wanaotoka mara kwa mara kwenye mtandao wa kampuni yao.

Idadi ya logins zilizohifadhiwa inaweza kubadilishwa kupitia **registry key or group policy** maalum. Ili kuona au kubadilisha mipangilio hii, amri ifuatayo inatumika:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Access to these cached credentials is tightly controlled, with only the **SYSTEM** account having the necessary permissions to view them. Administrators needing to access this information must do so with SYSTEM user privileges. The credentials are stored at: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** can be employed to extract these cached credentials using the command `lsadump::cache`.

For further details, the original [source](http://juggernaut.wikidot.com/cached-credentials) provides comprehensive information.

## Protected Users

Uanachama katika **Protected Users group** huleta maboresho kadhaa ya usalama kwa watumiaji, kuhakikisha viwango vya juu vya ulinzi dhidi ya wizi na matumizi mabaya ya nyaraka za utambulisho:

- **Credential Delegation (CredSSP)**: Hata kama Group Policy setting ya **Allow delegating default credentials** imewezeshwa, nyaraka za watumiaji zilizo kwa maandishi wazi za Protected Users hazitahifadhiwa.
- **Windows Digest**: Kuanzia **Windows 8.1 and Windows Server 2012 R2**, mfumo hautahifadhi nyaraka za maandishi wazi za Protected Users, bila kujali hali ya Windows Digest.
- **NTLM**: Mfumo hautahifadhi nyaraka za maandishi wazi za Protected Users au NT one-way functions (NTOWF).
- **Kerberos**: Kwa Protected Users, uthibitishaji wa Kerberos hautazalisha funguo za **DES** au **RC4**, wala hautahifadhi nyaraka za maandishi wazi au funguo za muda mrefu zaidi ya ununuzi wa awali wa Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Watumiaji wa Protected Users hawatakuwa na verifier iliyohifadhiwa (cached verifier) inayoundwa wakati wa kuingia au kufungua kifaa, hivyo kuingia bila mtandao (offline sign-in) haitegemezeki kwa akaunti hizi.

Ulinzi huu unaanza mara mtumiaji ambaye ni mwanachama wa **Protected Users group** anapoingia kwenye kifaa. Hii inahakikisha hatua muhimu za usalama ziko tayari kulinda dhidi ya mbinu mbalimbali za uvunjaji wa nyaraka za utambulisho.

For more detailed information, consult the official [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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

## References

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
