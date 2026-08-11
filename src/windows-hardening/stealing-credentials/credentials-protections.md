# Ulinzi wa Windows Credentials

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Itifaki ya [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), iliyoanzishwa pamoja na Windows XP, imeundwa kwa ajili ya authentication kupitia HTTP Protocol na **imewezeshwa kwa chaguo-msingi kwenye Windows XP hadi Windows 8.0 na Windows Server 2003 hadi Windows Server 2012**. Mpangilio huu wa chaguo-msingi husababisha **uhifadhi wa password katika maandishi wazi ndani ya LSASS** (Local Security Authority Subsystem Service). Mshambulizi anaweza kutumia Mimikatz **kutoa credentials hizi** kwa kutekeleza:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Ili **kuzima au kuwasha kipengele hiki**, registry keys za _**UseLogonCredential**_ na _**Negotiate**_ ndani ya _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ lazima ziwekwe kuwa "1". Ikiwa keys hizi **hazipo au zimewekwa kuwa "0"**, WDigest **imezimwa**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Ulinzi wa LSA (processes zilizo na ulinzi wa PP na PPL)

**Protected Process (PP)** na **Protected Process Light (PPL)** ni **ulinzi wa kiwango cha kernel wa Windows** ulioundwa kuzuia ufikiaji usioidhinishwa wa processes nyeti kama **LSASS**. Ulianzishwa katika **Windows Vista**, **PP model** iliundwa awali kwa ajili ya utekelezaji wa **DRM** na iliruhusu tu binaries zilizotiwa saini kwa **special media certificate** kulindwa. Process iliyowekwa alama ya **PP** inaweza kufikiwa tu na processes nyingine ambazo pia ni **PP** na zina **kiwango cha ulinzi sawa au cha juu zaidi**, na hata hivyo, **kwa access rights zilizowekewa mipaka tu** isipokuwa zimeruhusiwa mahususi.

**PPL**, iliyoanzishwa katika **Windows 8.1**, ni toleo linaloweza kubadilika zaidi la PP. Inaruhusu **matumizi mapana zaidi** (kwa mfano, LSASS, Defender) kwa kuanzisha **"protection levels"** kulingana na sehemu ya **EKU (Enhanced Key Usage)** ya **digital signature**. Kiwango cha ulinzi huhifadhiwa katika sehemu ya `EPROCESS.Protection`, ambayo ni muundo wa `PS_PROTECTION` wenye:
- **Type** (`Protected` au `ProtectedLight`)
- **Signer** (kwa mfano, `WinTcb`, `Lsa`, `Antimalware`, n.k.)

Muundo huu hufungwa kuwa byte moja na huamua **nani anaweza kumfikia nani**:
- **Signer values** za juu zinaweza kufikia zilizo chini
- **PPLs haziwezi kufikia PPs**
- **Processes zisizo na ulinzi haziwezi kufikia PPL/PP yoyote**

### Unachohitaji kujua kwa mtazamo wa offensive

- Wakati **LSASS inaendesha kama PPL**, majaribio ya kuifungua kwa kutumia `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` kutoka kwenye admin context ya kawaida **hushindwa kwa `0x5 (Access Denied)`**, hata kama `SeDebugPrivilege` imewezeshwa.
- Unaweza **kuangalia kiwango cha ulinzi cha LSASS** kwa kutumia tools kama Process Hacker au kupitia programmatically kwa kusoma thamani ya `EPROCESS.Protection`.
- Kwa kawaida LSASS huwa na `PsProtectedSignerLsa-Light` (`0x41`), ambayo inaweza kufikiwa **tu na processes zilizotiwa saini kwa signer ya kiwango cha juu**, kama `WinTcb` (`0x61` au `0x62`).
- PPL ni **kizuizi cha Userland pekee**; code ya **kernel-level** inaweza kukipita kikamilifu.
- LSASS kuwa PPL **hakuzuii credential dumping** ikiwa unaweza kutekeleza kernel shellcode au **kutumia process yenye privileges za juu yenye access inayofaa**.
- **Kuweka au kuondoa PPL** kunahitaji reboot au **mipangilio ya Secure Boot/UEFI**, ambayo inaweza kuendeleza mpangilio wa PPL hata baada ya mabadiliko ya registry kurejeshwa.

### Kuunda process ya PPL wakati wa launch (documented API)

Windows hutoa njia iliyoandikwa rasmi ya kuomba kiwango cha Protected Process Light kwa child process wakati wa kuunda, kwa kutumia extended startup attribute list. Hii haipiti mahitaji ya signing — target image lazima iwe imetiwa saini kwa signer class iliyoombwa.

Minimal flow in C/C++:
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
- Tumia `STARTUPINFOEX` pamoja na `InitializeProcThreadAttributeList` na `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, kisha pitisha `EXTENDED_STARTUPINFO_PRESENT` kwa `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- `DWORD` ya protection inaweza kuwekwa kuwa constants kama `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, au `PROTECTION_LEVEL_LSA_LIGHT`.
- Child huanza tu kama PPL ikiwa image yake imesainiwa kwa signer class hiyo; vinginevyo process creation hushindikana, kwa kawaida ikiwa na `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Hii si bypass — ni API inayoungwa mkono, iliyokusudiwa kwa images zilizosainiwa ipasavyo. Ni muhimu kwa kuimarisha tools au kuthibitisha configurations zilizolindwa na PPL.

Mfano wa CLI unaotumia loader ndogo:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Chaguo za bypass PPL protections:**

Ikiwa unataka kudump LSASS licha ya PPL, una chaguo 3 kuu:
1. **Tumia signed kernel driver (kwa mfano, Mimikatz + mimidrv.sys)** ili **kuondoa protection flag ya LSASS**:

![Mimikatz mimidrv driver output inayoonyesha mwingiliano na credential protection](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** ili kuendesha custom kernel code na kuzima protection. Tools kama **PPLKiller**, **gdrv-loader**, au **kdmapper** hufanya hili liwezekane.
3. **Steal existing LSASS handle** kutoka kwa process nyingine iliyoifungua (kwa mfano, process ya AV), kisha **ui-duplicate** ndani ya process yako. Huu ndio msingi wa technique ya `pypykatz live lsa --method handledup`.
4. **Abuse privileged process** fulani itakayokuruhusu kupakia arbitrary code kwenye address space yake au ndani ya privileged process nyingine, hivyo kupita restrictions za PPL. Unaweza kuona mfano wa hili kwenye [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) au [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Kagua hali ya sasa ya LSA protection (PPL/PP) kwa LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Unapoendesha **`mimikatz privilege::debug sekurlsa::logonpasswords`**, huenda ikashindwa kwa msimbo wa hitilafu `0x00000005` kutokana na ulinzi huu.

- Kwa maelezo zaidi kuhusu ukaguzi huu [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, kipengele cha kipekee cha **Windows 10 (matoleo ya Enterprise na Education)**, huimarisha usalama wa machine credentials kwa kutumia **Virtual Secure Mode (VSM)** na **Virtualization Based Security (VBS)**. Hutumia CPU virtualization extensions kutenga processes muhimu ndani ya protected memory space, mbali na uwezo wa kufikiwa na main operating system. Utengaji huu huhakikisha kwamba hata kernel haiwezi kufikia memory iliyo katika VSM, hivyo kulinda credentials dhidi ya attacks kama **pass-the-hash**. **Local Security Authority (LSA)** huendesha kazi katika mazingira haya salama kama trustlet, huku process ya **LSASS** katika main OS ikifanya kazi tu kama communicator na LSA ya VSM.

Kwa default, **Credential Guard** haijawezeshwa na inahitaji kuamilishwa manually ndani ya organization. Ni muhimu katika kuimarisha usalama dhidi ya tools kama **Mimikatz**, ambazo uwezo wake wa kutoa credentials huzuiwa. Hata hivyo, vulnerabilities bado zinaweza kutumiwa kupitia kuongezwa kwa custom **Security Support Providers (SSP)** ili kunasa credentials katika clear text wakati wa login attempts.

Ili kuthibitisha hali ya activation ya **Credential Guard**, registry key _**LsaCfgFlags**_ iliyo chini ya _**HKLM\System\CurrentControlSet\Control\LSA**_ inaweza kukaguliwa. Thamani ya "**1**" inaonyesha imeamilishwa ikiwa na **UEFI lock**, "**2**" ikiwa haina lock, na "**0**" inaonyesha kuwa haijawezeshwa. Ukaguzi huu wa registry, ingawa ni kiashiria muhimu, si hatua pekee ya kuwezesha Credential Guard. Mwongozo wa kina na PowerShell script ya kuwezesha kipengele hiki vinapatikana online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Kwa uelewa wa kina na maelekezo kuhusu kuwezesha **Credential Guard** katika Windows 10 na uanzishaji wake wa kiotomatiki kwenye mifumo inayooana ya **Windows 11 Enterprise and Education (version 22H2)**, tembelea [nyaraka za Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Maelezo zaidi kuhusu kutekeleza SSPs maalum kwa ajili ya credential capture yanapatikana katika [mwongozo huu](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 na Windows Server 2012 R2** zilianzisha vipengele vipya kadhaa vya usalama, kikiwemo _**Restricted Admin mode for RDP**_. Mode hii iliundwa kuimarisha usalama kwa kupunguza hatari zinazohusishwa na mashambulizi ya [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Kwa kawaida, unapounganisha kwenye kompyuta ya mbali kupitia RDP, credentials zako huhifadhiwa kwenye mashine lengwa. Hili huleta hatari kubwa ya usalama, hasa unapotumia accounts zilizo na privileges zilizoinuliwa. Hata hivyo, baada ya kuanzishwa kwa _**Restricted Admin mode**_, hatari hii hupunguzwa kwa kiasi kikubwa.

Unapoanzisha muunganisho wa RDP kwa kutumia amri **mstsc.exe /RestrictedAdmin**, authentication kwenye kompyuta ya mbali hufanyika bila kuhifadhi credentials zako humo. Njia hii huhakikisha kwamba, iwapo kutatokea maambukizi ya malware au mtumiaji hasidi akipata access kwenye server ya mbali, credentials zako hazitaathirika, kwa kuwa hazijahifadhiwa kwenye server hiyo.

Ni muhimu kutambua kwamba katika **Restricted Admin mode**, majaribio ya kufikia network resources kutoka kwenye RDP session hayatumii credentials zako binafsi; badala yake, hutumika **identity ya mashine**.

Kipengele hiki ni hatua muhimu ya kuimarisha usalama wa remote desktop connections na kulinda taarifa nyeti dhidi ya kufichuliwa iwapo kutatokea security breach.

![Mchoro wa Windows RAM memory kwa muktadha wa credential extraction](../../images/RAM.png)

Kwa maelezo zaidi, tembelea [resource hii](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Cached Credentials

Windows hulinda **domain credentials** kupitia **Local Security Authority (LSA)**, huku ikiunga mkono michakato ya logon kwa security protocols kama vile **Kerberos** na **NTLM**. Kipengele muhimu cha Windows ni uwezo wake wa kuweka cache ya **domain logins kumi za mwisho**, ili kuhakikisha kuwa users bado wanaweza kufikia computers zao hata kama **domain controller haipatikani**—jambo linalowanufaisha sana watumiaji wa laptops ambao mara nyingi huwa mbali na network ya kampuni yao.

Idadi ya cached logins inaweza kurekebishwa kupitia **registry key au group policy** maalum. Ili kuona au kubadilisha setting hii, amri ifuatayo hutumika:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Ufikiaji wa credentials hizi zilizohifadhiwa kwenye cache unadhibitiwa kwa ukali, huku akaunti ya **SYSTEM** pekee ikiwa na ruhusa zinazohitajika kuziona. Administrators wanaohitaji kufikia taarifa hizi lazima wafanye hivyo kwa kutumia privileges za mtumiaji wa SYSTEM. Credentials zimehifadhiwa kwenye: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** inaweza kutumika kutoa credentials hizi zilizohifadhiwa kwenye cache kwa kutumia command `lsadump::cache`.

Kwa maelezo zaidi, [source](http://juggernaut.wikidot.com/cached-credentials) ya awali inatoa taarifa kamili.<sup>[[7]](#references)</sup>

## Protected Users

Uanachama katika **Protected Users group** unaanzisha maboresho kadhaa ya usalama kwa users, na kuhakikisha viwango vya juu zaidi vya ulinzi dhidi ya credential theft na matumizi mabaya:

- **Credential Delegation (CredSSP)**: Hata kama setting ya Group Policy ya **Allow delegating default credentials** imewezeshwa, credentials za Protected Users zilizo katika plain text hazitahifadhiwa kwenye cache.
- **Windows Digest**: Kuanzia **Windows 8.1 na Windows Server 2012 R2**, mfumo hautahifadhi kwenye cache credentials za Protected Users zilizo katika plain text, bila kujali hali ya Windows Digest.
- **NTLM**: Mfumo hautahifadhi kwenye cache credentials za Protected Users zilizo katika plain text au one-way functions za NT (NTOWF).
- **Kerberos**: Kwa Protected Users, authentication ya Kerberos haitazalisha keys za **DES** au **RC4**, wala kuhifadhi kwenye cache credentials za plain text au long-term keys zaidi ya upatikanaji wa awali wa Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Protected Users hawatakuwa na cached verifier itakayoundwa wakati wa sign-in au unlock, kumaanisha kuwa offline sign-in haitumiki kwa accounts hizi.

Protections hizi huwashwa mara tu user ambaye ni mwanachama wa **Protected Users group** anapo-sign in kwenye device. Hii inahakikisha kuwa hatua muhimu za usalama zipo ili kulinda dhidi ya mbinu mbalimbali za credential compromise.

Kwa maelezo zaidi, soma [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) rasmi.<sup>[[10]](#references)</sup>

**Table kutoka** [**kwenye docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

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

- [1] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode for RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}
