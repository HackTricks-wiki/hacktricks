# Windows-bewysbeskerming

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Die [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)-protokol, wat met Windows XP bekendgestel is, is ontwerp vir verifikasie via die HTTP-protokol en is **by verstek geaktiveer op Windows XP tot en met Windows 8.0, asook Windows Server 2003 tot Windows Server 2012**. Hierdie verstekinstelling lei tot **berging van wagwoorde in gewone teks in LSASS** (Local Security Authority Subsystem Service). ’n Aanvaller kan Mimikatz gebruik om **hierdie credentials te onttrek** deur die volgende uit te voer:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Om hierdie funksie **af of aan te skakel**, moet die _**UseLogonCredential**_- en _**Negotiate**_-registersleutels binne _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ op "1" gestel word. Indien hierdie sleutels **ontbreek of op "0" gestel is**, is WDigest **gedeaktiveer**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP- en PPL-protected processes)

**Protected Process (PP)** en **Protected Process Light (PPL)** is **Windows kernel-level protections** wat ontwerp is om ongemagtigde toegang tot sensitiewe prosesse soos **LSASS** te voorkom. Die **PP model**, wat in **Windows Vista** bekendgestel is, is oorspronklik vir **DRM**-afdwinging geskep en het slegs binaries toegelaat wat met ’n **special media certificate** geteken is om beskerm te word. ’n Proses wat as **PP** gemerk is, kan slegs deur ander prosesse verkry word wat **ook PP** is en ’n **gelyke of hoër protection level** het, en selfs dan **slegs met beperkte toegangsregte**, tensy dit spesifiek toegelaat word.

**PPL**, wat in **Windows 8.1** bekendgestel is, is ’n meer buigsame weergawe van PP. Dit laat **breër gebruiksgevalle** toe (bv. LSASS, Defender) deur **"protection levels"** bekend te stel wat op die **digital signature se EKU (Enhanced Key Usage)**-veld gebaseer is. Die protection level word in die `EPROCESS.Protection`-veld gestoor, wat ’n `PS_PROTECTION`-struktuur is met:
- **Type** (`Protected` of `ProtectedLight`)
- **Signer** (bv. `WinTcb`, `Lsa`, `Antimalware`, ens.)

Hierdie struktuur word in ’n enkele byte verpak en bepaal **wie toegang tot wie kan kry**:
- **Hoër signer-waardes kan toegang tot laer waardes kry**
- **PPLs kan nie toegang tot PPs kry nie**
- **Onbeskermde prosesse kan nie toegang tot enige PPL/PP kry nie**

### Wat jy vanuit ’n offensiewe perspektief moet weet

- Wanneer **LSASS as ’n PPL loop**, misluk pogings om dit met `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` vanuit ’n normale admin-konteks oop te maak met **`0x5 (Access Denied)`**, selfs al is `SeDebugPrivilege` geaktiveer.
- Jy kan die **LSASS protection level** nagaan met tools soos Process Hacker, of programmaties deur die `EPROCESS.Protection`-waarde te lees.
- LSASS sal tipies `PsProtectedSignerLsa-Light` (`0x41`) hê, waartoe **slegs prosesse wat met ’n hoërvlak-signer geteken is**, toegang kan kry, soos `WinTcb` (`0x61` of `0x62`).
- PPL is ’n **slegs-Userland-beperking**; **kernel-level code** kan dit volledig omseil.
- Dat LSASS PPL is, **verhoed nie credential dumping** as jy **kernel shellcode** kan uitvoer of ’n hoogbevoorregte proses met toepaslike toegang kan benut nie.
- **Die instel of verwydering van PPL** vereis ’n reboot of **Secure Boot/UEFI-instellings**, wat die PPL-instelling kan behou selfs nadat registerveranderings teruggedraai is.

### Skep ’n PPL-proses tydens launch (gedokumenteerde API)

Windows bied ’n gedokumenteerde manier om tydens die skepping van ’n child process ’n Protected Process Light-vlak aan te vra deur die extended startup attribute list te gebruik. Dit omseil nie signing requirements nie — die target image moet vir die aangevraagde signer class geteken wees.

Minimale vloei in C/C++:
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
Notes en beperkings:
- Gebruik `STARTUPINFOEX` met `InitializeProcThreadAttributeList` en `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, en gee dan `EXTENDED_STARTUPINFO_PRESENT` aan `CreateProcess*` deur.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Die protection `DWORD` kan op konstantes soos `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` of `PROTECTION_LEVEL_LSA_LIGHT` gestel word.
- Die child begin slegs as PPL indien sy image vir daardie signer-klas geteken is; anders misluk process creation, gewoonlik met `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Dit is nie ’n bypass nie — dit is ’n ondersteunde API wat bedoel is vir toepaslik getekende images. Dit is nuttig om tools te harden of PPL-beskermde konfigurasies te valideer.

Voorbeeld-CLI wat ’n minimal loader gebruik:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opsies om PPL-beskerming te bypass:**

As jy LSASS wil dump ondanks PPL, het jy 3 hoofopsies:
1. **Gebruik ’n getekende kernel driver (bv. Mimikatz + mimidrv.sys)** om **LSASS se protection flag te verwyder**:

![Mimikatz mimidrv driver-uitset wat credential protection-interaksie wys](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** om custom kernel code uit te voer en die protection te disable. Tools soos **PPLKiller**, **gdrv-loader** of **kdmapper** maak dit haalbaar.
3. **Steal ’n bestaande LSASS-handle** van ’n ander process wat dit oop het (bv. ’n AV-process), en **duplicate dit** na jou process. Dit is die basis van die `pypykatz live lsa --method handledup`-tegniek.
4. **Abuse ’n geprivilegieerde process** wat jou sal toelaat om arbitrary code in sy address space of binne ’n ander geprivilegieerde process te laai, wat die PPL-beperkings effektief omseil. Jy kan ’n voorbeeld hiervan nagaan in [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) of [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Gaan die huidige status van LSA protection (PPL/PP) vir LSASS na**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Wanneer jy **`mimikatz privilege::debug sekurlsa::logonpasswords`** uitvoer, sal dit waarskynlik misluk met die foutkode `0x00000005` as gevolg hiervan.

- Vir meer inligting oor hierdie kontrole, besoek [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, ’n funksie wat eksklusief is tot **Windows 10 (Enterprise- en Education-uitgawes)**, verbeter die sekuriteit van masjienbewyse deur **Virtual Secure Mode (VSM)** en **Virtualization Based Security (VBS)** te gebruik. Dit benut CPU-virtualiseringsuitbreidings om sleutelprosesse binne ’n beskermde geheuespasie te isoleer, weg van die hoofbedryfstelsel se bereik. Hierdie isolasie verseker dat selfs die kernel nie toegang tot die geheue in VSM kan kry nie, wat bewyse effektief teen aanvalle soos **pass-the-hash** beskerm. Die **Local Security Authority (LSA)** funksioneer binne hierdie veilige omgewing as ’n trustlet, terwyl die **LSASS**-proses in die hoofbedryfstelsel bloot as ’n kommunikeerder met die VSM se LSA optree.

By verstek is **Credential Guard** nie aktief nie en vereis dit handmatige aktivering binne ’n organisasie. Dit is noodsaaklik om sekuriteit teen tools soos **Mimikatz** te verbeter, wat in hul vermoë om bewyse te onttrek, beperk word. Kwesbaarhede kan egter steeds uitgebuit word deur pasgemaakte **Security Support Providers (SSP)** by te voeg om bewyse in clear text tydens aanmeldpogings vas te lê.

Om die aktiveringstatus van **Credential Guard** te verifieer, kan die registersleutel _**LsaCfgFlags**_ onder _**HKLM\System\CurrentControlSet\Control\LSA**_ geïnspekteer word. ’n Waarde van "**1**" dui op aktivering met **UEFI lock**, "**2**" sonder lock, en "**0**" dui aan dat dit nie geaktiveer is nie. Hierdie registerkontrole is ’n sterk aanduiding, maar dit is nie die enigste stap om Credential Guard te aktiveer nie. Gedetailleerde riglyne en ’n PowerShell-script vir die aktivering van hierdie funksie is aanlyn beskikbaar.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Vir 'n omvattende begrip van en instruksies vir die aktivering van **Credential Guard** in Windows 10, asook die outomatiese aktivering daarvan in versoenbare stelsels van **Windows 11 Enterprise en Education (weergawe 22H2)**, besoek [Microsoft se dokumentasie](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Verdere besonderhede oor die implementering van pasgemaakte SSPs vir credential capture word in [hierdie gids](../active-directory-methodology/custom-ssp.md) verskaf.

## RDP RestrictedAdmin Mode

**Windows 8.1 en Windows Server 2012 R2** het verskeie nuwe sekuriteitskenmerke bekendgestel, insluitend die _**Restricted Admin mode for RDP**_. Hierdie modus is ontwerp om sekuriteit te verbeter deur die risiko's wat met [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) attacks geassosieer word, te verminder.

Tradisioneel, wanneer jy via RDP aan 'n afgeleë rekenaar koppel, word jou geloofsbriewe op die teikenmasjien gestoor. Dit hou 'n beduidende sekuriteitsrisiko in, veral wanneer rekeninge met verhoogde voorregte gebruik word. Met die bekendstelling van _**Restricted Admin mode**_ word hierdie risiko egter aansienlik verminder.

Wanneer 'n RDP-verbinding met die opdrag **mstsc.exe /RestrictedAdmin** begin word, vind authentication aan die afgeleë rekenaar plaas sonder om jou geloofsbriewe daarop te stoor. Hierdie benadering verseker dat jou geloofsbriewe nie gekompromitteer word indien malware die rekenaar besmet of 'n kwaadwillige gebruiker toegang tot die afgeleë server verkry nie, aangesien dit nie op die server gestoor word nie.

Dit is belangrik om daarop te let dat pogings om vanaf die RDP-sessie toegang tot netwerkhulpbronne te verkry, in **Restricted Admin mode** nie jou persoonlike geloofsbriewe sal gebruik nie; in plaas daarvan word die **machine's identity** gebruik.

Hierdie kenmerk is 'n belangrike stap vorentoe in die beveiliging van remote desktop-verbindings en die beskerming van sensitiewe inligting teen blootstelling in geval van 'n sekuriteitsbreuk.

![Windows RAM-geheuediagram vir credential extraction-konteks](../../images/RAM.png)

Vir meer gedetailleerde inligting, besoek [hierdie hulpbron](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Gekasde Geloofsbriewe

Windows beveilig **domain credentials** deur middel van die **Local Security Authority (LSA)**, wat logon-prosesse met sekuriteitsprotokolle soos **Kerberos** en **NTLM** ondersteun. 'n Belangrike kenmerk van Windows is die vermoë om die **laaste tien domain logins** te cache, sodat gebruikers steeds toegang tot hul rekenaars kan verkry selfs wanneer die **domain controller offline** is—'n groot voordeel vir laptopgebruikers wat dikwels weg van hul maatskappy se netwerk is.

Die aantal gekasde logins kan deur middel van 'n spesifieke **registry key or group policy** aangepas word. Om hierdie instelling te sien of te verander, word die volgende opdrag gebruik:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Toegang tot hierdie gekaste geloofsbriewe word streng beheer, met slegs die **SYSTEM**-rekening wat die nodige toestemmings het om dit te sien. Administrateurs wat toegang tot hierdie inligting benodig, moet dit met SYSTEM-gebruikervoorregte doen. Die geloofsbriewe word gestoor by: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** kan gebruik word om hierdie gekaste geloofsbriewe met die opdrag `lsadump::cache` te onttrek.

Vir verdere besonderhede verskaf die oorspronklike [bron](http://juggernaut.wikidot.com/cached-credentials) omvattende inligting.<sup>[[7]](#references)</sup>

## Protected Users

Lidmaatskap van die **Protected Users group** stel verskeie sekuriteitsverbeterings vir gebruikers bekend, wat hoër vlakke van beskerming teen geloofsbriefdiefstal en misbruik verseker:

- **Credential Delegation (CredSSP)**: Selfs al is die Group Policy-instelling vir **Allow delegating default credentials** geaktiveer, sal gewone teksgeloofsbriewe van Protected Users nie gekas word nie.
- **Windows Digest**: Vanaf **Windows 8.1 en Windows Server 2012 R2** sal die stelsel nie gewone teksgeloofsbriewe van Protected Users kas nie, ongeag die status van Windows Digest.
- **NTLM**: Die stelsel sal nie Protected Users se gewone teksgeloofsbriewe of NT-eenrigtingfunksies (NTOWF) kas nie.
- **Kerberos**: Vir Protected Users sal Kerberos-verifikasie nie **DES**- of **RC4-sleutels** genereer nie, en dit sal ook nie gewone teksgeloofsbriewe of langtermynsleutels buite die aanvanklike Ticket-Granting Ticket (TGT)-verkryging kas nie.
- **Offline Sign-In**: Protected Users sal nie ’n gekaste verifieerder tydens aanmelding of ontsluiting laat skep nie, wat beteken dat aflyn-aanmelding nie vir hierdie rekeninge ondersteun word nie.

Hierdie beskermings word geaktiveer sodra ’n gebruiker wat ’n lid van die **Protected Users group** is, by die toestel aanmeld. Dit verseker dat kritieke sekuriteitsmaatreëls in plek is om teen verskeie metodes van geloofsbriefkompromittering te beskerm.

Vir meer gedetailleerde inligting, raadpleeg die amptelike [dokumentasie](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Tabel uit** [**die dokumentasie**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

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

## Verwysings

- [1] [CreateProcessAsPPL – minimale PPL-proseslanseerder](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX-struktuur (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – agtergrond en interne werking](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode vir RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Bestuur Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

{{#include ../../banners/hacktricks-training.md}}
