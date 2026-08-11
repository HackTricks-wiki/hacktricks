# Windows Credentials-beskerming

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Die [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)-protokol, wat saam met Windows XP bekendgestel is, is ontwerp vir authentication via die HTTP-protokol en is **by verstek geaktiveer op Windows XP tot en met Windows 8.0, asook Windows Server 2003 tot Windows Server 2012**. Hierdie verstekinstelling lei tot **berging van wagwoorde in gewone teks in LSASS** (Local Security Authority Subsystem Service). ’n Aanvaller kan Mimikatz gebruik om **hierdie credentials te onttrek** deur die volgende uit te voer:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Om hierdie funksie **af of aan te skakel**, moet die _**UseLogonCredential**_- en _**Negotiate**_-registersleutels binne _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ op "1" gestel word. As hierdie sleutels **ontbreek of op "0" gestel is**, is WDigest **gedeaktiveer**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL-beskermde prosesse)

**Protected Process (PP)** en **Protected Process Light (PPL)** is **Windows-kernvlak-beskermingsmaatreëls** wat ontwerp is om ongemagtigde toegang tot sensitiewe prosesse soos **LSASS** te voorkom. Die **PP-model**, wat in **Windows Vista** bekendgestel is, is oorspronklik vir **DRM**-afdwinging geskep en het slegs binaries toegelaat wat met ’n **spesiale media-sertifikaat** onderteken is om beskerm te word. ’n Proses wat as **PP** gemerk is, kan slegs deur ander prosesse verkry word wat **ook PP** is en ’n **gelyke of hoër beskermingsvlak** het, en selfs dan **slegs met beperkte toegangsregte**, tensy dit spesifiek toegelaat word.

**PPL**, wat in **Windows 8.1** bekendgestel is, is ’n meer buigsame weergawe van PP. Dit maak **breër gebruiksgevalle** (bv. LSASS, Defender) moontlik deur **"beskermingsvlakke"** bekend te stel wat op die **digitale handtekening se EKU (Enhanced Key Usage)**-veld gebaseer is. Die beskermingsvlak word in die `EPROCESS.Protection`-veld gestoor, wat ’n `PS_PROTECTION`-struktuur is met:
- **Type** (`Protected` of `ProtectedLight`)
- **Signer** (bv. `WinTcb`, `Lsa`, `Antimalware`, ens.)

Hierdie struktuur word in ’n enkele byte verpak en bepaal **wie toegang tot wie kan verkry**:
- **Hoër signer-waardes kan toegang tot laer waardes verkry**
- **PPLs kan nie toegang tot PPs verkry nie**
- **Onbeskermde prosesse kan nie toegang tot enige PPL/PP verkry nie**

### Wat jy vanuit ’n offensive-perspektief moet weet

- Wanneer **LSASS as ’n PPL loop**, misluk pogings om dit vanuit ’n normale admin-konteks met `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` oop te maak met `0x5 (Access Denied)`, selfs al is `SeDebugPrivilege` geaktiveer.
- Jy kan **LSASS se beskermingsvlak nagaan** met tools soos Process Hacker of programmaties deur die `EPROCESS.Protection`-waarde te lees.
- LSASS sal tipies `PsProtectedSignerLsa-Light` (`0x41`) hê, waartoe **slegs prosesse wat met ’n hoër vlak signer onderteken is**, toegang kan verkry, soos `WinTcb` (`0x61` of `0x62`).
- PPL is ’n **slegs-Userland-beperking**; **kernvlakkode kan dit volledig omseil**.
- Die feit dat LSASS PPL is, **verhoed nie credential dumping as jy kernel shellcode kan uitvoer** of **’n hoogbevoorregte proses met die korrekte toegang kan benut nie**.
- **Die instel of verwydering van PPL** vereis ’n herlaai of **Secure Boot/UEFI-instellings**, wat die PPL-instelling kan behou selfs nadat registerveranderings omgekeer is.

### Skep ’n PPL-proses tydens bekendstelling (gedokumenteerde API)

Windows bied ’n gedokumenteerde manier om tydens die skepping van ’n child process ’n Protected Process Light-vlak aan te vra deur die uitgebreide startup-attribuutlys te gebruik. Dit omseil nie ondertekeningsvereistes nie — die teikenbeeld moet vir die aangevraagde signer-klas onderteken wees.

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
Notas en beperkings:
- Gebruik `STARTUPINFOEX` met `InitializeProcThreadAttributeList` en `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, en gee dan `EXTENDED_STARTUPINFO_PRESENT` aan `CreateProcess*` deur.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Die protection `DWORD` kan op konstantes soos `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` of `PROTECTION_LEVEL_LSA_LIGHT` gestel word.
- Die child begin slegs as PPL indien sy image vir daardie signer class signed is; anders misluk process creation, gewoonlik met `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Dit is nie ’n bypass nie — dit is ’n supported API wat bedoel is vir toepaslik signed images. Nuttig om tools te harden of PPL-protected configurations te valideer.

Voorbeeld-CLI wat ’n minimal loader gebruik:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opsies om PPL protections te bypass:**

As jy LSASS wil dump ondanks PPL, het jy 3 hoofopsies:
1. **Gebruik ’n signed kernel driver (bv. Mimikatz + mimidrv.sys)** om **LSASS se protection flag te verwyder**:

![Mimikatz mimidrv driver-uitset wat credential protection-interaksie toon](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** om custom kernel code uit te voer en die protection te disable. Tools soos **PPLKiller**, **gdrv-loader** of **kdmapper** maak dit haalbaar.
3. **Steal ’n bestaande LSASS handle** uit ’n ander process wat dit oop het (bv. ’n AV-process), en **duplicate dit** na jou process. Dit is die basis van die `pypykatz live lsa --method handledup` technique.
4. **Abuse ’n privileged process** wat jou sal toelaat om arbitrary code in sy address space of binne ’n ander privileged process te load, wat die PPL restrictions effektief bypass. Jy kan ’n voorbeeld hiervan nagaan in [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) of [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Gaan die huidige status van LSA protection (PPL/PP) vir LSASS na**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Wanneer **`mimikatz privilege::debug sekurlsa::logonpasswords`** uitgevoer word, sal dit waarskynlik met foutkode `0x00000005` misluk weens hierdie beskerming.

- Vir meer inligting oor hierdie kontrole [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, ’n funksie wat eksklusief is tot **Windows 10 (Enterprise- en Education-uitgawes)**, verbeter die sekuriteit van masjien-geloofsbriewe deur **Virtual Secure Mode (VSM)** en **Virtualization Based Security (VBS)** te gebruik. Dit benut CPU-virtualiseringsuitbreidings om sleutelprosesse binne ’n beskermde geheuespasie te isoleer, weg van die hoofbedryfstelsel se bereik. Hierdie isolasie verseker dat selfs die kernel nie toegang tot die geheue in VSM kan kry nie, wat geloofsbriewe doeltreffend beskerm teen aanvalle soos **pass-the-hash**. Die **Local Security Authority (LSA)** werk binne hierdie veilige omgewing as ’n trustlet, terwyl die **LSASS**-proses in die hoofbedryfstelsel bloot as ’n kommunikeerder met die VSM se LSA optree.

By verstek is **Credential Guard** nie aktief nie en moet dit handmatig binne ’n organisasie geaktiveer word. Dit is noodsaaklik om sekuriteit teen tools soos **Mimikatz** te verbeter, aangesien dit hul vermoë om geloofsbriewe te onttrek, beperk. Kwesbaarhede kan egter steeds uitgebuit word deur pasgemaakte **Security Support Providers (SSP)** by te voeg om geloofsbriewe in clear text tydens aanmeldpogings vas te lê.

Om die aktiveringstatus van **Credential Guard** te verifieer, kan die registersleutel _**LsaCfgFlags**_ onder _**HKLM\System\CurrentControlSet\Control\LSA**_ ondersoek word. ’n Waarde van "**1**" dui op aktivering met **UEFI lock**, "**2**" sonder lock, en "**0**" dui aan dat dit nie geaktiveer is nie. Hierdie registerkontrole is ’n sterk aanduiding, maar is nie die enigste stap om Credential Guard te aktiveer nie. Gedetailleerde leiding en ’n PowerShell-script om hierdie funksie te aktiveer, is aanlyn beskikbaar.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Vir 'n omvattende begrip van en instruksies oor die aktivering van **Credential Guard** in Windows 10 en die outomatiese aktivering daarvan in versoenbare stelsels van **Windows 11 Enterprise and Education (version 22H2)**, besoek [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Verdere besonderhede oor die implementering van custom SSPs vir credential capture word in [this guide](../active-directory-methodology/custom-ssp.md) verskaf.

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** het verskeie nuwe sekuriteitskenmerke bekendgestel, insluitend die _**Restricted Admin mode for RDP**_. Hierdie modus is ontwerp om sekuriteit te verbeter deur die risiko's wat met [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) attacks geassosieer word, te beperk.

Tradisioneel, wanneer jy via RDP aan 'n afgeleë rekenaar koppel, word jou credentials op die teikenmasjien gestoor. Dit hou 'n beduidende sekuriteitsrisiko in, veral wanneer accounts met verhoogde privileges gebruik word. Met die bekendstelling van _**Restricted Admin mode**_ word hierdie risiko egter aansienlik verminder.

Wanneer 'n RDP-verbinding met die command **mstsc.exe /RestrictedAdmin** begin word, vind authentication met die afgeleë rekenaar plaas sonder om jou credentials daarop te stoor. Hierdie benadering verseker dat jou credentials nie gekompromitteer word indien malware die rekenaar infekteer of 'n malicious user toegang tot die afgeleë server verkry nie, aangesien dit nie op die server gestoor word nie.

Dit is belangrik om daarop te let dat pogings om toegang tot network resources vanuit die RDP-sessie te verkry, in **Restricted Admin mode** nie jou persoonlike credentials sal gebruik nie; in plaas daarvan word die **machine's identity** gebruik.

Hierdie kenmerk is 'n belangrike stap vorentoe in die beveiliging van remote desktop connections en die beskerming van sensitiewe inligting teen blootstelling in geval van 'n security breach.

![Windows RAM memory diagram for credential extraction context](../../images/RAM.png)

Vir meer gedetailleerde inligting, besoek [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Cached Credentials

Windows beveilig **domain credentials** deur middel van die **Local Security Authority (LSA)** en ondersteun logon processes met security protocols soos **Kerberos** en **NTLM**. 'n Belangrike kenmerk van Windows is die vermoë om die **last ten domain logins** te cache, sodat users steeds toegang tot hul rekenaars kan verkry selfs wanneer die **domain controller is offline**—'n voordeel vir laptop users wat dikwels weg van hul company se network is.

Die aantal cached logins kan deur middel van 'n spesifieke **registry key or group policy** aangepas word. Om hierdie instelling te bekyk of te verander, word die volgende command gebruik:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Toegang tot hierdie gekaste geloofsbriewe word streng beheer, met slegs die **SYSTEM**-rekening wat die nodige toestemmings het om dit te sien. Administrateurs wat toegang tot hierdie inligting benodig, moet dit met SYSTEM-gebruikerbevoegdhede doen. Die geloofsbriewe word gestoor by: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** kan gebruik word om hierdie gekaste geloofsbriewe met die opdrag `lsadump::cache` te onttrek.

Vir verdere besonderhede verskaf die oorspronklike [bron](http://juggernaut.wikidot.com/cached-credentials) omvattende inligting.<sup>[[7]](#references)</sup>

## Protected Users

Lidmaatskap van die **Protected Users group** stel verskeie sekuriteitsverbeterings vir gebruikers bekend, wat hoër vlakke van beskerming teen diefstal en misbruik van geloofsbriewe verseker:

- **Credential Delegation (CredSSP)**: Selfs al is die Group Policy-instelling vir **Allow delegating default credentials** geaktiveer, sal plaintext-geloofsbriewe van Protected Users nie gekas word nie.
- **Windows Digest**: Vanaf **Windows 8.1 en Windows Server 2012 R2** sal die stelsel nie plaintext-geloofsbriewe van Protected Users kas nie, ongeag die status van Windows Digest.
- **NTLM**: Die stelsel sal nie Protected Users se plaintext-geloofsbriewe of NT-eenrigtingfunksies (NTOWF) kas nie.
- **Kerberos**: Vir Protected Users sal Kerberos-verifikasie nie **DES**- of **RC4-sleutels** genereer nie, en dit sal ook nie plaintext-geloofsbriewe of langtermynsleutels buite die aanvanklike verkryging van die Ticket-Granting Ticket (TGT) kas nie.
- **Offline Sign-In**: Geen gekaste verifieerder sal vir Protected Users tydens aanmelding of ontsluiting geskep word nie, wat beteken dat offline-aanmelding nie vir hierdie rekeninge ondersteun word nie.

Hierdie beskermings word geaktiveer sodra ’n gebruiker wat lid van die **Protected Users group** is, by die toestel aanmeld. Dit verseker dat kritieke sekuriteitsmaatreëls ingestel is om teen verskeie metodes van geloofsbriefkompromittering te beskerm.

Vir meer gedetailleerde inligting, raadpleeg die amptelike [dokumentasie](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Tabel uit** [**die dokumentasie**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins            | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers       | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins        | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## References

- [1] [CreateProcessAsPPL – minimale PPL-proseslanseerder](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX-struktuur (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – agtergrond en interne werking](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode vir RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Gekaste geloofsbriewe - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest-verifikasie (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Bestuur Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Bylae C: Beskermde rekeninge en groepe in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}
