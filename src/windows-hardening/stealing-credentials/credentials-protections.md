# Windows Credentials Beskermings

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Die [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, geïntroduceer met Windows XP, is ontwerp vir verifikasie via die HTTP Protocol en is **enabled by default on Windows XP through Windows 8.0 and Windows Server 2003 to Windows Server 2012**. Hierdie standaardinstelling lei tot **plain-text password storage in LSASS** (Local Security Authority Subsystem Service). 'n Aanvaller kan Mimikatz gebruik om **extract these credentials** deur die volgende uit te voer:
```bash
sekurlsa::wdigest
```
Om **hierdie funksie af of aan te skakel**, moet die _**UseLogonCredential**_ en _**Negotiate**_ registersleutels binne _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ op "1" gestel word. As hierdie sleutels **afwesig of op "0" gestel is**, is WDigest **uitgeskakel**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

**Protected Process (PP)** en **Protected Process Light (PPL)** is **Windows-kernvlakbeskerming** wat ontwerp is om ongemagtigde toegang tot sensitiewe prosesse soos **LSASS** te voorkom. Ingevoer in **Windows Vista**, is die **PP-model** oorspronklik geskep vir **DRM**-afdwinging en het slegs binaries wat met 'n **spesiale media-sertifikaat** onderteken is toegelaat om beskerm te word. 'n Proses wat as **PP** gemerk is, kan slegs deur ander prosesse wat **ook PP** is en 'n **gelyke of hoër beskermingsvlak** het, benader word, en selfs dan **slegs met beperkte toegangsregte** tensy dit spesifiek toegestaan is.

**PPL**, ingevoer in **Windows 8.1**, is 'n meer buigsame weergawe van PP. Dit laat **breër gebruiksgevalle** toe (bv., LSASS, Defender) deur **"protection levels"** in te stel gebaseer op die **digital signature’s EKU (Enhanced Key Usage)** veld. Die beskermingsvlak word gestoor in die `EPROCESS.Protection` veld, wat 'n `PS_PROTECTION` struktuur is met:
- **Type** (`Protected` or `ProtectedLight`)
- **Signer** (bv., `WinTcb`, `Lsa`, `Antimalware`, ens.)

Hierdie struktuur is in een byte gepak en bepaal **wie wie kan benader**:
- **Hoër signer-waardes kan laer eenhede benader**
- **PPLs kan nie PPs benader nie**
- **Onbeskermde prosesse kan nie enige PPL/PP benader nie**

### Wat jy vanuit 'n offensiewe oogpunt moet weet

- Wanneer **LSASS** as 'n **PPL** loop, misluk pogings om dit te open met `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` vanaf 'n normale admin-konteks met `0x5 (Access Denied)`, selfs al is `SeDebugPrivilege` geaktiveer.
- Jy kan die LSASS-beskermingsvlak nagaan deur hulpmiddels soos **Process Hacker** te gebruik of programmaties die `EPROCESS.Protection` waarde te lees.
- LSASS sal tipies `PsProtectedSignerLsa-Light` (`0x41`) hê, wat slegs benader kan word deur prosesse wat met 'n hoër vlak signer onderteken is, soos `WinTcb` (`0x61` of `0x62`).
- PPL is 'n **Userland-only** beperking; **kernel-level** kode kan dit volledig omseil.
- LSASS wat PPL is verhoed nie **credential dumping** as jy kernel shellcode kan uitvoer of 'n hooggeprivilegieerde proses met die nodige toegang kan benut nie.
- Om PPL te stel of te verwyder vereis 'n herbegin of **Secure Boot/UEFI**-instellings, wat die PPL-instelling kan behou selfs nadat registerveranderinge teruggedra is.

### Create a PPL process at launch (documented API)

Windows bied 'n gedokumenteerde manier om 'n Protected Process Light-vlak te versoek vir 'n child process tydens skepping deur die uitgebreide opstartattribuutlys te gebruik. Dit omseil nie ondertekeningsvereistes nie — die teikenbeeld moet onderteken wees vir die versoekte signer class.

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
Aantekeninge en beperkings:
- Gebruik `STARTUPINFOEX` met `InitializeProcThreadAttributeList` en `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, en gee dan `EXTENDED_STARTUPINFO_PRESENT` deur aan `CreateProcess*`.
- Die protection `DWORD` kan gestel word op konstantes soos `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, of `PROTECTION_LEVEL_LSA_LIGHT`.
- Die child begin slegs as PPL as sy image vir daardie signer-klas geteken is; anders falen prosescreasie, gewoonlik met `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Dit is nie 'n omseiling nie — dit is 'n ondersteunde API bedoel vir behoorlik getekende images. Nuttig om tools te verhardeer of PPL-beskermde konfigurasies te valideer.

Example CLI using a minimal loader:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opsies om PPL-beskerming te omseil:**

As jy LSASS wil dump ten spyte van PPL, het jy 3 hoofopsies:
1. **Gebruik 'n ondertekende kernel driver (bv. Mimikatz + mimidrv.sys)** om **LSASS se beskermingsvlag te verwyder**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** om pasgemaakte kernel-kode uit te voer en die beskerming te deaktiveer. Gereedskap soos **PPLKiller**, **gdrv-loader**, of **kdmapper** maak dit moontlik.
3. **Steel 'n bestaande LSASS-handle** van 'n ander proses wat dit oop het (bv. 'n AV-proses), en **dupliseer dit** dan in jou proses. Dit is die basis van die `pypykatz live lsa --method handledup` tegniek.
4. **Misbruik 'n bevoorregte proses** wat jou toelaat om arbitrêre kode in sy adresruimte of binne 'n ander bevoorregte proses te laai, en sodoende die PPL-beperkings omseil. Jy kan 'n voorbeeld hiervan sien in [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) of [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Kontroleer huidige status van LSA-beskerming (PPL/PP) vir LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Wanneer jy **`mimikatz privilege::debug sekurlsa::logonpasswords`** uitvoer, sal dit waarskynlik misluk met foutkode `0x00000005` as gevolg hiervan.

- Vir meer inligting oor hierdie kontrole: [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, 'n funksie uitsluitlik beskikbaar in **Windows 10 (Enterprise and Education editions)**, verbeter die veiligheid van masjienkredensiale deur gebruik te maak van **Virtual Secure Mode (VSM)** en **Virtualization Based Security (VBS)**. Dit maak gebruik van CPU-virtualiseringsuitbreidings om sleutelprosesse te isoleer in 'n beskermde geheuegebied, buite die bereik van die hoofbedryfstelsel. Hierdie isolasie verseker dat selfs die kernel nie toegang tot die geheue in VSM het nie, wat kredensiale effektief beskerm teen aanvalle soos **pass-the-hash**. Die **Local Security Authority (LSA)** werk binne hierdie veilige omgewing as 'n trustlet, terwyl die **LSASS**-proses in die hoof-OS slegs as 'n kommunikeerder met die VSM se LSA optree.

Standaard is **Credential Guard** nie geaktiveer nie en vereis handmatige aktivering binne 'n organisasie. Dit is 'n belangrike maatstaf om die sekuriteit teen gereedskap soos **Mimikatz** te verbeter, wat belemmer word in hul vermoë om kredensiale te onttrek. Nietemin kan kwesbaarhede steeds uitgebuit word deur die toevoeging van pasgemaakte **Security Support Providers (SSP)** om kredensiale in duidelike teks te vang tydens aanmeldpogings.

Om die aktiveringsstatus van **Credential Guard** te verifieer, kan die registerwaarde _**LsaCfgFlags**_ onder _**HKLM\System\CurrentControlSet\Control\LSA**_ nagegaan word. 'n Waarde van "**1**" dui op aktivering met **UEFI lock**, "**2**" sonder lock, en "**0**" beteken dit is nie aangeskakel nie. Hierdie registerkontrole is, al is dit 'n sterk aanduiding, nie die enigste stap om Credential Guard te aktiveer nie. Gedetaileerde leiding en 'n PowerShell-skrip om hierdie funksie te aktiveer is aanlyn beskikbaar.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Vir 'n omvattende begrip en instruksies oor die aktivering van **Credential Guard** in Windows 10 en die outomatiese aktivering daarvan op versoenbare stelsels van **Windows 11 Enterprise and Education (version 22H2)**, besoek [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Verdere besonderhede oor die implementering van custom SSPs vir credential capture word verskaf in [hierdie gids](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** het verskeie nuwe sekuriteitskenmerke bekendgestel, insluitend die _**Restricted Admin mode for RDP**_. Hierdie modus is ontwerp om sekuriteit te verbeter deur die risiko's wat geassosieer word met [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) aanvalle te verminder.

Tradisioneel, wanneer daar via RDP met 'n afstandrekenaar verbind word, word jou credentials op die teikenmasjien gestoor. Dit vorm 'n beduidende sekuriteitsrisiko, veral by die gebruik van rekeninge met verhoogde voorregte. Met die bekendstelling van _**Restricted Admin mode**_ word hierdie risiko egter aansienlik verminder.

Wanneer 'n RDP-verbinding geïnisieer word met die opdrag **mstsc.exe /RestrictedAdmin**, word otentisering na die afstandrekenaar uitgevoer sonder om jou credentials daarop te stoor. Hierdie benadering verseker dat, in die geval van 'n malware-infeksie of as 'n kwaadwillige gebruiker toegang tot die afstandbediener kry, jou credentials nie gekompromitteer word nie, aangesien hulle nie op die bediener gestoor word nie.

Dit is belangrik om daarop te let dat in **Restricted Admin mode** pogings om netwerkbronne van die RDP-sessie te bereik nie jou persoonlike credentials sal gebruik nie; in plaas daarvan word die **machine's identity** gebruik.

Hierdie funksie is 'n beduidende stap vorentoe in die beveiliging van remote desktop-verbindinge en in die beskerming van sensitiewe inligting teen blootstelling in die geval van 'n sekuriteitsinbreuk.

![](../../images/RAM.png)

Vir meer gedetailleerde inligting, sien [hierdie bron](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows beveilig **domain credentials** via die **Local Security Authority (LSA)** en ondersteun aanmeldprosesse met sekuriteitsprotokolle soos **Kerberos** en **NTLM**. 'n Sleutelfunksie van Windows is die vermoë om die **last ten domain logins** te cache, sodat gebruikers steeds toegang tot hul rekenaars kan hê selfs as die **domain controller** aflyn is — 'n voordeel vir laptopgebruikers wat dikwels weg van hul maatskappy se netwerk is.

Die aantal gecachede aanmeldings kan aangepas word via 'n spesifieke **registry key or group policy**. Om hierdie instelling te sien of te verander, word die volgende opdrag gebruik:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Toegang tot hierdie gecachede credentials word streng beheer, slegs die **SYSTEM**-rekening het die nodige toestemmings om dit te besigtig. Administrateurs wat toegang tot hierdie inligting benodig, moet dit doen met SYSTEM-gebruikersprivileges. Die credentials word gestoor by: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** kan gebruik word om hierdie gecachede credentials te onttrek met die opdrag `lsadump::cache`.

Vir meer besonderhede verskaf die oorspronklike [source](http://juggernaut.wikidot.com/cached-credentials) omvattende inligting.

## Protected Users

Membership in the **Protected Users group** introduceer verskeie sekuriteitsverbeterings vir gebruikers wat hoër vlakke van beskerming teen credential theft en misbruik verseker:

- **Credential Delegation (CredSSP)**: Selfs indien die Group Policy instelling vir **Allow delegating default credentials** geaktiveer is, sal plain text credentials van Protected Users nie gecache word nie.
- **Windows Digest**: Vanaf **Windows 8.1 and Windows Server 2012 R2** sal die stelsel nie plain text credentials van Protected Users cache nie, ongeag die Windows Digest-status.
- **NTLM**: Die stelsel sal nie Protected Users se plain text credentials of NT one-way functions (NTOWF) cache nie.
- **Kerberos**: Vir Protected Users sal Kerberos-authentisering nie **DES** of **RC4 keys** genereer nie, en dit sal ook nie plain text credentials of langtermynsleutels buite die aanvanklike Ticket-Granting Ticket (TGT) verkryging cache nie.
- **Offline Sign-In**: Protected Users sal geen gecachede verifiërer by aanmelding of ontsluiting hê nie, wat beteken dat offline sign-in nie vir hierdie rekeninge ondersteun word nie.

Hierdie beskermings tree in werking sodra 'n gebruiker wat lid is van die **Protected Users group** by die toestel aanmeld. Dit verseker dat kritieke sekuriteitsmaatreëls ingestel is om teen verskeie metodes van credential compromise te beskerm.

Vir meer gedetailleerde inligting, raadpleeg die amptelike [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

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

## Verwysings

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
