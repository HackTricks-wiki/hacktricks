# Esecuzione tramite Drop-Share di estensioni VS Code

{{#include ../banners/hacktricks-training.md}}

Le estensioni di VS Code e quelle di Visual Studio VSSDK usano entrambe il formato `.vsix`, ma hanno manifest e runtime diversi. Una share SMB di drop scrivibile diventa un percorso di esecuzione **solo se** un altro utente o un processo di distribuzione installa i pacchetti in VS Code. A quel punto, la funzione `activate()` dell'estensione viene eseguita nell'extension host con i privilegi di quell'utente. Scrivere semplicemente un file `.vsix` su una share non lo esegue.<sup>[[1]](#references)[[2]](#references)</sup>

## Flusso di lavoro di packaging e attivazione

Per prima cosa, verifica la versione di VS Code usata per l'installazione e che la share sia effettivamente sincronizzata o installata. Genera un'estensione TypeScript e inserisci l'azione Node.js desiderata in `activate()`. Usa un evento di attivazione che venga eseguito senza che l'utente selezioni un comando, come `onStartupFinished`, quindi compila e crea il pacchetto dell'estensione. `engines.vscode` è il **vincolo di compatibilità del runtime**; allineare `@types/vscode` alla versione API di destinazione è una misura di compatibilità in fase di build, non un requisito di installazione.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Per un editor che esegue VS Code 1.118, i campi pertinenti di `package.json` sono:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Un controllo minimo di `activate()` può eseguire un comando e registrare il relativo output dall’host dell’estensione. Sostituisci l’azione di test solo dopo aver verificato che il pacchetto sia attivato nell’account/sessione prevista. L’evento `onStartupFinished` viene eseguito dopo l’avvio, quindi non dimostra che il codice sia stato eseguito finché l’editor non viene effettivamente avviato e l’estensione non è installata e abilitata.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Un attaccante con accesso in scrittura alla share di drop può caricare il pacchetto testato e attendere il job che lo consuma. Nell'esempio Checkpoint, l'accesso alla share dell'account ripristinato ha fornito tale accesso in scrittura; l'account iniziale con privilegi limitati poteva solo leggere la share. Tieni distinti questi due prerequisiti. Per le estensioni di **Visual Studio**, consulta il capitolo separato [Abuso delle estensioni VSIX di Visual Studio](visual-studio-vsix-extension-abuse.md), invece di seguire questo flusso di lavoro di VS Code.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Eventi di attivazione](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Pubblicazione delle estensioni](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
