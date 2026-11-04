# Utekelezaji kupitia Drop-Share ya Kiendelezi cha VS Code

{{#include ../banners/hacktricks-training.md}}

Viendelezi vya VS Code na viendelezi vya Visual Studio VSSDK vyote hutumia ufungashaji wa `.vsix`, lakini vina manifest na runtime tofauti. SMB drop share inayoweza kuandikwa huwa njia ya utekelezaji **tu ikiwa** mtumiaji mwingine au kazi ya deployment itasakinisha vifurushi vyake kwenye VS Code. Kisha, kitendakazi cha kiendelezi cha `activate()` huendeshwa kwenye extension host kwa ruhusa za mtumiaji huyo. Kuandika tu faili ya `.vsix` kwenye share hakuitekelezi.<sup>[[1]](#references)[[2]](#references)</sup>

## Mchakato wa ufungashaji na uanzishaji

Kwanza thibitisha toleo la VS Code la mtumiaji wa kiendelezi na kwamba share inasawazishwa au kusakinishwa. Tengeneza kiendelezi cha TypeScript na uweke kitendo cha Node.js unachokusudia ndani ya `activate()`. Tumia tukio la uanzishaji linaloendeshwa bila mtumiaji kuchagua amri, kama vile `onStartupFinished`, kisha compile na ufungashe kiendelezi. `engines.vscode` ndiyo **kigezo cha uoanifu wa runtime**; kulinganisha `@types/vscode` na toleo la API lengwa ni hatua ya uoanifu wakati wa build, si sharti la wakati wa usakinishaji.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Kwa kihariri kinachoendesha VS Code 1.118, sehemu husika za `package.json` ni:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Ukaguzi mdogo wa `activate()` unaweza kutekeleza command na kurekodi matokeo yake kutoka kwa extension host. Badilisha kitendo cha majaribio tu baada ya kuthibitisha kuwa package imewashwa katika account/session inayotarajiwa. Tukio la `onStartupFinished` hutokea baada ya kuwasha, kwa hivyo si ushahidi wa utekelezaji hadi editor ianze na extension iwe imesakinishwa na kuwashwa.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Mshambuliaji mwenye ufikiaji wa kuandika kwenye share ya kupokelea anaweza kupakia package iliyojaribiwa na kusubiri kazi itakayoitumia. Katika mfano wa Checkpoint, ufikiaji wa share wa akaunti iliyorejeshwa ndio uliowezesha kuandika; akaunti ya mwanzo yenye mapendeleo ya chini iliweza kusoma share pekee. Tofautisha mahitaji hayo mawili. Kwa viendelezi vya **Visual Studio**, tumia sura tofauti ya [Visual Studio VSIX extension abuse](visual-studio-vsix-extension-abuse.md) badala ya mtiririko huu wa VS Code.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Matukio ya Uanzishaji](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Kuchapisha Viendelezi](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
