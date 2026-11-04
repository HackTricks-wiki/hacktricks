# Exécution via un partage de dépôt d’extensions VS Code

{{#include ../banners/hacktricks-training.md}}

Les extensions VS Code et les extensions Visual Studio VSSDK utilisent toutes deux un empaquetage `.vsix`, mais leurs manifestes et leurs environnements d’exécution sont différents. Un partage SMB de dépôt accessible en écriture ne devient un vecteur d’exécution **que si** un autre utilisateur ou un job de déploiement installe ses packages dans VS Code. La fonction `activate()` de l’extension s’exécute alors dans l’hôte d’extension avec les privilèges de cet utilisateur. Le simple fait d’écrire un `.vsix` sur un partage ne l’exécute pas.<sup>[[1]](#references)[[2]](#references)</sup>

## Workflow d’empaquetage et d’activation

Vérifiez d’abord la version de VS Code utilisée et que le partage est bien synchronisé ou installé. Générez une extension TypeScript et placez l’action Node.js souhaitée dans `activate()`. Utilisez un événement d’activation qui se déclenche sans commande sélectionnée par l’utilisateur, comme `onStartupFinished`, puis compilez et empaquetez l’extension. `engines.vscode` est la **barrière de compatibilité à l’exécution** ; faire correspondre `@types/vscode` à la version de l’API cible est une mesure de compatibilité à la compilation, et non une exigence à l’installation.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Pour un éditeur exécutant VS Code 1.118, les champs pertinents de `package.json` sont :<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Une vérification minimale de `activate()` peut exécuter une commande et consigner sa sortie depuis l’hôte de l’extension. Remplacez l’action de test uniquement après avoir vérifié que le package est activé dans le compte/la session attendus. L’événement `onStartupFinished` se déclenche après le démarrage : il ne prouve donc pas que l’extension s’est exécutée tant que l’éditeur n’a pas réellement démarré et que l’extension n’est pas installée et activée.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Un attaquant ayant un accès en écriture au partage de dépôt peut téléverser le package testé et attendre que le job consommateur s’exécute. Dans l’exemple Checkpoint, l’accès au partage du compte restauré fournissait cet accès en écriture ; le compte de départ à faibles privilèges ne pouvait que lire le partage. Ne confondez pas ces deux prérequis. Pour les extensions **Visual Studio**, consultez le chapitre distinct [Abus des extensions Visual Studio VSIX](visual-studio-vsix-extension-abuse.md) plutôt que ce workflow VS Code.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB : Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Événements d’activation](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Publication d’extensions](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
