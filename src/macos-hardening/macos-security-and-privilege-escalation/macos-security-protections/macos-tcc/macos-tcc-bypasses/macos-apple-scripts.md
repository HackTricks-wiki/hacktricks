# Apple Scripts macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

C'est un langage de script utilisé pour l'automatisation de tâches **en interagissant avec des processus distants**. Il permet assez facilement de **demander à d'autres processus d'effectuer certaines actions**. Les **malware** peuvent abuser de ces fonctionnalités pour exploiter les fonctions exportées par d'autres processus.\
Par exemple, un malware pourrait **injecter du code JS arbitraire dans les pages ouvertes d'un navigateur**. Ou effectuer un **auto click** sur certaines autorisations demandées à l'utilisateur&nbsp;;<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Voici quelques exemples : [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trouvez plus d’informations sur les malware utilisant des applescripts [**ici**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automatisation / particularités de TCC

Les approbations Apple Events sont **directionnelles** : la demande concerne une paire **processus source -> processus cible**. Une fois que l’utilisateur a cliqué sur **Allow**, les futures demandes du même source vers la même cible sont autorisées jusqu’à la réinitialisation de l’entrée. Lors des tests, accorder une seule fois l’autorisation `Terminal -> Finder` ou `Terminal -> System Events` suffit pour réutiliser cette permission ultérieurement sans afficher de nouvelle popup.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
C'est particulièrement pertinent lorsque la **cible** est **Finder**, car Finder dispose toujours de **Full Disk Access**, même s'il n'apparaît pas dans l'interface utilisateur FDA. Par conséquent, tout hôte qui dispose déjà de l'Automation sur Finder peut être utilisé comme proxy AppleScript/JXA pour accéder aux fichiers protégés par TCC.<sup>[1]</sup> Les payloads génériques de Finder et de System Events sont déjà documentés dans [la page principale sur TCC](../README.md) et dans [la page Apple Events](../macos-apple-events.md).

### Tradecraft offensive moderne

`/usr/bin/osascript` n'est que le point d'entrée le plus visible. AppleScript et JXA peuvent également être exécutés depuis des **binaires Mach-O** via **`NSAppleScript`** / **`OSAScript`**, ce qui est utile à la fois pour l'évasion et pour s'intégrer à un hôte qui dispose déjà d'autorisations TCC intéressantes.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Si vous créez un helper personnalisé qui envoie directement des Apple Events, lui attribuer une **identité d'application réelle** rend les tests et les opérations beaucoup plus fiables. En pratique, cela signifie intégrer un `Info.plist` avec `CFBundleIdentifier` et `NSAppleEventsUsageDescription`, signer le binaire et accorder l'entitlement `com.apple.security.automation.apple-events`. Sinon, l'invite Apple Events est souvent attribuée au **processus hôte parent** (par exemple `Terminal`), ou l'exécution de `NSAppleScript` échoue simplement avec des erreurs déroutantes `-1750` / `errOSASystemError`.<sup>[2]</sup>

Les scripts Apple peuvent être facilement "**compilés**". Ces versions peuvent être facilement "**décompilées**" avec `osadecompile`

Cependant, ces scripts peuvent également être **exportés en tant que "Read only"** (via l'option "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
et dans ce cas, le contenu ne peut pas être décompilé, même avec `osadecompile`

Cependant, certains outils peuvent encore être utilisés pour comprendre ce type d’exécutables, [**consultez cette recherche pour plus d’informations**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> L’outil [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler), avec [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile), sera très utile pour comprendre le fonctionnement du script.

## Références

- [1] [Contourner les protections de confidentialité utilisateur de macOS TCC, accidentellement et intentionnellement](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Faire fonctionner AppleScript dans les outils CLI macOS : les aspects non documentés](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Comment les acteurs offensifs utilisent AppleScript pour attaquer macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Aventures dans le reverse engineering de Run-Only AppleScripts malveillants](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
