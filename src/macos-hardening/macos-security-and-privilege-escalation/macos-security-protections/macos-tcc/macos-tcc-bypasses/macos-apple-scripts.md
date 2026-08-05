# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

C'est un langage de scripting utilisé pour automatiser des tâches en **interagissant avec des processus distants**. Il permet assez facilement de **demander à d'autres processus d'effectuer certaines actions**. Les **Malware** peuvent abuser de ces fonctionnalités afin d'exploiter les fonctions exportées par d'autres processus.\
Par exemple, un Malware pourrait **injecter du code JS arbitraire dans les pages ouvertes d'un navigateur**. Ou encore **cliquer automatiquement** sur certaines autorisations demandées à l'utilisateur;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Voici quelques exemples : [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trouvez plus d'informations sur les malwares utilisant des AppleScripts [**ici**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automatisation / particularités de TCC

Les autorisations Apple Events sont **directionnelles** : l'invite concerne une paire **processus source -> processus cible**. Une fois que l'utilisateur clique sur **Allow**, les futures requêtes du même processus source vers le même processus cible sont autorisées jusqu'à la réinitialisation de l'entrée. Lors des tests, accorder une fois l'autorisation `Terminal -> Finder` ou `Terminal -> System Events` suffit pour réutiliser ultérieurement cette permission sans afficher une nouvelle fenêtre contextuelle.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Ceci est particulièrement pertinent lorsque la **cible** est **Finder**, car Finder dispose toujours de **Full Disk Access**, même s'il n'apparaît pas dans l'interface utilisateur FDA. Par conséquent, tout hôte qui dispose déjà de l'**Automation** sur Finder peut être utilisé comme proxy AppleScript/JXA pour accéder aux fichiers protégés par TCC.<sup>[[1]](#references)</sup> Les payloads génériques Finder et System Events sont déjà documentés dans [la page TCC principale](../README.md) et dans [la page Apple Events](../macos-apple-events.md).

### Techniques offensives modernes

`/usr/bin/osascript` n'est que le point d'entrée le plus visible. AppleScript et JXA peuvent également être exécutés depuis des **Mach-O binaries** via **`NSAppleScript`** / **`OSAScript`**, ce qui est utile à la fois pour l'évasion et pour s'exécuter au sein d'un hôte qui dispose déjà d'éléments TCC intéressants.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Si vous créez un helper personnalisé qui envoie directement des Apple Events, lui attribuer une **real app identity** rend les tests et les opérations beaucoup plus fiables. En pratique, cela signifie intégrer un `Info.plist` avec `CFBundleIdentifier` et `NSAppleEventsUsageDescription`, signer le binaire et accorder l’entitlement `com.apple.security.automation.apple-events`. Sinon, l’invite Apple Events est souvent attribuée au **parent host** (par exemple `Terminal`) ou l’exécution de `NSAppleScript` échoue simplement avec des erreurs déroutantes `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Les Apple scripts peuvent être facilement "**compiled**". Ces versions peuvent facilement être "**decompiled**" avec `osadecompile`

Cependant, ces scripts peuvent également être **exportés en tant que "Read only"** (via l’option "Export...") :

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
et dans ce cas, le contenu ne peut pas être décompilé, même avec `osadecompile`

Cependant, certains outils peuvent encore être utilisés pour comprendre ce type d’exécutables, [**consultez cette recherche pour plus d’informations**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> L’outil [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler), associé à [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile), sera très utile pour comprendre le fonctionnement du script.

## Références

- [1] [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [How Offensive Actors Use AppleScript For Attacking macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Adventures in Reversing Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
