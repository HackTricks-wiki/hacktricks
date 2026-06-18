# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

C'est un langage de script utilisé pour l'automatisation de tâches en **interagissant avec des processus distants**. Il permet très facilement de **demander à d'autres processus d'effectuer certaines actions**. Les **malware** peuvent abuser de ces fonctionnalités pour exploiter des fonctions exportées par d'autres processus.\
Par exemple, un malware pourrait **injecter du code JS arbitraire dans des pages ouvertes dans le navigateur**. Ou **cliquer automatiquement** sur certaines autorisations demandées à l'utilisateur;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Here vous avez quelques exemples : [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trouvez plus d'infos sur les malware utilisant applescripts [**ici**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Les approbations Apple Events sont **directionnelles** : l’invite concerne une paire **processus source -> processus cible**. Une fois que l’utilisateur clique sur **Allow**, les futures requêtes du même source vers la même cible sont autorisées jusqu’à ce que l’entrée soit réinitialisée. Lors des tests, accorder `Terminal -> Finder` ou `Terminal -> System Events` une seule fois suffit pour réutiliser plus tard la permission sans autre popup.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Ceci est particulièrement pertinent lorsque la **cible** est **Finder**, car Finder a toujours **Full Disk Access** même s’il n’apparaît pas dans l’UI FDA. Par conséquent, tout hôte qui a déjà Automation sur Finder peut être utilisé comme proxy AppleScript/JXA pour accéder à des fichiers protégés par TCC. Les payloads génériques pour Finder et System Events sont déjà documentés dans [la page principale TCC](../README.md) et dans [la page Apple Events](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` n’est que le point d’entrée le plus visible. AppleScript et JXA peuvent aussi s’exécuter depuis des **Mach-O binaries** via **`NSAppleScript`** / **`OSAScript`**, ce qui est utile à la fois pour l’évasion et pour rester à l’intérieur d’un hôte qui possède déjà des autorisations TCC intéressantes.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Si vous construisez un helper personnalisé qui envoie directement des Apple Events, lui donner une **vraie identité d’app** rend les tests et les opérations beaucoup plus fiables. En pratique, cela signifie intégrer un `Info.plist` avec `CFBundleIdentifier` et `NSAppleEventsUsageDescription`, signer le binaire, et accorder l’entitlement `com.apple.security.automation.apple-events`. Sinon, l’invite Apple Events est souvent attribuée au **parent host** (par exemple `Terminal`) ou l’exécution de `NSAppleScript` échoue simplement avec des erreurs confuses `-1750` / `errOSASystemError`.

Les Apple scripts peuvent être facilement "**compiled**". Ces versions peuvent être facilement "**decompiled**" avec `osadecompile`

Cependant, ces scripts peuvent aussi être **exported as "Read only"** (via l’option "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
et dans ce cas le contenu ne peut pas être décompilé même avec `osadecompile`

Cependant, il existe encore quelques outils qui peuvent être utilisés pour comprendre ce type d'exécutables, [**lisez cette recherche pour plus d'infos**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). L'outil [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) avec [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) sera très utile pour comprendre comment le script fonctionne.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
