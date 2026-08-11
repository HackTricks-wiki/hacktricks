# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript est un langage d’automatisation capable d’envoyer des Apple Events aux applications scriptables. Avec les autorisations appropriées, un malware peut injecter du JavaScript dans un onglet de navigateur scriptable ou utiliser System Events/Accessibility pour cliquer sur une boîte de dialogue d’autorisation. Apple Events et Accessibility sont des services TCC distincts et nécessitent généralement les approbations respectives de l’utilisateur.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Le repository `abbeycode/AppleScripts` contient des exemples d'automatisation.<sup>[[7]](#references)</sup>\
Trouvez plus d'informations sur les malware utilisant des applescripts [**ici**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Particularités de l'automatisation / TCC

Les approbations Apple Events sont **directionnelles** : la demande concerne une paire **processus source -> processus cible**. Une fois que l'utilisateur clique sur **Autoriser**, les futures demandes du même source vers la même cible sont autorisées jusqu'à la réinitialisation de l'entrée. Lors des tests, accorder une fois l'autorisation `Terminal -> Finder` ou `Terminal -> System Events` suffit pour réutiliser ensuite cette permission sans nouvelle fenêtre contextuelle.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Ceci est particulièrement pertinent lorsque la **cible** est **Finder**, car Finder dispose toujours de **Full Disk Access**, même s'il n'apparaît pas dans l'interface utilisateur FDA. Par conséquent, tout hôte qui dispose déjà de l'**Automation** sur Finder peut être utilisé comme proxy AppleScript/JXA pour accéder aux fichiers protégés par TCC.<sup>[[1]](#references)</sup> Les payloads génériques Finder et System Events sont déjà documentés dans [la page TCC principale](../README.md) et dans [la page Apple Events](../macos-apple-events.md).

### Tradecraft offensif moderne

`/usr/bin/osascript` n'est que le point d'entrée le plus visible. AppleScript et JXA peuvent également être exécutés depuis des **binaires Mach-O** via **`NSAppleScript`** / **`OSAScript`**, ce qui est utile à la fois pour l'évasion et pour opérer au sein d'un hôte qui dispose déjà de grants TCC intéressants.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Si vous créez un helper personnalisé qui envoie directement des Apple Events, lui attribuer une **véritable identité d’application** rend les tests et les opérations beaucoup plus fiables. En pratique, cela signifie intégrer un `Info.plist` avec `CFBundleIdentifier` et `NSAppleEventsUsageDescription`, signer le binaire et accorder l’entitlement `com.apple.security.automation.apple-events`. Sinon, l’invite Apple Events est souvent attribuée au **parent host** (par exemple `Terminal`), ou l’exécution de `NSAppleScript` échoue simplement avec des erreurs déroutantes `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Les AppleScripts peuvent être enregistrés sous forme compilée et normalement décompilés avec `osadecompile`.

Cependant, ces scripts peuvent également être **exportés en tant que "Read only"** (via l’option "Export...") :

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
Dans ce cas, `osadecompile` refuse de récupérer le code source normal, mais le bytecode et la terminologie Apple Event peuvent toujours être analysés.

La recherche de SentinelOne sur les scripts run-only décrit comment récupérer la structure malgré cette restriction. `applescript-disassembler` et `aevt_decompile` permettent d’inspecter le script compilé et les données Apple Event.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Contourner les protections de confidentialité utilisateur TCC de macOS par accident et par conception](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Faire fonctionner AppleScript dans les outils CLI macOS : les parties non documentées](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Comment les acteurs offensifs utilisent AppleScript pour attaquer macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Aventures dans le reverse engineering de scripts AppleScript run-only malveillants](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [Exemples d’AppleScripts de abbeycode](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
