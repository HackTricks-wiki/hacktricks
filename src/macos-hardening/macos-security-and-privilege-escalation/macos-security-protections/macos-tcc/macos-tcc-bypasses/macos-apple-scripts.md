# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

C'est un langage de script utilisé pour l'automatisation des tâches **interagissant avec des processus distants**. Il facilite assez bien **la demande à d'autres processus d'effectuer certaines actions**. **Malware** peut abuser de ces fonctionnalités pour exploiter des fonctions exportées par d'autres processus.\
Par exemple, un malware pourrait **injecter du code JS arbitraire dans les pages ouvertes du navigateur**. Ou **cliquer automatiquement** sur certaines autorisations demandées à l'utilisateur ;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Voici quelques exemples : [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trouvez plus d'infos sur les malwares utilisant des applescripts [**ici**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Les scripts Apple peuvent être facilement "**compilés**". Ces versions peuvent être facilement "**décompilées**" avec `osadecompile`

Cependant, ces scripts peuvent également être **exportés en tant que "Lecture seule"** (via l'option "Exporter...") :

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
et dans ce cas, le contenu ne peut pas être décompilé même avec `osadecompile`

Cependant, il existe encore des outils qui peuvent être utilisés pour comprendre ce type d'exécutables, [**lisez cette recherche pour plus d'infos**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). L'outil [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) avec [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) sera très utile pour comprendre comment le script fonctionne.

{{#include ../../../../../banners/hacktricks-training.md}}
