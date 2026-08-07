# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

L’application utilise un **custom Sandbox** avec l’entitlement **`com.apple.security.temporary-exception.sbpl`** et ce custom sandbox permet d’écrire des fichiers n’importe où tant que le nom du fichier commence par `~$` : `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Par conséquent, l’évasion consistait simplement à **écrire un `plist`** LaunchAgent dans `~/Library/LaunchAgents/~$escape.plist`.

Consultez le [**rapport original ici**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

Rappelez-vous qu’après le premier escape, Word pouvait écrire des fichiers arbitraires dont le nom commençait par `~$`, bien qu’après le patch de la vulnérabilité précédente, il ne soit plus possible d’écrire dans `/Library/Application Scripts` ou dans `/Library/LaunchAgents`.

Il a été découvert que depuis le sandbox, il était possible de créer un **Login Item** (des apps qui sont exécutées lorsque l’utilisateur se connecte). Cependant, ces apps **ne s’exécuteront pas à moins** d’être **notarized**, et il **n’est pas possible d’ajouter des arguments** (il n’est donc pas possible d’exécuter directement un reverse shell avec **`bash`**).

À la suite du précédent Sandbox bypass, Microsoft a désactivé la possibilité d’écrire des fichiers dans `~/Library/LaunchAgents`. Cependant, il a été découvert que si vous placez un **fichier zip comme Login Item**, l’`Archive Utility` va simplement le **décompresser** à son emplacement actuel. Ainsi, comme le dossier `LaunchAgents` de `~/Library` n’est pas créé par défaut, il était possible de **zipper un plist dans `LaunchAgents/~$escape.plist`** et de **placer** le fichier zip dans **`~/Library`**, afin qu’en le décompressant, il atteigne la destination de persistence.

Consultez le [**rapport original ici**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(Rappelez-vous qu’après le premier escape, Word pouvait écrire des fichiers arbitraires dont le nom commençait par `~$`.)

Cependant, la technique précédente avait une limitation : si le dossier **`~/Library/LaunchAgents`** existait parce qu’un autre software l’avait créé, elle échouait. Une autre chaîne de Login Items a donc été découverte pour résoudre ce problème.

Un attacker pouvait créer les fichiers **`.bash_profile`** et **`.zshenv`** contenant le payload à exécuter, puis les zipper et **écrire le zip dans le dossier utilisateur de la victime** : **`~/~$escape.zip`**.

Ajoutez ensuite le fichier zip aux **Login Items**, puis l’app **`Terminal`**. Lorsque l’utilisateur se reconnecterait, le fichier zip serait décompressé dans son dossier utilisateur, écrasant **`.bash_profile`** et **`.zshenv`** ; le terminal exécuterait donc l’un de ces fichiers (selon que bash ou zsh est utilisé).

Consultez le [**rapport original ici**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Depuis des processus sandboxés, il est toujours possible d’invoquer d’autres processus à l’aide de l’utilitaire **`open`**. De plus, ces processus s’exécuteront **dans leur propre sandbox**.

Il a été découvert que l’utilitaire open possède l’option **`--env`**, qui permet d’exécuter une app avec des variables **env** spécifiques. Il était donc possible de créer le fichier **`.zshenv`** dans un dossier **à l’intérieur** du **sandbox**, puis d’utiliser `open` avec `--env` en définissant la variable **`HOME`** sur ce dossier et en ouvrant l’app `Terminal`, qui exécuterait le fichier `.zshenv` (pour une raison inconnue, il était également nécessaire de définir la variable `__OSINSTALL_ENVIROMENT`).

Consultez le [**rapport original ici**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

L’utilitaire **`open`** supportait également le paramètre **`--stdin`** (et après le bypass précédent, il n’était plus possible d’utiliser `--env`).

Le problème est que même si **`python`** était signé par Apple, il **n’exécuterait pas** un script avec l’attribut **`quarantine`**. Cependant, il était possible de lui transmettre un script via stdin, afin qu’il ne vérifie pas s’il était quarantined ou non :

1. Déposez un fichier **`~$exploit.py`** contenant des commandes Python arbitraires.
2. Exécutez _open_ **`–stdin='~$exploit.py' -a Python`**, ce qui lance l’app Python avec notre fichier déposé comme entrée standard. Python exécute volontiers notre code et, comme il s’agit d’un processus enfant de **`launchd`**, il n’est pas soumis aux règles du sandbox de Word.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
