# Contournements du Sandbox d’Office sur macOS

{{#include ../../../../../banners/hacktricks-training.md}}

### Contournement du Sandbox de Word via les Launch Agents

L’application utilise un **Sandbox personnalisé** avec l’entitlement **`com.apple.security.temporary-exception.sbpl`**, et ce Sandbox personnalisé autorise l’écriture de fichiers n’importe où tant que le nom de fichier commence par `~$` : `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Par conséquent, l’évasion consistait simplement à **écrire un `plist`** LaunchAgent dans `~/Library/LaunchAgents/~$escape.plist`.

Consultez [**le rapport original ici**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Contournement du Sandbox de Word via les Login Items et zip

Rappelez-vous qu’après le premier contournement, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`, bien qu’après le patch de la vulnérabilité précédente, il ne soit plus possible d’écrire dans `/Library/Application Scripts` ou `/Library/LaunchAgents`.

Il a été découvert qu’il est possible, depuis le Sandbox, de créer un **Login Item** (des applications qui seront exécutées lorsque l’utilisateur se connecte). Cependant, ces applications **ne s’exécuteront que si** elles sont **notarisées**, et il **n’est pas possible d’ajouter des arguments** (il n’est donc pas possible de lancer simplement un reverse shell avec **`bash`**).

À la suite du précédent contournement du Sandbox, Microsoft a désactivé la possibilité d’écrire des fichiers dans `~/Library/LaunchAgents`. Cependant, il a été découvert que si vous placez un **fichier zip en tant que Login Item**, l’`Archive Utility` va simplement le **décompresser** à son emplacement actuel. Ainsi, puisque le dossier `LaunchAgents` de `~/Library` n’est pas créé par défaut, il était possible de **compresser un plist dans `LaunchAgents/~$escape.plist`** et de **placer** le fichier zip dans **`~/Library`**, afin qu’une fois décompressé, il atteigne la destination de persistence.

Consultez [**le rapport original ici**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Contournement du Sandbox de Word via les Login Items et .zshenv

(Rappelez-vous qu’après le premier contournement, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`.)

Cependant, la technique précédente avait une limitation : si le dossier **`~/Library/LaunchAgents`** existe parce qu’un autre logiciel l’a créé, elle échouerait. Une chaîne différente de Login Items a donc été découverte pour résoudre ce problème.

Un attaquant pouvait créer les fichiers **`.bash_profile`** et **`.zshenv`** contenant le payload à exécuter, puis les compresser et **écrire le fichier zip dans le dossier utilisateur de la victime** : **`~/~$escape.zip`**.

Il fallait ensuite ajouter le fichier zip aux **Login Items**, puis l’application **`Terminal`**. Lorsque l’utilisateur se reconnectait, le fichier zip était décompressé dans son dossier utilisateur, écrasant **`.bash_profile`** et **`.zshenv`** ; le terminal exécutait donc l’un de ces fichiers, selon que bash ou zsh était utilisé.

Consultez [**le rapport original ici**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Contournement du Sandbox de Word avec Open et les variables env

Depuis les processus placés dans le Sandbox, il est toujours possible d’invoquer d’autres processus avec l’utilitaire **`open`**. De plus, ces processus s’exécuteront dans **leur propre Sandbox**.

Il a été découvert que l’utilitaire open possède l’option **`--env`**, qui permet de lancer une application avec des variables **env spécifiques**. Il était donc possible de créer le **fichier `.zshenv`** dans un dossier **à l’intérieur** du **Sandbox**, puis d’utiliser `open` avec `--env` pour définir la variable **`HOME`** sur ce dossier et ouvrir l’application `Terminal`, qui exécutera le fichier `.zshenv` (pour une raison quelconque, il était également nécessaire de définir la variable `__OSINSTALL_ENVIROMENT`).

Consultez [**le rapport original ici**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Contournement du Sandbox de Word avec Open et stdin

L’utilitaire **`open`** prenait également en charge le paramètre **`--stdin`** (et après le contournement précédent, il n’était plus possible d’utiliser `--env`).

Le problème est que, même si **`python`** était signé par Apple, il **n’exécuterait pas** un script possédant l’attribut **`quarantine`**. Cependant, il était possible de lui transmettre un script via stdin, afin qu’il ne vérifie pas s’il était placé en quarantaine ou non :

1. Déposer un fichier **`~$exploit.py`** contenant des commandes Python arbitraires.
2. Exécuter _open_ **`–stdin='~$exploit.py' -a Python`**, ce qui lance l’application Python avec notre fichier déposé comme entrée standard. Python exécute volontiers notre code et, puisqu’il s’agit d’un processus enfant de **`launchd`**, il n’est pas soumis aux règles du Sandbox de Word.

## Références

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
