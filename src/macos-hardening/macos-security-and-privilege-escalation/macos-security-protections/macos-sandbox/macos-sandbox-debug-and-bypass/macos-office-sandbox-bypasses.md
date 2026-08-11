# Contournements du sandbox d’Office pour macOS

{{#include ../../../../../banners/hacktricks-training.md}}

Les éléments suivants sont des **escapes historiques du sandbox de Microsoft Office pour Mac**. Ils documentent des erreurs réutilisables au niveau des frontières de confiance, mais il ne faut pas supposer que les combinaisons Office/macOS corrigées sont vulnérables sans reproduire exactement la version et la policy.

### Contournement du sandbox de Word via LaunchAgents

L’application concernée utilisait une règle de sandbox personnalisée via `com.apple.security.temporary-exception.sbpl`. Elle autorisait les fichiers ordinaires dont le basename commençait par `~$` : `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Par conséquent, l’escape consistait simplement à **écrire un `plist`** LaunchAgent dans `~/Library/LaunchAgents/~$escape.plist`.

Consultez le [**rapport original ici**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Contournement du sandbox de Word via Login Items et zip

Rappelez-vous qu’après le premier escape, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`, bien qu’après le patch de la vulnérabilité précédente, il n’était plus possible d’écrire dans `/Library/Application Scripts` ou dans `/Library/LaunchAgents`.

Le sandbox concerné autorisait la création d’un **Login Item**, qui se lance lorsque l’utilisateur ouvre une session. Le chemin démontré nécessitait une application signée/notarisée acceptable et n’autorisait pas les arguments arbitraires ; ajouter `bash` avec un argument de reverse-shell était donc insuffisant.<sup>[[2]](#references)</sup>

À la suite du précédent contournement du sandbox, Microsoft a désactivé la possibilité d’écrire des fichiers dans `~/Library/LaunchAgents`. Cependant, il a été découvert que si vous placez un **fichier zip comme Login Item**, l’`Archive Utility` va simplement le **décompresser** à son emplacement actuel. Ainsi, puisque le dossier `LaunchAgents` de `~/Library` n’est pas créé par défaut, il était possible de **compresser un plist dans `LaunchAgents/~$escape.plist`** et de **placer** le fichier zip dans **`~/Library`**, afin qu’une fois décompressé, il atteigne la destination de persistence.

Consultez le [**rapport original ici**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Contournement du sandbox de Word via Login Items et .zshenv

(Rappelez-vous qu’après le premier escape, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`.)

Cependant, la technique précédente avait une limitation : si le dossier **`~/Library/LaunchAgents`** existait parce qu’un autre logiciel l’avait créé, elle échouait. Une autre chaîne de Login Items a donc été découverte.

Un attaquant pouvait créer **`.bash_profile`** et **`.zshenv`** contenant le payload, les archiver, puis écrire le ZIP dans le répertoire personnel de la **victime** sous le nom **`~/~$escape.zip`**.

Il fallait ensuite ajouter le ZIP et **Terminal** comme Login Items. À la prochaine ouverture de session, Archive Utility extrait les dotfiles dans le répertoire personnel de l’utilisateur et le shell de Terminal évalue le fichier de démarrage applicable (`.bash_profile` pour le chemin Bash démontré ou `.zshenv` pour Zsh).<sup>[[3]](#references)</sup>

Consultez le [**rapport original ici**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Contournement du sandbox de Word avec Open et les variables env

Les processus sandboxés pouvaient toujours demander le lancement d’applications via **`open`**. L’application lancée s’exécutait dans son propre contexte de sécurité au lieu d’hériter du profil de sandbox exact de Word.<sup>[[4]](#references)</sup>

L’utilitaire `open` concerné disposait d’une option **`--env`** permettant de fournir des variables d’environnement. L’exploit créait `.zshenv` à l’intérieur du sandbox, définissait `HOME` sur ce répertoire, puis lançait Terminal afin que Zsh l’évalue. La chaîne rapportée définissait également la variable privée mal orthographiée `__OSINSTALL_ENVIROMENT` ; conservez cette orthographe exacte lors de la reproduction du PoC historique.<sup>[[4]](#references)</sup>

Consultez le [**rapport original ici**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Contournement du sandbox de Word avec Open et stdin

L’utilitaire **`open`** prenait également en charge le paramètre **`--stdin`** (et après le contournement précédent, il n’était plus possible d’utiliser `--env`).

Bien que l’application Python d’Apple refuse un script mis en quarantaine, le workflow vulnérable pouvait transmettre le même script via l’entrée standard, évitant ainsi le contrôle de quarantaine basé sur le fichier :<sup>[[5]](#references)</sup>

1. Déposer un fichier **`~$exploit.py`** contenant des commandes Python arbitraires.
2. Exécuter `open --stdin='~$exploit.py' -a Python`. L’application Python lancée reçoit le code déposé sur l’entrée standard et, dans les versions vulnérables, s’exécute en dehors du sandbox de Word parce que LaunchServices la crée sous `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Échapper au sandbox – Microsoft Office sur macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Drame d’Office sur macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Escape du sandbox d’Office365 sur MacOS](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Analyse technique de CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Découverte d’une vulnérabilité d’escape du App Sandbox macOS : analyse approfondie de CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
