# Bypass della Sandbox di Office su macOS

{{#include ../../../../../banners/hacktricks-training.md}}

### Bypass della Sandbox di Word tramite Launch Agents

L'applicazione utilizza una **custom Sandbox** usando l'entitlement **`com.apple.security.temporary-exception.sbpl`** e questa custom sandbox consente di scrivere file ovunque, purché il nome del file inizi con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Pertanto, evadere era semplice quanto **scrivere un `plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist`.

Consulta il [**report originale qui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Bypass della Sandbox di Word tramite Login Items e zip

Ricorda che, dopo il primo escape, Word può scrivere file arbitrari il cui nome inizia con `~$`, anche se, dopo la patch della vulnerabilità precedente, non era possibile scrivere in `/Library/Application Scripts` o in `/Library/LaunchAgents`.

È stato scoperto che dalla sandbox è possibile creare un **Login Item** (applicazioni che vengono eseguite quando l'utente effettua il login). Tuttavia, queste app **non verranno eseguite a meno che** non siano **notarized** e **non è possibile aggiungere argomenti** (quindi non puoi semplicemente eseguire una reverse shell usando **`bash`**).

Nel precedente Sandbox bypass, Microsoft ha disabilitato la possibilità di scrivere file in `~/Library/LaunchAgents`. Tuttavia, è stato scoperto che, se inserisci un **file zip come Login Item**, `Archive Utility` lo **decomprimerà** nella posizione corrente. Quindi, poiché per impostazione predefinita la cartella `LaunchAgents` di `~/Library` non viene creata, era possibile **comprimere un plist in `LaunchAgents/~$escape.plist`** e **posizionare** il file zip in **`~/Library`**, così che, quando viene decompresso, raggiunga la destinazione della persistence.

Consulta il [**report originale qui**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Bypass della Sandbox di Word tramite Login Items e .zshenv

(Ricorda che, dopo il primo escape, Word può scrivere file arbitrari il cui nome inizia con `~$`).

Tuttavia, la tecnica precedente aveva una limitazione: se la cartella **`~/Library/LaunchAgents`** esiste perché è stata creata da un altro software, avrebbe avuto esito negativo. Per questo è stata scoperta una catena diversa basata sui Login Items.

Un attacker potrebbe creare i file **`.bash_profile`** e **`.zshenv`** con il payload da eseguire, quindi comprimerli e **scrivere lo zip nella** cartella dell'utente vittima: **`~/~$escape.zip`**.

Successivamente, aggiungere il file zip ai **Login Items** e quindi l'app **`Terminal`**. Quando l'utente effettuerà nuovamente il login, il file zip verrà decompresso nella cartella dell'utente, sovrascrivendo **`.bash_profile`** e **`.zshenv`**; di conseguenza, il terminale eseguirà uno di questi file, a seconda che venga utilizzato bash o zsh.

Consulta il [**report originale qui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass con Open e variabili env

Dai processi in sandbox è ancora possibile invocare altri processi usando l'utility **`open`**. Inoltre, questi processi verranno eseguiti **all'interno della propria sandbox**.

È stato scoperto che l'utility open dispone dell'opzione **`--env`** per eseguire un'app con variabili **env specifiche**. Pertanto, era possibile creare il **file `.zshenv`** all'interno di una cartella **dentro** la **sandbox** e usare `open` con **`--env`**, impostando la variabile **`HOME`** su quella cartella e aprendo l'app `Terminal`, che avrebbe eseguito il file `.zshenv` (per qualche motivo era anche necessario impostare la variabile `__OSINSTALL_ENVIROMENT`).

Consulta il [**report originale qui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass con Open e stdin

L'utility **`open`** supportava anche il parametro **`--stdin`** (e, dopo il bypass precedente, non era più possibile usare `--env`).

Il punto è che, anche se **`python`** era firmato da Apple, **non avrebbe eseguito** uno script con l'attributo **`quarantine`**. Tuttavia, era possibile passargli uno script tramite stdin, in modo che non verificasse se fosse stato messo in quarantena:

1. Rilascia un file **`~$exploit.py`** contenente comandi Python arbitrari.
2. Esegui _open_ **`–stdin='~$exploit.py' -a Python`**, eseguendo l'app Python con il file rilasciato come standard input. Python esegue senza problemi il nostro codice e, poiché è un processo figlio di _launchd_, non è vincolato dalle regole della sandbox di Word.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
