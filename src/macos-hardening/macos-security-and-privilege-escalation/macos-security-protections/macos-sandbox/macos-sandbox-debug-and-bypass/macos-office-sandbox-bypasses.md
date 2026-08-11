# Bypass della Sandbox di Office su macOS

{{#include ../../../../../banners/hacktricks-training.md}}

Di seguito sono riportati **escape storici dalla sandbox di Microsoft Office per Mac**. Documentano errori riutilizzabili nei confini di fiducia, ma non si deve presumere che combinazioni di Office/macOS patchate siano vulnerabili senza riprodurre la versione e la policy esatte.

### Bypass della sandbox di Word tramite LaunchAgents

L'applicazione interessata utilizzava una regola sandbox personalizzata tramite `com.apple.security.temporary-exception.sbpl`. Consentiva i file normali il cui basename iniziava con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Pertanto, l'escape era semplice quanto **scrivere un** `plist` **LaunchAgent** in `~/Library/LaunchAgents/~$escape.plist`.

Consulta il [**report originale qui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Bypass della sandbox di Word tramite Login Items e zip

Ricorda che, dal primo escape, Word può scrivere file arbitrari il cui nome inizia con `~$`, anche se dopo la patch della precedente vulnerabilità non era possibile scrivere in `/Library/Application Scripts` o in `/Library/LaunchAgents`.

La sandbox interessata consentiva la creazione di un **Login Item**, che viene avviato quando l'utente effettua il login. Il percorso dimostrato richiedeva un'applicazione firmata/notarizzata accettabile e non consentiva argomenti arbitrari, quindi aggiungere `bash` con un argomento reverse-shell non era sufficiente.<sup>[[2]](#references)</sup>

Dal precedente bypass della sandbox, Microsoft aveva disabilitato la possibilità di scrivere file in `~/Library/LaunchAgents`. Tuttavia, è stato scoperto che, inserendo un **file zip come Login Item**, `Archive Utility` lo **decomprime** semplicemente nella posizione corrente. Poiché, per impostazione predefinita, la cartella `LaunchAgents` di `~/Library` non viene creata, era quindi possibile **comprimere un plist in `LaunchAgents/~$escape.plist`** e **posizionare** il file zip in **`~/Library`**, così che, quando veniva decompresso, raggiungesse la destinazione di persistenza.

Consulta il [**report originale qui**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Bypass della sandbox di Word tramite Login Items e .zshenv

(Ricorda che, dal primo escape, Word può scrivere file arbitrari il cui nome inizia con `~$`).

Tuttavia, la tecnica precedente aveva una limitazione: se la cartella **`~/Library/LaunchAgents`** esisteva perché era stata creata da un altro software, l'operazione falliva. Per questo è stata scoperta una catena diversa basata sui Login Items.

Un attaccante poteva creare **`.bash_profile`** e **`.zshenv`** contenenti il payload, archiviarli e scrivere lo ZIP nella home directory della **vittima** come **`~/~$escape.zip`**.

Quindi aggiungeva lo ZIP e **Terminal** come Login Items. Al login successivo, Archive Utility estraeva i dotfile nella home directory dell'utente e la shell di Terminal valutava il file di avvio applicabile (`.bash_profile` per il percorso Bash dimostrato o `.zshenv` per Zsh).<sup>[[3]](#references)</sup>

Consulta il [**report originale qui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Bypass della sandbox di Word con Open e variabili d'ambiente

I processi in sandbox potevano comunque richiedere l'avvio di applicazioni tramite **`open`**. L'applicazione avviata veniva eseguita nel proprio contesto di sicurezza, invece di ereditare l'esatto profilo sandbox di Word.<sup>[[4]](#references)</sup>

L'utility `open` interessata disponeva di un'opzione **`--env`** per fornire variabili d'ambiente. L'exploit creava `.zshenv` all'interno della sandbox, impostava `HOME` su quella directory e avviava Terminal, affinché Zsh lo valutasse. La catena descritta impostava anche la variabile privata scritta erroneamente `__OSINSTALL_ENVIROMENT`; mantieni questa grafia esatta quando riproduci il PoC storico.<sup>[[4]](#references)</sup>

Consulta il [**report originale qui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Bypass della sandbox di Word con Open e stdin

L'utility **`open`** supportava anche il parametro **`--stdin`** (e, dopo il bypass precedente, non era più possibile utilizzare `--env`).

Sebbene l'applicazione Python di Apple rifiutasse un file di script in quarantena, il workflow vulnerabile poteva fornire lo stesso script tramite lo standard input, evitando il controllo di quarantena basato sui file:<sup>[[5]](#references)</sup>

1. Rilascia un file **`~$exploit.py`** contenente comandi Python arbitrari.
2. Esegui `open --stdin='~$exploit.py' -a Python`. L'applicazione Python avviata riceve il codice rilasciato tramite lo standard input e, nelle versioni vulnerabili, viene eseguita al di fuori della sandbox di Word perché LaunchServices la crea sotto `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Escape dalla Sandbox – Microsoft Office su macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Dramma di Office su macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Escape dalla Sandbox di Office365 per MacOS](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Analisi tecnica di CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Alla scoperta di una vulnerabilità di escape dalla App Sandbox di macOS: analisi approfondita di CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
